from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import argparse

from sqlalchemy.orm import Session

from config import (
    PROJECT_NAME,
    TARGET_URL,
    DEMO_ROLES,
    API_CANDIDATE_PATHS,
    AUTHORIZATION_POLICIES,
)
from database.database import engine, initialize_database
from database.assessment_manager import create_assessment
from database.models import Assessment, AssessmentStage, Target


FRAMEWORK_ROOT = Path(__file__).resolve().parent
REPORTS_ROOT = FRAMEWORK_ROOT.parent / "reports"
ZAP_REPORT = REPORTS_ROOT / "zap" / "zap-baseline-report.json"


def require_local_target(target_url):
    parsed = urlparse(target_url)
    configured = urlparse(TARGET_URL)
    configured_port = configured.port or 80
    target_port = parsed.port or 80
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"localhost", "127.0.0.1"}
        or target_port != configured_port
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(f"Refusing assessment outside the local HTTP lab: {target_url}")


def record_stage(assessment_id, name, status, details="", started_at=None):
    with Session(engine) as session:
        session.add(AssessmentStage(
            assessment_id=assessment_id,
            name=name,
            status=status,
            details=str(details)[:4000],
            started_at=started_at or datetime.utcnow(),
            finished_at=datetime.utcnow(),
        ))
        session.commit()


def run_stage(assessment_id, name, operation):
    started_at = datetime.utcnow()
    print(f"\n[{name}] running")
    try:
        result = operation()
        detail = result if isinstance(result, str) else "Completed"
        record_stage(assessment_id, name, "SUCCEEDED", detail, started_at)
        print(f"[{name}] succeeded")
        return True
    except Exception as error:
        record_stage(assessment_id, name, "FAILED", f"{type(error).__name__}: {error}", started_at)
        print(f"[{name}] failed: {type(error).__name__}: {error}")
        return False


def skip_stage(assessment_id, name, reason):
    record_stage(assessment_id, name, "SKIPPED", reason)
    print(f"[{name}] skipped: {reason}")


def run_recon(target_url, target_id, assessment_id):
    from recon.web_crawler import WebCrawler
    from recon.api_discovery import APIDiscoverer
    from recon.save_endpoints import save_endpoints

    endpoints_saved = 0
    crawler = WebCrawler(target_url, max_depth=2)
    endpoints = crawler.crawl()
    save_endpoints(target_id, endpoints, role="anonymous")
    endpoints_saved += len(endpoints)

    for role, credentials in DEMO_ROLES.items():
        crawler = WebCrawler(target_url, max_depth=2)
        if not crawler.login(credentials["username"], credentials["password"]):
            raise RuntimeError(f"Could not authenticate configured role {role!r}.")
        endpoints = crawler.crawl()
        save_endpoints(target_id, endpoints, role=role)
        endpoints_saved += len(endpoints)

        discoverer = APIDiscoverer(target_url)
        if not discoverer.login(credentials["username"], credentials["password"]):
            raise RuntimeError(f"API discovery login failed for role {role!r}.")
        observations = discoverer.probe(API_CANDIDATE_PATHS, role=role)
        # API discovery returns full URLs; persist the same normalized schema as the crawler.
        from recon.discovery import normalize_endpoints
        normalized = normalize_endpoints(observations, discovered_by="api_discovery")
        save_endpoints(target_id, normalized, role=role)
        endpoints_saved += len(normalized)

    return f"Persisted {endpoints_saved} endpoint observations for target {target_id}."


def run_assessment(target_url=TARGET_URL, zap_report=None):
    require_local_target(target_url)
    zap_report = Path(zap_report) if zap_report else (ZAP_REPORT if ZAP_REPORT.is_file() else None)
    initialize_database()
    assessment_id = create_assessment(target_url)
    with Session(engine) as session:
        target = session.query(Target).filter_by(assessment_id=assessment_id).order_by(Target.id).first()
        assessment = session.get(Assessment, assessment_id)
        target_id = target.id
        assessment.status = "RUNNING"
        session.commit()

    print(f"Assessment #{assessment_id} | target #{target_id} | {target_url}")
    zap_live_report = REPORTS_ROOT / "zap" / f"zap-live-verification-assessment-{assessment_id}.json"
    outcomes = []
    outcomes.append(run_stage(assessment_id, "reconnaissance_and_role_mapping",
        lambda: run_recon(target_url, target_id, assessment_id)))

    from verification.authorization import run_role_aware_assessment
    outcomes.append(run_stage(
        assessment_id,
        "role_aware_authorization_and_idor",
        lambda: run_role_aware_assessment(
            assessment_id,
            target_url,
            DEMO_ROLES,
            AUTHORIZATION_POLICIES,
        ),
    ))

    from scanners.common_web import scan_common_vulnerabilities
    outcomes.append(run_stage(
        assessment_id,
        "common_web_vulnerability_probes",
        lambda: scan_common_vulnerabilities(assessment_id, target_url),
    ))

    def import_zap():
        if zap_report is None or not zap_report.is_file():
            raise FileNotFoundError(f"ZAP baseline report not found: {zap_report}")
        from scanners.zap_importer import import_zap_findings
        import_zap_findings(assessment_id, zap_report)
        return f"Imported scoped ZAP report {zap_report.name}."

    if zap_report is not None:
        outcomes.append(run_stage(assessment_id, "zap_candidate_import", import_zap))
        def verify_zap_live():
            from scanners.zap_verifier import main as verify_live
            verify_live(zap_report, zap_live_report, assessment_id=assessment_id)
            return f"Safe live-response checks saved to {zap_live_report.name}."
        outcomes.append(run_stage(assessment_id, "live_response_verification", verify_zap_live))
    else:
        skip_stage(assessment_id, "zap_candidate_import", "No ZAP baseline artifact was provided.")
        outcomes.append(False)
        skip_stage(assessment_id, "live_response_verification", "Requires a scoped ZAP baseline artifact.")
        outcomes.append(False)

    def live_triage():
        if not zap_live_report.is_file():
            raise FileNotFoundError(f"ZAP live verification report not found: {zap_live_report}")
        from verification.zap_triage import main as triage
        triage(assessment_id, zap_live_report)
        return "Persisted matching live checks as evidence; finding states unchanged."

    if zap_live_report.is_file():
        outcomes.append(run_stage(assessment_id, "verification_evidence_triage", live_triage))
    else:
        skip_stage(assessment_id, "verification_evidence_triage", "No ZAP live verification artifact was provided.")
        outcomes.append(False)

    from risk.assess_findings import assess_findings
    outcomes.append(run_stage(assessment_id, "risk_assessment", lambda: assess_findings(assessment_id)))
    from attack_graph.engine import generate_attack_paths
    outcomes.append(run_stage(assessment_id, "attack_path_analysis", lambda: generate_attack_paths(assessment_id)))

    correlation_path = REPORTS_ROOT / f"correlation-report-assessment-{assessment_id}.json"
    from verification.correlation import main as correlate
    outcomes.append(run_stage(assessment_id, "finding_correlation", lambda: correlate(assessment_id, correlation_path)))

    pre_report_status = "COMPLETED" if all(outcomes) else "PARTIAL"
    with Session(engine) as session:
        session.get(Assessment, assessment_id).status = pre_report_status
        session.commit()

    from reporting.generate_report import main as generate_report
    report_succeeded = run_stage(assessment_id, "report_generation", lambda: generate_report(assessment_id))

    final_status = "COMPLETED" if all(outcomes) and report_succeeded else "PARTIAL"
    with Session(engine) as session:
        assessment = session.get(Assessment, assessment_id)
        assessment.status = final_status
        session.commit()

    # Refresh once after the report-generation stage is recorded so the final
    # artifact contains its own stage result and the final assessment status.
    if report_succeeded:
        try:
            generate_report(assessment_id)
        except Exception as error:
            final_status = "PARTIAL"
            record_stage(
                assessment_id,
                "report_finalization",
                "FAILED",
                f"{type(error).__name__}: {error}",
            )
            with Session(engine) as session:
                session.get(Assessment, assessment_id).status = final_status
                session.commit()
            print(f"Final report refresh failed: {type(error).__name__}: {error}")
    print(f"\nAssessment #{assessment_id} finished with status {final_status}.")
    return assessment_id


def main():
    parser = argparse.ArgumentParser(description=PROJECT_NAME)
    parser.add_argument("--target", default=TARGET_URL, help="Local lab URL (must match configured host and port).")
    parser.add_argument("--zap-report", default=None, help="Optional fresh, scope-matched ZAP JSON report. Defaults to the project's existing baseline report when present.")
    args = parser.parse_args()

    print("=" * 60)
    print(PROJECT_NAME)
    print("=" * 60)

    print(f"Target: {args.target}")
    assessment_id = run_assessment(args.target, args.zap_report)
    print(f"Assessment created and processed: #{assessment_id}")


if __name__ == "__main__":
    main()
