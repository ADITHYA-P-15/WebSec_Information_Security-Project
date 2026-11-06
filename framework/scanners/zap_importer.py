
import json
from collections import defaultdict
from pathlib import Path

from sqlalchemy.orm import Session

from config import TARGET_URL
from database.database import engine
from scanners.zap_parser import parse_zap_report
from verification.finding_manager import record_finding


REPORT_PATH = Path("../reports/zap/zap-baseline-report.json")


def classify_alert(plugin_id):
    """Map ZAP alerts into broad framework vulnerability categories."""
    plugin_id = str(plugin_id)

    if plugin_id == "10111":
        return "AUTHENTICATION_INFORMATION"

    if plugin_id == "10049":
        return "CACHE_CONTROL"

    return "SECURITY_MISCONFIGURATION"


def validate_report_scope(report_path):
    """Allow only the configured local target and its Docker host alias."""
    report = json.loads(report_path.read_text(encoding="utf-8"))

    from urllib.parse import urlparse

    configured = urlparse(TARGET_URL)
    allowed_hosts = {
        configured.hostname,
        "host.docker.internal",
    }

    allowed_port = configured.port or (
        443 if configured.scheme == "https" else 80
    )

    sites = report.get("site", [])
    if not sites:
        raise ValueError("The ZAP report contains no sites.")

    for site in sites:
        site_url = urlparse(site.get("@name", ""))
        site_port = site_url.port or (
            443 if site_url.scheme == "https" else 80
        )

        if (
            site_url.hostname not in allowed_hosts
            or site_port != allowed_port
            or site_url.scheme != configured.scheme
        ):
            raise ValueError(
                f"Report target {site.get('@name')!r} does not match "
                f"the configured target {TARGET_URL!r}."
            )


def import_zap_findings(assessment_id, report_path=REPORT_PATH):
    report_path = Path(report_path)

    if not report_path.is_file():
        raise FileNotFoundError(
            f"ZAP report not found: {report_path.resolve()}"
        )

    validate_report_scope(report_path)

    alerts = parse_zap_report(report_path)

    if not alerts:
        print("No ZAP alert instances were found.")
        return

    # Group individual affected URLs under one alert-level finding.
    grouped = defaultdict(list)

    for alert in alerts:
        key = (str(alert["plugin_id"]), alert["name"])
        grouped[key].append(alert)

    print(f"ZAP instances parsed: {len(alerts)}")
    print(f"Unique alert groups: {len(grouped)}")
    print(f"Assessment ID: {assessment_id}")
    print()

    created_count = 0
    reused_count = 0
    evidence_count = 0

    for (plugin_id, name), instances in sorted(grouped.items()):
        first = instances[0]

        # Keep scanner severity separate from framework risk scoring.
        title = f"ZAP: {name} [Plugin {plugin_id}]"

        description = first.get("description") or (
            "Candidate finding reported by OWASP ZAP. "
            "Manual verification is required."
        )

        solution = first.get("solution")
        if solution:
            description += "\n\nZAP suggested solution:\n" + solution

        evidence_items = []

        for instance in instances:
            evidence_items.append(
                {
                    "evidence_type": "zap_alert_instance",
                    "data": {
                        "source": "OWASP_ZAP",
                        "plugin_id": instance["plugin_id"],
                        "alert_name": instance["name"],
                        "scanner_risk": instance["risk"],
                        "risk_description": instance.get(
                            "risk_description"
                        ),
                        "confidence": instance.get("confidence"),
                        "url": instance["url"],
                        "method": instance.get("method"),
                        "parameter": instance.get("parameter"),
                        "observed_evidence": instance.get("evidence"),
                        "description": instance.get("description"),
                        "solution": instance.get("solution"),
                        "reference": instance.get("reference"),
                        "verified": False,
                    },
                }
            )

        result = record_finding(
            assessment_id=assessment_id,
            title=title,
            vulnerability_type=classify_alert(plugin_id),
            description=description,
            evidence_items=evidence_items,
            severity="UNASSESSED",
            status="CANDIDATE",
        )

        if result["created"]:
            created_count += 1
        else:
            reused_count += 1

        evidence_count += result["evidence_added"]

        print(
            f"[{'CREATED' if result['created'] else 'REUSED'}] "
            f"Finding #{result['finding_id']}: {name} "
            f"| instances={len(instances)} "
            f"| new evidence={result['evidence_added']} "
            f"| status={result['status']}"
        )

    print("\nImport summary")
    print(f"  Alert groups processed: {len(grouped)}")
    print(f"  New findings:           {created_count}")
    print(f"  Existing findings reused: {reused_count}")
    print(f"  New evidence records:   {evidence_count}")
    print("  Verification:           Not performed")
    print("  Risk scores:            Not modified")


if __name__ == "__main__":
    raise SystemExit("Call import_zap_findings(assessment_id) from the assessment workflow.")
