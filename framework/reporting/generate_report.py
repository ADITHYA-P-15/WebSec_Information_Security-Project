import json
import html
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import re
from html.parser import HTMLParser

from sqlalchemy.orm import Session

from database.database import engine
from database.models import (
    Assessment,
    Target,
    Endpoint,
    EndpointAccess,
    Asset,
    Finding,
    Evidence,
    AttackPath,
    FindingStatusHistory,
    AssessmentStage,
)


ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT.parent / "reports"
JSON_OUTPUT = REPORTS_DIR / "final-report.json"
HTML_OUTPUT = REPORTS_DIR / "final-report.html"


def read_json(path):
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}


def safe_value(obj, field, default=None):
    value = getattr(obj, field, default)
    if value is None:
        return default
    return value


def record_dict(record, fields):
    return {
        field: safe_value(record, field)
        for field in fields
    }


def parse_json(value):
    if not value:
        return {}
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return {"raw": str(value)}


def severity_for(finding):
    return (
        safe_value(finding, "risk_severity")
        or safe_value(finding, "severity")
        or "UNASSESSED"
    )


def assess_path_lifecycle(finding_ids, finding_status_by_id):
    """Summarize linked finding states without asserting path exploitability."""
    linked_statuses = {
        str(finding_id): str(
            finding_status_by_id.get(finding_id, "UNKNOWN")
        ).upper()
        for finding_id in finding_ids
    }

    statuses = list(linked_statuses.values())

    if not statuses:
        assessment = "UNLINKED"
    elif "REOPENED" in statuses:
        assessment = "REVIEW_REQUIRED_REOPENED_FINDING"
    elif all(status == "REMEDIATED" for status in statuses):
        assessment = "ALL_LINKED_FINDINGS_REMEDIATED"
    elif "REMEDIATED" in statuses:
        assessment = "PARTIALLY_REMEDIATED"
    elif "CANDIDATE" in statuses:
        assessment = "CANDIDATE_FINDINGS_REMAIN"
    elif all(status == "VERIFIED" for status in statuses):
        assessment = "ALL_LINKED_FINDINGS_VERIFIED"
    else:
        assessment = "MIXED_LIFECYCLE_REVIEW"

    return {
        "lifecycle_assessment": assessment,
        "linked_finding_statuses": linked_statuses,
        "path_exploitability_confirmed": False,
    }



def build_report(assessment_id, correlation_path=None):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    correlation_path = Path(correlation_path) if correlation_path else (
        REPORTS_DIR / f"correlation-report-assessment-{assessment_id}.json"
    )
    correlation = read_json(correlation_path)
    if correlation.get("assessment_id") != assessment_id:
        correlation = {"assessment_id": assessment_id, "relationships": [],
                       "note": "No correlation artifact exists for this assessment."}
    # Include only live checks tagged with this assessment ID.
    zap_live_path = REPORTS_DIR / "zap" / f"zap-live-verification-assessment-{assessment_id}.json"
    zap_live = read_json(zap_live_path)
    if zap_live.get("assessment_id") != assessment_id:
        zap_live = {"assessment_id": assessment_id, "results": [],
                    "note": "No live ZAP verification artifact exists for this assessment."}

    with Session(engine) as session:
        assessment = session.get(Assessment, assessment_id)

        if assessment is None:
            raise RuntimeError(
                f"Assessment {assessment_id} was not found in the database."
            )

        targets = (
            session.query(Target)
            .filter_by(assessment_id=assessment_id)
            .order_by(Target.id)
            .all()
        )

        stages_db = (
            session.query(AssessmentStage)
            .filter_by(assessment_id=assessment_id)
            .order_by(AssessmentStage.id)
            .all()
        )

        assets = (
            session.query(Asset)
            .filter_by(assessment_id=assessment_id)
            .order_by(Asset.id)
            .all()
        )

        findings_db = (
            session.query(Finding)
            .filter_by(assessment_id=assessment_id)
            .order_by(Finding.id)
            .all()
        )

        paths_db = (
            session.query(AttackPath)
            .filter_by(assessment_id=assessment_id)
            .order_by(AttackPath.id)
            .all()
        )

        endpoints = []
        target_ids = [target.id for target in targets]

        if target_ids:
            endpoints = (
                session.query(Endpoint)
                .filter(Endpoint.target_id.in_(target_ids))
                .order_by(Endpoint.id)
                .all()
            )

        endpoint_ids = [endpoint.id for endpoint in endpoints]
        access_rows_db = []
        if endpoint_ids:
            access_rows_db = (
                session.query(EndpointAccess)
                .filter(EndpointAccess.endpoint_id.in_(endpoint_ids))
                .order_by(EndpointAccess.endpoint_id, EndpointAccess.role)
                .all()
            )
        access_by_endpoint = {}
        for access in access_rows_db:
            access_by_endpoint.setdefault(access.endpoint_id, {})[access.role] = access.status_code

        findings = []

        for finding in findings_db:
            evidence_rows = (
                session.query(Evidence)
                .filter_by(finding_id=finding.id)
                .order_by(Evidence.id)
                .all()
            )

            evidence = []
            for item in evidence_rows:
                evidence.append({
                    "id": item.id,
                    "type": item.evidence_type,
                    "created_at": str(
                        safe_value(item, "created_at", "")
                    ),
                    "data": parse_json(item.data),
                })

            history_rows = (
                session.query(FindingStatusHistory)
                .filter_by(finding_id=finding.id)
                .order_by(
                    FindingStatusHistory.transitioned_at,
                    FindingStatusHistory.id,
                )
                .all()
            )

            status_history = [
                {
                    "id": item.id,
                    "previous_status": item.previous_status,
                    "new_status": item.new_status,
                    "reason": item.reason,
                    "actor": item.actor,
                    "evidence_ids": parse_json(item.evidence_ids),
                    "transitioned_at": (
                        item.transitioned_at.isoformat()
                        if item.transitioned_at else None
                    ),
                }
                for item in history_rows
            ]

            retest_rows = (
                session.query(Evidence)
                .filter_by(
                    finding_id=finding.id,
                    evidence_type="remediation_retest",
                )
                .order_by(Evidence.id.desc())
                .all()
            )

            latest_retest = None
            for retest_item in retest_rows:
                retest_data = parse_json(retest_item.data)
                if retest_data.get("source") != "REMEDIATION_RETEST":
                    continue

                checks = retest_data.get("checks", [])
                latest_retest = {
                    "evidence_id": retest_item.id,
                    "tested_at": retest_data.get("tested_at"),
                    "all_checks_passed": retest_data.get("all_checks_passed"),
                    "checks_passed": sum(
                        1 for check in checks if check.get("result") == "PASS"
                    ),
                    "checks_failed": sum(
                        1 for check in checks if check.get("result") == "FAIL"
                    ),
                    "checks_inconclusive": sum(
                        1 for check in checks
                        if check.get("result") not in {"PASS", "FAIL"}
                    ),
                }
                break

            findings.append({
                "id": finding.id,
                "title": finding.title,
                "vulnerability_type": finding.vulnerability_type,
                "severity": safe_value(finding, "severity", "UNASSESSED"),
                "risk_score": safe_value(finding, "risk_score"),
                "risk_severity": safe_value(
                    finding, "risk_severity", "UNASSESSED"
                ),
                "risk_factors": (
                    parse_json(safe_value(finding, "risk_factors"))
                    if safe_value(finding, "risk_factors") else {}
                ),
                "risk_method": safe_value(finding, "risk_method"),
                "status": safe_value(finding, "status", "UNKNOWN"),
                "description": safe_value(finding, "description", ""),
                "evidence": evidence,
                "status_history": status_history,
                "latest_retest": latest_retest,
            })

        zap_live["results"] = [
            evidence_item["data"]
            for finding in findings
            for evidence_item in finding["evidence"]
            if evidence_item["type"] == "zap_live_verification"
        ]

        attack_paths = []

        for path in paths_db:
            data = parse_json(path.description)
            attack_paths.append({
                "id": path.id,
                "name": path.name,
                "severity": path.severity,
                "path_status": data.get("path_status", "UNKNOWN"),
                "path_type": data.get("path_type", "UNKNOWN"),
                "finding_id": data.get("finding_id"),
                "finding_ids": data.get(
                    "finding_ids",
                    [data["finding_id"]]
                    if data.get("finding_id") is not None else [],
                ),
                "evidence_ids": data.get("evidence_ids", []),
                "explanation": data.get("explanation", ""),
                "details": data,
            })

        
        finding_status_by_id = {
            finding["id"]: finding["status"] or "UNKNOWN"
            for finding in findings
        }

        for path in attack_paths:
            finding_ids = path.get("finding_ids", [])
            path.update(
                assess_path_lifecycle(
                    finding_ids,
                    finding_status_by_id,
                )
            )


        target_data = [
            record_dict(target, ["id", "url", "status"])
            for target in targets
        ]

        asset_data = [
            record_dict(
                asset,
                [
                    "id", "host", "port", "protocol", "state",
                    "service", "version", "discovered_by",
                ],
            )
            for asset in assets
        ]

        endpoint_data = [
            record_dict(
                endpoint,
                ["id", "target_id", "method", "path", "discovered_by"],
            )
            for endpoint in endpoints
        ]

        access_matrix = [
            {
                "endpoint_id": endpoint.id,
                "method": endpoint.method,
                "path": endpoint.path,
                "discovered_by": endpoint.discovered_by,
                "roles": access_by_endpoint.get(endpoint.id, {}),
            }
            for endpoint in endpoints
        ]

        report = {
            "report_metadata": {
                "title": "Web Application Security Assessment Report",
                "assessment_id": assessment.id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "framework": "Web Application Security Assessment Framework",
                "risk_score_note": (
                    "Risk scores are project-specific prioritization scores, "
                    "not CVSS scores."
                ),
            },
            "assessment": record_dict(
                assessment,
                ["id", "target_url", "status", "created_at"],
            ),
            "execution_stages": [
                {
                    "name": stage.name,
                    "status": stage.status,
                    "details": stage.details,
                    "started_at": stage.started_at.isoformat() if stage.started_at else None,
                    "finished_at": stage.finished_at.isoformat() if stage.finished_at else None,
                }
                for stage in stages_db
            ],
            "targets": target_data,
            "assets": asset_data,
            "endpoints": endpoint_data,
            "access_matrix": access_matrix,
            "summary": {
                "finding_count": len(findings),
                "candidate_finding_count": sum(
                    1 for item in findings
                    if str(item["status"]).upper() == "CANDIDATE"
                ),
                "severity_distribution": dict(
                    Counter(item["risk_severity"] for item in findings)
                ),
                "finding_status_distribution": dict(
                    Counter(item["status"] for item in findings)
                ),
                "attack_path_count": len(attack_paths),
                "endpoint_count": len(endpoint_data),
                "asset_count": len(asset_data),
                "execution_stage_count": len(stages_db),
                "execution_stage_status_distribution": dict(
                    Counter(stage.status for stage in stages_db)
                ),
                "verified_finding_count": sum(
                1 for item in findings
                if str(item["status"]).upper() == "VERIFIED"
            ),
            "remediated_finding_count": sum(
                1 for item in findings
                if str(item["status"]).upper() == "REMEDIATED"
            ),
            "reopened_finding_count": sum(
                1 for item in findings
                if str(item["status"]).upper() == "REOPENED"
),
            },
            "findings": findings,
            "attack_paths": attack_paths,
            "correlation_analysis": correlation,
            "zap_live_verification": zap_live,
            "limitations": [
                "Candidate findings are not automatically confirmed vulnerabilities.",
                "Observed response characteristics do not independently prove exploitability.",
                "Some scanner checks may require authenticated testing or manual review.",
                "Correlation between records does not by itself establish a common root cause.",
                "Attack paths remain candidates unless independently verified.",
                "SQL injection, XSS, CSRF, and traversal checks use controlled local probes; observations require review and are not automatic verification.",
            ],
        }

    return report


def format_value(value):
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def esc(value):
    return html.escape(format_value(value))

class DescriptionHTMLParser(HTMLParser):
    """Convert HTML descriptions into readable plain text."""

    BLOCK_TAGS = {
        "p", "div", "br", "li", "ul", "ol",
        "h1", "h2", "h3", "h4", "tr"
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag.lower() in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def clean_description(value):
    """Return readable, safe-to-escape description text."""
    if not value:
        return ""

    text = str(value)

    # Stored descriptions contain literal escaped HTML delimiters.
    text = text.replace(r"\<", "<").replace(r"\>", ">")

    parser = DescriptionHTMLParser()
    try:
        parser.feed(text)
        parser.close()
        text = "".join(parser.parts)
    except Exception:
        # Fall back to plain text if malformed markup is encountered.
        pass

    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def render_html(report):
    summary = report["summary"]
    findings = report["findings"]
    paths = report["attack_paths"]
    roles = sorted({
        role
        for endpoint in report.get("access_matrix", [])
        for role in endpoint.get("roles", {})
    })

    severity_rows = "".join(
        f"<tr><td>{esc(severity)}</td><td>{count}</td></tr>"
        for severity, count in sorted(
            summary["severity_distribution"].items()
        )
    )

    target_rows = "".join(
        f"<tr><td>{esc(target.get('id'))}</td><td>{esc(target.get('url'))}</td>"
        f"<td>{esc(target.get('status'))}</td></tr>"
        for target in report.get("targets", [])
    ) or '<tr><td colspan="3">No targets recorded.</td></tr>'

    stage_rows = "".join(
        f"<tr><td>{esc(str(stage.get('name') or '').replace('_', ' '))}</td><td>{esc(stage.get('status'))}</td>"
        f"<td>{esc(stage.get('started_at'))}</td><td>{esc(stage.get('finished_at'))}</td>"
        f"<td>{esc(stage.get('details'))}</td></tr>"
        for stage in report.get("execution_stages", [])
    ) or '<tr><td colspan="5">No workflow stages recorded.</td></tr>'

    role_header = "".join(f"<th>{esc(role)}</th>" for role in roles)
    access_rows = "".join(
        "<tr>"
        f"<td>{esc(item.get('method'))}</td><td>{esc(item.get('path'))}</td>"
        + "".join(
            f"<td>{esc(item.get('roles', {}).get(role, '—'))}</td>"
            for role in roles
        )
        + "</tr>"
        for item in report.get("access_matrix", [])
    ) or f'<tr><td colspan="{2 + len(roles)}">No role access observations recorded.</td></tr>'

    finding_rows = ""

    for item in findings:
        evidence_html = "".join(
            f"<li><strong>Evidence #{ev['id']}</strong> "
            f"({esc(ev['type'])})<pre>{esc(ev['data'])}</pre></li>"
            for ev in item["evidence"]
        )

        history_html = "".join(
            f"""
            <li>
              <strong>{esc(entry['previous_status'])} → {esc(entry['new_status'])}</strong>
              <p><strong>Reviewer:</strong> {esc(entry['actor'])}</p>
              <p><strong>Reason:</strong> {esc(entry['reason'])}</p>
              <p><strong>Time:</strong> {esc(entry['transitioned_at'])}</p>
              <p><strong>Linked evidence IDs:</strong> {esc(entry['evidence_ids'])}</p>
            </li>
            """
            for entry in item.get("status_history", [])
        )

        retest = item.get("latest_retest")
        if retest is None:
            retest_html = '<p class="muted">No remediation retest recorded.</p>'
        else:
            if retest.get("all_checks_passed") is True:
                retest_result = "PASS"
            elif retest.get("all_checks_passed") is False:
                retest_result = "FAIL"
            else:
                retest_result = "INCONCLUSIVE"
            retest_html = f"""
            <div class="retest-summary">
              <strong>Latest retest: {esc(retest_result)}</strong>
              <p>Checks: {retest['checks_passed']} passed,
              {retest['checks_failed']} failed,
              {retest['checks_inconclusive']} inconclusive.</p>
              <p>Tested: {esc(retest.get('tested_at') or 'Unknown')}</p>
              <p>Evidence ID: {retest['evidence_id']}</p>
            </div>
            """

        finding_rows += f"""
        <tr>
          <td>{item['id']}</td>
          <td>{esc(item['title'])}</td>
          <td>{esc(item['vulnerability_type'])}</td>
          <td>{esc(item['risk_severity'])}</td>
          <td>{esc(item['risk_score'])}</td>
          <td>{esc(item['status'])}</td>
          <td>
            <div class="finding-description">{esc(clean_description(item['description']))}</div>
            <details>
              <summary>Evidence ({len(item['evidence'])})</summary>
              <ul>{evidence_html}</ul>
            </details>
            <details>
              <summary>Status history ({len(item.get('status_history', []))})</summary>
              <ul>{history_html or '<li>No status transitions recorded.</li>'}</ul>
            </details>
            <details>
              <summary>Latest remediation retest</summary>
              {retest_html}
            </details>
          </td>
        </tr>
        """

    path_rows = ""

    for path in paths:
        path_rows += f"""
        <tr>
          <td>{path['id']}</td>
          <td>{esc(path['name'])}</td>
          <td>{esc(path['path_type'])}</td>
          <td>{esc(path['severity'])}</td>
          <td>{esc(path['path_status'])}</td>
          <td>{esc(path['finding_ids'])}</td>
          <td>{esc(path['evidence_ids'])}</td>
          <td>{esc(path['explanation'])}</td>
          <td>{esc(path['lifecycle_assessment'])}</td>
        </tr>
        """

    correlation = report["correlation_analysis"]
    zap = report["zap_live_verification"]

    correlation_pretty = esc(correlation)
    zap_pretty = esc(zap)
    limitations = "".join(
        f"<li>{esc(item)}</li>"
        for item in report["limitations"]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(report['report_metadata']['title'])}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wdth,wght@12..96,75..100,500..800&family=Source+Serif+4:ital,opsz,wght@0,8..60,400;1,8..60,400&display=swap" rel="stylesheet">
<style>
:root {{
  color-scheme: light;
  --ink: oklch(16% .012 280);
  --muted: oklch(44% .010 75);
  --line: oklch(82% .009 85);
  --surface: oklch(97% .007 86);
  --background: oklch(97% .007 86);
  --accent: oklch(43% .130 152);
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: var(--background);
  color: var(--ink);
  font: 16px/1.55 "Source Serif 4", Georgia, serif;
}}
header {{
  padding: 32px max(24px, calc((100% - 1240px) / 2));
  border-bottom: 3px solid var(--ink);
  background: var(--surface);
  color: var(--ink);
}}
header h1 {{ margin: 0 0 8px; font: 700 clamp(30px, 4vw, 44px)/1.1 "Bricolage Grotesque", sans-serif; letter-spacing: -.03em; }}
header p {{ margin: 4px 0; color: var(--muted); overflow-wrap: anywhere; }}
main {{ max-width: 1240px; margin: 26px auto; padding: 0 20px 50px; }}
section {{
  background: transparent;
  border-top: 1px solid var(--line);
  padding: 22px 0;
  margin-bottom: 10px;
  overflow-wrap: anywhere;
}}
h2 {{ margin-top: 0; font: 700 25px/1.2 "Bricolage Grotesque", sans-serif; letter-spacing: -.02em; }}
h3 {{ font: 650 17px/1.3 "Bricolage Grotesque", sans-serif; }}
.muted {{ color: var(--muted); }}
.cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin: 20px 0;
}}
.metric {{
  border: 1px solid var(--line);
  border-radius: 0;
  padding: 16px;
  background: var(--surface);
}}
.metric span {{ display: block; color: var(--muted); font-size: 13px; }}
.metric strong {{ display: block; font-size: 28px; margin-top: 5px; }}
.table-wrap {{ max-width: 100%; overflow-x: auto; overscroll-behavior-inline: contain; border-top: 1px solid var(--line); }}
table {{ border-collapse: collapse; width: 100%; font: 14px/1.45 "Source Serif 4", Georgia, serif; }}
th, td {{
  text-align: left;
  vertical-align: top;
  padding: 10px 12px;
  border-bottom: 1px solid var(--line);
  overflow-wrap: anywhere;
}}
th {{ background: oklch(94% .010 86); font: 600 13px/1.4 "Bricolage Grotesque", sans-serif; }}
tr:last-child td {{ border-bottom: 0; }}
pre {{
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: oklch(94% .010 86);
  padding: 10px;
  border-radius: 6px;
  font-size: 12px;
}}
summary {{ cursor: pointer; color: var(--accent); margin-top: 8px; }}
.notice {{
  border-left: 4px solid var(--accent);
  padding: 12px 16px;
  background: oklch(94% .010 86);
}}
footer {{ color: var(--muted); font-size: 12px; padding: 10px 0; }}
.findings-table {{ min-width: 1200px; table-layout: fixed; }}
.findings-table th,
.findings-table td {{
    padding: 14px 12px;
    overflow-wrap: anywhere;
    word-break: normal;
}}
.findings-table th:nth-child(1),
.findings-table td:nth-child(1) {{ width: 5%; white-space: nowrap; }}
.findings-table th:nth-child(2),
.findings-table td:nth-child(2) {{ width: 22%; }}
.findings-table th:nth-child(3),
.findings-table td:nth-child(3) {{ width: 18%; }}
.findings-table th:nth-child(4), .findings-table td:nth-child(4) {{ width: 11%; }}
.findings-table th:nth-child(5), .findings-table td:nth-child(5) {{ width: 8%; }}
.findings-table th:nth-child(6), .findings-table td:nth-child(6) {{ width: 12%; white-space: nowrap; }}
.findings-table th:nth-child(7),
.findings-table td:nth-child(7) {{ width: 24%; }}
.findings-table td:nth-child(4), .findings-table td:nth-child(5) {{ white-space: nowrap; overflow-wrap: normal; }}
.stage-table {{ min-width: 900px; table-layout: fixed; }}
.stage-table th:nth-child(1), .stage-table td:nth-child(1) {{ width: 250px; }}
.stage-table th:nth-child(2), .stage-table td:nth-child(2) {{ width: 110px; white-space: nowrap; }}
.stage-table th:nth-child(3), .stage-table td:nth-child(3),
.stage-table th:nth-child(4), .stage-table td:nth-child(4) {{ width: 170px; }}
.stage-table td:nth-child(2) {{ overflow-wrap: normal; }}
.finding-description {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
.retest-summary {{ margin-top: 12px; padding: 14px; border: 1px solid var(--line); background: oklch(94% .010 86); }}
.retest-summary p {{ margin: 4px 0; }}
@media print {{
  body {{ background: white; }}
  section {{ break-inside: avoid; }}
  header {{ background: var(--surface); color: var(--ink); padding-left: 0; }}
  header p {{ color: var(--muted); }}
}}
details {{ margin-top: 10px; padding-top: 8px; border-top: 1px solid var(--line); }}
section + section {{ margin-top: 20px; }}
</style>
</head>
<body>
<header>
  <h1>Web Application Security Assessment</h1>
  <p>Assessment ID: {esc(report['report_metadata']['assessment_id'])}</p>
  <p>Target: {esc(report['assessment'].get('target_url'))}</p>
  <p>Assessment status: {esc(report['assessment'].get('status'))}</p>
  <p>Generated: {esc(report['report_metadata']['generated_at'])}</p>
</header>
<main>
<section>
  <h2>Executive summary</h2>
  <p class="notice">This report consolidates persisted assessment data and available
  analysis artifacts. Findings and attack paths retain their stored status;
  candidate results must not be interpreted as confirmed vulnerabilities.</p>
  <div class="cards">
    <div class="metric"><span>Findings</span><strong>{summary['finding_count']}</strong></div>
    <div class="metric"><span>Candidate findings</span><strong>{summary['candidate_finding_count']}</strong></div>
    <div class="metric"><span>Attack paths</span><strong>{summary['attack_path_count']}</strong></div>
    <div class="metric"><span>Endpoints</span><strong>{summary['endpoint_count']}</strong></div>
    <div class="metric"><span>Assets</span><strong>{summary['asset_count']}</strong></div>
    <div class="metric">
    <span>Verified findings</span>
    <strong>{summary['verified_finding_count']}</strong>
</div>
<div class="metric">
    <span>Remediated findings</span>
    <strong>{summary['remediated_finding_count']}</strong>
</div>
<div class="metric">
    <span>Reopened findings</span>
    <strong>{summary['reopened_finding_count']}</strong>
</div>
  </div>
  <p class="muted">{esc(report['report_metadata']['risk_score_note'])}</p>
  <h3>Risk severity distribution</h3>
  <div class="table-wrap"><table>
    <thead><tr><th>Risk severity</th><th>Findings</th></tr></thead>
    <tbody>{severity_rows}</tbody>
  </table></div>
</section>

<section>
  <h2>Assessment metadata and workflow</h2>
  <p>Created: {esc(report['assessment'].get('created_at'))}</p>
  <h3>Targets</h3>
  <div class="table-wrap"><table>
    <thead><tr><th>ID</th><th>URL</th><th>Status</th></tr></thead>
    <tbody>{target_rows}</tbody>
  </table></div>
  <h3>Execution stages</h3>
  <div class="table-wrap"><table class="stage-table">
    <thead><tr><th>Stage</th><th>Status</th><th>Started</th><th>Finished</th><th>Details</th></tr></thead>
    <tbody>{stage_rows}</tbody>
  </table></div>
</section>

<section>
  <h2>Findings register</h2>
  <div class="table-wrap"><table class="findings-table">
    <thead><tr>
      <th>ID</th><th>Finding</th><th>Type</th><th>Risk severity</th>
      <th>Risk score</th><th>Status</th><th>Description and evidence</th>
    </tr></thead>
    <tbody>{finding_rows}</tbody>
  </table></div>
</section>

<section>
  <h2>Attack-path analysis</h2>
  <p class="muted">Paths describe candidate relationships supported by stored
  evidence. A relationship is not proof of a complete exploit chain.</p>
  <div class="table-wrap"><table>
    <thead><tr>
      <th>ID</th><th>Name</th><th>Path type</th><th>Severity</th>
      <th>Evidence status</th>
<th>Lifecycle assessment</th>
<th>Finding IDs</th><th>Evidence IDs</th><th>Explanation</th>
    </tr></thead>
    <tbody>{path_rows}</tbody>
  </table></div>
</section>

<section>
  <h2>Reconnaissance inventory</h2>
  <h3>Targets</h3><pre>{esc(report['targets'])}</pre>
  <h3>Assets</h3><pre>{esc(report['assets'])}</pre>
  <h3>Discovered endpoints</h3><pre>{esc(report['endpoints'])}</pre>
</section>

<section>
  <h2>Role-based endpoint access matrix</h2>
  <p class="muted">Observed HTTP status by role. These observations describe access behavior and do not independently confirm authorization defects.</p>
  <div class="table-wrap"><table>
    <thead><tr><th>Method</th><th>Endpoint</th>{role_header}</tr></thead>
    <tbody>{access_rows}</tbody>
  </table></div>
</section>

<section>
  <h2>Correlation analysis</h2>
  <p class="muted">Assessment-specific candidate relationships.</p>
  <details><summary>View correlation data</summary><pre>{correlation_pretty}</pre></details>
</section>

<section>
  <h2>Live ZAP verification</h2>
  <p class="muted">Assessment-specific persisted verification evidence.
  Safe GET substitutes for reported POST checks are not equivalent to verifying
  the original POST response.</p>
  <details><summary>View live verification data</summary><pre>{zap_pretty}</pre></details>
</section>

<section>
  <h2>Limitations and interpretation</h2>
  <ul>{limitations}</ul>
</section>

<footer>
  Generated by the Web Application Security Assessment Framework.
  Review the underlying evidence and retest results before making remediation
  or sign-off decisions.
</footer>
</main>
</body>
</html>"""


def main(assessment_id):
    report = build_report(assessment_id)
    json_output = REPORTS_DIR / f"final-report-assessment-{assessment_id}.json"
    html_output = REPORTS_DIR / f"final-report-assessment-{assessment_id}.html"

    json_output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    html_output.write_text(render_html(report), encoding="utf-8")

    print("Unified assessment report generated.")
    print(f"Findings: {report['summary']['finding_count']}")
    print(f"Attack paths: {report['summary']['attack_path_count']}")
    print(f"JSON: {json_output}")
    print(f"HTML: {html_output}")


if __name__ == "__main__":
    raise SystemExit("Call main(assessment_id) from the assessment workflow.")
