"""Loopback-only web dashboard for running assessments and reviewing reports."""

from datetime import datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qs, urlparse

from sqlalchemy.orm import Session

from config import TARGET_URL
from database.database import engine, initialize_database
from database.models import Assessment, AssessmentStage
from main import run_assessment
from verification.record_remediation_retest import run_retest
from reporting.generate_report import main as generate_report


ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
RUN_LOCK = Lock()

REMEDIATION = {
    "SQL_INJECTION": "Use parameterized queries for every search value; avoid SQL string interpolation.",
    "CROSS_SITE_SCRIPTING": "Encode output for its HTML context, sanitize allowed rich text, and use textContent for DOM updates.",
    "CSRF": "Require an unpredictable per-session token on every state-changing request; use SameSite cookies as defense in depth.",
    "PATH_TRAVERSAL": "Resolve paths under an explicit public directory and reject paths outside it.",
    "BROKEN_ACCESS_CONTROL": "Enforce authentication and role checks on the server for every admin route and API.",
    "IDOR_BOLA": "Check object ownership or an authorized role on each order read; do not rely on an unguessable identifier.",
    "SECURITY_MISCONFIGURATION": "Set security headers and secure cookie attributes; remove exposed debug or metadata routes.",
}


def esc(value):
    return escape(str(value if value is not None else ""))


def report_for(assessment_id):
    path = REPORTS / f"final-report-assessment-{assessment_id}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if data.get("assessment", {}).get("id") != assessment_id:
        return {}
    return data


def dashboard_page(selected_id=None, message=""):
    with Session(engine) as session:
        assessments = session.query(Assessment).order_by(Assessment.id.desc()).limit(12).all()
        if selected_id is None and assessments:
            selected_id = assessments[0].id
        assessment = session.get(Assessment, selected_id) if selected_id else None
        stages = []
        if assessment:
            stages = (
                session.query(AssessmentStage)
                .filter_by(assessment_id=assessment.id)
                .order_by(AssessmentStage.id)
                .all()
            )
            assessment_summary = {
                "id": assessment.id,
                "target_url": assessment.target_url,
                "status": assessment.status,
                "created_at": assessment.created_at,
            }
        else:
            assessment_summary = None

        history = [
            {"id": item.id, "status": item.status, "target_url": item.target_url}
            for item in assessments
        ]

    report = report_for(selected_id) if selected_id else {}
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    attack_paths = report.get("attack_paths", [])
    stage_rows = "".join(
        f"<tr><td>{esc(str(stage.name).replace('_', ' '))}</td><td class='status {esc(stage.status).lower()}'>{esc(stage.status)}</td><td>{esc(stage.details)}</td></tr>"
        for stage in stages
    )
    finding_rows = "".join(
        "<tr><td>" + esc(item.get("title")) + "</td><td>" +
        esc(item.get("vulnerability_type")) + "</td><td>" +
        esc(item.get("status")) + "</td><td>" +
        esc(item.get("risk_severity") or item.get("severity")) + "</td><td>"+
        esc(item.get("risk_score")) + "</td><td>" + esc(REMEDIATION.get(item.get("vulnerability_type"), "Review evidence and apply the least-privilege control for this issue.")) + "</td></tr>"
        for item in findings
    )
    path_rows = "".join(
        f"<li><strong>{esc(item.get('title') or item.get('name') or 'Candidate path')}</strong> — {esc(item.get('description') or item.get('path') or '')}</li>"
        for item in attack_paths
    ) or "<li>No attack paths recorded for this assessment.</li>"
    history_links = "".join(
        f"<a class='history' href='/?assessment_id={item['id']}'>Assessment #{item['id']} — {esc(item['status'])}</a>"
        for item in history
    ) or "<span class='muted'>No assessments yet.</span>"
    links = ""
    if assessment_summary:
        links = (
            f"<a class='button secondary' href='/report/{assessment_summary['id']}.html?view=editorial-20261103'>Open HTML report</a> "
            f"<a class='button secondary' href='/report/{assessment_summary['id']}.json'>Open JSON report</a>"
        )
    content = (
        f"<div class='alert'>{esc(message)}</div>" if message else ""
    )
    if assessment_summary:
        content += f"""
<section class="hero"><div><h1>Assessment #{assessment_summary['id']}</h1>
<p>{esc(assessment_summary['target_url'])}</p></div><span class="pill {esc(assessment_summary['status']).lower()}">{esc(assessment_summary['status'])}</span></section>
<div class="stats"><div><b>{summary.get('finding_count', len(findings))}</b><span>findings</span></div><div><b>{summary.get('candidate_finding_count', 0)}</b><span>candidates</span></div><div><b>{summary.get('attack_path_count', len(attack_paths))}</b><span>candidate paths</span></div><div><b>{summary.get('execution_stage_count', len(stages))}</b><span>workflow stages</span></div></div>
<section><div class="sectionhead"><h2>Workflow</h2><div>{links}</div></div><div class="tablewrap"><table class="workflow-table"><thead><tr><th>Stage</th><th>Status</th><th>Details</th></tr></thead><tbody>{stage_rows or '<tr><td colspan="3">Assessment stages will appear after a run.</td></tr>'}</tbody></table></div></section>
<section><h2>Findings and remediation</h2><p class="muted">Candidates need evidence review; retests append evidence without changing finding status.</p><div class="tablewrap"><table class="findings-table"><thead><tr><th>Finding</th><th>Category</th><th>State</th><th>Risk</th><th>Score</th><th>Suggested remediation</th></tr></thead><tbody>{finding_rows or '<tr><td colspan="6">No report findings for this assessment.</td></tr>'}</tbody></table></div></section>
<section><h2>Retest after a code fix</h2><p class="muted">Run authorization and order ownership checks against this assessment's target. Results are stored as retest evidence; finding status stays unchanged for reviewer action.</p><form class="run" method="post" action="/retest"><input type="hidden" name="assessment_id" value="{assessment_summary['id'] if assessment_summary else ''}"><button class="secondary" {'disabled' if not assessment_summary else ''}>Record remediation retest</button></form></section>
<section><h2>Attack-path analysis</h2><ul>{path_rows}</ul></section>
"""
    else:
        content += "<section><h1>Run your first assessment</h1><p>Start the Northstar storefront, then click Run assessment. The framework will create the assessment records and reports.</p></section>"

    template = (Path(__file__).parent / "templates" / "dashboard.html").read_text(encoding="utf-8")
    return (template.replace("%%TARGET_URL%%", esc(TARGET_URL))
            .replace("%%CONTENT%%", content)
            .replace("%%HISTORY%%", history_links))


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "LocalAssessmentDashboard/1.0"

    def send_html(self, body, status=200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/assets/"):
            name = parsed.path.removeprefix("/assets/")
            if name not in {"tokens.css", "base.css", "dashboard.css"}:
                self.send_error(404)
                return
            source = (ROOT / "target-app" / "static" / name) if name in {"tokens.css", "base.css"} else (ROOT / "framework" / "static" / name)
            try:
                data = source.read_bytes()
            except OSError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(data)
            return
        if parsed.path.startswith("/report/"):
            name = parsed.path.removeprefix("/report/")
            if not name.endswith((".html", ".json")):
                self.send_error(404)
                return
            try:
                assessment_id = int(name.rsplit(".", 1)[0])
            except ValueError:
                self.send_error(404)
                return
            path = REPORTS / f"final-report-assessment-{assessment_id}.{name.rsplit('.', 1)[1]}"
            try:
                data = path.read_bytes()
            except OSError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8" if path.suffix == ".html" else "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
            return
        query = parse_qs(parsed.query)
        try:
            selected_id = int(query["assessment_id"][0]) if query.get("assessment_id") else None
        except ValueError:
            selected_id = None
        self.send_html(dashboard_page(selected_id))

    def do_POST(self):
        parsed_path = urlparse(self.path).path
        if parsed_path == "/retest":
            length = min(int(self.headers.get("Content-Length", "0")), 4096)
            form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
            if not RUN_LOCK.acquire(blocking=False):
                self.send_html(dashboard_page(message="An assessment or retest is already running. Wait for it to finish."), 409)
                return
            try:
                assessment_id = int(form.get("assessment_id", [""])[0])
                outcome = "PASS"
                try:
                    run_retest(assessment_id)
                except SystemExit as error:
                    outcome = str(error)
                generate_report(assessment_id)
                message = f"Retest evidence recorded for assessment #{assessment_id}. Outcome: {outcome}. Finding status was not changed."
            except Exception as error:
                assessment_id = None
                message = f"Retest could not complete: {type(error).__name__}: {error}"
            finally:
                RUN_LOCK.release()
            self.send_html(dashboard_page(assessment_id, message))
            return
        if parsed_path != "/run-assessment":
            self.send_error(404)
            return
        length = min(int(self.headers.get("Content-Length", "0")), 4096)
        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        target_url = form.get("target_url", [TARGET_URL])[0]
        if not RUN_LOCK.acquire(blocking=False):
            self.send_html(dashboard_page(message="An assessment is already running. Wait for it to finish."), 409)
            return
        try:
            assessment_id = run_assessment(target_url)
        except Exception as error:
            self.send_html(dashboard_page(message=f"Assessment could not start: {type(error).__name__}: {error}"), 400)
            return
        finally:
            RUN_LOCK.release()
        self.send_response(303)
        self.send_header("Location", f"/?assessment_id={assessment_id}")
        self.end_headers()

    def log_message(self, format_string, *args):
        print(f"[dashboard] {self.address_string()} {format_string % args}")


def main():
    initialize_database()
    server = ThreadingHTTPServer(("127.0.0.1", 8010), DashboardHandler)
    print("Security assessment dashboard: http://localhost:8010")
    print("Northstar storefront: http://localhost:5001/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
