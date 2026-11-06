# Web Application Security Assessment Framework

An intentionally vulnerable, local-only online store and Python security assessment framework. Northstar Supply is the target application: assessors use its shopping, reviews, account, receipt, and store operations flows, then review evidence, risk, attack paths, remediation guidance, and retest results. The storefront and assessment desk share the Hallmark Editorial design system.

## Start the demonstration store

From the repository root:

```bash
cd target-app
docker compose up --build
```

Open **http://localhost:5001/**. It is a small storefront with a product catalog, search, account sign-in, demo checkout, order receipts, customer reviews, delivery preferences, and store operations. These are live flows backed by the target application's database. The intentionally weak behavior is part of those ordinary routes rather than an exercise page. Sign in as `alice / alice123`, `bob / bob123`, or `admin / admin123` to explore role-specific behavior. Demo checkout creates local sample orders only; there is no payment integration.

The Compose mapping binds to `127.0.0.1:5001`. Keep the vulnerable app local. Stop it with `Ctrl+C` or `docker compose down` from `target-app/`.

## Run the full assessment

In a second terminal, start the assessment dashboard:

```bash
cd framework
source .venv/bin/activate
python dashboard.py
```

Open **http://localhost:8010/**. The dashboard reads assessment history from the existing database. Press **Run assessment** to start the central workflow and then review its stages, findings, risk, attack paths, suggested remediations, and HTML/JSON report links. The target defaults to `http://localhost:5001`; the controller rejects non-local targets and mismatched ports. It runs reconnaissance/role mapping, authorization and IDOR checks, controlled vulnerability probes, optional ZAP import and safe live-response checks, risk scoring, attack-path analysis, correlation, and report generation.

The same workflow remains available from the command line:

```bash
python main.py
```

To supply a freshly generated, scope-matched ZAP JSON artifact:

```bash
python main.py --zap-report /absolute/path/to/zap-baseline-report.json
```

If omitted, the framework uses `reports/zap/zap-baseline-report.json` when it exists. That checked-in artifact may be old; supply a fresh report for a current ZAP assessment. If no ZAP report exists, its stages are marked skipped and the assessment is reported as partial.

At completion, note the printed assessment ID. Its report files are:

```text
../reports/final-report-assessment-<ID>.html
../reports/final-report-assessment-<ID>.json
../reports/correlation-report-assessment-<ID>.json
../reports/zap/zap-live-verification-assessment-<ID>.json
```

The report includes findings, evidence, endpoint and role observations, stage results, project-specific risk scores (not CVSS), correlations, candidate attack paths, and limitations. A `CANDIDATE` is not a confirmed vulnerability; review its evidence before changing lifecycle status.

## Retest a remediation

After applying a fix to the target and restarting it, open the original assessment in the dashboard and press **Record remediation retest**. The dashboard runs the authorization and order ownership checks, stores evidence against the original findings, and refreshes the report. Finding status remains unchanged for reviewer action. The command line is also available:

```bash
python -m verification.record_remediation_retest <ASSESSMENT_ID>
```

The command checks the configured local target, verifies that it matches the assessment, discovers current order IDs, and appends retest evidence to the existing findings. It does not change finding status or risk fields. The dashboard regenerates the report after the retest.

## What the automated checks do

- SQL injection uses read-only control, boolean, and error probes against a vulnerable search endpoint; the paired endpoint uses parameter binding.
- XSS checks reflected output and a static DOM source/sink pattern. The stored-output check submits a temporary harmless formatting marker, compares vulnerable and escaped review views, and removes the review through the protected moderation route. No script payload is executed.
- CSRF inspects authenticated form token presence and cookie attributes; it does not submit state-changing forms.
- Path traversal reads only the controlled fixture under `target-app/lab_files/`.
- Authorization checks compare anonymous, user, and admin responses. IDOR compares owned and foreign orders using IDs discovered from responses.
- Scanner observations are persisted as candidates and do not automatically become verified findings.

The central run does not launch OWASP ZAP itself; it imports a supplied baseline report and performs safe live-response verification for its alerts.
