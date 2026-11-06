import json
import argparse
from datetime import datetime, timezone

import requests
from sqlalchemy.orm import Session

from config import TARGET_URL, AUTHORIZATION_POLICIES
from database.database import engine
from database.models import Assessment, Evidence, Finding


ADMIN_ROUTES = {
    path: f"Broken Access Control: GET {path}"
    for path in AUTHORIZATION_POLICIES
    if path != "/admin/lab/users"
}

IDOR_TITLE = "IDOR/BOLA: GET /api/orders/insecure/{order_id}"

IDENTITIES = [
    ("anonymous", None, None, 302),
    ("alice", "alice", "alice123", 403),
    ("admin", "admin", "admin123", 200),
]


def create_session(target_url, username=None, password=None):
    target = target_url.rstrip("/")
    session = requests.Session()
    login_status = None

    if username:
        response = session.post(
            f"{target}/login",
            data={"username": username, "password": password},
            allow_redirects=False,
            timeout=5,
        )
        login_status = response.status_code

        if login_status != 302:
            session.close()
            raise RuntimeError(
                f"Login failed for {username}: HTTP {login_status}"
            )

    return session, login_status


def make_check(identity, role, path, expected, response,
               login_status=None, extra=None):
    check = {
        "identity": identity,
        "role": role,
        "login_status": login_status,
        "route": path,
        "method": "GET",
        "expected_status": expected,
        "observed_status": response.status_code,
        "result": "PASS" if response.status_code == expected else "FAIL",
    }

    if extra:
        check.update(extra)

    return check


def collect_admin_checks(target_url):
    results = {}

    for path, title in ADMIN_ROUTES.items():
        checks = []

        for identity, username, password, expected in IDENTITIES:
            session, login_status = create_session(target_url, username, password)

            try:
                response = session.get(
                    f"{target_url.rstrip('/')}{path}",
                    allow_redirects=False,
                    timeout=5,
                )
                check = make_check(
                    identity=identity,
                    role=(
                        "anonymous" if username is None
                        else "admin" if username == "admin"
                        else "user"
                    ),
                    path=path,
                    expected=expected,
                    response=response,
                    login_status=login_status,
                )
            except requests.RequestException as exc:
                check = {
                    "identity": identity,
                    "role": identity,
                    "route": path,
                    "method": "GET",
                    "expected_status": expected,
                    "observed_status": None,
                    "result": "INCONCLUSIVE",
                    "error": str(exc),
                }
            finally:
                session.close()

            checks.append(check)
            print(
                f"{path} | {identity}: expected {expected}, "
                f"observed {check['observed_status']} | {check['result']}"
            )

        results[title] = checks

    return results


def collect_idor_checks(target_url):
    checks = []
    target = target_url.rstrip("/")
    alice_session, alice_login_status = create_session(target, "alice", "alice123")
    admin_session, admin_login_status = create_session(target, "admin", "admin123")
    try:
        profile_response = alice_session.get(f"{target}/profile", timeout=5)
        own_orders_response = alice_session.get(f"{target}/orders", timeout=5)
        all_orders_response = admin_session.get(f"{target}/admin/orders", timeout=5)
        if not all(
            response.status_code == 200
            for response in (profile_response, own_orders_response, all_orders_response)
        ):
            raise RuntimeError("Could not discover identities and orders for IDOR retest.")
        profile = profile_response.json()
        own_orders = own_orders_response.json()
        all_orders = all_orders_response.json()
        if not isinstance(profile, dict) or not isinstance(own_orders, list) or not isinstance(all_orders, list):
            raise RuntimeError("Target returned an unexpected identity or order response shape.")
        user_id = profile.get("id")
        own_order = next((item for item in own_orders if isinstance(item, dict) and item.get("id") is not None), None)
        foreign_order = next((
            item for item in all_orders
            if isinstance(item, dict) and item.get("id") is not None
            and str(item.get("user_id")) != str(user_id)
        ), None)
        if user_id is None or own_order is None or foreign_order is None:
            raise RuntimeError("Target lacks an owned and a foreign order for IDOR retest.")
        cases = [
            ("alice", "user", alice_session, alice_login_status,
             f"/api/orders/insecure/{own_order['id']}", 200),
            ("alice", "user", alice_session, alice_login_status,
             f"/api/orders/insecure/{foreign_order['id']}", 403),
            ("admin", "admin", admin_session, admin_login_status,
             f"/api/orders/insecure/{foreign_order['id']}", 200),
        ]
        for identity, role, session, login_status, path, expected in cases:
            try:
                response = session.get(
                    f"{target}{path}", allow_redirects=False, timeout=5
                )
                check = make_check(
                    identity=identity, role=role, path=path, expected=expected,
                    response=response, login_status=login_status,
                )
                if response.status_code == 200:
                    try:
                        body = response.json()
                        if isinstance(body, dict):
                            check["returned_order_id"] = body.get("id")
                            check["returned_owner_id"] = body.get("user_id")
                        else:
                            check["result"] = "INCONCLUSIVE"
                            check["reason"] = "Successful response was not a JSON object"
                    except ValueError:
                        check["result"] = "INCONCLUSIVE"
                        check["reason"] = "Successful response was not valid JSON"
            except requests.RequestException as exc:
                check = {
                    "identity": identity, "role": role, "route": path,
                    "method": "GET", "expected_status": expected,
                    "observed_status": None, "result": "INCONCLUSIVE",
                    "error": str(exc),
                }
            checks.append(check)
    finally:
        alice_session.close()
        admin_session.close()

    for check in checks:
        print(
            f"{check['route']} | {check['identity']}: expected {check['expected_status']}, "
            f"observed {check['observed_status']} | {check['result']}"
        )

    return checks


def persist_evidence(db_session, finding, checks, run_at, target_url):
    data = {
        "source": "REMEDIATION_RETEST",
        "tested_at": run_at,
        "target_url": target_url.rstrip("/"),
        "checks": checks,
        "all_checks_passed": bool(checks) and all(
            item["result"] == "PASS" for item in checks
        ),
        "finding_status_changed": False,
        "historical_evidence_preserved": True,
    }

    # Compare stable content without the timestamp so repeated identical
    # retests do not create duplicate evidence rows.
    stable_data = {
        "source": data["source"],
        "target_url": data["target_url"],
        "checks": data["checks"],
    }

    for existing in db_session.query(Evidence).filter_by(
        finding_id=finding.id,
        evidence_type="remediation_retest",
    ).all():
        try:
            previous = json.loads(existing.data)
        except (TypeError, json.JSONDecodeError):
            continue

        previous_stable = {
            "source": previous.get("source"),
            "target_url": previous.get("target_url"),
            "checks": previous.get("checks"),
        }

        if previous_stable == stable_data:
            print(
                f"Finding #{finding.id}: identical retest evidence "
                "already exists; skipped duplicate."
            )
            return False, data["all_checks_passed"]

    db_session.add(
        Evidence(
            finding_id=finding.id,
            evidence_type="remediation_retest",
            data=json.dumps(data, sort_keys=True, ensure_ascii=False),
        )
    )

    print(
        f"Finding #{finding.id}: new remediation retest evidence prepared."
    )
    return True, data["all_checks_passed"]


def run_retest(assessment_id, target_url=TARGET_URL):
    from scanners.common_web import validate_local_target

    target_url = validate_local_target(target_url)
    with Session(engine) as db_session:
        assessment = db_session.get(Assessment, assessment_id)
        if assessment is None:
            raise ValueError(f"Assessment {assessment_id} was not found.")
        if assessment.target_url.rstrip("/") != target_url:
            raise ValueError(
                f"Target {target_url} does not match assessment #{assessment_id} "
                f"({assessment.target_url})."
            )
    run_at = datetime.now(timezone.utc).isoformat()

    results = collect_admin_checks(target_url)
    results[IDOR_TITLE] = collect_idor_checks(target_url)

    titles_and_types = [
        (title, "BROKEN_ACCESS_CONTROL")
        for title in ADMIN_ROUTES.values()
    ]
    titles_and_types.append((IDOR_TITLE, "IDOR_BOLA"))

    overall_passed = True
    inserted = 0
    skipped = 0

    with Session(engine) as db_session:
        for title, vulnerability_type in titles_and_types:
            finding = db_session.query(Finding).filter_by(
                assessment_id=assessment_id,
                title=title,
                vulnerability_type=vulnerability_type,
            ).first()

            if finding is None:
                raise ValueError(
                    f"Existing finding not found: {title} "
                    f"({vulnerability_type})"
                )

            added, passed = persist_evidence(
                db_session,
                finding,
                results[title],
                run_at,
                target_url,
            )
            inserted += int(added)
            skipped += int(not added)
            overall_passed = overall_passed and passed

        # Intentionally preserve finding status, severity, and risk fields.
        db_session.commit()

    print(f"\nRetest completed at {run_at}")
    print(f"Evidence inserted: {inserted}")
    print(f"Duplicate records skipped: {skipped}")
    print(f"Overall result: {'PASS' if overall_passed else 'FAIL/INCONCLUSIVE'}")
    print("Finding statuses, severities, and risk fields were not modified.")

    if not overall_passed:
        raise SystemExit("Retest did not fully pass. Review the stored evidence.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Record evidence for a remediation retest.")
    parser.add_argument("assessment_id", type=int, help="Assessment ID containing the existing finding.")
    parser.add_argument("--target", default=TARGET_URL, help="Local lab target URL.")
    args = parser.parse_args()
    run_retest(args.assessment_id, args.target)
