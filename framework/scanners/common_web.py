"""Controlled probes for the local demonstration application."""

import re
from urllib.parse import urlparse

import requests
from uuid import uuid4

from verification.finding_manager import record_finding
from config import DEMO_ROLES, TARGET_URL


TIMEOUT = 5
SQL_CONTROL = "codex-no-match-7f3a"
SQL_BOOLEAN_PROBE = "%' OR 1=1 -- "
SQL_ERROR_PROBE = "'"
XSS_PROBE = "codex-xss-<svg/onload=alert(1)>"
DEBUG_PATHS = (
    "/console",
    "/debug",
    "/_debugger",
    "/__debugger__",
    "/.env",
    "/.git/HEAD",
    "/server-status",
)


def validate_local_target(target_url):
    parsed = urlparse(target_url)
    configured = urlparse(TARGET_URL)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"localhost", "127.0.0.1"}
        or (parsed.port or 80) != (configured.port or 80)
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(f"Refusing to scan non-local target: {target_url}")
    return target_url.rstrip("/")


def get_response(base_url, path, params):
    return requests.get(
        f"{base_url}{path}",
        params=params,
        timeout=TIMEOUT,
        allow_redirects=False,
    )


def json_products(response):
    try:
        payload = response.json()
    except ValueError:
        return []
    return payload.get("products", []) if isinstance(payload, dict) else []


def scan_sql_injection(assessment_id, base_url):
    path = "/api/products/search"
    control = get_response(base_url, path, {"q": SQL_CONTROL})
    boolean = get_response(base_url, path, {"q": SQL_BOOLEAN_PROBE})
    error = get_response(base_url, path, {"q": SQL_ERROR_PROBE})

    control_products = json_products(control)
    boolean_products = json_products(boolean)
    boolean_difference = (
        control.status_code == 200
        and boolean.status_code == 200
        and not control_products
        and bool(boolean_products)
    )

    error_payload = {}
    try:
        error_payload = error.json()
    except ValueError:
        pass
    database_error = error_payload.get("database_error", "")
    error_disclosure = error.status_code == 500 and bool(database_error)

    if not boolean_difference and not error_disclosure:
        return False

    evidence = {
        "source": "CONTROLLED_HTTP_PROBE",
        "test": "SQL_INJECTION",
        "endpoint": path,
        "method": "GET",
        "parameter": "q",
        "finding_status": "CANDIDATE",
        "verified": False,
        "boolean_response_difference": boolean_difference,
        "control_status": control.status_code,
        "control_result_count": len(control_products),
        "boolean_status": boolean.status_code,
        "boolean_result_count": len(boolean_products),
        "error_status": error.status_code,
        "database_error_disclosed": error_disclosure,
        "database_error_excerpt": database_error[:240],
        "secure_comparison_endpoint": "/api/products/search/secure",
        "note": "Read-only search probes; scanner observations remain candidates pending review.",
    }
    record_finding(
        assessment_id=assessment_id,
        title="SQL Injection: product search parameter",
        vulnerability_type="SQL_INJECTION",
        description=(
            "Controlled search probes observed a SQL-dependent response difference "
            "or database error disclosure. Review the evidence and compare the paired "
            "parameterized endpoint before confirming exploitability."
        ),
        evidence_items=[{"evidence_type": "controlled_sql_injection_probe", "data": evidence}],
        severity="UNASSESSED",
        status="CANDIDATE",
    )
    return True


def scan_reflected_xss(assessment_id, base_url):
    path = "/products/preview"
    vulnerable = get_response(base_url, path, {"q": XSS_PROBE})
    securely_rendered = get_response(
        base_url,
        "/products/preview/secure",
        {"q": XSS_PROBE},
    )

    raw_reflection = XSS_PROBE in vulnerable.text
    escaped_comparison = (
        "&lt;svg/onload=alert(1)&gt;" in securely_rendered.text
        and XSS_PROBE not in securely_rendered.text
    )
    if vulnerable.status_code != 200 or not raw_reflection:
        return False

    evidence = {
        "source": "CONTROLLED_HTTP_PROBE",
        "test": "REFLECTED_XSS",
        "endpoint": path,
        "method": "GET",
        "parameter": "q",
        "finding_status": "CANDIDATE",
        "verified": False,
        "payload_reflected_unescaped": raw_reflection,
        "secure_comparison_endpoint": "/products/preview/secure",
        "secure_comparison_escaped": escaped_comparison,
        "response_content_type": vulnerable.headers.get("Content-Type", ""),
        "note": "Reflection was checked in the response only; no script or event handler was executed.",
    }
    record_finding(
        assessment_id=assessment_id,
        title="Cross-Site Scripting: product search preview",
        vulnerability_type="CROSS_SITE_SCRIPTING",
        description=(
            "The search preview reflected a controlled HTML marker without escaping. "
            "This is a candidate reflected XSS issue; browser execution and context "
            "were not tested."
        ),
        evidence_items=[{"evidence_type": "controlled_reflected_xss_probe", "data": evidence}],
        severity="UNASSESSED",
        status="CANDIDATE",
    )
    return True


def scan_stored_xss(assessment_id, base_url):
    marker = f"Assessment review probe {uuid4().hex[:10]} <em>formatting check</em>"
    with requests.Session() as client:
        created = client.post(
            f"{base_url}/reviews", data={"body": marker}, timeout=TIMEOUT,
            allow_redirects=False,
        )
        if created.status_code != 201:
            return False
        review_id = created.json().get("review_id")
    try:
        vulnerable = get_response(base_url, "/reviews", {})
        secure = get_response(base_url, "/reviews/secure", {})
        raw_marker = marker in vulnerable.text and "<em>formatting check</em>" in vulnerable.text
        escaped_marker = (
            "&lt;em&gt;formatting check&lt;/em&gt;" in secure.text
            and marker not in secure.text
        )
    finally:
        with requests.Session() as admin:
            login = admin.post(
                f"{base_url}/login", data=DEMO_ROLES["admin"], timeout=TIMEOUT,
                allow_redirects=False,
            )
            if login.status_code == 302:
                admin.delete(f"{base_url}/admin/reviews/{review_id}", timeout=TIMEOUT)
    if vulnerable.status_code != 200 or not raw_marker:
        return False

    evidence = {
        "source": "CONTROLLED_HTTP_PROBE",
        "test": "STORED_XSS_OUTPUT_ENCODING",
        "endpoint": "/reviews",
        "method": "GET",
        "parameter": "stored review body",
        "finding_status": "CANDIDATE",
        "verified": False,
        "assessment_review_markup_rendered_unescaped": raw_marker,
        "secure_comparison_endpoint": "/reviews/secure",
        "secure_comparison_escaped": escaped_marker,
        "note": "The scanner submitted a harmless formatting marker, compared both renderers, then removed the review; no script was executed.",
    }
    record_finding(
        assessment_id=assessment_id,
        title="Cross-Site Scripting: stored product review output",
        vulnerability_type="CROSS_SITE_SCRIPTING",
        description=(
            "A temporary assessment review containing a harmless formatting marker was rendered without output encoding. "
            "The paired secure route escapes the same stored value; browser execution "
            "was not tested."
        ),
        evidence_items=[{"evidence_type": "controlled_stored_xss_probe", "data": evidence}],
        severity="UNASSESSED",
        status="CANDIDATE",
    )
    return True


def scan_dom_xss_source(assessment_id, base_url):
    vulnerable = get_response(base_url, "/products/dom-preview", {})
    secure = get_response(base_url, "/products/dom-preview/secure", {})
    vulnerable_source = vulnerable.text
    secure_source = secure.text
    source_index = vulnerable_source.find("window.location.hash")
    sink_index = vulnerable_source.find(".innerHTML")
    source_to_sink = (
        source_index >= 0
        and sink_index > source_index
        and sink_index - source_index < 350
    )
    secure_uses_text_content = (
        "window.location.hash" in secure_source
        and ".textContent" in secure_source
        and ".innerHTML" not in secure_source
    )
    if vulnerable.status_code != 200 or not source_to_sink:
        return False

    evidence = {
        "evidence_source": "STATIC_RESPONSE_SOURCE_REVIEW",
        "test": "DOM_XSS_SOURCE_TO_SINK_HEURISTIC",
        "endpoint": "/products/dom-preview",
        "method": "GET",
        "dom_source": "window.location.hash",
        "sink": "element.innerHTML",
        "finding_status": "CANDIDATE",
        "verified": False,
        "source_and_sink_nearby": source_to_sink,
        "secure_comparison_endpoint": "/products/dom-preview/secure",
        "secure_comparison_uses_text_content": secure_uses_text_content,
        "javascript_executed": False,
        "note": "Static heuristic only; no URL fragment payload was sent or executed in a browser.",
    }
    record_finding(
        assessment_id=assessment_id,
        title="Cross-Site Scripting: DOM fragment rendered with innerHTML",
        vulnerability_type="CROSS_SITE_SCRIPTING",
        description=(
            "The response source contains a URL-fragment source near an innerHTML sink. "
            "This static candidate requires browser-context review; no payload was executed."
        ),
        evidence_items=[{"evidence_type": "dom_xss_source_sink_observation", "data": evidence}],
        severity="UNASSESSED",
        status="CANDIDATE",
    )
    return True


def scan_csrf(assessment_id, base_url):
    credentials = DEMO_ROLES["user"]
    with requests.Session() as client:
        login = client.post(
            f"{base_url}/login",
            data=credentials,
            timeout=TIMEOUT,
            allow_redirects=False,
        )
        if login.status_code not in {302, 303}:
            raise RuntimeError("Could not authenticate for the local CSRF form checks.")

        vulnerable = client.get(
            f"{base_url}/account/preferences",
            timeout=TIMEOUT,
            allow_redirects=False,
        )
        secure = client.get(
            f"{base_url}/account/preferences/secure",
            timeout=TIMEOUT,
            allow_redirects=False,
        )

    vulnerable_form = vulnerable.status_code == 200 and "<form" in vulnerable.text.lower()
    vulnerable_has_token = bool(re.search(r'name=["\']_csrf_token["\']', vulnerable.text, re.I))
    secure_has_token = bool(re.search(r'name=["\']_csrf_token["\']', secure.text, re.I))
    if not vulnerable_form or vulnerable_has_token:
        return False

    evidence = {
        "source": "CONTROLLED_HTTP_PROBE",
        "test": "CSRF_TOKEN_OBSERVATION",
        "endpoint": "/account/preferences",
        "method": "POST form inspected with GET only",
        "parameter": "display_name",
        "finding_status": "CANDIDATE",
        "verified": False,
        "authenticated_role": "user",
        "vulnerable_form_has_csrf_token": vulnerable_has_token,
        "secure_comparison_endpoint": "/account/preferences/secure",
        "secure_form_has_csrf_token": secure_has_token,
        "state_changing_form_submitted": False,
        "note": "Missing-token observation only; no cross-origin request or form submission was performed.",
    }
    record_finding(
        assessment_id=assessment_id,
        title="CSRF: account preference form lacks a token",
        vulnerability_type="CSRF",
        description=(
            "An authenticated state-changing form was observed without an anti-CSRF token. "
            "The scanner did not submit the form; browser cookie policy and cross-origin "
            "exploitability require review."
        ),
        evidence_items=[{"evidence_type": "controlled_csrf_form_observation", "data": evidence}],
        severity="UNASSESSED",
        status="CANDIDATE",
    )
    return True


def scan_path_traversal(assessment_id, base_url):
    path = "/api/files/download"
    traversal = "../private/lab-note.txt"
    response = get_response(base_url, path, {"name": traversal})
    secure = get_response(base_url, "/api/files/download/secure", {"name": traversal})

    payload = {}
    try:
        payload = response.json()
    except ValueError:
        pass
    leaked_fixture = "TRAINING_LAB_PRIVATE_NOTE" in payload.get("content", "")
    if response.status_code != 200 or not leaked_fixture:
        return False

    secure_payload = {}
    try:
        secure_payload = secure.json()
    except ValueError:
        pass
    evidence = {
        "source": "CONTROLLED_HTTP_PROBE",
        "test": "PATH_TRAVERSAL",
        "endpoint": path,
        "method": "GET",
        "parameter": "name",
        "finding_status": "CANDIDATE",
        "verified": False,
        "controlled_fixture_marker_observed": leaked_fixture,
        "secure_comparison_status": secure.status_code,
        "secure_comparison_rejected": secure.status_code in {400, 403, 404},
        "secure_comparison_error": secure_payload.get("error"),
        "note": "Probe reads only the fabricated fixture inside the local lab directory.",
    }
    record_finding(
        assessment_id=assessment_id,
        title="Path Traversal: file download name parameter",
        vulnerability_type="PATH_TRAVERSAL",
        description=(
            "A traversal sequence escaped the public fixture directory and returned a "
            "fabricated private lab file. The test is limited to the training fixture."
        ),
        evidence_items=[{"evidence_type": "controlled_path_traversal_probe", "data": evidence}],
        severity="UNASSESSED",
        status="CANDIDATE",
    )
    return True


def scan_security_misconfiguration(assessment_id, base_url):
    response = get_response(base_url, "/", {})
    headers = {key.lower(): value for key, value in response.headers.items()}
    missing_headers = [
        header for header in (
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
        )
        if not headers.get(header)
    ]
    server_header = headers.get("server", "")
    if missing_headers or server_header:
        evidence = {
            "source": "CONTROLLED_HTTP_PROBE",
            "test": "SECURITY_HEADER_REVIEW",
            "endpoint": "/",
            "method": "GET",
            "finding_status": "CANDIDATE",
            "verified": False,
            "missing_headers": missing_headers,
            "server_header": server_header,
            "scanner_severity": "LOW_CONTEXTUAL_REVIEW",
            "note": "Header absence or server fingerprinting needs application context; neither is treated as proof of high impact.",
        }
        record_finding(
            assessment_id=assessment_id,
            title="Security Misconfiguration: response header review",
            vulnerability_type="SECURITY_MISCONFIGURATION",
            description=(
                "A safe response-header review found missing defense-in-depth headers "
                "or a server fingerprint. Assess deployment context and application "
                "requirements before assigning impact."
            ),
            evidence_items=[{"evidence_type": "security_header_observation", "data": evidence}],
            severity="UNASSESSED",
            status="CANDIDATE",
        )

    credentials = DEMO_ROLES["user"]
    with requests.Session() as client:
        login = client.post(
            f"{base_url}/login",
            data=credentials,
            timeout=TIMEOUT,
            allow_redirects=False,
        )
        if login.status_code not in {302, 303}:
            raise RuntimeError("Could not authenticate for local cookie checks.")
        set_cookie = login.headers.get("Set-Cookie", "")

    cookie_flags = {
        "http_only": "httponly" in set_cookie.lower(),
        "same_site": "samesite=" in set_cookie.lower(),
        # Secure is intentionally not assessed on the local HTTP-only lab.
    }
    absent_flags = [name for name, present in cookie_flags.items() if not present]
    if absent_flags:
        evidence = {
            "source": "CONTROLLED_HTTP_PROBE",
            "test": "SESSION_COOKIE_ATTRIBUTE_REVIEW",
            "endpoint": "/login",
            "method": "POST authentication only",
            "finding_status": "CANDIDATE",
            "verified": False,
            "absent_attributes": absent_flags,
            "secure_attribute_assessment": "NOT_ASSESSED_ON_LOCAL_HTTP",
            "note": "Cookie policy is context-sensitive; the scanner did not replay authenticated state-changing requests.",
        }
        record_finding(
            assessment_id=assessment_id,
            title="Security Misconfiguration: session cookie attributes",
            vulnerability_type="SECURITY_MISCONFIGURATION",
            description=(
                "The local session cookie lacks one or more observed protective attributes. "
                "Review SameSite behavior and deployment requirements; the Secure flag is "
                "not assessed for this HTTP-only lab."
            ),
            evidence_items=[{"evidence_type": "session_cookie_attribute_observation", "data": evidence}],
            severity="UNASSESSED",
            status="CANDIDATE",
        )

    exposed = []
    for path in DEBUG_PATHS:
        probe = get_response(base_url, path, {})
        if probe.status_code == 200:
            exposed.append({
                "path": path,
                "status_code": probe.status_code,
                "content_type": probe.headers.get("Content-Type", ""),
                "body_bytes": len(probe.content),
            })
    if exposed:
        evidence = {
            "source": "CONTROLLED_HTTP_PROBE",
            "test": "EXPOSED_DEBUG_OR_METADATA_PATHS",
            "method": "GET",
            "finding_status": "CANDIDATE",
            "verified": False,
            "observations": exposed,
            "note": "Only response status and metadata were retained; no response body was stored.",
        }
        record_finding(
            assessment_id=assessment_id,
            title="Security Misconfiguration: exposed debug or metadata path",
            vulnerability_type="SECURITY_MISCONFIGURATION",
            description=(
                "A common debug or metadata path returned HTTP 200. Confirm that the "
                "content is intended to be public before treating it as a vulnerability."
            ),
            evidence_items=[{"evidence_type": "exposed_path_observation", "data": evidence}],
            severity="UNASSESSED",
            status="CANDIDATE",
        )
    return bool(missing_headers or server_header or absent_flags or exposed)


def scan_common_vulnerabilities(assessment_id, target_url):
    base_url = validate_local_target(target_url)
    results = {
        "sql_injection_candidate": scan_sql_injection(assessment_id, base_url),
        "reflected_xss_candidate": scan_reflected_xss(assessment_id, base_url),
        "stored_xss_candidate": scan_stored_xss(assessment_id, base_url),
        "dom_xss_candidate": scan_dom_xss_source(assessment_id, base_url),
        "csrf_candidate": scan_csrf(assessment_id, base_url),
        "path_traversal_candidate": scan_path_traversal(assessment_id, base_url),
        "security_misconfiguration_candidate": scan_security_misconfiguration(assessment_id, base_url),
    }
    return (
        "Common vulnerability probes complete: "
        f"SQL injection candidate={results['sql_injection_candidate']}, "
        f"reflected XSS candidate={results['reflected_xss_candidate']}, "
        f"stored XSS candidate={results['stored_xss_candidate']}, "
        f"DOM XSS candidate={results['dom_xss_candidate']}, "
        f"CSRF candidate={results['csrf_candidate']}, "
        f"path traversal candidate={results['path_traversal_candidate']}, "
        f"security misconfiguration candidate={results['security_misconfiguration_candidate']}."
    )
