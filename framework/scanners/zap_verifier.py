
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

from config import TARGET_URL


REPORT_PATH = Path("../reports/zap/zap-baseline-report.json")
OUTPUT_PATH = Path("../reports/zap/zap-live-verification.json")

# Only permit requests to this project's local target.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "host.docker.internal"}
TIMEOUT = 5

# ZAP plugin ID -> response header(s) relevant to the alert.
HEADER_CHECKS = {
    "10038": ("Content-Security-Policy",),
    "10020": ("X-Frame-Options", "Content-Security-Policy"),
    "10063": ("Permissions-Policy",),
    "10021": ("X-Content-Type-Options",),
    "10036": ("Server",),
}

# ZAP uses plugin 90004 for several different header alerts.
NAMED_HEADER_CHECKS = {
    "Cross-Origin-Embedder-Policy Header Missing or Invalid":
        ("Cross-Origin-Embedder-Policy",),
    "Cross-Origin-Opener-Policy Header Missing or Invalid":
        ("Cross-Origin-Opener-Policy",),
    "Cross-Origin-Resource-Policy Header Missing or Invalid":
        ("Cross-Origin-Resource-Policy",),
}


def validate_target():
    target = urlparse(TARGET_URL)

    if target.scheme != "http":
        raise ValueError("This verifier is configured for the local HTTP lab target.")

    if target.hostname not in {"localhost", "127.0.0.1"}:
        raise ValueError(
            f"Refusing to scan non-local target: {TARGET_URL}"
        )

    if not target.port:
        raise ValueError("TARGET_URL must specify the lab target's port.")

    return target


def local_url(report_url, target):
    """Map a ZAP Docker URL to the same path on our local lab target."""
    parsed = urlparse(report_url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Unsupported URL scheme.")

    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Refusing out-of-scope URL: {report_url}")

    if parsed.port != target.port:
        raise ValueError(f"URL port does not match target port: {report_url}")

    # Keep the path and query, but connect to the configured local target.
    return f"{TARGET_URL.rstrip('/')}{parsed.path or '/'}" + (
        f"?{parsed.query}" if parsed.query else ""
    )


def relevant_headers(alert):
    plugin_id = str(alert.get("pluginid", ""))
    name = alert.get("name", "")

    if name in NAMED_HEADER_CHECKS:
        return NAMED_HEADER_CHECKS[name]

    if plugin_id == "10020":
        # X-Frame-Options OR CSP frame-ancestors can provide protection.
        return HEADER_CHECKS[plugin_id]

    return HEADER_CHECKS.get(plugin_id, ())


def inspect_response(alert, instance, target, session):
    method = str(instance.get("method", "GET")).upper()
    report_url = instance.get("uri", "")

    result = {
        "alert_name": alert.get("name"),
        "plugin_id": str(alert.get("pluginid", "")),
        "reported_method": method,
        "reported_url": report_url,
        "verification": "INCONCLUSIVE",
        "reason": "",
        "observed_status": None,
        "observed_headers": {},
    }

    # Do not replay POST/PUT/PATCH/DELETE requests automatically.
    # They may change application state or submit credentials.
    
    plugin_id = str(alert.get("pluginid", ""))

    # For response-header alerts, inspect the page with GET instead
    # of replaying the original POST request or submitting credentials.
    header_alert = (
        plugin_id in {"10038", "10020", "10063", "10036", "10021"}
        or alert.get("name", "") in NAMED_HEADER_CHECKS
    )

    if method not in {"GET", "HEAD"}:
        if method == "POST" and header_alert:
            method = "GET"
            result["verification_method"] = "SAFE_GET_SUBSTITUTE"
            result["reason"] = (
                "Inspected the same endpoint with GET instead of "
                "replaying the original POST. This is supporting evidence, "
                "not proof about the original POST response."
            )
        else:
            result["reason"] = (
                f"Skipped {method}: no automatic replay of "
                "credential-submission or potentially state-changing requests."
            )
            return result
    else:
        result["verification_method"] = "ORIGINAL_SAFE_METHOD"


    try:
        url = local_url(report_url, target)
        response = session.request(
            method,
            url,
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except (requests.RequestException, ValueError) as exc:
        result["reason"] = f"Live request failed or was rejected: {exc}"
        return result

    result["observed_status"] = response.status_code
    result["observed_headers"] = dict(response.headers)

    name = alert.get("name", "")
    plugin_id = str(alert.get("pluginid", ""))

    # Version disclosure: inspect the actual Server response header.
    if plugin_id == "10036":
        server = response.headers.get("Server", "")
        result["verification"] = (
            "OBSERVED" if server else "NOT_OBSERVED"
        )
        result["reason"] = (
            f"Server header present: {server}"
            if server
            else "Server header absent in this live response."
        )

    # CSP is also relevant to clickjacking when frame-ancestors is present.
    elif plugin_id == "10020":
        x_frame = response.headers.get("X-Frame-Options", "").strip()
        csp = response.headers.get("Content-Security-Policy", "").lower()
        has_frame_ancestors = "frame-ancestors" in csp

        protected = bool(x_frame) or has_frame_ancestors
        result["verification"] = (
            "NOT_OBSERVED" if protected else "OBSERVED"
        )
        result["reason"] = (
            "A relevant anti-framing directive/header is present."
            if protected
            else "Neither X-Frame-Options nor CSP frame-ancestors was observed."
        )

    # Header presence is checked; policy quality still needs context.
    elif relevant_headers(alert):
        headers = relevant_headers(alert)

        present = {
            header: bool(response.headers.get(header, "").strip())
            for header in headers
        }

        result["verification"] = (
            "OBSERVED" if not any(present.values()) else "NOT_OBSERVED"
        )
        result["reason"] = (
            "Relevant header presence checked against the live response."
        )
        result["header_presence"] = present

    # Cache alerts are context-sensitive. Presence of a cache header alone
    # does not prove that sensitive information is exposed.
    elif plugin_id == "10049":
        result["verification"] = "NEEDS_CONTEXT"
        result["reason"] = (
            "Review Cache-Control, response content sensitivity, "
            "authentication state, and caching requirements."
        )
        result["cache_headers"] = {
            name: response.headers.get(name)
            for name in ("Cache-Control", "Pragma", "Expires", "Vary")
            if response.headers.get(name) is not None
        }

    else:
        result["verification"] = "MANUAL_REVIEW"
        result["reason"] = (
            "No automated live-response rule is defined for this alert."
        )

    return result


def main(report_path=REPORT_PATH, output_path=OUTPUT_PATH, assessment_id=None):
    report_path = Path(report_path)
    output_path = Path(output_path)
    target = validate_target()

    if not report_path.exists():
        raise FileNotFoundError(
            f"ZAP report not found: {report_path.resolve()}"
        )

    report = json.loads(report_path.read_text())
    results = []

    with requests.Session() as session:
        for site in report.get("site", []):
            for alert in site.get("alerts", []):
                for instance in alert.get("instances", []):
                    results.append(
                        inspect_response(alert, instance, target, session)
                    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "assessment_id": assessment_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": TARGET_URL,
        "mode": "read-only live-response verification",
        "results": results,
        "summary": {
            "total_instances": len(results),
            "observed": sum(
                r["verification"] == "OBSERVED" for r in results
            ),
            "not_observed": sum(
                r["verification"] == "NOT_OBSERVED" for r in results
            ),
            "inconclusive": sum(
                r["verification"] == "INCONCLUSIVE" for r in results
            ),
            "needs_context": sum(
                r["verification"] == "NEEDS_CONTEXT" for r in results
            ),
            "manual_review": sum(
                r["verification"] == "MANUAL_REVIEW" for r in results
            ),
        },
    }

    output_path.write_text(json.dumps(output, indent=2))

    print("ZAP live-response verification complete.")
    print("Target:", TARGET_URL)
    print("Results:", len(results))
    print("Summary:", json.dumps(output["summary"], indent=2))
    print("Output:", output_path.resolve())


if __name__ == "__main__":
    main()
