
import json
from pathlib import Path

from sqlalchemy.orm import Session

from database.database import engine
from database.models import Assessment, Evidence, Finding


INPUT_PATH = Path("../reports/zap/zap-live-verification.json")

VULNERABILITY_TYPES = {
    "10111": "AUTHENTICATION_INFORMATION",
    "10049": "CACHE_CONTROL",
}

# Keep the persisted evidence focused and stable across repeated runs.
RELEVANT_HEADERS = {
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "permissions-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "server",
    "cache-control",
    "pragma",
    "expires",
    "vary",
}


def classify_result(item):
    """Classify what the live-response check actually established."""
    plugin_id = str(item.get("plugin_id", ""))
    outcome = item.get("verification", "INCONCLUSIVE")

    if plugin_id == "10111":
        return "INFORMATIONAL"

    return {
        "OBSERVED": "OBSERVED_CHARACTERISTIC",
        "NOT_OBSERVED": "NOT_REPRODUCED",
        "NEEDS_CONTEXT": "NEEDS_CONTEXT",
        "INCONCLUSIVE": "INCONCLUSIVE",
        "MANUAL_REVIEW": "MANUAL_REVIEW",
    }.get(outcome, "MANUAL_REVIEW")


def canonical_evidence(item):
    """Build deterministic evidence without volatile response headers."""
    raw_headers = item.get("observed_headers") or {}

    headers = {
        key: value
        for key, value in sorted(raw_headers.items(), key=lambda pair: pair[0].lower())
        if key.lower() in RELEVANT_HEADERS
    }

    verification_method = item.get("verification_method", "UNKNOWN")

    if verification_method == "SAFE_GET_SUBSTITUTE":
        actual_method = "GET"
    elif verification_method == "ORIGINAL_SAFE_METHOD":
        actual_method = item.get("reported_method")
    else:
        actual_method = None

    return {
        "source": "OWASP_ZAP_LIVE_VERIFICATION",
        "plugin_id": str(item.get("plugin_id", "")),
        "alert_name": item.get("alert_name"),
        "reported_url": item.get("reported_url"),
        "reported_method": item.get("reported_method"),
        "actual_request_method": actual_method,
        "verification_method": verification_method,
        "triage_category": classify_result(item),
        "verification_outcome": item.get("verification", "INCONCLUSIVE"),
        "reason": item.get("reason", ""),
        "observed_status": item.get("observed_status"),
        "relevant_headers": headers,
        "verified_vulnerability": False,
    }


def vulnerability_type(plugin_id):
    return VULNERABILITY_TYPES.get(
        str(plugin_id),
        "SECURITY_MISCONFIGURATION",
    )


def main(assessment_id, input_path=INPUT_PATH):
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(
            f"Live verification report not found: {input_path.resolve()}"
        )

    report = json.loads(input_path.read_text())
    results = report.get("results", [])

    if not results:
        raise ValueError("The live verification report contains no results.")

    inserted = 0
    duplicates = 0
    unmatched = 0
    category_counts = {}

    with Session(engine) as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            raise RuntimeError(f"Assessment {assessment_id} does not exist.")

        for item in results:
            plugin_id = str(item.get("plugin_id", ""))
            alert_name = item.get("alert_name", "")
            title = f"ZAP: {alert_name} [Plugin {plugin_id}]"
            vuln_type = vulnerability_type(plugin_id)

            finding = (
                session.query(Finding)
                .filter_by(
                    assessment_id=assessment.id,
                    title=title,
                    vulnerability_type=vuln_type,
                )
                .first()
            )

            if finding is None:
                unmatched += 1
                print(f"[UNMATCHED] {title}")
                continue

            category = classify_result(item)
            category_counts[category] = category_counts.get(category, 0) + 1

            evidence_data = json.dumps(
                canonical_evidence(item),
                sort_keys=True,
                ensure_ascii=False,
            )

            existing = (
                session.query(Evidence)
                .filter_by(
                    finding_id=finding.id,
                    evidence_type="zap_live_verification",
                    data=evidence_data,
                )
                .first()
            )

            if existing:
                duplicates += 1
                continue

            session.add(
                Evidence(
                    finding_id=finding.id,
                    evidence_type="zap_live_verification",
                    data=evidence_data,
                )
            )
            inserted += 1

        session.commit()

    print("\nZAP triage persistence complete.")
    print("Assessment ID:", assessment_id)
    print("Verification results:", len(results))
    print("Evidence inserted:", inserted)
    print("Duplicate evidence skipped:", duplicates)
    print("Unmatched results:", unmatched)
    print("Triage categories:", json.dumps(category_counts, indent=2))
    print("Finding status, severity and risk scores were not modified.")


if __name__ == "__main__":
    raise SystemExit("Call main(assessment_id) from the assessment workflow.")
