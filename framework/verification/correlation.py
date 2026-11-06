
import json
from pathlib import Path

from sqlalchemy.orm import Session

from database.database import engine
from database.models import Assessment, Evidence, Finding


OUTPUT_PATH = Path("../reports/correlation-report.json")


def load_evidence(session, finding_id):
    records = (
        session.query(Evidence)
        .filter_by(finding_id=finding_id)
        .order_by(Evidence.id)
        .all()
    )

    parsed = []
    for record in records:
        try:
            data = json.loads(record.data or "{}")
        except (json.JSONDecodeError, TypeError):
            data = {"raw": record.data}

        parsed.append({
            "evidence_id": record.id,
            "evidence_type": record.evidence_type,
            "data": data,
        })

    return parsed


def zap_plugin_id(finding):
    title = finding.title or ""
    marker = "[Plugin "
    if marker not in title:
        return None

    try:
        return title.rsplit(marker, 1)[1].split("]", 1)[0]
    except IndexError:
        return None


def normalized_url(url):
    """Normalize host aliases used by Docker and the local host."""
    if not url:
        return None

    from urllib.parse import urlsplit, urlunsplit

    parsed = urlsplit(url)
    host = parsed.hostname

    if host in {"host.docker.internal", "127.0.0.1", "localhost"}:
        host = "localhost"

    netloc = host or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    return urlunsplit((
        parsed.scheme.lower(),
        netloc,
        parsed.path.rstrip("/") or "/",
        parsed.query,
        "",
    ))


def correlate_finding(finding, evidence):
    relationships = []
    plugin_id = zap_plugin_id(finding)

    zap_instances = [
        item for item in evidence
        if item["evidence_type"] == "zap_alert_instance"
    ]
    live_checks = [
        item for item in evidence
        if item["evidence_type"] == "zap_live_verification"
    ]

    # Link scanner observations to matching live-response checks.
    for alert in zap_instances:
        alert_data = alert["data"]
        alert_url = normalized_url(alert_data.get("url"))
        alert_method = (alert_data.get("method") or "GET").upper()

        for live in live_checks:
            live_data = live["data"]

            if str(live_data.get("plugin_id")) != str(plugin_id):
                continue

            live_url = normalized_url(live_data.get("reported_url"))
            live_method = (
                live_data.get("reported_method") or "GET"
            ).upper()
            verification_method = live_data.get("verification_method")

            same_url = alert_url == live_url
            same_method = alert_method == live_method

            safe_get_match = (
                same_url
                and alert_method == "POST"
                and verification_method == "SAFE_GET_SUBSTITUTE"
            )

            if same_url and (same_method or safe_get_match):
                relationships.append({
                    "type": "SCANNER_TO_LIVE_CHECK",
                    "finding_id": finding.id,
                    "source_evidence_id": alert["evidence_id"],
                    "related_evidence_id": live["evidence_id"],
                    "match_basis": (
                        "same URL; GET substitute for POST; "
"original POST response not verified"
                        if safe_get_match
                        else "same plugin, URL and method"
                    ),
                })

    # Identify repeated endpoint instances for the same finding.
    endpoints = {}
    for alert in zap_instances:
        data = alert["data"]
        key = (
            str(data.get("plugin_id", plugin_id)),
            normalized_url(data.get("url")),
            (data.get("method") or "GET").upper(),
        )
        endpoints.setdefault(key, []).append(alert["evidence_id"])

    for key, evidence_ids in sorted(
        endpoints.items(),
        key=lambda item: str(item[0]),
    ):
        if len(evidence_ids) > 1:
            relationships.append({
                "type": "REPEATED_SCANNER_INSTANCE",
                "finding_id": finding.id,
                "plugin_id": key[0],
                "url": key[1],
                "method": key[2],
                "evidence_ids": sorted(evidence_ids),
                "note": "Repeated scanner evidence; not a separate finding.",
            })

    return relationships


def evidence_endpoint(item):
    """Extract an endpoint from supported evidence fields."""
    data = item.get("data", {})

    candidates = [
        data.get("url"),
        data.get("reported_url"),
        data.get("path"),
        data.get("endpoint"),
        data.get("requested_path"),
    ]

    from urllib.parse import urlsplit

    for candidate in candidates:
        if not isinstance(candidate, str) or not candidate.strip():
            continue

        value = candidate.strip()

        if value.startswith(("http://", "https://")):
            parsed = urlsplit(value)
            return parsed.path.rstrip("/") or "/"

        if value.startswith("/"):
            return urlsplit(value).path.rstrip("/") or "/"

    return None


def correlate_findings(findings, evidence_by_finding):
    """Generate conservative, evidence-backed cross-finding links."""
    relationships = []

    for i, first in enumerate(findings):
        for second in findings[i + 1:]:
            if first.id == second.id:
                continue

            first_type = (first.vulnerability_type or "").upper()
            second_type = (second.vulnerability_type or "").upper()

            first_is_zap = zap_plugin_id(first) is not None
            second_is_zap = zap_plugin_id(second) is not None

            # Only correlate scanner findings with authorization findings.
            if first_is_zap and second_type in {
                "BROKEN_ACCESS_CONTROL", "IDOR_BOLA"
            }:
                scanner, authorization = first, second
            elif second_is_zap and first_type in {
                "BROKEN_ACCESS_CONTROL", "IDOR_BOLA"
            }:
                scanner, authorization = second, first
            else:
                continue

            scanner_evidence = evidence_by_finding.get(scanner.id, [])
            authorization_evidence = evidence_by_finding.get(
                authorization.id, []
            )

            scanner_endpoints = {}
            for item in scanner_evidence:
                if item["evidence_type"] != "zap_alert_instance":
                    continue
                endpoint = evidence_endpoint(item)
                if endpoint:
                    scanner_endpoints.setdefault(endpoint, []).append(
                        item["evidence_id"]
                    )

            authorization_endpoints = {}
            for item in authorization_evidence:
                if item["evidence_type"] not in {
                    "authorization_observation",
                    "authorization_policy",
                    "idor_ownership_observation",
                    "verification_result",
                }:
                    continue

                endpoint = evidence_endpoint(item)
                if endpoint:
                    authorization_endpoints.setdefault(endpoint, []).append(
                        item["evidence_id"]
                    )

            for endpoint in sorted(
                set(scanner_endpoints) & set(authorization_endpoints)
            ):
                relationships.append({
                    "type": "AUTHORIZATION_SCANNER_CORRELATION",
                    "finding_ids": sorted([scanner.id, authorization.id]),
                    "endpoint": endpoint,
                    "scanner_evidence_ids": sorted(
                        scanner_endpoints[endpoint]
                    ),
                    "authorization_evidence_ids": sorted(
                        authorization_endpoints[endpoint]
                    ),
                    "match_basis": (
                        "same normalized endpoint; candidate relationship "
                        "for manual review"
                    ),
                    "verified_relationship": False,
                })

    return relationships



def correlate_shared_endpoints(findings, evidence_by_finding):
    """Summarize findings sharing an endpoint without pairwise link spam."""
    endpoint_index = {}

    supported_types = {
        "zap_alert_instance",
        "controlled_sql_injection_probe",
        "controlled_reflected_xss_probe",
        "controlled_stored_xss_probe",
        "dom_xss_source_sink_observation",
        "controlled_csrf_form_observation",
        "controlled_path_traversal_probe",
        "security_header_observation",
        "session_cookie_attribute_observation",
        "exposed_path_observation",
        "authorization_observation",
        "authorization_policy",
        "idor_ownership_observation",
        "verification_result",
    }

    for finding in findings:
        for item in evidence_by_finding.get(finding.id, []):
            if item["evidence_type"] not in supported_types:
                continue

            endpoint = evidence_endpoint(item)
            if not endpoint:
                continue

            endpoint_index.setdefault(endpoint, {}).setdefault(
                finding.id, []
            ).append(item["evidence_id"])

    relationships = []

    for endpoint, finding_map in sorted(endpoint_index.items()):
        if len(finding_map) < 2:
            continue

        relationships.append({
            "type": "SHARED_ENDPOINT_GROUP",
            "endpoint": endpoint,
            "finding_ids": sorted(finding_map),
            "evidence_ids_by_finding": {
                str(finding_id): sorted(set(evidence_ids))
                for finding_id, evidence_ids in sorted(finding_map.items())
            },
            "match_basis": "multiple findings have evidence for this endpoint",
            "verified_relationship": False,
            "note": (
                "Endpoint-level grouping only; does not establish a common "
                "root cause, exploitability, or an attack path."
            ),
        })

    return relationships



def main(assessment_id, output_path=None):
    output_path = Path(output_path) if output_path else (
        OUTPUT_PATH.parent / f"correlation-report-assessment-{assessment_id}.json"
    )
    report = {
        "mode": "read-only correlation",
        "assessment_id": None,
        "findings_processed": 0,
        "relationships": [],
        "notes": [
            "Relationships are candidates, not proof of exploitability.",
            "No findings or evidence records are merged or deleted.",
            "Safe GET substitutes do not prove the original POST response.",
        ],
    }

    with Session(engine) as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            raise RuntimeError(f"Assessment {assessment_id} does not exist.")

        report["assessment_id"] = assessment_id

        findings = (
            session.query(Finding)
            .filter_by(assessment_id=assessment_id)
            .order_by(Finding.id)
            .all()
        )

        
        evidence_by_finding = {}

        for finding in findings:
            evidence = load_evidence(session, finding.id)
            evidence_by_finding[finding.id] = evidence

            relationships = correlate_finding(finding, evidence)
            report["findings_processed"] += 1
            report["relationships"].extend(relationships)

        report["relationships"].extend(
            correlate_findings(findings, evidence_by_finding)
        )

        report["relationships"].extend(
            correlate_shared_endpoints(findings, evidence_by_finding)
        )


    # Stable output helps compare repeated runs.
    
    report["relationships"].sort(
        key=lambda item: (
            item.get(
                "finding_id",
                min(item.get("finding_ids", [0]))
            ),
            item["type"],
            item.get("source_evidence_id", 0),
            item.get("related_evidence_id", 0),
            item.get("endpoint", ""),
        )
    )


    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2))

    print("Correlation analysis complete.")
    print("Assessment ID:", report["assessment_id"])
    print("Findings processed:", report["findings_processed"])
    print("Relationships:", len(report["relationships"]))
    print("Output:", output_path.resolve())


if __name__ == "__main__":
    raise SystemExit("Call main(assessment_id) from the assessment workflow.")
