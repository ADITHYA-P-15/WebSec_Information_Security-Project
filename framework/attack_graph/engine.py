
import json

from sqlalchemy.orm import Session

from database.database import engine
from database.models import AttackPath, Evidence, Finding


# Only these evidence types directly support the current path models.
PATH_EVIDENCE_TYPES = {
    "BROKEN_ACCESS_CONTROL": {
        "authorization_observation",
        "authorization_policy",
    },
    "IDOR_BOLA": {
        "idor_ownership_observation",
    },
    "SQL_INJECTION": {"controlled_sql_injection_probe"},
    "CROSS_SITE_SCRIPTING": {
        "controlled_reflected_xss_probe",
        "controlled_stored_xss_probe",
        "dom_xss_source_sink_observation",
    },
    "CSRF": {"controlled_csrf_form_observation"},
    "PATH_TRAVERSAL": {"controlled_path_traversal_probe"},
}


def build_path(finding, evidence_records):
    """Build an evidence-backed candidate path for one finding."""

    allowed_types = PATH_EVIDENCE_TYPES.get(
        finding.vulnerability_type, set()
    )

    evidence = []

    for record in evidence_records:
        if record.evidence_type not in allowed_types:
            continue

        try:
            data = json.loads(record.data)
        except (ValueError, TypeError):
            data = {"raw": record.data}

        evidence.append({
            "evidence_id": record.id,
            "type": record.evidence_type,
            "data": data,
        })

    if not evidence:
        return None

    base = {
        "path_status": "CANDIDATE",
        "finding_id": finding.id,
        "finding_title": finding.title,
        "vulnerability_type": finding.vulnerability_type,
        "risk_score": finding.risk_score,
        "risk_severity": finding.risk_severity,
        "evidence_ids": [item["evidence_id"] for item in evidence],
        "evidence": evidence,
    }

    if finding.vulnerability_type == "IDOR_BOLA":
        observations = [
            item["data"]
            for item in evidence
            if item["type"] == "idor_ownership_observation"
        ]

        own = next(
            (
                item for item in observations
                if item.get("classification") == "owned_object_access"
            ),
            None,
        )

        foreign = next(
            (
                item for item in observations
                if item.get("classification")
                == "candidate_cross_user_access"
            ),
            None,
        )

        if own and foreign:
            base.update({
                "path_type": "cross_user_object_access",
                "nodes": [
                    {
                        "type": "identity",
                        "label": "Alice (authenticated user)",
                        "user_id": own.get("authenticated_user_id"),
                    },
                    {
                        "type": "endpoint",
                        "label": "/api/orders/{order_id}",
                    },
                    {
                        "type": "resource",
                        "label": f"Order {foreign.get('object_id')}",
                        "owner_id": foreign.get("owner_id"),
                    },
                ],
                "edges": [
                    {
                        "from": "identity",
                        "to": "endpoint",
                        "relationship": "requests as authenticated user",
                    },
                    {
                        "from": "endpoint",
                        "to": "resource",
                        "relationship": (
                            "returned object owned by another user"
                        ),
                        "supporting_evidence_ids": [
                            item["evidence_id"]
                            for item in evidence
                        ],
                    },
                ],
                "explanation": (
                    "The authenticated user retrieved an order whose "
                    "returned owner ID differs from the user's ID. "
                    "This is a candidate cross-user access path."
                ),
            })
            return base

    if finding.vulnerability_type == "BROKEN_ACCESS_CONTROL":
        policy = next(
            (
                item["data"]
                for item in evidence
                if item["type"] == "authorization_policy"
            ),
            {},
        )

        observations = [
            item["data"]
            for item in evidence
            if item["type"] == "authorization_observation"
        ]

        unexpected_role = policy.get("unexpected_role", "user")
        endpoint = policy.get("endpoint", "unknown endpoint")

        unexpected_success = any(
            item.get("role") == unexpected_role
            and isinstance(item.get("status_code"), int)
            and 200 <= item["status_code"] < 300
            for item in observations
        )

        if unexpected_success:
            base.update({
                "path_type": "role_boundary_violation",
                "nodes": [
                    {
                        "type": "identity",
                        "label": f"{unexpected_role} role",
                    },
                    {
                        "type": "endpoint",
                        "label": endpoint,
                    },
                    {
                        "type": "protected_resource",
                        "label": (
                            "Resource protected by "
                            "administrator-only policy"
                        ),
                    },
                ],
                "edges": [
                    {
                        "from": "identity",
                        "to": "endpoint",
                        "relationship": "successful HTTP request",
                    },
                    {
                        "from": "endpoint",
                        "to": "protected_resource",
                        "relationship": (
                            "policy indicates administrator-only access"
                        ),
                        "supporting_evidence_ids": [
                            item["evidence_id"]
                            for item in evidence
                        ],
                    },
                ],
                "explanation": (
                    "A role outside the configured expected roles received "
                    "a successful response. The protected-resource "
                    "relationship is based on the stored policy and "
                    "requires verification."
                ),
            })
            return base

    if finding.vulnerability_type == "SQL_INJECTION":
        observations = [item["data"] for item in evidence]
        supported = any(
            item.get("boolean_response_difference")
            or item.get("database_error_disclosed")
            for item in observations
        )
        if supported:
            endpoint = next((item.get("endpoint") for item in observations if item.get("endpoint")), "unknown endpoint")
            base.update({
                "path_type": "candidate_sql_injection_to_data_access",
                "nodes": [
                    {"type": "identity", "label": "Unauthenticated requester"},
                    {"type": "endpoint", "label": endpoint},
                    {"type": "data_store", "label": "Product catalogue query"},
                ],
                "edges": [
                    {"from": "identity", "to": "endpoint", "relationship": "sends controlled search input"},
                    {"from": "endpoint", "to": "data_store", "relationship": "response difference or database error observed", "supporting_evidence_ids": base["evidence_ids"]},
                ],
                "explanation": "Controlled read-only evidence suggests a SQL-dependent response path. Data access and exploitability remain unconfirmed.",
            })
            return base

    if finding.vulnerability_type == "CROSS_SITE_SCRIPTING":
        for item in evidence:
            data = item["data"]
            if item["type"] == "controlled_reflected_xss_probe" and data.get("payload_reflected_unescaped"):
                base.update({
                    "path_type": "candidate_reflected_xss_rendering",
                    "nodes": [
                        {"type": "identity", "label": "Requester"},
                        {"type": "endpoint", "label": data.get("endpoint", "unknown endpoint")},
                        {"type": "browser_context", "label": "Unescaped response output"},
                    ],
                    "edges": [
                        {"from": "identity", "to": "endpoint", "relationship": "supplies controlled HTML marker"},
                        {"from": "endpoint", "to": "browser_context", "relationship": "marker reflected without escaping", "supporting_evidence_ids": base["evidence_ids"]},
                    ],
                    "explanation": "The response reflected a marker without escaping. Browser execution and impact were not tested.",
                })
                return base
            if item["type"] == "controlled_stored_xss_probe" and data.get("seeded_marker_reflected_unescaped"):
                base.update({
                    "path_type": "candidate_stored_xss_rendering",
                    "nodes": [
                        {"type": "stored_content", "label": "Seeded training review"},
                        {"type": "endpoint", "label": data.get("endpoint", "unknown endpoint")},
                        {"type": "browser_context", "label": "Unescaped review output"},
                    ],
                    "edges": [
                        {"from": "stored_content", "to": "endpoint", "relationship": "review loaded by page"},
                        {"from": "endpoint", "to": "browser_context", "relationship": "fixture marker rendered without escaping", "supporting_evidence_ids": base["evidence_ids"]},
                    ],
                    "explanation": "A seeded review marker was rendered without escaping. No browser execution was performed.",
                })
                return base
            if item["type"] == "dom_xss_source_sink_observation" and data.get("source_and_sink_nearby"):
                base.update({
                    "path_type": "candidate_dom_xss_source_to_sink",
                    "nodes": [
                        {"type": "client_source", "label": data.get("dom_source", "URL fragment")},
                        {"type": "client_sink", "label": data.get("sink", "innerHTML")},
                        {"type": "browser_context", "label": "DOM rendering"},
                    ],
                    "edges": [
                        {"from": "client_source", "to": "client_sink", "relationship": "static source-to-sink pattern observed", "supporting_evidence_ids": base["evidence_ids"]},
                        {"from": "client_sink", "to": "browser_context", "relationship": "client-side HTML rendering"},
                    ],
                    "explanation": "A static source-to-sink pattern was observed in response code. No fragment payload or browser execution was tested.",
                })
                return base

    if finding.vulnerability_type == "CSRF":
        observations = [item["data"] for item in evidence]
        if any(item.get("vulnerable_form_has_csrf_token") is False for item in observations):
            endpoint = next((item.get("endpoint") for item in observations if item.get("endpoint")), "unknown endpoint")
            base.update({
                "path_type": "candidate_csrf_form_to_state_change",
                "nodes": [
                    {"type": "external_origin", "label": "Untrusted site"},
                    {"type": "identity", "label": "Authenticated user's browser"},
                    {"type": "endpoint", "label": endpoint},
                    {"type": "state", "label": "Preference update"},
                ],
                "edges": [
                    {"from": "external_origin", "to": "identity", "relationship": "cross-origin request possibility requires browser review"},
                    {"from": "identity", "to": "endpoint", "relationship": "authenticated form lacks observed CSRF token", "supporting_evidence_ids": base["evidence_ids"]},
                    {"from": "endpoint", "to": "state", "relationship": "form is state-changing; request was not submitted"},
                ],
                "explanation": "The form observation supports a candidate CSRF path only. Cookie policy and cross-origin exploitability remain untested.",
            })
            return base

    if finding.vulnerability_type == "PATH_TRAVERSAL":
        observations = [item["data"] for item in evidence]
        if any(item.get("controlled_fixture_marker_observed") for item in observations):
            endpoint = next((item.get("endpoint") for item in observations if item.get("endpoint")), "unknown endpoint")
            base.update({
                "path_type": "candidate_path_traversal_to_fixture_read",
                "nodes": [
                    {"type": "identity", "label": "Unauthenticated requester"},
                    {"type": "endpoint", "label": endpoint},
                    {"type": "file", "label": "Fabricated private training fixture"},
                ],
                "edges": [
                    {"from": "identity", "to": "endpoint", "relationship": "supplies traversal path"},
                    {"from": "endpoint", "to": "file", "relationship": "controlled fixture marker returned", "supporting_evidence_ids": base["evidence_ids"]},
                ],
                "explanation": "The read was limited to a fabricated fixture inside the local lab. Access to real files was not attempted.",
            })
            return base

    return None


def build_compound_authorization_path(findings, evidence_by_finding):
    """Build a candidate group for multiple observed role-boundary failures."""
    target_findings = []

    for finding in findings:
        if finding.vulnerability_type != "BROKEN_ACCESS_CONTROL":
            continue

        evidence = evidence_by_finding.get(finding.id, [])
        policy = next(
            (
                item for item in evidence
                if item.evidence_type == "authorization_policy"
            ),
            None,
        )

        if policy is None:
            continue

        try:
            policy_data = json.loads(policy.data or "{}")
        except (ValueError, TypeError):
            continue

        expected_roles = policy_data.get("expected_roles", [])
        if "admin" not in expected_roles:
            continue

        observations = []
        for item in evidence:
            if item.evidence_type != "authorization_observation":
                continue

            try:
                data = json.loads(item.data or "{}")
            except (ValueError, TypeError):
                continue

            if (
                data.get("role") == policy_data.get("unexpected_role")
                and isinstance(data.get("status_code"), int)
                and 200 <= data["status_code"] < 300
            ):
                observations.append(item)

        if observations:
            target_findings.append({
                "finding_id": finding.id,
                "title": finding.title,
                "endpoint": policy_data.get("endpoint"),
                "policy_evidence_id": policy.id,
                "observation_evidence_ids": [
                    item.id for item in observations
                ],
                "unexpected_role": policy_data.get("unexpected_role"),
            })

    if len(target_findings) < 2:
        return None

    evidence_ids = sorted({
        evidence_id
        for item in target_findings
        for evidence_id in (
            [item["policy_evidence_id"]]
            + item["observation_evidence_ids"]
        )
    })

    return {
        "path_status": "CANDIDATE",
        "path_type": "compound_role_boundary_exposure",
        "finding_ids": [
            item["finding_id"] for item in target_findings
        ],
        "finding_details": target_findings,
        "evidence_ids": evidence_ids,
        
        "nodes": (
            [
                {
                    "type": "identity",
                    "label": "Authenticated user with ordinary role",
                }
            ]
            + [
                {
                    "type": "endpoint",
                    "label": item["endpoint"] or "Unknown endpoint",
                    "finding_id": item["finding_id"],
                }
                for item in target_findings
            ]
        ),

    }

def generate_attack_paths(assessment_id):
    created_count = 0
    updated_count = 0
    skipped_count = 0

    with Session(engine) as session:
        findings = (
            session.query(Finding)
            .filter_by(assessment_id=assessment_id)
            .order_by(Finding.id)
            .all()
        )

        evidence_by_finding = {}

        for finding in findings:
            evidence_by_finding[finding.id] = (
                session.query(Evidence)
                .filter_by(finding_id=finding.id)
                .order_by(Evidence.id)
                .all()
            )

        for finding in findings:
            evidence_records = (
                session.query(Evidence)
                .filter_by(finding_id=finding.id)
                .order_by(Evidence.id)
                .all()
            )

            path_data = build_path(finding, evidence_records)

            if path_data is None:
                skipped_count += 1
                continue

            path_name = (
                f"Finding {finding.id}: "
                f"{path_data['path_type']}"
            )

            description = json.dumps(
                path_data,
                sort_keys=True,
                ensure_ascii=False,
            )

            existing = (
                session.query(AttackPath)
                .filter_by(
                    assessment_id=assessment_id,
                    name=path_name,
                )
                .first()
            )

            if existing:
                existing.description = description
                existing.severity = finding.risk_severity or "UNASSESSED"
                updated_count += 1
            else:
                session.add(
                    AttackPath(
                        assessment_id=assessment_id,
                        name=path_name,
                        description=description,
                        severity=finding.risk_severity or "UNASSESSED",
                    )
                )
                created_count += 1

        compound_data = build_compound_authorization_path(
            findings,
            evidence_by_finding,
        )

        if compound_data is not None:
            compound_name = (
                f"Assessment {assessment_id}: "
                "compound_role_boundary_exposure"
            )

            compound_description = json.dumps(
                compound_data,
                sort_keys=True,
                ensure_ascii=False,
            )

            compound_path = (
                session.query(AttackPath)
                .filter_by(
                    assessment_id=assessment_id,
                    name=compound_name,
                )
                .first()
            )

            # Keep the compound severity conservative: use the highest
            # preliminary severity among its supporting findings.
            severity_order = {
                "INFO": 0,
                "LOW": 1,
                "MEDIUM": 2,
                "HIGH": 3,
                "CRITICAL": 4,
            }

            compound_severity = max(
                (
                    finding.risk_severity or "UNASSESSED"
                    for finding in findings
                    if finding.id in compound_data["finding_ids"]
                ),
                key=lambda severity: severity_order.get(severity, -1),
                default="UNASSESSED",
            )

            if compound_path:
                compound_path.description = compound_description
                compound_path.severity = compound_severity
                updated_count += 1
            else:
                session.add(
                    AttackPath(
                        assessment_id=assessment_id,
                        name=compound_name,
                        description=compound_description,
                        severity=compound_severity,
                    )
                )
                created_count += 1

        session.commit()

    print("Attack-path generation complete.")
    print(f"Created: {created_count}")
    print(f"Updated: {updated_count}")
    print(f"Skipped: {skipped_count}")
