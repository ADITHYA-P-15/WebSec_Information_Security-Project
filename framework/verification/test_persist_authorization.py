
from verification.authorization import AuthorizationVerifier
from verification.finding_manager import record_finding


verifier = AuthorizationVerifier(
    base_url="http://localhost:5001"
)

accounts = [
    {
        "role": "user",
        "username": "alice",
        "password": "alice123",
    },
    {
        "role": "admin",
        "username": "admin",
        "password": "admin123",
    },
]

test_cases = [
    {
        "path": "/admin/users",
        "expected_roles": ["admin"],
    },
    {
        "path": "/api/admin/reports",
        "expected_roles": ["admin"],
    },
]

sessions = {}

try:
    for account in accounts:
        sessions[account["role"]] = (
            verifier.create_authenticated_session(
                account["username"],
                account["password"],
            )
        )

    for test_case in test_cases:
        path = test_case["path"]
        observations = []

        for account in accounts:
            observations.append(
                verifier.inspect_endpoint(
                    session=sessions[account["role"]],
                    path=path,
                    role=account["role"],
                )
            )

        results = verifier.compare_roles(
            path=path,
            observations=observations,
            expected_roles=test_case["expected_roles"],
        )

        candidates = [
            result
            for result in results
            if result["classification"]
            == "candidate_unexpected_access"
        ]

        if not candidates:
            print(f"\nNo authorization candidate: {path}")
            continue

        # Persist only candidates backed by an actual
        # successful response. Keep both roles' observations.
        for candidate in candidates:
            if not (
                200 <= candidate.get("status_code", 0) < 300
            ):
                continue

            evidence_items = [
                {
                    "evidence_type": "authorization_observation",
                    "data": observation,
                }
                for observation in observations
            ]

            evidence_items.append({
                "evidence_type": "authorization_policy",
                "data": {
                    "endpoint": path,
                    "expected_roles": test_case["expected_roles"],
                    "unexpected_role": candidate["role"],
                    "verification": "candidate_only",
                },
            })

            result = record_finding(
                assessment_id=1,
                title=f"Broken Access Control: GET {path}",
                vulnerability_type="BROKEN_ACCESS_CONTROL",
                description=(
                    f"Role '{candidate['role']}' received a successful "
                    f"response from {path}, although the configured "
                    "policy restricts this endpoint to administrators. "
                    "Candidate requires further verification."
                ),
                evidence_items=evidence_items,
            )

            print(f"\nEndpoint: {path}")
            print(f"Finding ID: {result['finding_id']}")
            print(f"New finding: {result['created']}")
            print(f"Evidence records added: {result['evidence_added']}")
            print(f"Status: {result['status']}")

finally:
    for session in sessions.values():
        session.close()
