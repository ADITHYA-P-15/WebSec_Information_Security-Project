
from verification.authorization import AuthorizationVerifier


verifier = AuthorizationVerifier(
    base_url="http://localhost:5001"
)

# Test-only credentials for the local vulnerable application.
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

# These are test cases for our controlled target,
# not routes hardcoded into the discovery engine.
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

    print("\nAuthorization Evidence Collection")
    print("=================================")

    for test_case in test_cases:
        observations = []

        for account in accounts:
            role = account["role"]

            observation = verifier.inspect_endpoint(
                session=sessions[role],
                path=test_case["path"],
                role=role,
            )

            observations.append(observation)

        results = verifier.compare_roles(
            path=test_case["path"],
            observations=observations,
            expected_roles=test_case["expected_roles"],
        )

        print(f"\nEndpoint: {test_case['path']}")

        for result in results:
            print(f"  Role: {result['role']}")

            if "error" in result:
                print(f"  Error: {result['error']}")
                print("  Classification: inconclusive")
                continue

            print(f"  HTTP status: {result['status_code']}")
            print(f"  Content-Type: {result['content_type']}")
            print(f"  Response size: {result['response_bytes']} bytes")
            print(f"  SHA-256: {result['body_sha256']}")
            print(f"  Classification: {result['classification']}")
            print(f"  Verified: {result['verified']}")
            print(f"  Response preview: {result['body_preview']}")

finally:
    for session in sessions.values():
        session.close()
