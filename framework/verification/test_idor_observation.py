
import hashlib
import json

from verification.authorization import AuthorizationVerifier


BASE_URL = "http://localhost:5001"


def observe_order(session, order_id):
    path = f"/api/orders/{order_id}"

    try:
        response = session.get(
            f"{BASE_URL}{path}",
            timeout=5,
            allow_redirects=False,
        )
    except Exception as error:
        print(f"\nGET {path}: request failed: {error}")
        return

    body = response.text

    print(f"\nGET {path}")
    print("-" * (len(path) + 4))
    print(f"Status: {response.status_code}")
    print(f"Content-Type: {response.headers.get('Content-Type')}")
    print(f"Response bytes: {len(response.content)}")
    print(f"Body SHA-256: {hashlib.sha256(response.content).hexdigest()}")

    try:
        parsed = response.json()
        print(
            "Response JSON:\n"
            + json.dumps(parsed, indent=2, ensure_ascii=False)
        )
    except ValueError:
        print(f"Response body preview: {body[:500]}")


def main():
    verifier = AuthorizationVerifier(BASE_URL)

    try:
        alice_session = verifier.create_authenticated_session(
            "alice",
            "alice123",
        )
    except Exception as error:
        print(f"Could not authenticate as Alice: {error}")
        return

    print("Controlled IDOR observation")
    print("Authenticated role: Alice (ordinary user)")
    print("Expected ownership: Alice owns order 1; Bob owns order 3.")

    observe_order(alice_session, 1)
    observe_order(alice_session, 3)


if __name__ == "__main__":
    main()
