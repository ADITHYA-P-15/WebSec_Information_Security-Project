
from sqlalchemy.orm import Session

from database.database import engine
from database.models import Assessment
from verification.authorization import AuthorizationVerifier
from verification.finding_manager import record_finding
from verification.idor_verifier import IDORVerifier


BASE_URL = "http://localhost:5001"
ALICE_USER_ID = 2


def main():
    auth = AuthorizationVerifier(BASE_URL)
    verifier = IDORVerifier(BASE_URL)

    try:
        session = auth.create_authenticated_session(
            "alice",
            "alice123",
        )
    except Exception as error:
        print(f"Authentication failed: {error}")
        return

    # Compare a known-owned object with a known foreign-owned object.
    observations = [
        verifier.inspect_object(
            session,
            "/api/orders/1",
            authenticated_user_id=ALICE_USER_ID,
        ),
        verifier.inspect_object(
            session,
            "/api/orders/3",
            authenticated_user_id=ALICE_USER_ID,
        ),
    ]

    for item in observations:
        print(f"\nEndpoint: {item['path']}")
        print(f"Classification: {item['classification']}")
        print(f"Status: {item.get('status_code', 'N/A')}")
        print(f"Object ID: {item.get('object_id', 'N/A')}")
        print(f"Owner ID: {item.get('owner_id', 'N/A')}")

        if item.get("reason"):
            print(f"Reason: {item['reason']}")

    own = next(
        (item for item in observations
         if item["path"] == "/api/orders/1"),
        None,
    )
    foreign = next(
        (item for item in observations
         if item["path"] == "/api/orders/3"),
        None,
    )

    if not own or not foreign:
        print("\nNo complete comparison; nothing persisted.")
        return

    if own["classification"] != "owned_object_access":
        print("\nControl request did not establish owned-object access.")
        print("No finding persisted.")
        return

    if foreign["classification"] != "candidate_cross_user_access":
        print("\nNo cross-user ownership mismatch observed.")
        print("No finding persisted.")
        return

    with Session(engine) as db:
        assessment = db.query(Assessment).filter_by(
            target_url=BASE_URL
        ).order_by(Assessment.id).first()

        if assessment is None:
            print("No matching assessment found; nothing persisted.")
            return

        assessment_id = assessment.id

    evidence_items = [
        {
            "evidence_type": "idor_ownership_observation",
            "data": item,
        }
        for item in observations
    ]

    result = record_finding(
        assessment_id=assessment_id,
        title="IDOR/BOLA: GET /api/orders/{order_id}",
        vulnerability_type="IDOR_BOLA",
        description=(
            "An authenticated user retrieved an order whose returned "
            "owner ID differs from the authenticated user's ID. "
            "The ownership mismatch is supported by the stored HTTP "
            "observations; retain candidate status pending formal "
            "verification and policy review."
        ),
        evidence_items=evidence_items,
        severity="UNASSESSED",
        status="CANDIDATE",
    )

    print("\nFinding persisted")
    print(f"Finding ID: {result['finding_id']}")
    print(f"New finding: {result['created']}")
    print(f"Evidence records added: {result['evidence_added']}")
    print(f"Status: {result['status']}")


if __name__ == "__main__":
    main()
