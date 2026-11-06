
import json

from sqlalchemy.orm import Session

from database.database import engine
from database.models import Evidence, Finding
from verification.results import (
    evaluate_authorization,
    evaluate_object_ownership,
)
from verification.persist_results import (
    persist_verification_results,
)


def load_finding_evidence(finding_id):
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if finding is None:
            raise ValueError(f"Finding {finding_id} not found.")

        records = session.query(Evidence).filter_by(
            finding_id=finding_id
        ).order_by(Evidence.id).all()

        return [
            {
                "evidence_id": record.id,
                "evidence_type": record.evidence_type,
                "data": json.loads(record.data),
            }
            for record in records
        ]


def main():
    # Findings 1 and 2: use the stored policy and HTTP observations.
    for finding_id in (1, 2):
        records = load_finding_evidence(finding_id)

        policy_record = next(
            (
                item for item in records
                if item["evidence_type"] == "authorization_policy"
            ),
            None,
        )

        if policy_record is None:
            print(
                f"Finding {finding_id}: no policy evidence; skipped."
            )
            continue

        policy = policy_record["data"]

        observations = [
            item["data"]
            for item in records
            if item["evidence_type"] == "authorization_observation"
        ]

        results = evaluate_authorization(
            observations,
            expected_roles=policy["expected_roles"],
        )

        for result in results:
            result["source"] = "stored_assessment_evidence"
            result["source_evidence_ids"] = [
                item["evidence_id"]
                for item in records
                if item["evidence_type"] == "authorization_observation"
            ]
            result["policy_evidence_id"] = policy_record["evidence_id"]

        saved = persist_verification_results(finding_id, results)
        print(f"\nFinding {finding_id}: {saved}")

        for result in results:
            print(
                f"  {result.get('role')} | "
                f"{result.get('path')} | {result['outcome']}"
            )

    # Finding 3: evaluate stored ownership observations.
    finding_id = 3
    records = load_finding_evidence(finding_id)

    observations = [
        item["data"]
        for item in records
        if item["evidence_type"] == "idor_ownership_observation"
    ]

    results = evaluate_object_ownership(observations)

    source_ids = [
        item["evidence_id"]
        for item in records
        if item["evidence_type"] == "idor_ownership_observation"
    ]

    for result in results:
        result["source"] = "stored_assessment_evidence"
        result["source_evidence_ids"] = source_ids

    saved = persist_verification_results(finding_id, results)
    print(f"\nFinding {finding_id}: {saved}")

    for result in results:
        print(
            f"  {result.get('path')} | {result['outcome']}"
        )


if __name__ == "__main__":
    main()
