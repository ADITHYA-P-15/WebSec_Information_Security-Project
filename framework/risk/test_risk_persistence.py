
from sqlalchemy.orm import Session

from database.database import engine
from database.models import Finding, Evidence
from risk.assess_findings import assess_findings


ASSESSMENT_ID = 1


def take_snapshot():
    with Session(engine) as session:
        findings = session.query(Finding).filter_by(
            assessment_id=ASSESSMENT_ID
        ).order_by(Finding.id).all()

        snapshot = {}

        for finding in findings:
            evidence_ids = [
                row[0]
                for row in session.query(Evidence.id).filter_by(
                    finding_id=finding.id
                ).order_by(Evidence.id).all()
            ]

            snapshot[finding.id] = {
                "title": finding.title,
                "status": finding.status,
                "severity": finding.severity,
                "evidence_ids": evidence_ids,
            }

        return snapshot


def test_risk_persistence():
    before = take_snapshot()

    if not before:
        raise AssertionError(
            "No findings found. Run the existing assessment first."
        )

    print("Running risk assessment...")
    assess_findings()

    after = take_snapshot()

    assert before.keys() == after.keys(), (
        "Finding IDs changed: findings may have been created or removed."
    )

    for finding_id, old in before.items():
        new = after[finding_id]

        assert old["status"] == new["status"], (
            f"Finding {finding_id}: verification status changed."
        )

        assert old["severity"] == new["severity"], (
            f"Finding {finding_id}: final severity changed."
        )

        assert old["evidence_ids"] == new["evidence_ids"], (
            f"Finding {finding_id}: evidence records changed."
        )

    with Session(engine) as session:
        for finding_id in before:
            finding = session.get(Finding, finding_id)

            assert finding.risk_score is not None, (
                f"Finding {finding_id}: risk score was not saved."
            )

            assert finding.risk_severity is not None, (
                f"Finding {finding_id}: risk rating was not saved."
            )

            assert finding.risk_factors is not None, (
                f"Finding {finding_id}: risk factors were not saved."
            )

            assert finding.risk_method == (
                "project_preliminary_risk_v1"
            ), f"Finding {finding_id}: unexpected scoring method."

    print("\nPASS: Finding IDs are unchanged.")
    print("PASS: Verification statuses are unchanged.")
    print("PASS: Final severity values are unchanged.")
    print("PASS: Evidence records are unchanged.")
    print("PASS: Risk assessments are persisted.")
    print("\nAll risk-persistence regression checks passed.")


if __name__ == "__main__":
    test_risk_persistence()
