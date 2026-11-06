
import json

from sqlalchemy.orm import Session

from database.database import engine
from database.models import AttackPath
from attack_graph.engine import generate_attack_paths


ASSESSMENT_ID = 1


def snapshot_paths():
    with Session(engine) as session:
        paths = (
            session.query(AttackPath)
            .filter_by(assessment_id=ASSESSMENT_ID)
            .order_by(AttackPath.id)
            .all()
        )

        snapshot = {}

        for path in paths:
            data = json.loads(path.description)

            snapshot[path.name] = {
                "id": path.id,
                "severity": path.severity,
                "status": data.get("path_status"),
                "finding_id": data.get("finding_id"),
                "evidence_ids": sorted(data.get("evidence_ids", [])),
            }

        return snapshot


def main():
    print("Capturing initial attack paths...")
    before = snapshot_paths()

    if not before:
        raise AssertionError(
            "No attack paths found. Run the attack-path engine first."
        )

    print("\nRegenerating attack paths...")
    generate_attack_paths(ASSESSMENT_ID)

    after = snapshot_paths()

    original_names = set(before.keys())
    updated_names = set(after.keys())
    assert original_names == updated_names, (
        "Path names changed; paths may have been added or removed."
    )


    assert original_names == updated_names, (
        "Path names changed; paths may have been added or removed."
    )

    for name, old in before.items():
        new = after[name]

        assert old["id"] == new["id"], (
            f"{name}: path ID changed."
        )

        assert old["severity"] == new["severity"], (
            f"{name}: preliminary severity changed."
        )

        assert old["status"] == new["status"], (
            f"{name}: path status changed."
        )

        assert old["finding_id"] == new["finding_id"], (
            f"{name}: linked finding changed."
        )

        assert old["evidence_ids"] == new["evidence_ids"], (
            f"{name}: evidence references changed."
        )

    print("\nPASS: No duplicate paths created.")
    print("PASS: Path IDs remained stable.")
    print("PASS: Preliminary severities remained stable.")
    print("PASS: Candidate statuses remained unchanged.")
    print("PASS: Finding and evidence references remained stable.")
    print("\nAll attack-path persistence checks passed.")


if __name__ == "__main__":
    main()
