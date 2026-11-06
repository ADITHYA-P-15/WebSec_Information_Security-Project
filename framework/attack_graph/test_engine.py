
import json

from sqlalchemy.orm import Session

from database.database import engine
from database.models import AttackPath
from attack_graph.engine import generate_attack_paths


ASSESSMENT_ID = 1


def main():
    generate_attack_paths(ASSESSMENT_ID)

    with Session(engine) as session:
        paths = (
            session.query(AttackPath)
            .filter_by(assessment_id=ASSESSMENT_ID)
            .order_by(AttackPath.id)
            .all()
        )

        print("\nSTORED ATTACK PATHS")
        print("===================")

        for path in paths:
            print(f"\nPath ID: {path.id}")
            print(f"Name: {path.name}")
            print(f"Preliminary severity: {path.severity}")

            try:
                data = json.loads(path.description)
            except (ValueError, TypeError):
                print("Invalid path description JSON.")
                continue

            print(f"Status: {data.get('path_status')}")
            print(f"Type: {data.get('path_type')}")
            print(f"Finding ID: {data.get('finding_id')}")
            print(f"Evidence IDs: {data.get('evidence_ids')}")
            print(f"Explanation: {data.get('explanation')}")

            print("Nodes:")
            for node in data.get("nodes", []):
                print(f"  - {node}")

            print("Edges:")
            for edge in data.get("edges", []):
                print(f"  - {edge}")


if __name__ == "__main__":
    main()
