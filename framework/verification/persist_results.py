
import json

from sqlalchemy.orm import Session

from database.database import engine
from database.models import Evidence, Finding


def persist_verification_results(finding_id, results):
    added = 0

    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if finding is None:
            raise ValueError(f"Finding {finding_id} does not exist.")

        for result in results:
            evidence_data = json.dumps(
                result,
                sort_keys=True,
                ensure_ascii=False,
            )

            existing = session.query(Evidence).filter_by(
                finding_id=finding_id,
                evidence_type="verification_result",
                data=evidence_data,
            ).first()

            if existing:
                continue

            session.add(
                Evidence(
                    finding_id=finding_id,
                    evidence_type="verification_result",
                    data=evidence_data,
                )
            )
            added += 1

        # Deliberately do not change finding status, severity,
        # risk fields, or attack paths.
        session.commit()

        return {
            "finding_id": finding_id,
            "results_supplied": len(results),
            "evidence_added": added,
            "status": finding.status,
            "severity": finding.severity,
        }
