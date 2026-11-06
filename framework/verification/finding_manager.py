
import json

from sqlalchemy.orm import Session

from database.database import engine
from database.models import Finding, Evidence


def record_finding(
    assessment_id,
    title,
    vulnerability_type,
    description,
    evidence_items,
    severity="UNASSESSED",
    status="CANDIDATE",
):
    """
    Create or reuse a finding and attach new evidence.

    Repeated runs reuse the same finding and do not
    insert duplicate evidence records.
    """

    with Session(engine) as session:
        finding = session.query(Finding).filter_by(
            assessment_id=assessment_id,
            title=title,
            vulnerability_type=vulnerability_type,
        ).first()

        created = finding is None

        if created:
            finding = Finding(
                assessment_id=assessment_id,
                title=title,
                vulnerability_type=vulnerability_type,
                severity=severity,
                description=description,
                status=status,
            )
            session.add(finding)
            session.flush()

        else:
            # Refresh descriptive information without
            # downgrading an existing finding's status.
            finding.description = description

            if finding.severity == "UNASSESSED":
                finding.severity = severity

        evidence_added = 0

        for item in evidence_items:
            evidence_data = json.dumps(
                item["data"],
                sort_keys=True,
                ensure_ascii=False,
            )

            existing_evidence = session.query(Evidence).filter_by(
                finding_id=finding.id,
                evidence_type=item["evidence_type"],
                data=evidence_data,
            ).first()

            if existing_evidence:
                continue

            session.add(
                Evidence(
                    finding_id=finding.id,
                    evidence_type=item["evidence_type"],
                    data=evidence_data,
                )
            )

            evidence_added += 1

        session.commit()

        return {
            "finding_id": finding.id,
            "created": created,
            "evidence_added": evidence_added,
            "status": finding.status,
        }
