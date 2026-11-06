
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from database.database import engine
from database.models import Evidence, Finding, FindingStatusHistory


VALID_TRANSITIONS = {
    "CANDIDATE": {"VERIFIED"},
    "VERIFIED": {"REMEDIATED"},
    "REMEDIATED": {"REOPENED"},
    "REOPENED": {"VERIFIED"},
}


def latest_retest_outcome(session, finding_id):
    """Return PASS, FAIL, or INCONCLUSIVE for the newest retest."""

    records = (
        session.query(Evidence)
        .filter_by(
            finding_id=finding_id,
            evidence_type="remediation_retest",
        )
        .order_by(Evidence.id.desc())
        .all()
    )

    for record in records:
        try:
            data = json.loads(record.data or "{}")
        except (TypeError, json.JSONDecodeError):
            continue

        if data.get("source") != "REMEDIATION_RETEST":
            continue

        checks = data.get("checks", [])
        if not checks:
            return "INCONCLUSIVE"

        results = [check.get("result") for check in checks]

        if all(result == "PASS" for result in results):
            return "PASS"

        if any(result == "FAIL" for result in results):
            return "FAIL"

        return "INCONCLUSIVE"

    return "INCONCLUSIVE"


def transition_finding(
    finding_id,
    new_status,
    reason,
    actor="manual_review",
    evidence_ids=None,
    bind=engine,
):
    """Validate, record, and apply one finding status transition."""

    new_status = new_status.strip().upper()
    reason = reason.strip() if reason else ""
    actor = actor.strip() if actor else ""

    if not reason:
        raise ValueError("A transition reason is required.")

    if not actor:
        raise ValueError("An actor is required.")

    with Session(bind=bind) as session:
        finding = session.get(Finding, finding_id)

        if finding is None:
            raise ValueError(f"Finding {finding_id} does not exist.")

        previous_status = (finding.status or "").upper()

        allowed = VALID_TRANSITIONS.get(previous_status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Invalid transition: {previous_status} -> {new_status}"
            )

        if new_status == "REMEDIATED":
            outcome = latest_retest_outcome(session, finding.id)
            if outcome != "PASS":
                raise ValueError(
                    "Remediation requires a successful persisted retest. "
                    f"Latest retest outcome: {outcome}"
                )

        if new_status == "REOPENED":
            outcome = latest_retest_outcome(session, finding.id)
            if outcome != "FAIL":
                raise ValueError(
                    "Reopening requires a failed persisted retest. "
                    f"Latest retest outcome: {outcome}"
                )

        linked_evidence_ids = evidence_ids or []
        if not isinstance(linked_evidence_ids, list):
            raise ValueError("evidence_ids must be a list of evidence IDs.")

        if linked_evidence_ids:
            found_ids = {
                item.id
                for item in session.query(Evidence.id).filter(
                    Evidence.finding_id == finding.id,
                    Evidence.id.in_(linked_evidence_ids),
                ).all()
            }
            if found_ids != set(linked_evidence_ids):
                raise ValueError(
                    "Every linked evidence ID must belong to this finding."
                )

        history = FindingStatusHistory(
            finding_id=finding.id,
            previous_status=previous_status,
            new_status=new_status,
            reason=reason,
            actor=actor,
            evidence_ids=json.dumps(
                linked_evidence_ids,
                sort_keys=True,
            ),
            transitioned_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )

        finding.status = new_status
        session.add(history)
        session.commit()

        return {
            "finding_id": finding.id,
            "previous_status": previous_status,
            "new_status": new_status,
            "history_id": history.id,
            "actor": actor,
            "reason": reason,
        }
