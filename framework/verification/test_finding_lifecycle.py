
import json
import unittest

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session

from database.models import (
    Base,
    Assessment,
    Finding,
    Evidence,
    FindingStatusHistory,
)
from verification.finding_lifecycle import transition_finding


class FindingLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(cls.engine)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    def setUp(self):
        with Session(bind=self.engine) as session:
            session.query(Evidence).delete()
            session.query(FindingStatusHistory).delete()
            session.query(Finding).delete()
            session.query(Assessment).delete()

            session.add(Assessment(
                id=1,
                target_url="http://localhost:5001",
                status="CREATED",
            ))
            session.add(Finding(
                id=1,
                assessment_id=1,
                title="Test authorization finding",
                vulnerability_type="BROKEN_ACCESS_CONTROL",
                severity="HIGH",
                description="Test-only finding",
                status="CANDIDATE",
                risk_score=68.8,
                risk_severity="HIGH",
                risk_factors="test",
                risk_method="test",
            ))
            session.commit()

    def add_retest(self, result):
        payload = {
            "source": "REMEDIATION_RETEST",
            "checks": [{"result": result}],
        }
        with Session(bind=self.engine) as session:
            session.add(Evidence(
                finding_id=1,
                evidence_type="remediation_retest",
                data=json.dumps(payload),
            ))
            session.commit()

    def test_candidate_can_be_verified(self):
        result = transition_finding(
            1, "VERIFIED", "Reviewed supporting evidence",
            actor="reviewer", bind=self.engine,
        )
        self.assertEqual(result["previous_status"], "CANDIDATE")
        self.assertEqual(result["new_status"], "VERIFIED")

    def test_candidate_cannot_skip_to_remediated(self):
        with self.assertRaises(ValueError):
            transition_finding(
                1, "REMEDIATED", "Attempt to skip verification",
                actor="reviewer", bind=self.engine,
            )

    def test_remediation_requires_passing_retest(self):
        transition_finding(
            1, "VERIFIED", "Evidence reviewed",
            actor="reviewer", bind=self.engine,
        )
        with self.assertRaises(ValueError):
            transition_finding(
                1, "REMEDIATED", "Retest evidence is missing",
                actor="reviewer", bind=self.engine,
            )

    def test_passing_retest_allows_remediation(self):
        transition_finding(
            1, "VERIFIED", "Evidence reviewed",
            actor="reviewer", bind=self.engine,
        )
        self.add_retest("PASS")
        result = transition_finding(
            1, "REMEDIATED", "All remediation checks passed",
            actor="reviewer", bind=self.engine,
        )
        self.assertEqual(result["new_status"], "REMEDIATED")

    def test_failed_retest_allows_reopening(self):
        transition_finding(
            1, "VERIFIED", "Evidence reviewed",
            actor="reviewer", bind=self.engine,
        )
        self.add_retest("PASS")
        transition_finding(
            1, "REMEDIATED", "Initial retest passed",
            actor="reviewer", bind=self.engine,
        )
        self.add_retest("FAIL")
        result = transition_finding(
            1, "REOPENED", "Regression detected on retest",
            actor="reviewer", bind=self.engine,
        )
        self.assertEqual(result["new_status"], "REOPENED")

    def test_transition_requires_reason(self):
        with self.assertRaises(ValueError):
            transition_finding(
                1, "VERIFIED", " ",
                actor="reviewer", bind=self.engine,
            )

    def test_history_is_recorded_and_risk_is_unchanged(self):
        transition_finding(
            1, "VERIFIED", "Evidence reviewed",
            actor="reviewer", bind=self.engine,
        )
        with Session(bind=self.engine) as session:
            finding = session.get(Finding, 1)
            history = session.query(FindingStatusHistory).all()

            self.assertEqual(finding.status, "VERIFIED")
            self.assertEqual(finding.risk_score, 68.8)
            self.assertEqual(finding.risk_severity, "HIGH")
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0].previous_status, "CANDIDATE")
            self.assertEqual(history[0].new_status, "VERIFIED")
            self.assertEqual(history[0].actor, "reviewer")


if __name__ == "__main__":
    unittest.main(verbosity=2)
