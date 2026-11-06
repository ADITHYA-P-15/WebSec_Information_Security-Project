
import unittest

from reporting.generate_report import assess_path_lifecycle


class PathLifecycleTests(unittest.TestCase):
    def assess(self, statuses):
        finding_status_by_id = {
            index: status
            for index, status in enumerate(statuses, start=1)
        }
        finding_ids = list(finding_status_by_id)
        return assess_path_lifecycle(
            finding_ids,
            finding_status_by_id,
        )

    def test_all_candidates(self):
        result = self.assess(["CANDIDATE", "CANDIDATE"])
        self.assertEqual(
            result["lifecycle_assessment"],
            "CANDIDATE_FINDINGS_REMAIN",
        )

    def test_all_remediated(self):
        result = self.assess(["REMEDIATED", "REMEDIATED"])
        self.assertEqual(
            result["lifecycle_assessment"],
            "ALL_LINKED_FINDINGS_REMEDIATED",
        )

    def test_partially_remediated(self):
        result = self.assess(["REMEDIATED", "CANDIDATE"])
        self.assertEqual(
            result["lifecycle_assessment"],
            "PARTIALLY_REMEDIATED",
        )

    def test_reopened_finding_requires_review(self):
        result = self.assess(["REMEDIATED", "REOPENED"])
        self.assertEqual(
            result["lifecycle_assessment"],
            "REVIEW_REQUIRED_REOPENED_FINDING",
        )

    def test_all_verified(self):
        result = self.assess(["VERIFIED", "VERIFIED"])
        self.assertEqual(
            result["lifecycle_assessment"],
            "ALL_LINKED_FINDINGS_VERIFIED",
        )

    def test_no_linked_findings(self):
        result = assess_path_lifecycle([], {})
        self.assertEqual(result["lifecycle_assessment"], "UNLINKED")

    def test_never_claims_exploitability(self):
        result = self.assess(["REMEDIATED"])
        self.assertFalse(result["path_exploitability_confirmed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
