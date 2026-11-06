
import unittest
from types import SimpleNamespace

from verification.correlation import correlate_findings


class CrossFindingCorrelationTests(unittest.TestCase):

    def finding(self, finding_id, title, vulnerability_type):
        return SimpleNamespace(
            id=finding_id,
            title=title,
            vulnerability_type=vulnerability_type,
        )

    def evidence(self, evidence_id, evidence_type, data):
        return {
            "evidence_id": evidence_id,
            "evidence_type": evidence_type,
            "data": data,
        }

    def test_links_matching_scanner_and_authorization_endpoint(self):
        scanner = self.finding(
            10, "ZAP: Example [Plugin 10038]",
            "SECURITY_MISCONFIGURATION",
        )
        authorization = self.finding(
            20, "Broken Access Control: GET /admin/users",
            "BROKEN_ACCESS_CONTROL",
        )

        evidence = {
            10: [self.evidence(
                101, "zap_alert_instance",
                {"plugin_id": "10038",
                 "url": "http://localhost:5001/admin/users",
                 "method": "GET"},
            )],
            20: [self.evidence(
                201, "authorization_observation",
                {"path": "/admin/users", "role": "user",
                 "status_code": 200},
            )],
        }

        results = correlate_findings(
            [scanner, authorization], evidence
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0]["type"], "AUTHORIZATION_SCANNER_CORRELATION"
        )
        self.assertEqual(results[0]["endpoint"], "/admin/users")
        self.assertFalse(results[0]["verified_relationship"])

    def test_different_endpoints_do_not_link(self):
        scanner = self.finding(
            10, "ZAP: Example [Plugin 10038]",
            "SECURITY_MISCONFIGURATION",
        )
        authorization = self.finding(
            20, "Broken Access Control",
            "BROKEN_ACCESS_CONTROL",
        )

        evidence = {
            10: [self.evidence(
                101, "zap_alert_instance",
                {"url": "http://localhost:5001/login"},
            )],
            20: [self.evidence(
                201, "authorization_observation",
                {"path": "/admin/users"},
            )],
        }

        self.assertEqual(
            correlate_findings([scanner, authorization], evidence), []
        )

    def test_unrelated_finding_types_do_not_link(self):
        first = self.finding(
            10, "ZAP: Example [Plugin 10038]",
            "SECURITY_MISCONFIGURATION",
        )
        second = self.finding(
            20, "Another issue", "SECURITY_MISCONFIGURATION"
        )

        self.assertEqual(
            correlate_findings([first, second], {}), []
        )


if __name__ == "__main__":
    unittest.main()
