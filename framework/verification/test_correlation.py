
import unittest
from types import SimpleNamespace

from verification.correlation import correlate_finding


class CorrelationTests(unittest.TestCase):

    def setUp(self):
        self.finding = SimpleNamespace(
            id=99,
            title="ZAP: CSP Header Not Set [Plugin 10038]",
        )

    def evidence(self, evidence_id, evidence_type, data):
        return {
            "evidence_id": evidence_id,
            "evidence_type": evidence_type,
            "data": data,
        }

    def scanner(self, evidence_id=1, **overrides):
        data = {
            "plugin_id": "10038",
            "name": "CSP Header Not Set",
            "url": "http://host.docker.internal:5001/",
            "method": "GET",
        }
        data.update(overrides)
        return self.evidence(
            evidence_id, "zap_alert_instance", data
        )

    def live(self, evidence_id=2, **overrides):
        data = {
            "plugin_id": "10038",
            "reported_url": "http://localhost:5001/",
            "reported_method": "GET",
            "actual_request_method": "GET",
            "verification_method": "ORIGINAL_SAFE_METHOD",
            "triage_category": "OBSERVED_CHARACTERISTIC",
        }
        data.update(overrides)
        return self.evidence(
            evidence_id, "zap_live_verification", data
        )

    def test_matches_same_url_plugin_and_method(self):
        results = correlate_finding(
            self.finding,
            [self.scanner(), self.live()],
        )
        matches = [
            r for r in results
            if r["type"] == "SCANNER_TO_LIVE_CHECK"
        ]
        self.assertEqual(len(matches), 1)

    def test_safe_get_substitute_is_explicit(self):
        results = correlate_finding(
            self.finding,
            [
                self.scanner(method="POST"),
                self.live(
                    reported_method="POST",
                    actual_request_method="GET",
                    verification_method="SAFE_GET_SUBSTITUTE",
                ),
            ],
        )
        matches = [
            r for r in results
            if r["type"] == "SCANNER_TO_LIVE_CHECK"
        ]
        self.assertEqual(len(matches), 1)
        self.assertIn("substitute", matches[0]["match_basis"].lower())
        self.assertIn(
            "original POST response not verified",
            matches[0]["match_basis"],
        )

    def test_rejects_different_urls(self):
        results = correlate_finding(
            self.finding,
            [
                self.scanner(),
                self.live(
                    reported_url="http://localhost:5001/login"
                ),
            ],
        )
        self.assertFalse(any(
            r["type"] == "SCANNER_TO_LIVE_CHECK"
            for r in results
        ))

    def test_rejects_mismatched_plugin(self):
        results = correlate_finding(
            self.finding,
            [
                self.scanner(plugin_id="10020"),
                self.live(plugin_id="10020"),
            ],
        )
        self.assertFalse(any(
            r["type"] == "SCANNER_TO_LIVE_CHECK"
            for r in results
        ))

    def test_repeated_scanner_instances_are_grouped(self):
        results = correlate_finding(
            self.finding,
            [
                self.scanner(1),
                self.scanner(2),
            ],
        )
        repeated = [
            r for r in results
            if r["type"] == "REPEATED_SCANNER_INSTANCE"
        ]
        self.assertEqual(len(repeated), 1)
        self.assertEqual(
            sorted(repeated[0]["evidence_ids"]), [1, 2]
        )


if __name__ == "__main__":
    unittest.main()
