import unittest

import requests

from config import TARGET_URL


class RemediationRegressionTests(unittest.TestCase):
    """Integration tests against the controlled local security target."""

    @classmethod
    def setUpClass(cls):
        cls.base_url = TARGET_URL.rstrip("/")
        cls.sessions = {}

        for identity, credentials in {
            "alice": ("alice", "alice123"),
            "admin": ("admin", "admin123"),
        }.items():
            session = requests.Session()
            response = session.post(
                f"{cls.base_url}/login",
                data={
                    "username": credentials[0],
                    "password": credentials[1],
                },
                allow_redirects=False,
                timeout=5,
            )
            if response.status_code != 302:
                session.close()
                raise RuntimeError(
                    f"Could not authenticate {identity}: "
                    f"HTTP {response.status_code}"
                )
            cls.sessions[identity] = session

        cls.anonymous = requests.Session()

    @classmethod
    def tearDownClass(cls):
        cls.anonymous.close()
        for session in cls.sessions.values():
            session.close()

    def test_anonymous_cannot_access_admin_routes(self):
        for path in ("/admin/users", "/api/admin/reports"):
            with self.subTest(path=path):
                response = self.anonymous.get(
                    f"{self.base_url}{path}",
                    allow_redirects=False,
                    timeout=5,
                )
                self.assertEqual(response.status_code, 302)

    def test_regular_user_is_forbidden_from_admin_routes(self):
        for path in ("/admin/users", "/api/admin/reports"):
            with self.subTest(path=path):
                response = self.sessions["alice"].get(
                    f"{self.base_url}{path}",
                    allow_redirects=False,
                    timeout=5,
                )
                self.assertEqual(response.status_code, 403)

    def test_admin_retains_access_to_admin_routes(self):
        for path in ("/admin/users", "/api/admin/reports"):
            with self.subTest(path=path):
                response = self.sessions["admin"].get(
                    f"{self.base_url}{path}",
                    allow_redirects=False,
                    timeout=5,
                )
                self.assertEqual(response.status_code, 200)

    def test_alice_can_access_her_own_order(self):
        response = self.sessions["alice"].get(
            f"{self.base_url}/api/orders/1",
            timeout=5,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get("user_id"), 2)

    
    def test_alice_cannot_access_bobs_order(self):
        """Verify Alice cannot access Bob's order."""
        response = self.sessions["alice"].get(
            f"{self.base_url}/api/orders/3",
            timeout=5,
        )
        self.assertIn(response.status_code, (403, 404))


if __name__ == "__main__":
    unittest.main(verbosity=2)
