
import hashlib
from urllib.parse import urljoin

import requests


class AuthorizationVerifier:

    def __init__(self, base_url, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def create_authenticated_session(self, username, password):
        session = requests.Session()
        login_url = urljoin(self.base_url + "/", "login")

        try:
            response = session.post(
                login_url,
                data={
                    "username": username,
                    "password": password,
                },
                timeout=self.timeout,
                allow_redirects=True,
            )

        except requests.RequestException as error:
            session.close()
            raise RuntimeError(
                f"Login request failed for {username}: {error}"
            ) from error

        if response.status_code != 200 or response.url == login_url:
            session.close()
            raise RuntimeError(
                f"Could not authenticate as {username}."
            )

        return session

    def inspect_endpoint(self, session, path, role):
        url = urljoin(self.base_url + "/", path.lstrip("/"))

        try:
            response = session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
            )

        except requests.RequestException as error:
            return {
                "role": role,
                "path": path,
                "error": str(error),
                "classification": "request_error",
            }

        body = response.content

        return {
            "role": role,
            "path": path,
            "status_code": response.status_code,
            "content_type": response.headers.get(
                "Content-Type", ""
            ),
            "response_bytes": len(body),
            "redirect_location": response.headers.get("Location"),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_preview": response.text[:500],
            "classification": "observed",
        }

    def compare_roles(
        self,
        path,
        observations,
        expected_roles,
    ):
        results = []

        for observation in observations:
            role = observation["role"]
            status = observation.get("status_code")

            if "error" in observation:
                classification = "inconclusive"

            elif role in expected_roles and status is not None:
                classification = (
                    "expected_access"
                    if 200 <= status < 300
                    else "unexpected_response"
                )

            elif status in (401, 403, 301, 302, 303, 307, 308):
                classification = "access_restricted"

            elif status is not None and 200 <= status < 300:
                classification = "candidate_unexpected_access"

            else:
                classification = "inconclusive"

            results.append({
                **observation,
                "expected_roles": expected_roles,
                "classification": classification,
                "verified": False,
            })

        return results


def run_role_aware_assessment(assessment_id, base_url, accounts, policies):
    """Run safe role and object-ownership GET checks for one assessment."""
    from verification.finding_manager import record_finding
    from verification.idor_verifier import IDORVerifier

    verifier = AuthorizationVerifier(base_url)
    idor_verifier = IDORVerifier(base_url)
    sessions = {"anonymous": requests.Session()}
    summaries = {"authorization_candidates": 0, "idor_candidate": False}

    try:
        for role, credentials in accounts.items():
            sessions[role] = verifier.create_authenticated_session(
                credentials["username"],
                credentials["password"],
            )

        for path, expected_roles in policies.items():
            observations = [
                verifier.inspect_endpoint(sessions[role], path, role)
                for role in sessions
            ]
            evaluations = verifier.compare_roles(
                path=path,
                observations=observations,
                expected_roles=expected_roles,
            )
            candidates = [
                item for item in evaluations
                if item["classification"] == "candidate_unexpected_access"
                and isinstance(item.get("status_code"), int)
                and 200 <= item["status_code"] < 300
            ]

            for candidate in candidates:
                evidence_items = [
                    {"evidence_type": "authorization_observation", "data": item}
                    for item in observations
                ]
                evidence_items.append({
                    "evidence_type": "authorization_policy",
                    "data": {
                        "endpoint": path,
                        "expected_roles": expected_roles,
                        "unexpected_role": candidate["role"],
                        "verification": "candidate_only",
                    },
                })
                record_finding(
                    assessment_id=assessment_id,
                    title=f"Broken Access Control: GET {path}",
                    vulnerability_type="BROKEN_ACCESS_CONTROL",
                    description=(
                        f"Role '{candidate['role']}' received a successful response from "
                        f"{path}, although the configured policy allows only "
                        f"{', '.join(expected_roles)}. This observation remains a candidate."
                    ),
                    evidence_items=evidence_items,
                    severity="UNASSESSED",
                    status="CANDIDATE",
                )
                summaries["authorization_candidates"] += 1

        # Resolve the authenticated identity and object IDs from the target;
        # fixtures may change their primary keys over time.
        alice_session = sessions.get("user")
        admin_session = sessions.get("admin")
        if alice_session is not None and admin_session is not None:
            profile_response = alice_session.get(
                f"{base_url.rstrip('/')}/profile",
                timeout=5,
                allow_redirects=False,
            )
            own_orders_response = alice_session.get(
                f"{base_url.rstrip('/')}/orders",
                timeout=5,
                allow_redirects=False,
            )
            all_orders_response = admin_session.get(
                f"{base_url.rstrip('/')}/admin/orders",
                timeout=5,
                allow_redirects=False,
            )

            if all(
                response.status_code == 200
                for response in (profile_response, own_orders_response, all_orders_response)
            ):
                try:
                    profile = profile_response.json()
                    own_orders = own_orders_response.json()
                    all_orders = all_orders_response.json()
                    user_id = profile.get("id") if isinstance(profile, dict) else None
                    own_orders = own_orders if isinstance(own_orders, list) else []
                    all_orders = all_orders if isinstance(all_orders, list) else []
                except (ValueError, AttributeError):
                    user_id = None
                    own_orders = []
                    all_orders = []

                own = next(
                    (
                        item for item in own_orders
                        if isinstance(item, dict) and item.get("id") is not None
                    ),
                    None,
                )
                foreign = next(
                    (
                        item for item in all_orders
                        if isinstance(item, dict)
                        if item.get("id") is not None
                        and str(item.get("user_id")) != str(user_id)
                    ),
                    None,
                )
                if user_id is not None and own and foreign:
                    observations = [
                        idor_verifier.inspect_object(
                            alice_session,
                            f"/api/orders/insecure/{order['id']}",
                            authenticated_user_id=user_id,
                        )
                        for order in (own, foreign)
                    ]
                    if (
                        observations[0]["classification"] == "owned_object_access"
                        and observations[1]["classification"] == "candidate_cross_user_access"
                    ):
                        evidence_items = [
                            {"evidence_type": "idor_ownership_observation", "data": item}
                            for item in observations
                        ]
                        record_finding(
                            assessment_id=assessment_id,
                            title="IDOR/BOLA: GET /api/orders/insecure/{order_id}",
                            vulnerability_type="IDOR_BOLA",
                            description=(
                                "The authenticated user retrieved an order whose owner differs "
                                "from the authenticated identity. The comparison is evidence-backed "
                                "and remains a candidate pending policy review."
                            ),
                            evidence_items=evidence_items,
                            severity="UNASSESSED",
                            status="CANDIDATE",
                        )
                        summaries["idor_candidate"] = True
    finally:
        for client in sessions.values():
            client.close()

    return (
        f"Role checks complete: {summaries['authorization_candidates']} authorization "
        f"candidates; IDOR candidate={summaries['idor_candidate']}."
    )
