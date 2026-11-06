
import hashlib
import json

import requests


class IDORVerifier:
    def __init__(self, base_url, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def inspect_object(
        self,
        session,
        path,
        authenticated_user_id,
        owner_field="user_id",
    ):
        url = f"{self.base_url}{path}"

        try:
            response = session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as error:
            return {
                "path": path,
                "classification": "inconclusive",
                "error": str(error),
            }

        body = response.text

        observation = {
            "path": path,
            "method": "GET",
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "response_bytes": len(response.content),
            "body_sha256": hashlib.sha256(
                response.content
            ).hexdigest(),
            "authenticated_user_id": authenticated_user_id,
            "classification": "inconclusive",
        }

        if not 200 <= response.status_code < 300:
            observation["classification"] = "not_successful"
            return observation

        try:
            data = response.json()
        except ValueError:
            observation["classification"] = "inconclusive"
            observation["reason"] = "Response is not valid JSON."
            return observation

        if not isinstance(data, dict):
            observation["classification"] = "inconclusive"
            observation["reason"] = "Expected a JSON object."
            return observation

        observation["object_id"] = data.get("id")
        observation["owner_id"] = data.get(owner_field)
        observation["body_preview"] = json.dumps(
            data,
            sort_keys=True,
            ensure_ascii=False,
        )[:500]

        owner_id = data.get(owner_field)

        if owner_id is None:
            observation["classification"] = "inconclusive"
            observation["reason"] = (
                f"Owner field '{owner_field}' is missing."
            )
        elif str(owner_id) == str(authenticated_user_id):
            observation["classification"] = "owned_object_access"
        else:
            observation["classification"] = (
                "candidate_cross_user_access"
            )

        return observation
