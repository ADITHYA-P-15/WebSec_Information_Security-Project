
def evaluate_authorization(observations, expected_roles):
    """
    Evaluate role-based endpoint observations.

    This is a policy-based assessment, not a universal
    proof of authorization correctness.
    """
    results = []

    for observation in observations:
        role = observation.get("role")
        status = observation.get("status_code")

        if observation.get("error") or status is None:
            outcome = "INCONCLUSIVE"
            reason = "The request did not produce a usable response."

        elif role in expected_roles:
            if 200 <= status < 300:
                outcome = "EXPECTED_ACCESS_OBSERVED"
                reason = "An allowed role received a successful response."
            else:
                outcome = "UNEXPECTED_RESPONSE"
                reason = (
                    "An allowed role did not receive a successful response."
                )

        elif 200 <= status < 300:
            outcome = "POLICY_MISMATCH_CANDIDATE"
            reason = (
                "A role outside the configured allowlist received "
                "a successful response. Response content and policy "
                "semantics still require review."
            )

        elif status in (401, 403, 301, 302, 303, 307, 308):
            outcome = "ACCESS_RESTRICTED_OBSERVED"
            reason = (
                "The response indicates restricted access or redirection."
            )

        else:
            outcome = "INCONCLUSIVE"
            reason = (
                "The response does not establish whether access "
                "was correctly enforced."
            )

        results.append({
            "role": role,
            "path": observation.get("path"),
            "status_code": status,
            "expected_roles": list(expected_roles),
            "outcome": outcome,
            "reason": reason,
            "verified": False,
        })

    return results


def evaluate_object_ownership(observations):
    """
    Compare authenticated identity with the returned object's owner.

    The authenticated identity must come from trusted test-account
    configuration, not from the response being evaluated.
    """
    results = []

    for observation in observations:
        if observation.get("error"):
            outcome = "INCONCLUSIVE"
            reason = "The request failed."

        else:
            user_id = observation.get("authenticated_user_id")
            owner_id = observation.get("owner_id")
            status = observation.get("status_code")

            if user_id is None or owner_id is None:
                outcome = "INCONCLUSIVE"
                reason = "Authenticated user ID or object owner ID is missing."

            elif status is None or not 200 <= status < 300:
                outcome = "INCONCLUSIVE"
                reason = "A successful object response was not observed."

            elif str(user_id) == str(owner_id):
                outcome = "OWNED_OBJECT_ACCESS_OBSERVED"
                reason = "The returned object owner matches the user."

            else:
                outcome = "CROSS_USER_ACCESS_CANDIDATE"
                reason = (
                    "The returned object owner differs from the "
                    "authenticated user's ID."
                )

        results.append({
            "path": observation.get("path"),
            "object_id": observation.get("object_id"),
            "authenticated_user_id": observation.get(
                "authenticated_user_id"
            ),
            "owner_id": observation.get("owner_id"),
            "outcome": outcome,
            "reason": reason,
            "verified": False,
        })

    return results
