
from verification.results import (
    evaluate_authorization,
    evaluate_object_ownership,
)


def main():
    authorization_cases = [
        {
            "role": "user",
            "path": "/admin/users",
            "status_code": 200,
        },
        {
            "role": "admin",
            "path": "/admin/users",
            "status_code": 200,
        },
        {
            "role": "user",
            "path": "/api/admin/reports",
            "status_code": 403,
        },
        {
            "role": "user",
            "path": "/unknown",
            "error": "Connection timed out",
        },
    ]

    print("AUTHORIZATION RESULTS")
    print("=====================")

    for result in evaluate_authorization(
        authorization_cases,
        expected_roles=["admin"],
    ):
        print(
            f"{result['path']} | {result['role']} | "
            f"{result['outcome']} | verified={result['verified']}"
        )

    ownership_cases = [
        {
            "path": "/api/orders/1",
            "status_code": 200,
            "authenticated_user_id": 2,
            "owner_id": 2,
            "object_id": 1,
        },
        {
            "path": "/api/orders/3",
            "status_code": 200,
            "authenticated_user_id": 2,
            "owner_id": 3,
            "object_id": 3,
        },
    ]

    print("\nOWNERSHIP RESULTS")
    print("=================")

    for result in evaluate_object_ownership(ownership_cases):
        print(
            f"{result['path']} | {result['outcome']} | "
            f"verified={result['verified']}"
        )


if __name__ == "__main__":
    main()
