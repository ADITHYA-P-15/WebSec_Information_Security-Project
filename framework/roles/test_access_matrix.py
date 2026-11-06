from roles.access_matrix import build_access_matrix


matrix = build_access_matrix(
    target_id=1
)

print("\nAccess Matrix")
print("=============")

for endpoint, roles in matrix.items():

    method, path = endpoint

    print(f"\n{method} {path}")

    for role, status in roles.items():

        print(
            f"  {role}: {status}"
        )