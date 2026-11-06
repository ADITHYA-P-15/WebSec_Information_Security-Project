from recon.api_discovery import APIDiscoverer


discoverer = APIDiscoverer(
    base_url="http://localhost:5001"
)


candidate_paths = [
    "/orders",
    "/api/orders/1",
    "/admin/users",
    "/api/admin/reports"
]


logged_in = discoverer.login(
    username="alice",
    password="alice123"
)

print(
    f"Login successful: {logged_in}"
)


if not logged_in:

    raise RuntimeError(
        "User authentication failed."
    )


results = discoverer.probe(
    candidate_paths,
    role="user"
)


print("\nAuthenticated API Discovery")
print("============================")

for result in results:

    print(
        f"{result['method']} "
        f"{result['url']} "
        f"[{result['status_code']}] "
        f"{result['classification']} "
        f"role={result['role']}"
    )