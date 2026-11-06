from recon.web_crawler import WebCrawler
from recon.save_endpoints import save_endpoints


crawler = WebCrawler(
    base_url="http://localhost:5001",
    max_depth=2
)

role = "user"

logged_in = crawler.login(
    username="alice",
    password="alice123"
)

print(f"Login successful: {logged_in}")
print(f"Role: {role}")

if not logged_in:
    raise RuntimeError(
        "User authentication failed."
    )

endpoints = crawler.crawl()

print("\nUser Endpoints")
print("================")

for endpoint in endpoints:
    print(
        f"{endpoint['method']} "
        f"{endpoint['path']} "
        f"[{endpoint['status_code']}]"
    )

save_endpoints(
    target_id=1,
    endpoints=endpoints,
    role=role
)

print("\nUser endpoints saved successfully.")