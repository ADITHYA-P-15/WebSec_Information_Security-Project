from recon.web_crawler import WebCrawler
from recon.save_endpoints import save_endpoints


crawler = WebCrawler(
    base_url="http://localhost:5001",
    max_depth=2
)

role = "admin"

logged_in = crawler.login(
    username="admin",
    password="admin123"
)

print(f"Login successful: {logged_in}")
print(f"Role: {role}")

if not logged_in:
    raise RuntimeError(
        "Admin authentication failed."
    )

endpoints = crawler.crawl()

print("\nAdmin Endpoints")
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

print("\nAdmin endpoints saved successfully.")