from recon.web_crawler import WebCrawler


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

if logged_in:

    endpoints = crawler.crawl()

    print("\nAuthenticated Endpoints")
    print("=======================")

    for endpoint in endpoints:

        print(
            f"{endpoint['method']} "
            f"{endpoint['path']} "
            f"[{endpoint['status_code']}]"
        )