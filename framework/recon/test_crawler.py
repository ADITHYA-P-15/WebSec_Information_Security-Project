from recon.web_crawler import WebCrawler


crawler = WebCrawler(
    base_url="http://localhost:5001",
    max_depth=2
)

endpoints = crawler.crawl()

print("\nDiscovered Endpoints")
print("====================")

for endpoint in endpoints:

    print(
        f"{endpoint['method']} "
        f"{endpoint['path']} "
        f"[{endpoint['status_code']}]"
    )