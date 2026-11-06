from recon.web_crawler import WebCrawler


crawler = WebCrawler(
    base_url="http://localhost:5001",
    max_depth=2
)

logged_in = crawler.login(
    username="alice",
    password="alice123"
)

print("Login:", logged_in)

response = crawler.session.get(
    "http://localhost:5001/",
    timeout=5
)

print("Status:", response.status_code)
print("Final URL:", response.url)
print("\nHTML:")
print(response.text)