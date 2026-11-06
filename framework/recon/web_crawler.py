from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class WebCrawler:

    def __init__(
        self,
        base_url,
        max_depth=2,
        timeout=5
    ):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.timeout = timeout

        parsed = urlparse(self.base_url)
        self.allowed_host = parsed.netloc

        self.session = requests.Session()

        self.visited = set()
        self.discovered_endpoints = set()
        self.endpoints = []

        self.authenticated_start_url = None

    def is_in_scope(self, url):
        parsed = urlparse(url)

        return (
            parsed.scheme in ("http", "https")
            and parsed.netloc == self.allowed_host
        )

    def login(self, username, password):

        login_url = urljoin(
            self.base_url,
            "/login"
        )

        try:
            response = self.session.post(
                login_url,
                data={
                    "username": username,
                    "password": password
                },
                timeout=self.timeout,
                allow_redirects=True
            )

        except requests.RequestException as error:
            print(f"Login request failed: {error}")
            return False

        if response.status_code != 200:
            return False

        if response.url == login_url:
            return False

        self.authenticated_start_url = response.url

        return True

    def crawl(self):

        queue = deque()

        start_url = (
            self.authenticated_start_url
            or self.base_url
        )

        queue.append(
            (start_url, 0)
        )

        while queue:

            current_url, depth = queue.popleft()

            if current_url in self.visited:
                continue

            if depth > self.max_depth:
                continue

            if not self.is_in_scope(current_url):
                continue

            self.visited.add(current_url)

            try:
                response = self.session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=True
                )

            except requests.RequestException:
                continue

            parsed_url = urlparse(response.url)

            endpoint = {
                "method": "GET",
                "path": parsed_url.path or "/",
                "status_code": response.status_code,
                "discovered_by": "crawler"
            }

            endpoint_key = (
                endpoint["method"],
                endpoint["path"]
            )

            if endpoint_key not in self.discovered_endpoints:

                self.discovered_endpoints.add(
                    endpoint_key
                )

                self.endpoints.append(endpoint)

            content_type = response.headers.get(
                "Content-Type",
                ""
            )

            if "text/html" not in content_type.lower():
                continue

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            for link in soup.find_all(
                "a",
                href=True
            ):

                next_url = urljoin(
                    response.url,
                    link["href"]
                )

                next_url = next_url.split("#")[0]

                if (
                    self.is_in_scope(next_url)
                    and next_url not in self.visited
                ):
                    queue.append(
                        (next_url, depth + 1)
                    )

        return self.endpoints