import requests


class APIDiscoverer:

    def __init__(
        self,
        base_url,
        timeout=5
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self.session = requests.Session()

    def classify_status(self, status_code):

        if 200 <= status_code < 300:
            return "accessible"

        if status_code in (301, 302, 303, 307, 308):
            return "redirect"

        if status_code in (401, 403):
            return "restricted"

        if status_code == 404:
            return "not_found"

        if 400 <= status_code < 500:
            return "client_error"

        if 500 <= status_code < 600:
            return "server_error"

        return "unknown"

    def login(
        self,
        username,
        password
    ):

        login_url = f"{self.base_url}/login"

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

            print(
                f"Login request failed: {error}"
            )

            return False

        if response.status_code != 200:
            return False

        if response.url == login_url:
            return False

        return True

    def probe(
        self,
        paths,
        role="anonymous"
    ):

        discovered = []

        for path in paths:

            url = f"{self.base_url}{path}"

            try:

                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False
                )

            except requests.RequestException:

                continue

            classification = self.classify_status(
                response.status_code
            )

            if classification == "not_found":
                continue

            discovered.append({
                "method": "GET",
                "url": url,
                "status_code": response.status_code,
                "classification": classification,
                "role": role,
                "discovered_by": "api_discovery"
            })

        return discovered