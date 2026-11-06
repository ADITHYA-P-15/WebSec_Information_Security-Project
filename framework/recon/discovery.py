from urllib.parse import urlparse


def normalize_endpoint(
    method,
    url,
    status_code=None,
    discovered_by="unknown"
):
    """
    Convert a discovered URL into the framework's
    canonical endpoint representation.
    """

    method = method.upper().strip()

    parsed = urlparse(url)

    path = parsed.path or "/"

    return {
        "method": method,
        "path": path,
        "status_code": status_code,
        "discovered_by": discovered_by
    }


def normalize_endpoints(
    endpoints,
    discovered_by="unknown"
):
    """
    Normalize and deduplicate a collection of
    discovered endpoint observations.
    """

    normalized = {}

    for endpoint in endpoints:

        method = endpoint.get("method", "GET")

        url = endpoint.get("url")

        if not url:
            continue

        normalized_endpoint = normalize_endpoint(
            method=method,
            url=url,
            status_code=endpoint.get(
                "status_code"
            ),
            discovered_by=endpoint.get(
                "discovered_by",
                discovered_by
            )
        )

        key = (
            normalized_endpoint["method"],
            normalized_endpoint["path"]
        )

        if key not in normalized:

            normalized[key] = normalized_endpoint

    return list(normalized.values())