from recon.discovery import normalize_endpoints


raw_endpoints = [

    {
        "method": "GET",
        "url": "http://localhost:5001/profile",
        "status_code": 200,
        "discovered_by": "crawler"
    },

    {
        "method": "GET",
        "url": "http://localhost:5001/profile",
        "status_code": 200,
        "discovered_by": "zap"
    },

    {
        "method": "GET",
        "url": "http://localhost:5001/orders",
        "status_code": 200,
        "discovered_by": "api_discovery"
    },

    {
        "method": "POST",
        "url": "http://localhost:5001/api/orders",
        "status_code": 201,
        "discovered_by": "api_discovery"
    }
]


endpoints = normalize_endpoints(
    raw_endpoints
)


print("\nNormalized Endpoints")
print("====================")

for endpoint in endpoints:

    print(
        f"{endpoint['method']} "
        f"{endpoint['path']} "
        f"[{endpoint['status_code']}] "
        f"via {endpoint['discovered_by']}"
    )