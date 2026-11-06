TARGET_URL = "http://localhost:5001"

DATABASE_URL = "sqlite:///assessment.db"

PROJECT_NAME = "Web Application Security Assessment Framework"

# Accounts seeded by the local demonstration target. Keep credentials demo-only.
DEMO_ROLES = {
    "user": {"username": "alice", "password": "alice123"},
    "admin": {"username": "admin", "password": "admin123"},
}

AUTHORIZATION_POLICIES = {
    "/admin/users": ["admin"],
    "/admin/lab/users": ["admin"],
    "/admin/orders": ["admin"],
    "/api/admin/reports": ["admin"],
}

API_CANDIDATE_PATHS = [
    "/api/profile",
    "/api/orders/1",
    "/api/orders/insecure/1",
    "/admin/users",
    "/admin/lab/users",
    "/api/admin/reports",
    "/admin/orders",
    "/api/products/search",
    "/api/products/search/secure",
    "/products/preview/secure",
    "/account/preferences",
    "/account/preferences/secure",
    "/api/files/download",
    "/api/files/download/secure",
    "/reviews",
    "/reviews/secure",
    "/products/dom-preview",
    "/products/dom-preview/secure",
]
