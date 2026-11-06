from sqlalchemy.orm import Session

from database.database import engine
from database.models import Endpoint, EndpointAccess


with Session(engine) as session:

    endpoints = session.query(
        Endpoint
    ).order_by(
        Endpoint.id
    ).all()

    canonical = {}

    removed = 0

    for endpoint in endpoints:

        key = (
            endpoint.target_id,
            endpoint.method,
            endpoint.path
        )

        if key not in canonical:

            canonical[key] = endpoint
            continue

        canonical_endpoint = canonical[key]

        accesses = session.query(
            EndpointAccess
        ).filter_by(
            endpoint_id=endpoint.id
        ).all()

        for access in accesses:

            existing_access = session.query(
                EndpointAccess
            ).filter_by(
                endpoint_id=canonical_endpoint.id,
                role=access.role
            ).first()

            if existing_access:

                existing_access.status_code = (
                    access.status_code
                )

                existing_access.discovered_by = (
                    access.discovered_by
                )

            else:

                access.endpoint_id = (
                    canonical_endpoint.id
                )

        session.delete(endpoint)

        removed += 1

    session.commit()

print(
    f"Endpoint cleanup completed. "
    f"Removed {removed} duplicate endpoint(s)."
)