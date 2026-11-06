from sqlalchemy.orm import Session

from database.database import engine
from database.models import Endpoint, EndpointAccess


def save_endpoints(
    target_id,
    endpoints,
    role="anonymous"
):

    with Session(engine) as session:

        for endpoint_data in endpoints:

            endpoint = session.query(
                Endpoint
            ).filter_by(
                target_id=target_id,
                method=endpoint_data["method"],
                path=endpoint_data["path"]
            ).first()

            if not endpoint:

                endpoint = Endpoint(
                    target_id=target_id,
                    method=endpoint_data["method"],
                    path=endpoint_data["path"],
                    discovered_by=endpoint_data[
                        "discovered_by"
                    ]
                )

                session.add(endpoint)
                session.flush()

            else:

                endpoint.discovered_by = (
                    endpoint_data["discovered_by"]
                )

            access = session.query(
                EndpointAccess
            ).filter_by(
                endpoint_id=endpoint.id,
                role=role
            ).first()

            if access:

                access.status_code = (
                    endpoint_data["status_code"]
                )

                access.discovered_by = (
                    endpoint_data["discovered_by"]
                )

            else:

                access = EndpointAccess(
                    endpoint_id=endpoint.id,
                    role=role,
                    status_code=endpoint_data[
                        "status_code"
                    ],
                    discovered_by=endpoint_data[
                        "discovered_by"
                    ]
                )

                session.add(access)

        session.commit()