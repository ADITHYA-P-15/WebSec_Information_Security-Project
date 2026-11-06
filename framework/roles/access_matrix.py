from collections import defaultdict

from sqlalchemy.orm import Session

from database.database import engine
from database.models import Endpoint, EndpointAccess


def build_access_matrix(target_id):

    with Session(engine) as session:

        endpoints = session.query(
            Endpoint
        ).filter_by(
            target_id=target_id
        ).all()

        matrix = defaultdict(dict)

        for endpoint in endpoints:

            accesses = session.query(
                EndpointAccess
            ).filter_by(
                endpoint_id=endpoint.id
            ).all()

            key = (
                endpoint.method,
                endpoint.path
            )

            for access in accesses:

                matrix[key][
                    access.role
                ] = access.status_code

        return matrix