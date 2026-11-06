from sqlalchemy.orm import Session

from database.database import engine
from database.models import Assessment, Target


def create_assessment(target_url):

    with Session(engine) as session:

        assessment = Assessment(
            target_url=target_url,
            status="CREATED"
        )

        session.add(assessment)
        session.commit()

        session.refresh(assessment)

        target = Target(
            assessment_id=assessment.id,
            url=target_url,
            status="ACTIVE"
        )

        session.add(target)
        session.commit()

        return assessment.id