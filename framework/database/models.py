from datetime import datetime, timezone


def utcnow_naive():
    """Return current UTC time as a naive datetime for existing DB columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Float
)

from sqlalchemy.orm import declarative_base, relationship


Base = declarative_base()


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True)

    target_url = Column(
        String(500),
        nullable=False
    )

    status = Column(
        String(50),
        default="CREATED"
    )

    created_at = Column(
        DateTime,
        default=utcnow_naive
    )

    targets = relationship(
        "Target",
        back_populates="assessment"
    )

    stages = relationship("AssessmentStage", back_populates="assessment")


class AssessmentStage(Base):
    """Execution record for one phase of an assessment workflow."""
    __tablename__ = "assessment_stages"

    id = Column(Integer, primary_key=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    status = Column(String(30), nullable=False)
    details = Column(Text)
    started_at = Column(DateTime, default=utcnow_naive, nullable=False)
    finished_at = Column(DateTime)

    assessment = relationship("Assessment", back_populates="stages")


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=False
    )

    url = Column(
        String(500),
        nullable=False
    )

    status = Column(
        String(50),
        default="ACTIVE"
    )

    assessment = relationship(
        "Assessment",
        back_populates="targets"
    )


class Asset(Base):
    __tablename__ = "assets"

    id = Column(
        Integer,
        primary_key=True
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=False
    )

    host = Column(
        String(255),
        nullable=False
    )

    port = Column(Integer)

    protocol = Column(String(20))

    state = Column(String(50))

    service = Column(String(100))

    version = Column(String(255))

    discovered_by = Column(String(100))


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(
        Integer,
        primary_key=True
    )

    target_id = Column(
        Integer,
        ForeignKey("targets.id"),
        nullable=False
    )

    method = Column(
        String(20),
        nullable=False
    )

    path = Column(
        String(500),
        nullable=False
    )

    discovered_by = Column(
        String(100)
    )

class EndpointAccess(Base):
    __tablename__ = "endpoint_access"

    id = Column(
        Integer,
        primary_key=True
    )

    endpoint_id = Column(
        Integer,
        ForeignKey("endpoints.id"),
        nullable=False
    )

    role = Column(
        String(50),
        nullable=False
    )

    status_code = Column(Integer)

    discovered_by = Column(
        String(100)
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(
        Integer,
        primary_key=True
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=False
    )

    title = Column(
        String(255),
        nullable=False
    )

    vulnerability_type = Column(String(100))

    # Existing finding severity and verification status
    severity = Column(String(50))

    description = Column(Text)

    status = Column(
        String(50),
        default="OPEN"
    )

    # Preliminary risk assessment fields
    risk_score = Column(Float)

    risk_severity = Column(String(50))

    risk_factors = Column(Text)

    risk_method = Column(String(100))

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(
        Integer,
        primary_key=True
    )

    finding_id = Column(
        Integer,
        ForeignKey("findings.id"),
        nullable=False
    )

    evidence_type = Column(String(100))

    data = Column(Text)

    created_at = Column(
        DateTime,
        default=utcnow_naive
    )


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(
        Integer,
        primary_key=True
    )

    assessment_id = Column(
        Integer,
        ForeignKey("assessments.id"),
        nullable=False
    )

    name = Column(String(255))

    description = Column(Text)

    severity = Column(String(50))

class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"

    id = Column(Integer, primary_key=True)
    finding_id = Column(
        Integer,
        ForeignKey("findings.id"),
        nullable=False,
        index=True,
    )
    previous_status = Column(String(50), nullable=False)
    new_status = Column(String(50), nullable=False)
    reason = Column(Text, nullable=False)
    actor = Column(String(100), nullable=False, default="manual_review")
    evidence_ids = Column(Text, nullable=False, default="[]")
    transitioned_at = Column(
        DateTime,
        nullable=False,
        default=utcnow_naive,
    )
