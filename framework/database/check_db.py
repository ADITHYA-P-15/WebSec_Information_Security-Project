
import json

from sqlalchemy.orm import Session

from database.database import engine
from database.models import (
    Assessment,
    Target,
    Asset,
    Endpoint,
    EndpointAccess,
    Finding,
    Evidence,
)


def print_section(title):
    print(f"\n{title}")
    print("=" * len(title))


with Session(engine) as session:
    assessments = session.query(Assessment).order_by(
        Assessment.id
    ).all()

    if not assessments:
        print("No assessments found.")
    
    for assessment in assessments:
        print_section("ASSESSMENT")
        print(f"ID: {assessment.id}")
        print(f"Target URL: {assessment.target_url}")
        print(f"Status: {assessment.status}")

        targets = session.query(Target).filter_by(
            assessment_id=assessment.id
        ).order_by(Target.id).all()

        for target in targets:
            print_section("TARGET")
            print(f"ID: {target.id}")
            print(f"URL: {target.url}")
            print(f"Status: {target.status}")

            assets = session.query(Asset).filter_by(
                assessment_id=assessment.id
            ).order_by(Asset.id).all()

            print_section("ASSETS")

            if not assets:
                print("No assets discovered.")

            for asset in assets:
                print(
                    f"{asset.host}:{asset.port} | "
                    f"{asset.protocol} | {asset.state} | "
                    f"{asset.service} | {asset.version} | "
                    f"Source: {asset.discovered_by}"
                )

            endpoints = session.query(Endpoint).filter_by(
                target_id=target.id
            ).order_by(Endpoint.id).all()

            print_section("ENDPOINTS AND ROLE ACCESS")

            if not endpoints:
                print("No endpoints discovered.")

            for endpoint in endpoints:
                print(f"\n{endpoint.method} {endpoint.path}")
                print(f"Discovered by: {endpoint.discovered_by}")

                accesses = session.query(
                    EndpointAccess
                ).filter_by(
                    endpoint_id=endpoint.id
                ).order_by(EndpointAccess.id).all()

                if not accesses:
                    print("  No role observations recorded.")

                for access in accesses:
                    print(
                        f"  {access.role} -> "
                        f"{access.status_code}"
                    )

        findings = session.query(Finding).filter_by(
            assessment_id=assessment.id
        ).order_by(Finding.id).all()

        print_section("FINDINGS AND RISK ASSESSMENTS")

        if not findings:
            print("No findings recorded.")
            continue

        for finding in findings:
            print(f"\nFinding ID: {finding.id}")
            print(f"Title: {finding.title}")
            print(f"Type: {finding.vulnerability_type}")
            print(f"Verification status: {finding.status}")
            print(f"Final severity: {finding.severity}")
            print(f"Description: {finding.description}")

            print("\n  PRELIMINARY RISK")
            print(
                f"  Score: {finding.risk_score}/100"
                if finding.risk_score is not None
                else "  Score: Not assessed"
            )
            print(
                f"  Rating: {finding.risk_severity or 'Not assessed'}"
            )
            print(f"  Scoring method: {finding.risk_method or 'N/A'}")

            if finding.risk_factors:
                try:
                    factors = json.loads(finding.risk_factors)
                    print(
                        "  Factors: "
                        + json.dumps(factors, ensure_ascii=False)
                    )
                except (ValueError, TypeError):
                    print(f"  Factors: {finding.risk_factors}")
            else:
                print("  Factors: Not recorded")

            evidence_records = session.query(Evidence).filter_by(
                finding_id=finding.id
            ).order_by(Evidence.id).all()

            print(f"\n  Evidence records: {len(evidence_records)}")

            for evidence in evidence_records:
                print(
                    f"  Evidence ID: {evidence.id} | "
                    f"Type: {evidence.evidence_type}"
                )

                try:
                    data = json.loads(evidence.data)
                    print(
                        "  Data: "
                        + json.dumps(data, ensure_ascii=False)
                    )
                except (ValueError, TypeError):
                    print(f"  Data: {evidence.data}")
