
import json

from sqlalchemy.orm import Session

from database.database import engine
from database.models import Finding
from risk.scoring import calculate_risk


RISK_POLICIES = {
    "BROKEN_ACCESS_CONTROL": {
        "impact": 4,
        "exploitability": 4,
        "confidence": 3,
    },
    "IDOR_BOLA": {
        "impact": 4,
        "exploitability": 4,
        "confidence": 4,
    },
    "SQL_INJECTION": {"impact": 5, "exploitability": 4, "confidence": 2},
    "CROSS_SITE_SCRIPTING": {"impact": 3, "exploitability": 4, "confidence": 2},
    "CSRF": {"impact": 3, "exploitability": 3, "confidence": 2},
    "PATH_TRAVERSAL": {"impact": 4, "exploitability": 3, "confidence": 2},
    "SECURITY_MISCONFIGURATION": {"impact": 2, "exploitability": 2, "confidence": 2},
}


def assess_findings(assessment_id):
    with Session(engine) as session:
        findings = (
            session.query(Finding)
            .filter_by(
                assessment_id=assessment_id,
                status="CANDIDATE",
            )
            .order_by(Finding.id)
            .all()
        )

        if not findings:
            print("No candidate findings found.")
            return

        for finding in findings:
            factors = RISK_POLICIES.get(
                finding.vulnerability_type
            )

            if factors is None:
                print(
                    f"\nSkipping finding {finding.id}: "
                    f"no risk policy for "
                    f"{finding.vulnerability_type}."
                )
                continue

            result = calculate_risk(**factors)

            finding.risk_score = result["score"]
            finding.risk_severity = result["severity"]
            finding.risk_factors = json.dumps(
                result["factors"],
                sort_keys=True,
            )
            finding.risk_method = result["method"]

            print(f"\nFinding ID: {finding.id}")
            print(f"Title: {finding.title}")
            print(f"Type: {finding.vulnerability_type}")
            print(f"Risk score: {result['score']}/100")
            print(f"Preliminary rating: {result['severity']}")
            print(f"Factors: {result['factors']}")
            print(f"Verification status: {finding.status}")

        session.commit()
        print("\nRisk assessments saved successfully.")


if __name__ == "__main__":
    raise SystemExit("Call assess_findings(assessment_id) from the assessment workflow.")
