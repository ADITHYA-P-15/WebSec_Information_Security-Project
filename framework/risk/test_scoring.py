
from risk.scoring import calculate_risk


test_cases = [
    {
        "name": "Low-impact, difficult to exploit",
        "impact": 2,
        "exploitability": 2,
        "confidence": 3,
    },
    {
        "name": "Confirmed administrative data exposure",
        "impact": 4,
        "exploitability": 4,
        "confidence": 5,
    },
    {
        "name": "Uncertain observation",
        "impact": 4,
        "exploitability": 4,
        "confidence": 1,
    },
]


for case in test_cases:
    result = calculate_risk(
        impact=case["impact"],
        exploitability=case["exploitability"],
        confidence=case["confidence"],
    )

    print(f"\n{case['name']}")
    print("-" * len(case["name"]))
    print(f"Score: {result['score']}/100")
    print(f"Severity: {result['severity']}")
    print(f"Factors: {result['factors']}")
