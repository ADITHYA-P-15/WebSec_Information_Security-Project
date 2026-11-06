
import json
from pathlib import Path
from urllib.parse import urlparse


RISK_MAP = {
    "informational": "INFO",
    "info": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}


def normalize_risk(risk_description):
    """Extract the risk label from descriptions such as 'Medium (High)'."""
    if not risk_description:
        return "UNASSESSED"

    risk = str(risk_description).split("(", 1)[0].strip().lower()
    return RISK_MAP.get(risk, "UNASSESSED")


def parse_zap_report(report_path):
    """Parse ZAP JSON alerts and expand their affected instances."""
    path = Path(report_path)
    report = json.loads(path.read_text(encoding="utf-8"))

    parsed_alerts = []

    for site in report.get("site", []):
        site_url = site.get("@name", "")
        site_host = urlparse(site_url).netloc

        for alert in site.get("alerts", []):
            instances = alert.get("instances") or [{}]

            for instance in instances:
                url = instance.get("uri") or instance.get("url") or site_url
                parsed_host = urlparse(url).netloc

                # Avoid importing an alert instance outside the scanned host.
                if site_host and parsed_host and parsed_host != site_host:
                    continue

                parsed_alerts.append({
                    "source": "OWASP_ZAP",
                    "plugin_id": str(alert.get("pluginid", "")),
                    "name": alert.get("name", "Unnamed ZAP alert"),
                    "risk": normalize_risk(alert.get("riskdesc")),
                    "risk_description": alert.get("riskdesc"),
                    "confidence": alert.get("confidence"),
                    "url": url,
                    "method": instance.get("method"),
                    "parameter": instance.get("param"),
                    "evidence": instance.get("evidence"),
                    "description": alert.get("desc", ""),
                    "solution": alert.get("solution", ""),
                    "reference": alert.get("reference", ""),
                    "status": "CANDIDATE",
                    "verified": False,
                })

    return parsed_alerts


def main():
    report_path = Path("../reports/zap/zap-baseline-report.json")
    alerts = parse_zap_report(report_path)

    print(f"Parsed ZAP instances: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert['risk']}] {alert['name']} | "
            f"{alert['method'] or 'N/A'} {alert['url']} | "
            f"Plugin: {alert['plugin_id']}"
        )

    print("\nNo database records were modified.")


if __name__ == "__main__":
    main()
