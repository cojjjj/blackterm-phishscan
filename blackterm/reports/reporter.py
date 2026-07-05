import json
from datetime import datetime
from pathlib import Path


def save_json_report(
    url,
    result,
    score,
    reasons,
    vt_result,
    whois_result,
    ssl_result,
    dns_result,
    ip_result,
    screenshot_result,
    threat_summary,
):
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    domain = result.get("domain") or "unknown"
    safe_domain = domain.replace(":", "_").replace("/", "_")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = reports_dir / f"{safe_domain}_{timestamp}.json"

    report = {
        "tool": "BlackTerm PhishScan",
        "target": url,
        "scan_time": datetime.now().isoformat(),
        "result": result,
        "risk_score": score,
        "reasons": reasons,
        "virustotal": vt_result,
        "whois": whois_result,
        "ssl": ssl_result,
        "dns": dns_result,
        "ip_intelligence": ip_result,
        "screenshot": screenshot_result,
        "threat_summary": threat_summary,
    }

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return filename