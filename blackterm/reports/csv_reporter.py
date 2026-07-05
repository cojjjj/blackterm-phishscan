import csv
from datetime import datetime
from pathlib import Path


def save_csv_summary(url, result, score, vt_result, whois_result, ssl_result, ip_result):
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    filename = reports_dir / "summary.csv"
    file_exists = filename.exists()

    row = {
        "scan_time": datetime.now().isoformat(),
        "target": url,
        "domain": result.get("domain"),
        "final_url": result.get("final_url"),
        "risk_score": score,
        "https": result.get("https"),
        "reachable": result.get("reachable"),
        "status_code": result.get("status_code"),
        "vt_malicious": vt_result.get("malicious"),
        "vt_suspicious": vt_result.get("suspicious"),
        "registrar": whois_result.get("registrar"),
        "domain_age_days": whois_result.get("domain_age_days"),
        "ssl_valid": ssl_result.get("is_valid"),
        "ssl_expires": ssl_result.get("valid_until"),
        "ip_address": ip_result.get("ip_address"),
        "asn": ip_result.get("asn"),
        "asn_description": ip_result.get("asn_description"),
    }

    with open(filename, "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=row.keys())

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)

    return filename