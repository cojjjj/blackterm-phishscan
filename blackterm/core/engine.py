from blackterm.core.models import ScanResult
from blackterm.core.scanner import scan_url
from blackterm.core.scoring import calculate_risk
from blackterm.core.threat_summary import generate_threat_summary
from blackterm.core.logger import setup_logger

from blackterm.intelligence.manager import run_intelligence_modules

from blackterm.reports.reporter import save_json_report
from blackterm.reports.html_reporter import save_html_report
from blackterm.reports.csv_reporter import save_csv_summary


logger = setup_logger()


def get_verdict(score):
    if score < 25:
        return "LOW", "HIGH"
    if score < 60:
        return "MEDIUM", "MEDIUM"
    return "HIGH", "LOW"


def run_scan(target, no_screenshot=False):
    logger.info(f"Starting scan for {target}")

    result = scan_url(target)
    score, reasons = calculate_risk(target)

    modules = run_intelligence_modules(result, no_screenshot=no_screenshot)

    threat = modules["threat"]

    vt_result = threat["providers"]["virustotal"]
    urlhaus_result = threat["providers"]["urlhaus"]
    safebrowsing_result = threat["providers"]["safebrowsing"]

    whois_result = modules["whois"]
    ssl_result = modules["ssl"]
    dns_result = modules["dns"]
    ip_result = modules["ip"]
    screenshot_result = modules["screenshot"]

    score += threat.get("risk_boost", 0)
    reasons.extend(threat.get("reasons", []))

    if ssl_result.get("error"):
        score += 10
        reasons.append("SSL certificate check failed")

    if screenshot_result.get("error") and not no_screenshot:
        reasons.append("Website screenshot capture failed")

    score = min(score, 100)
    threat_level, confidence = get_verdict(score)

    summary = generate_threat_summary(
        target,
        result,
        score,
        reasons,
        vt_result,
        whois_result,
        ssl_result,
        dns_result,
        ip_result,
        screenshot_result,
    )

    json_report = save_json_report(
        target,
        result,
        score,
        reasons,
        vt_result,
        whois_result,
        ssl_result,
        dns_result,
        ip_result,
        screenshot_result,
        summary,
    )

    html_report = save_html_report(
        target,
        result,
        score,
        reasons,
        vt_result,
        whois_result,
        ssl_result,
        dns_result,
        ip_result,
        screenshot_result,
        summary,
    )

    csv_report = save_csv_summary(
        target,
        result,
        score,
        vt_result,
        whois_result,
        ssl_result,
        ip_result,
    )

    scan = ScanResult(
        target=target,
        domain=result.get("domain"),
        final_url=result.get("final_url"),
        risk_score=score,
        threat_level=threat_level,
        confidence=confidence,
        reasons=reasons,
        summary=summary,
    )

    scan.modules = {
        "scanner": result,
        "threat": threat,
        "virustotal": vt_result,
        "urlhaus": urlhaus_result,
        "safebrowsing": safebrowsing_result,
        "whois": whois_result,
        "ssl": ssl_result,
        "dns": dns_result,
        "ip": ip_result,
        "screenshot": screenshot_result,
    }

    scan.reports = {
        "json": str(json_report),
        "html": str(html_report),
        "csv": str(csv_report),
        "screenshot": str(screenshot_result.get("screenshot_path")),
    }

    logger.info(f"Finished scan for {target} with score {score}")

    return scan