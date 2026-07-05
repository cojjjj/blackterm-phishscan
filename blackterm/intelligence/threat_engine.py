from blackterm.intelligence.virustotal import check_virustotal
from blackterm.intelligence.urlhaus import check_urlhaus
from blackterm.intelligence.safebrowsing import check_safe_browsing


def run_threat_intelligence(final_url):
    results = {
        "virustotal": check_virustotal(final_url),
        "urlhaus": check_urlhaus(final_url),
        "safebrowsing": check_safe_browsing(final_url),
    }

    reputation = "CLEAN"
    risk_boost = 0
    reasons = []

    vt = results["virustotal"]

    if vt.get("malicious", 0) > 0:
        reputation = "MALICIOUS"
        risk_boost += 30
        reasons.append(f"VirusTotal malicious detections: {vt.get('malicious')}")

    if vt.get("suspicious", 0) > 0:
        if reputation != "MALICIOUS":
            reputation = "SUSPICIOUS"
        risk_boost += 15
        reasons.append(f"VirusTotal suspicious detections: {vt.get('suspicious')}")

    urlhaus = results["urlhaus"]

    if urlhaus.get("query_status") == "ok":
        reputation = "MALICIOUS"
        risk_boost += 35
        reasons.append("URLHaus match found")

    safe_browsing = results["safebrowsing"]

    if safe_browsing.get("listed"):
        reputation = "MALICIOUS"
        risk_boost += 40
        reasons.append("Google Safe Browsing match found")

    return {
        "enabled": True,
        "reputation": reputation,
        "risk_boost": risk_boost,
        "reasons": reasons,
        "providers": results,
    }