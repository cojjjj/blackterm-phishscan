from blackterm.intelligence.whois_lookup import lookup_whois
from blackterm.intelligence.ssl_checker import check_ssl_certificate
from blackterm.intelligence.dns_lookup import lookup_dns
from blackterm.intelligence.ip_lookup import lookup_ip
from blackterm.intelligence.screenshotter import capture_screenshot
from blackterm.intelligence.threat_engine import run_threat_intelligence


def run_intelligence_modules(result, no_screenshot=False):
    domain = result.get("domain")
    final_url = result.get("final_url")

    modules = {
        "threat": run_threat_intelligence(final_url),
        "whois": lookup_whois(domain),
        "ssl": check_ssl_certificate(domain),
        "dns": lookup_dns(domain),
        "ip": lookup_ip(domain),
        "screenshot": {
            "enabled": False,
            "screenshot_path": None,
            "error": "Screenshot disabled",
        },
    }

    if not no_screenshot:
        modules["screenshot"] = capture_screenshot(final_url, domain)

    return modules