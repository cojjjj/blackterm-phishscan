def generate_threat_summary(
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
):
    if score < 25:
        verdict = "LOW"
    elif score < 60:
        verdict = "MEDIUM"
    else:
        verdict = "HIGH"

    summary = []

    summary.append(f"Target {url} was assessed as {verdict} risk with a score of {score}/100.")

    if vt_result.get("malicious", 0) == 0 and vt_result.get("suspicious", 0) == 0:
        summary.append("VirusTotal reported no malicious or suspicious detections.")
    else:
        summary.append(
            f"VirusTotal reported {vt_result.get('malicious', 0)} malicious and "
            f"{vt_result.get('suspicious', 0)} suspicious detections."
        )

    if whois_result.get("domain_age_days"):
        summary.append(f"The domain is approximately {whois_result['domain_age_days']} days old.")

    if ssl_result.get("is_valid"):
        summary.append(
            f"The SSL certificate is valid and expires on {ssl_result.get('valid_until')}."
        )
    else:
        summary.append("The SSL certificate could not be confirmed as valid.")

    if dns_result.get("a_records") or dns_result.get("aaaa_records"):
        summary.append("DNS records are present and the domain resolves successfully.")
    else:
        summary.append("No A or AAAA DNS records were found.")

    if ip_result.get("asn_description"):
        summary.append(f"The hosting network appears to be {ip_result.get('asn_description')}.")

    if screenshot_result.get("screenshot_path"):
        summary.append("A website screenshot was captured successfully.")

    if reasons:
        summary.append("Notable findings: " + "; ".join(reasons) + ".")
    else:
        summary.append("No suspicious indicators were detected by the local rule engine.")

    return " ".join(summary)