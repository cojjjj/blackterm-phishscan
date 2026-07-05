from datetime import datetime
from pathlib import Path


def _html_list(values):
    if not values:
        return "<li>None</li>"
    return "".join(f"<li>{value}</li>" for value in values[:10])


def _badge(text, cls):
    return f'<span class="badge {cls}">{text}</span>'


def save_html_report(
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
    filename = reports_dir / f"{safe_domain}_{timestamp}.html"

    if score < 25:
        verdict = "LOW RISK"
        verdict_class = "low"
    elif score < 60:
        verdict = "MEDIUM RISK"
        verdict_class = "medium"
    else:
        verdict = "HIGH RISK"
        verdict_class = "high"

    screenshot_path = screenshot_result.get("screenshot_path")
    screenshot_html = "<p>No screenshot captured.</p>"

    if screenshot_path:
        screenshot_file = Path(screenshot_path).name
        screenshot_html = f'<img class="screenshot" src="{screenshot_file}">'

    reasons_html = "".join(f"<li>{reason}</li>" for reason in reasons) or "<li>No suspicious indicators detected.</li>"

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BlackTerm PhishScan Report</title>
    <style>
        body {{
            background: radial-gradient(circle at top, #1a1115, #07090d 45%);
            color: #e6edf3;
            font-family: Segoe UI, Arial, sans-serif;
            padding: 30px;
        }}
        .container {{
            max-width: 1150px;
            margin: auto;
        }}
        h1 {{
            color: #ff2e2e;
            letter-spacing: 2px;
        }}
        .subtitle {{
            color: #8b949e;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
        }}
        .card {{
            background: rgba(17, 24, 39, 0.92);
            border: 1px solid #30363d;
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px rgba(255, 46, 46, 0.08);
        }}
        .stat {{
            font-size: 28px;
            font-weight: bold;
        }}
        .low {{ color: #00ff88; }}
        .medium {{ color: #ffd166; }}
        .high {{ color: #ff4d4d; }}
        .badge {{
            padding: 5px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge.low {{
            background: rgba(0, 255, 136, .12);
            color: #00ff88;
            border: 1px solid #00ff88;
        }}
        .badge.medium {{
            background: rgba(255, 209, 102, .12);
            color: #ffd166;
            border: 1px solid #ffd166;
        }}
        .badge.high {{
            background: rgba(255, 77, 77, .12);
            color: #ff4d4d;
            border: 1px solid #ff4d4d;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        td, th {{
            border-bottom: 1px solid #30363d;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }}
        .bar {{
            width: 100%;
            height: 18px;
            background: #21262d;
            border-radius: 999px;
            overflow: hidden;
            border: 1px solid #30363d;
        }}
        .fill {{
            height: 100%;
            width: {score}%;
            background: linear-gradient(90deg, #00ff88, #ffd166, #ff4d4d);
        }}
        .screenshot {{
            width: 100%;
            border-radius: 14px;
            border: 1px solid #30363d;
        }}
        .footer {{
            color: #8b949e;
            font-size: 13px;
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>BLACKTERM PHISHSCAN</h1>
    <p class="subtitle">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

    <div class="grid">
        <div class="card">
            <h3>Risk Score</h3>
            <div class="stat {verdict_class}">{score}/100</div>
            <div class="bar"><div class="fill"></div></div>
        </div>
        <div class="card">
            <h3>Verdict</h3>
            {_badge(verdict, verdict_class)}
        </div>
        <div class="card">
            <h3>Target</h3>
            <p>{url}</p>
        </div>
    </div>

    <div class="card">
        <h2>AI Threat Summary</h2>
        <p>{threat_summary}</p>
    </div>

    <div class="card">
        <h2>Website Screenshot</h2>
        {screenshot_html}
    </div>

    <div class="card">
        <h2>Scan Results</h2>
        <table>
            <tr><th>Check</th><th>Value</th></tr>
            <tr><td>Valid URL</td><td>{result["valid"]}</td></tr>
            <tr><td>HTTPS</td><td>{result["https"]}</td></tr>
            <tr><td>Reachable</td><td>{result["reachable"]}</td></tr>
            <tr><td>Status Code</td><td>{result["status_code"]}</td></tr>
            <tr><td>Domain</td><td>{result["domain"]}</td></tr>
            <tr><td>Final URL</td><td>{result["final_url"]}</td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Threat Intelligence</h2>
        <table>
            <tr><th>Source</th><th>Status</th></tr>
            <tr><td>VirusTotal</td><td>Malicious: {vt_result["malicious"]}, Suspicious: {vt_result["suspicious"]}</td></tr>
            <tr><td>WHOIS</td><td>Registrar: {whois_result["registrar"]}, Age: {whois_result["domain_age_days"]} days</td></tr>
            <tr><td>SSL</td><td>Issuer: {ssl_result["issuer"]}, Valid: {ssl_result["is_valid"]}</td></tr>
            <tr><td>DNS</td><td>A: {_html_list(dns_result.get("a_records", []))}</td></tr>
            <tr><td>IP</td><td>{ip_result["ip_address"]} - {ip_result["asn_description"]}</td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Detection Reasons</h2>
        <ul>{reasons_html}</ul>
    </div>

    <p class="footer">Generated by BlackTerm PhishScan</p>
</div>
</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html)

    return filename