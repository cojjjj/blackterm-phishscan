import argparse
from datetime import datetime
from pathlib import Path

from colorama import init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.progress import track

from blackterm.core.scanner import scan_url
from blackterm.core.scoring import calculate_risk
from blackterm.core.threat_summary import generate_threat_summary

from blackterm.reports.reporter import save_json_report
from blackterm.reports.html_reporter import save_html_report
from blackterm.reports.csv_reporter import save_csv_summary

from blackterm.intelligence.virustotal import check_virustotal
from blackterm.intelligence.whois_lookup import lookup_whois
from blackterm.intelligence.ssl_checker import check_ssl_certificate
from blackterm.intelligence.dns_lookup import lookup_dns
from blackterm.intelligence.ip_lookup import lookup_ip
from blackterm.intelligence.screenshotter import capture_screenshot


init(autoreset=True)
console = Console()
VERSION = "1.1.0"


ASCII_LOGO = r"""
██████╗ ██╗      █████╗  ██████╗██╗  ██╗████████╗███████╗██████╗ ███╗   ███╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝██║     ███████║██║     █████╔╝    ██║   █████╗  ██████╔╝██╔████╔██║
██╔══██╗██║     ██╔══██║██║     ██╔═██╗    ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
"""


def get_verdict(score):
    if score < 25:
        return "LOW", "green", "HIGH"
    if score < 60:
        return "MEDIUM", "yellow", "MEDIUM"
    return "HIGH", "red", "LOW"


def module_status(name, status):
    return f"[green]✓[/green] {name:<30} [cyan]{status}[/cyan]"


def scan_target(url, no_screenshot=False, quiet=False):
    scan_started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    result = scan_url(url)
    score, reasons = calculate_risk(url)

    vt_result = check_virustotal(result["final_url"])
    whois_result = lookup_whois(result["domain"])
    ssl_result = check_ssl_certificate(result["domain"])
    dns_result = lookup_dns(result["domain"])
    ip_result = lookup_ip(result["domain"])

    screenshot_result = {
        "enabled": False,
        "screenshot_path": None,
        "error": "Screenshot disabled",
    }

    if not no_screenshot:
        screenshot_result = capture_screenshot(result["final_url"], result["domain"])

    if vt_result.get("malicious", 0) > 0:
        score += 30
        reasons.append(f"VirusTotal malicious detections: {vt_result['malicious']}")

    if vt_result.get("suspicious", 0) > 0:
        score += 15
        reasons.append(f"VirusTotal suspicious detections: {vt_result['suspicious']}")

    if ssl_result.get("error"):
        score += 10
        reasons.append("SSL certificate check failed")

    if screenshot_result.get("error") and not no_screenshot:
        reasons.append("Website screenshot capture failed")

    score = min(score, 100)
    threat_level, risk_color, confidence = get_verdict(score)

    threat_summary = generate_threat_summary(
        url, result, score, reasons, vt_result, whois_result,
        ssl_result, dns_result, ip_result, screenshot_result
    )

    json_report = save_json_report(
        url, result, score, reasons, vt_result, whois_result,
        ssl_result, dns_result, ip_result, screenshot_result, threat_summary
    )

    html_report = save_html_report(
        url, result, score, reasons, vt_result, whois_result,
        ssl_result, dns_result, ip_result, screenshot_result, threat_summary
    )

    csv_report = save_csv_summary(
        url, result, score, vt_result, whois_result, ssl_result, ip_result
    )

    vt_total = (
        vt_result.get("malicious", 0)
        + vt_result.get("suspicious", 0)
        + vt_result.get("harmless", 0)
        + vt_result.get("undetected", 0)
    )

    scan_data = {
        "target": url,
        "domain": result.get("domain"),
        "score": score,
        "threat_level": threat_level,
        "confidence": confidence,
        "json_report": json_report,
        "html_report": html_report,
        "csv_report": csv_report,
        "screenshot": screenshot_result.get("screenshot_path"),
        "vt_detection": f"{vt_result.get('malicious', 0)} / {vt_total}",
        "ip": ip_result.get("ip_address"),
        "asn": ip_result.get("asn_description"),
    }

    if quiet:
        return scan_data

    modules = "\n".join([
        module_status("URL Validation", "PASSED" if result["valid"] else "FAILED"),
        module_status("VirusTotal Intelligence", "CLEAN" if vt_result.get("malicious", 0) == 0 else "DETECTED"),
        module_status("WHOIS Intelligence", "COMPLETE" if not whois_result.get("error") else "FAILED"),
        module_status("SSL Certificate", "VALID" if ssl_result.get("is_valid") else "INVALID"),
        module_status("DNS Intelligence", "RESOLVED" if dns_result.get("a_records") or dns_result.get("aaaa_records") else "FAILED"),
        module_status("IP Intelligence", "RESOLVED" if ip_result.get("ip_address") else "FAILED"),
        module_status("Website Screenshot", "CAPTURED" if screenshot_result.get("screenshot_path") else "SKIPPED"),
        module_status("AI Threat Summary", "GENERATED"),
        module_status("JSON Report", "SAVED"),
        module_status("HTML Report", "SAVED"),
        module_status("CSV Summary", "SAVED"),
    ])

    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="cyan")
    overview.add_column()
    overview.add_row("Target", url)
    overview.add_row("Scan Started", scan_started)
    overview.add_row("Engine", "BlackTerm Intelligence Engine")
    overview.add_row("Version", VERSION)
    overview.add_row("Risk", f"[{risk_color}]{threat_level}[/{risk_color}]")
    overview.add_row("Confidence", confidence)

    intel = Table.grid(padding=(0, 2))
    intel.add_column(style="cyan")
    intel.add_column()
    intel.add_row("Target IP", str(ip_result.get("ip_address")))
    intel.add_row("ASN", str(ip_result.get("asn_description")))
    intel.add_row("Domain Age", f"{whois_result.get('domain_age_days')} days")
    intel.add_row("SSL Status", "VALID" if ssl_result.get("is_valid") else "INVALID")
    intel.add_row("VT Detection", scan_data["vt_detection"])

    reports = Table.grid(padding=(0, 2))
    reports.add_column(style="green")
    reports.add_column()
    reports.add_row("JSON", str(json_report))
    reports.add_row("HTML", str(html_report))
    reports.add_row("CSV", str(csv_report))
    reports.add_row("PNG", str(screenshot_result.get("screenshot_path")))

    console.print(Panel(
        ASCII_LOGO,
        title=f"[bold red]BLACKTERM PHISHSCAN v{VERSION}[/bold red]",
        subtitle="Offensive Intelligence & Threat Scanner",
        border_style="red",
    ))

    console.print(Columns([
        Panel(overview, title="Scan Overview", border_style="cyan"),
        Panel(intel, title="Intelligence", border_style="green"),
    ]))

    console.print(Panel(modules, title="Modules", border_style="red"))

    console.print(Panel(
        f"[{risk_color}]Risk Score: {score}/100\nThreat Level: {threat_level}\nConfidence: {confidence}[/{risk_color}]",
        title="Assessment",
        border_style=risk_color,
    ))

    console.print(Panel(threat_summary, title="AI Threat Summary", border_style="cyan"))
    console.print(Panel(reports, title="Reports", border_style="green"))

    return scan_data


def load_targets(path):
    target_path = Path(path)

    if not target_path.exists():
        raise FileNotFoundError(f"Target file not found: {path}")

    targets = []

    with open(target_path, "r", encoding="utf-8") as file:
        for line in file:
            target = line.strip()

            if target and not target.startswith("#"):
                targets.append(target)

    return targets


def batch_scan(file_path, no_screenshot=False):
    targets = load_targets(file_path)

    if not targets:
        console.print("[red]No targets found in file.[/red]")
        return

    console.print(Panel(
        f"Loaded {len(targets)} targets from {file_path}",
        title="Batch Scan",
        border_style="cyan",
    ))

    results = []

    for target in track(targets, description="Scanning targets..."):
        try:
            results.append(scan_target(target, no_screenshot=no_screenshot, quiet=True))
        except Exception as error:
            results.append({
                "target": target,
                "domain": None,
                "score": 100,
                "threat_level": "ERROR",
                "confidence": "LOW",
                "json_report": None,
                "html_report": None,
                "csv_report": None,
                "screenshot": None,
                "vt_detection": "N/A",
                "ip": None,
                "asn": None,
                "error": str(error),
            })

    table = Table(title="Batch Scan Summary")
    table.add_column("#", style="cyan")
    table.add_column("Target")
    table.add_column("Risk")
    table.add_column("Score")
    table.add_column("IP")
    table.add_column("Report")

    low = medium = high = errors = 0

    for index, item in enumerate(results, start=1):
        level = item["threat_level"]

        if level == "LOW":
            low += 1
            risk_style = "green"
        elif level == "MEDIUM":
            medium += 1
            risk_style = "yellow"
        elif level == "HIGH":
            high += 1
            risk_style = "red"
        else:
            errors += 1
            risk_style = "magenta"

        table.add_row(
            str(index),
            str(item["target"]),
            f"[{risk_style}]{level}[/{risk_style}]",
            str(item["score"]),
            str(item["ip"]),
            str(item["html_report"]),
        )

    console.print(table)

    stats = (
        f"[green]LOW:[/green] {low}\n"
        f"[yellow]MEDIUM:[/yellow] {medium}\n"
        f"[red]HIGH:[/red] {high}\n"
        f"[magenta]ERRORS:[/magenta] {errors}\n"
        f"[cyan]TOTAL:[/cyan] {len(results)}"
    )

    console.print(Panel(stats, title="Batch Results", border_style="green"))
    console.print("[green]CSV summary updated:[/green] reports/summary.csv")


def main():
    parser = argparse.ArgumentParser(
        prog="blackterm",
        description="BlackTerm PhishScan - phishing URL intelligence scanner",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a URL or a .txt target list")
    scan_parser.add_argument("target", help="URL/domain or path to targets.txt")
    scan_parser.add_argument("--no-screenshot", action="store_true")

    batch_parser = subparsers.add_parser("batch", help="Scan targets from a text file")
    batch_parser.add_argument("file", help="Path to targets.txt")
    batch_parser.add_argument("--no-screenshot", action="store_true")

    args = parser.parse_args()

    if args.command == "scan":
        if args.target.lower().endswith(".txt"):
            batch_scan(args.target, args.no_screenshot)
        else:
            scan_target(args.target, args.no_screenshot)

    elif args.command == "batch":
        batch_scan(args.file, args.no_screenshot)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()