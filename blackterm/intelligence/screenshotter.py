from pathlib import Path
from datetime import datetime
from playwright.sync_api import sync_playwright


def capture_screenshot(url, domain):
    result = {
        "enabled": True,
        "screenshot_path": None,
        "error": None,
    }

    try:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        safe_domain = (domain or "unknown").replace(":", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = reports_dir / f"{safe_domain}_{timestamp}.png"

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1366, "height": 768})
            page.goto(url, wait_until="networkidle", timeout=15000)
            page.screenshot(path=str(filename), full_page=True)
            browser.close()

        result["screenshot_path"] = str(filename)

    except Exception as error:
        result["error"] = str(error)

    return result