import requests
import validators
from urllib.parse import urlparse


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def scan_url(url):
    url = normalize_url(url)

    result = {
        "valid": False,
        "https": False,
        "reachable": False,
        "status_code": None,
        "domain": None,
        "final_url": url,
    }

    if not validators.url(url):
        return result

    result["valid"] = True

    parsed = urlparse(url)
    result["domain"] = parsed.netloc
    result["https"] = parsed.scheme == "https"

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        result["reachable"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url
    except requests.RequestException:
        pass

    return result