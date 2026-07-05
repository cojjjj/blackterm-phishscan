import os
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")


def get_url_id(url):
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded


def check_virustotal(url):
    if not VT_API_KEY:
        return {
            "enabled": False,
            "error": "Missing VT_API_KEY in .env",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        }

    url_id = get_url_id(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(api_url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "enabled": True,
                "error": "No VirusTotal report found for this URL",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
            }

        response.raise_for_status()
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "enabled": True,
            "error": None,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    except requests.RequestException as error:
        return {
            "enabled": True,
            "error": str(error),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        }