import os
import requests
from dotenv import load_dotenv

load_dotenv()

URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


def check_urlhaus(url):
    result = {
        "enabled": True,
        "query_status": None,
        "threat": None,
        "url_status": None,
        "host": None,
        "date_added": None,
        "tags": [],
        "payloads": [],
        "error": None,
    }

    if not URLHAUS_API_KEY:
        result["enabled"] = False
        result["error"] = "Missing URLHAUS_API_KEY in .env"
        return result

    try:
        headers = {
            "Auth-Key": URLHAUS_API_KEY
        }

        data = {
            "url": url
        }

        response = requests.post(
            URLHAUS_ENDPOINT,
            headers=headers,
            data=data,
            timeout=15,
        )

        response.raise_for_status()
        payload = response.json()

        result["query_status"] = payload.get("query_status")
        result["threat"] = payload.get("threat")
        result["url_status"] = payload.get("url_status")
        result["host"] = payload.get("host")
        result["date_added"] = payload.get("date_added")
        result["tags"] = payload.get("tags") or []
        result["payloads"] = payload.get("payloads") or []

    except Exception as error:
        result["error"] = str(error)

    return result