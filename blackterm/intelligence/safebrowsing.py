import os
import requests
from dotenv import load_dotenv

load_dotenv()

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_safe_browsing(url):
    result = {
        "enabled": True,
        "listed": False,
        "matches": [],
        "error": None,
    }

    if not GOOGLE_SAFE_BROWSING_API_KEY:
        result["enabled"] = False
        result["error"] = "Missing GOOGLE_SAFE_BROWSING_API_KEY in .env"
        return result

    try:
        response = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": GOOGLE_SAFE_BROWSING_API_KEY},
            json={
                "client": {
                    "clientId": "blackterm-phishscan",
                    "clientVersion": "1.1.0",
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=15,
        )

        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])
        result["matches"] = matches
        result["listed"] = len(matches) > 0

    except Exception as error:
        result["error"] = str(error)

    return result