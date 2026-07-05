from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "paypal", "password", "signin", "confirm",
    "wallet", "free", "gift", "reward",
]


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def calculate_risk(url):
    url = normalize_url(url)
    parsed = urlparse(url)

    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 25
        reasons.append("Not using HTTPS")

    if len(url) > 75:
        score += 15
        reasons.append("Long URL")

    if parsed.netloc.count("-") >= 3:
        score += 15
        reasons.append("Many hyphens in domain")

    if parsed.netloc.count(".") >= 4:
        score += 10
        reasons.append("Many subdomains")

    lower_url = url.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lower_url:
            score += 10
            reasons.append(f"Contains '{keyword}'")

    return min(score, 100), reasons