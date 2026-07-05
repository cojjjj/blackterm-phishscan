import socket
import ssl
from datetime import datetime, timezone


def check_ssl_certificate(domain):
    result = {
        "enabled": True,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "is_valid": False,
        "error": None,
    }

    if not domain:
        result["error"] = "No domain supplied."
        return result

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        valid_from = datetime.strptime(
            cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        valid_until = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
        result["subject"] = subject.get("commonName")
        result["valid_from"] = valid_from.strftime("%Y-%m-%d")
        result["valid_until"] = valid_until.strftime("%Y-%m-%d")
        result["days_remaining"] = (valid_until - now).days
        result["is_valid"] = valid_from <= now <= valid_until

    except Exception as error:
        result["error"] = str(error)

    return result