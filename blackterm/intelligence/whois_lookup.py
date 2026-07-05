from datetime import datetime, timezone
import whois


def clean_date(value):
    if isinstance(value, list):
        value = value[0] if value else None

    if isinstance(value, datetime):
        return value

    return None


def format_date(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return None


def lookup_whois(domain):
    result = {
        "enabled": True,
        "registrar": None,
        "created": None,
        "expires": None,
        "domain_age_days": None,
        "error": None,
    }

    if not domain:
        result["error"] = "No domain supplied."
        return result

    try:
        w = whois.whois(domain)

        created = clean_date(w.creation_date)
        expires = clean_date(w.expiration_date)

        result["registrar"] = w.registrar
        result["created"] = format_date(created)
        result["expires"] = format_date(expires)

        if created:

            # Make both datetimes timezone-aware (UTC)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)

            age = now - created

            result["domain_age_days"] = age.days

    except Exception as e:
        result["error"] = str(e)

    return result