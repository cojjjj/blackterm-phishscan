import dns.resolver


def get_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(answer) for answer in answers]
    except Exception:
        return []


def lookup_dns(domain):
    data = {
        "enabled": True,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "error": None,
    }

    if not domain:
        data["error"] = "No domain supplied."
        return data

    data["a_records"] = get_records(domain, "A")
    data["aaaa_records"] = get_records(domain, "AAAA")
    data["mx_records"] = get_records(domain, "MX")
    data["ns_records"] = get_records(domain, "NS")
    data["txt_records"] = get_records(domain, "TXT")

    return data