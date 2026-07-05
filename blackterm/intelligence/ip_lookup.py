import socket
from ipwhois import IPWhois


def lookup_ip(domain):
    result = {
        "enabled": True,
        "ip_address": None,
        "asn": None,
        "asn_description": None,
        "network_name": None,
        "country": None,
        "error": None,
    }

    if not domain:
        result["error"] = "No domain supplied."
        return result

    try:
        ip_address = socket.gethostbyname(domain)
        result["ip_address"] = ip_address

        obj = IPWhois(ip_address)
        data = obj.lookup_rdap()

        result["asn"] = data.get("asn")
        result["asn_description"] = data.get("asn_description")
        result["network_name"] = data.get("network", {}).get("name")
        result["country"] = data.get("network", {}).get("country")

    except Exception as error:
        result["error"] = str(error)

    return result