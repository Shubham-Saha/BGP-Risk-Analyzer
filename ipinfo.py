"""IP intelligence via ipinfo.io — geolocation, ASN, and organization."""

from network import fetch_json


def query_ipinfo(ip: str) -> dict:
    """Query ipinfo.io for geolocation, ASN, and organization.

    Returns a dict with keys: ip, hostname, city, region, country, org,
    asn, asn_name.
    """
    data = fetch_json(f"https://ipinfo.io/{ip}/json")
    org = data.get("org", "")
    asn, asn_name = "", ""
    if org.startswith("AS"):
        parts = org.split(" ", 1)
        asn = parts[0]
        asn_name = parts[1] if len(parts) > 1 else ""
    return {
        "ip": data.get("ip", ip),
        "hostname": data.get("hostname", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "country": data.get("country", ""),
        "org": org,
        "asn": asn,
        "asn_name": asn_name,
    }
