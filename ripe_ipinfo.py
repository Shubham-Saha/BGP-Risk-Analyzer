"""IP intelligence via RIPE Stat — geolocation, ASN, hostname, and organization.

Replaces ipinfo.io with three RIPE Stat endpoints (run in parallel):
  1. reverse-dns-ip   → hostname (PTR record)
  2. maxmind-geo-lite → city, country
  3. prefix-overview  → ASN, org name

RIPE Stat has no hard rate limit (unlike ipinfo.io's 50k/month free tier),
requires no API key, and permits commercial use.
"""

from concurrent.futures import ThreadPoolExecutor

from network import fetch_json

_SOURCEAPP = "BGP-Risk-Analyzer"


def _get_hostname(ip: str) -> str:
    """Reverse DNS lookup via RIPE Stat."""
    try:
        data = fetch_json(
            f"https://stat.ripe.net/data/reverse-dns-ip/data.json"
            f"?resource={ip}&sourceapp={_SOURCEAPP}"
        )
        delegations = data.get("data", {}).get("delegations", [])
        if delegations:
            nameservers = delegations[0].get("nameservers", [])
            if nameservers:
                return nameservers[0].rstrip(".")
        result = data.get("data", {}).get("result", [])
        if result:
            return result[0].rstrip(".")
    except Exception:
        pass
    return ""


def _get_geolocation(ip: str) -> dict:
    """City + country via RIPE Stat MaxMind GeoLite data."""
    try:
        data = fetch_json(
            f"https://stat.ripe.net/data/maxmind-geo-lite/data.json"
            f"?resource={ip}&sourceapp={_SOURCEAPP}"
        )
        locations = data.get("data", {}).get("located_resources", [])
        if locations:
            for loc in locations:
                locs_list = loc.get("locations", [])
                if locs_list:
                    geo = locs_list[0]
                    return {
                        "city": geo.get("city", ""),
                        "country": geo.get("country", ""),
                    }
    except Exception:
        pass
    return {"city": "", "country": ""}


def _get_prefix_overview(ip: str) -> dict:
    """ASN + org name via RIPE Stat prefix-overview."""
    try:
        data = fetch_json(
            f"https://stat.ripe.net/data/prefix-overview/data.json"
            f"?resource={ip}&sourceapp={_SOURCEAPP}"
        )
        overview = data.get("data", {})
        asns = overview.get("asns", [])
        if asns:
            asn_entry = asns[0]
            asn_num = asn_entry.get("asn", "")
            holder = asn_entry.get("holder", "")
            return {
                "asn": f"AS{asn_num}" if asn_num else "",
                "asn_name": holder,
            }
    except Exception:
        pass
    return {"asn": "", "asn_name": ""}


def query_ripe_ipinfo(ip: str) -> dict:
    """Query RIPE Stat for geolocation, ASN, and hostname (parallel).

    Returns a dict with the same keys as ipinfo.query_ipinfo():
    ip, hostname, city, region, country, org, asn, asn_name.
    """
    with ThreadPoolExecutor(max_workers=3) as pool:
        hostname_future = pool.submit(_get_hostname, ip)
        geo_future = pool.submit(_get_geolocation, ip)
        prefix_future = pool.submit(_get_prefix_overview, ip)

        hostname = hostname_future.result()
        geo = geo_future.result()
        prefix_info = prefix_future.result()

    asn = prefix_info["asn"]
    asn_name = prefix_info["asn_name"]
    org = f"{asn} {asn_name}".strip() if asn else asn_name

    return {
        "ip": ip,
        "hostname": hostname,
        "city": geo["city"],
        "region": "",  # RIPE Stat doesn't provide region without WHOIS parsing
        "country": geo["country"],
        "org": org,
        "asn": asn,
        "asn_name": asn_name,
    }
