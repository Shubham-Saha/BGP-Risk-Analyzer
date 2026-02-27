"""RPKI/ROA validation via RIPE Stat and EROSION case classification.

EROSION Cases (IEEE 10646806):
    Case 1: ROA exists, MaxLength = prefix length     -> Safest
    Case 2: ROA exists, MaxLength > prefix length     -> Vulnerable despite RPKI
    Case 3: No ROA, prefix is /24                     -> Partial protection
    Case 4: No ROA, prefix larger than /24            -> Most vulnerable
"""

from urllib.parse import quote

from network import fetch_json


def get_announced_prefix(ip: str) -> tuple[str, str]:
    """Get the BGP-announced prefix and origin ASN for an IP from RIPE Stat."""
    data = fetch_json(
        f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
    )
    prefix = data["data"].get("prefix", "")
    asns = data["data"].get("asns", [])
    asn = f"AS{asns[0]}" if asns else ""
    return prefix, asn


def validate_rpki(asn: str, prefix: str) -> dict:
    """Validate RPKI/ROA via RIPE Stat and classify into EROSION cases.

    Returns a dict with keys: prefix, prefix_length, asn, roa_exists,
    max_length, validity, erosion_case, erosion_description, gap, all_roas.
    """
    asn_str = asn if asn.startswith("AS") else f"AS{asn}"
    encoded_prefix = quote(prefix, safe="")
    data = fetch_json(
        f"https://stat.ripe.net/data/rpki-validation/data.json"
        f"?resource={asn_str}&prefix={encoded_prefix}"
    )
    rpki = data["data"]
    status = rpki.get("status", "unknown")
    roas = rpki.get("validating_roas", [])
    prefix_length = int(prefix.split("/")[1])

    all_roas = [
        {
            "origin": f"AS{r['origin']}",
            "prefix": r["prefix"],
            "max_length": r["max_length"],
            "validity": r.get("validity", status),
        }
        for r in roas
    ]

    if roas:
        roa = roas[0]
        max_length = int(roa.get("max_length", prefix_length))
        roa_exists = True

        if max_length <= prefix_length:
            case = 1
            gap = 0
            description = (
                "SAFE — ROA exists, MaxLength = prefix length. "
                "Sub-prefix hijack blocked by RPKI validation."
            )
        else:
            case = 2
            gap = max_length - prefix_length
            description = (
                f"VULNERABLE — ROA exists but MaxLength (/{max_length}) > "
                f"prefix length (/{prefix_length}). Gap: {gap} levels. "
                f"Forged-origin sub-prefix hijack passes RPKI validation."
            )
    else:
        roa_exists = False
        max_length = None
        gap = None
        if prefix_length >= 24:
            case = 3
            description = (
                f"PARTIAL PROTECTION — No ROA exists, prefix is /{prefix_length}. "
                f"Most BGP routers reject more-specific than /24. "
                f"Equal-length hijack still possible via AS path competition."
            )
        else:
            case = 4
            description = (
                f"MOST VULNERABLE — No ROA exists, prefix is /{prefix_length}. "
                f"Attacker can announce a more-specific /24 sub-prefix "
                f"and attract traffic without any RPKI obstacle."
            )

    return {
        "prefix": prefix,
        "prefix_length": prefix_length,
        "asn": asn_str,
        "roa_exists": roa_exists,
        "max_length": max_length,
        "validity": status,
        "erosion_case": case,
        "erosion_description": description,
        "gap": gap,
        "all_roas": all_roas,
    }
