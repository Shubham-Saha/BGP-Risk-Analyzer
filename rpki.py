"""RPKI/ROA validation via RIPE Stat and EROSION case classification.

EROSION Cases (IEEE 10646806):
    Case 1: ROA exists, MaxLength = prefix length     -> Lowest risk
    Case 2: ROA exists, MaxLength > prefix length     -> High risk
    Case 3: No ROA, prefix is /24                     -> High risk (constrained)
    Case 4: No ROA, prefix larger than /24            -> Highest risk

Note: No case provides complete protection. RPKI validates only the origin
AS, not the AS path. Even Case 1 remains susceptible to forged-origin
same-prefix hijacks and AS path manipulation attacks.
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
                f"LOWEST RISK — ROA exists, MaxLength (/{max_length}) = "
                f"prefix length (/{prefix_length}). "
                f"RPKI-validating routers will reject unauthorized sub-prefix "
                f"announcements. However, forged-origin same-prefix hijacks "
                f"remain possible: an attacker can announce the same "
                f"/{prefix_length} prefix with the legitimate origin ASN "
                f"appended to their AS path, bypassing ROV. If the attacker "
                f"is topologically closer to the victim, partial traffic "
                f"interception occurs via BGP shortest-path preference. "
                f"Protection scope: sub-prefix hijack only, contingent on "
                f"ROV enforcement by upstream providers."
            )
        else:
            case = 2
            gap = max_length - prefix_length
            description = (
                f"HIGH RISK — ROA exists but MaxLength (/{max_length}) > "
                f"prefix length (/{prefix_length}). Gap: {gap} bits. "
                f"An attacker can announce more-specific sub-prefixes up to "
                f"/{max_length} that will pass RPKI validation. This "
                f"misconfiguration enables forged-origin sub-prefix hijacks "
                f"that bypass ROV entirely. The presence of a ROA creates a "
                f"false sense of security while the loose MaxLength actively "
                f"enables the attack. Additionally, same-prefix forged-origin "
                f"hijacks and AS path manipulation remain possible."
            )
    else:
        roa_exists = False
        max_length = None
        gap = None
        if prefix_length >= 24:
            case = 3
            description = (
                f"HIGH RISK (CONSTRAINED) — No ROA exists, prefix is "
                f"/{prefix_length}. No RPKI protection is in place. However, "
                f"most BGP routers filter prefixes more specific than /24, so "
                f"sub-prefix hijacking is operationally constrained (not "
                f"guaranteed — this is a convention, not a protocol rule). "
                f"The primary attack vector is an equal-length same-prefix "
                f"hijack, where the attacker announces the same "
                f"/{prefix_length} prefix and competes for traffic via AS "
                f"path length and local routing policy. Effectiveness depends "
                f"on the attacker's topological position relative to the victim."
            )
        else:
            case = 4
            description = (
                f"HIGHEST RISK — No ROA exists, prefix is /{prefix_length}. "
                f"No RPKI protection is in place and the prefix is larger "
                f"than /24. An attacker can announce a more-specific /24 "
                f"sub-prefix within this address space. BGP inherently prefers "
                f"the longest (most specific) prefix match, so the attacker's "
                f"/24 will be preferred by all routers globally — resulting in "
                f"complete traffic interception for the targeted sub-prefix "
                f"with no RPKI obstacle. This is the most exposed "
                f"configuration: no origin validation, no path validation, "
                f"and no operational filtering constraint."
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
