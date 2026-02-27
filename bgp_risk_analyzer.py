"""BGP Risk Analyzer — Assess BGP hijacking vulnerability of network endpoints.

Performs DNS resolution, ping checks, IP geolocation via ipinfo.io,
ASN identification, RPKI/ROA validation via RIPE Stat, and EROSION
attack case classification.  Results are appended to a single CSV file.

EROSION Cases (IEEE 10646806):
    Case 1: ROA exists, MaxLength = prefix length     -> Safest
    Case 2: ROA exists, MaxLength > prefix length     -> Vulnerable despite RPKI
    Case 3: No ROA, prefix is /24                     -> Partial protection
    Case 4: No ROA, prefix larger than /24            -> Most vulnerable

Usage:
    Phase 1 — single IP:
        python bgp_risk_analyzer.py --ip 127.0.0.1

    Phase 2 — IP list from file:
        python bgp_risk_analyzer.py --ip_filename targets_ips.txt

    Phase 3 — single URL (DNS resolve then Phase 1):
        python bgp_risk_analyzer.py --url https://xyz.com

    Phase 4 — URL list from file:
        python bgp_risk_analyzer.py --url_filename targets_urls.txt
"""

import argparse
import csv
import json
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


RESULTS_DIR = Path(__file__).parent / "results"
CSV_FILE = RESULTS_DIR / "scan_results.csv"
USER_AGENT = "BGP-Risk-Analyzer/1.0"

CSV_HEADERS = [
    "IP Addresses",
    "URL",
    "Ping Status",
    "ASN",
    "Hostname",
    "Company Name",
    "Range",
    "Location (City; Region; Country)",
    "ROA Return",
    "Prefix",
    "MaxLength",
    "Erosion Case?",
    "Erosion Description",
    "Last accessed",
]


# ── Network utilities ────────────────────────────────────────────────────────


def fetch_json(url: str, timeout: int = 20) -> dict:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    response = urlopen(req, timeout=timeout)
    return json.loads(response.read().decode("utf-8"))


def resolve_hostname(url_or_hostname: str) -> tuple[str, str]:
    """Extract hostname from URL and resolve to IPv4 address."""
    if "://" not in url_or_hostname:
        url_or_hostname = f"https://{url_or_hostname}"
    hostname = urlparse(url_or_hostname).hostname
    ip = socket.gethostbyname(hostname)
    return hostname, ip


def ping_host(ip: str, count: int = 4) -> tuple[bool, str]:
    """Ping an IP and return (is_reachable, raw_output)."""
    flag = "-n" if sys.platform == "win32" else "-c"
    try:
        result = subprocess.run(
            ["ping", flag, str(count), ip],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return result.returncode == 0, result.stdout
    except subprocess.TimeoutExpired:
        return False, "Ping timed out"


# ── IP intelligence ──────────────────────────────────────────────────────────


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


def get_announced_prefix(ip: str) -> tuple[str, str]:
    """Get the BGP-announced prefix and origin ASN for an IP from RIPE Stat."""
    data = fetch_json(
        f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
    )
    prefix = data["data"].get("prefix", "")
    asns = data["data"].get("asns", [])
    asn = f"AS{asns[0]}" if asns else ""
    return prefix, asn


# ── RPKI validation & EROSION classification ─────────────────────────────────


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


# ── Display ──────────────────────────────────────────────────────────────────


def print_header(text: str):
    print(f"\n{'=' * 64}")
    print(f"  {text}")
    print(f"{'=' * 64}")


def print_field(label: str, value: str, indent: int = 2):
    padding = 32 - len(label)
    dots = "." * max(padding, 2)
    print(f"{' ' * indent}{label}{dots} {value}")


def display_resolution(hostname: str, ip: str, input_url: str):
    print_header("DNS RESOLUTION")
    print_field("Input", input_url)
    print_field("Hostname", hostname)
    print_field("Resolved IP", ip)


def display_ping(ip: str, is_alive: bool, output: str):
    print_header("PING CHECK")
    print_field("Target", ip)
    print_field("Status", "ACTIVE" if is_alive else "DEACTIVE")
    for line in output.strip().split("\n"):
        stripped = line.strip()
        keywords = ["average", "avg", "packets", "loss", "round-trip", "rtt"]
        if any(kw in stripped.lower() for kw in keywords):
            print(f"    {stripped}")


def display_ipinfo(info: dict):
    print_header("IP INTELLIGENCE (ipinfo.io)")
    print_field("IP Address", info["ip"])
    print_field("Hostname", info["hostname"] or "(none)")
    print_field("Location", f"{info['city']}, {info['region']}, {info['country']}")
    print_field("Organization", info["org"])
    print_field("ASN", info["asn"] or "(not found)")
    print_field("ASN Name", info["asn_name"] or "(not found)")


def display_rpki(result: dict):
    print_header("RPKI / ROA ANALYSIS (RIPE Stat)")
    print_field("Announced Prefix", result["prefix"])
    print_field("Prefix Length", f"/{result['prefix_length']}")
    print_field("Origin ASN", result["asn"])
    print_field("ROA Exists", "Yes" if result["roa_exists"] else "No")
    print_field("RPKI Validity", result["validity"].upper())
    if result["max_length"] is not None:
        print_field("ROA MaxLength", f"/{result['max_length']}")
    if result["gap"] is not None and result["gap"] > 0:
        print_field("MaxLength Gap", f"{result['gap']} levels")

    if result["all_roas"]:
        print(f"\n  Covering ROAs:")
        for roa in result["all_roas"]:
            print(
                f"    {roa['origin']} | {roa['prefix']} | "
                f"MaxLen /{roa['max_length']} | {roa['validity']}"
            )

    print_header(f"EROSION CLASSIFICATION: CASE {result['erosion_case']}")
    print(f"  {result['erosion_description']}")


# ── CSV persistence ──────────────────────────────────────────────────────────


def append_to_csv(row: dict):
    """Append a single result row to the CSV file.

    Creates the file with headers if it does not exist yet.
    Uses semicolon delimiter and UTF-8 BOM for native Microsoft Excel
    compatibility on European locale systems.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    file_exists = CSV_FILE.exists()

    if not file_exists:
        # New file: BOM + headers + first row
        with open(CSV_FILE, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, delimiter=";")
            writer.writeheader()
            writer.writerow(row)
    else:
        # Existing file: append row
        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, delimiter=";")
            writer.writerow(row)

    print(f"\n  Result appended to: {CSV_FILE}")


# ── Core flow ────────────────────────────────────────────────────────────────


def analyze_ip(ip: str, url: str = "", auto_proceed: bool = False) -> dict | None:
    """Full analysis pipeline for a single IP.

    Parameters
    ----------
    ip : str
        The IP address to analyze.
    url : str
        The original URL if the IP was resolved from a URL (Phase 3/4).
        Left empty for direct IP input (Phase 1/2).
    auto_proceed : bool
        If True, skip the interactive confirmation prompt (used in batch modes).

    Returns the CSV row dict, or None if analysis was skipped/failed.
    """
    # Step 1: Ping
    is_alive, ping_output = ping_host(ip)
    display_ping(ip, is_alive, ping_output)
    ping_status = "Active" if is_alive else "Deactive"

    # Interactive confirmation (only for single --ip / --url)
    if not auto_proceed:
        print()
        proceed = input("  Proceed with RPKI analysis? [y/n]: ").strip().lower()
        if proceed != "y":
            print("\n  Stopped.")
            return None

    # Step 2: ipinfo.io
    ipinfo = query_ipinfo(ip)
    display_ipinfo(ipinfo)

    # Step 3: Get BGP announced prefix from RIPE Stat
    prefix, ripe_asn = get_announced_prefix(ip)
    asn = ripe_asn or ipinfo["asn"]

    if not prefix:
        print(f"\n  No announced BGP prefix found for {ip}. Cannot perform RPKI analysis.")
        return None
    if not asn:
        print(f"\n  No ASN found for {ip}. Cannot perform RPKI analysis.")
        return None

    print_field("BGP Prefix (RIPE Stat)", prefix, indent=2)
    print_field("Origin ASN (RIPE Stat)", asn, indent=2)

    # Step 4: RPKI validation and EROSION classification
    rpki = validate_rpki(asn, prefix)
    display_rpki(rpki)

    # Step 5: Build CSV row and append
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    max_length_str = f"/{rpki['max_length']}" if rpki["max_length"] is not None else ""
    location = f"{ipinfo['city']}; {ipinfo['region']}; {ipinfo['country']}"

    row = {
        "IP Addresses": ip,
        "URL": url,
        "Ping Status": ping_status,
        "ASN": asn,
        "Hostname": ipinfo["hostname"],
        "Company Name": ipinfo["asn_name"],
        "Range": prefix,
        "Location (City; Region; Country)": location,
        "ROA Return": "Valid" if rpki["roa_exists"] else "Not Valid",
        "Prefix": rpki["prefix"],
        "MaxLength": max_length_str,
        "Erosion Case?": rpki["erosion_case"],
        "Erosion Description": rpki["erosion_description"],
        "Last accessed": now,
    }

    append_to_csv(row)
    return row


def run_ip_file(filepath: str):
    """Phase 2: Read a file of IP addresses, run Phase 1 for each."""
    path = Path(filepath)
    if not path.exists():
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    lines = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    print(f"Loaded {len(lines)} IP addresses from {path.name}\n")

    results = []
    for i, ip in enumerate(lines, 1):
        print(f"\n{'#' * 64}")
        print(f"  TARGET {i}/{len(lines)}: {ip}")
        print(f"{'#' * 64}")

        row = analyze_ip(ip, url="", auto_proceed=True)
        if row:
            results.append(row)

    print_batch_summary(results)


def run_url_file(filepath: str):
    """Phase 4: Read a file of URLs, resolve DNS (Phase 3), then run Phase 1."""
    path = Path(filepath)
    if not path.exists():
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    lines = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    print(f"Loaded {len(lines)} URLs from {path.name}\n")

    results = []
    for i, target_url in enumerate(lines, 1):
        print(f"\n{'#' * 64}")
        print(f"  TARGET {i}/{len(lines)}: {target_url}")
        print(f"{'#' * 64}")

        try:
            hostname, ip = resolve_hostname(target_url)
            display_resolution(hostname, ip, target_url)
        except (socket.gaierror, socket.herror) as e:
            print(f"\n  DNS resolution failed for {target_url}: {e}")
            continue

        row = analyze_ip(ip, url=target_url, auto_proceed=True)
        if row:
            results.append(row)

    print_batch_summary(results)


def print_batch_summary(results: list[dict]):
    """Print a summary table after batch processing."""
    if not results:
        print("\n  No results to summarize.")
        return

    print_header("BATCH SUMMARY")
    for r in results:
        target = r["URL"] or r["IP Addresses"]
        print(
            f"  {target:.<40} Case {r['Erosion Case?']} | "
            f"{r['Prefix']} | {r['ASN']} | "
            f"{r['ROA Return']} | {r['Ping Status']}"
        )
    print(f"\n  Total: {len(results)} targets scanned")
    print(f"  Results in: {CSV_FILE}")


# ── Entry point ──────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="BGP Risk Analyzer — assess BGP hijacking vulnerability using EROSION classification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Phase 1:  python bgp_risk_analyzer.py --ip 127.0.0.1
  Phase 2:  python bgp_risk_analyzer.py --ip_filename targets_ips.txt
  Phase 3:  python bgp_risk_analyzer.py --url https://xyz.com
  Phase 4:  python bgp_risk_analyzer.py --url_filename targets_urls.txt
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="Phase 1: Single IP address to analyze")
    group.add_argument("--ip_filename", help="Phase 2: Text file with one IP address per line")
    group.add_argument("--url", help="Phase 3: Single URL to resolve and analyze")
    group.add_argument("--url_filename", help="Phase 4: Text file with one URL per line")
    args = parser.parse_args()

    if args.ip:
        # Phase 1: Single IP
        analyze_ip(args.ip)

    elif args.ip_filename:
        # Phase 2: IP list from file
        run_ip_file(args.ip_filename)

    elif args.url:
        # Phase 3: Single URL → DNS resolve → Phase 1
        try:
            hostname, ip = resolve_hostname(args.url)
            display_resolution(hostname, ip, args.url)
        except (socket.gaierror, socket.herror) as e:
            print(f"DNS resolution failed for {args.url}: {e}")
            sys.exit(1)
        analyze_ip(ip, url=args.url)

    elif args.url_filename:
        # Phase 4: URL list from file
        run_url_file(args.url_filename)


if __name__ == "__main__":
    main()
