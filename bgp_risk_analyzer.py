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
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from csv_writer import append_to_csv
from display import (
    display_ipinfo,
    display_ping,
    display_resolution,
    display_rpki,
    print_batch_summary,
    print_field,
)
from ipinfo import query_ipinfo
from network import ping_host, resolve_hostname
from rpki import get_announced_prefix, validate_rpki


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
        analyze_ip(args.ip)

    elif args.ip_filename:
        run_ip_file(args.ip_filename)

    elif args.url:
        try:
            hostname, ip = resolve_hostname(args.url)
            display_resolution(hostname, ip, args.url)
        except (socket.gaierror, socket.herror) as e:
            print(f"DNS resolution failed for {args.url}: {e}")
            sys.exit(1)
        analyze_ip(ip, url=args.url)

    elif args.url_filename:
        run_url_file(args.url_filename)


if __name__ == "__main__":
    main()
