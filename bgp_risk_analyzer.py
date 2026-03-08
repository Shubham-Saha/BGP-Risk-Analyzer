"""BGP Risk Analyzer -- Assess BGP hijacking vulnerability of network endpoints.

Interactive tool that performs DNS resolution, ping checks, IP geolocation
via ipinfo.io, ASN identification, RPKI/ROA validation via RIPE Stat,
and EROSION attack case classification.

EROSION Cases (IEEE 10646806):
    Case 1: ROA exists, MaxLength = prefix length     -> Lowest risk
    Case 2: ROA exists, MaxLength > prefix length     -> High risk
    Case 3: No ROA, prefix is /24                     -> High risk (constrained)
    Case 4: No ROA, prefix larger than /24            -> Highest risk

Note: No case is fully safe. RPKI validates origin AS only, not the AS path.
Even Case 1 is susceptible to forged-origin same-prefix hijacks.

Usage:
    python bgp_risk_analyzer.py
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from csv_writer import append_to_csv_dedup
from display import (
    display_ipinfo,
    display_ping,
    display_resolution,
    display_rpki,
    print_batch_summary,
    print_field,
)
from ripe_ipinfo import query_ripe_ipinfo
from network import ping_host, resolve_hostname
from rpki import get_announced_prefix, validate_rpki


# -- Core analysis ------------------------------------------------------------


def analyze_ip(
    ip: str, url: str = "", auto_proceed: bool = False, platform: str = ""
) -> dict | None:
    """Full analysis pipeline for a single IP.

    Returns the CSV row dict, or None if analysis was skipped/failed.
    """
    # Step 1: Ping
    is_alive, ping_output = ping_host(ip)
    display_ping(ip, is_alive, ping_output)
    ping_status = "Active" if is_alive else "Deactive"

    # Interactive confirmation (skipped in batch/auto modes)
    if not auto_proceed:
        print()
        proceed = input("  Proceed with RPKI analysis? [y/n]: ").strip().lower()
        if proceed != "y":
            print("\n  Stopped.")
            return None

    # Step 2: ipinfo.io + RIPE Stat network-info (parallel)
    # Time each call individually (they run concurrently)
    def _timed(fn, *args):
        t = time.time()
        result = fn(*args)
        return result, round(time.time() - t, 2)

    with ThreadPoolExecutor(max_workers=2) as pool:
        ipinfo_future = pool.submit(_timed, query_ripe_ipinfo, ip)
        prefix_future = pool.submit(_timed, get_announced_prefix, ip)
        ipinfo, ipinfo_seconds = ipinfo_future.result()
        (prefix, ripe_asn), prefix_seconds = prefix_future.result()

    display_ipinfo(ipinfo)
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
    t_rpki = time.time()
    rpki = validate_rpki(asn, prefix)
    rpki_seconds = round(time.time() - t_rpki, 2)
    display_rpki(rpki)

    # Step 5: Build CSV row and append (with deduplication)
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
        "New Info after rescan?": "",
        "Platform": platform,
    }

    append_to_csv_dedup(row)

    # Attach timing data AFTER CSV write (extra keys would cause DictWriter error)
    row["_ipinfo_seconds"] = ipinfo_seconds
    row["_prefix_seconds"] = prefix_seconds
    row["_rpki_seconds"] = rpki_seconds
    return row


# -- Batch helpers ------------------------------------------------------------


def run_ip_file(filepath: str):
    """Read a file of IP addresses, run analysis for each."""
    path = Path(filepath)
    if not path.exists():
        print(f"  Error: File not found: {filepath}")
        return

    lines = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    print(f"  Loaded {len(lines)} IP addresses from {path.name}\n")

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
    """Read a file of URLs, resolve DNS, then run analysis for each."""
    path = Path(filepath)
    if not path.exists():
        print(f"  Error: File not found: {filepath}")
        return

    lines = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    print(f"  Loaded {len(lines)} URLs from {path.name}\n")

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


# -- Phase 5: Prime Intellect ------------------------------------------------


def run_prime_interactive():
    """Phase 5: Auto-discover GPU offerings, scan each pod's IP.

    Flow per offering:
        Discover -> Create pod -> Wait for IP -> Get details/logs ->
        BGP analysis (while pod is alive) -> Terminate pod -> Save CSV
    """
    from prime_intellect import (
        append_failure_csv,
        append_to_prime_csv,
        build_prime_csv_row,
        display_pod_result,
        display_prime_scan_summary,
        get_api_key,
        get_team_id,
        scan_all_pods,
    )

    api_key = get_api_key()
    if not api_key:
        return

    team_id = get_team_id()
    if not team_id:
        return

    def bgp_analyze(ip: str) -> dict | None:
        """Run BGP analysis on a pod IP (called after termination)."""
        return analyze_ip(ip, url="", auto_proceed=True, platform="PI")

    def on_pod_done(index: int, total: int, result: dict):
        """Save CSV and display result after each pod is processed.

        Thread-safe: always called from the single background CSV
        writer thread, never from multiple threads simultaneously.
        """
        pod_ip = result.get("pod_ip", "")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Log failures to separate CSV for analysis
        if result.get("error"):
            try:
                append_failure_csv(result, now)
            except Exception as e:
                print(f"    Warning: Failed to log failure: {e}")

        prime_row = build_prime_csv_row(result)
        t_csv = time.time()
        status = append_to_prime_csv(prime_row)
        result["_csv_save_seconds"] = round(time.time() - t_csv, 2)
        if status == "changed":
            print(f"    [{index}/{total}] [CHANGE DETECTED] Pod ID reused with different values.")
        display_pod_result(index, total, pod_ip, result.get("bgp_row"), result.get("error"))

    # scan_all_pods handles: discovery, pod creation loop, Ctrl+C
    # BGP analysis runs after each pod is terminated (only needs the IP)
    # CSV is saved after each pod via on_pod_done callback
    results = scan_all_pods(
        api_key,
        bgp_analyze=bgp_analyze,
        on_pod_done=on_pod_done,
        team_id=team_id,
    )

    if not results:
        print("\n  No pods were scanned.")
        return

    display_prime_scan_summary(results)


# -- Phase 6: Vast.ai --------------------------------------------------------


def run_vast_interactive():
    """Vast.ai: Fetch public machine listings, analyze each unique IP.

    No credentials needed -- uses Vast.ai's public search API.
    """
    from vast_ai import (
        append_to_vast_csv,
        append_vast_failure_csv,
        build_vast_csv_row,
        display_machine_result,
        display_vast_scan_summary,
        scan_all_machines,
    )

    def bgp_analyze(ip: str) -> dict | None:
        """Run BGP analysis on a machine IP."""
        return analyze_ip(ip, url="", auto_proceed=True, platform="Vast")

    def on_machine_done(index: int, total: int, result: dict):
        """Save CSV and display result after each IP is analyzed."""
        ip = result.get("ip", "")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if result.get("error"):
            try:
                append_vast_failure_csv(result, now)
            except Exception as e:
                print(f"    Warning: Failed to log failure: {e}")

        vast_row = build_vast_csv_row(result)
        t_csv = time.time()
        status = append_to_vast_csv(vast_row)
        result["_csv_save_seconds"] = round(time.time() - t_csv, 2)
        if status == "changed":
            print(f"    [{index}/{total}] [CHANGE DETECTED] IP reused with different values.")
        display_machine_result(index, total, ip, result.get("bgp_row"), result.get("error"))

    results = scan_all_machines(
        bgp_analyze=bgp_analyze,
        on_machine_done=on_machine_done,
    )

    if not results:
        print("\n  No IPs were scanned.")
        return

    display_vast_scan_summary(results)


# -- Phase 7: Ping Test (Unique IPs) -----------------------------------------


def run_ping_test_interactive():
    """Ping all unique IPs and track status over time."""
    from ping_checker import run_ping_test

    raw = input("\n  Parallel workers [default=200]: ").strip()
    max_workers = int(raw) if raw.isdigit() and int(raw) > 0 else 200
    run_ping_test(max_workers=max_workers)


# -- Interactive menu ---------------------------------------------------------


BANNER = """
================================================================
   ____   ____ ____    ____  _     _      _                _
  | __ ) / ___|  _ \\  |  _ \\(_)___| | __ / \\   _ __   __ _| |_   _ _______ _ __
  |  _ \\| |  _| |_) | | |_) | / __| |/ // _ \\ | '_ \\ / _` | | | | |_  / _ \\ '__|
  | |_) | |_| |  __/  |  _ <| \\__ \\   </ ___ \\| | | | (_| | | |_| |/ /  __/ |
  |____/ \\____|_|     |_| \\_\\_|___/_|\\_\\_/   \\_\\_| |_|\\__,_|_|\\__, /___\\___|_|
                                                               |___/
  Tool for BGP Hijacking Risk Assessment                  v2.1.0
================================================================
"""

MENU = """
  [1] Scan single IP address
  [2] Scan IP addresses from file
  [3] Scan single URL
  [4] Scan URLs from file
  [5] Prime Intellect GPU Pod Scan
  [6] Vast.ai GPU Machine Scan
  [7] Ping Test (Unique IPs)
  [8] Refresh Unique IPs (from scan_results.csv)
  [9] Generate Visualizations
  [10] Overlap Detection (PI vs Vast.ai)
  [11] Analysis
  [0] Exit
"""


def show_menu() -> str:
    """Display the menu and return the user's choice."""
    print(MENU)
    return input("  Select option: ").strip()


def interactive_main():
    """Main interactive loop -- keeps running until the user exits."""
    print(BANNER)

    while True:
        choice = show_menu()

        if choice == "0":
            print("\n  Goodbye!\n")
            break

        elif choice == "1":
            ip = input("\n  Enter IP address: ").strip()
            if ip:
                analyze_ip(ip)
            else:
                print("  No IP entered.")

        elif choice == "2":
            filepath = input("\n  Enter file path: ").strip()
            if filepath:
                run_ip_file(filepath)
            else:
                print("  No file path entered.")

        elif choice == "3":
            url = input("\n  Enter URL: ").strip()
            if url:
                try:
                    hostname, ip = resolve_hostname(url)
                    display_resolution(hostname, ip, url)
                    analyze_ip(ip, url=url)
                except (socket.gaierror, socket.herror) as e:
                    print(f"\n  DNS resolution failed for {url}: {e}")
            else:
                print("  No URL entered.")

        elif choice == "4":
            filepath = input("\n  Enter file path: ").strip()
            if filepath:
                run_url_file(filepath)
            else:
                print("  No file path entered.")

        elif choice == "5":
            run_prime_interactive()

        elif choice == "6":
            run_vast_interactive()

        elif choice == "7":
            run_ping_test_interactive()

        elif choice == "8":
            from csv_writer import refresh_unique_ips
            refresh_unique_ips()

        elif choice == "9":
            from visualization import run_visualizations
            run_visualizations()

        elif choice == "10":
            from overlap import run_overlap_check
            run_overlap_check()

        elif choice == "11":
            from analysis import run_analysis_menu
            run_analysis_menu()

        else:
            print("  Invalid option. Please select 0-11.")


# -- Entry point --------------------------------------------------------------


if __name__ == "__main__":
    interactive_main()
