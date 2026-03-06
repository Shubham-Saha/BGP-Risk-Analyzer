"""Cross-provider IP overlap detection between Prime Intellect and Vast.ai."""

import csv
from datetime import datetime, timezone

from config import (
    OVERLAP_CSV_FILE,
    OVERLAP_CSV_HEADERS,
    PRIME_CSV_FILE,
    RESULTS_DIR,
    VAST_CSV_FILE,
)
from display import print_field, print_header


def _read_pi_ips() -> dict[str, dict]:
    """Read Prime Intellect pod results and return {ip: row_data}."""
    ip_map: dict[str, dict] = {}
    if not PRIME_CSV_FILE.exists():
        return ip_map
    try:
        with open(PRIME_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f, delimiter=";"):
                ip = row.get("Pod IP", "").strip()
                if ip:
                    ip_map[ip] = row  # Latest row wins
    except Exception as e:
        print(f"  Warning: Could not read PI CSV: {e}")
    return ip_map


def _read_vast_ips() -> dict[str, dict]:
    """Read Vast.ai machine results and return {ip: row_data}."""
    ip_map: dict[str, dict] = {}
    if not VAST_CSV_FILE.exists():
        return ip_map
    try:
        with open(VAST_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f, delimiter=";"):
                ip = row.get("IP Address", "").strip()
                if ip:
                    ip_map[ip] = row
    except Exception as e:
        print(f"  Warning: Could not read Vast CSV: {e}")
    return ip_map


def detect_overlap() -> list[dict]:
    """Find IPs that appear in both PI and Vast.ai results.

    Saves overlap records to ip_overlap_results.csv and returns them.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    pi_ips = _read_pi_ips()
    vast_ips = _read_vast_ips()

    if not pi_ips:
        print("  No Prime Intellect results found. Run a PI scan first.")
        return []
    if not vast_ips:
        print("  No Vast.ai results found. Run a Vast.ai scan first.")
        return []

    common_ips = set(pi_ips.keys()) & set(vast_ips.keys())

    if not common_ips:
        print(f"\n  No overlap found between {len(pi_ips)} PI IPs and {len(vast_ips)} Vast IPs.")
        return []

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    overlaps = []

    for ip in sorted(common_ips):
        pi_row = pi_ips[ip]
        vast_row = vast_ips[ip]
        overlaps.append({
            "IP Address": ip,
            "PI Pod ID": pi_row.get("Pod ID", ""),
            "PI GPU Type": pi_row.get("GPU Type", ""),
            "PI Provider": pi_row.get("Provider Type", ""),
            "Vast Machine ID": vast_row.get("Machine ID", ""),
            "Vast GPU Type": vast_row.get("GPU Type", ""),
            "Vast Host ID": vast_row.get("Host ID", ""),
            "ASN": pi_row.get("ASN", vast_row.get("ASN", "")),
            "Prefix": pi_row.get("Prefix", vast_row.get("Prefix", "")),
            "Erosion Case?": pi_row.get("Erosion Case?", vast_row.get("Erosion Case?", "")),
            "Detection Timestamp": now,
        })

    # Write to CSV
    file_exists = OVERLAP_CSV_FILE.exists()
    mode = "a" if file_exists else "w"
    encoding = "utf-8" if file_exists else "utf-8-sig"

    with open(OVERLAP_CSV_FILE, mode, newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=OVERLAP_CSV_HEADERS, delimiter=";")
        if not file_exists:
            writer.writeheader()
        for row in overlaps:
            writer.writerow(row)

    return overlaps


def run_overlap_check():
    """Interactive entry point for overlap detection."""
    print_header("CROSS-PROVIDER OVERLAP DETECTION")
    print("  Comparing Prime Intellect pod IPs with Vast.ai machine IPs...\n")

    overlaps = detect_overlap()

    if not overlaps:
        print("\n  No overlapping IPs detected.")
        return

    print_field("Overlapping IPs Found", str(len(overlaps)))
    print()

    for o in overlaps:
        print(f"    {o['IP Address']}")
        print(f"      PI:   Pod {o['PI Pod ID']} / {o['PI GPU Type']} / {o['PI Provider']}")
        print(f"      Vast: Machine {o['Vast Machine ID']} / {o['Vast GPU Type']} / Host {o['Vast Host ID']}")
        print(f"      ASN: {o['ASN']} | Prefix: {o['Prefix']} | Case: {o['Erosion Case?']}")
        print()

    print(f"  Overlap results saved to: {OVERLAP_CSV_FILE}")
