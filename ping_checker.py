"""Ping all unique IPs and track their status over time.

Each run adds a new column to ip_ping_status.csv with the current timestamp
as the header and Active/Inactive as values. Previous columns are preserved,
building a longitudinal view of IP availability.
"""

import csv
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from config import IP_PING_STATUS_FILE, UNIQUE_IPS_CSV_FILE


def _ping_one(ip: str, timeout: int = 5) -> tuple[str, bool]:
    """Ping a single IP and return (ip, is_reachable).

    Uses a single ping packet with a short timeout for speed.
    """
    flag = "-n" if sys.platform == "win32" else "-c"
    w_flag = "-w" if sys.platform == "win32" else "-W"
    # Windows -w is in milliseconds, Linux -W is in seconds
    w_val = str(timeout * 1000) if sys.platform == "win32" else str(timeout)
    try:
        result = subprocess.run(
            ["ping", flag, "1", w_flag, w_val, ip],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        return ip, result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return ip, False


def run_ping_test(max_workers: int = 200):
    """Read unique IPs, ping them in parallel, update the status CSV."""

    # -- Load unique IPs -----------------------------------------------------
    if not UNIQUE_IPS_CSV_FILE.exists():
        print("  No unique_scan_ips.csv found. Run a scan and refresh unique IPs first.")
        return

    with open(UNIQUE_IPS_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter=";")
        ips = []
        for row in reader:
            ip = row.get("IP Addresses", "").strip()
            if ip:
                ips.append(ip)

    if not ips:
        print("  No IPs found in unique_scan_ips.csv.")
        return

    # Deduplicate while preserving order
    seen = set()
    unique_ips = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    total = len(unique_ips)
    print(f"\n  Pinging {total} unique IPs with {max_workers} parallel workers...")

    # -- Ping all IPs --------------------------------------------------------
    start = time.time()
    results: dict[str, str] = {}
    done_count = 0

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ping_one, ip): ip for ip in unique_ips}
        for future in as_completed(futures):
            ip, is_alive = future.result()
            results[ip] = "Active" if is_alive else "Inactive"
            done_count += 1
            if done_count % 100 == 0 or done_count == total:
                print(f"    Progress: {done_count}/{total}")

    elapsed = round(time.time() - start, 1)

    # -- Build the new column header -----------------------------------------
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    new_col = f"Status on {now}"

    # -- Read existing CSV (if any) ------------------------------------------
    existing_headers: list[str] = []
    existing_rows: dict[str, dict] = {}  # keyed by IP

    if IP_PING_STATUS_FILE.exists():
        with open(IP_PING_STATUS_FILE, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f, delimiter=";")
            existing_headers = list(reader.fieldnames or [])
            for row in reader:
                ip = row.get("IP Address", "").strip()
                if ip:
                    existing_rows[ip] = dict(row)

    # -- Build merged headers ------------------------------------------------
    if existing_headers:
        headers = existing_headers + [new_col]
    else:
        headers = ["IP Address", new_col]

    # -- Merge data ----------------------------------------------------------
    all_ips = list(dict.fromkeys(
        list(existing_rows.keys()) + unique_ips
    ))

    output_rows = []
    for ip in all_ips:
        row = existing_rows.get(ip, {"IP Address": ip})
        row["IP Address"] = ip
        # Fill new column
        row[new_col] = results.get(ip, "")
        # Ensure all headers have a value
        for h in headers:
            if h not in row:
                row[h] = ""
        output_rows.append(row)

    # -- Write CSV -----------------------------------------------------------
    with open(IP_PING_STATUS_FILE, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers, delimiter=";", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(output_rows)

    # -- Summary -------------------------------------------------------------
    active = sum(1 for v in results.values() if v == "Active")
    inactive = total - active
    status_cols = [h for h in headers if h.startswith("Status on ")]

    print(f"\n  Ping test complete in {elapsed}s")
    print(f"    Active:   {active}/{total}")
    print(f"    Inactive: {inactive}/{total}")
    print(f"    Total status snapshots: {len(status_cols)}")
    print(f"    Saved to: {IP_PING_STATUS_FILE}")
