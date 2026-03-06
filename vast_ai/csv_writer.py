"""CSV persistence for Vast.ai machine scan results with change detection."""

import csv

from config import (
    RESULTS_DIR,
    VAST_CHANGES_CSV_FILE,
    VAST_CHANGES_CSV_HEADERS,
    VAST_COMPARE_FIELDS,
    VAST_CSV_FILE,
    VAST_CSV_HEADERS,
    VAST_FAILURES_CSV_FILE,
    VAST_FAILURES_CSV_HEADERS,
)


def _find_existing_by_ip(ip: str) -> list[dict]:
    """Return all CSV rows where 'IP Address' matches *ip*."""
    if not VAST_CSV_FILE.exists():
        return []
    rows = []
    try:
        with open(VAST_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f, delimiter=";"):
                if row.get("IP Address", "").strip() == ip:
                    rows.append(row)
    except Exception as e:
        print(f"  Warning: Could not read Vast CSV for change check: {e}")
    return rows


def _detect_changes(old_row: dict, new_row: dict) -> list[tuple[str, str, str]]:
    """Compare two rows on VAST_COMPARE_FIELDS.

    Returns list of (field_name, old_value, new_value) for fields that differ.
    """
    changes = []
    for field in VAST_COMPARE_FIELDS:
        old_val = str(old_row.get(field, "")).strip()
        new_val = str(new_row.get(field, "")).strip()
        if old_val != new_val:
            changes.append((field, old_val, new_val))
    return changes


def _append_changes_csv(
    ip: str,
    changes: list[tuple[str, str, str]],
    prev_timestamp: str,
    curr_timestamp: str,
):
    """Append change records to the Vast.ai changes log CSV."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    file_exists = VAST_CHANGES_CSV_FILE.exists()

    mode = "a" if file_exists else "w"
    encoding = "utf-8" if file_exists else "utf-8-sig"

    with open(VAST_CHANGES_CSV_FILE, mode, newline="", encoding=encoding) as f:
        writer = csv.DictWriter(
            f, fieldnames=VAST_CHANGES_CSV_HEADERS, delimiter=";"
        )
        if not file_exists:
            writer.writeheader()

        for field, old_val, new_val in changes:
            writer.writerow({
                "IP Address": ip,
                "Field Changed": field,
                "Previous Value": old_val,
                "New Value": new_val,
                "Previous Scan Timestamp": prev_timestamp,
                "Current Scan Timestamp": curr_timestamp,
            })


def _write_row(row: dict):
    """Write a single row to the Vast CSV (handles file creation)."""
    file_exists = VAST_CSV_FILE.exists()

    if not file_exists:
        with open(VAST_CSV_FILE, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=VAST_CSV_HEADERS, delimiter=";")
            writer.writeheader()
            writer.writerow(row)
    else:
        with open(VAST_CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=VAST_CSV_HEADERS, delimiter=";")
            writer.writerow(row)

    print(f"\n  Vast result appended to: {VAST_CSV_FILE}")


def append_to_vast_csv(row: dict) -> str:
    """Append a Vast.ai machine result row with change detection.

    Always appends the row (never skips). Compares against previous
    rows with the same IP Address and flags changes.

    Returns "new", "changed", "unchanged", or "no_ip".
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    ip = str(row.get("IP Address", "")).strip()
    if not ip:
        return "no_ip"

    # Look up previous rows with this IP
    existing = _find_existing_by_ip(ip)
    crawl_number = len(existing) + 1
    row["Crawl Number"] = str(crawl_number)

    if not existing:
        row["Changes in Crawl Number"] = ""
        _write_row(row)
        return "new"

    # Compare against most recent row (by Scan Timestamp)
    existing.sort(key=lambda r: r.get("Scan Timestamp", ""), reverse=True)
    most_recent = existing[0]
    changes = _detect_changes(most_recent, row)

    if changes:
        row["Changes in Crawl Number"] = str(crawl_number)
        _append_changes_csv(
            ip,
            changes,
            prev_timestamp=most_recent.get("Scan Timestamp", ""),
            curr_timestamp=row.get("Scan Timestamp", ""),
        )
        changed_names = [c[0] for c in changes]
        print(f"  Change detected for IP {ip}: {', '.join(changed_names)}")
        _write_row(row)
        return "changed"
    else:
        row["Changes in Crawl Number"] = ""
        _write_row(row)
        return "unchanged"


def append_vast_failure_csv(result: dict, timestamp: str):
    """Log a failed Vast.ai scan to the failures CSV."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    machine = result.get("machine", {})

    row = {
        "Crawl Timestamp": timestamp,
        "IP Address": result.get("ip", ""),
        "Machine ID": str(machine.get("machine_id", "")),
        "Host ID": str(machine.get("host_id", "")),
        "GPU Type": machine.get("gpu_name", ""),
        "Num GPUs": str(machine.get("num_gpus", "")),
        "Error Type": result.get("error_type", "unknown"),
        "Error Message": str(result.get("error", ""))[:500],
    }

    file_exists = VAST_FAILURES_CSV_FILE.exists()
    mode = "a" if file_exists else "w"
    encoding = "utf-8" if file_exists else "utf-8-sig"

    with open(VAST_FAILURES_CSV_FILE, mode, newline="", encoding=encoding) as f:
        writer = csv.DictWriter(
            f, fieldnames=VAST_FAILURES_CSV_HEADERS, delimiter=";"
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
