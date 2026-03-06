"""CSV persistence for Prime Intellect pod scan results with change detection."""

import csv

from config import (
    PI_FAILURES_CSV_FILE,
    PI_FAILURES_CSV_HEADERS,
    PRIME_CHANGES_CSV_FILE,
    PRIME_CHANGES_CSV_HEADERS,
    PRIME_COMPARE_FIELDS,
    PRIME_CSV_FILE,
    PRIME_CSV_HEADERS,
    RESULTS_DIR,
)

# Old filename before the rename (for migration)
_OLD_FAILURES_FILE = RESULTS_DIR / "crawl_failures.csv"


def _find_existing_by_pod_id(pod_id: str) -> list[dict]:
    """Return all CSV rows where 'Pod ID' matches *pod_id*."""
    if not PRIME_CSV_FILE.exists():
        return []
    rows = []
    try:
        with open(PRIME_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f, delimiter=";"):
                if row.get("Pod ID", "").strip() == pod_id:
                    rows.append(row)
    except Exception as e:
        print(f"  Warning: Could not read CSV for change check: {e}")
    return rows


def _detect_changes(old_row: dict, new_row: dict) -> list[tuple[str, str, str]]:
    """Compare two rows on PRIME_COMPARE_FIELDS.

    Returns list of (field_name, old_value, new_value) for fields that differ.
    """
    changes = []
    for field in PRIME_COMPARE_FIELDS:
        old_val = str(old_row.get(field, "")).strip()
        new_val = str(new_row.get(field, "")).strip()
        if old_val != new_val:
            changes.append((field, old_val, new_val))
    return changes


def _append_changes_csv(
    pod_id: str,
    changes: list[tuple[str, str, str]],
    prev_timestamp: str,
    curr_timestamp: str,
):
    """Append change records to the changes log CSV (one row per changed field)."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    file_exists = PRIME_CHANGES_CSV_FILE.exists()

    mode = "a" if file_exists else "w"
    encoding = "utf-8" if file_exists else "utf-8-sig"

    with open(PRIME_CHANGES_CSV_FILE, mode, newline="", encoding=encoding) as f:
        writer = csv.DictWriter(
            f, fieldnames=PRIME_CHANGES_CSV_HEADERS, delimiter=";"
        )
        if not file_exists:
            writer.writeheader()

        for field, old_val, new_val in changes:
            writer.writerow({
                "Pod ID": pod_id,
                "Field Changed": field,
                "Previous Value": old_val,
                "New Value": new_val,
                "Previous Scan Timestamp": prev_timestamp,
                "Current Scan Timestamp": curr_timestamp,
            })


def _ensure_prime_csv_headers_current():
    """If the CSV exists with old headers, migrate to the current column set."""
    if not PRIME_CSV_FILE.exists():
        return

    try:
        with open(PRIME_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f, delimiter=";")
            existing_headers = reader.fieldnames
            if not existing_headers:
                return
            if "Crawl Number" in existing_headers:
                return  # already current
            rows = list(reader)
    except Exception:
        return

    # Rewrite with all current headers (backfill missing columns with "")
    with open(PRIME_CSV_FILE, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=PRIME_CSV_HEADERS, delimiter=";")
        writer.writeheader()
        for row in rows:
            for header in PRIME_CSV_HEADERS:
                row.setdefault(header, "")
            writer.writerow(row)

    print(f"  Migrated Prime CSV to {len(PRIME_CSV_HEADERS)}-column format.")


def _write_row(row: dict):
    """Write a single row to the Prime CSV (handles file creation)."""
    file_exists = PRIME_CSV_FILE.exists()

    if not file_exists:
        with open(PRIME_CSV_FILE, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=PRIME_CSV_HEADERS, delimiter=";")
            writer.writeheader()
            writer.writerow(row)
    else:
        with open(PRIME_CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=PRIME_CSV_HEADERS, delimiter=";")
            writer.writerow(row)

    print(f"\n  Prime result appended to: {PRIME_CSV_FILE}")


def append_to_prime_csv(row: dict) -> str:
    """Append a Prime pod result row with change detection.

    Always appends the row (never skips).  Compares against previous
    rows with the same Pod ID and flags changes.

    Returns "new", "changed", "unchanged", or "no_pod_id".
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_prime_csv_headers_current()

    # Skip offerings that completely failed to provision
    pod_id = str(row.get("Pod ID", "")).strip()
    if not pod_id:
        return "no_pod_id"

    # Normalize Pod IP (some providers return list)
    pod_ip = row.get("Pod IP", "")
    if isinstance(pod_ip, list):
        pod_ip = pod_ip[0] if pod_ip else ""
        row["Pod IP"] = pod_ip

    # Look up previous rows with this Pod ID
    existing = _find_existing_by_pod_id(pod_id)
    crawl_number = len(existing) + 1
    row["Crawl Number"] = str(crawl_number)

    if not existing:
        # First time seeing this Pod ID
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
            pod_id,
            changes,
            prev_timestamp=most_recent.get("Scan Timestamp", ""),
            curr_timestamp=row.get("Scan Timestamp", ""),
        )
        changed_names = [c[0] for c in changes]
        print(f"  Change detected for Pod ID {pod_id}: {', '.join(changed_names)}")
        _write_row(row)
        return "changed"
    else:
        row["Changes in Crawl Number"] = ""
        _write_row(row)
        return "unchanged"


def _migrate_failures_file():
    """Rename old crawl_failures.csv -> crawl_failures_pi.csv if needed."""
    if _OLD_FAILURES_FILE.exists() and not PI_FAILURES_CSV_FILE.exists():
        _OLD_FAILURES_FILE.rename(PI_FAILURES_CSV_FILE)
        print(f"  Renamed {_OLD_FAILURES_FILE.name} -> {PI_FAILURES_CSV_FILE.name}")


def append_failure_csv(result: dict, timestamp: str):
    """Log a failed pod attempt to the PI failures CSV.

    Called for every result where result["error"] is truthy.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _migrate_failures_file()
    offering = result.get("offering", {})

    row = {
        "Crawl Timestamp": timestamp,
        "GPU Type": offering.get("gpuType", offering.get("gpu_type", "")),
        "Socket": offering.get("socket", ""),
        "GPU Count": str(offering.get("gpuCount", offering.get("gpu_count", ""))),
        "Provider": offering.get("provider", offering.get("providerType", "")),
        "Region": offering.get("region", ""),
        "Data Center": offering.get("dataCenter", offering.get("data_center_id", "")),
        "Cloud ID": offering.get("cloudId", offering.get("cloud_id", "")),
        "Error Type": result.get("error_type", "unknown"),
        "Error Message": str(result.get("error", ""))[:500],
        "Pod ID": result.get("pod_id") or "",
        "Price per Hour": str(
            offering.get("prices", {}).get("onDemand", "")
            if isinstance(offering.get("prices"), dict)
            else ""
        ),
    }

    file_exists = PI_FAILURES_CSV_FILE.exists()
    mode = "a" if file_exists else "w"
    encoding = "utf-8" if file_exists else "utf-8-sig"

    with open(PI_FAILURES_CSV_FILE, mode, newline="", encoding=encoding) as f:
        writer = csv.DictWriter(
            f, fieldnames=PI_FAILURES_CSV_HEADERS, delimiter=";"
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
