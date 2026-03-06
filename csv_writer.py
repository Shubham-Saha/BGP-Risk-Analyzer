"""CSV persistence — append scan results to a semicolon-delimited CSV."""

import csv

from config import CSV_FILE, CSV_HEADERS, RESULTS_DIR

# Fields excluded from change detection (timestamps and the flag itself)
_SKIP_FIELDS = {"Last accessed", "New Info after rescan?"}


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


# ── Deduplication helpers ────────────────────────────────────────────────────


def _ensure_csv_headers_current():
    """If the CSV exists with old headers, migrate to current column set."""
    if not CSV_FILE.exists():
        return

    with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter=";")
        existing_headers = reader.fieldnames
        if not existing_headers:
            return
        if "Platform" in existing_headers:
            return  # already up to date
        rows = list(reader)

    # Rewrite with all current headers, backfill Platform with "PI" for old rows
    with open(CSV_FILE, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, delimiter=";")
        writer.writeheader()
        for row in rows:
            for h in CSV_HEADERS:
                row.setdefault(h, "")
            if not row.get("Platform"):
                row["Platform"] = "PI"
            writer.writerow(row)

    print(f"  Migrated CSV to {len(CSV_HEADERS)}-column format.")


def find_existing_rows(ip: str) -> list[dict]:
    """Return all CSV rows where 'IP Addresses' matches *ip*."""
    if not CSV_FILE.exists():
        return []

    rows = []
    try:
        with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f, delimiter=";")
            for row in reader:
                if row.get("IP Addresses") == ip:
                    rows.append(row)
    except Exception as e:
        print(f"  Warning: Could not read CSV for dedup check: {e}")
    return rows


def detect_changes(old_row: dict, new_row: dict) -> list[str]:
    """Compare two rows and return the list of field names that differ.

    Ignores 'Last accessed' and 'New Info after rescan?' fields.
    """
    changed = []
    for field in CSV_HEADERS:
        if field in _SKIP_FIELDS:
            continue
        old_val = str(old_row.get(field, "")).strip()
        new_val = str(new_row.get(field, "")).strip()
        if old_val != new_val:
            changed.append(field)
    return changed


def append_to_csv_dedup(row: dict) -> str:
    """Append a row with deduplication: skip if identical, flag if changed.

    Returns "new", "skipped", or "rescan_changed".
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_csv_headers_current()

    ip = row.get("IP Addresses", "")
    existing = find_existing_rows(ip)

    if not existing:
        # Brand new IP
        row["New Info after rescan?"] = ""
        append_to_csv(row)
        return "new"

    # Compare against the most recent row (by 'Last accessed' timestamp)
    existing.sort(key=lambda r: r.get("Last accessed", ""), reverse=True)
    most_recent = existing[0]
    changed_fields = detect_changes(most_recent, row)

    if not changed_fields:
        print(f"\n  Skipped: {ip} already in CSV with identical data.")
        return "skipped"

    # Something changed — add new row with the flag
    row["New Info after rescan?"] = "Yes: " + ", ".join(changed_fields)
    append_to_csv(row)
    print(f"  Rescan detected changes for {ip}: {', '.join(changed_fields)}")
    return "rescan_changed"
