"""CSV persistence for Prime Intellect pod scan results."""

import csv

from config import PRIME_CSV_FILE, PRIME_CSV_HEADERS, RESULTS_DIR

# Fields that identify a unique offering.  If two rows share the same
# Pod IP *and* identical values for all these fields, the second row is
# a true duplicate (same machine, different Pod ID) and is skipped.
_DEDUP_FIELDS = ("Pod IP", "GPU Type", "GPU Count", "Provider Type")


def _find_duplicate(row: dict) -> bool:
    """Return True if an existing row matches on Pod IP + offering fields."""
    pod_ip = row.get("Pod IP", "").strip()
    if not pod_ip:
        return False  # no IP → failed pod, always keep

    if not PRIME_CSV_FILE.exists():
        return False

    try:
        with open(PRIME_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
            for existing in csv.DictReader(f, delimiter=";"):
                if all(
                    str(existing.get(k, "")).strip() == str(row.get(k, "")).strip()
                    for k in _DEDUP_FIELDS
                ):
                    return True
    except Exception:
        pass
    return False


def append_to_prime_csv(row: dict) -> str:
    """Append a single Prime pod result row to the Prime CSV file.

    Skips true duplicates (same Pod IP + GPU Type + GPU Count + Provider).
    Creates the file with headers if it does not exist yet.
    Uses semicolon delimiter and UTF-8 BOM for Excel compatibility.

    Returns "new", "skipped", or "no_ip" (failed pod, always kept).
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Skip offerings that completely failed to provision (no Pod ID at all).
    # These produce blank rows with only API responses and Availability Data.
    pod_id = str(row.get("Pod ID", "")).strip()
    if not pod_id:
        return "no_pod_id"

    pod_ip = row.get("Pod IP", "")
    if isinstance(pod_ip, list):
        pod_ip = pod_ip[0] if pod_ip else ""
        row["Pod IP"] = pod_ip
    pod_ip = str(pod_ip).strip()

    if pod_ip and _find_duplicate(row):
        print(f"\n  Skipped: Pod IP {pod_ip} with same offering already in CSV.")
        return "skipped"

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
    return "no_ip" if not pod_ip else "new"
