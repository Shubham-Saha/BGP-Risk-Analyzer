"""CSV persistence — append scan results to a semicolon-delimited CSV."""

import csv

from config import CSV_FILE, CSV_HEADERS, RESULTS_DIR


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
