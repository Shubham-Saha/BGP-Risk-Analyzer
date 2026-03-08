"""Load and prepare data from CSV files for visualization."""

import csv
from collections import defaultdict
from pathlib import Path

from config import (
    CSV_FILE,
    UNIQUE_IPS_CSV_FILE,
    VAST_CHANGES_CSV_FILE,
    VAST_CSV_FILE,
    PRIME_CHANGES_CSV_FILE,
    PRIME_CSV_FILE,
)


def load_unique_ips() -> list[dict]:
    """Load unique_scan_ips.csv rows."""
    if not UNIQUE_IPS_CSV_FILE.exists():
        return []
    with open(UNIQUE_IPS_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f, delimiter=";"))


def load_scan_results() -> list[dict]:
    """Load scan_results.csv (all rows, including duplicates across crawls)."""
    if not CSV_FILE.exists():
        return []
    with open(CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f, delimiter=";"))


def load_vast_results() -> list[dict]:
    """Load vast_machine_results.csv."""
    if not VAST_CSV_FILE.exists():
        return []
    with open(VAST_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f, delimiter=";"))


def load_changes() -> list[dict]:
    """Load all change records from both platforms."""
    changes: list[dict] = []

    for csv_path, ip_col in [
        (VAST_CHANGES_CSV_FILE, "IP Address"),
        (PRIME_CHANGES_CSV_FILE, "Pod ID"),
    ]:
        if not csv_path.exists():
            continue
        with open(csv_path, "r", newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f, delimiter=";"):
                # Normalize IP column name
                ip = row.get(ip_col, "").strip()
                row["_ip"] = ip
                changes.append(row)

    return changes


def load_vast_changes() -> list[dict]:
    """Load vast_machine_changes.csv only."""
    if not VAST_CHANGES_CSV_FILE.exists():
        return []
    with open(VAST_CHANGES_CSV_FILE, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f, delimiter=";"))
