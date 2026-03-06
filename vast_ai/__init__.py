"""Vast.ai GPU Machine API integration package.

Fetches public machine listings, deduplicates by IP, runs BGP analysis
on each unique IP, and saves results to CSV.

No authentication required -- uses Vast.ai's public search API.
"""

from vast_ai.csv_builder import build_vast_csv_row
from vast_ai.csv_writer import append_to_vast_csv, append_vast_failure_csv
from vast_ai.display import (
    display_machine_result,
    display_vast_scan_start,
    display_vast_scan_summary,
)
from vast_ai.scanner import scan_all_machines

__all__ = [
    "scan_all_machines",
    "build_vast_csv_row",
    "append_to_vast_csv",
    "append_vast_failure_csv",
    "display_machine_result",
    "display_vast_scan_start",
    "display_vast_scan_summary",
]
