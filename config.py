"""Shared constants for the BGP Risk Analyzer."""

from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
CSV_FILE = RESULTS_DIR / "scan_results.csv"
USER_AGENT = "BGP-Risk-Analyzer/1.0"

CSV_HEADERS = [
    "IP Addresses",
    "URL",
    "Ping Status",
    "ASN",
    "Hostname",
    "Company Name",
    "Range",
    "Location (City; Region; Country)",
    "ROA Return",
    "Prefix",
    "MaxLength",
    "Erosion Case?",
    "Erosion Description",
    "Last accessed",
]
