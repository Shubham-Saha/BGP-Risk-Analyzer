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
    "New Info after rescan?",
]

# ── Prime Intellect API ─────────────────────────────────────────────────────

PRIME_API_BASE_URL = "https://api.primeintellect.ai/api/v1"
PRIME_CSV_FILE = RESULTS_DIR / "prime_pod_results.csv"

PRIME_CSV_HEADERS = [
    "Pod ID",
    "Pod Name",
    "Cloud ID",
    "GPU Type",
    "GPU Count",
    "Provider Type",
    "Pod Status",
    "Pod IP",
    "SSH Connection",
    "Installation Status",
    "Installation Progress",
    "Price per Hour",
    "Total Billed Price",
    "Created At",
    "Terminated At",
    "Pod Logs (excerpt)",
    "List Pods Response (summary)",
    "Create Pod Response (status)",
    "History Response (summary)",
    "Status Response (raw)",
    "Get Pod Response (raw)",
    "Delete Response (status)",
    "Logs Response (excerpt)",
    "Availability Data",
    "Scan Timestamp",
]
