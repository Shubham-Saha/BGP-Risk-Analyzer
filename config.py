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
    "Platform",
]

# ── Pod Lifecycle ─────────────────────────────────────────────────────────

POD_TERMINAL_STATUSES = {"failed", "error", "unknown", "terminated", "terminating"}

# ── Crawl Time Summary (shared across platforms) ─────────────────────────

CRAWL_TIME_SUMMARY_FILE = RESULTS_DIR / "crawl_time_summary.csv"

CRAWL_TIME_CSV_HEADERS = [
    "Crawl Timestamp",
    "Platform",
    "Parallel",
    "Total Offerings",
    "Pods Processed",
    "Pods Failed/Timed Out",
    "Failures: Timeout (8min)",
    "Failures: Terminal Status",
    "Failures: Active No IP",
    "Failures: API/Other",
    "Avg Provisioning + IP Time (s)",
    "Avg Termination Time (s)",
    "Avg Provisioning + IP + Termination (s)",
    "Avg RIPE Stat IP Lookup Time (s)",
    "Avg Prefix Lookup + RPKI Validation Time (s)",
    "Avg End-to-End Per Pod (s)",
    "Total Crawl Time (s)",
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
    # ── Spin-up timing ──
    "Spin-Up Time (s)",
    # ── Hardware specs (from offering) ──
    "GPU Memory",
    "vCPUs",
    "Disk (GB)",
    "RAM (GB)",
    "Advertised Provisioning Time",
    # ── API response data ──
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
    # ── Change tracking ──
    "Crawl Number",
    "Changes in Crawl Number",
]

PI_FAILURES_CSV_FILE = RESULTS_DIR / "crawl_failures_pi.csv"

PI_FAILURES_CSV_HEADERS = [
    "Crawl Timestamp",
    "GPU Type",
    "Socket",
    "GPU Count",
    "Provider",
    "Region",
    "Data Center",
    "Cloud ID",
    "Error Type",
    "Error Message",
    "Pod ID",
    "Price per Hour",
]

PRIME_CHANGES_CSV_FILE = RESULTS_DIR / "prime_pod_changes.csv"

PRIME_CHANGES_CSV_HEADERS = [
    "Pod ID",
    "Field Changed",
    "Previous Value",
    "New Value",
    "Previous Scan Timestamp",
    "Current Scan Timestamp",
]

# Fields to compare for meaningful changes (excludes raw API dumps, logs, timestamps).
PRIME_COMPARE_FIELDS = (
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
    "GPU Memory",
    "vCPUs",
    "Disk (GB)",
    "RAM (GB)",
    "Advertised Provisioning Time",
    "Spin-Up Time (s)",
)

# ── Vast.ai ──────────────────────────────────────────────────────────────

VAST_API_URL = "https://cloud.vast.ai/api/v0/bundles/"
VAST_CSV_FILE = RESULTS_DIR / "vast_machine_results.csv"

VAST_CSV_HEADERS = [
    "IP Address",
    "Machine ID",
    "Host ID",
    "GPU Type",
    "Num GPUs",
    "GPU RAM (GB)",
    "CPU Name",
    "CPU Cores",
    "RAM (GB)",
    "Disk (GB)",
    "Internet Down (Mbps)",
    "Internet Up (Mbps)",
    "Geolocation",
    "Price per Hour",
    "Reliability",
    "Static IP",
    "CUDA Version",
    "Driver Version",
    "Total Machines at IP",
    # ── BGP analysis fields ──
    "ASN",
    "Hostname",
    "Company Name",
    "Range",
    "Location (ipinfo)",
    "ROA Return",
    "Prefix",
    "MaxLength",
    "Erosion Case?",
    "Erosion Description",
    "Scan Timestamp",
    # ── Change tracking ──
    "Crawl Number",
    "Changes in Crawl Number",
]

VAST_FAILURES_CSV_FILE = RESULTS_DIR / "crawl_failures_vast.csv"

VAST_FAILURES_CSV_HEADERS = [
    "Crawl Timestamp",
    "IP Address",
    "Machine ID",
    "Host ID",
    "GPU Type",
    "Num GPUs",
    "Error Type",
    "Error Message",
]

VAST_CHANGES_CSV_FILE = RESULTS_DIR / "vast_machine_changes.csv"

VAST_CHANGES_CSV_HEADERS = [
    "IP Address",
    "Field Changed",
    "Previous Value",
    "New Value",
    "Previous Scan Timestamp",
    "Current Scan Timestamp",
]

VAST_COMPARE_FIELDS = (
    "GPU Type",
    "Num GPUs",
    "GPU RAM (GB)",
    "CPU Name",
    "CPU Cores",
    "RAM (GB)",
    "Disk (GB)",
    "Price per Hour",
    "Reliability",
    "Static IP",
    "Total Machines at IP",
    "ASN",
    "ROA Return",
    "Prefix",
    "Erosion Case?",
)

# ── Unique IPs ────────────────────────────────────────────────────────────

UNIQUE_IPS_CSV_FILE = RESULTS_DIR / "unique_scan_ips.csv"

# ── Cross-Provider Overlap ────────────────────────────────────────────────

OVERLAP_CSV_FILE = RESULTS_DIR / "ip_overlap_results.csv"

OVERLAP_CSV_HEADERS = [
    "IP Address",
    "PI Pod ID",
    "PI GPU Type",
    "PI Provider",
    "Vast Machine ID",
    "Vast GPU Type",
    "Vast Host ID",
    "ASN",
    "Prefix",
    "Erosion Case?",
    "Detection Timestamp",
]
