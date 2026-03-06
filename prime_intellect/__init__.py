"""Prime Intellect GPU Pod API integration package.

Manages the full pod lifecycle: create, monitor, extract IP, terminate,
and collect responses from all API endpoints for logging.

API reference: https://docs.primeintellect.ai/api-reference/managing-pods
"""

from prime_intellect.csv_builder import build_prime_csv_row
from prime_intellect.csv_writer import append_failure_csv, append_to_prime_csv
from prime_intellect.display import (
    display_pod_result,
    display_prime_scan_start,
    display_prime_scan_summary,
)
from prime_intellect.env import get_api_key, get_team_id
from prime_intellect.cleanup import cleanup_running_pods
from prime_intellect.deployer import deploy_and_analyze_pod
from prime_intellect.scanner import scan_all_pods
from prime_intellect.timing import CrawlTimer

__all__ = [
    "get_api_key",
    "get_team_id",
    "cleanup_running_pods",
    "deploy_and_analyze_pod",
    "scan_all_pods",
    "build_prime_csv_row",
    "append_to_prime_csv",
    "append_failure_csv",
    "display_pod_result",
    "display_prime_scan_start",
    "display_prime_scan_summary",
    "CrawlTimer",
]
