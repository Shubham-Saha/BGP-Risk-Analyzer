"""Terminal output formatting for Prime Intellect Phase 5."""

from config import PRIME_CSV_FILE
from display import print_field, print_header


def display_prime_scan_start(total_offerings: int):
    """Print the Phase 5 scan banner."""
    print_header("PRIME INTELLECT GPU POD SCAN")
    print_field("Available Offerings", str(total_offerings))
    print()
    print("  The scanner will create each pod, extract its IP,")
    print("  run BGP analysis, and terminate it automatically.")
    print("  Press Ctrl+C to stop gracefully after the current pod.\n")


def display_pod_result(
    index: int,
    total: int,
    pod_ip: str,
    bgp_row: dict | None,
    error: str | None,
):
    """Print a single pod scan result."""
    if error:
        print(f"    Result: ERROR — {error}")
    elif bgp_row:
        print(
            f"    Result: Case {bgp_row.get('Erosion Case?', '?')} | "
            f"{bgp_row.get('ROA Return', '?')} | "
            f"{bgp_row.get('ASN', '?')} | "
            f"{bgp_row.get('Prefix', '?')}"
        )
    else:
        print(f"    Result: IP {pod_ip or '(none)'} — BGP analysis skipped")


def display_prime_scan_summary(results: list[dict]):
    """Print the final summary after all pods are scanned."""
    print_header("PRIME SCAN SUMMARY")

    success = sum(1 for r in results if r.get("pod_ip"))
    failed = sum(1 for r in results if r.get("error"))

    print_field("Pods Scanned", str(len(results)))
    print_field("Successful (got IP)", str(success))
    print_field("Failed", str(failed))
    print(f"\n  Results saved to: {PRIME_CSV_FILE}")
