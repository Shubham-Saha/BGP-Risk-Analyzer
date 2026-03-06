"""Terminal output formatting for Vast.ai scans."""

from config import VAST_CSV_FILE
from display import print_field, print_header


def display_vast_scan_start(total_machines: int, unique_ips: int):
    """Print the Vast.ai scan banner."""
    print_header("VAST.AI GPU MACHINE SCAN")
    print_field("Total Machines Listed", str(total_machines))
    print_field("Unique IPs (deduplicated)", str(unique_ips))
    print()
    print("  The scanner will analyze each unique IP's BGP/RPKI status.")
    print("  Press Ctrl+C to stop gracefully after the current IP.\n")


def display_machine_result(
    index: int,
    total: int,
    ip: str,
    bgp_row: dict | None,
    error: str | None,
):
    """Print a single IP scan result."""
    if error:
        print(f"    Result: ERROR -- {error}")
    elif bgp_row:
        print(
            f"    Result: Case {bgp_row.get('Erosion Case?', '?')} | "
            f"{bgp_row.get('ROA Return', '?')} | "
            f"{bgp_row.get('ASN', '?')} | "
            f"{bgp_row.get('Prefix', '?')}"
        )
    else:
        print(f"    Result: IP {ip or '(none)'} -- BGP analysis skipped")


def display_vast_scan_summary(results: list[dict]):
    """Print the final summary after all IPs are scanned."""
    print_header("VAST.AI SCAN SUMMARY")

    success = sum(1 for r in results if r.get("bgp_row"))
    failed = sum(1 for r in results if r.get("error"))

    print_field("IPs Scanned", str(len(results)))
    print_field("Successful (BGP analyzed)", str(success))
    print_field("Failed", str(failed))
    print(f"\n  Results saved to: {VAST_CSV_FILE}")
