"""Terminal output formatting for scan results."""

from config import CSV_FILE


def print_header(text: str):
    print(f"\n{'=' * 64}")
    print(f"  {text}")
    print(f"{'=' * 64}")


def print_field(label: str, value: str, indent: int = 2):
    padding = 32 - len(label)
    dots = "." * max(padding, 2)
    print(f"{' ' * indent}{label}{dots} {value}")


def display_resolution(hostname: str, ip: str, input_url: str):
    print_header("DNS RESOLUTION")
    print_field("Input", input_url)
    print_field("Hostname", hostname)
    print_field("Resolved IP", ip)


def display_ping(ip: str, is_alive: bool, output: str):
    print_header("PING CHECK")
    print_field("Target", ip)
    print_field("Status", "ACTIVE" if is_alive else "DEACTIVE")
    for line in output.strip().split("\n"):
        stripped = line.strip()
        keywords = ["average", "avg", "packets", "loss", "round-trip", "rtt"]
        if any(kw in stripped.lower() for kw in keywords):
            print(f"    {stripped}")


def display_ipinfo(info: dict):
    print_header("IP INTELLIGENCE (RIPE Stat)")
    print_field("IP Address", info["ip"])
    print_field("Hostname", info["hostname"] or "(none)")
    print_field("Location", f"{info['city']}, {info['region']}, {info['country']}")
    print_field("Organization", info["org"])
    print_field("ASN", info["asn"] or "(not found)")
    print_field("ASN Name", info["asn_name"] or "(not found)")


def display_rpki(result: dict):
    print_header("RPKI / ROA ANALYSIS (RIPE Stat)")
    print_field("Announced Prefix", result["prefix"])
    print_field("Prefix Length", f"/{result['prefix_length']}")
    print_field("Origin ASN", result["asn"])
    print_field("ROA Exists", "Yes" if result["roa_exists"] else "No")
    print_field("RPKI Validity", result["validity"].upper())
    if result["max_length"] is not None:
        print_field("ROA MaxLength", f"/{result['max_length']}")
    if result["gap"] is not None and result["gap"] > 0:
        print_field("MaxLength Gap", f"{result['gap']} levels")

    if result["all_roas"]:
        print(f"\n  Covering ROAs:")
        for roa in result["all_roas"]:
            print(
                f"    {roa['origin']} | {roa['prefix']} | "
                f"MaxLen /{roa['max_length']} | {roa['validity']}"
            )

    print_header(f"EROSION CLASSIFICATION: CASE {result['erosion_case']}")
    print(f"  {result['erosion_description']}")


def print_batch_summary(results: list[dict]):
    """Print a summary table after batch processing."""
    if not results:
        print("\n  No results to summarize.")
        return

    print_header("BATCH SUMMARY")
    for r in results:
        target = r["URL"] or r["IP Addresses"]
        print(
            f"  {target:.<40} Case {r['Erosion Case?']} | "
            f"{r['Prefix']} | {r['ASN']} | "
            f"{r['ROA Return']} | {r['Ping Status']}"
        )
    print(f"\n  Total: {len(results)} targets scanned")
    print(f"  Results in: {CSV_FILE}")
