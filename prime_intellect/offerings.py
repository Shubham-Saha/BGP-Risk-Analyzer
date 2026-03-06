"""GPU offering discovery — fetch, filter, and display available offerings."""

from urllib.error import HTTPError, URLError

from prime_intellect.api import get_available_gpus


def fetch_and_display_offerings(api_key: str) -> list[dict]:
    """Fetch available GPU offerings, filter, and display them.

    Returns the filtered list of GPU offerings, or an empty list on error.
    """
    print("  Querying available GPU offerings (secure_cloud + community_cloud)...")
    try:
        offerings = get_available_gpus(api_key)
    except (HTTPError, URLError) as e:
        print(f"\n  ERROR: Could not query GPU availability: {e}")
        return []

    if not offerings:
        print("  No available GPU offerings found.")
        return []

    print(f"  Total offerings fetched: {len(offerings)}")

    # Show stock status breakdown for transparency
    status_counts: dict[str, int] = {}
    for o in offerings:
        s = str(o.get("stockStatus", o.get("stock_status", "unknown"))).lower()
        status_counts[s] = status_counts.get(s, 0) + 1
    for status, count in sorted(status_counts.items()):
        print(f"    stockStatus={status}: {count}")

    # Filter out only truly unavailable offerings
    _UNAVAILABLE = {"unavailable", "out_of_stock", "out of stock", "sold_out", "sold out"}
    in_stock = [
        o for o in offerings
        if str(o.get("stockStatus", o.get("stock_status", "available"))).lower()
        not in _UNAVAILABLE
    ]
    skipped = len(offerings) - len(in_stock)
    if skipped:
        print(f"  Filtered out {skipped} unavailable offerings.")
    offerings = in_stock if in_stock else offerings

    # Filter out CPU_NODE offerings (not relevant for GPU BGP scanning)
    gpu_only = [
        o for o in offerings
        if str(o.get("gpuType", o.get("gpu_type", ""))).upper() != "CPU_NODE"
    ]
    cpu_skipped = len(offerings) - len(gpu_only)
    if cpu_skipped:
        print(f"  Filtered out {cpu_skipped} CPU-only offerings.")
    offerings = gpu_only if gpu_only else offerings

    print(f"  GPU offerings to scan: {len(offerings)}\n")

    # Show discovered offerings
    for idx, o in enumerate(offerings, 1):
        g = o.get("gpuType", o.get("gpu_type", "?"))
        s = o.get("socket", "?")
        p = o.get("provider", o.get("providerType", "?"))
        r = o.get("region", "?")
        gc = o.get("gpuCount", o.get("gpu_count", "?"))
        sec = o.get("security", "?")
        pr = o.get("prices", {})
        od = pr.get("onDemand", "?") if isinstance(pr, dict) else "?"
        sec_tag = " [community]" if sec == "community_cloud" else ""
        print(f"    {idx}. {g} ({s}) x{gc} / {p} / {r}  (${od}/hr){sec_tag}")

    return offerings
