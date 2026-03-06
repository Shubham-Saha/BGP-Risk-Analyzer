"""Vast.ai public API integration -- fetch machine listings without authentication."""

from config import VAST_API_URL
from network import fetch_api


def fetch_machine_listings() -> list[dict]:
    """Fetch all available machine listings from Vast.ai public search API.

    No authentication required. Filters for verified, rentable, unrented
    on-demand machines.

    Returns list of machine dicts, each containing fields like:
        public_ipaddr, machine_id, host_id, gpu_name, num_gpus, gpu_ram,
        cpu_name, cpu_cores_effective, cpu_ram, disk_space, disk_bw,
        inet_up, inet_down, geolocation, dph_total, reliability2,
        static_ip, cuda_max_good, driver_version, verified
    """
    body = {
        "limit": 5000,
        "type": "on-demand",
        "verified": {"eq": True},
        "rentable": {"eq": True},
        "rented": {"eq": False},
    }

    try:
        status, data = fetch_api(
            VAST_API_URL, method="POST", json_body=body, timeout=60
        )
    except Exception as e:
        print(f"  Error fetching Vast.ai listings: {e}")
        return []

    if isinstance(data, dict):
        offers = data.get("offers", [])
        if not offers:
            print("  Warning: Vast.ai returned no offers.")
        return offers

    print(f"  Unexpected Vast.ai response type: {type(data).__name__}")
    return []
