"""Pod lifecycle management — create, poll, scan, and terminate."""

import signal
import sys
import time
from urllib.error import HTTPError, URLError

from prime_intellect.api import (
    _safe_json,
    create_pod,
    delete_pod,
    get_available_gpus,
    get_pod_details,
    get_pod_history,
    get_pod_logs,
    get_pod_status,
    list_pods,
)


# ── Polling ──────────────────────────────────────────────────────────────────


_TERMINAL_STATUSES = {"failed", "error", "unknown", "terminated", "terminating"}

# Max consecutive polls where the pod is ACTIVE but has no IP before giving up.
_MAX_ACTIVE_NO_IP = 8  # 8 × 15s = 2 minutes


def wait_for_pod_ready(
    api_key: str,
    pod_id: str,
    poll_interval: int = 15,
    max_wait: int = 600,
) -> dict:
    """Poll get_pod_status until the pod is running and has an IP.

    Raises TimeoutError or RuntimeError on failure.
    """
    elapsed = 0
    last_status = None
    active_no_ip_count = 0

    while elapsed < max_wait:
        status_resp = get_pod_status(api_key, pod_id)
        pods = status_resp.get("data", [])

        if pods:
            pod = pods[0]
            last_status = pod.get("status", "unknown")
            pod_ip = pod.get("ip") or pod.get("ipAddress") or pod.get("publicIp")

            # Some providers (e.g. Nebius) return IP as a list
            if isinstance(pod_ip, list):
                pod_ip = pod_ip[0] if pod_ip else None

            # Extract IP from sshConnection if direct IP field is empty
            if not pod_ip:
                ssh_conn = pod.get("sshConnection", "")
                if isinstance(ssh_conn, str) and "@" in ssh_conn:
                    pod_ip = ssh_conn.split("@")[-1].split(":")[0].strip()

            if last_status.lower() in _TERMINAL_STATUSES:
                raise RuntimeError(
                    f"Pod entered '{last_status}' state. "
                    f"Details: {_safe_json(pod, 300)}"
                )

            # API may return "running", "ACTIVE", "active", etc.
            if last_status.lower() in ("running", "active") and pod_ip:
                # Store extracted IP back so callers can find it
                pod["ip"] = pod_ip
                return status_resp

            # Track ACTIVE-with-no-IP to avoid waiting the full timeout
            if last_status.lower() in ("running", "active") and not pod_ip:
                active_no_ip_count += 1
                if active_no_ip_count >= _MAX_ACTIVE_NO_IP:
                    raise RuntimeError(
                        f"Pod is '{last_status}' but no IP after "
                        f"{active_no_ip_count * poll_interval}s. "
                        f"Details: {_safe_json(pod, 300)}"
                    )
            else:
                active_no_ip_count = 0

            progress = pod.get("installationProgress", "")
            print(
                f"    Pod status: {last_status}"
                f"{f' ({progress}%)' if progress else ''}"
                f" — waiting {poll_interval}s …"
                f" (ip={pod.get('ip', 'none')}, ssh={str(pod.get('sshConnection', 'none'))[:40]})"
            )

        time.sleep(poll_interval)
        elapsed += poll_interval

    raise TimeoutError(
        f"Pod did not reach 'running' state within {max_wait}s. "
        f"Last status: {last_status}"
    )


# ── Single Pod Scan ─────────────────────────────────────────────────────────


def scan_single_pod(api_key: str, offering: dict, analyze_callback=None, team_id: str = "") -> dict:
    """Create one pod from an offering, gather all API data, terminate it.

    Parameters
    ----------
    api_key : str
        Prime Intellect API key.
    offering : dict
        An offering dict from get_available_gpus() containing at minimum
        cloudId, gpuType/gpu_type, and provider.
    analyze_callback : callable, optional
        A function ``f(ip: str) -> dict | None`` to run while the pod is
        still alive (before termination).  Used for BGP analysis.
    team_id : str, optional
        Team ID for billing against team wallet instead of personal wallet.

    Returns a dict with pod_id, pod_ip, bgp_row, api_responses, offering,
    and error.  Pod termination is guaranteed via try/finally.
    """
    # Extract offering fields (API may use camelCase or snake_case)
    cloud_id = offering.get("cloudId", offering.get("cloud_id", ""))
    gpu_type = offering.get("gpuType", offering.get("gpu_type", ""))
    socket = offering.get("socket", "")
    provider = offering.get("provider", offering.get("providerType", ""))
    gpu_count = offering.get("gpuCount", offering.get("gpu_count", 1))
    region = offering.get("region", "")
    data_center = offering.get("dataCenter", offering.get("data_center_id", ""))
    country = offering.get("country", "")

    pod_name = f"{gpu_type}-{region}".replace(" ", "-").lower()[:60]

    print(f"    Offering details: cloudId={cloud_id}, gpuType={gpu_type}, "
          f"socket={socket}, provider={provider}, gpuCount={gpu_count}, "
          f"region={region}, dataCenter={data_center}")

    if not cloud_id or not gpu_type or not socket:
        return {
            "pod_id": None,
            "pod_ip": None,
            "bgp_row": None,
            "api_responses": {},
            "offering": offering,
            "error": f"Missing required fields from offering: "
                     f"cloudId={'OK' if cloud_id else 'MISSING'}, "
                     f"gpuType={'OK' if gpu_type else 'MISSING'}, "
                     f"socket={'OK' if socket else 'MISSING'}. "
                     f"Raw offering: {_safe_json(offering, 300)}",
        }

    pod_id = None
    pod_ip = None
    bgp_row = None
    error = None
    api_responses: dict = {}

    try:
        # Create pod (Endpoint 2)
        print(f"    Creating pod: {pod_name}")
        create_resp = create_pod(
            api_key, pod_name, cloud_id, gpu_type, socket,
            gpu_count=int(gpu_count) if gpu_count else 1,
            provider_type=provider,
            data_center_id=data_center,
            country=country,
            team_id=team_id,
        )
        api_responses["create_pod"] = create_resp
        pod_id = create_resp.get("id") or create_resp.get("podId")

        if not pod_id:
            raise RuntimeError(
                f"Pod creation did not return an ID. Response: {_safe_json(create_resp, 300)}"
            )

        print(f"    Pod created: {pod_id}")

        # Poll until running (Endpoint 4)
        status_resp = wait_for_pod_ready(api_key, pod_id)
        api_responses["get_pod_status"] = status_resp
        pod_data = status_resp["data"][0]
        pod_ip = pod_data.get("ip")
        # Normalize list IPs (some providers return ['1.2.3.4'] instead of '1.2.3.4')
        if isinstance(pod_ip, list):
            pod_ip = pod_ip[0] if pod_ip else None
        print(f"    Pod ready! IP: {pod_ip}")

        # Get pod details (Endpoint 5)
        try:
            api_responses["get_pod_details"] = get_pod_details(api_key, pod_id)
        except (HTTPError, URLError) as e:
            api_responses["get_pod_details"] = {"error": str(e)}

        # Get pod logs (Endpoint 7)
        try:
            api_responses["get_pod_logs"] = get_pod_logs(api_key, pod_id)
        except (HTTPError, URLError) as e:
            api_responses["get_pod_logs"] = {"error": str(e)}

        # Run BGP analysis WHILE pod is still alive
        if pod_ip and analyze_callback:
            print(f"    Running BGP analysis on live pod IP: {pod_ip}")
            try:
                bgp_row = analyze_callback(pod_ip)
            except Exception as bgp_err:
                print(f"    Warning: BGP analysis failed: {bgp_err}")

    except (HTTPError, URLError, RuntimeError, TimeoutError) as e:
        error = str(e)
        print(f"    ERROR: {error}")

    finally:
        # Terminate pod (Endpoint 6) — ALWAYS runs if pod was created
        if pod_id:
            print(f"    Terminating pod {pod_id} …")
            try:
                api_responses["delete_pod"] = delete_pod(api_key, pod_id)
                print(f"    Pod terminated.")
            except (HTTPError, URLError) as del_err:
                api_responses["delete_pod"] = {"error": str(del_err)}
                print(
                    f"    WARNING: Failed to terminate pod {pod_id}: {del_err}\n"
                    f"    The pod may still be running and incurring costs!\n"
                    f"    Manually terminate it at https://app.primeintellect.ai"
                )

    # Get pod history (Endpoint 3) — after termination
    try:
        api_responses["get_pod_history"] = get_pod_history(api_key)
    except (HTTPError, URLError) as e:
        api_responses["get_pod_history"] = {"error": str(e)}

    return {
        "pod_id": pod_id,
        "pod_ip": pod_ip,
        "bgp_row": bgp_row,
        "api_responses": api_responses,
        "offering": offering,
        "error": error,
    }


# ── Offering Discovery ──────────────────────────────────────────────────────


def _fetch_and_display_offerings(api_key: str) -> list[dict]:
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


# ── Scan All Pods ───────────────────────────────────────────────────────────

# Flag for graceful Ctrl+C termination during pod scanning
_stop_requested = False


def _handle_sigint(_sig, _frame):
    """Signal handler for graceful Ctrl+C during pod scanning."""
    global _stop_requested
    if _stop_requested:
        print("\n\n  Force exit.")
        sys.exit(1)
    _stop_requested = True
    print("\n\n  Ctrl+C received. Finishing current pod, then stopping...")


def scan_all_pods(
    api_key: str,
    analyze_callback=None,
    on_pod_done=None,
    team_id: str = "",
) -> list[dict]:
    """Discover all available GPU offerings and scan each one.

    For each offering: create pod -> wait for IP -> gather info ->
    BGP analysis (while alive) -> terminate -> save CSV.
    Ctrl+C finishes the current pod gracefully, then stops.

    Parameters
    ----------
    api_key : str
        Prime Intellect API key.
    analyze_callback : callable, optional
        ``f(ip: str) -> dict | None`` — BGP analysis function called
        while the pod is still running.
    on_pod_done : callable, optional
        ``f(index, total, result)`` — called after each pod is fully
        processed (including termination).  Used to save CSV per-pod.
    team_id : str, optional
        Team ID for billing against team wallet.

    Returns the list of scan results (one per pod).
    """
    global _stop_requested
    _stop_requested = False

    # Endpoint 1: List existing pods
    try:
        existing = list_pods(api_key)
        count = existing.get("total_count", "?")
        print(f"\n  Existing pods on your account: {count}")
    except (HTTPError, URLError) as e:
        print(f"\n  Warning: Could not list existing pods: {e}")

    # Fetch and display available offerings (with refresh loop)
    offerings = _fetch_and_display_offerings(api_key)
    if not offerings:
        return []

    while True:
        # Ask which offerings to scan
        print(f"\n  Which offerings to scan? Enter number(s) from the list above.")
        print(f"    'all'        — scan all {len(offerings)} offerings")
        print(f"    '3'          — scan offering #3")
        print(f"    '1,4,7'      — scan offerings #1, #4, #7")
        print(f"    '1-20'       — scan offerings #1 through #20")
        print(f"    '1-20,25,30' — mix ranges and individual numbers")
        print(f"    'refresh'    — refresh the available offerings list")
        print(f"    'back'       — return to main menu")
        scan_input = input("  Selection [all]: ").strip().lower()

        if scan_input == "refresh":
            offerings = _fetch_and_display_offerings(api_key)
            if not offerings:
                return []
            continue

        if scan_input == "back":
            print("  Returning to main menu.\n")
            return []

        break

    if scan_input in ("", "all"):
        pass  # use all offerings as-is
    else:
        # Parse comma-separated tokens, each can be a number or a range (e.g. "1-20")
        try:
            indices = []
            for token in scan_input.split(","):
                token = token.strip()
                if "-" in token:
                    start, end = token.split("-", 1)
                    indices.extend(range(int(start), int(end) + 1))
                else:
                    indices.append(int(token))
            selected = [offerings[i - 1] for i in indices if 1 <= i <= len(offerings)]
            if not selected:
                print("  No valid selections. Defaulting to all.")
            else:
                offerings = selected
        except ValueError:
            print(f"  Invalid input. Defaulting to all ({len(offerings)}).")

    print(f"\n  Will scan {len(offerings)} offering(s). (Press Ctrl+C to stop gracefully)")
    print("  Flow per offering: Create pod -> Wait for IP -> Gather info")
    print("  -> BGP analysis (while alive) -> Terminate pod -> Save CSV\n")

    # Install Ctrl+C handler for graceful stop
    old_handler = signal.signal(signal.SIGINT, _handle_sigint)

    results = []
    try:
        for i, offering in enumerate(offerings, 1):
            if _stop_requested:
                print(f"\n  Stopped by user. {i - 1}/{len(offerings)} offerings scanned.")
                break

            gpu = offering.get("gpuType", offering.get("gpu_type", "?"))
            provider = offering.get("provider", offering.get("providerType", "?"))
            region = offering.get("region", "?")
            price = offering.get("prices", {})
            on_demand = price.get("onDemand", "?") if isinstance(price, dict) else "?"

            print(f"  [{i}/{len(offerings)}] {gpu} / {provider} / {region} (${on_demand}/hr)")

            result = scan_single_pod(api_key, offering, analyze_callback=analyze_callback, team_id=team_id)
            results.append(result)

            if on_pod_done:
                on_pod_done(i, len(offerings), result)

            status = "OK" if result["pod_ip"] else "FAILED"
            ip_str = f"IP: {result['pod_ip']}" if result["pod_ip"] else "No IP obtained"
            print(f"    [{status}] {ip_str}\n")

    finally:
        # Restore original signal handler
        signal.signal(signal.SIGINT, old_handler)
        _stop_requested = False

    print(f"\n  Scan complete. {len(results)}/{len(offerings)} offerings processed.")
    return results
