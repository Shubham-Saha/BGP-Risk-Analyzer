"""Pod deployer — create, capture info, terminate, and run BGP analysis."""

import time
from urllib.error import HTTPError, URLError

from prime_intellect.api import (
    _safe_json,
    create_pod,
    delete_pod,
    get_pod_details,
    get_pod_history,
    get_pod_logs,
)
from prime_intellect.poller import wait_for_pod_ready


def deploy_and_analyze_pod(api_key: str, offering: dict, bgp_analyze=None, team_id: str = "") -> dict:
    """Create one pod from an offering, gather all API data, terminate it.

    Parameters
    ----------
    api_key : str
        Prime Intellect API key.
    offering : dict
        An offering dict from get_available_gpus() containing at minimum
        cloudId, gpuType/gpu_type, and provider.
    bgp_analyze : callable, optional
        A function ``f(ip: str) -> dict | None`` that runs BGP risk
        analysis on the pod's IP after termination.
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
    spinup_seconds: float | None = None
    termination_seconds: float | None = None
    error_type: str | None = None

    try:
        # Create pod (Endpoint 2)
        print(f"    Creating pod: {pod_name}")
        t_create = time.time()
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

        # Poll until running (Endpoint 4) — 5-minute timeout
        status_resp = wait_for_pod_ready(api_key, pod_id)
        t_ready = time.time()
        spinup_seconds = round(t_ready - t_create, 1)
        api_responses["get_pod_status"] = status_resp
        pod_data = status_resp["data"][0]
        pod_ip = pod_data.get("ip")
        # Normalize list IPs (some providers return ['1.2.3.4'] instead of '1.2.3.4')
        if isinstance(pod_ip, list):
            pod_ip = pod_ip[0] if pod_ip else None
        print(f"    Pod ready! IP: {pod_ip}  (spin-up: {spinup_seconds}s)")

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

    except TimeoutError as e:
        error = str(e)
        error_type = "timeout"
        print(f"    ERROR [{error_type}]: {error}")
    except RuntimeError as e:
        error = str(e)
        if "entered" in error or any(s in error.lower() for s in ("failed", "error", "terminated")):
            error_type = "terminal_status"
        elif "no IP" in error:
            error_type = "active_no_ip"
        elif "did not return an ID" in error:
            error_type = "no_pod_id"
        else:
            error_type = "runtime_error"
        print(f"    ERROR [{error_type}]: {error}")
    except (HTTPError, URLError) as e:
        error = str(e)
        error_type = "api_error"
        print(f"    ERROR [{error_type}]: {error}")

    finally:
        # Terminate pod IMMEDIATELY after info capture (Endpoint 6)
        if pod_id:
            print(f"    Terminating pod {pod_id} …")
            t_term_start = time.time()
            try:
                api_responses["delete_pod"] = delete_pod(api_key, pod_id)
                termination_seconds = round(time.time() - t_term_start, 1)
                print(f"    Pod terminated. ({termination_seconds}s)")
            except (HTTPError, URLError) as del_err:
                api_responses["delete_pod"] = {"error": str(del_err)}
                print(
                    f"    WARNING: Failed to terminate pod {pod_id}: {del_err}\n"
                    f"    The pod may still be running and incurring costs!\n"
                    f"    Manually terminate it at https://app.primeintellect.ai"
                )

    # Run BGP analysis AFTER pod is terminated (only needs the IP)
    if pod_ip and bgp_analyze:
        print(f"    Running BGP analysis on collected IP: {pod_ip}")
        try:
            bgp_row = bgp_analyze(pod_ip)
        except Exception as bgp_err:
            print(f"    Warning: BGP analysis failed: {bgp_err}")

    # Get pod history (Endpoint 3) — after termination
    try:
        api_responses["get_pod_history"] = get_pod_history(api_key)
    except (HTTPError, URLError) as e:
        api_responses["get_pod_history"] = {"error": str(e)}

    # ── Hardware specs (from the offering/availability endpoint) ────
    gpu_memory = offering.get("gpuMemory", offering.get("gpu_memory", ""))
    vcpu_info = offering.get("vcpu", {})
    vcpus = vcpu_info.get("defaultCount", "") if isinstance(vcpu_info, dict) else ""
    disk_info = offering.get("disk", {})
    disk = disk_info.get("defaultCount", "") if isinstance(disk_info, dict) else ""
    mem_info = offering.get("memory", {})
    ram = mem_info.get("defaultCount", "") if isinstance(mem_info, dict) else ""
    advertised_provisioning_time = offering.get("provisioningTime", "")

    return {
        "pod_id": pod_id,
        "pod_ip": pod_ip,
        "bgp_row": bgp_row,
        "api_responses": api_responses,
        "offering": offering,
        "error": error,
        "spinup_seconds": spinup_seconds,
        "termination_seconds": termination_seconds,
        "error_type": error_type,
        "hardware": {
            "gpu_memory": gpu_memory,
            "vcpus": vcpus,
            "disk": disk,
            "ram": ram,
            "advertised_provisioning_time": advertised_provisioning_time,
        },
    }
