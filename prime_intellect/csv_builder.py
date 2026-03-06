"""Build CSV row dicts from Prime Intellect pod scan results."""

from datetime import datetime, timezone

from prime_intellect.api import _safe_json


def build_prime_csv_row(scan_result: dict) -> dict:
    """Build a row dict for the Prime CSV from scan results."""
    api = scan_result["api_responses"]
    pod_id = scan_result["pod_id"] or ""
    pod_ip = scan_result["pod_ip"] or ""
    offering = scan_result.get("offering", {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Extract fields from create_pod response
    create = api.get("create_pod", {})
    if isinstance(create, dict):
        pod_name = create.get("name", "")
        cloud_id = create.get("cloudId", "")
        gpu_type = create.get("gpuName", create.get("gpuType", ""))
        gpu_count = create.get("gpuCount", "")
        provider = create.get("providerType", "")
        price_hr = create.get("priceHr", "")
    else:
        pod_name = cloud_id = gpu_type = gpu_count = provider = price_hr = ""

    # Extract fields from status response
    status_data = api.get("get_pod_status", {})
    pods_list = status_data.get("data", []) if isinstance(status_data, dict) else []
    if pods_list:
        pod_status_info = pods_list[0]
        pod_status = pod_status_info.get("status", "")
        ssh_conn = pod_status_info.get("sshConnection", "")
        install_status = pod_status_info.get("installationStatus", "")
        install_progress = pod_status_info.get("installationProgress", "")
    else:
        pod_status = ssh_conn = install_status = install_progress = ""

    # Extract fields from history
    history = api.get("get_pod_history", {})
    total_billed = ""
    created_at = ""
    terminated_at = ""
    if isinstance(history, dict):
        for h in history.get("data", []):
            if h.get("id") == pod_id:
                total_billed = h.get("totalBilledPrice", "")
                created_at = h.get("createdAt", "")
                terminated_at = h.get("terminatedAt", "")
                if not price_hr:
                    price_hr = h.get("priceHr", "")
                break

    # Logs excerpt
    logs_raw = api.get("get_pod_logs", "")
    if isinstance(logs_raw, dict):
        logs_excerpt = _safe_json(logs_raw, 500)
    else:
        logs_excerpt = str(logs_raw)[:500]

    # API response summaries
    list_resp = api.get("list_pods", {})
    list_summary = (
        f"total_count={list_resp.get('total_count', '?')}"
        if isinstance(list_resp, dict) and "error" not in list_resp
        else f"error: {list_resp.get('error', '?')}" if isinstance(list_resp, dict) else str(list_resp)
    )

    create_summary = (
        f"id={pod_id}, status={create.get('status', '?')}"
        if isinstance(create, dict) and "error" not in create
        else f"error: {create.get('error', '?')}" if isinstance(create, dict) else str(create)
    )

    history_found = any(
        h.get("id") == pod_id
        for h in history.get("data", [])
    ) if isinstance(history, dict) and "error" not in history else False
    history_summary = (
        f"total={history.get('total_count', '?')}, this_pod_found={'Yes' if history_found else 'No'}"
        if isinstance(history, dict) and "error" not in history
        else f"error: {history.get('error', '?')}" if isinstance(history, dict) else str(history)
    )

    delete_resp = api.get("delete_pod", {})
    delete_status = (
        "success" if isinstance(delete_resp, dict) and "error" not in delete_resp
        else f"error: {delete_resp.get('error', '?')}" if isinstance(delete_resp, dict)
        else str(delete_resp)
    )

    # Availability data from discovery endpoint
    availability_data = _safe_json(offering, 1000) if offering else ""

    # ── Spin-up time & hardware specs ────────────────────────────────
    spinup_seconds = scan_result.get("spinup_seconds", "")
    hw = scan_result.get("hardware", {})

    return {
        "Pod ID": pod_id,
        "Pod Name": pod_name,
        "Cloud ID": cloud_id,
        "GPU Type": gpu_type,
        "GPU Count": str(gpu_count),
        "Provider Type": provider,
        "Pod Status": pod_status,
        "Pod IP": pod_ip,
        "SSH Connection": str(ssh_conn),
        "Installation Status": str(install_status),
        "Installation Progress": str(install_progress),
        "Price per Hour": str(price_hr),
        "Total Billed Price": str(total_billed),
        "Created At": str(created_at),
        "Terminated At": str(terminated_at),
        "Spin-Up Time (s)": str(spinup_seconds) if spinup_seconds is not None else "",
        "GPU Memory": str(hw.get("gpu_memory", "")),
        "vCPUs": str(hw.get("vcpus", "")),
        "Disk (GB)": str(hw.get("disk", "")),
        "RAM (GB)": str(hw.get("ram", "")),
        "Advertised Provisioning Time": str(hw.get("advertised_provisioning_time", "")),
        "Pod Logs (excerpt)": logs_excerpt,
        "List Pods Response (summary)": list_summary,
        "Create Pod Response (status)": create_summary,
        "History Response (summary)": history_summary,
        "Status Response (raw)": _safe_json(status_data),
        "Get Pod Response (raw)": _safe_json(api.get("get_pod_details", {})),
        "Delete Response (status)": delete_status,
        "Logs Response (excerpt)": logs_excerpt,
        "Availability Data": availability_data,
        "Scan Timestamp": now,
        "Crawl Number": "",              # Set by csv_writer during append
        "Changes in Crawl Number": "",   # Set by csv_writer during append
    }
