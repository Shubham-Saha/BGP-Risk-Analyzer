"""Pod polling — wait for a pod to become ready with an IP address."""

import time

from config import POD_TERMINAL_STATUSES
from prime_intellect.api import _safe_json, get_pod_status

# Max consecutive polls where the pod is ACTIVE but has no IP before giving up.
_MAX_ACTIVE_NO_IP = 20  # 20 × 15s = 5 minutes


def wait_for_pod_ready(
    api_key: str,
    pod_id: str,
    poll_interval: int = 15,
    max_wait: int = 480,
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

            if last_status.lower() in POD_TERMINAL_STATUSES:
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
        f"Pod did not reach 'running' state within {max_wait // 60}min ({max_wait}s). "
        f"Last status: {last_status}"
    )
