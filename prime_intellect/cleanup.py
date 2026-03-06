"""Pod cleanup — detect and terminate unattended pods."""

from urllib.error import HTTPError, URLError

from config import POD_TERMINAL_STATUSES
from prime_intellect.api import delete_pod, list_pods


def cleanup_running_pods(api_key: str):
    """Check for any running pods and terminate them.

    Call after scanning to ensure no pods are left running unattended.
    Terminates every pod whose status is NOT in POD_TERMINAL_STATUSES.
    """
    try:
        existing = list_pods(api_key)
    except (HTTPError, URLError) as e:
        print(f"    Warning: Could not check for running pods: {e}")
        return

    pods = existing.get("data", [])
    if not pods:
        return

    # Terminate anything NOT already in a terminal state
    running = [
        p for p in pods
        if str(p.get("status", "")).lower() not in POD_TERMINAL_STATUSES
    ]

    if not running:
        return

    print(f"\n  Found {len(running)} pod(s) still alive. Terminating...")
    for pod in running:
        pid = pod.get("id") or pod.get("podId", "unknown")
        status = pod.get("status", "unknown")
        print(f"    Terminating pod {pid} (status: {status}) …")
        try:
            delete_pod(api_key, pid)
            print(f"    Pod {pid} terminated.")
        except (HTTPError, URLError) as e:
            print(
                f"    WARNING: Failed to terminate pod {pid}: {e}\n"
                f"    Manually terminate it at https://app.primeintellect.ai"
            )
