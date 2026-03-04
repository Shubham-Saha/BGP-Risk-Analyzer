"""Prime Intellect API endpoint wrappers.

Endpoints:
    1. GET  /pods/               — List existing pods
    2. POST /pods/               — Create a new pod
    3. GET  /pods/history        — Get terminated pods history
    4. GET  /pods/status         — Get pod status + IP
    5. GET  /pods/{podId}        — Get pod details
    6. DELETE /pods/{podId}      — Terminate pod
    7. GET  /pods/{podId}/logs   — Get pod logs
    8. GET  /availability/gpus   — Discover available GPU offerings

API reference: https://docs.primeintellect.ai/api-reference/managing-pods
"""

import json

from config import PRIME_API_BASE_URL
from network import fetch_api


def _auth_headers(api_key: str) -> dict:
    """Return Authorization header dict."""
    return {"Authorization": f"Bearer {api_key}"}


def _safe_json(obj, max_len: int = 2000) -> str:
    """Compact JSON string, truncated if too long (for CSV cells)."""
    text = json.dumps(obj, default=str, ensure_ascii=False)
    if len(text) > max_len:
        return text[: max_len - 14] + "...[truncated]"
    return text


# ── Endpoint Wrappers ────────────────────────────────────────────────────────


def get_available_gpus(api_key: str) -> list[dict]:
    """GET /availability/gpus — Discover all available GPU offerings.

    Paginates through all pages (max 100 items each) and returns the
    combined list.  Fetches both secure_cloud and community_cloud offerings.
    """
    headers = _auth_headers(api_key)
    all_items: list[dict] = []

    for security in ("secure_cloud", "community_cloud"):
        page = 1
        while True:
            url = (
                f"{PRIME_API_BASE_URL}/availability/gpus"
                f"?page={page}&page_size=100&security={security}"
            )
            _status, data = fetch_api(url, headers=headers)

            # Extract items from response
            if isinstance(data, list):
                items = data
                total = len(data)
            elif isinstance(data, dict):
                items = data.get("items", data.get("data", []))
                total = data.get("totalCount", len(items))
            else:
                break

            all_items.extend(items)

            # Stop if we've fetched all items for this security type
            if len(items) < 100 or page * 100 >= total:
                break
            page += 1

    return all_items


def list_pods(api_key: str) -> dict:
    """GET /pods/ — List all existing pods."""
    url = f"{PRIME_API_BASE_URL}/pods/"
    _status, data = fetch_api(url, headers=_auth_headers(api_key))
    return data


def create_pod(
    api_key: str,
    name: str,
    cloud_id: str,
    gpu_type: str,
    socket: str,
    gpu_count: int = 1,
    disk_size: int = 100,
    provider_type: str = "runpod",
    data_center_id: str = "",
    country: str = "",
    team_id: str = "",
) -> dict:
    """POST /pods/ — Create a new GPU pod."""
    url = f"{PRIME_API_BASE_URL}/pods/"
    pod_body = {
        "name": name,
        "cloudId": cloud_id,
        "gpuType": gpu_type,
        "socket": socket,
        "gpuCount": gpu_count,
        "diskSize": disk_size,
    }
    if data_center_id:
        pod_body["dataCenterId"] = data_center_id
    if country:
        pod_body["country"] = country
    body = {
        "pod": pod_body,
        "provider": {"type": provider_type},
    }
    if team_id:
        body["team"] = {"teamId": team_id}
    _status, data = fetch_api(
        url, method="POST", headers=_auth_headers(api_key), json_body=body
    )
    return data


def get_pod_history(api_key: str) -> dict:
    """GET /pods/history — Get terminated pods history."""
    url = f"{PRIME_API_BASE_URL}/pods/history"
    _status, data = fetch_api(url, headers=_auth_headers(api_key))
    return data


def get_pod_status(api_key: str, pod_id: str) -> dict:
    """GET /pods/status?pod_ids=<id> — Get pod status including IP."""
    url = f"{PRIME_API_BASE_URL}/pods/status?pod_ids={pod_id}"
    _status, data = fetch_api(url, headers=_auth_headers(api_key))
    return data


def get_pod_details(api_key: str, pod_id: str) -> dict:
    """GET /pods/{podId} — Get full pod configuration details."""
    url = f"{PRIME_API_BASE_URL}/pods/{pod_id}"
    _status, data = fetch_api(url, headers=_auth_headers(api_key))
    return data


def delete_pod(api_key: str, pod_id: str) -> dict | str:
    """DELETE /pods/{podId} — Terminate the pod."""
    url = f"{PRIME_API_BASE_URL}/pods/{pod_id}"
    _status, data = fetch_api(url, method="DELETE", headers=_auth_headers(api_key))
    return data


def get_pod_logs(api_key: str, pod_id: str) -> str:
    """GET /pods/{podId}/logs — Retrieve pod logs."""
    url = f"{PRIME_API_BASE_URL}/pods/{pod_id}/logs"
    _status, data = fetch_api(url, headers=_auth_headers(api_key))
    if isinstance(data, dict):
        return json.dumps(data, default=str)
    return str(data)
