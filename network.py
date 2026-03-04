"""Network utilities — HTTP fetch, DNS resolution, and ping."""

import json
import socket
import subprocess
import sys
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from config import USER_AGENT


def fetch_json(url: str, timeout: int = 20) -> dict:
    """GET a URL and return parsed JSON."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    response = urlopen(req, timeout=timeout)
    return json.loads(response.read().decode("utf-8"))


def fetch_api(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    json_body: dict | None = None,
    timeout: int = 30,
) -> tuple[int, dict | str]:
    """Send an HTTP request with optional auth/body and return (status, data).

    Supports GET, POST, and DELETE.  For POST requests, *json_body* is
    serialized and sent as ``application/json``.
    """
    data = None
    if json_body is not None and method == "POST":
        data = json.dumps(json_body).encode("utf-8")

    req = Request(url, data=data, method=method)
    req.add_header("User-Agent", USER_AGENT)

    if data is not None:
        req.add_header("Content-Type", "application/json")

    if headers:
        for key, value in headers.items():
            req.add_header(key, value)

    try:
        response = urlopen(req, timeout=timeout)
    except HTTPError as e:
        # Read the error response body so callers can see WHY it failed
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
        except Exception:
            pass
        raise HTTPError(
            e.url, e.code, f"HTTP {e.code}: {error_body or e.reason}", e.headers, None
        ) from None

    body = response.read().decode("utf-8")

    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        parsed = body

    return response.status, parsed


def resolve_hostname(url_or_hostname: str) -> tuple[str, str]:
    """Extract hostname from URL and resolve to IPv4 address."""
    if "://" not in url_or_hostname:
        url_or_hostname = f"https://{url_or_hostname}"
    hostname = urlparse(url_or_hostname).hostname
    ip = socket.gethostbyname(hostname)
    return hostname, ip


def ping_host(ip: str, count: int = 4) -> tuple[bool, str]:
    """Ping an IP and return (is_reachable, raw_output)."""
    flag = "-n" if sys.platform == "win32" else "-c"
    try:
        result = subprocess.run(
            ["ping", flag, str(count), ip],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return result.returncode == 0, result.stdout
    except subprocess.TimeoutExpired:
        return False, "Ping timed out"
