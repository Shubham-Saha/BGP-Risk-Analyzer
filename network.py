"""Network utilities — HTTP fetch, DNS resolution, and ping."""

import json
import socket
import subprocess
import sys
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from config import USER_AGENT


def fetch_json(url: str, timeout: int = 20) -> dict:
    """GET a URL and return parsed JSON."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    response = urlopen(req, timeout=timeout)
    return json.loads(response.read().decode("utf-8"))


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
