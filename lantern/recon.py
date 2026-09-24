"""Subdomain enumeration via crt.sh and parallel DNS resolution."""

from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def fetch_subdomains(domain: str, timeout: int = 25) -> list[str]:
    """Return sorted unique subdomains of *domain* from crt.sh (Certificate Transparency)."""
    q = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={q}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "lantern/0.1.0 (security research)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    subs: set[str] = set()
    suffix = "." + domain.lower()
    for entry in data:
        for line in str(entry.get("name_value", "")).splitlines():
            name = line.strip().lower().rstrip(".")
            if not name or name.startswith("*"):
                continue
            if name == domain.lower() or name.endswith(suffix):
                subs.add(name)
    return sorted(subs)


def _resolve_one(host: str) -> tuple[str, list[str]]:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return host, []
    ips = sorted({info[4][0] for info in infos})
    return host, ips


def resolve_hosts(hosts: list[str], workers: int = 20) -> dict[str, list[str]]:
    """Resolve hostnames to IPs in parallel. Returns {host: [ips]}."""
    out: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, ips in pool.map(_resolve_one, hosts):
            out[host] = ips
    return out
