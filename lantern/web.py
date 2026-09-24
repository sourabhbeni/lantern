"""Web posture checks: security headers and TLS certificate inspection."""

from __future__ import annotations

import datetime as dt
import http.client
import socket
import ssl

#: Headers we expect on a hardened web response.
EXPECTED_HEADERS = {
    "strict-transport-security": ("medium", "HSTS not set — first-visit traffic can be downgraded"),
    "content-security-policy": ("low", "No Content-Security-Policy — wider XSS impact if injection occurs"),
    "x-frame-options": ("low", "Missing X-Frame-Options — page may be embeddable (clickjacking)"),
    "x-content-type-options": ("low", "Missing X-Content-Type-Options — MIME sniffing possible"),
    "referrer-policy": ("info", "No Referrer-Policy set"),
    "permissions-policy": ("info", "No Permissions-Policy set"),
}


def fetch_headers(host: str, use_https: bool, timeout: int = 10) -> tuple[int | None, dict[str, str]]:
    """Return (status, {lowercased header: value})."""
    conn_cls = http.client.HTTPSConnection if use_https else http.client.HTTPConnection
    conn = conn_cls(host, timeout=timeout)
    try:
        conn.request("GET", "/", headers={"User-Agent": "lantern/0.1.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers
    except Exception:
        return None, {}
    finally:
        conn.close()


def header_findings(host: str, headers: dict[str, str]) -> list[dict]:
    findings = []
    for name, (severity, title) in EXPECTED_HEADERS.items():
        if name not in headers:
            findings.append({
                "target": host, "severity": severity, "check": "security-headers",
                "title": title, "detail": f"Response did not include `{name}`.",
            })
    server = headers.get("server")
    if server:
        findings.append({
            "target": host, "severity": "info", "check": "banner",
            "title": f"Server banner discloses `{server}`",
            "detail": "Version banners help attackers fingerprint the stack; consider minimizing.",
        })
    return findings


def tls_info(host: str, port: int = 443, timeout: int = 10) -> dict:
    """Return TLS version, cert issuer, and days until expiry (empty dict on failure)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version() or "unknown"
    except Exception:
        return {}
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    days_left = (dt.datetime.fromtimestamp(not_after, tz=dt.timezone.utc)
                 - dt.datetime.now(tz=dt.timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", []))
    return {
        "tls_version": version,
        "days_left": days_left,
        "issuer": issuer.get("organizationName", issuer.get("commonName", "?")),
    }


def tls_findings(host: str, info: dict) -> list[dict]:
    findings = []
    if not info:
        return findings
    if info["days_left"] < 0:
        findings.append({"target": host, "severity": "high", "check": "tls",
                         "title": "TLS certificate has EXPIRED",
                         "detail": f"Expired {-info['days_left']} days ago."})
    elif info["days_left"] < 14:
        findings.append({"target": host, "severity": "medium", "check": "tls",
                         "title": f"TLS certificate expires in {info['days_left']} days",
                         "detail": f"Issuer: {info['issuer']}. Rotate before expiry to avoid outage."})
    if info["tls_version"] in ("TLSv1", "TLSv1.1"):
        findings.append({"target": host, "severity": "high", "check": "tls",
                         "title": f"Deprecated {info['tls_version']} negotiated",
                         "detail": "TLS 1.0/1.1 have known weaknesses; require TLS 1.2+."})
    return findings


def check_web(host: str, https_open: bool, http_open: bool) -> list[dict]:
    """Run header + TLS checks against *host*. Returns findings."""
    findings: list[dict] = []
    if https_open:
        status, headers = fetch_headers(host, use_https=True)
        if status:
            findings += header_findings(f"https://{host}", headers)
        info = tls_info(host)
        findings += tls_findings(host, info)
    elif http_open:
        status, headers = fetch_headers(host, use_https=False)
        if status:
            findings.append({"target": f"http://{host}", "severity": "medium", "check": "plaintext",
                             "title": "Site served over plaintext HTTP",
                             "detail": "No HTTPS listener found; traffic is unencrypted."})
            findings += header_findings(f"http://{host}", headers)
    return findings
