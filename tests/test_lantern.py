"""Offline unit tests for lantern (no network access)."""

import json

from lantern import ports, recon, report as report_mod, web


def test_parse_ports_top():
    from lantern.cli import parse_ports
    assert parse_ports("top") == ports.TOP_PORTS


def test_parse_ports_list_and_range():
    from lantern.cli import parse_ports
    assert parse_ports("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]


def test_parse_ports_invalid_falls_back():
    from lantern.cli import parse_ports
    assert parse_ports("99999") == ports.TOP_PORTS


def test_header_findings_missing():
    findings = web.header_findings("https://x.test", {})
    names = {f["check"] for f in findings}
    assert "security-headers" in names
    assert any(f["severity"] == "medium" for f in findings if "HSTS" in f["title"])


def test_header_findings_present_and_banner():
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "server": "nginx/1.25",
    }
    findings = web.header_findings("https://x.test", headers)
    assert not [f for f in findings if f["check"] == "security-headers"]
    assert any(f["check"] == "banner" and "nginx" in f["title"] for f in findings)


def test_tls_findings_expired_and_old_version():
    findings = web.tls_findings("x.test", {"tls_version": "TLSv1", "days_left": -3, "issuer": "X"})
    assert any(f["severity"] == "high" and "EXPIRED" in f["title"] for f in findings)
    assert any("Deprecated" in f["title"] for f in findings)


def test_tls_findings_healthy():
    assert web.tls_findings("x.test", {"tls_version": "TLSv1.3", "days_left": 90, "issuer": "X"}) == []
    assert web.tls_findings("x.test", {}) == []


def test_subdomain_parsing(monkeypatch):
    sample = [
        {"name_value": "a.example.com"},
        {"name_value": "b.example.com\n*.example.com"},
        {"name_value": "other.com"},
    ]

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(sample).encode()

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=25: FakeResp())
    assert recon.fetch_subdomains("example.com") == ["a.example.com", "b.example.com"]


def test_report_ordering_and_json():
    findings = [
        {"target": "t", "severity": "info", "check": "c", "title": "i", "detail": "d"},
        {"target": "t", "severity": "high", "check": "c", "title": "h", "detail": "d"},
    ]
    rep = report_mod.build_report("example.com", {"example.com": {"ips": ["1.2.3.4"], "open_ports": [443]}}, findings)
    assert rep["findings"][0]["severity"] == "high"
    assert rep["summary"] == {"high": 1, "medium": 0, "low": 0, "info": 1}
    assert json.loads(report_mod.to_json(rep))["target"] == "example.com"
    html = report_mod.to_html(rep)
    assert "Lantern report" in html and "example.com" in html
