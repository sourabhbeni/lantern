"""Lantern CLI — map the attack surface of a domain you own."""

from __future__ import annotations

import argparse
import sys

from . import __version__, ports, recon, report as report_mod, web


def parse_ports(spec: str) -> list[int]:
    if spec.strip().lower() == "top":
        return ports.TOP_PORTS
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        elif part:
            out.add(int(part))
    return sorted(p for p in out if 1 <= p <= 65535) or ports.TOP_PORTS


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="lantern",
        description="Map a domain's attack surface: subdomains, open ports, web security posture. "
                    "Only scan systems you own or are authorized to test.",
    )
    p.add_argument("target", help="Domain to scan, e.g. example.com")
    p.add_argument("-o", "--output", default="lantern-report.html", help="HTML report path (default: lantern-report.html)")
    p.add_argument("--json", dest="json_out", default=None, help="Also write JSON results to this path")
    p.add_argument("--ports", default="top", help='"top" (26 common ports) or list like "80,443,8000-8100"')
    p.add_argument("--timeout", type=float, default=1.5, help="Per-port timeout in seconds (default: 1.5)")
    p.add_argument("--no-subdomains", action="store_true", help="Skip crt.sh subdomain enumeration")
    p.add_argument("--max-hosts", type=int, default=25, help="Max hosts to port-scan (default: 25)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    target = args.target.strip().lower()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].rstrip(".")
    if not target or "." not in target:
        print("error: give a bare domain like example.com", file=sys.stderr)
        return 2

    print(f"🏮 lantern {__version__} → {target}")

    # 1. Subdomains
    hosts = [target]
    if not args.no_subdomains:
        print("  ▸ enumerating subdomains via crt.sh …", flush=True)
        try:
            subs = recon.fetch_subdomains(target)
        except Exception as exc:
            print(f"    ! subdomain lookup failed: {exc}")
            subs = []
        print(f"    found {len(subs)} subdomains")
        hosts += subs
    hosts = hosts[: args.max_hosts]

    # 2. DNS
    print("  ▸ resolving …", flush=True)
    resolved = recon.resolve_hosts(hosts)
    live = {h: ips for h, ips in resolved.items() if ips}
    print(f"    {len(live)}/{len(hosts)} hosts resolve")

    # 3. Ports (scan each unique IP once)
    port_list = parse_ports(args.ports)
    print(f"  ▸ scanning {len(port_list)} ports …", flush=True)
    ip_to_host = {}
    for h, ips in live.items():
        for ip in ips:
            ip_to_host.setdefault(ip, h)
    ip_ports = ports.scan_targets(list(ip_to_host), port_list, timeout=args.timeout)

    host_data: dict[str, dict] = {}
    for h, ips in live.items():
        open_ports = sorted({p for ip in ips for p in ip_ports.get(ip, [])})
        host_data[h] = {"ips": ips, "open_ports": open_ports}

    # 4. Web posture for hosts with web ports open
    findings: list[dict] = []
    for host, data in host_data.items():
        for p, label in ports.SENSITIVE_PORTS.items():
            if p in data["open_ports"]:
                findings.append({
                    "target": f"{host}:{p}", "severity": "high" if p in (23, 445, 3389) else "medium",
                    "check": "exposed-service",
                    "title": f"Sensitive service exposed: {label}",
                    "detail": f"Port {p} is reachable from the internet. Restrict with firewall/security groups.",
                })
        https_open = 443 in data["open_ports"]
        http_open = 80 in data["open_ports"]
        if https_open or http_open:
            findings += web.check_web(host, https_open, http_open)

    # 5. Report
    rep = report_mod.build_report(target, host_data, findings)
    with open(args.output, "w") as f:
        f.write(report_mod.to_html(rep))
    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(report_mod.to_json(rep))

    n_high = rep["summary"]["high"]
    print(f"  ✓ {len(host_data)} hosts, {len(findings)} findings ({n_high} high)")
    print(f"  → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
