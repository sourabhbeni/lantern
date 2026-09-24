# 🏮 Lantern

[![ci](https://github.com/sourabhbeni/lantern/actions/workflows/ci.yml/badge.svg)](https://github.com/sourabhbeni/lantern/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![deps](https://img.shields.io/badge/dependencies-zero-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

**Lightweight attack-surface mapper.** Point Lantern at a domain and it maps what's
exposed: subdomains (via Certificate Transparency), open ports, security headers,
and TLS posture — then writes a clean HTML report. **Zero dependencies**, stdlib only.

```
$ python -m lantern beniwal.me -o report.html

🏮 lantern 0.1.0 → beniwal.me
  ▸ enumerating subdomains via crt.sh …
    found 3 subdomains
  ▸ resolving …
    4/4 hosts resolve
  ▸ scanning 26 ports …
  ✓ 4 hosts, 7 findings (0 high)
  → report.html
```

## How it works

```
                 ┌─────────────┐
                 │   crt.sh    │  Certificate Transparency → subdomains
                 └──────┬──────┘
                        ▼
┌────────┐      ┌──────────────┐      ┌───────────────┐
│ target │ ───▶ │ DNS resolve  │ ──▶ │ asyncio port  │ ──▶ open ports
└────────┘      │ (thread pool)│      │ scan (26 top) │
               └──────────────┘      └───────┬───────┘
                                            ▼
                              ┌─────────────────────────┐
                              │ web checks on :80 / :443 │
                              │ • security headers      │
                              │ • TLS version + expiry  │
                              │ • exposed admin ports   │
                              └────────────┬────────────┘
                                           ▼
                              ┌─────────────────────────┐
                              │ HTML + JSON report      │
                              └─────────────────────────┘
```

## Install

No dependencies — just Python 3.10+:

```bash
git clone https://github.com/sourabhbeni/lantern && cd lantern
python -m lantern --help
```

## Usage

```bash
# Quick scan (top 26 ports, subdomains included)
python -m lantern example.com

# Custom ports + JSON output
python -m lantern example.com --ports 80,443,8000-8100 --json out.json -o out.html

# Skip subdomain enumeration, longer timeouts
python -m lantern example.com --no-subdomains --timeout 3
```

### What gets flagged

| Check | Severity |
|---|---|
| Telnet / SMB / RDP reachable from the internet | High |
| Databases (MySQL, Postgres, Redis, Mongo) exposed | Medium |
| Site served over plaintext HTTP | Medium |
| Missing `Strict-Transport-Security` | Medium |
| Expired TLS certificate / TLS 1.0–1.1 | High |
| TLS expiring in < 14 days | Medium |
| Missing `Content-Security-Policy`, `X-Frame-Options`, … | Low |
| Server version banner disclosed | Info |

## Example report

Sample output (rendered by Lantern itself) lives in [`examples/sample-report.html`](examples/sample-report.html) —
open it in a browser to see what a finished scan looks like.

## Tests

```bash
pip install pytest && python -m pytest -q
```

All tests are offline (network calls are mocked).

## Ethics

Only scan systems you **own** or have **explicit permission** to test.
Unauthorized scanning may violate laws and terms of service. Lantern is built
for defenders — lab environments, bug-bounty scopes, and your own infrastructure.

## Roadmap

- [ ] Screenshot capture for web hosts
- [ ] CVE lookup for detected service banners
- [ ] DNS records audit (SPF/DMARC/CAA)
- [ ] Markdown report output

## License

MIT — see [LICENSE](LICENSE).
