"""Async TCP port scanner (stdlib only)."""

from __future__ import annotations

import asyncio

#: Commonly exposed ports worth checking first.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    8888, 9200, 27017,
]

#: Ports that are rarely meant to face the internet.
SENSITIVE_PORTS = {
    23: "Telnet (cleartext)",
    445: "SMB",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
}


async def _check(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except Exception:
        return False
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return True


async def _scan(host: str, ports: list[int], timeout: float, concurrency: int) -> list[int]:
    sem = asyncio.Semaphore(concurrency)

    async def one(port: int) -> int | None:
        async with sem:
            return port if await _check(host, port, timeout) else None

    results = await asyncio.gather(*(one(p) for p in ports))
    return sorted(p for p in results if p is not None)


def scan_host(host: str, ports: list[int], timeout: float = 1.5, concurrency: int = 200) -> list[int]:
    """Return sorted list of open TCP ports on *host*."""
    return asyncio.run(_scan(host, ports, timeout, concurrency))


def scan_targets(targets: list[str], ports: list[int], timeout: float = 1.5) -> dict[str, list[int]]:
    """Scan several hosts/IPs. Returns {target: [open ports]}."""
    return {t: scan_host(t, ports, timeout) for t in targets}
