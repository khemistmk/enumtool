from __future__ import annotations

import asyncio
from typing import Iterable, List, Tuple


DEFAULT_PORTS = [
    21, 22, 25, 53, 80, 110, 123, 143, 161, 389,
    443, 445, 465, 587, 631, 636, 8000, 8080, 8443, 9000,
]


async def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def scan_ports(host: str, ports: Iterable[int], concurrency: int = 200, timeout: float = 3.0) -> List[Tuple[int, bool]]:
    sem = asyncio.Semaphore(concurrency)
    results: List[Tuple[int, bool]] = []

    async def worker(p: int):
        async with sem:
            open_ = await check_port(host, p, timeout=timeout)
            results.append((p, open_))

    await asyncio.gather(*(worker(p) for p in ports))
    return sorted(results)
