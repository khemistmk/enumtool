from __future__ import annotations

import asyncio
from typing import Iterable, List, Tuple, Optional
import socket
import asyncio
try:
    import socks  # PySocks
except Exception:  # pragma: no cover
    socks = None  # type: ignore


DEFAULT_PORTS = [
    21, 22, 25, 53, 80, 110, 123, 143, 161, 389,
    443, 445, 465, 587, 631, 636, 8000, 8080, 8443, 9000,
]


async def check_port(host: str, port: int, timeout: float = 3.0, socks_proxy: Optional[Tuple[str, int]] = None) -> bool:
    if socks_proxy and socks is not None:
        # Use blocking PySocks connect in a thread to avoid blocking the event loop
        def _block() -> bool:
            try:
                s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                s.set_proxy(socks.SOCKS5, socks_proxy[0], socks_proxy[1])
                s.settimeout(timeout)
                s.connect((host, port))
                s.close()
                return True
            except Exception:
                return False
        return await asyncio.to_thread(_block)
    # Fallback: plain asyncio TCP
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


async def scan_ports(host: str, ports: Iterable[int], concurrency: int = 200, timeout: float = 3.0, socks_proxy: Optional[Tuple[str, int]] = None) -> List[Tuple[int, bool]]:
    sem = asyncio.Semaphore(concurrency)
    results: List[Tuple[int, bool]] = []

    async def worker(p: int):
        async with sem:
            open_ = await check_port(host, p, timeout=timeout, socks_proxy=socks_proxy)
            results.append((p, open_))

    await asyncio.gather(*(worker(p) for p in ports))
    return sorted(results)


async def check_udp_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Best-effort UDP check: send a small payload and consider 'open' only if any response arrives.
    Limitations: many UDP services don't reply to random payloads, so open ports may be missed.
    """
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bool] = loop.create_future()

    class Proto(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            try:
                transport.sendto(b"\x00")
            except Exception:
                pass

        def datagram_received(self, data, addr):
            if not fut.done():
                fut.set_result(True)

        def error_received(self, exc):
            if not fut.done():
                fut.set_result(False)

    try:
        transport, protocol = await loop.create_datagram_endpoint(lambda: Proto(), remote_addr=(host, port))
        try:
            try:
                return await asyncio.wait_for(fut, timeout=timeout)
            except asyncio.TimeoutError:
                return False
        finally:
            transport.close()
    except Exception:
        return False


async def scan_udp_ports(host: str, ports: Iterable[int], concurrency: int = 200, timeout: float = 1.0) -> List[Tuple[int, bool]]:
    sem = asyncio.Semaphore(concurrency)
    results: List[Tuple[int, bool]] = []

    async def worker(p: int):
        async with sem:
            open_ = await check_udp_port(host, p, timeout=timeout)
            results.append((p, open_))

    await asyncio.gather(*(worker(p) for p in ports))
    return sorted(results)
