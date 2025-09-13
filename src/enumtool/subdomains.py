from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Iterable, List, Set

from .dns_utils import enumerate_dns


async def _exists(name: str) -> bool:
    a, aaaa, cname, *_ = await enumerate_dns(name)
    return bool(a or aaaa or cname)


async def brute_subdomains(domain: str, wordlist_path: Path, concurrency: int = 200) -> List[str]:
    words = []
    try:
        with wordlist_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if not w or w.startswith("#"):
                    continue
                words.append(w)
    except FileNotFoundError:
        return []

    sem = asyncio.Semaphore(concurrency)
    results: List[str] = []

    async def worker(sub: str):
        fqdn = f"{sub}.{domain}".strip()
        async with sem:
            if await _exists(fqdn):
                results.append(fqdn)

    await asyncio.gather(*(worker(w) for w in words))
    return sorted(set(results))


async def passive_hints(domain: str) -> List[str]:
    # Scan DNS TXT/MX/NS/CNAME for host-like strings
    _, _, cname, txt, mx, ns, _ = await enumerate_dns(domain)
    hints: Set[str] = set()
    candidates = []
    candidates += [r.split()[-1].strip(".") for r in mx]
    candidates += [r.strip(".") for r in ns]
    candidates += [r.strip(".") for r in cname]
    for t in txt:
        for token in t.replace("\"", "").split():
            if token.endswith(domain) and "." in token:
                candidates.append(token.strip("."))
    for c in candidates:
        if c.endswith(domain):
            hints.add(c)
    return sorted(hints)
