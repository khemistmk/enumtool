from __future__ import annotations

import asyncio
from typing import List, Tuple

import dns.asyncresolver
import dns.resolver


async def _query(resolver: dns.asyncresolver.Resolver, name: str, rtype: str) -> List[str]:
    try:
        ans = await resolver.resolve(name, rtype, lifetime=3.0)
        return [str(r.to_text()).strip() for r in ans]
    except Exception:
        return []


def build_resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    # Reasonable public resolvers fallback
    r.nameservers = [
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
    ]
    r.lifetime = 3.0
    return r


async def enumerate_dns(name: str) -> Tuple[List[str], List[str], List[str], List[str], List[str], List[str], List[str]]:
    resolver = build_resolver()
    a, aaaa, cname, txt, mx, ns, srv = await asyncio.gather(
        _query(resolver, name, "A"),
        _query(resolver, name, "AAAA"),
        _query(resolver, name, "CNAME"),
        _query(resolver, name, "TXT"),
        _query(resolver, name, "MX"),
        _query(resolver, name, "NS"),
        _query(resolver, name, "SRV"),
    )
    return a, aaaa, cname, txt, mx, ns, srv
