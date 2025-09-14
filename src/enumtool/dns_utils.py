from __future__ import annotations

import asyncio
from typing import List, Tuple, Optional
import ipaddress
import dns.reversename

import dns.asyncresolver
import dns.resolver
import httpx


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


async def enumerate_dns_doh(name: str, client: Optional[httpx.AsyncClient] = None) -> Tuple[List[str], List[str], List[str], List[str], List[str], List[str], List[str]]:
    """Resolve DNS records using DoH (Cloudflare), suitable for Tor/anon mode.
    Requires an httpx.AsyncClient; if not provided, a short-lived one will be used.
    """
    url = "https://cloudflare-dns.com/dns-query"
    headers = {"accept": "application/dns-json"}
    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=5.0)
        close_client = True
    async def q(t: str) -> List[str]:
        try:
            r = await client.get(url, params={"name": name, "type": t}, headers=headers)
            if r.status_code != 200:
                return []
            data = r.json()
            ans = data.get("Answer") or []
            out: List[str] = []
            for rr in ans:
                if not isinstance(rr, dict):
                    continue
                d = rr.get("data")
                if isinstance(d, str):
                    out.append(d)
            return out
        except Exception:
            return []
    a, aaaa, cname, txt, mx, ns, srv = await asyncio.gather(
        q("A"), q("AAAA"), q("CNAME"), q("TXT"), q("MX"), q("NS"), q("SRV")
    )
    if close_client:
        await client.aclose()
    return a, aaaa, cname, txt, mx, ns, srv


async def ptr_lookup(ip: str, *, anon: bool = False, client: Optional[httpx.AsyncClient] = None) -> List[str]:
    """Reverse DNS (PTR) lookup to map IP -> hostnames. If anon, use DoH; else standard DNS.
    Returns a list of PTR names (FQDNs without trailing dot).
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return []
    try:
        rev = dns.reversename.from_address(ip)
        name = str(rev).rstrip('.')
    except Exception:
        return []
    if not anon:
        try:
            resolver = build_resolver()
            ans = await _query(resolver, name, "PTR")
            return [n.rstrip('.') for n in ans]
        except Exception:
            return []
    # DoH path
    url = "https://cloudflare-dns.com/dns-query"
    headers = {"accept": "application/dns-json"}
    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=5.0)
        close_client = True
    try:
        r = await client.get(url, params={"name": name, "type": "PTR"}, headers=headers)
        if r.status_code != 200:
            return []
        data = r.json()
        ans = data.get("Answer") or []
        out: List[str] = []
        for rr in ans:
            if not isinstance(rr, dict):
                continue
            d = rr.get("data")
            if isinstance(d, str):
                out.append(d.rstrip('.'))
        return out
    except Exception:
        return []
    finally:
        if close_client:
            await client.aclose()
