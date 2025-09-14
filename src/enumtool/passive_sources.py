from __future__ import annotations

import json
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import quote_plus

import httpx

from .config import get_api_key, load_env, get_settings


async def from_crtsh(domain: str, client: Optional[httpx.AsyncClient] = None) -> List[str]:
    # Public, no key required
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0)
            close = True
        r = await client.get(url)
        if r.status_code != 200:
            return []
        # Some entries may be concatenated JSON objects; handle leniency
        try:
            data = r.json()
        except json.JSONDecodeError:
            # Fallback: parse line-by-line
            data = json.loads("[" + r.text.replace("}\n{", "},{") + "]")
        names: Set[str] = set()
        for item in data:
            name_value = item.get("name_value") or ""
            for raw in name_value.split("\n"):
                fqdn = raw.strip().lower()
                if fqdn.endswith(domain):
                    names.add(fqdn)
        return sorted(names)
    except Exception:
        return []
    finally:
        if 'close' in locals() and close:
            await client.aclose()


async def from_threatcrowd(domain: str, client: Optional[httpx.AsyncClient] = None) -> List[str]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0)
            close = True
        r = await client.get(url)
        if r.status_code != 200:
            return []
        data = r.json()
        subs = data.get("subdomains") or []
        out = [s.strip().lower() for s in subs if isinstance(s, str) and s.endswith(domain)]
        return sorted(set(out))
    except Exception:
        return []
    finally:
        if 'close' in locals() and close:
            await client.aclose()


async def from_threatcrowd_ip(ip: str, client: Optional[httpx.AsyncClient] = None) -> List[str]:
    """Resolve IP to domains observed by ThreatCrowd."""
    url = f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}"
    try:
        close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0)
            close = True
        r = await client.get(url)
        if r.status_code != 200:
            return []
        data = r.json()
        doms = data.get("resolutions") or []
        out: List[str] = []
        for item in doms:
            d = item.get("domain") if isinstance(item, dict) else None
            if isinstance(d, str) and d:
                out.append(d.strip().lower())
        return sorted(set(out))
    except Exception:
        return []
    finally:
        if 'close' in locals() and close:
            await client.aclose()


async def from_shodan(domain: str) -> Tuple[List[str], List[Tuple[str, int, List[str]]]]:
    """Return (hostnames, observed_ports). observed_ports: list of (hostname, port, tech-hints)
    Uses Shodan API: search for domain and parse hostnames and open ports from datasets.
    """
    load_env()
    key = get_api_key("SHODAN_API_KEY")
    if not key:
        return [], []
    # Domain search via Shodan Search API (query: hostname:*.domain)
    query = f"hostname:.{domain}"
    url = f"https://api.shodan.io/shodan/host/search?key={key}&query={quote_plus(query)}"
    hostnames: Set[str] = set()
    ports: List[Tuple[str, int, List[str]]] = []
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return [], []
            data = r.json()
            for m in data.get("matches", []):
                # hostnames
                for h in m.get("hostnames", []) or []:
                    if isinstance(h, str) and h.endswith(domain):
                        hostnames.add(h.lower())
                # open ports
                p = m.get("port")
                if isinstance(p, int):
                    # Basic tech hints from Shodan fields
                    hints: List[str] = []
                    product = m.get("product") or m.get("_shodan", {}).get("module")
                    if isinstance(product, str):
                        hints.append(product)
                    http = m.get("http") or {}
                    if isinstance(http, dict):
                        server = http.get("server")
                        title = http.get("title")
                        if isinstance(server, str):
                            hints.append(f"server:{server}")
                        if isinstance(title, str):
                            hints.append(f"title:{title[:60]}")
                    # Choose a hostname to associate
                    assoc = None
                    for h in (m.get("hostnames") or []):
                        if isinstance(h, str) and h.endswith(domain):
                            assoc = h.lower()
                            break
                    if assoc:
                        ports.append((assoc, p, hints))
            return sorted(hostnames), ports
    except Exception:
        return [], []


# --- SecurityTrails ---

async def st_subdomains(domain: str, client: Optional[httpx.AsyncClient] = None) -> List[str]:
    """Enumerate subdomains via SecurityTrails (requires SECURITYTRAILS_API_KEY).
    API: POST https://api.securitytrails.com/v1/domain/{domain}/subdomains
    """
    load_env()
    key = get_api_key("SECURITYTRAILS_API_KEY")
    if not key:
        return []
    base = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"Accept": "application/json", "APIKEY": key}
    close = False
    try:
        if client is None:
            client = httpx.AsyncClient(timeout=15.0)
            close = True
        r = await client.get(base, headers=headers)
        if r.status_code != 200:
            return []
        data = r.json()
        subs = data.get("subdomains") or []
        out = [f"{s.strip().lower()}.{domain}" for s in subs if isinstance(s, str) and s.strip()]
        return sorted(set(out))
    except Exception:
        return []
    finally:
        if close:
            await client.aclose()


async def st_dns_history(domain: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, List[str]]:
    """Fetch current DNS A/AAAA and historical to cross-reference IPs for the domain via SecurityTrails.
    API: GET https://api.securitytrails.com/v1/domain/{domain}
    Returns mapping record_type -> list of values (e.g., {"a": ["1.2.3.4"], "aaaa": ["::1"]}).
    """
    load_env()
    key = get_api_key("SECURITYTRAILS_API_KEY")
    if not key:
        return {}
    url = f"https://api.securitytrails.com/v1/domain/{domain}"
    headers = {"Accept": "application/json", "APIKEY": key}
    close = False
    try:
        if client is None:
            client = httpx.AsyncClient(timeout=15.0)
            close = True
        r = await client.get(url, headers=headers)
        if r.status_code != 200:
            return {}
        data = r.json()
        recs: Dict[str, List[str]] = {}
        for t in ("a", "aaaa", "mx", "ns", "cname"):
            vals: List[str] = []
            cur = (((data.get("current_dns") or {}).get(t) or {}).get("values") or [])
            for v in cur:
                if isinstance(v, dict):
                    # A/AAAA
                    if "ip" in v:
                        vals.append(str(v.get("ip")).strip())
                    # CNAME/MX/NS
                    if "hostname" in v:
                        vals.append(str(v.get("hostname")).strip().lower())
            if vals:
                recs[t] = sorted(set(vals))
        return recs
    except Exception:
        return {}
    finally:
        if close:
            await client.aclose()
