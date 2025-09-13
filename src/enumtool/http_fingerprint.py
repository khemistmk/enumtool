from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

import httpx
from bs4 import BeautifulSoup


async def fetch(url: str, timeout: float = 5.0) -> Optional[httpx.Response]:
    try:
        async with httpx.AsyncClient(http2=True, follow_redirects=True, timeout=timeout, headers={
            "User-Agent": "EnumTool/1.0"
        }) as client:
            resp = await client.get(url)
            return resp
    except Exception:
        return None


async def favicon_hash(url: str, timeout: float = 5.0) -> Optional[str]:
    # naive: try /favicon.ico
    base = url.rstrip("/")
    fav_url = base + "/favicon.ico"
    try:
        async with httpx.AsyncClient(http2=True, follow_redirects=True, timeout=timeout) as client:
            r = await client.get(fav_url)
            if r.status_code == 200 and r.content:
                return hashlib.sha1(r.content).hexdigest()
    except Exception:
        return None
    return None


def tech_hints_from_headers(headers: httpx.Headers) -> List[str]:
    hints: List[str] = []
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    if server:
        hints.append(f"server:{server}")
    if powered:
        hints.append(f"powered:{powered}")
    if "cloudflare" in (server or "").lower():
        hints.append("Cloudflare")
    if powered and "php" in powered.lower():
        hints.append("PHP")
    if powered and "express" in powered.lower():
        hints.append("Node.js Express")
    return hints


def tech_hints_from_html(html: str) -> List[str]:
    hints: List[str] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        if soup.find("meta", {"name": "generator"}):
            hints.append("Meta-Generator")
        title = soup.title.string.strip() if soup.title and soup.title.string else None
        if title:
            # Just keep as info, not strong signal
            pass
        # WordPress fingerprint
        if any("/wp-content/" in (tag.get("href") or tag.get("src") or "") for tag in soup.find_all(["link", "script", "img"])):
            hints.append("WordPress")
    except Exception:
        pass
    return hints


async def fingerprint_http(host: str, port: int, ssl: bool, timeout: float = 5.0) -> Dict[str, Optional[str]]:
    scheme = "https" if ssl else "http"
    url = f"{scheme}://{host}:{port}"
    resp = await fetch(url, timeout=timeout)
    if not resp:
        return {"url": url}
    hints = tech_hints_from_headers(resp.headers)
    body = resp.text if resp.content else ""
    hints += tech_hints_from_html(body)
    fav = await favicon_hash(url, timeout=timeout)
    title = None
    try:
        soup = BeautifulSoup(body, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else None
    except Exception:
        pass
    return {
        "url": url,
        "status": str(resp.status_code),
        "server": resp.headers.get("server"),
        "title": title,
        "favicon_hash": fav,
        "tech": ", ".join(sorted(set(hints))) if hints else None,
    }
