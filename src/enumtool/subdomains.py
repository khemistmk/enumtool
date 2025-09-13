from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Iterable, List, Set, Optional, TYPE_CHECKING

from .dns_utils import enumerate_dns, enumerate_dns_doh
if TYPE_CHECKING:
    import httpx


async def _exists(name: str, *, anon: bool = False, client: Optional["httpx.AsyncClient"] = None) -> bool:
    if anon:
        a, aaaa, cname, *_ = await enumerate_dns_doh(name, client)
    else:
        a, aaaa, cname, *_ = await enumerate_dns(name)
    return bool(a or aaaa or cname)


def _expand_to_top_1000(base_words: List[str]) -> List[str]:
    # Ensure unique and prioritized common seeds first
    seeds = [
        "www","mail","smtp","imap","pop","webmail","ns","ns1","ns2","dns","mx","autodiscover",
        "api","app","dev","test","qa","stage","staging","prod","beta","alpha","demo","sandbox",
        "cdn","static","assets","img","media","files","download","uploads","origin","edge","proxy",
        "vpn","admin","portal","sso","auth","login","git","gitlab","jenkins","nexus","grafana","prometheus",
        "kibana","elastic","status","monitor","alerts","support","help","docs","wiki","blog","news","shop",
        "store","payments","billing","jira","confluence","wiki","db","sql","mysql","postgres","redis","kafka",
        "rabbitmq","k8s","kubernetes","istio","argocd","vault","consul","sonar","sonarqube","nginx","apache","iis",
        "tomcat","node","python","php","java","go","react","next","angular","vue","sso2","mobile","m",
    ]
    # Start from file-provided base words, then seeds
    base = []
    base.extend(base_words)
    base.extend(seeds)
    seen: Set[str] = set()
    out: List[str] = []
    def add(w: str):
        if w and w not in seen:
            seen.add(w)
            out.append(w)
    for w in base:
        add(w)
    # Numeric suffixes for common patterns
    common_numeric = [
        "www","mail","api","app","dev","test","stage","staging","cdn","static","img","media","files",
        "ns","dns","mx","edge","origin","proxy","gateway","admin","portal","vpn","db","web","server","node"
    ]
    for w in common_numeric:
        for i in range(1, 101):  # 100 each -> up to 1200, but duplicates filtered
            add(f"{w}{i}")
    # Hyphen variants
    hyphen_pairs = [
        ("api","dev"),("api","staging"),("api","beta"),("app","dev"),("app","staging"),("app","beta"),
        ("cdn","edge"),("cdn","origin"),("admin","portal"),("auth","sso"),("git","lab"),("status","page"),
    ]
    for a,b in hyphen_pairs:
        add(f"{a}-{b}")
        for i in range(1, 21):
            add(f"{a}-{b}{i}")
    # Environment prefixes
    envs = ["dev","staging","qa","test","prod","beta","alpha","demo","sandbox","internal","private"]
    for e in envs:
        for w in ["api","app","web","admin","portal","cdn","static","assets","auth","sso","git","jenkins","db","sql","files","media","docs","status","monitor","vpn"]:
            add(f"{e}-{w}")
    # Trim to top ~1000
    return out[:1000]


async def brute_subdomains(domain: str, wordlist_path: Path, concurrency: int = 200, *, anon: bool = False, client: Optional["httpx.AsyncClient"] = None) -> List[str]:
    words: List[str] = []
    try:
        with wordlist_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if not w or w.startswith("#"):
                    continue
                words.append(w)
    except FileNotFoundError:
        return []
    # Expand to approximately top 1000 common patterns
    words = _expand_to_top_1000(words)

    sem = asyncio.Semaphore(concurrency)
    results: List[str] = []

    async def worker(sub: str):
        fqdn = f"{sub}.{domain}".strip()
        async with sem:
            if await _exists(fqdn, anon=anon, client=client):
                results.append(fqdn)

    await asyncio.gather(*(worker(w) for w in words))
    return sorted(set(results))


async def passive_hints(domain: str, *, anon: bool = False, client: Optional["httpx.AsyncClient"] = None) -> List[str]:
    # Scan DNS TXT/MX/NS/CNAME for host-like strings
    if anon:
        _, _, cname, txt, mx, ns, _ = await enumerate_dns_doh(domain, client)
    else:
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
