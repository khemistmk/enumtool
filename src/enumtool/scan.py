from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from .dns_utils import enumerate_dns
from .http_fingerprint import fingerprint_http
from .models import DNSRecords, HTTPInfo, PortInfo, ScanResult, SubdomainFinding, WhoisInfo
from .ports import DEFAULT_PORTS, scan_ports
from .report import render_report, write_report
from .subdomains import brute_subdomains, passive_hints
from .whois_utils import fetch_whois


def _choose_ports(preset: Optional[str], explicit: Optional[str]) -> List[int]:
    if explicit:
        return sorted({int(p.strip()) for p in explicit.split(",") if p.strip().isdigit()})
    if preset == "web":
        return [80, 443, 8080, 8443]
    if preset == "top100":
        # Minimal representative set; user can expand later
        base = set(DEFAULT_PORTS)
        base.update([23, 135, 139, 3306, 3389, 53, 25])
        return sorted(base)
    if preset == "full-small":
        return sorted(set(DEFAULT_PORTS))
    return sorted(set(DEFAULT_PORTS))


async def _resolve_all(names: Iterable[str]) -> List[SubdomainFinding]:
    results: List[SubdomainFinding] = []
    for name in names:
        a, aaaa, cname, txt, mx, ns, srv = await enumerate_dns(name)
        ips = a + aaaa
        rec = DNSRecords(a=a, aaaa=aaaa, cname=cname, txt=txt, mx=mx, ns=ns, srv=srv)
        results.append(SubdomainFinding(name=name, ips=ips, dns=rec))
    return results


async def _fingerprint_services(f: SubdomainFinding, ports: List[int], timeout: float, concurrency: int) -> None:
    # Port scan
    port_states = await scan_ports(f.name, ports, concurrency=concurrency, timeout=timeout)
    f.ports = [PortInfo(port=p, open=state) for p, state in port_states]
    # For opened ports, try HTTP(S) on common web ports
    http_targets = []
    for p, state in port_states:
        if not state:
            continue
        if p in (80, 8080, 8000, 8888):
            http_targets.append((p, False))
        if p in (443, 8443):
            http_targets.append((p, True))
    # Fingerprint concurrently
    async def do_fp(p: int, ssl: bool):
        data = await fingerprint_http(f.name, p, ssl, timeout=timeout)
        if data:
            f.http[f"{p}/{ 'https' if ssl else 'http'}"] = HTTPInfo(
                url=data.get("url", f"http://{f.name}:{p}"),
                status=int(data["status"]) if data.get("status") and data["status"].isdigit() else None,
                title=data.get("title"),
                server=data.get("server"),
                favicon_hash=data.get("favicon_hash"),
                tech=[t.strip() for t in (data.get("tech") or "").split(",") if t.strip()],
            )

    await asyncio.gather(*(do_fp(p, ssl) for p, ssl in http_targets))


async def run_scan(domain: str, outdir: Path, ports_preset: Optional[str], ports_list: Optional[str], wordlist: Path, concurrency: int, timeout: float) -> ScanResult:
    # WHOIS and apex DNS
    who = fetch_whois(domain)
    a, aaaa, cname, txt, mx, ns, srv = await enumerate_dns(domain)
    apex_records = DNSRecords(a=a, aaaa=aaaa, cname=cname, txt=txt, mx=mx, ns=ns, srv=srv)
    whois_info = WhoisInfo(
        registrar=who.get("registrar"),
        creation_date=str(who.get("creation_date")),
        expiration_date=str(who.get("expiration_date")),
        name_servers=[str(who.get("name_servers"))] if who.get("name_servers") else [],
    )

    # Subdomains
    hints = await passive_hints(domain)
    brute = await brute_subdomains(domain, wordlist, concurrency=concurrency)
    names = sorted(set(hints + brute + [domain]))
    subfindings = await _resolve_all(names)

    # Ports + HTTP fingerprint per subdomain
    chosen_ports = _choose_ports(ports_preset, ports_list)
    await asyncio.gather(*(
        _fingerprint_services(sf, chosen_ports, timeout=timeout, concurrency=concurrency)
        for sf in subfindings
    ))

    return ScanResult(domain=domain, whois=whois_info, records=apex_records, subdomains=subfindings)


def scan_domain(
    domain: str,
    outdir: Optional[Path] = None,
    ports: Optional[str] = None,
    ports_list: Optional[str] = None,
    wordlist: Optional[Path] = None,
    concurrency: int = 200,
    timeout: float = 5.0,
    write_json: bool = True,
) -> Path:
    outdir = outdir or Path("reports") / f"{domain}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    project_root = Path(__file__).resolve().parents[2]
    tmpl_dir = project_root / "templates"
    wordlist = wordlist or (project_root / "data" / "subdomains-top.txt")

    result = asyncio.run(run_scan(domain, outdir, ports, ports_list, wordlist, concurrency, timeout))
    # Render HTML
    html = render_report(tmpl_dir, {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "result": result,
    })
    path = write_report(outdir, html)

    if write_json:
        (outdir / "result.json").write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
    return path
