from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from .dns_utils import enumerate_dns
from .models import DNSRecords, HTTPInfo, PortInfo, ScanResult, SubdomainFinding, WhoisInfo
from .report import render_report, write_report
from .subdomains import brute_subdomains, passive_hints
from .whois_utils import fetch_whois
from .config import get_settings
from .shodan_utils import ShodanClient
from .passive_sources import from_crtsh, from_threatcrowd
from .ports import DEFAULT_PORTS  # presets used only when active scan is enabled


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


async def _enrich_with_shodan(f: SubdomainFinding, shodan: ShodanClient) -> None:
    """Use Shodan host data to populate open ports and HTTP info without active probing."""
    # For each resolved IP, pull Shodan host info
    seen_ports = set()
    for ip in f.ips:
        host = shodan.host_info(ip)
        if not host:
            continue
        for item in host.get("data", []) or []:
            port = item.get("port")
            if not isinstance(port, int):
                continue
            if port not in seen_ports:
                seen_ports.add(port)
                f.ports.append(PortInfo(port=port, open=True, service=item.get("product")))
            # HTTP specifics
            http = item.get("http")
            if http:
                ssl = bool(item.get("ssl")) or port in (443, 8443)
                scheme = "https" if ssl else "http"
                key = f"{port}/{scheme}"
                if key not in f.http:
                    f.http[key] = HTTPInfo(
                        url=f"{scheme}://{f.name}:{port}",
                        status=http.get("status") if isinstance(http.get("status"), int) else None,
                        title=http.get("title"),
                        server=http.get("server"),
                        tech=[t for t in [http.get("server"), item.get("product")] if t],
                    )


async def run_scan(domain: str, outdir: Path, ports_preset: Optional[str], ports_list: Optional[str], wordlist: Path, concurrency: int, timeout: float, active_scan: bool) -> ScanResult:
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

    # OSINT clients
    settings = get_settings()
    shodan = ShodanClient(settings.shodan_api_key)

    # Subdomains via DNS hints, crt.sh, ThreatCrowd, and Shodan
    hints = await passive_hints(domain)
    crt = await from_crtsh(domain)
    tc = await from_threatcrowd(domain)
    shodan_subs, shodan_records = ([], {})
    if shodan.enabled():
        try:
            shodan_subs, shodan_records = shodan.domain_info(domain)
        except Exception:
            shodan_subs, shodan_records = ([], {})
    names = sorted(set(hints + crt + tc + shodan_subs + [domain]))
    subfindings = await _resolve_all(names)

    # Enrich with OSINT (Shodan). No active host probing unless explicitly enabled.
    await asyncio.gather(*(_enrich_with_shodan(sf, shodan) for sf in subfindings))

    # Optionally perform active scan if enabled by user flag
    if active_scan:
        from .ports import scan_ports  # lazy import to avoid accidental usage otherwise
        from .http_fingerprint import fingerprint_http  # lazy import
        chosen_ports = _choose_ports(ports_preset, ports_list)
        async def _active(sf: SubdomainFinding):
            port_states = await scan_ports(sf.name, chosen_ports, concurrency=concurrency, timeout=timeout)
            # Merge: preserve OSINT-found open ports, add newly open ones
            known = {p.port for p in sf.ports if p.open}
            for p, state in port_states:
                if state and p not in known:
                    sf.ports.append(PortInfo(port=p, open=True))
            # Try HTTP fingerprint only for open web ports not already in http map
            targets = []
            for pinfo in sf.ports:
                if not pinfo.open:
                    continue
                if pinfo.port in (80, 8080, 8000, 8888):
                    targets.append((pinfo.port, False))
                if pinfo.port in (443, 8443):
                    targets.append((pinfo.port, True))
            async def do_fp(p: int, ssl: bool):
                key = f"{p}/{ 'https' if ssl else 'http'}"
                if key in sf.http:
                    return
                data = await fingerprint_http(sf.name, p, ssl, timeout=timeout)
                if data:
                    sf.http[key] = HTTPInfo(
                        url=data.get("url", f"http://{sf.name}:{p}"),
                        status=int(data["status"]) if data.get("status") and str(data["status"]).isdigit() else None,
                        title=data.get("title"),
                        server=data.get("server"),
                        favicon_hash=data.get("favicon_hash"),
                        tech=[t.strip() for t in (data.get("tech") or "").split(",") if t.strip()],
                    )
            await asyncio.gather(*(do_fp(p, ssl) for p, ssl in targets))
        await asyncio.gather(*(_active(sf) for sf in subfindings))

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
    active: bool = False,
) -> Path:
    outdir = outdir or Path("reports") / f"{domain}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    project_root = Path(__file__).resolve().parents[2]
    tmpl_dir = project_root / "templates"
    wordlist = wordlist or (project_root / "data" / "subdomains-top.txt")

    result = asyncio.run(run_scan(domain, outdir, ports, ports_list, wordlist, concurrency, timeout, active))
    # Render HTML
    html = render_report(tmpl_dir, {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "result": result,
    })
    path = write_report(outdir, html)

    if write_json:
        (outdir / "result.json").write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
    return path
