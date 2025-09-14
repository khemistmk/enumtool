from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, List, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    import httpx

from .dns_utils import enumerate_dns, enumerate_dns_doh, ptr_lookup
from .models import DNSRecords, HTTPInfo, PortInfo, ScanResult, SubdomainFinding, WhoisInfo
from .report import render_report, write_report
from .subdomains import brute_subdomains, passive_hints
from .whois_utils import fetch_whois
from .config import get_settings
from .shodan_utils import ShodanClient
from .passive_sources import from_crtsh, from_threatcrowd, st_subdomains, st_dns_history
from .ports import DEFAULT_PORTS  # presets used only when active scan is enabled
from .tor_utils import TorManager


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


async def _resolve_all(names: Iterable[str], *, anon: bool = False, client: Optional["httpx.AsyncClient"] = None) -> List[SubdomainFinding]:
    results: List[SubdomainFinding] = []
    for name in names:
        if anon:
            a, aaaa, cname, txt, mx, ns, srv = await enumerate_dns_doh(name, client)
        else:
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


async def run_scan(domain: str, outdir: Path, ports_preset: Optional[str], ports_list: Optional[str], wordlist: Path, bruteforce: bool, concurrency: int, timeout: float, active_scan: bool, progress: Optional[Callable[[str], None]] = None, anon: bool = False) -> ScanResult:
    if progress:
        progress("Fetching WHOIS and apex DNS records…")
    # WHOIS and apex DNS
    who = {} if anon else fetch_whois(domain)
    if anon:
        a, aaaa, cname, txt, mx, ns, srv = await enumerate_dns_doh(domain)
    else:
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
    tor: Optional[TorManager] = None
    socks_url = None
    if anon:
        tor = TorManager()
        try:
            host, port = tor.start(progress)
            socks_url = f"socks5://{host}:{port}"
        except Exception as e:
            # Fail hard in anon mode
            if progress:
                progress(f"[warning] Could not start Tor: {e}")
            raise RuntimeError("--anon requested but Tor is not available/running. Install Tor or set TOR_EXE.")
    shodan = ShodanClient(settings.shodan_api_key, proxies={"http": socks_url, "https": socks_url} if socks_url else None)

    # Subdomains via DNS hints, crt.sh, ThreatCrowd, and Shodan
    if progress:
        progress("Gathering passive subdomain hints (DNS TXT/MX/NS/CNAME)…")
    # Shared HTTP client (optionally over Tor)
    http_client = None
    if socks_url:
        import httpx  # type: ignore[import]
        proxies = {"http://": socks_url, "https://": socks_url}
        http_client = httpx.AsyncClient(timeout=10.0, proxies=proxies)
    # Passive OSINT collection
    hints = await passive_hints(domain, anon=anon, client=http_client)  # DNS hints respect anon mode
    if progress:
        progress("Querying crt.sh and ThreatCrowd for CT and community data…")
    crt = await from_crtsh(domain, client=http_client) if http_client else await from_crtsh(domain)
    tc = await from_threatcrowd(domain, client=http_client) if http_client else await from_threatcrowd(domain)
    # SecurityTrails: subdomains and apex DNS cross-ref
    st_subs: List[str] = []
    try:
        if progress:
            progress("Querying SecurityTrails for subdomains and DNS…")
        st_subs = await st_subdomains(domain, client=http_client) if http_client else await st_subdomains(domain)
        st_dns = await st_dns_history(domain, client=http_client) if http_client else await st_dns_history(domain)
        # Merge apex A/AAAA records with SecurityTrails current DNS
        if st_dns:
            a_merge = sorted(set((apex_records.a or []) + st_dns.get("a", [])))
            aaaa_merge = sorted(set((apex_records.aaaa or []) + st_dns.get("aaaa", [])))
            apex_records = DNSRecords(
                a=a_merge,
                aaaa=aaaa_merge,
                cname=apex_records.cname,
                txt=apex_records.txt,
                mx=apex_records.mx,
                ns=apex_records.ns,
                srv=apex_records.srv,
            )
    except Exception:
        st_subs = st_subs or []
    shodan_subs, shodan_records = ([], {})
    if shodan.enabled():
        if progress:
            progress("Pulling Shodan domain data (subdomains & DNS records)…")
        try:
            shodan_subs, shodan_records = shodan.domain_info(domain)
        except Exception:
            shodan_subs, shodan_records = ([], {})
    brute: List[str] = []
    if bruteforce:
        if progress:
            progress("Running DNS bruteforce (~1000 common names)…")
        brute = await brute_subdomains(domain, wordlist, concurrency=concurrency, anon=anon, client=http_client)
    crt = crt or []
    tc = tc or []
    st_subs = st_subs or []
    shodan_subs = shodan_subs or []
    brute = brute or []
    names = sorted(set(hints + crt + tc + st_subs + shodan_subs + brute + [domain]))
    if progress:
        progress(f"Resolving {len(names)} names to collect DNS records and IPs…")
    subfindings = await _resolve_all(names, anon=anon, client=http_client)

    # Enrich with OSINT (Shodan). No active host probing unless explicitly enabled.
    if progress:
        progress("Enriching with Shodan host data (ports/tech) for resolved IPs…")
    await asyncio.gather(*(_enrich_with_shodan(sf, shodan) for sf in subfindings))

    # Optionally perform active scan if enabled by user flag
    if active_scan:
        if progress:
            progress("Active scan enabled: probing TCP ports and HTTP services…")
        from .ports import scan_ports, scan_udp_ports  # lazy import to avoid accidental usage otherwise
        from .http_fingerprint import fingerprint_http  # lazy import
        # Determine TCP/UDP targets
        tcp_ports: List[int] = []
        udp_ports: List[int] = []
        if ports_list:
            tcp_ports = _choose_ports(None, ports_list)
        elif ports_preset == "tcp":
            tcp_ports = list(range(1, 65536))
        elif ports_preset == "udp":
            udp_ports = list(range(1, 65536))
        elif ports_preset == "all":
            tcp_ports = list(range(1, 65536))
            udp_ports = list(range(1, 65536))
        else:
            tcp_ports = _choose_ports(ports_preset, None)
        async def _active(sf: SubdomainFinding):
            socks_tuple = None
            if socks_url:
                # parse socks5://host:port -> (host, port)
                try:
                    host_port = socks_url.split("://",1)[1]
                    host, port_s = host_port.split(":")
                    socks_tuple = (host, int(port_s))
                except Exception:
                    socks_tuple = None
            if tcp_ports:
                if progress:
                    progress(f"[dim]  → {sf.name}: scanning {len(tcp_ports)} TCP ports…[/]")
                port_states = await scan_ports(sf.name, tcp_ports, concurrency=concurrency, timeout=timeout, socks_proxy=socks_tuple)
            else:
                port_states = []
            # UDP cannot be proxied over Tor; skip in anon mode
            udp_states: List[tuple[int, bool]] = []
            if udp_ports:
                if anon:
                    if progress:
                        progress(f"[yellow]Skipping UDP scan for {sf.name} in anon mode (cannot route via Tor).[/]")
                else:
                    if progress:
                        progress(f"[dim]  → {sf.name}: scanning {len(udp_ports)} UDP ports…[/]")
                    udp_states = await scan_udp_ports(sf.name, udp_ports, concurrency=concurrency, timeout=max(1.0, timeout/2))
            # Merge: preserve OSINT-found open ports, add newly open ones
            known = {p.port for p in sf.ports if p.open}
            for p, state in port_states:
                if state and p not in known:
                    sf.ports.append(PortInfo(port=p, open=True, protocol="tcp"))
            for p, state in udp_states:
                if state and p not in known:
                    sf.ports.append(PortInfo(port=p, open=True, protocol="udp"))
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
                if progress:
                    scheme = 'https' if ssl else 'http'
                    progress(f"[dim]  → {sf.name}: fingerprinting {scheme} on port {p}…[/]")
                data = await fingerprint_http(sf.name, p, ssl, timeout=timeout, client=http_client)
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
    # Run active tasks for all subdomains when active_scan is requested (including anon via Tor)
    if active_scan:
        await asyncio.gather(*(_active(sf) for sf in subfindings))

    # Cleanup after all network work is complete
    if http_client:
        await http_client.aclose()
    if tor:
        tor.stop()

    return ScanResult(domain=domain, whois=whois_info, records=apex_records, subdomains=subfindings)


async def run_scan_ip(ip: str, outdir: Path, ports_preset: Optional[str], ports_list: Optional[str], concurrency: int, timeout: float, active_scan: bool, progress: Optional[Callable[[str], None]] = None, anon: bool = False) -> ScanResult:
    if progress:
        progress("Gathering reverse DNS (PTR) and passive IP intelligence…")
    settings = get_settings()
    tor: Optional[TorManager] = None
    socks_url = None
    http_client = None
    try:
        if anon:
            tor = TorManager()
            try:
                host, port = tor.start(progress)
                socks_url = f"socks5://{host}:{port}"
            except Exception as e:
                if progress:
                    progress(f"[warning] Could not start Tor: {e}")
                raise RuntimeError("--anon requested but Tor is not available/running. Install Tor or set TOR_EXE.")
        if socks_url:
            import httpx  # type: ignore[import]
            proxies = {"http://": socks_url, "https://": socks_url}
            http_client = httpx.AsyncClient(timeout=10.0, proxies=proxies)
        # PTR and ThreatCrowd
        ptrs = await ptr_lookup(ip, anon=anon, client=http_client)
        from .passive_sources import from_threatcrowd_ip
        tc = await from_threatcrowd_ip(ip, client=http_client)
        # Shodan host to extract hostnames and ports
        shodan = ShodanClient(settings.shodan_api_key, proxies={"http": socks_url, "https": socks_url} if socks_url else None)
        host = shodan.host_info(ip) if shodan.enabled() else None
        hostnames: List[str] = sorted(set(ptrs + tc + (host.get("hostnames") if isinstance(host, dict) else []) or []))
        # Build findings
        subs: List[SubdomainFinding] = []
        for hn in (hostnames or [ip]):
            name = hn if isinstance(hn, str) and hn else ip
            rec = DNSRecords(a=[ip], aaaa=[], cname=[], txt=[], mx=[], ns=[], srv=[])
            sf = SubdomainFinding(name=name, ips=[ip], dns=rec)
            # Shodan ports
            if isinstance(host, dict):
                for item in host.get("data", []) or []:
                    p = item.get("port")
                    if isinstance(p, int):
                        if p not in [pp.port for pp in sf.ports]:
                            sf.ports.append(PortInfo(port=p, open=True, service=item.get("product")))
                        http = item.get("http")
                        if http:
                            ssl = bool(item.get("ssl")) or p in (443, 8443)
                            scheme = "https" if ssl else "http"
                            key = f"{p}/{scheme}"
                            if key not in sf.http:
                                sf.http[key] = HTTPInfo(
                                    url=f"{scheme}://{name}:{p}",
                                    status=http.get("status") if isinstance(http.get("status"), int) else None,
                                    title=http.get("title"),
                                    server=http.get("server"),
                                    tech=[t for t in [http.get("server"), item.get("product")] if t],
                                )
            subs.append(sf)

        # Optionally active scan the IP (over Tor if anon)
        if active_scan:
            if progress:
                progress("Active scan enabled for IP: probing TCP ports and HTTP services…")
            from .ports import scan_ports, scan_udp_ports
            from .http_fingerprint import fingerprint_http
            tcp_ports: List[int] = []
            udp_ports: List[int] = []
            if ports_list:
                tcp_ports = _choose_ports(None, ports_list)
            elif ports_preset == "tcp":
                tcp_ports = list(range(1, 65536))
            elif ports_preset == "udp":
                udp_ports = list(range(1, 65536))
            elif ports_preset == "all":
                tcp_ports = list(range(1, 65536))
                udp_ports = list(range(1, 65536))
            else:
                tcp_ports = _choose_ports(ports_preset, None)
            socks_tuple = None
            if socks_url:
                try:
                    host_port = socks_url.split("://",1)[1]
                    sh, sp = host_port.split(":")
                    socks_tuple = (sh, int(sp))
                except Exception:
                    socks_tuple = None
            async def scan_sf(sf: SubdomainFinding):
                if tcp_ports:
                    if progress:
                        progress(f"[dim]  → {sf.name}: scanning {len(tcp_ports)} TCP ports…[/]")
                    results = await scan_ports(ip, tcp_ports, concurrency=concurrency, timeout=timeout, socks_proxy=socks_tuple)
                else:
                    results = []
                # UDP in anon mode is skipped
                udp_results: List[tuple[int, bool]] = []
                if udp_ports:
                    if anon:
                        if progress:
                            progress(f"[yellow]Skipping UDP scan for {sf.name} in anon mode (cannot route via Tor).[/]")
                    else:
                        if progress:
                            progress(f"[dim]  → {sf.name}: scanning {len(udp_ports)} UDP ports…[/]")
                        udp_results = await scan_udp_ports(ip, udp_ports, concurrency=concurrency, timeout=max(1.0, timeout/2))
                known = {p.port for p in sf.ports if p.open}
                for p, state in results:
                    if state and p not in known:
                        sf.ports.append(PortInfo(port=p, open=True, protocol="tcp"))
                for p, state in udp_results:
                    if state and p not in known:
                        sf.ports.append(PortInfo(port=p, open=True, protocol="udp"))
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
                    if progress:
                        scheme = 'https' if ssl else 'http'
                        progress(f"[dim]  → {sf.name}: fingerprinting {scheme} on port {p}…[/]")
                    data = await fingerprint_http(ip, p, ssl, timeout=timeout, client=http_client)
                    if data:
                        sf.http[key] = HTTPInfo(
                            url=data.get("url", f"http://{ip}:{p}"),
                            status=int(data["status"]) if data.get("status") and str(data["status"]).isdigit() else None,
                            title=data.get("title"),
                            server=data.get("server"),
                            favicon_hash=data.get("favicon_hash"),
                            tech=[t.strip() for t in (data.get("tech") or "").split(",") if t.strip()],
                        )
                await asyncio.gather(*(do_fp(p, ssl) for p, ssl in targets))
            await asyncio.gather(*(scan_sf(sf) for sf in subs))

        # Build result (treat IP as domain label)
        res = ScanResult(domain=ip, whois=WhoisInfo(), records=DNSRecords(a=[ip]), subdomains=subs)
        return res
    finally:
        if http_client:
            await http_client.aclose()
        if tor:
            tor.stop()


def scan_domain(
    domain: str,
    outdir: Optional[Path] = None,
    ports: Optional[str] = None,
    ports_list: Optional[str] = None,
    wordlist: Optional[Path] = None,
    bruteforce: bool = False,
    concurrency: int = 200,
    timeout: float = 5.0,
    write_json: bool = True,
    active: bool = False,
    progress: Optional[Callable[[str], None]] = None,
    anon: bool = False,
) -> Path:
    outdir = outdir or Path("reports") / f"{domain}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    project_root = Path(__file__).resolve().parents[2]
    tmpl_dir = project_root / "templates"
    # Prefer user-specified or repo data; otherwise fall back to packaged wordlist
    if wordlist is None:
        candidate = project_root / "data" / "subdomains-top.txt"
        wordlist = candidate if candidate.exists() else Path(__file__)  # dummy for typing
        if not candidate.exists():
            import importlib.resources as pkg_resources
            with pkg_resources.as_file(pkg_resources.files("enumtool.resources") / "subdomains-top.txt") as p:
                wordlist = Path(str(p))

    result = asyncio.run(run_scan(domain, outdir, ports, ports_list, wordlist, bruteforce, concurrency, timeout, active, progress, anon))
    # Render HTML
    if progress:
        progress("Rendering HTML report…")
    html = render_report(tmpl_dir, {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "result": result,
    })
    if progress:
        progress("Writing report files (HTML/JSON)…")
    path = write_report(outdir, html)

    if write_json:
        (outdir / "result.json").write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
    return path


def scan_ip(
    ip: str,
    outdir: Optional[Path] = None,
    ports: Optional[str] = None,
    ports_list: Optional[str] = None,
    concurrency: int = 200,
    timeout: float = 5.0,
    write_json: bool = True,
    active: bool = False,
    progress: Optional[Callable[[str], None]] = None,
    anon: bool = False,
) -> Path:
    outdir = outdir or Path("reports") / f"{ip}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    project_root = Path(__file__).resolve().parents[2]
    tmpl_dir = project_root / "templates"

    result = asyncio.run(run_scan_ip(ip, outdir, ports, ports_list, concurrency, timeout, active, progress, anon))
    if progress:
        progress("Rendering HTML report…")
    html = render_report(tmpl_dir, {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "result": result,
    })
    if progress:
        progress("Writing report files (HTML/JSON)…")
    path = write_report(outdir, html)
    if write_json:
        (outdir / "result.json").write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
    return path
