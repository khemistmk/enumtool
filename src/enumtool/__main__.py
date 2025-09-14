from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from . import __version__

from .scan import scan_domain, scan_ip


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="EnumTool - domain enumeration and fingerprinting")
    p.add_argument("target", help="Target domain (default) or IP when used with --ip")
    p.add_argument("--ip", dest="is_ip", action="store_true", help="Interpret target as an IP address and run IP-centric scan")
    p.add_argument("-o", "--outdir", type=Path, help="Output directory (default: reports/<domain>-<timestamp>)")
    p.add_argument("--ports", choices=["web", "top100", "full-small", "tcp", "udp", "all"], help="Port preset (used only with --active). Use 'tcp' for all TCP ports, 'udp' for all UDP ports, or 'all' for both (very slow)")
    p.add_argument("--ports-list", help="Explicit comma-separated ports (overrides preset; used only with --active)")
    p.add_argument("--wordlist", type=Path, help="Subdomain wordlist path")
    p.add_argument("--bruteforce", action="store_true", help="Enable DNS bruteforce of top ~1000 common subdomains (passive sources are used regardless)")
    p.add_argument("--max-workers", type=int, default=200, help="Concurrency level (default: 200)")
    p.add_argument("--timeout", type=float, default=5.0, help="Timeout seconds (default: 5)")
    p.add_argument("--active", action="store_true", help="Enable active probing (TCP connect/HTTP). Default is passive OSINT only.")
    p.add_argument("--anon", action="store_true", help="Route requests via Tor and use DoH; disables WHOIS; active probing, if enabled, runs over Tor.")
    p.add_argument("--no-json", action="store_true", help="Do not write JSON output")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    console = Console()
    # ASCII banner
    banner = r"""
  ___              _____         _ 
 | __|_ _ _  _ _ _|_   _|__  ___| |
 | _|| ' \ || | '  \| |/ _ \/ _ \ |
 |___|_||_\_,_|_|_|_|_|\___/\___/_|
   Domain and IP enumeration tool
 v1.1 by Timothy Wilson (@khemistmk)
 """
    console.print(banner, style="cyan")
    console.print(f"[dim]Version {__version__}[/]")
    if args.anon and args.active:
        console.print("[yellow]--anon + --active: active probing will run over Tor.[/]")
    mode = "ANON" if args.anon else ("ACTIVE" if args.active else "PASSIVE")
    target_label = args.target
    console.print(f"[bold]EnumTool[/] starting {mode} {'IP' if args.is_ip else 'scan'} for [yellow]{target_label}[/]\n")

    def progress(msg: str) -> None:
        console.print(f"[cyan]»[/] {msg}")
    try:
        if args.is_ip:
            report = scan_ip(
                ip=args.target,
                outdir=args.outdir,
                ports=args.ports,
                ports_list=args.ports_list,
                concurrency=args.max_workers,
                timeout=args.timeout,
                write_json=not args.no_json,
                active=args.active,
                progress=progress,
                anon=args.anon,
            )
        else:
            report = scan_domain(
            domain=args.target,
            outdir=args.outdir,
            ports=args.ports,
            ports_list=args.ports_list,
            wordlist=args.wordlist,
            concurrency=args.max_workers,
            timeout=args.timeout,
            write_json=not args.no_json,
            active=args.active,
            bruteforce=args.bruteforce,
            progress=progress,
            anon=args.anon,
            )
    except RuntimeError as e:
        console.print(f"[red]Error:[/] {e}")
        raise SystemExit(2)
    console.print(f"Report written to: [green]{report}[/]")


if __name__ == "__main__":
    main()
