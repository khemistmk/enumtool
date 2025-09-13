from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from .scan import scan_domain


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="EnumTool - domain enumeration and fingerprinting")
    p.add_argument("domain", help="Target domain, e.g. example.com")
    p.add_argument("-o", "--outdir", type=Path, help="Output directory (default: reports/<domain>-<timestamp>)")
    p.add_argument("--ports", choices=["web", "top100", "full-small"], help="Port preset (used only with --active)")
    p.add_argument("--ports-list", help="Explicit comma-separated ports (overrides preset; used only with --active)")
    p.add_argument("--wordlist", type=Path, help="Subdomain wordlist path")
    p.add_argument("--bruteforce", action="store_true", help="Enable DNS bruteforce of top ~1000 common subdomains (passive sources are used regardless)")
    p.add_argument("--max-workers", type=int, default=200, help="Concurrency level (default: 200)")
    p.add_argument("--timeout", type=float, default=5.0, help="Timeout seconds (default: 5)")
    p.add_argument("--active", action="store_true", help="Enable active probing (TCP connect/HTTP). Default is passive OSINT only.")
    p.add_argument("--anon", action="store_true", help="Route requests via Tor (SOCKS5 127.0.0.1:9050) and use DoH; disables WHOIS and active probing.")
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
 """
    console.print(banner, style="cyan")
    if args.anon and args.active:
        console.print("[yellow]--anon enabled: disabling --active (active probing is not supported over Tor).[/]")
        args.active = False
    mode = "ANON" if args.anon else ("ACTIVE" if args.active else "PASSIVE")
    console.print(f"[bold]EnumTool[/] starting {mode} scan for [yellow]{args.domain}[/]\n")

    def progress(msg: str) -> None:
        console.print(f"[cyan]»[/] {msg}")
    report = scan_domain(
        domain=args.domain,
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
    console.print(f"Report written to: [green]{report}[/]")


if __name__ == "__main__":
    main()
