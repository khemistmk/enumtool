# EnumTool

A fast, concurrent domain enumerator and service fingerprinting tool. It analyzes a target domain, discovers subdomains, resolves DNS records, fetches WHOIS, gathers OSINT about subdomains, ports, and technologies from public sources (crt.sh, ThreatCrowd, Shodan) by default (no active probing), and optionally performs active probing when enabled, producing a clean HTML report (plus JSON).

## Features

- Subdomain discovery: DNS records, wordlist brute-force, and passive hints from TXT/MX/NS/CNAME.
- DNS resolution: A/AAAA/CNAME/TXT/MX/NS/SRV with fallback resolvers.
- WHOIS summary: Registrar, creation/expiry, name servers.
- Passive OSINT: crt.sh (CT logs), ThreatCrowd, Shodan (subdomains, observed open ports, tech hints).
- Optional active probing: TCP connect and HTTP fetch can be enabled with `--active`.
- Technology inference: Map headers/paths/content to frameworks and products.
- Output: Clean HTML report and machine-readable JSON.
- Concurrency: Async for network I/O with configurable limits.
- Friendly CLI: ASCII banner and stepwise progress logs during scanning and report generation.
 - Anonymous mode: `--anon` routes HTTP via Tor (SOCKS5 127.0.0.1:9050) and uses DNS-over-HTTPS; disables WHOIS and active probing.

## Quick start

1) Windows setup (installs Tor and deps):
	- Run scripts/setup.ps1 in an elevated PowerShell to install Tor Browser via winget, set TOR_EXE, create .venv, and install deps.
	- Open a new terminal to pick up TOR_EXE.

2) Linux/macOS setup:
	- Run scripts/setup.sh (requires sudo for package managers/brew). It installs Tor, sets TOR_EXE in your shell profile, creates .venv, and installs deps.

3) Manual setup:
	- Create and activate a virtual environment, then install dependencies from requirements.txt and pip install -e .

4) Run a scan and open the generated report.

## Usage

```
python -m enumtool <domain> [options]
```

Key options:
- `-o, --outdir` Output directory (default `reports/<domain>-<timestamp>`)
- OSINT-only by default (no active probing)
- `--active` Enable TCP/HTTP probing (optional)
- `--ports` Comma list or preset: `top100`, `web`, `full-small` (used only with --active)
- `--wordlist` Subdomain wordlist path (defaults to bundled list)
- `--bruteforce` Enable fast DNS brute-force (~1000 common names) in addition to passive sources
- `--max-workers` Concurrency level (default 200)
- `--timeout` Socket/HTTP timeout seconds (default 5)
- `--no-json` Skip writing JSON result (HTML is always written)
 - `--anon` Run via Tor + DoH (requires Tor running locally on 9050). Disables WHOIS and `--active`.
	- On Windows, `scripts/setup.ps1` installs Tor Browser and sets TOR_EXE so the tool can launch Tor automatically.

## API keys and environment
- Create a `.env` file (not committed) in the project root. Copy from `.env.example`.
- Supported variables:
	- `SHODAN_API_KEY=...`

## Notes
- Use responsibly and only against domains you have permission to test.
 - Anonymous mode requires a local Tor SOCKS proxy on 127.0.0.1:9050 (e.g., Tor Browser). Active probing is disabled in anon mode.

## License
MIT