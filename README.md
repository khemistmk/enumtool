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

## Quick start

1) Create and activate a virtual environment, then install dependencies.

2) Run a scan and open the generated report.

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

## API keys and environment
- Create a `.env` file (not committed) in the project root. Copy from `.env.example`.
- Supported variables:
	- `SHODAN_API_KEY=...`

## Notes
- Use responsibly and only against domains you have permission to test.

## License
MIT