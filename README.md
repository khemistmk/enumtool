# EnumTool

A fast, concurrent domain enumerator and service fingerprinting tool. It analyzes a target domain, discovers subdomains, resolves DNS records, fetches WHOIS, scans common ports, fingerprints HTTP services, infers technologies, and outputs a well-formatted HTML report (plus JSON).

## Features

- Subdomain discovery: DNS records, wordlist brute-force, and passive hints from TXT/MX/NS/CNAME.
- DNS resolution: A/AAAA/CNAME/TXT/MX/NS/SRV with fallback resolvers.
- WHOIS summary: Registrar, creation/expiry, name servers.
- Port scan (selected ports): TCP connect scan with timeouts.
- HTTP fingerprinting: Status, title, server headers, TLS, favicon hash, tech hints.
- Technology inference: Map headers/paths/content to frameworks and products.
- Output: Clean HTML report and machine-readable JSON.
- Concurrency: Async for network I/O with configurable limits.

## Quick start

1) Create and activate a virtual environment, then install dependencies.

2) Run a scan and open the generated report.

## Usage

```
python -m enumtool <domain> [options]
```

Key options:
- `-o, --outdir` Output directory (default `reports/<domain>-<timestamp>`)
- `--ports` Comma list or preset: `top100`, `web`, `full-small`
- `--wordlist` Subdomain wordlist path (defaults to bundled list)
- `--max-workers` Concurrency level (default 200)
- `--timeout` Socket/HTTP timeout seconds (default 5)
- `--json` Also write JSON result

## Notes
- Use responsibly and only against domains you have permission to test.

## License
MIT