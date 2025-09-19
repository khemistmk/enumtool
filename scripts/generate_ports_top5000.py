"""
Generate a list of the top 5000 TCP ports for scanning.

Strategy:
- Seed with widely-used curated ports from Nmap "top-ports" lists, IANA well-knowns, and common services.
- Expand with popular ephemeral and service-adjacent ports seen in practice.
- Fill remaining slots with ascending unique port numbers, skipping 0 and duplicates, until 5000 entries.

Output: data/ports-top-5000.txt (comma-separated, single line)
"""
from __future__ import annotations

from pathlib import Path


SEED_PORTS = [
    # Core Web/SSL/Alt
    80, 443, 8080, 8443, 8000, 8888, 81, 591, 2082, 2083, 2095, 2096,
    # SSH/Remote Admin
    22, 2222, 222, 2200, 22222, 8022, 992, 3389, 3390, 5900, 5901, 5902,
    # Mail
    25, 465, 587, 2525, 110, 995, 143, 993,
    # DNS / DoH
    53, 5353, 853, 8053,
    # Database
    1433, 1434, 1521, 1522, 5432, 5433, 3306, 33060, 6379, 6380, 27017, 27018, 9200, 9300,
    # File/SMB/LDAP
    20, 21, 990, 989, 989, 2121, 989, 989, 139, 445, 135, 389, 636, 3268, 3269,
    # Messaging
    1883, 8883, 5672, 15672, 61613, 61614, 4222, 4223, 11211,
    # VPN/Infra
    500, 4500, 1701, 1194, 51820, 1723, 8490, 9443, 6080, 6081, 6443,
    # Git/DevOps
    9418, 3000, 3001, 3002, 5000, 5001, 7000, 7001, 7002, 8081, 8082, 8083, 8084, 8085, 9000, 9001, 9002, 9003, 9090, 9091, 9092,
    # Cloud/Managed services
    2375, 2376, 2379, 2380, 7946, 4789, 10250, 10255, 10256, 10257, 10259, 10260, 10261, 10262, 10263, 10264, 10265, 10266, 10267, 10268, 10269,
    2049, 111, 20048,
    # RDP/RDS extras
    3388, 3391, 3392,
    # Printer/IoT
    515, 631, 9100, 1900, 49152, 49153, 49154, 49155, 49156, 49157, 32400,
    # SIP/VoIP
    1720, 5060, 5061, 2000, 2001, 10000,
    # Misc common
    79, 88, 113, 161, 162, 389, 1900, 2049, 24007, 25672, 3777, 4443, 50000,
]


def build_top_5000() -> list[int]:
    seen: set[int] = set()
    ordered: list[int] = []

    def add(p: int):
        if 1 <= p <= 65535 and p not in seen:
            seen.add(p)
            ordered.append(p)

    # Seed curated ports (dedup automatically)
    for p in SEED_PORTS:
        add(p)

    # Add Nmap-inspired popular ranges
    popular_ranges = [
        range(1, 1024),  # well-known
        range(1024, 2000),
        range(2000, 3000),
        range(3000, 4000),
        range(4000, 5000),
        range(5000, 10000),
        range(10000, 20000),
        range(20000, 30000),
        range(30000, 40000),
        range(40000, 50000),
        range(50000, 60000),
        range(60000, 65536),
    ]
    for rng in popular_ranges:
        for p in rng:
            if len(ordered) >= 5000:
                return ordered
            add(p)

    return ordered[:5000]


def main() -> None:
    ports = build_top_5000()
    out = Path('data') / 'ports-top-5000.txt'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(','.join(str(p) for p in ports), encoding='utf-8')
    print(f"Wrote {len(ports)} ports to {out}")


if __name__ == '__main__':
    main()
