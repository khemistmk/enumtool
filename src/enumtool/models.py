from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DNSRecords:
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    cname: List[str] = field(default_factory=list)
    txt: List[str] = field(default_factory=list)
    mx: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    srv: List[str] = field(default_factory=list)


@dataclass
class PortInfo:
    port: int
    open: bool
    service: Optional[str] = None
    banner: Optional[str] = None
    tls: Optional[bool] = None


@dataclass
class HTTPInfo:
    url: str
    status: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    tech: List[str] = field(default_factory=list)
    favicon_hash: Optional[str] = None
    redirects: List[str] = field(default_factory=list)


@dataclass
class SubdomainFinding:
    name: str
    ips: List[str] = field(default_factory=list)
    dns: DNSRecords = field(default_factory=DNSRecords)
    ports: List[PortInfo] = field(default_factory=list)
    http: Dict[str, HTTPInfo] = field(default_factory=dict)
    tech: List[str] = field(default_factory=list)


@dataclass
class WhoisInfo:
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    domain: str
    whois: WhoisInfo
    records: DNSRecords
    subdomains: List[SubdomainFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
