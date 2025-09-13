from __future__ import annotations

from typing import Dict, List, Optional, Tuple
import os
import time
import requests

SHODAN_API_BASE = "https://api.shodan.io"


class ShodanClient:
    def __init__(self, api_key: Optional[str], proxies: Optional[dict] = None):
        self.api_key = api_key
        self._proxies = proxies

    def enabled(self) -> bool:
        return bool(self.api_key)

    def _get(self, path: str, params: Optional[Dict[str, str]] = None) -> Optional[Dict]:
        if not self.enabled():
            return None
        url = f"{SHODAN_API_BASE}{path}"
        qp = {"key": self.api_key}
        if params:
            qp.update(params)
        try:
            r = requests.get(url, params=qp, timeout=10, proxies=self._proxies)
            if r.status_code == 429:
                # Simple one-shot backoff
                time.sleep(1)
                r = requests.get(url, params=qp, timeout=10, proxies=self._proxies)
            if r.ok:
                return r.json()
        except Exception:
            return None
        return None

    def domain_info(self, domain: str) -> Tuple[List[str], Dict[str, List[str]]]:
        """Return (subdomains, dns_records_by_type) via /dns/domain endpoint."""
        data = self._get(f"/dns/domain/{domain}")
        subs: List[str] = []
        records: Dict[str, List[str]] = {}
        if not data:
            return subs, records
        # subdomains list requires combining with domain
        for s in data.get("subdomains", []) or []:
            subs.append(f"{s}.{domain}")
        # Records present under 'data'
        for rec in data.get("data", []) or []:
            rtype = rec.get("type") or ""
            value = rec.get("value") or ""
            if not rtype or not value:
                continue
            records.setdefault(rtype, []).append(str(value))
        return sorted(set(subs)), records

    def host_info(self, ip: str) -> Optional[Dict]:
        """Return Shodan host info for an IP, including ports and service banners."""
        return self._get(f"/shodan/host/{ip}")
