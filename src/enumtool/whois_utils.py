from __future__ import annotations

from typing import Optional

try:
    import whois  # type: ignore
except Exception:  # pragma: no cover - optional dep resolution issues
    whois = None  # type: ignore


def fetch_whois(domain: str) -> dict:
    if whois is None:
        return {}
    try:
        data = whois.whois(domain)
        # Convert complex types to strings
        out = {}
        for k, v in data.items():
            if isinstance(v, (list, tuple)) and v:
                out[k] = str(v[0])
            else:
                out[k] = str(v) if v is not None else None
        return out
    except Exception:
        return {}
