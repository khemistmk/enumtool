from __future__ import annotations

from typing import Iterable, List


def merge_tech_hints(*hint_groups: Iterable[str]) -> List[str]:
    out = set()
    for g in hint_groups:
        for h in g:
            if not h:
                continue
            out.add(h)
    return sorted(out)
