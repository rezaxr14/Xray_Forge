"""
Config deduplication.

Removes duplicate proxy configurations based on (scheme, uuid, host, port)
so the user's list stays clean.
"""

from __future__ import annotations

from typing import Any
from xray_forge.core.parser import parse_target


def dedup_configs(lines: list[str]) -> tuple[list[str], int]:
    """Return (deduplicated_lines, removed_count)."""
    seen: set[tuple[str, str, str, str]] = set()
    out: list[str] = []
    removed = 0
    for line in lines:
        t = parse_target(line)
        if not t:
            out.append(line)
            continue
        key = (t["scheme"], t["uuid"], t["host"], t["port"])
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        out.append(line)
    return out, removed
