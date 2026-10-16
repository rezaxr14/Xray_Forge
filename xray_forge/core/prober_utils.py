"""
Shared formatting helpers used by tester, scanner, and exporters.
"""

from __future__ import annotations


def fmt_ms(v):
    if isinstance(v, (int, float)):
        return f"{v:.0f}"
    if isinstance(v, str) and v.strip() not in ("", "—"):
        return v
    return "—"


def cc_cell(cc, edge):
    if not cc:
        return ""
    return f"{cc_flag(cc)} {cc}{'*' if edge else ''}"


def cc_flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c.upper()) - 65) for c in cc)
