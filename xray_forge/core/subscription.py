"""
Remote subscription fetcher.

Downloads subscription links (base64 or plain text) and returns a list of
raw config lines. Handles HTTP/HTTPS with anti-DPI direct connect fallback.
"""

import base64
import re

from xray_forge.core.probe import direct_get_json, ProbeError


def is_base64_config(text: str) -> bool:
    """Heuristic: text looks like a base64-encoded subscription."""
    stripped = text.strip()
    if not stripped:
        return False
    # Remove whitespace/newlines
    compact = re.sub(r"\s+", "", stripped)
    if len(compact) < 16:
        return False
    # Must be valid base64 alphabet
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return False
    # Try decode — if it yields proxy:// URIs, treat as base64 sub
    try:
        padded = compact + "=" * (-len(compact) % 4)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8", "replace")
    except Exception:
        return False
    return any(
        decoded.startswith(scheme + "://")
        for scheme in ("vless", "trojan", "vmess", "ss", "socks", "http")
    ) or "vless://" in decoded or "trojan://" in decoded


def decode_subscription(text: str) -> list[str]:
    """Decode a subscription text (base64 or plain) into config lines."""
    text = text.strip()
    if not text:
        return []
    if is_base64_config(text):
        compact = re.sub(r"\s+", "", text)
        padded = compact + "=" * (-len(compact) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode("utf-8", "replace")
        except Exception:
            decoded = text
    else:
        decoded = text
    lines: list[str] = []
    for raw in decoded.splitlines():
        line = raw.strip()
        if line and ("://" in line):
            lines.append(line)
    return lines


def fetch_subscription(url: str, timeout: float = 10.0) -> list[str]:
    """Fetch a subscription URL and return decoded config lines."""
    try:
        # Try anti-DPI direct fetch first
        data = direct_get_json(url, timeout=timeout)
        text = data if isinstance(data, str) else str(data)
    except Exception:
        try:
            import urllib.request
            req = urllib.request.Request(
                url, headers={"User-Agent": "vless-forge/2.0-subscriber"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                text = r.read().decode("utf-8", "replace")
        except Exception as e:
            raise ProbeError("sub", f"cannot fetch subscription: {e}")
    return decode_subscription(text)
