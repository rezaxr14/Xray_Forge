"""Hysteria2 protocol handler (sing-box / mihomo — not supported by Xray-core)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, quote

from xray_forge.core.models import Outbound
from xray_forge.core.protocols.base import ProtocolHandler, hostport


class Hysteria2Handler(ProtocolHandler):
    name = "hysteria2"
    label = "Hysteria2"
    schemes = ("hysteria2", "hy2")
    default_transport = "udp"

    def to_uri(self, out: Outbound) -> str:
        scheme = "hysteria2"
        params: list[tuple[str, str]] = []
        if out.sni:
            params.append(("sni", out.sni))
        if out.allow_insecure:
            params.append(("insecure", "1"))
        ex = out.extra
        if ex.get("obfs"):
            params.append(("obfs", ex["obfs"]))
            if ex.get("obfs-password"):
                params.append(("obfs-password", ex["obfs-password"]))
        if ex.get("up"):
            params.append(("up", ex["up"]))
        if ex.get("down"):
            params.append(("down", ex["down"]))
        qs = ("?" + urlencode(params, quote_via=quote)) if params else ""
        name = quote(out.name or f"{out.host}:{out.port}", safe="")
        return f"{scheme}://{quote(out.credential, safe='')}@{hostport(out)}{qs}#{name}"
