"""TUIC protocol handler (sing-box / mihomo — not supported by Xray-core)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, quote

from xray_forge.core.models import Outbound
from xray_forge.core.protocols.base import ProtocolHandler, append_extra_params, hostport


class TuicHandler(ProtocolHandler):
    name = "tuic"
    label = "TUIC"
    schemes = ("tuic",)
    default_transport = "udp"

    def to_uri(self, out: Outbound) -> str:
        params: list[tuple[str, str]] = []
        if out.sni:
            params.append(("sni", out.sni))
        if out.alpn:
            params.append(("alpn", out.alpn))
        ex = out.extra
        if ex.get("congestion_control"):
            params.append(("congestion_control", ex["congestion_control"]))
        if ex.get("udp_relay_mode"):
            params.append(("udp_relay_mode", ex["udp_relay_mode"]))
        if out.allow_insecure:
            params.append(("insecure", "1"))
        params = append_extra_params(params, out)
        qs = ("?" + urlencode(params, quote_via=quote)) if params else ""
        user, _, pwd = out.credential.partition(":")
        password = ex.get("password", "") or pwd
        auth = f"{quote(user, safe='')}:{quote(password, safe='')}" if password \
            else quote(user, safe="")
        name = quote(out.name or f"{out.host}:{out.port}", safe="")
        return f"tuic://{auth}@{hostport(out)}{qs}#{name}"
