"""Shadowsocks protocol handler (xray / sing-box / mihomo)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, quote

from xray_forge.core.models import Outbound, b64_encode
from xray_forge.core.protocols.base import ProtocolHandler, append_extra_params, hostport


class ShadowsocksHandler(ProtocolHandler):
    name = "ss"
    label = "Shadowsocks"
    schemes = ("ss",)
    default_transport = "tcp"

    def to_uri(self, out: Outbound) -> str:
        method, password = out.ss_split()
        # SIP002: base64url(method:password)@host:port
        userinfo = b64_encode(f"{method}:{password}", urlsafe=True).rstrip("=")
        params: list[tuple[str, str]] = []
        plugin = out.extra.get("plugin")
        if plugin:
            params.append(("plugin", plugin))
        params = append_extra_params(params, out)
        qs = ("?" + urlencode(params, quote_via=quote)) if params else ""
        name = quote(out.name or f"{out.host}:{out.port}", safe="")
        return f"ss://{userinfo}@{hostport(out)}{qs}#{name}"

    def xray_outbound(self, out: Outbound) -> dict[str, Any] | None:
        method, password = out.ss_split()
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": out.host,
                "port": int(out.port) if str(out.port).isdigit() else 443,
                "method": method,
                "password": password,
            }]},
        }
