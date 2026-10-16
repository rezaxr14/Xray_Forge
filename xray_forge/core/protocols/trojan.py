"""Trojan protocol handler (xray / sing-box / mihomo)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, quote

from xray_forge.core.models import Outbound
from xray_forge.core.protocols.base import (
    ProtocolHandler, hostport, xray_stream,
)


class TrojanHandler(ProtocolHandler):
    name = "trojan"
    label = "Trojan"
    schemes = ("trojan",)
    default_transport = "ws"

    def to_uri(self, out: Outbound) -> str:
        params: list[tuple[str, str]] = []
        if out.security:
            params.append(("security", out.security))
        if out.sni:
            params.append(("sni", out.sni))
        if out.fingerprint:
            params.append(("fp", out.fingerprint))
        params.append(("type", out.transport or "tcp"))
        if out.host_header:
            params.append(("host", out.host_header))
        if out.path and out.transport in ("ws", "httpupgrade", "xhttp"):
            params.append(("path", out.path))
        if out.service_name:
            params.append(("serviceName", out.service_name))
        if out.header_type:
            params.append(("headerType", out.header_type))
        if out.transport == "xhttp" and out.extra.get("mode"):
            params.append(("mode", out.extra["mode"]))
        if out.security == "reality":
            if out.public_key:
                params.append(("pbk", out.public_key))
            if out.short_id:
                params.append(("sid", out.short_id))
        if out.alpn:
            params.append(("alpn", out.alpn))
        if out.allow_insecure:
            params.append(("allowInsecure", "1"))
        qs = urlencode(params, quote_via=quote)
        name = quote(out.name or f"{out.host}:{out.port}", safe="")
        return f"trojan://{quote(out.credential, safe='')}@{hostport(out)}?{qs}#{name}"

    def xray_outbound(self, out: Outbound) -> dict[str, Any] | None:
        return {
            "protocol": "trojan",
            "settings": {"servers": [{
                "address": out.host,
                "port": int(out.port) if str(out.port).isdigit() else 443,
                "password": out.credential,
            }]},
        }

    def build_with_stream(self, out: Outbound, frag_on: bool = False,
                          front_domain: str | None = None) -> dict[str, Any]:
        ob = self.xray_outbound(out)
        if ob is None:
            return None
        ob["tag"] = "proxy"
        ob["streamSettings"] = xray_stream(out, frag_on, front_domain)
        return ob
