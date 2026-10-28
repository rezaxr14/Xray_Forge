"""VMess protocol handler (xray / sing-box / mihomo)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode, quote

from xray_forge.core.models import Outbound, b64_encode
from xray_forge.core.protocols.base import (
    ProtocolHandler, hostport, xray_stream,
)


class VmessHandler(ProtocolHandler):
    name = "vmess"
    label = "VMess"
    schemes = ("vmess",)
    default_transport = "ws"

    def to_uri(self, out: Outbound) -> str:
        payload = {
            "v": "2",
            "ps": out.name,
            "add": out.host,
            "port": out.port,
            "id": out.credential,
            "aid": out.alter_id or "0",
            "scy": out.encryption or "auto",
            "net": out.transport or "tcp",
            "type": out.header_type or "none",
            "host": out.host_header,
            "path": out.path,
            "tls": "tls" if out.is_tls() else "",
            "sni": out.sni,
            "alpn": out.alpn,
            "fp": out.fingerprint,
        }
        for k, v in (out.extra_params or {}).items():
            payload.setdefault(k, v)          # keep unmodeled JSON keys
        return "vmess://" + b64_encode(json.dumps(payload, ensure_ascii=False))

    def xray_outbound(self, out: Outbound) -> dict[str, Any] | None:
        try:
            aid = int(out.alter_id)
        except (TypeError, ValueError):
            aid = 0
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": out.host,
                "port": int(out.port) if str(out.port).isdigit() else 443,
                "users": [{"id": out.credential,
                           "alterId": aid,
                           "security": out.encryption or "auto"}],
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
