"""Xray-core adapter: config building (pure, no subprocess) + capabilities."""

from __future__ import annotations

from typing import Any

from xray_forge.core.models import Outbound
from xray_forge.core.protocols import handler_for
from xray_forge.core.protocols.base import xray_stream
from xray_forge.core.cores.base import CoreAdapter


class XrayCore(CoreAdapter):
    name = "xray"
    display_name = "Xray-core"
    config_suffix = ".json"
    run_args = ("run", "-c")

    def render_outbound(self, out: Outbound) -> dict[str, Any] | None:
        h = handler_for(out.scheme)
        if h is None:
            return None
        try:
            return h.xray_outbound(out)
        except Exception:
            return None

    def build_outbound(self, out: Outbound, frag_on: bool = False,
                       front_domain: str | None = None) -> dict[str, Any] | None:
        """Full tagged outbound object incl. streamSettings (or None)."""
        h = handler_for(out.scheme)
        if h is None:
            return None
        ob = h.xray_outbound(out)
        if ob is None:
            return None
        ob["tag"] = "proxy"
        ob["streamSettings"] = xray_stream(out, frag_on, front_domain)
        return ob

    def build_client_config(self, outbounds: list[Outbound], socks_port: int,
                            frag_on: bool = False,
                            front_domain: str | None = None) -> dict[str, Any]:
        outs: list[dict[str, Any]] = []
        for out in outbounds:
            ob = self.build_outbound(out, frag_on, front_domain)
            if ob is not None:
                outs.append(ob)
        if not outs:
            raise ValueError("xray cannot run any of the given outbounds")
        if frag_on and any(o.is_tls() for o in outbounds):
            outs.append({"tag": "frag", "protocol": "freedom",
                         "settings": {"fragment": {"packets": "tlshello",
                                                   "length": "5-94",
                                                   "interval": "1"}}})
        outs.append({"tag": "direct", "protocol": "freedom"})
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{"tag": "socks", "protocol": "socks",
                          "listen": "127.0.0.1", "port": socks_port,
                          "settings": {"udp": False}}],
            "outbounds": outs,
        }
