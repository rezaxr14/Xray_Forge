"""sing-box adapter."""

from __future__ import annotations

from typing import Any

from xray_forge.core.models import Outbound
from xray_forge.core.protocols import handler_for
from xray_forge.core.cores.base import CoreAdapter


class SingboxCore(CoreAdapter):
    name = "singbox"
    display_name = "sing-box"
    config_suffix = ".json"
    run_args = ("run", "-c")

    def render_outbound(self, out: Outbound) -> dict[str, Any] | None:
        h = handler_for(out.scheme)
        if h is None:
            return None
        try:
            return h.singbox_outbound(out)
        except Exception:
            return None

    def build_client_config(self, outbounds: list[Outbound], socks_port: int,
                            frag_on: bool = False,
                            front_domain: str | None = None) -> dict[str, Any]:
        outs: list[dict[str, Any]] = []
        for out in outbounds:
            ob = self.render_outbound(out)
            if ob is not None:
                outs.append(ob)
        if not outs:
            raise ValueError("sing-box cannot run any of the given outbounds")
        outs.append({"type": "direct", "tag": "direct"})
        return {
            "log": {"level": "warn"},
            "inbounds": [{"type": "mixed", "tag": "mixed-in",
                          "listen": "127.0.0.1", "listen_port": socks_port}],
            "outbounds": outs,
        }
