"""Mihomo (Clash.Meta) adapter."""

from __future__ import annotations

from typing import Any

from xray_forge.core.models import Outbound
from xray_forge.core.protocols import handler_for
from xray_forge.core.cores.base import CoreAdapter


class MihomoCore(CoreAdapter):
    name = "mihomo"
    display_name = "Mihomo (Clash.Meta)"
    config_suffix = ".yaml"
    run_args = ("-f",)

    def render_outbound(self, out: Outbound) -> dict[str, Any] | None:
        h = handler_for(out.scheme)
        if h is None:
            return None
        try:
            return h.clash_proxy(out)
        except Exception:
            return None

    def build_client_config(self, outbounds: list[Outbound], socks_port: int,
                            frag_on: bool = False,
                            front_domain: str | None = None) -> dict[str, Any]:
        proxies: list[dict[str, Any]] = []
        for out in outbounds:
            px = self.render_outbound(out)
            if px is not None:
                proxies.append(px)
        if not proxies:
            raise ValueError("mihomo cannot run any of the given outbounds")
        return {
            "mixed-port": socks_port,
            "mode": "global",
            "log-level": "warning",
            "proxies": proxies,
            "proxy-groups": [{
                "name": "FORGE",
                "type": "select",
                "proxies": [p["name"] for p in proxies],
            }],
            "rules": ["MATCH,FORGE"],
        }
