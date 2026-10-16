"""
Protocol registry.

Usage::

    from xray_forge.core.protocols import handler_for, iter_handlers, supported_schemes

    h = handler_for("vless")          # VlessHandler instance
    h.parse(uri) -> Outbound | None
    h.to_uri(outbound) -> str
    h.xray_outbound(outbound) -> dict | None
"""

from __future__ import annotations

from xray_forge.core.protocols.base import ProtocolHandler

_HANDLERS: dict[str, ProtocolHandler] = {}
_HANDLER_INSTANCES: list[ProtocolHandler] = []


def register(handler: ProtocolHandler) -> None:
    if handler not in _HANDLER_INSTANCES:
        _HANDLER_INSTANCES.append(handler)
    for scheme in handler.schemes:
        _HANDLERS[scheme.lower()] = handler


def handler_for(scheme: str) -> ProtocolHandler | None:
    return _HANDLERS.get((scheme or "").lower())


def iter_handlers() -> list[ProtocolHandler]:
    return list(_HANDLER_INSTANCES)


def supported_schemes() -> set[str]:
    return set(_HANDLERS.keys())


def parse_any(line: str):
    """Try every handler; returns (handler, Outbound) or (None, None)."""
    for h in _HANDLER_INSTANCES:
        out = h.parse(line)
        if out:
            return h, out
    return None, None


# --- self-register the built-in protocols ------------------------------
from xray_forge.core.protocols.vless import VlessHandler            # noqa: E402
from xray_forge.core.protocols.vmess import VmessHandler            # noqa: E402
from xray_forge.core.protocols.trojan import TrojanHandler          # noqa: E402
from xray_forge.core.protocols.shadowsocks import ShadowsocksHandler  # noqa: E402
from xray_forge.core.protocols.hysteria2 import Hysteria2Handler    # noqa: E402
from xray_forge.core.protocols.tuic import TuicHandler              # noqa: E402
from xray_forge.core.protocols.wireguard import WireGuardHandler    # noqa: E402

register(VlessHandler())
register(VmessHandler())
register(TrojanHandler())
register(ShadowsocksHandler())
register(Hysteria2Handler())
register(TuicHandler())
register(WireGuardHandler())
