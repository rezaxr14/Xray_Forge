"""WireGuard / WARP protocol handler (xray / sing-box / mihomo).

WireGuard has no share-link form.  Outbounds are built from WARP accounts
(see :mod:`xray_forge.core.warp`) carried in ``out.extra``:

    private_key       client WireGuard secret key (base64)
    peer_public_key   server public key (base64)
    ipv4 / ipv6       assigned tunnel addresses (CIDR)
    client_id         WARP client id (hex) — becomes the ``reserved`` field
    mtu               default 1280
"""

from __future__ import annotations

from typing import Any

from xray_forge.core.models import Outbound
from xray_forge.core.protocols.base import ProtocolHandler


def _reserved(ex: dict) -> list[int]:
    """WARP reserved bytes from client_id hex (fallback 0,0,0)."""
    cid = ex.get("client_id", "")
    try:
        b = bytes.fromhex(cid)
        if len(b) == 3:
            return list(b)
    except ValueError:
        pass
    return [0, 0, 0]


class WireGuardHandler(ProtocolHandler):
    name = "wireguard"
    label = "WireGuard / WARP"
    schemes = ("wireguard", "wg")
    default_transport = "udp"

    def to_uri(self, out: Outbound) -> str:
        raise NotImplementedError("WireGuard has no share-link form")

    def xray_outbound(self, out: Outbound) -> dict[str, Any] | None:
        ex = out.extra
        peer = {
            "publicKey": ex.get("peer_public_key", ""),
            "allowedIPs": ["0.0.0.0/0", "::/0"],
            "endpoint": out.endpoint,
        }
        if ex.get("pre_shared_key"):
            peer["preSharedKey"] = ex["pre_shared_key"]
        return {
            "protocol": "wireguard",
            "settings": {
                "secretKey": ex.get("private_key", ""),
                "address": [a for a in (ex.get("ipv4"), ex.get("ipv6")) if a],
                "peers": [peer],
                "mtu": int(ex.get("mtu", 1280)),
                "reserved": _reserved(ex),
            },
        }

    # sing-box / clash renderers come from parser.out_to_singbox / out_to_clash
    def singbox_outbound(self, out: Outbound) -> dict[str, Any] | None:
        ex = out.extra
        local = [a for a in (ex.get("ipv4"), ex.get("ipv6")) if a] or ["172.16.0.2/32"]
        ob: dict[str, Any] = {
            "type": "wireguard",
            "tag": out.name or "warp",
            "server": out.host,
            "server_port": int(out.port) if str(out.port).isdigit() else 2408,
            "local_address": local,
            "private_key": ex.get("private_key", ""),
            "peer_public_key": ex.get("peer_public_key", ""),
            "reserved": _reserved(ex),
            "mtu": int(ex.get("mtu", 1280)),
        }
        return ob

    def clash_proxy(self, out: Outbound) -> dict[str, Any] | None:
        ex = out.extra
        proxy: dict[str, Any] = {
            "name": out.name or "WARP",
            "type": "wireguard",
            "server": out.host,
            "port": int(out.port) if str(out.port).isdigit() else 2408,
            "ip": (ex.get("ipv4") or "172.16.0.2/32").split("/")[0],
            "private-key": ex.get("private_key", ""),
            "public-key": ex.get("peer_public_key", ""),
            "mtu": int(ex.get("mtu", 1280)),
            "reserved": _reserved(ex),
        }
        if ex.get("ipv6"):
            proxy["ipv6"] = ex["ipv6"].split("/")[0]
        return proxy
