"""
Core registry: Xray-core, sing-box, Mihomo adapters.

Usage::

    from xray_forge.core.cores import get_core, iter_cores, core_names
    xray = get_core("xray")
    xray.supported_protocols()          # {"vless", "vmess", "trojan", "ss", "wireguard"}
"""

from __future__ import annotations

from xray_forge.core.cores.base import CoreAdapter

_CORES: dict[str, CoreAdapter] = {}


def register(core: CoreAdapter) -> None:
    _CORES[core.name] = core


def get_core(name: str) -> CoreAdapter | None:
    return _CORES.get((name or "").lower())


def iter_cores() -> list[CoreAdapter]:
    return list(_CORES.values())


def core_names() -> list[str]:
    return list(_CORES.keys())


# --- self-register the built-in cores -----------------------------------
from xray_forge.core.cores.xray_core import XrayCore      # noqa: E402
from xray_forge.core.cores.singbox_core import SingboxCore  # noqa: E402
from xray_forge.core.cores.mihomo_core import MihomoCore    # noqa: E402

register(XrayCore())
register(SingboxCore())
register(MihomoCore())
