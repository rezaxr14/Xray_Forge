"""Psiphon through a user-supplied ``ConsoleClient`` binary and config file.

Xray Forge ships no Psiphon binary and no Psiphon Labs values (propagation
channel, sponsor, server-list keys): the user points at their own, exactly as
for the other cores.  The client is run as a separate process (so Psiphon's
GPL-3.0 licence does not apply to this project) with a private rewritten copy
of the config whose local ports and data directory are ours.
"""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
from typing import Any

from xray_forge.core import settings as _settings
from xray_forge.core.cores.base import CoreAdapter, _free_port, run_socks_probe
from xray_forge.core.log import get_logger

log = get_logger(__name__)

MAX_CONFIG = 1024 * 1024
REQUIRED = ("PropagationChannelId", "SponsorId")


def load_config(path: str) -> dict[str, Any]:
    """Read and sanity-check the user's config; values are never logged."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_CONFIG + 1)
    except OSError as e:
        raise ValueError(f"cannot read config: {type(e).__name__}") from None
    if len(raw) > MAX_CONFIG:
        raise ValueError("config is too large")
    try:
        cfg = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("config is not valid JSON") from None
    if not isinstance(cfg, dict):
        raise ValueError("config must be a JSON object")
    for key in REQUIRED:
        if not isinstance(cfg.get(key), str) or not cfg[key]:
            raise ValueError(f"config needs a {key} (from Psiphon Labs)")
    return cfg


def run_config(cfg: dict[str, Any], socks_port: int, http_port: int, data_dir: str) -> dict[str, Any]:
    out = copy.deepcopy(cfg)
    out["LocalSocksProxyPort"] = socks_port
    out["LocalHttpProxyPort"] = http_port
    out["DataRootDirectory"] = data_dir
    return out


class _Console(CoreAdapter):
    name = "psiphon"
    display_name = "Psiphon"
    config_suffix = ".json"
    run_args = ("-config",)


def configured_config() -> str:
    value = _settings.load_settings().get("psiphon_config", "")
    return value if isinstance(value, str) else ""


def save_config(path: str) -> None:
    data = _settings.load_settings()
    if path:
        data["psiphon_config"] = path
    else:
        data.pop("psiphon_config", None)
    _settings.save_settings(data)


def probe(binary: str, config_path: str, timeout: float = 8.0, start_timeout: float = 120.0,
          stop=None) -> dict[str, Any]:
    """Connect with the user's config and fetch a page through the local SOCKS port.

    ``start_timeout`` is long because Psiphon may need to fetch server lists first.
    Raises ``ValueError`` (before any process starts) when the config is unusable."""
    cfg = load_config(config_path)
    data_dir = tempfile.mkdtemp(prefix="xf-psiphon-")
    try:
        socks, http = _free_port(), _free_port()
        while http == socks:
            http = _free_port()
        return run_socks_probe(_Console(), binary, run_config(cfg, socks, http, data_dir), socks,
                               timeout=timeout, start_timeout=start_timeout, stop=stop)
    finally:
        shutil.rmtree(data_dir, ignore_errors=True)
