"""Engine methods for the opt-in MASQUE path (the sing-box-extended fork)."""

from __future__ import annotations

import json
import os
from typing import Any

from xray_forge.core import masque
from xray_forge.core.cores import discover
from xray_forge.engine.rpc import Dispatcher, invalid_params, seconds

SLOT = "singbox_extended"
T_MIN, T_MAX = 0.2, 120.0
START_MIN, START_MAX = 1.0, 300.0


def _status() -> dict[str, Any]:
    path, source = discover.find(SLOT)
    out: dict[str, Any] = {"path": path, "source": source, "configured": discover.configured_path(SLOT),
                           "found": bool(path), "version": "", "ok": False,
                           "supported": False, "detail": ""}
    if not path:
        out["detail"] = "sing-box-extended not found; set its path"
        return out
    out["ok"], out["version"] = discover.version(SLOT, path)
    sup = masque.check_support(path)
    out["supported"], out["detail"] = sup["supported"], sup["detail"]
    return out


def _options(params: Any) -> masque.MasqueOptions:
    try:
        return masque.MasqueOptions.from_params(params)
    except (ValueError, TypeError) as e:
        raise invalid_params(str(e)) from None


def register(d: Dispatcher, jobs) -> None:
    @d.method("masque.status")
    def masque_status() -> dict:
        return _status()

    @d.method("masque.set_path")
    def masque_set_path(path: Any = "") -> dict:
        """Remember the sing-box-extended executable ("" clears it)."""
        if not isinstance(path, str):
            raise invalid_params("path must be a string")
        path = path.strip()
        if path:
            if not os.path.isabs(path):
                raise invalid_params("path must be absolute")
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                raise invalid_params("not an executable file")
            ok, text = discover.version(SLOT, path)
            if not ok:
                raise invalid_params(f"sing-box-extended did not answer its version command: {text}")
        discover.save_path(SLOT, path)
        return _status()

    @d.method("masque.config")
    def masque_config(options: Any = None, socks_port: Any = 1080, include_secrets: Any = False) -> dict:
        """The client config as JSON; credentials are ``***`` unless asked for."""
        opts = _options(options)
        if isinstance(socks_port, bool) or not isinstance(socks_port, int) or not 1 <= socks_port <= 65535:
            raise invalid_params("socks_port must be 1..65535")
        if not isinstance(include_secrets, bool):
            raise invalid_params("include_secrets must be true or false")
        cfg = masque.build_client_config(opts, socks_port)
        if not include_secrets:
            cfg = masque.redact(cfg)
        return {"content": json.dumps(cfg, indent=2), "redacted": not include_secrets}

    @d.method("masque.probe")
    def masque_probe(options: Any = None, timeout: Any = 8, start_timeout: Any = 60) -> dict:
        """Start the fork with a MASQUE outbound and fetch a page through it (a job)."""
        opts = _options(options)
        t = seconds(timeout, "timeout", T_MIN, T_MAX)
        st = seconds(start_timeout, "start_timeout", START_MIN, START_MAX)
        binary = discover.find_binary(SLOT)
        if not binary:
            raise invalid_params("sing-box-extended not found; set its path with masque.set_path")

        def run(ctx) -> dict:
            r = masque.probe(binary, opts, timeout=t, start_timeout=st, stop=ctx.stop)
            ctx.item(r)
            return r
        return {"job": jobs.start("masque.probe", run)}
