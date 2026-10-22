"""Engine methods for Psiphon (user-supplied ConsoleClient binary and config)."""

from __future__ import annotations

import os
from typing import Any

from xray_forge.core import psiphon
from xray_forge.core.cores import discover
from xray_forge.engine.rpc import Dispatcher, invalid_params, seconds

SLOT = "psiphon"


def _status() -> dict[str, Any]:
    path, source = discover.find(SLOT)
    out: dict[str, Any] = {"path": path, "source": source, "configured": discover.configured_path(SLOT),
                           "found": bool(path), "version": "", "ok": False,
                           "config_path": psiphon.configured_config(), "config_ok": False, "detail": ""}
    if path:
        out["ok"], out["version"] = discover.version(SLOT, path)
    else:
        out["detail"] = "Psiphon ConsoleClient not found; set its path"
    if out["config_path"]:
        try:
            psiphon.load_config(out["config_path"])
            out["config_ok"] = True
        except ValueError as e:
            out["detail"] = (out["detail"] + "; " if out["detail"] else "") + str(e)
    elif not out["detail"]:
        out["detail"] = "no Psiphon config set"
    return out


def _abs_file(path: Any, what: str) -> str:
    if not isinstance(path, str):
        raise invalid_params("path must be a string")
    path = path.strip()
    if path:
        if not os.path.isabs(path):
            raise invalid_params("path must be absolute")
        if not os.path.isfile(path):
            raise invalid_params(f"{what} not found")
    return path


def register(d: Dispatcher, jobs) -> None:
    @d.method("psiphon.status")
    def psiphon_status() -> dict:
        return _status()

    @d.method("psiphon.set_path")
    def psiphon_set_path(path: Any = "") -> dict:
        """Remember the ConsoleClient executable ("" clears). Its version command is informational only."""
        path = _abs_file(path, "file")
        if path and not os.access(path, os.X_OK):
            raise invalid_params("not an executable file")
        discover.save_path(SLOT, path)
        return _status()

    @d.method("psiphon.set_config")
    def psiphon_set_config(path: Any = "") -> dict:
        """Remember the user's Psiphon config file ("" clears). Values are never returned."""
        path = _abs_file(path, "file")
        if path:
            try:
                psiphon.load_config(path)
            except ValueError as e:
                raise invalid_params(str(e)) from None
        psiphon.save_config(path)
        return _status()

    @d.method("psiphon.probe")
    def psiphon_probe(timeout: Any = 8, start_timeout: Any = 120) -> dict:
        """Connect and fetch a page through the tunnel (a job)."""
        t = seconds(timeout, "timeout", 0.2, 120.0)
        st = seconds(start_timeout, "start_timeout", 1.0, 600.0)
        binary = discover.find_binary(SLOT)
        if not binary:
            raise invalid_params("Psiphon ConsoleClient not found; set its path with psiphon.set_path")
        config = psiphon.configured_config()
        if not config:
            raise invalid_params("set its config with psiphon.set_config first")
        try:
            psiphon.load_config(config)
        except ValueError as e:
            raise invalid_params(str(e)) from None

        def run(ctx) -> dict:
            r = psiphon.probe(binary, config, timeout=t, start_timeout=st, stop=ctx.stop)
            ctx.item(r)
            return r
        return {"job": jobs.start("psiphon.probe", run)}
