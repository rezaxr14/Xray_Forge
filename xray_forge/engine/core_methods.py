"""Engine methods for proxy cores (xray / sing-box / mihomo)."""

from __future__ import annotations

import os
from typing import Any

from xray_forge.core.cores import discover, get_core, iter_cores
from xray_forge.engine.rpc import Dispatcher, invalid_params


def describe(core_name: str, with_version: bool = True) -> dict[str, Any]:
    core = get_core(core_name)
    path, source = discover.find(core_name)
    entry: dict[str, Any] = {
        "name": core_name, "display_name": core.display_name if core else core_name,
        "path": path, "source": source, "configured": discover.configured_path(core_name),
        "found": bool(path), "version": "", "ok": False,
    }
    if path and with_version:
        entry["ok"], entry["version"] = discover.version(core_name, path)
    return entry


def installed_cores() -> list[str]:
    return [c.name for c in iter_cores() if discover.find_binary(c.name)]


def register(d: Dispatcher) -> None:
    @d.method("core.detect")
    def core_detect() -> list[dict]:
        return [describe(c.name) for c in iter_cores()]

    @d.method("core.set_path")
    def core_set_path(name: str, path: str = "") -> dict:
        """Remember an executable for ``name`` ("" clears the setting).

        The file must exist, be executable and answer its version command;
        that is the only time the engine runs a user-chosen binary besides
        health checks the user starts.
        """
        if get_core(name) is None:
            raise invalid_params(f"unknown core: {name}")
        if not isinstance(path, str):
            raise invalid_params("path must be a string")
        path = path.strip()
        if path:
            if not os.path.isabs(path):
                raise invalid_params("path must be absolute")
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                raise invalid_params("not an executable file")
            ok, text = discover.version(name, path)
            if not ok:
                raise invalid_params(f"{name} did not answer its version command: {text}")
        discover.save_path(name, path)
        return describe(name)
