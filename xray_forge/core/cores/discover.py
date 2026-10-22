"""Locate proxy-core executables and read their versions.

Search order for each core: the path saved in settings (``core_paths``), the
core's environment variable (``XRAY_CORE`` / ``SINGBOX_CORE`` /
``MIHOMO_CORE``), v2rayN's ``bin`` folders, ``bin/<core>`` next to the app or
the working directory, then ``PATH``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from xray_forge.core import settings as _settings
from xray_forge.core.log import get_logger

log = get_logger(__name__)

SPECS: dict[str, dict] = {
    "xray": {"env": "XRAY_CORE", "names": ("xray",), "v2rayn": ("xray",),
             "version_args": ("version",)},
    "singbox": {"env": "SINGBOX_CORE", "names": ("sing-box", "sing_box"),
                "v2rayn": ("sing_box", "sing-box"), "version_args": ("version",)},
    # the opt-in sing-box fork with a MASQUE outbound; not a registered core
    # (it has no share-link protocols), only a binary slot used by core/masque.py
    "singbox_extended": {"env": "SINGBOX_EXTENDED_CORE", "names": ("sing-box-extended",),
                         "v2rayn": (), "version_args": ("version",)},
    # Psiphon's console client: the user supplies the binary and their own config
    "psiphon": {"env": "PSIPHON_CORE", "names": ("ConsoleClient", "psiphon-console-client"),
                "v2rayn": (), "version_args": ("-version",)},
    "mihomo": {"env": "MIHOMO_CORE", "names": ("mihomo", "clash-meta", "verge-mihomo"),
               "v2rayn": ("mihomo", "clash_meta"), "version_args": ("-v",)},
}


def _exe(name: str) -> str:
    return name + (".exe" if os.name == "nt" else "")


def _is_exec(path: str) -> bool:
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


def configured_path(core: str) -> str:
    paths = _settings.load_settings().get("core_paths")
    value = paths.get(core, "") if isinstance(paths, dict) else ""
    return value if isinstance(value, str) else ""


def save_path(core: str, path: str) -> None:
    data = _settings.load_settings()
    paths = data.get("core_paths")
    paths = dict(paths) if isinstance(paths, dict) else {}
    if path:
        paths[core] = path
    else:
        paths.pop(core, None)
    data["core_paths"] = paths
    _settings.save_settings(data)


def _app_dirs() -> list[str]:
    dirs = [os.getcwd()]
    if getattr(sys, "frozen", False):
        dirs.insert(0, os.path.dirname(sys.executable))
    elif sys.argv and sys.argv[0]:
        dirs.insert(0, os.path.dirname(os.path.abspath(sys.argv[0])))
    return dirs


def candidates(core: str) -> list[tuple[str, str]]:
    """(source, path-or-command) pairs in priority order."""
    spec = SPECS.get(core)
    if spec is None:
        return []
    out: list[tuple[str, str]] = []
    if configured_path(core):
        out.append(("settings", configured_path(core)))
    if os.environ.get(spec["env"]):
        out.append(("env", os.environ[spec["env"]]))
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "") or os.path.join(home, "AppData", "Roaming")
    roots = [os.path.join(appdata, "v2rayN", "bin"), os.path.join(home, "v2rayN", "bin")]
    for root in roots:
        for sub in spec["v2rayn"]:
            for n in spec["names"]:
                out.append(("v2rayN", os.path.join(root, sub, _exe(n))))
    for base in _app_dirs():
        for n in spec["names"]:
            out.append(("local", os.path.join(base, "bin", n, _exe(n))))
            out.append(("local", os.path.join(base, "bin", _exe(n))))
            out.append(("local", os.path.join(base, _exe(n))))
    for n in spec["names"]:
        out.append(("PATH", n))
    return out


def find(core: str) -> tuple[str, str]:
    """(path, source) of the first usable binary, or ("", "")."""
    for source, cand in candidates(core):
        path = cand if os.path.isabs(cand) or os.sep in cand else (shutil.which(cand) or "")
        if source == "env" and path and not _is_exec(path):
            path = shutil.which(cand) or ""
        if _is_exec(path):
            return os.path.abspath(path), source
    return "", ""


def find_binary(core: str) -> str:
    return find(core)[0]


def version(core: str, path: str, timeout: float = 10.0) -> tuple[bool, str]:
    """Run the core's version command. Returns (ok, first output line)."""
    spec = SPECS.get(core)
    if spec is None:
        return False, "unknown core"
    kw: dict = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        proc = subprocess.run([path, *spec["version_args"]], capture_output=True,
                              text=True, timeout=timeout, **kw)
    except OSError as e:
        return False, f"cannot run: {type(e).__name__}"
    except subprocess.TimeoutExpired:
        return False, "version check timed out"
    lines = (proc.stdout or proc.stderr or "").strip().splitlines()
    if proc.returncode != 0 or not lines:
        return False, (lines[0].strip()[:90] if lines else f"exit code {proc.returncode}")
    return True, lines[0].strip()[:90]
