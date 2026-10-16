"""
Real Xray-core bridge: config generation, local SOCKS5 proxy executor, version detection.

This module is the backwards-compatible façade over
:mod:`xray_forge.core.cores.xray_core` (config building) and
:mod:`xray_forge.core.cores.base.run_socks_probe` (process management).
Includes MMDF-style domain-fronting and fake-SNI outbounds (patterniha tricks).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any

from xray_forge.core.config import IPV4_RE
from xray_forge.core.models import Outbound
from xray_forge.core.parser import parse_target
from xray_forge.core.socks import socks5_connect  # re-exported for compat
from xray_forge.core.probe import ProbeError
from xray_forge.core.cores import get_core
from xray_forge.core.cores.base import run_socks_probe

__all__ = ["find_xray_core", "check_core_version", "build_xray_config",
           "socks5_connect", "xray_probe"]


def find_xray_core() -> str:
    exe = "xray.exe" if os.name == "nt" else "xray"
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "") or os.path.join(home, "AppData", "Roaming")
    here = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv else "."
    cands = [
        os.environ.get("XRAY_CORE", ""),
        os.path.join(appdata, "v2rayN", "bin", "xray", exe),
        os.path.join(home, "AppData", "Roaming", "v2rayN", "bin", "xray", exe),
        os.path.join(home, "v2rayN", "bin", "xray", exe),
        os.path.join(here, "bin", "xray", exe),
        os.path.join(here, exe),
        os.path.join("bin", "xray", exe),
        exe,
    ]
    for c in cands:
        if not c:
            continue
        w = shutil.which(c)
        if w:
            return w
        if os.path.isfile(c):
            return os.path.abspath(c)
    return ""


def check_core_version(path: str) -> str:
    kw: dict[str, Any] = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        out = subprocess.run([path, "version"], capture_output=True,
                             text=True, timeout=10, **kw)
    except OSError as e:
        return f"✖ cannot run core: {type(e).__name__}"
    except subprocess.TimeoutExpired:
        return "✖ core version check timed out"
    first = (out.stdout or out.stderr or "").strip().splitlines()
    return first[0].strip()[:90] if first else "✖ no version output"


def build_xray_config(line: str, socks_port: int, frag_on: bool,
                      front_domain: str | None = None) -> dict:
    """Build a full Xray client config for one share-link.

    Backwards-compatible entry: now routes through the protocol registry,
    which also fixes VMess/Shadowsocks/Reality outbound generation.
    """
    out = parse_target(line)
    if out is None:
        parts_scheme = line.strip().split("://", 1)[0].lower() if "://" in line else "?"
        raise ProbeError("cfg", f"scheme {parts_scheme} unsupported")
    xray = get_core("xray")
    assert xray is not None
    return xray.build_client_config([out], socks_port, frag_on=frag_on,
                                    front_domain=front_domain)


def xray_probe(line: str, xray_path: str, frag_on: bool,
               timeout: float = 8.0,
               front_domain: str | None = None) -> dict[str, Any]:
    out = parse_target(line)
    if out is None:
        return {"real": None, "cc": "", "exit_ip": "", "status": "unparsable config"}
    xray = get_core("xray")
    assert xray is not None
    try:
        port_free = __import__("socket").socket()
        try:
            port_free.bind(("127.0.0.1", 0))
            port = port_free.getsockname()[1]
        finally:
            port_free.close()
        cfg = xray.build_client_config([out], port, frag_on=frag_on,
                                       front_domain=front_domain)
    except Exception as e:
        return {"real": None, "cc": "", "exit_ip": "",
                "status": f"cfg: {type(e).__name__}"}
    return run_socks_probe(xray, xray_path, cfg, port, timeout=timeout)
