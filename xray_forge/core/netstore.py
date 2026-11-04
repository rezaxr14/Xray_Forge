"""The user's own DNS entries and proxies (``~/.xray_forge/net_custom.json``).

Also reads the two files the old stand-alone "DNS & Proxy Changer" kept (``dns_servers.json``
as ``{"Name": ["primary", "secondary"]}`` and ``proxies.json``) so nothing has to be retyped.
Proxy user names and passwords are not kept: the operating system's proxy setting cannot use them.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from xray_forge.core import settings as _settings
from xray_forge.core.dns_presets import valid_ip
from xray_forge.core.fsutil import write_private
from xray_forge.core.sysnet import clean_proxy, clean_servers

FILE = "net_custom.json"
MAX_ENTRIES = 100
NAME_RE = re.compile(r"^[^\x00-\x1f]{1,60}$")


def _path() -> str:
    return os.path.join(_settings.data_dir(), FILE)


def load() -> dict[str, dict]:
    data: Any = {}
    try:
        with open(_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    out: dict[str, dict] = {"dns": {}, "proxies": {}}
    for name, e in (data.get("dns") or {}).items() if isinstance(data.get("dns"), dict) else []:
        try:
            out["dns"][name] = {"servers": clean_servers(e["servers"]), "note": str(e.get("note", ""))[:200]}
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
    for name, e in (data.get("proxies") or {}).items() if isinstance(data.get("proxies"), dict) else []:
        try:
            h, p, k = clean_proxy(e["host"], e["port"], e["kind"])
            out["proxies"][name] = {"host": h, "port": p, "kind": k}
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
    return out


def _save(data: dict) -> None:
    write_private(_path(), json.dumps(data, indent=2, ensure_ascii=False))


def _name(name: Any) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name.strip()) or not name.strip():
        raise ValueError("the name must be 1 to 60 characters")
    return name.strip()


def _room(data: dict, kind: str, name: str) -> None:
    if name not in data[kind] and len(data[kind]) >= MAX_ENTRIES:
        raise ValueError(f"at most {MAX_ENTRIES} saved entries")


def save_dns(name: Any, servers: Any, note: Any = "") -> dict:
    name, servers = _name(name), clean_servers(servers)
    data = load()
    _room(data, "dns", name)
    data["dns"][name] = {"servers": servers, "note": str(note or "")[:200]}
    _save(data)
    return data["dns"][name]


def save_proxy(name: Any, host: Any, port: Any, kind: Any) -> dict:
    name = _name(name)
    h, p, k = clean_proxy(host, port, kind)
    data = load()
    _room(data, "proxies", name)
    data["proxies"][name] = {"host": h, "port": p, "kind": k}
    _save(data)
    return data["proxies"][name]


def delete(kind: str, name: Any) -> bool:
    data = load()
    if name not in data[kind]:
        return False
    del data[kind][name]
    _save(data)
    return True


def import_legacy(dns: Any = None, proxies: Any = None) -> dict:
    """Merge the old tool's JSON.  Returns counts; bad entries are skipped, never fatal."""
    data = load()
    added = {"dns": 0, "proxies": 0, "skipped": 0}
    for name, ips in (dns.items() if isinstance(dns, dict) else []):
        try:
            n = _name(name)
            if isinstance(ips, dict):       # our own format
                ips = ips.get("servers")
            _room(data, "dns", n)
            data["dns"][n] = {"servers": clean_servers([valid_ip(i) for i in ips if str(i).strip()]), "note": ""}
            added["dns"] += 1
        except (ValueError, TypeError):
            added["skipped"] += 1
    for name, e in (proxies.items() if isinstance(proxies, dict) else []):
        try:
            n = _name(name)
            if not isinstance(e, dict) or not str(e.get("server", e.get("host", ""))).strip():
                continue                    # the old "No Proxy" placeholder has no server
            kind = "socks" if str(e.get("type", e.get("kind", "http"))).lower().startswith("socks") else "http"
            h, p, k = clean_proxy(str(e.get("server", e.get("host"))), e.get("port"), kind)
            _room(data, "proxies", n)
            data["proxies"][n] = {"host": h, "port": p, "kind": k}
            added["proxies"] += 1
        except (ValueError, TypeError):
            added["skipped"] += 1
    _save(data)
    return added
