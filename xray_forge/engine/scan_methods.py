"""Engine methods for the scanners: IP scan, SNI search, WARP, MITM-DF."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import tempfile
import threading
import time
from typing import Any

from xray_forge.core import domainfront, warp
from xray_forge.core.config import MITM_DF_XRAY_MIN_VERSION
from xray_forge.core.cores import get_core
from xray_forge.core.scan_session import ScanSession
from xray_forge.core import settings as _settings
from xray_forge.core.sni_search import (
    DEFAULT_SNI_CANDIDATES, SniSearch, targets_from_scan,
)
from xray_forge.engine.jobs import JobContext, JobManager
from xray_forge.engine.rpc import Dispatcher, invalid_params

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_TARGETS = 100000


def _session_name(name: str | None, prefix: str) -> str:
    if name is None or name == "":
        return f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}"
    if not isinstance(name, str) or not _NAME_RE.match(name) or ".." in name:
        raise invalid_params("session name may only contain letters, digits, _ . -")
    return name


def _int(v: Any, lo: int, hi: int, what: str) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise invalid_params(f"{what} must be an integer") from None
    if not lo <= n <= hi:
        raise invalid_params(f"{what} must be {lo}..{hi}")
    return n


def _port(v: Any) -> str:
    return str(_int(v, 1, 65535, "port"))


def _str_list(v: Any, what: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise invalid_params(f"{what} must be a list of strings")
    return [x.strip() for x in v if x.strip()]


def _export(session, fmt: str) -> dict:
    if fmt not in ("csv", "json"):
        raise invalid_params("format must be csv or json")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, f"out.{fmt}")
        (session.export_csv if fmt == "csv" else session.export_json)(path)
        with open(path, "r", encoding="utf-8") as f:
            return {"format": fmt, "content": f.read()}


def _list_sessions(dirname: str, loader) -> list[dict]:
    d = os.path.join(_settings.data_dir(), dirname)
    if not os.path.isdir(d):
        return []
    out = []
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".json") and _NAME_RE.match(fn[:-5]):
            out.append(loader(fn[:-5]))
    return out


def _pending_count(s) -> int:
    return len(s.pending)


def _warp_status() -> dict:
    acct = warp.load_account()
    if acct is None:
        return {"registered": False}
    return {"registered": True, "device_id": acct.device_id[:12],
            "endpoint": acct.endpoint, "ipv4": acct.ipv4, "ipv6": acct.ipv6}


def register(d: Dispatcher, jobs: JobManager) -> None:
    # ------------------------------------------------------------ IP scan
    @d.method("scan.run")
    def scan_run(cidrs: list, count: int = 200, port: str = "443",
                 sni: str | None = None, workers: int = 64,
                 frag: str = "5,94,1@2", geo: bool = False,
                 timeout: float = 5.0, session: str | None = None,
                 resume: bool = False) -> dict:
        cidr_list = _str_list(cidrs, "cidrs")
        if not cidr_list and not resume:
            raise invalid_params("cidrs must not be empty")
        if resume and not session:
            raise invalid_params("resume needs a session name")
        count = _int(count, 1, 5000, "count")
        workers = _int(workers, 1, 256, "workers")
        port = _port(port)
        name = _session_name(session, "scan")
        sess = ScanSession(name)
        n = sess.set_targets(cidr_list, count, resume=bool(resume))
        if n == 0:
            raise invalid_params("nothing to resume" if resume
                                 else "no scannable IPs in the given ranges")
        if n > MAX_TARGETS:
            raise invalid_params("too many targets")

        def run(ctx: JobContext) -> dict:
            sess.run(port=port, workers=workers, frag=frag, sni=sni or None,
                     geo=bool(geo), timeout=float(timeout), stop=ctx.stop,
                     progress=ctx.progress,
                     on_result=lambda r: ctx.item(r.to_dict()))
            return {"session": name, "alive": len(sess.alive()),
                    "total": len(sess.results), "pending": _pending_count(sess)}
        return {"job": jobs.start("scan.run", run), "session": name, "targets": n}

    @d.method("scan.sessions")
    def scan_sessions() -> list[dict]:
        return _list_sessions("scans", lambda n: (lambda s: {
            "name": n, "total": len(s.results), "alive": len(s.alive()),
            "pending": _pending_count(s)})(ScanSession(n)))

    @d.method("scan.get")
    def scan_get(session: str) -> dict:
        s = ScanSession(_session_name(session, "scan"))
        return {"name": s.name, "pending": _pending_count(s),
                "results": [r.to_dict() for r in s.alive()] +
                           [r.to_dict() for r in s.results.values() if not r.alive]}

    @d.method("scan.export")
    def scan_export(session: str, format: str = "csv") -> dict:
        return _export(ScanSession(_session_name(session, "scan")), format)

    # --------------------------------------------------------- SNI search
    @d.method("sni.presets")
    def sni_presets() -> list[str]:
        return list(DEFAULT_SNI_CANDIDATES)

    @d.method("sni.run")
    def sni_run(ips: list, snis: list, presets: bool = False,
                from_scan: str | None = None, port: str = "443",
                workers: int = 32, frag: str = "5,94,1@2", timeout: float = 5.0,
                http_check: bool = True, session: str | None = None,
                resume: bool = False) -> dict:
        ip_list = SniSearch.parse_list(" ".join(_str_list(ips, "ips")))
        if from_scan:
            ip_list = SniSearch.parse_list(
                " ".join(ip_list + targets_from_scan(_session_name(from_scan, "scan"))))
        sni_list = SniSearch.parse_list(" ".join(_str_list(snis, "snis")))
        if presets:
            sni_list += [c for c in DEFAULT_SNI_CANDIDATES if c not in sni_list]
        if not ip_list or not sni_list:
            raise invalid_params("need at least one IP and one SNI")
        if len(ip_list) * len(sni_list) > MAX_TARGETS:
            raise invalid_params("too many (ip, sni) pairs")
        workers = _int(workers, 1, 256, "workers")
        port = _port(port)
        name = _session_name(session, "sni")
        search = SniSearch(name)
        n = search.set_targets(ip_list, sni_list, port=port, resume=bool(resume))

        def run(ctx: JobContext) -> dict:
            search.run(port=port, workers=workers, frag=frag,
                       timeout=float(timeout), http_check=bool(http_check),
                       stop=ctx.stop, progress=ctx.progress,
                       on_result=lambda h: ctx.item(h.to_dict()))
            return {"session": name, "working": len(search.hits()),
                    "total": len(search.results), "pending": _pending_count(search)}
        return {"job": jobs.start("sni.run", run), "session": name, "pairs": n}

    @d.method("sni.sessions")
    def sni_sessions() -> list[dict]:
        return _list_sessions("sni_search", lambda n: (lambda s: {
            "name": n, "total": len(s.results), "working": len(s.hits()),
            "pending": _pending_count(s)})(SniSearch(n)))

    @d.method("sni.get")
    def sni_get(session: str) -> dict:
        s = SniSearch(_session_name(session, "sni"))
        return {"name": s.name, "pending": _pending_count(s),
                "results": [h.to_dict() for h in s.hits()]}

    @d.method("sni.export")
    def sni_export(session: str, format: str = "csv") -> dict:
        return _export(SniSearch(_session_name(session, "sni")), format)

    # --------------------------------------------------------------- WARP
    @d.method("warp.status")
    def warp_status() -> dict:
        return _warp_status()

    @d.method("warp.register")
    def warp_register() -> dict:
        acct = warp.register_account()      # network; errors surface as RPC errors
        warp.save_account(acct)
        return _warp_status()

    @d.method("warp.config")
    def warp_config(endpoint: str = "", format: str = "singbox") -> dict:
        """WARP outbound as a JSON snippet for ``format`` (a core name:
        xray / singbox / mihomo). WireGuard has no share-link form."""
        acct = warp.load_account()
        if acct is None:
            raise invalid_params("no saved WARP account; register first")
        core = get_core(format) if isinstance(format, str) else None
        if core is None:
            raise invalid_params("format must be one of: xray, singbox, mihomo")
        out = warp.account_to_outbound(acct, endpoint=endpoint or "")
        rendered = core.render_outbound(out)
        if rendered is None:
            raise invalid_params(f"{format} cannot render this WARP outbound")
        return {"format": format, "content": json.dumps(rendered, indent=2)}

    @d.method("warp.scan")
    def warp_scan(count: int = 60, workers: int = 20) -> dict:
        count = _int(count, 1, 500, "count")
        workers = _int(workers, 1, 128, "workers")

        def run(ctx: JobContext) -> dict:
            results = warp.scan_endpoints(
                count, workers, progress=ctx.progress, stop=ctx.stop)
            for ep, ms in results:
                ctx.item({"endpoint": ep, "ms": ms})
            return {"responsive": len(results)}
        return {"job": jobs.start("warp.scan", run)}

    # ------------------------------------------------------------- MITM-DF
    @d.method("mitm.groups")
    def mitm_groups() -> dict:
        return {"groups": {k: {"domains": v["domains"], "cover_sni": v["cover_sni"]}
                           for k, v in domainfront.ROUTE_GROUPS.items()},
                "defaults": domainfront.default_options()["groups"],
                "min_xray_version": MITM_DF_XRAY_MIN_VERSION}

    @d.method("mitm.ca_paths")
    def mitm_ca_paths() -> dict:
        base = os.path.join(_settings.data_dir(), "mitm")
        return {"cert": os.path.join(base, "mitm-ca.crt"),
                "key": os.path.join(base, "mitm-ca.key"),
                "exists": os.path.isfile(os.path.join(base, "mitm-ca.crt"))}

    @d.method("mitm.build")
    def mitm_build(groups: list | None = None, use_generated_ca: bool = False) -> dict:
        overrides: dict[str, Any] = {}
        if groups is not None:
            gl = _str_list(groups, "groups")
            bad = [g for g in gl if g not in domainfront.ROUTE_GROUPS]
            if bad:
                raise invalid_params(f"unknown groups: {', '.join(bad)}")
            overrides["groups"] = gl
        if use_generated_ca:
            paths = mitm_ca_paths()
            if not paths["exists"]:
                raise invalid_params("no generated CA yet; generate one first")
            overrides["cert_file"], overrides["key_file"] = paths["cert"], paths["key"]
        cfg = domainfront.build_config(**overrides)
        return {"content": json.dumps(cfg, indent=2),
                "min_xray_version": MITM_DF_XRAY_MIN_VERSION}

    @d.method("mitm.generate_ca")
    def mitm_generate_ca(cn: str = "Xray Forge MITM CA",
                         permitted_domains: list | None = None) -> dict:
        if not isinstance(cn, str) or not cn.strip() or len(cn) > 64:
            raise invalid_params("cn must be 1..64 characters")
        pd = _str_list(permitted_domains, "permitted_domains") if permitted_domains else None
        paths = mitm_ca_paths()
        os.makedirs(os.path.dirname(paths["cert"]), exist_ok=True)
        domainfront.generate_ca(cn.strip(), paths["cert"], paths["key"],
                                permitted_domains=pd)
        return {"cert": paths["cert"], "key": paths["key"],
                "constrained": bool(pd),
                "note": "Trust the certificate on this device only; never share the key."}

    @d.method("mitm.guide")
    def mitm_guide(platform: str = "windows") -> dict:
        if platform not in ("windows", "android"):
            raise invalid_params("platform must be windows or android")
        return {"content": domainfront.setup_guide(platform)}
