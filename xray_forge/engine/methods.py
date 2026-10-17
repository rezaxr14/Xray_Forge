"""Engine methods.  Each is a thin adapter over ``xray_forge.core``; no
business logic lives here so the CLI, the Tk GUI and the new UI stay in sync.
"""

from __future__ import annotations

import dataclasses
import json
import threading
from typing import Any

from xray_forge import __version__
from xray_forge.core import healthcheck as hc
from xray_forge.core.config import (
    DEFAULT_CS, DEFAULT_FM, DEFAULT_FP, DEFAULT_TEMPLATE,
)
from xray_forge.core.cores import core_names, get_core
from xray_forge.core.dedup import dedup_configs
from xray_forge.core.models import Outbound
from xray_forge.core.parser import (
    convert_block, export_to_clash, export_to_singbox, export_to_sub,
    parse_target,
)
from xray_forge.core.protocols import handler_for, supported_schemes
from xray_forge.core.sub_source import SourceManager
from xray_forge.core.subscription import text_to_lines
from xray_forge.engine import PROTOCOL_VERSION
from xray_forge.engine.jobs import JobContext, JobManager
from xray_forge.engine.rpc import Dispatcher, invalid_params

MAX_LINES = 20000


def _outbound_dict(out: Outbound) -> dict:
    d = dataclasses.asdict(out)
    d.pop("raw", None)
    return d


def _core_support(out: Outbound) -> dict[str, bool]:
    res: dict[str, bool] = {}
    for name in core_names():
        core = get_core(name)
        try:
            res[name] = bool(core and core.supports(out))
        except Exception:
            res[name] = False
    return res


def _lines(lines: Any) -> list[str]:
    if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
        raise invalid_params("lines must be a list of strings")
    if len(lines) > MAX_LINES:
        raise invalid_params(f"too many lines (max {MAX_LINES})")
    return [x for x in (s.strip() for s in lines) if x]


def _describe(line: str) -> dict:
    out = parse_target(line)
    if out is None:
        return {"line": line, "ok": False}
    return {"line": line, "ok": True, "outbound": _outbound_dict(out),
            "supports": _core_support(out)}


def build(emit, sources: SourceManager | None = None
          ) -> tuple[Dispatcher, JobManager]:
    """Create a dispatcher + job manager bound to ``emit`` (a callable that
    sends one notification dict to the client)."""
    d = Dispatcher()
    jobs = JobManager(lambda ev: emit({"jsonrpc": "2.0", "method": "job.event",
                                       "params": ev}))
    state: dict[str, Any] = {"sources": sources}

    def src_mgr() -> SourceManager:
        if state["sources"] is None:
            state["sources"] = SourceManager()
        return state["sources"]

    # ------------------------------------------------------------- engine
    @d.method("engine.info")
    def engine_info() -> dict:
        return {"version": __version__, "protocol": PROTOCOL_VERSION,
                "schemes": sorted(supported_schemes()),
                "cores": core_names(), "methods": d.names(),
                "defaults": {"fp": DEFAULT_FP, "cs": DEFAULT_CS,
                             "fm": DEFAULT_FM, "template": DEFAULT_TEMPLATE}}

    # ------------------------------------------------------------- config
    @d.method("config.parse")
    def config_parse(line: str) -> dict:
        if not isinstance(line, str):
            raise invalid_params("line must be a string")
        return _describe(line.strip())

    @d.method("config.parse_many")
    def config_parse_many(text: str) -> list[dict]:
        if not isinstance(text, str):
            raise invalid_params("text must be a string")
        return [_describe(x) for x in _lines(text.splitlines())]

    @d.method("config.render")
    def config_render(outbound: dict) -> dict:
        """Edited outbound -> share link (the editor's save path)."""
        if not isinstance(outbound, dict):
            raise invalid_params("outbound must be an object")
        known = {f.name for f in dataclasses.fields(Outbound)}
        bad = set(outbound) - known
        if bad:
            raise invalid_params(f"unknown outbound fields: {', '.join(sorted(bad))}")
        out = Outbound.from_dict(outbound)
        h = handler_for(out.scheme)
        if h is None:
            raise invalid_params(f"unsupported scheme: {out.scheme!r}")
        uri = h.to_uri(out)
        again = parse_target(uri)
        return {"uri": uri, "roundtrip_ok": again is not None,
                "supports": _core_support(out)}

    @d.method("config.convert")
    def config_convert(text: str, fp: str = DEFAULT_FP, cs: str = DEFAULT_CS,
                       fm: str | None = None, template: str = DEFAULT_TEMPLATE,
                       start: int = 1, ip: str = "", port: str = "",
                       rename: bool = True, tls_only: bool = True,
                       want_fp: bool = True, want_cs: bool = True,
                       want_fm: bool = True, dedup: bool = False) -> dict:
        if not isinstance(text, str):
            raise invalid_params("text must be a string")
        if fm is None:
            fm = json.dumps(DEFAULT_FM, separators=(",", ":"))
        lines, names, counts = convert_block(
            text, fp, cs, fm, tls_only, rename, template, start, ip, port,
            want_fp, want_cs, want_fm)
        removed = 0
        if dedup:
            lines, removed = dedup_configs(lines)
        return {"lines": lines, "counts": counts, "removed": removed}

    @d.method("config.export")
    def config_export(lines: list, format: str) -> dict:
        ls = _lines(lines)
        fn = {"clash": export_to_clash, "singbox": export_to_singbox,
              "sub": export_to_sub}.get(format)
        if fn is None:
            raise invalid_params("format must be one of: clash, singbox, sub")
        return {"format": format, "count": len(ls), "content": fn(ls)}

    @d.method("config.dedup")
    def config_dedup(lines: list) -> dict:
        out, removed = dedup_configs(_lines(lines))
        return {"lines": out, "removed": removed}

    # ------------------------------------------------------ subscriptions
    @d.method("sub.list")
    def sub_list() -> list[dict]:
        return [s.to_dict() for s in src_mgr().list_sources()]

    @d.method("sub.add")
    def sub_add(url: str, name: str = "") -> dict:
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            raise invalid_params("url must start with http:// or https://")
        return src_mgr().add(url, name).to_dict()

    @d.method("sub.remove")
    def sub_remove(url: str) -> bool:
        return src_mgr().remove(url)

    @d.method("sub.set_enabled")
    def sub_set_enabled(url: str, enabled: bool) -> bool:
        src_mgr().set_enabled(url, bool(enabled))
        return True

    @d.method("sub.configs")
    def sub_configs(dedupe: bool = True) -> dict:
        lines, removed = src_mgr().combined_lines(dedupe=dedupe)
        return {"lines": lines, "removed": removed}

    @d.method("sub.fetch")
    def sub_fetch(force: bool = False, timeout: float = 15.0) -> dict:
        def run(ctx: JobContext) -> dict:
            mgr = src_mgr()
            srcs = [s for s in mgr.list_sources() if s.enabled]
            total = len(srcs)
            counts: dict[str, int] = {}
            for i, src in enumerate(srcs, 1):
                if ctx.stop.is_set():
                    break
                lines = mgr.fetch(src, force=force, timeout=timeout)
                counts[src.url] = len(lines)
                ctx.item({"url": src.url, "count": len(lines),
                          "status": src.last_status})
                ctx.progress(i, total)
            return {"counts": counts}
        return {"job": jobs.start("sub.fetch", run)}

    # -------------------------------------------------------------- health
    @d.method("health.run")
    def health_run(lines: list, workers: int = 8, timeout: float = 6.0,
                   throughput: bool = True, core: str | None = None) -> dict:
        ls = _lines(lines)
        if not 1 <= int(workers) <= 64:
            raise invalid_params("workers must be 1..64")
        if core is not None and core != "auto" and get_core(core) is None:
            raise invalid_params(f"unknown core: {core}")

        def run(ctx: JobContext) -> dict:
            reports: list[dict] = []
            total = len(ls)
            done = [0]
            lock = threading.Lock()

            def one(line: str) -> None:
                rep = hc.run_health_check(line, do_throughput=throughput,
                                          timeout=timeout, stop=ctx.stop, core=core)
                row = dataclasses.asdict(rep)
                row["passed"] = rep.passed()
                with lock:
                    reports.append(row)
                    done[0] += 1
                    ctx.item(row)
                    ctx.progress(done[0], total)

            from concurrent.futures import ThreadPoolExecutor
            ex = ThreadPoolExecutor(max_workers=int(workers))
            try:
                futs = [ex.submit(one, x) for x in ls]
                for f in futs:
                    try:
                        f.result()
                    except Exception as e:  # one bad probe must not abort the run
                        with lock:
                            done[0] += 1
                            ctx.item({"line": "", "error": str(e)[:80]})
                    if ctx.stop.is_set():
                        break
            finally:
                ex.shutdown(wait=True, cancel_futures=ctx.stop.is_set())
            reports.sort(key=lambda r: -r.get("score", 0))
            return {"total": total, "passed": sum(1 for r in reports if r["passed"])}
        return {"job": jobs.start("health.run", run)}

    # ----------------------------------------------------------------- jobs
    @d.method("job.cancel")
    def job_cancel(job: str) -> bool:
        return jobs.cancel(job)

    @d.method("job.list")
    def job_list() -> list[str]:
        return jobs.active()

    return d, jobs
