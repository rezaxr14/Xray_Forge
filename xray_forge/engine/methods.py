"""Engine methods.  Each is a thin adapter over ``xray_forge.core``; no
business logic lives here so the CLI, the Tk GUI and the new UI stay in sync.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import threading
from collections import Counter, OrderedDict
from typing import Any
from urllib.parse import unquote, urlsplit

from xray_forge import __version__
from xray_forge.core import healthcheck as hc
from xray_forge.core.config import (
    CF_RANGES, DEFAULT_CS, DEFAULT_FM, DEFAULT_FP, DEFAULT_TEMPLATE, FASTLY_RANGES,
    FLOWS, FRAG_PRESETS, SECURITIES, TEMPLATE_KEYS, WARP_RANGES, TRANSPORTS, XHTTP_MODES,
)
from xray_forge.core.cores import core_names, get_core
from xray_forge.core.dedup import dedup_configs
from xray_forge.core.models import Outbound
from xray_forge.core.parser import (
    classify_endpoint, convert_block, export_to_clash, export_to_singbox,
    export_to_sub, parse_target, tag_name_with_cc, valid_port,
)
from xray_forge.core.protocols import handler_for, supported_schemes
from xray_forge.core.sub_source import SourceManager
from xray_forge.core.subscription import text_to_lines
from xray_forge.engine import PROTOCOL_VERSION
from xray_forge.engine.jobs import JobContext, JobManager
from xray_forge.engine.rpc import Dispatcher, invalid_params, seconds

MAX_LINES = 20000
KEEP_RUNS = 4          # health runs whose reports stay available for export
MAX_START = 99999


def _opt_str(v: Any, what: str) -> str:
    if v is None:
        return ""
    if not isinstance(v, (str, int)) or isinstance(v, bool):
        raise invalid_params(f"{what} must be a string")
    return str(v).strip()


def _override_ip(v: Any) -> str:
    ip = _opt_str(v, "ip")
    if ip and classify_endpoint(ip) is None:
        raise invalid_params("ip must be an IPv4/IPv6 address or a domain")
    return ip


def _override_port(v: Any) -> str:
    port = _opt_str(v, "port")
    if port and not valid_port(port):
        raise invalid_params("port must be 1..65535")
    return port


def _start_id(v: Any) -> int:
    if isinstance(v, bool):
        raise invalid_params("start must be an integer")
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise invalid_params("start must be an integer") from None
    if not 0 <= n <= MAX_START:
        raise invalid_params(f"start must be 0..{MAX_START}")
    return n


def _mask_json(fm: str) -> str:
    """The fm= value is injected into every link, so it must be real JSON."""
    try:
        parsed = json.loads(fm)
    except ValueError:
        raise invalid_params("fm must be valid JSON") from None
    if not isinstance(parsed, (dict, list)):
        raise invalid_params("fm must be a JSON object or array")
    return fm


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

_OUT_STR_FIELDS = (
    "scheme", "name", "host", "port", "credential", "transport", "security",
    "sni", "host_header", "path", "fingerprint", "alpn", "service_name",
    "header_type", "public_key", "short_id", "spider_x", "flow", "ss_method",
    "alter_id", "encryption", "raw")
_OUT_NUM_AS_STR = ("port", "alter_id")


def _outbound_from_obj(obj: Any) -> Outbound:
    """Validate an editor payload and build the Outbound.

    Unknown fields and wrongly-typed values are rejected (-32602) instead of
    being dropped or crashing a handler later.  ``port`` / ``alter_id`` may
    be given as integers (raw JSON editing); everything else must be a
    string.  ``extra`` is free-form JSON, ``extra_params`` holds scalars.
    """
    if not isinstance(obj, dict):
        raise invalid_params("outbound must be an object")
    known = {f.name for f in dataclasses.fields(Outbound)}
    bad = set(obj) - known
    if bad:
        raise invalid_params(f"unknown outbound fields: {', '.join(sorted(bad))}")
    data = dict(obj)
    for key in _OUT_STR_FIELDS:
        if key not in data:
            continue
        v = data[key]
        if key in _OUT_NUM_AS_STR and isinstance(v, int) and not isinstance(v, bool):
            data[key] = v = str(v)
        if not isinstance(v, str):
            raise invalid_params(f"{key} must be a string")
    if "allow_insecure" in data and not isinstance(data["allow_insecure"], bool):
        raise invalid_params("allow_insecure must be true or false")
    for key in ("extra", "extra_params"):
        if key in data:
            v = data[key]
            if not isinstance(v, dict) or not all(isinstance(k, str) for k in v):
                raise invalid_params(f"{key} must be an object")
    for k, v in (data.get("extra_params") or {}).items():
        if not isinstance(v, (str, int, float, bool)):
            raise invalid_params(f"extra_params.{k} must be a string or number")
    if data.get("port") and not valid_port(data["port"]):
        raise invalid_params("port must be 1..65535")
    data["raw"] = ""
    return Outbound.from_dict(data)


def build(emit, sources: SourceManager | None = None
          ) -> tuple[Dispatcher, JobManager]:
    """Create a dispatcher + job manager bound to ``emit`` (a callable that
    sends one notification dict to the client)."""
    d = Dispatcher()
    jobs = JobManager(lambda ev: emit({"jsonrpc": "2.0", "method": "job.event",
                                       "params": ev}))
    state: dict[str, Any] = {"sources": sources}
    runs: OrderedDict[str, list] = OrderedDict()   # job id -> HealthReports
    runs_lock = threading.Lock()

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
                             "fm": DEFAULT_FM, "template": DEFAULT_TEMPLATE},
                "template_keys": list(TEMPLATE_KEYS),
                "frag_presets": list(FRAG_PRESETS),
                "ranges": {"cloudflare": list(CF_RANGES), "fastly": list(FASTLY_RANGES),
                           "warp": list(WARP_RANGES)},
                "editor": {"transports": TRANSPORTS, "flows": FLOWS,
                           "securities": SECURITIES,
                           "xhttp_modes": XHTTP_MODES}}

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
        out = _outbound_from_obj(outbound)
        h = handler_for(out.scheme)
        if h is None:
            raise invalid_params(f"unsupported scheme: {out.scheme!r}")
        uri = h.to_uri(out)
        again = parse_target(uri)
        return {"uri": uri, "roundtrip_ok": again is not None,
                "supports": _core_support(out)}

    @d.method("config.from_json")
    def config_from_json(text: str) -> dict:
        """Raw-JSON editor -> validated outbound (the JSON -> form step)."""
        if not isinstance(text, str):
            raise invalid_params("text must be a string")
        try:
            obj = json.loads(text)
        except ValueError as e:
            raise invalid_params(f"bad JSON: {e}") from None
        out = _outbound_from_obj(obj)
        if handler_for(out.scheme) is None:
            raise invalid_params(f"unsupported scheme: {out.scheme!r}")
        return {"outbound": _outbound_dict(out), "supports": _core_support(out)}

    @d.method("config.convert")
    def config_convert(text: str, fp: str = DEFAULT_FP, cs: str = DEFAULT_CS,
                       fm: str | None = None, template: str = DEFAULT_TEMPLATE,
                       start: int = 1, ip: str = "", port: str = "",
                       rename: bool = True, tls_only: bool = True,
                       want_fp: bool = True, want_cs: bool = True,
                       want_fm: bool = True, dedup: bool = False) -> dict:
        """Apply the converter rules.  ``ip``/``port`` force one endpoint on
        every config; ``want_*`` choose what is injected (all false = the
        Tk GUI's "IP only" mode).  ``names`` lists ``{name, line}`` for each
        output link, in output order."""
        if not isinstance(text, str):
            raise invalid_params("text must be a string")
        for what, val in (("fp", fp), ("cs", cs), ("template", template)):
            if not isinstance(val, str):
                raise invalid_params(f"{what} must be a string")
        if fm is None:
            fm = json.dumps(DEFAULT_FM, separators=(",", ":"))
        if not isinstance(fm, str):
            raise invalid_params("fm must be a string")
        for what, val in (("rename", rename), ("tls_only", tls_only),
                          ("want_fp", want_fp), ("want_cs", want_cs),
                          ("want_fm", want_fm), ("dedup", dedup)):
            if not isinstance(val, bool):
                raise invalid_params(f"{what} must be true or false")
        fp, cs, fm = fp.strip(), cs.strip(), fm.strip()
        if want_fm and fm:
            _mask_json(fm)
        ip, port = _override_ip(ip), _override_port(port)
        lines, names, counts = convert_block(
            text, fp, cs, fm, tls_only, rename,
            template.strip() or DEFAULT_TEMPLATE, _start_id(start), ip, port,
            want_fp, want_cs, want_fm)
        removed = 0
        if dedup:
            lines, removed = dedup_configs(lines)
        left = Counter(lines)
        kept: list[dict] = []
        for name, line in names:
            if left[line] > 0:
                left[line] -= 1
                if not rename:   # links keep their own #name; report that one
                    name = unquote(urlsplit(line).fragment)
                kept.append({"name": name, "line": line})
        return {"lines": lines, "counts": counts, "removed": removed,
                "names": kept}

    @d.method("config.check_override")
    def config_check_override(ip: str = "", port: str = "") -> dict:
        """Classify a FORCE IP / FORCE PORT entry for live feedback.  ``ip``
        is ``ipv4``/``ipv6``/``domain``, ``""`` when empty, ``None`` when
        invalid; ``port`` is true/false, ``None`` when empty."""
        ip, port = _opt_str(ip, "ip"), _opt_str(port, "port")
        return {"ip": (classify_endpoint(ip) if ip else ""),
                "port": (valid_port(port) if port else None)}

    @d.method("config.tag_cc")
    def config_tag_cc(items: list) -> dict:
        """Append ``[CC]`` (exit country) to config names.  ``items`` is a
        list of ``{line, cc}``; the result keeps the same order."""
        if not isinstance(items, list) or len(items) > MAX_LINES:
            raise invalid_params(f"items must be a list (max {MAX_LINES})")
        res: list[dict] = []
        tagged = 0
        for it in items:
            if (not isinstance(it, dict) or not isinstance(it.get("line"), str)
                    or not isinstance(it.get("cc", ""), str)):
                raise invalid_params("each item needs a string line and cc")
            new, name, changed = tag_name_with_cc(it["line"], it.get("cc", ""))
            tagged += changed
            res.append({"line": new, "name": name, "changed": changed})
        return {"items": res, "tagged": tagged}

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
            lines, removed = mgr.combined_lines()
            return {"counts": counts, "total": len(lines), "removed": removed}
        return {"job": jobs.start("sub.fetch", run)}

    # -------------------------------------------------------------- health
    def _core_check(core: str | None) -> None:
        if core is not None and core != "auto" and get_core(core) is None:
            raise invalid_params(f"unknown core: {core}")
        if core:
            from xray_forge.engine.core_methods import installed_cores
            have = installed_cores()
            if core == "auto" and not have:
                raise invalid_params("no proxy core found; set a path in the Cores tab")
            if core != "auto" and core not in have:
                raise invalid_params(f"{core} not found; set its path in the Cores tab")

    def _hostname_opt(v: Any, what: str) -> str | None:
        """A DNS name for the fake SNI / fronting Host header (or empty/None)."""
        if v is None or v == "":
            return None
        if not isinstance(v, str) or len(v) > 253 or any(c.isspace() for c in v) \
                or "/" in v or ":" in v:
            raise invalid_params(f"{what} must be a plain host name")
        return v.strip().lower().rstrip(".") or None

    def _flag(v: Any, what: str) -> bool:
        if not isinstance(v, bool):
            raise invalid_params(f"{what} must be true or false")
        return v

    def _health_kwargs(fake_sni: Any, front_host: Any, record_frag: Any,
                       pad_hello: Any, frag_variants: Any) -> dict:
        """Validate the anti-DPI options shared by health.run and sub.check."""
        kw: dict = {}
        opts = hc.TlsOptions(_hostname_opt(fake_sni, "fake_sni"),
                             _flag(record_frag, "record_frag"), _flag(pad_hello, "pad_hello"),
                             _hostname_opt(front_host, "front_host"))
        if opts.active():
            kw["tls_opts"] = opts
        if frag_variants is not None:
            if (not isinstance(frag_variants, list) or not 1 <= len(frag_variants) <= 8
                    or not all(isinstance(x, str) and len(x) <= 64 for x in frag_variants)):
                raise invalid_params("frag_variants must be 1..8 short strings, e.g. [\"off\", \"5,94,1@2\"]")
            kw["frag_variants"] = tuple(x.strip() for x in frag_variants)
        return kw

    def _start_health(ls: list[str], workers: Any, timeout: Any,
                      throughput: bool, core: str | None,
                      probe_kw: dict | None = None) -> str:
        """Validate and start a health-check job over ``ls``; the reports are
        kept (last ``KEEP_RUNS`` runs) so best-N / tagged exports can use the
        engine's own scores instead of trusting the client."""
        if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 64:
            raise invalid_params("workers must be 1..64")
        _core_check(core)

        def run(ctx: JobContext) -> dict:
            total = len(ls)
            kept: list[hc.HealthReport] = []
            with runs_lock:
                runs[ctx.id] = kept
                while len(runs) > KEEP_RUNS:
                    runs.popitem(last=False)
            done = [0]
            lock = threading.Lock()

            def one(line: str) -> None:
                rep = hc.run_health_check(line, do_throughput=throughput,
                                          timeout=timeout, stop=ctx.stop, core=core,
                                          **(probe_kw or {}))
                row = dataclasses.asdict(rep)
                row["passed"] = rep.passed()
                with lock:
                    kept.append(rep)
                    done[0] += 1
                    ctx.item(row)
                    ctx.progress(done[0], total)

            from concurrent.futures import ThreadPoolExecutor
            ex = ThreadPoolExecutor(max_workers=workers)
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
            with lock:
                passed = sum(1 for r in kept if r.passed())
            return {"total": total, "passed": passed}
        return jobs.start("health.run", run)

    def _timeout(v: Any) -> float:
        return seconds(v, "timeout", 0.5, 120)

    def _stage_timeouts(v: Any) -> dict[str, float] | None:
        """``{"tcp": 3, "tls": 4, "transfer": 30, ...}``: per-stage overrides of ``timeout``."""
        if v is None:
            return None
        if not isinstance(v, dict):
            raise invalid_params("timeouts must be an object like {\"tcp\": 3, \"transfer\": 30}")
        bad = sorted(k for k in v if k not in hc.STAGE_TIMEOUT_KEYS)
        if bad:
            raise invalid_params(f"unknown stage {str(bad[0])[:30]!r} in timeouts; "
                                 f"use {', '.join(hc.STAGE_TIMEOUT_KEYS)}")
        return {k: seconds(x, f"timeouts.{k}", 0.5, 120) for k, x in v.items()} or None

    @d.method("health.run")
    def health_run(lines: list, workers: int = 8, timeout: float = 6.0,
                   throughput: bool = True, core: str | None = None,
                   fake_sni: Any = None, front_host: Any = None,
                   record_frag: Any = False, pad_hello: Any = False,
                   frag_variants: Any = None, timeouts: Any = None) -> dict:
        ls = _lines(lines)
        t = _timeout(timeout)
        kw = _health_kwargs(fake_sni, front_host, record_frag, pad_hello, frag_variants)
        stage_t = _stage_timeouts(timeouts)
        if stage_t:
            kw["timeouts"] = stage_t
        return {"job": _start_health(ls, workers, t, bool(throughput), core, kw)}

    @d.method("sub.check")
    def sub_check(workers: int = 8, timeout: float = 6.0,
                  throughput: bool = True, core: str | None = None,
                  fake_sni: Any = None, front_host: Any = None,
                  record_frag: Any = False, pad_hello: Any = False,
                  frag_variants: Any = None, timeouts: Any = None) -> dict:
        """Health-check the cached configs of every enabled subscription
        source (``sub.fetch`` fills the cache).  Same job as ``health.run``;
        the configs never cross the pipe."""
        lines, removed = src_mgr().combined_lines()
        if not lines:
            raise invalid_params("no cached configs: fetch the sources first")
        ls = _lines(lines)
        t = _timeout(timeout)
        kw = _health_kwargs(fake_sni, front_host, record_frag, pad_hello, frag_variants)
        stage_t = _stage_timeouts(timeouts)
        if stage_t:
            kw["timeouts"] = stage_t
        return {"job": _start_health(ls, workers, t, bool(throughput), core, kw),
                "total": len(ls), "removed": removed}

    def _run_reports(job: Any) -> list:
        if not isinstance(job, str):
            raise invalid_params("job must be a string")
        with runs_lock:
            kept = runs.get(job)
            snap = list(kept) if kept is not None else None
        if snap is None:
            raise invalid_params(
                f"no results for that run (the last {KEEP_RUNS} runs are kept)")
        return snap

    @d.method("health.export_best")
    def health_export_best(job: str, top_n: int = 10) -> dict:
        """Base64 subscription of the best ``top_n`` *working* configs of a
        health run (works on a finished, cancelled or still running job)."""
        if isinstance(top_n, bool) or not isinstance(top_n, int) or not 1 <= top_n <= 1000:
            raise invalid_params("top_n must be 1..1000")
        reports = _run_reports(job)
        content = hc.export_best_subscription(reports, top_n)
        count = len(base64.b64decode(content).decode().splitlines()) if content else 0
        return {"content": content, "count": count}

    @d.method("health.tagged")
    def health_tagged(job: str, min_score: float = 0.0) -> dict:
        """Working configs of a run, best first, each re-tagged with the
        anti-DPI techniques that worked, e.g. ``name [fragment:5,94,1@2]``."""
        if isinstance(min_score, bool) or not isinstance(min_score, (int, float)) \
                or not 0 <= min_score <= 100:
            raise invalid_params("min_score must be 0..100")
        return {"lines": hc.tagged_lines(_run_reports(job), float(min_score))}

    # ----------------------------------------------------------------- jobs
    @d.method("job.cancel")
    def job_cancel(job: str) -> bool:
        return jobs.cancel(job)

    @d.method("job.list")
    def job_list() -> list[str]:
        return jobs.active()

    from xray_forge.engine import scan_methods, core_methods, ui_methods, masque_methods, psiphon_methods
    scan_methods.register(d, jobs)
    core_methods.register(d)
    masque_methods.register(d, jobs)
    psiphon_methods.register(d, jobs)
    ui_methods.register(d)
    return d, jobs
