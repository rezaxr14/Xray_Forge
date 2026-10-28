"""
Staged health-check pipeline for subscription configs.

Stages (each can fail-fast and short-circuits the rest):

1. dns     — resolve the endpoint host via anti-hijack DoH
2. tcp     — TCP connect (latency + jitter)
3. tls     — TLS handshake, tried with several fragmentation variants;
             the variant that works is recorded as a *technique tag*
4. request — a real HTTP request through the tunnel
             (native VLESS/WS tunnel when possible, else SOCKS via a core)
5. download / upload — sustained throughput.  This matters because many
             Iranian networks throttle upload to foreign IPs: a config that
             passes a latency check can still be unusable (the reason
             Free-Configs tests configs locally instead of on GitHub).

Scoring is 0-100 with stage weights; :func:`rank_reports` sorts by score and
:func:`export_best_subscription` writes the top-N as a base64 subscription.
"""

from __future__ import annotations

import base64
import contextlib
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from xray_forge.core.models import Outbound
from xray_forge.core.parser import parse_target
from xray_forge.core.probe import (
    ProbeError, tcp_ping, tls_connect, parse_frag, ws_upgrade,
    VlessTunnel, tunnel_http_get, tunnel_http_post,
)
from xray_forge.core.cores.base import running_core
from xray_forge.core.socks import fetch_via_socks

# Stage weights (sum 100)
WEIGHTS = {"dns": 5, "tcp": 10, "tls": 20, "request": 30,
           "download": 20, "upload": 15}
DEFAULT_FRAG_VARIANTS = ("off", "5,94,1@2", "rand:1-16@2")


@dataclass(frozen=True)
class TlsOptions:
    """Optional anti-DPI tweaks for the *native* probes (ignored by core-backed
    checks, where the core builds its own TLS).

    * ``fake_sni``: name sent in the ClientHello instead of the real SNI.
    * ``record_frag``: split the handshake at TLS-record level too.
    * ``pad_hello``: pad the ClientHello (changes its size/shape).
    * ``front_host``: Host header for the WebSocket upgrade (domain fronting).
    """
    fake_sni: str | None = None
    record_frag: bool = False
    pad_hello: bool = False
    front_host: str | None = None

    def active(self) -> bool:
        return bool(self.fake_sni or self.record_frag or self.pad_hello or self.front_host)

    def tls_kwargs(self) -> dict:
        return {"fake_sni": self.fake_sni or None, "record_frag": self.record_frag,
                "pad_hello": self.pad_hello}
DEFAULT_TARGET = ("speed.cloudflare.com", 80, "/__down?bytes=524288")
DEFAULT_DOWNLOAD_BYTES = 262144
# Upload throttling kicks in after a burst, so the payload must be big enough
# to outlast socket buffers: 64 KiB measured nothing but the local send buffer.
DEFAULT_UPLOAD_BYTES = 1024 * 1024
MIN_FILL = 0.9      # a download that returns <90% of the bytes asked is a failure
# Request target for core-backed checks (also yields exit IP + country)
SOCKS_REQUEST_TARGET = ("ip-api.com", 80,
                        "/json?fields=status,countryCode,country,city,isp,query")


@dataclass
class StageResult:
    name: str
    ok: bool
    ms: float | None = None
    detail: str = ""
    data: dict = field(default_factory=dict)


@dataclass
class HealthReport:
    line: str
    name: str = ""
    scheme: str = ""
    endpoint: str = ""
    stages: list[StageResult] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    score: float = 0.0

    def stage(self, name: str) -> StageResult | None:
        for s in self.stages:
            if s.name == name:
                return s
        return None

    def passed(self) -> bool:
        req = self.stage("request")
        return bool(req and req.ok)

    def summary(self) -> str:
        parts = [f"{s.name}:{'ok' if s.ok else 'fail'}" for s in self.stages]
        tags = ",".join(self.techniques) if self.techniques else "-"
        return f"{self.name} score={self.score:.0f} [{tags}] {' '.join(parts)}"


# ===========================================================================
# Probes (module-level so tests can monkeypatch them)
# ===========================================================================

def probe_dns(host: str, timeout: float = 4.0) -> StageResult:
    import ipaddress
    literal = host.strip("[]")
    try:
        ipaddress.ip_address(literal)
    except ValueError:
        pass
    else:                                   # nothing to resolve: an IP literal is its own answer
        return StageResult("dns", True, ms=0.0, detail="ip literal", data={"ips": [literal]})
    from xray_forge.core.probe import doh_resolve
    t0 = time.perf_counter()
    try:
        ips = doh_resolve(host, timeout=timeout)
    except Exception as e:
        return StageResult("dns", False, detail=str(e)[:60])
    ms = (time.perf_counter() - t0) * 1000
    if ips:
        return StageResult("dns", True, ms=ms, data={"ips": ips[:3]})
    return StageResult("dns", False, ms=ms, detail="no answer (system fallback?)")


def probe_tcp(host: str, port: str, timeout: float = 5.0) -> StageResult:
    t0 = time.perf_counter()
    ms = tcp_ping(host, port, timeout=timeout, attempts=3)
    if ms is None:
        return StageResult("tcp", False, detail="connect failed/filtered")
    # jitter: stddev of two more connects
    samples = []
    for _ in range(2):
        m = tcp_ping(host, port, timeout=timeout, attempts=1)
        if m is not None:
            samples.append(m)
    jitter = (max(samples) - min([ms] + samples)) if samples else 0.0
    return StageResult("tcp", True, ms=ms,
                       data={"jitter": round(jitter, 1)})


def probe_tls(out: Outbound, frag_variants: tuple[str, ...] = DEFAULT_FRAG_VARIANTS,
              timeout: float = 6.0, stop=None, opts: TlsOptions | None = None):
    """Try TLS with each fragmentation variant.

    Returns ``(StageResult, (TLSClient, socket), technique_tag)``.  The session
    pair is ``(None, None)`` and the tag ``""`` when every variant failed; on
    success the caller owns (and must close) the socket.
    """
    sni = out.effective_sni
    last = StageResult("tls", False, detail="no fragmentation variants to try")
    for variant in frag_variants:
        frag = parse_frag(variant)
        try:
            tc, sock, info = tls_connect(out.host, out.port, sni=sni, frag=frag,
                                         timeout=timeout, stop=stop,
                                         **(opts.tls_kwargs() if opts else {}))
        except ProbeError as pe:
            last = StageResult("tls", False, detail=f"{variant}: {pe.detail[:40]}")
            continue
        tag = "fragment:" + variant if variant != "off" else "fragment:off"
        return StageResult("tls", True, ms=info.get("tls_ms"),
                           data={"variant": variant, "ver": info.get("ver", "")}), \
            (tc, sock), tag
    return last, (None, None), ""


def probe_request(out: Outbound, tc, sock, timeout: float = 8.0, stop=None,
                  opts: TlsOptions | None = None) -> StageResult:
    """Real request through the tunnel (native vless/ws only)."""
    if tc is None:
        return StageResult("request", False, detail="no tls session")
    if out.scheme != "vless" or out.transport != "ws":
        return StageResult("request", False,
                           detail=f"native tunnel unsupported for {out.scheme}/{out.transport}")
    try:
        line, ms = ws_upgrade(tc, out.host_header, out.path, timeout, stop,
                              front_domain=(opts.front_host if opts else None) or None)
    except ProbeError as pe:
        return StageResult("request", False, detail=f"{pe.stage}: {pe.detail[:40]}")
    ok = line.startswith("HTTP/1.1 101") or " 101 " in line
    return StageResult("request", ok, ms=ms, detail=line[:40])


def probe_request_socks(socks_port: int, timeout: float = 8.0, stop=None) -> StageResult:
    """Request stage through a running core's local SOCKS5 inbound.

    This is how every non-VLESS/WS protocol (trojan, vmess, ss, hysteria2,
    tuic, wireguard) gets checked: a real core binary runs the config and
    the request goes through it.  The geo response also yields the exit
    IP/country in ``data``.
    """
    try:
        ms, status, body = fetch_via_socks("127.0.0.1", socks_port,
                                           *SOCKS_REQUEST_TARGET, timeout=timeout)
    except Exception as e:
        return StageResult("request", False, detail=str(e)[:60])
    ok = status.startswith("HTTP/1.1 200") or " 200 " in status
    data: dict = {}
    try:
        d = json.loads(body.decode("utf-8", "replace"))
        cc = str(d.get("countryCode") or "")
        if len(cc) == 2 and cc.isalpha():
            data["cc"] = cc.upper()
            data["exit_ip"] = str(d.get("query") or "")
    except Exception:
        pass
    return StageResult("request", ok, ms=ms, detail=status[:40], data=data)


def _core_context(out: Outbound, core: str | None,
                  binary: str | None = None):
    """Context manager yielding a local SOCKS port for ``out`` via a real
    core, or ``None`` when no usable core is installed.

    ``core`` is a registered adapter name ("xray" | "singbox" | "mihomo")
    or ``"auto"`` (first installed core that supports the config).
    """
    if not core:
        return None
    from xray_forge.core.cores import get_core, iter_cores
    if core == "auto":
        candidates = iter_cores()
    else:
        adapter = get_core(core)
        candidates = [adapter] if adapter is not None else []
    for adapter in candidates:
        bin_path = binary or adapter.find_binary()
        if not bin_path or not adapter.supports(out):
            continue
        return running_core(adapter, [out], binary=bin_path)
    return None


def _http_ok(status: str) -> bool:
    parts = (status or "").split(" ", 2)
    return len(parts) > 1 and parts[1].startswith("2")


def native_tunnel_factory(out: Outbound, variant: str = "", timeout: float = 6.0,
                          stop=None, opts: TlsOptions | None = None):
    """Return ``make()`` -> (VlessTunnel, socket): a *fresh* TLS + WebSocket +
    VLESS session to the throughput target.

    One WebSocket carries exactly one VLESS connection (header sent once), so
    every throughput direction needs its own session -- reusing the one the
    request stage already used corrupts the stream.
    """
    host, port, _ = DEFAULT_TARGET

    def make():
        tc, sock, _info = tls_connect(out.host, out.port, sni=out.effective_sni,
                                      frag=parse_frag(variant) if variant else None,
                                      timeout=timeout, stop=stop,
                                      **(opts.tls_kwargs() if opts else {}))
        try:
            line, _ms = ws_upgrade(tc, out.host_header, out.path, timeout, stop,
                                   front_domain=(opts.front_host if opts else None) or None)
            if "101" not in line:
                raise ProbeError("ws", line[:40] or "no upgrade")
            return VlessTunnel(tc, out.credential, host, port, stop), sock
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise
    return make


def probe_throughput(out: Outbound, tc, sock, direction: str = "download",
                     bytes_count: int | None = None, timeout: float = 15.0,
                     stop=None, socks_port: int | None = None,
                     tunnel_factory=None) -> StageResult:
    """Measure download or upload through the tunnel (native or via socks).

    A stage only passes when the server answered 2xx *and* (download) returned
    at least ``MIN_FILL`` of the requested bytes.  ``tunnel_factory`` (see
    :func:`native_tunnel_factory`) supplies a fresh native session; without it
    the already-upgraded ``tc`` is used (valid for ONE direction only).
    """
    host, port, path = DEFAULT_TARGET
    if bytes_count is None:
        bytes_count = (DEFAULT_DOWNLOAD_BYTES if direction == "download"
                       else DEFAULT_UPLOAD_BYTES)
    if direction == "download":
        path = f"/__down?bytes={bytes_count}"
    native = out.scheme == "vless" and out.transport == "ws" and \
        (tc is not None or tunnel_factory is not None)
    extra_sock = None
    try:
        if native:
            if tunnel_factory is not None:
                tun, extra_sock = tunnel_factory()
            else:
                tun = VlessTunnel(tc, out.credential, host, port, stop)
            if direction == "download":
                ms, status, body = tunnel_http_get(tun, host, path, timeout, stop)
                got = len(body)
            else:
                ms, status, body = tunnel_http_post(tun, host, "/__up",
                                                    bytes_count, timeout, stop)
                got = bytes_count
        elif socks_port is not None:
            if direction == "download":
                ms, status, body = fetch_via_socks("127.0.0.1", socks_port, host,
                                                   port, path, timeout=timeout)
                got = len(body)
            else:
                ms, status, body = fetch_via_socks(
                    "127.0.0.1", socks_port, host, port, "/__up",
                    timeout=timeout, method="POST", body=b"x" * bytes_count)
                got = bytes_count
        else:
            return StageResult(direction, False, detail="no transport available")
    except ProbeError as pe:
        return StageResult(direction, False, detail=f"{pe.stage}: {pe.detail[:40]}")
    except Exception as e:
        return StageResult(direction, False, detail=str(e)[:60])
    finally:
        if extra_sock is not None:
            try:
                extra_sock.close()
            except Exception:
                pass
    if not _http_ok(status):
        return StageResult(direction, False, ms=ms,
                           detail=(status or "no response")[:40])
    if direction == "download" and got < bytes_count * MIN_FILL:
        return StageResult(direction, False, ms=ms,
                           detail=f"short body {got}/{bytes_count} bytes")
    if got == 0:
        return StageResult(direction, False, detail="0 bytes")
    bps = got / max(0.001, ms / 1000.0)
    return StageResult(direction, True, ms=ms,
                       data={"bytes": got, "bps": round(bps)})


# ===========================================================================
# Pipeline
# ===========================================================================

def score_report(report: HealthReport) -> float:
    total = 0.0
    for s in report.stages:
        w = WEIGHTS.get(s.name, 0)
        if s.ok:
            total += w
        elif s.name in ("download", "upload"):
            # throughput failures only lose their own weight
            pass
    # latency bonus: up to 10 points for a fast working tunnel
    req = report.stage("request")
    if req and req.ok and req.ms is not None:
        if req.ms < 300:
            total += 10
        elif req.ms < 800:
            total += 5
    return min(100.0, total)


STAGE_TIMEOUT_KEYS = ("dns", "tcp", "tls", "request", "transfer")
DEFAULT_DNS_TIMEOUT = 4.0


def run_health_check(line: str,
                     frag_variants: tuple[str, ...] = DEFAULT_FRAG_VARIANTS,
                     do_dns: bool = True,
                     do_throughput: bool = True,
                     timeout: float = 6.0,
                     stop=None,
                     socks_port: int | None = None,
                     upload_bytes: int = DEFAULT_UPLOAD_BYTES,
                     core: str | None = None,
                     core_binary: str | None = None,
                     tls_opts: TlsOptions | None = None,
                     timeouts: dict[str, float] | None = None) -> HealthReport:
    """Run the full staged pipeline for one share-link.

    ``timeout`` bounds every stage; ``timeouts`` overrides it per stage
    (keys ``dns``, ``tcp``, ``tls``, ``request``, ``transfer``; ``transfer``
    covers download and upload).  Without a ``dns`` entry the DNS stage keeps
    its own 4 s default.  ``tls`` applies to each fragmentation variant tried.

    ``core`` ("xray" | "singbox" | "mihomo" | "auto") enables core-backed
    checks: when the native tunnel can't run the protocol, the request and
    throughput stages go through a locally spawned core's SOCKS inbound
    instead of failing.
    """
    unknown = sorted(set(timeouts or {}) - set(STAGE_TIMEOUT_KEYS))
    if unknown:
        raise ValueError(f"unknown stage timeout {unknown[0]!r}; "
                         f"use one of {', '.join(STAGE_TIMEOUT_KEYS)}")
    st = {k: (timeouts or {}).get(k, timeout) for k in STAGE_TIMEOUT_KEYS}
    dns_timeout = (timeouts or {}).get("dns", DEFAULT_DNS_TIMEOUT)
    out = parse_target(line)
    if out is None:
        rep = HealthReport(line=line)
        rep.stages.append(StageResult("parse", False, detail="unparsable"))
        return rep
    rep = HealthReport(line=line, name=out.name, scheme=out.scheme,
                       endpoint=out.endpoint)
    if do_dns:
        rep.stages.append(probe_dns(out.host, timeout=dns_timeout))
    rep.stages.append(probe_tcp(out.host, out.port, timeout=st["tcp"]))
    tcp_ok = rep.stage("tcp") is not None and rep.stage("tcp").ok
    if tcp_ok:
        # short-circuit: no TCP, no point trying TLS/request/throughput
        extra = {"opts": tls_opts} if tls_opts is not None and tls_opts.active() else {}
        tls_res, (tc, sock), tag = probe_tls(out, frag_variants, timeout=st["tls"],
                                             stop=stop, **extra)
        if tag:
            rep.techniques.append(tag)
        rep.stages.append(tls_res)
        if tls_res.ok:
            core_ctx = _core_context(out, core, core_binary)
            socks = socks_port
            with contextlib.ExitStack() as stack:
                if core_ctx is not None:
                    try:
                        socks = stack.enter_context(core_ctx)
                    except Exception as e:  # core missing / died on start
                        rep.stages.append(StageResult(
                            "core", False, detail=str(e)[:60] or type(e).__name__))
                req_res = probe_request(out, tc, sock, timeout=st["request"], stop=stop, **extra)
                if not req_res.ok and socks is not None:
                    sres = probe_request_socks(socks, timeout=st["request"], stop=stop)
                    if sres.ok:
                        req_res = sres
                rep.stages.append(req_res)
                if do_throughput and req_res.ok:
                    factory = None
                    if out.scheme == "vless" and out.transport == "ws":
                        factory = native_tunnel_factory(
                            out, tls_res.data.get("variant", ""), st["transfer"], stop, **extra)
                    # download uses the session the request stage upgraded;
                    # upload gets its own fresh one (one VLESS conn per WS)
                    rep.stages.append(probe_throughput(out, tc, sock, "download",
                                                       timeout=st["transfer"], stop=stop,
                                                       socks_port=socks))
                    rep.stages.append(probe_throughput(out, tc, sock, "upload",
                                                       bytes_count=upload_bytes,
                                                       timeout=st["transfer"], stop=stop,
                                                       socks_port=socks,
                                                       tunnel_factory=factory))
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
    rep.score = score_report(rep)
    return rep


def run_health_checks(lines: list[str], workers: int = 8, progress=None,
                      stop=None, **kwargs) -> list[HealthReport]:
    """Run the pipeline over many configs in parallel.

    ``progress(done, total)`` fires as each report completes; ``stop`` is a
    :class:`threading.Event` that aborts result collection (in-flight probes
    still finish, bounded by their timeouts).
    """
    reports: list[HealthReport] = []
    if stop is not None:
        kwargs.setdefault("stop", stop)   # let in-flight probes abort too
    ex = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futs = {ex.submit(run_health_check, line, **kwargs): line for line in lines}
        done = 0
        for fut in as_completed(futs):
            if stop is not None and stop.is_set():
                break
            try:
                reports.append(fut.result())
            except Exception as e:
                rep = HealthReport(line=futs[fut])
                rep.stages.append(StageResult("error", False, detail=str(e)[:60]))
                reports.append(rep)
            done += 1
            if progress:
                progress(done, len(futs))
    finally:
        # Leaving a plain ``with`` block would wait for every *queued* probe
        # (minutes for big lists) even after the user pressed stop.
        ex.shutdown(wait=True,
                    cancel_futures=bool(stop is not None and stop.is_set()))
    return reports


def rank_reports(reports: list[HealthReport], top_n: int = 0) -> list[HealthReport]:
    """Sort by score desc, then by request latency asc. top_n=0 → all."""
    def key(r: HealthReport):
        req = r.stage("request")
        lat = req.ms if (req and req.ms is not None) else 1e9
        return (-r.score, lat)
    ordered = sorted(reports, key=key)
    return ordered[:top_n] if top_n > 0 else ordered


def export_best_subscription(reports: list[HealthReport], top_n: int = 10) -> str:
    """Base64 subscription of the best N working configs.

    Only configs that passed the request stage compete for the N slots: a
    failing config with a high partial score must not push a working one out.
    """
    best = rank_reports([r for r in reports if r.passed()], top_n)
    raw = "\n".join(r.line for r in best)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def tagged_lines(reports: list[HealthReport], min_score: float = 0.0) -> list[str]:
    """Working configs, best first, with the techniques that worked appended
    to the config *name*, e.g. ``name [fragment:5,94,1@2]``.  Only the name
    changes; the link itself is left intact."""
    from xray_forge.core.parser import append_name_suffix
    out: list[str] = []
    for r in rank_reports(reports):
        if r.score < min_score or not r.passed():
            continue
        line = r.line
        if r.techniques:
            line, _name, _changed = append_name_suffix(
                line, f" [{','.join(r.techniques)}]")
        out.append(line)
    return out
