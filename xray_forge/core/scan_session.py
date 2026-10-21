"""
Resumable CIDR scan sessions with export and per-ISP persistence.

A :class:`ScanSession` scans sampled IPs from one or more CIDR ranges with a
thread pool, measures latency *and jitter*, optionally tags each alive IP
with country/ISP, and can be:

* interrupted (``stop`` event) and **resumed** later from its state file
* exported to CSV or JSON
* persisted per-ISP so repeated scans can be compared over time

State lives in ``~/.xray_forge/scans/<name>.json``.
"""

from __future__ import annotations

import csv
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass, field, asdict

from xray_forge.core.probe import ProbeError, tls_connect, parse_frag, curl_cffi_probe, HAS_CURL_CFFI
from xray_forge.core.scanner import sample_cidr, ip_meta, tcp_jitter
from xray_forge.core.fsutil import write_private
from xray_forge.core.settings import data_dir
from xray_forge.core.probe import tcp_ping

from xray_forge.core.log import get_logger

log = get_logger(__name__)


@dataclass
class ScanResult:
    ip: str
    port: str
    alive: bool
    ms: float | None = None
    jitter: float | None = None
    tls: str = ""
    cc: str = ""
    isp: str = ""
    info: str = ""
    ts: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


def _scans_dir() -> str:
    path = os.path.join(data_dir(), "scans")
    os.makedirs(path, exist_ok=True)
    return path


class ScanSession:
    """One named scan run with persistence and resume support."""

    def __init__(self, name: str, state_dir: str | None = None):
        self.name = name or "scan"
        self.state_dir = state_dir or _scans_dir()
        os.makedirs(self.state_dir, exist_ok=True)
        self.state_path = os.path.join(self.state_dir, f"{self.name}.json")
        self.results: dict[str, ScanResult] = {}
        self.pending: list[str] = []
        self._load()

    # ---------------------------------------------------------------- io
    def _load(self) -> None:
        if not os.path.isfile(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data.get("results", []):
                r = ScanResult.from_dict(item)
                self.results[r.ip] = r
            self.pending = list(data.get("pending", []))
        except (OSError, json.JSONDecodeError) as e:
            log.warning("cannot load scan session %s: %s", self.state_path, e)

    def save(self) -> None:
        """Write the state file atomically (temp file + rename): a crash or a
        full disk can no longer leave a half-written, unresumable session."""
        try:
            data = json.dumps({
                "name": self.name,
                "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "pending": self.pending,
                "results": [r.to_dict() for r in self.results.values()],
            }, indent=1)
            write_private(self.state_path, data, mode=0o644)
        except (OSError, ValueError, TypeError) as e:
            log.warning("cannot save scan session %s: %s", self.state_path, e)

    # ------------------------------------------------------------- setup
    def set_targets(self, cidrs: list[str], count: int = 200,
                    resume: bool = False) -> int:
        """Sample IPs from ranges. With resume=True, keep unscanned pending."""
        if resume and self.pending:
            return len(self.pending)
        ips: list[str] = []
        for cidr in cidrs:
            ips.extend(sample_cidr(cidr, count))
        seen: set[str] = set()
        fresh: list[str] = []
        for ip in ips:
            if ip not in seen and ip not in self.results:
                seen.add(ip)
                fresh.append(ip)
        self.pending = fresh
        self.save()
        return len(self.pending)

    # -------------------------------------------------------------- scan
    WINDOW_FACTOR = 4      # at most workers * 4 probes are submitted at any time

    def run(self, port: str = "443", workers: int = 64, frag: str = "5,94,1@2",
            sni: str | None = None, use_curl: bool = False,
            geo: bool = True, timeout: float = 5.0,
            stop: threading.Event | None = None,
            progress=None, batch_size: int = 10,
            on_result=None, tcp_timeout: float | None = None,
            tls_timeout: float | None = None, tcp_retries: int = 1,
            save_interval: float = 5.0) -> list[ScanResult]:
        """Scan pending IPs. Returns the new results from this run.

        ``on_result(ScanResult)`` fires as each IP completes (for live UIs).

        Built for large scans: only ``workers * 4`` probes are in flight at a
        time (no future per pending IP), ``stop`` cancels everything that has
        not started, and the state file is written at most every
        ``save_interval`` seconds (and every ``batch_size`` results) instead of
        after each batch.  ``tcp_timeout`` / ``tls_timeout`` bound the two
        stages separately and default to ``timeout``; ``tcp_retries`` is how
        many extra connects a host that never answered gets (0 = one try).
        """
        frag_t = parse_frag(frag)
        tcp_t = float(timeout if tcp_timeout is None else tcp_timeout)
        tls_t = float(timeout if tls_timeout is None else tls_timeout)
        stop = stop or threading.Event()
        new: list[ScanResult] = []

        def work(ip: str) -> ScanResult:
            res = ScanResult(ip=ip, port=port, alive=False,
                             ts=time.strftime("%Y-%m-%dT%H:%M:%S"))
            if stop.is_set():               # queued work that starts after stop bails out at once
                res.info = "stopped"
                return res
            try:
                best, jitter = tcp_jitter(ip, port, attempts=2, timeout=tcp_t,
                                          retries=tcp_retries, stop=stop)
            except Exception as e:
                res.info = f"err: {type(e).__name__}"
                return res
            res.ms, res.jitter = best, jitter
            if stop.is_set():
                res.info = "stopped"        # cut short: not a verdict, stays pending
                return res
            if best is None:
                res.info = "tcp filtered"
                return res
            try:
                if use_curl and HAS_CURL_CFFI:
                    info = curl_cffi_probe(ip, port, sni, timeout=tls_t)
                    res.alive = True
                    res.ms = info["tls_ms"]
                    res.tls = info["ver"]
                    res.info = f"curl_cffi {info['ver']}"
                else:
                    tc, sock, info = tls_connect(ip, port, sni=sni, frag=frag_t,
                                                 timeout=tls_t, stop=stop)
                    res.alive = True
                    res.ms = info["tls_ms"]
                    res.tls = info["ver"]
                    res.info = f"{info['ver']} tls ok"
                    try:
                        sock.close()
                    except Exception:
                        pass
            except ProbeError as pe:
                res.info = f"{pe.stage}: {pe.detail[:30]}"
            except Exception as e:
                res.info = f"err: {type(e).__name__}"
            if res.alive and geo:
                cc, isp = ip_meta(ip)
                res.cc, res.isp = cc, isp
            return res

        todo = list(self.pending)
        total = len(todo)
        done_ips: set[str] = set()
        queue = iter(todo)
        window = max(1, workers) * self.WINDOW_FACTOR
        inflight: dict = {}
        last_save = time.monotonic()
        unsaved = 0

        def sync_pending() -> None:
            if done_ips:
                self.pending = [ip for ip in self.pending if ip not in done_ips]
                done_ips.clear()

        def checkpoint() -> None:
            nonlocal last_save, unsaved
            sync_pending()
            self.save()
            last_save, unsaved = time.monotonic(), 0

        def top_up(ex) -> None:
            while len(inflight) < window and not stop.is_set():
                ip = next(queue, None)
                if ip is None:
                    return
                inflight[ex.submit(work, ip)] = ip

        def record(ip: str, res: ScanResult) -> None:
            nonlocal unsaved
            self.results[ip] = res
            done_ips.add(ip)
            new.append(res)
            unsaved += 1
            if on_result:
                try:
                    on_result(res)
                except Exception:
                    log.exception("on_result callback failed")
            if progress:
                progress(len(new), total)

        ex = ThreadPoolExecutor(max_workers=max(1, workers))
        try:
            top_up(ex)
            while inflight:
                finished, _ = wait(list(inflight), timeout=0.25, return_when=FIRST_COMPLETED)
                for fut in finished:
                    ip = inflight.pop(fut)
                    if fut.cancelled():
                        continue
                    try:
                        res = fut.result()
                    except Exception as e:      # work() catches its own; belt and braces
                        res = ScanResult(ip=ip, port=port, alive=False,
                                         info=f"err: {type(e).__name__}",
                                         ts=time.strftime("%Y-%m-%dT%H:%M:%S"))
                    if res.info == "stopped" and not res.alive:
                        continue                # interrupted mid-probe: stays pending
                    record(ip, res)
                    if (unsaved >= batch_size
                            and time.monotonic() - last_save >= save_interval):
                        checkpoint()
                if stop.is_set():
                    # queued probes are cancelled; running ones finish (bounded by
                    # their timeouts) and are collected below
                    ex.shutdown(wait=True, cancel_futures=True)
                    for fut, ip in list(inflight.items()):
                        if fut.cancelled() or not fut.done():
                            continue
                        try:
                            res = fut.result()
                        except Exception:
                            continue
                        if not (res.info == "stopped" and not res.alive):
                            record(ip, res)
                    inflight.clear()
                    break
                top_up(ex)
        finally:
            ex.shutdown(wait=True, cancel_futures=True)
            checkpoint()
        return new

    # ------------------------------------------------------------- export
    def alive(self) -> list[ScanResult]:
        out = [r for r in self.results.values() if r.alive]
        out.sort(key=lambda r: (r.ms if r.ms is not None else 9e9))
        return out

    def by_isp(self) -> dict[str, list[ScanResult]]:
        groups: dict[str, list[ScanResult]] = {}
        for r in self.alive():
            groups.setdefault(r.isp or "(unknown isp)", []).append(r)
        return groups

    def export_csv(self, path: str) -> str:
        rows = sorted(self.results.values(), key=lambda r: r.ip)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "port", "alive", "ms", "jitter", "tls", "cc",
                        "isp", "info", "ts"])
            for r in rows:
                w.writerow([r.ip, r.port, int(r.alive),
                            f"{r.ms:.0f}" if r.ms is not None else "",
                            f"{r.jitter:.0f}" if r.jitter is not None else "",
                            r.tls, r.cc, r.isp, r.info, r.ts])
        return path

    def export_json(self, path: str) -> str:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"name": self.name,
                       "results": [r.to_dict() for r in
                                   sorted(self.results.values(), key=lambda r: r.ip)]},
                      f, indent=1)
        return path


def load_session(name: str) -> ScanSession:
    """Load a previous session (resume) by name."""
    return ScanSession(name)
