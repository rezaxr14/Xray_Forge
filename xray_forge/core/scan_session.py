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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict

from xray_forge.core.probe import ProbeError, tls_connect, parse_frag, curl_cffi_probe, HAS_CURL_CFFI
from xray_forge.core.scanner import sample_cidr, ip_meta, tcp_jitter
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
        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump({
                    "name": self.name,
                    "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "pending": self.pending,
                    "results": [r.to_dict() for r in self.results.values()],
                }, f, indent=1)
        except OSError as e:
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
    def run(self, port: str = "443", workers: int = 64, frag: str = "5,94,1@2",
            sni: str | None = None, use_curl: bool = False,
            geo: bool = True, timeout: float = 5.0,
            stop: threading.Event | None = None,
            progress=None, batch_size: int = 10) -> list[ScanResult]:
        """Scan pending IPs. Returns the new results from this run."""
        frag_t = parse_frag(frag)
        new: list[ScanResult] = []

        def work(ip: str) -> ScanResult:
            res = ScanResult(ip=ip, port=port, alive=False,
                             ts=time.strftime("%Y-%m-%dT%H:%M:%S"))
            best, jitter = tcp_jitter(ip, port, attempts=2, timeout=timeout)
            res.ms, res.jitter = best, jitter
            if best is None:
                res.info = "tcp filtered"
                return res
            try:
                if use_curl and HAS_CURL_CFFI:
                    info = curl_cffi_probe(ip, port, sni, timeout=timeout)
                    res.alive = True
                    res.ms = info["tls_ms"]
                    res.tls = info["ver"]
                    res.info = f"curl_cffi {info['ver']}"
                else:
                    tc, sock, info = tls_connect(ip, port, sni=sni, frag=frag_t,
                                                 timeout=timeout, stop=stop)
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
        stop = stop or threading.Event()
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futs = {ex.submit(work, ip): ip for ip in todo}
            done = 0
            for fut in as_completed(futs):
                if stop.is_set():
                    break
                ip = futs[fut]
                try:
                    res = fut.result()
                except Exception:
                    continue
                self.results[ip] = res
                new.append(res)
                if ip in self.pending:
                    self.pending.remove(ip)
                done += 1
                if progress:
                    progress(done, len(todo))
                if done % batch_size == 0:
                    self.save()
        self.save()
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
