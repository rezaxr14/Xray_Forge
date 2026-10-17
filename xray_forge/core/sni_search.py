"""
SNI / fronting-host search (Phase 4): probe candidate SNI names against
clean IPs.

You found a set of "clean" IPs (e.g. alive Cloudflare/Fastly edges from a
:class:`~xray_forge.core.scan_session.ScanSession`) — but a config is only
usable with an SNI the local censorship box lets through.  This module runs
the cartesian product *candidate SNI × clean IP* through fragmented TLS
handshakes and records which pairs complete:

* ``ok``       — the TLS handshake with that SNI succeeded on that IP
* ``http_ok``  — a plain ``GET /`` over the tunnel answered with ``HTTP/``
                 (a strong "fronting works here" signal)

Results persist under ``~/.xray_forge/sni_search/<name>.json`` and are
resumable across processes, mirroring :mod:`~xray_forge.core.scan_session`.
"""

from __future__ import annotations

import csv
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

from xray_forge.core.probe import ProbeError, tls_connect, parse_frag
from xray_forge.core.settings import data_dir

from xray_forge.core.log import get_logger

log = get_logger(__name__)

# Domains commonly seen as fronting/SNI candidates in public write-ups.
# The search tells you which of these your network actually lets through.
DEFAULT_SNI_CANDIDATES = [
    "www.speedtest.net",
    "letsencrypt.org",
    "www.bing.com",
    "www.yahoo.com",
    "player.vimeo.com",
    "www.wikipedia.org",
    "www.python.org",
    "dl.google.com",
    "www.microsoft.com",
    "www.cloudflare.com",
]


@dataclass
class SniHit:
    """One (ip, sni) probe outcome."""

    ip: str
    port: str
    sni: str
    ok: bool = False
    http_ok: bool = False
    tls_ms: float | None = None
    tls_ver: str = ""
    info: str = ""
    ts: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "SniHit":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


def _search_dir() -> str:
    path = os.path.join(data_dir(), "sni_search")
    os.makedirs(path, exist_ok=True)
    return path


class SniSearch:
    """One named SNI-search run with persistence and resume support."""

    def __init__(self, name: str, state_dir: str | None = None):
        self.name = name or "sni"
        self.state_dir = state_dir or _search_dir()
        os.makedirs(self.state_dir, exist_ok=True)
        self.state_path = os.path.join(self.state_dir, f"{self.name}.json")
        self.results: dict[tuple[str, str], SniHit] = {}
        self.pending: list[tuple[str, str]] = []
        self.port = "443"
        self._load()

    # ---------------------------------------------------------------- io
    def _load(self) -> None:
        if not os.path.isfile(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data.get("results", []):
                h = SniHit.from_dict(item)
                self.results[(h.ip, h.sni)] = h
            self.pending = [(ip, sni) for ip, sni in data.get("pending", [])]
            self.port = str(data.get("port") or "443")
        except (OSError, json.JSONDecodeError, ValueError) as e:
            log.warning("cannot load SNI session %s: %s", self.state_path, e)

    def save(self) -> None:
        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump({
                    "name": self.name,
                    "port": self.port,
                    "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "pending": [list(p) for p in self.pending],
                    "results": [h.to_dict() for h in self.results.values()],
                }, f, indent=1)
        except OSError as e:
            log.warning("cannot save SNI session %s: %s", self.state_path, e)

    # ------------------------------------------------------------- setup
    @staticmethod
    def parse_list(text: str) -> list[str]:
        """Comma / whitespace / newline separated entries, deduped."""
        out: list[str] = []
        seen: set[str] = set()
        for tok in (text or "").replace("\n", " ").replace(",", " ").split():
            tok = tok.strip()
            if tok and tok not in seen:
                seen.add(tok)
                out.append(tok)
        return out

    def set_targets(self, ips: list[str], snis: list[str], port: str = "443",
                    resume: bool = False) -> int:
        """Queue the (ip, sni) product. With resume=True, keep pending."""
        if resume and self.pending:
            return len(self.pending)
        self.port = port or "443"
        pairs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for ip in ips:
            for sni in snis:
                key = (ip, sni)
                if key in seen or key in self.results:
                    continue
                seen.add(key)
                pairs.append(key)
        self.pending = pairs
        self.save()
        return len(self.pending)

    # -------------------------------------------------------------- probe
    def probe(self, ip: str, sni: str, port: str = "443",
              frag: tuple | None = None, timeout: float = 5.0,
              http_check: bool = True,
              stop: threading.Event | None = None) -> SniHit:
        """One TLS handshake (+ optional GET) of ``sni`` against ``ip``."""
        hit = SniHit(ip=ip, port=port, sni=sni,
                     ts=time.strftime("%Y-%m-%dT%H:%M:%S"))
        try:
            tc, sock, info = tls_connect(ip, port, sni=sni, frag=frag,
                                         timeout=timeout, stop=stop)
            hit.ok = True
            hit.tls_ms = info["tls_ms"]
            hit.tls_ver = info["ver"]
            if http_check:
                deadline = time.perf_counter() + max(1.0, timeout)
                req = (f"GET / HTTP/1.1\r\nHost: {sni}\r\n"
                       "User-Agent: Mozilla/5.0 (XrayForge prober)\r\n"
                       "Accept: */*\r\nConnection: close\r\n\r\n")
                try:
                    tc.write(req.encode("ascii", "replace"))
                    data = tc.read(4096, deadline=deadline)
                    line = data.split(b"\r\n", 1)[0][:120]
                    hit.http_ok = line.startswith(b"HTTP/")
                    hit.info = line.decode("latin-1", "replace").strip()
                except ProbeError as pe:
                    hit.info = f"tls ok · http {pe.stage}: {pe.detail[:30]}"
            try:
                sock.close()
            except Exception:
                pass
        except ProbeError as pe:
            hit.info = f"{pe.stage}: {pe.detail[:40]}"
        except Exception as e:
            hit.info = f"err: {type(e).__name__}"
        return hit

    # -------------------------------------------------------------- scan
    def run(self, port: str = "443", workers: int = 32,
            frag: str = "5,94,1@2", timeout: float = 5.0,
            http_check: bool = True, stop: threading.Event | None = None,
            progress=None, batch_size: int = 10) -> list[SniHit]:
        """Probe all pending (ip, sni) pairs. Returns this run's hits."""
        frag_t = parse_frag(frag)
        self.port = port or self.port or "443"
        new: list[SniHit] = []
        todo = list(self.pending)
        stop = stop or threading.Event()

        def work(item: tuple[str, str]) -> SniHit:
            ip, sni = item
            if stop.is_set():
                return SniHit(ip=ip, port=self.port, sni=sni,
                              info="stopped")
            return self.probe(ip, sni, port=self.port, frag=frag_t,
                              timeout=timeout, http_check=http_check,
                              stop=stop)

        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futs = {ex.submit(work, item): item for item in todo}
            done = 0
            for fut in as_completed(futs):
                item = futs[fut]
                try:
                    hit = fut.result()
                except Exception:
                    continue
                if stop.is_set() and not hit.ok:
                    continue  # unscanned — stays pending
                self.results[item] = hit
                new.append(hit)
                if item in self.pending:
                    self.pending.remove(item)
                done += 1
                if progress:
                    progress(done, len(todo))
                if done % batch_size == 0:
                    self.save()
        self.save()
        return new

    # ------------------------------------------------------------- export
    def hits(self) -> list[SniHit]:
        """Working pairs first (http_ok > ok), then by latency."""
        out = [h for h in self.results.values() if h.ok]
        out.sort(key=lambda h: (not h.http_ok,
                                h.tls_ms if h.tls_ms is not None else 9e9))
        return out

    def export_csv(self, path: str) -> str:
        rows = sorted(self.results.values(),
                      key=lambda h: (h.ip, h.sni))
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "port", "sni", "ok", "http_ok", "tls_ms",
                        "tls_ver", "info", "ts"])
            for h in rows:
                w.writerow([h.ip, h.port, h.sni, int(h.ok), int(h.http_ok),
                            f"{h.tls_ms:.0f}" if h.tls_ms is not None else "",
                            h.tls_ver, h.info, h.ts])
        return path

    def export_json(self, path: str) -> str:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"name": self.name, "port": self.port,
                       "results": [h.to_dict() for h in
                                   sorted(self.results.values(),
                                          key=lambda h: (h.ip, h.sni))]},
                      f, indent=1)
        return path


def targets_from_scan(scan_name: str, state_dir: str | None = None,
                      max_ips: int = 100) -> list[str]:
    """Alive IPs of a saved scan session — the 'clean IP' input."""
    from xray_forge.core.scan_session import ScanSession
    s = ScanSession(scan_name, state_dir=state_dir)
    return [r.ip for r in s.alive()[:max_ips]]
