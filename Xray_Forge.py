#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
⚡ VLESS Forge — full xray config utility (single file, stdlib-only)

Modes      : ⚡ Full fix (fp+cs+fm) · 🎯 IP only (no injection) · 🛠 Custom
Tester     : fragmented ClientHello (DPI-proof), ws-101, REAL delay,
             exit country via tunnel geo (flag+CC, exit IP shown),
             fallback edge-IP geo marked '*'
🧩 Xray Core tab: point at any xray.exe (auto-detects v2rayN's), verify it,
             and run configs through REAL Xray-core via local SOCKS —
             handles trojan / odd UUIDs / impl quirks natively.
IP Finder  : CIDR scan w/ fragmented probes + SNI modes, anti-hijack DNS
             (DoH over IP-direct + Iranian resolvers), geo, exit-IP mapping.

Run:  python xray_util.py
CLI:  python xray_util.py in.txt out.txt [--ip IP] [--port P] [--ip-only]
      python xray_util.py in.txt --test [--core /path/to/xray] [--no-cc]
      python xray_util.py --scan 104.16.0.0/13 --sni edgestuff.pages.dev
      python xray_util.py --geo 1.2.3.4
"""

import argparse
import base64
import importlib.util
import ipaddress
import json
import os
import queue
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.request
import uuid as uuid_mod
from concurrent.futures import ThreadPoolExecutor
from tkinter import ttk, filedialog, messagebox, font as tkfont
from typing import Any, Literal
from urllib.parse import (urlsplit, urlunsplit, parse_qsl, urlencode,
                          quote, unquote)

TextState = Literal["normal", "disabled"]

# ===========================================================================
# Defaults
# ===========================================================================

DEFAULT_FP = "unsafe"

DEFAULT_CS = ":".join([
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
])

DEFAULT_FM = {
    "tcp": [
        {"type": "fragment",
         "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"],
                      "delays": ["0"], "maxSplit": "0"}},
        {"type": "fragment",
         "settings": {"packets": "1-1", "lengths": ["109", "1"],
                      "delays": ["1"], "maxSplit": "355"}},
    ]
}

DEFAULT_TEMPLATE = "{id:02d}_{sub}_{path}"
PROXY_SCHEMES = {"vless", "trojan"}
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

MODE_FULL = "⚡ Full fix   (fp→unsafe + cs + fm)"
MODE_IPONLY = "🎯 IP only   (no injection)"
MODE_CUSTOM = "🛠 Custom"
MODES = [MODE_FULL, MODE_IPONLY, MODE_CUSTOM]

CF_RANGES = [
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15",
    "198.41.128.0/17", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "131.0.72.0/22",
]

FRAG_PRESETS = ["5,94,1@2", "rand:8-32@3", "rand:1-16@2", "off"]
TEST_TARGET_DEFAULT = "http://www.gstatic.com/generate_204"

GEO_VIA_TUNNEL = [
    ("http", "ip-api.com",
     "/json/?fields=status,countryCode,country,city,isp,query"),
    ("https", "ipwho.is", "/"),
    ("https", "ipinfo.io", "/json"),
]

DOH_ENDPOINTS = [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/resolve",
    "https://free.shecan.ir/dns-query",
    "https://dns.403.online/dns-query",
]
_DOH_SERVERS = (("1.1.1.1", "/dns-query"), ("8.8.8.8", "/resolve"))
IRAN_UDP_RESOLVERS = [("178.22.122.100", "shecan"),
                      ("185.55.226.26", "begzar"),
                      ("10.202.10.202", "403online")]

HAS_CURL_CFFI = False
try:
    if importlib.util.find_spec("curl_cffi") is not None:
        HAS_CURL_CFFI = True
except Exception:
    HAS_CURL_CFFI = False


def compact_json(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def classify_endpoint(v: str) -> str | None:
    v = (v or "").strip()
    if not v:
        return None
    try:
        ipaddress.IPv4Address(v)
        return "ipv4"
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(v)
        return "ipv6"
    except ValueError:
        pass
    if re.fullmatch(r"(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}"
                    r"(?:\.(?!-)[A-Za-z0-9_-]{1,63})+\.?", v):
        return "domain"
    return None


def valid_port(v: str) -> bool:
    return v.isdigit() and 1 <= int(v) <= 65535


def fmt_ms(v: Any) -> str:
    if isinstance(v, (int, float)):
        return f"{v:.0f}"
    if isinstance(v, str) and v.strip() not in ("", "—"):
        return v
    return "—"


def cc_flag(cc: str) -> str:
    """2-letter code -> flag emoji. Windows shows letter pairs — read the CC."""
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c.upper()) - 65) for c in cc)


def cc_cell(cc: str, edge: bool) -> str:
    if not cc:
        return ""
    return f"{cc_flag(cc)} {cc}{'*' if edge else ''}"


# ===========================================================================
# Naming engine
# ===========================================================================

def sanitize(s: str, maxlen: int = 64) -> str:
    s = unquote(s or "")
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    s = re.sub(r"_{2,}", "_", s).strip("_.-")
    return s[:maxlen].strip("_.-")


def is_ip(host: str) -> bool:
    return bool(IPV4_RE.match(host or ""))


def split_netloc(netloc: str) -> tuple[str, str]:
    hostport = netloc.split("@", 1)[1] if "@" in netloc else netloc
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        return host, rest.lstrip(":")
    if ":" in hostport:
        host, _, port = hostport.rpartition(":")
        if port.isdigit():
            return host, port
    return hostport, ""


def build_netloc(userinfo: str, host: str, port: str) -> str:
    hostpart = f"[{host}]" if (":" in host and not host.startswith("[")) else host
    if port:
        hostpart = f"{hostpart}:{port}"
    return f"{userinfo}@{hostpart}" if userinfo else hostpart


def pick_domain(params: dict, netloc_host: str) -> str:
    for key in ("host", "sni"):
        v = params.get(key, "").strip()
        if v and not is_ip(v):
            return v
    for key in ("host", "sni"):
        v = params.get(key, "").strip()
        if v:
            return v
    return netloc_host or ""


def subdomain_of(host: str) -> str:
    host = (host or "").strip().strip(".").lower()
    if not host:
        return "host"
    if is_ip(host):
        return "ip"
    if ":" in host:
        return "v6"
    return sanitize(host.split(".")[0], 32) or "host"


def make_namer(template: str, start_id: int):
    used: set[str] = set()

    def name_for(i: int, params: dict, ip: str, port: str, scheme: str,
                 old_name: str) -> str:
        dom = pick_domain(params, ip)
        keys = {
            "id": start_id + i,
            "sub": subdomain_of(dom),
            "path": sanitize(params.get("path", "")),
            "ip": (ip or "").replace(":", "-").strip("[]"),
            "port": port or "",
            "host": sanitize(dom),
            "net": sanitize(".".join(dom.split(".")[1:]) if "." in dom else dom),
            "sni": sanitize(params.get("sni", "")),
            "proto": scheme or "vless",
            "old": sanitize(old_name, 32),
        }
        try:
            base = template.format(**keys)
        except Exception:
            base = f"{start_id + i:03d}_{keys['sub']}"
        base = sanitize(base, 80) or f"cfg_{start_id + i:03d}"
        cand = base
        if cand in used and keys["ip"]:
            cand = f"{base}_{keys['ip']}"
        n = 2
        while cand in used:
            cand = f"{base}_{n}"
            n += 1
        used.add(cand)
        return cand

    return name_for


def rename_fragment(line: str, suffix: str) -> str:
    parts = urlsplit(line)
    name = unquote(parts.fragment)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query,
                       quote(name + suffix, safe="")))


# ===========================================================================
# Core transformation — mode-aware
# ===========================================================================

def fix_uri(line: str, fp: str, cs: str, fm: str, tls_only: bool,
            rename: bool, namer, idx: int, ov_ip: str = "", ov_port: str = "",
            want_fp: bool = True, want_cs: bool = True,
            want_fm: bool = True):
    line = line.strip()
    if not line:
        return line, "blank", None
    try:
        parts = urlsplit(line)
    except ValueError:
        return line, "skipped", None
    if parts.scheme.lower() not in PROXY_SCHEMES or "@" not in parts.netloc:
        return line, "skipped", None
    try:
        params = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return line, "skipped", None

    pd: dict[str, str] = {}
    for k, v in params:
        pd.setdefault(k.lower(), v)

    inject: list[tuple[str, str]] = []
    if want_fp:
        inject.append(("fp", fp))
    if want_cs and cs:
        inject.append(("cs", cs))
    if want_fm and fm:
        inject.append(("fm", fm))
    injecting = bool(inject)

    security = pd.get("security")
    if injecting and tls_only and security is not None \
            and security.lower() != "tls":
        return line, "skipped", None

    old_name = unquote(parts.fragment)
    ip, port = split_netloc(parts.netloc)

    userinfo = parts.netloc.rsplit("@", 1)[0] if "@" in parts.netloc else ""
    eff_ip = ov_ip or ip
    eff_port = ov_port or port
    if ov_ip or ov_port:
        netloc = build_netloc(userinfo, eff_ip, eff_port)
    else:
        netloc, eff_ip, eff_port = parts.netloc, ip, port

    name = namer(idx, pd, eff_ip, eff_port, parts.scheme.lower(), old_name)

    if injecting:
        drop = {k for k, _ in inject}
        lower = [k.lower() for k, _ in params]
        if want_fp and "fp" in lower:
            at = lower.index("fp")
        else:
            anchor = max((i for i, k in enumerate(lower)
                          if k in ("sni", "security")), default=-1)
            at = anchor + 1
        out: list[tuple[str, str]] = []
        placed = False
        for i, (k, v) in enumerate(params):
            if i == at and not placed:
                out.extend(inject)
                placed = True
            if k.lower() in drop:
                continue
            out.append((k, v))
        if not placed:
            out.extend(inject)
        query = urlencode(out, quote_via=quote)
    else:
        query = parts.query          # IP-only: keep original query bytes

    frag = quote(name, safe="") if rename else parts.fragment
    new = urlunsplit((parts.scheme, netloc, parts.path, query, frag))
    return new, ("unchanged" if new == line else "fixed"), name


def convert_block(text: str, fp: str, cs: str, fm: str, tls_only: bool,
                  rename: bool, template: str, start_id: int,
                  ov_ip: str = "", ov_port: str = "",
                  want_fp: bool = True, want_cs: bool = True,
                  want_fm: bool = True):
    namer = make_namer(template, start_id)
    lines: list[str] = []
    names: list[tuple[str, str]] = []
    counts = {"fixed": 0, "unchanged": 0, "skipped": 0}
    idx = 0
    for raw in text.splitlines():
        if not raw.strip():
            continue
        idx += 1
        new, st, name = fix_uri(raw, fp, cs, fm, tls_only, rename, namer, idx,
                                ov_ip, ov_port, want_fp, want_cs, want_fm)
        if st in ("fixed", "unchanged"):
            counts[st] += 1
            lines.append(new)
            names.append((name or "", new))
        elif st == "skipped":
            counts["skipped"] += 1
            lines.append(raw.strip())
    return lines, names, counts


def parse_target(line: str) -> dict[str, str] | None:
    try:
        parts = urlsplit(line.strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in PROXY_SCHEMES or "@" not in parts.netloc:
        return None
    host, port = split_netloc(parts.netloc)
    if not host:
        return None
    pd: dict[str, str] = {}
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        pd.setdefault(k.lower(), v)
    sni = pd.get("sni", "") or pd.get("host", "") or host
    hdr = pd.get("host", "") or sni
    path = pd.get("path", "") or "/"
    if not path.startswith("/"):
        path = "/" + path
    name = unquote(parts.fragment) or f"{host}:{port}"
    uuid_s = unquote(parts.username or "")
    return {"name": name, "host": host, "port": port or "443", "sni": sni,
            "hdr": hdr, "path": path, "uuid": uuid_s}


# ===========================================================================
# Network layer — DPI-resistant probes
# ===========================================================================

class ProbeError(Exception):
    def __init__(self, stage: str, detail: str):
        super().__init__(f"{stage}: {detail}")
        self.stage = stage
        self.detail = detail


class _Done(Exception):
    pass


def _check(stop: threading.Event | None, deadline: float | None) -> None:
    if stop is not None and stop.is_set():
        raise ProbeError("io", "stopped")
    if deadline is not None and time.perf_counter() >= deadline:
        raise ProbeError("io", "timeout")


def human_ssl_error(e: Exception) -> str:
    s = str(e)
    if "WRONG_VERSION_NUMBER" in s:
        return "non-TLS answer (wrong port / DPI injection)"
    if "SSLV3_ALERT" in s:
        return "TLS alert from server"
    if "UNEXPECTED_RECORD" in s:
        return "garbage instead of TLS (DPI)"
    if "EOF" in s:
        return "closed mid-handshake (DPI RST?)"
    return (s.split("[")[0].strip() or "ssl error")[:60]


def oserr_text(e: Exception) -> str:
    if isinstance(e, PermissionError):
        return "permission denied"
    s = str(e)
    if "Network is unreachable" in s:
        return "network unreachable"
    if "timed out" in s:
        return "timeout"
    return type(e).__name__


def parse_frag(s: str) -> tuple | None:
    s = (s or "").strip().lower()
    if not s or s in ("off", "none", "-"):
        return None
    delay = 2.0
    if "@" in s:
        s, _, d = s.partition("@")
        try:
            delay = max(0.0, float(d))
        except ValueError:
            pass
    if s.startswith("rand"):
        m = re.search(r"(\d+)\s*-\s*(\d+)", s)
        lo, hi = (int(m.group(1)), int(m.group(2))) if m else (1, 16)
        return ("rand", lo, hi, delay)
    sizes = [int(x) for x in re.findall(r"\d+", s)] or [5, 94, 1]
    return ("list", sizes, delay)


def send_fragmented(send, data: bytes, frag: tuple) -> None:
    kind = frag[0]
    if kind == "list":
        sizes: list[int] = frag[1]
        delay = frag[2]
        off, i = 0, 0
        while off < len(data):
            n = sizes[i] if i < len(sizes) else len(data) - off
            chunk = data[off:off + n]
            send(chunk)
            off += len(chunk)
            i += 1
            if off < len(data) and delay:
                time.sleep(delay / 1000.0)
    else:
        lo: int = frag[1]
        hi: int = frag[2]
        delay = frag[3]
        off = 0
        while off < len(data):
            n = random.randint(max(1, lo), max(lo, hi))
            chunk = data[off:off + n]
            send(chunk)
            off += len(chunk)
            if off < len(data) and delay:
                time.sleep(delay / 1000.0)


def sock_send(sock: socket.socket):
    return lambda data: sock.sendall(data)


def sock_recv(sock: socket.socket, stop: threading.Event | None):
    def recv(deadline: float | None) -> bytes:
        while True:
            _check(stop, deadline)
            rem = (deadline - time.perf_counter()) if deadline else 10.0
            if rem <= 0:
                raise ProbeError("io", "timeout waiting for server")
            sock.settimeout(min(rem, 10.0))
            try:
                return sock.recv(65536)
            except socket.timeout:
                raise ProbeError("io", "timeout waiting for server")
            except (ConnectionResetError, ConnectionAbortedError):
                raise ProbeError("io", "RST (DPI/firewall reset)")
            except OSError as e:
                raise ProbeError("io", oserr_text(e))
    return recv


class TLSClient:
    """TLS over any byte transport, with ClientHello FRAGMENTATION
    (stdlib equivalent of Xray's fm= fragment mask)."""

    def __init__(self, send, recv, sni: str | None = None,
                 ciphers: str | None = None, frag: tuple | None = None,
                 stop: threading.Event | None = None, hs_timeout: float = 5.0):
        self._send = send
        self._recv = recv
        self._stop = stop
        self._frag = frag
        self._dl = time.perf_counter() + max(0.5, hs_timeout)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        if ciphers:
            try:
                ctx.set_ciphers(ciphers)
            except ssl.SSLError:
                pass
        self.inb = ssl.MemoryBIO()
        self.outb = ssl.MemoryBIO()
        if sni:
            self.obj = ctx.wrap_bio(self.inb, self.outb, server_hostname=sni)
        else:
            self.obj = ctx.wrap_bio(self.inb, self.outb)
        self._handshake()

    def _handshake(self) -> None:
        first = True
        while True:
            _check(self._stop, self._dl)
            try:
                self.obj.do_handshake()
                return
            except ssl.SSLWantReadError:
                self._flush(self._frag if first else None)
                first = False
                try:
                    data = self._recv(self._dl)
                except ProbeError as pe:
                    raise ProbeError("tls", pe.detail)
                if not data:
                    raise ProbeError("tls", "closed during handshake (EOF)")
                self.inb.write(data)
            except ssl.SSLWantWriteError:
                self._flush(None)
            except ssl.SSLError as e:
                raise ProbeError("tls", human_ssl_error(e))

    def _flush(self, frag: tuple | None) -> None:
        while True:
            data = self.outb.read()
            if not data:
                break
            if frag:
                send_fragmented(self._send, data, frag)
            else:
                self._send(data)

    def write(self, data: bytes) -> None:
        self.obj.write(data)
        self._flush(None)

    def read(self, n: int = 16384, deadline: float | None = None) -> bytes:
        dl = deadline if deadline is not None else self._dl
        while True:
            _check(self._stop, dl)
            try:
                return self.obj.read(n)
            except ssl.SSLZeroReturnError:
                return b""
            except ssl.SSLWantReadError:
                data = self._recv(dl)
                if not data:
                    raise ProbeError("io", "connection closed")
                self.inb.write(data)
            except ssl.SSLWantWriteError:
                self._flush(None)
            except ssl.SSLError as e:
                raise ProbeError("io", human_ssl_error(e))


def tls_connect(host: str, port: str, sni: str | None = None,
                frag: tuple | None = None, timeout: float = 5.0,
                stop: threading.Event | None = None,
                ciphers: str | None = None):
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
    except socket.timeout:
        raise ProbeError("tcp", "timeout (filtered or dead)")
    except (ConnectionResetError, ConnectionAbortedError):
        raise ProbeError("tcp", "reset during connect")
    except OSError as e:
        raise ProbeError("tcp", oserr_text(e))
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        tc = TLSClient(sock_send(sock), sock_recv(sock, stop), sni=sni,
                       ciphers=ciphers, frag=frag, stop=stop,
                       hs_timeout=max(0.5, timeout))
        info: dict[str, Any] = {
            "tls_ms": (time.perf_counter() - t0) * 1000,
            "ver": tc.obj.version() or "tls",
        }
        return tc, sock, info
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def tcp_ping(host: str, port: str, timeout: float = 3.0, attempts: int = 2,
             stop: threading.Event | None = None) -> float | None:
    best: float | None = None
    for _ in range(max(1, attempts)):
        if stop is not None and stop.is_set():
            break
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((host, int(port)), timeout=timeout)
            s.close()
        except OSError:
            return None
        ms = (time.perf_counter() - t0) * 1000
        best = ms if best is None else min(best, ms)
    return best


# ---- minimal WebSocket ------------------------------------------------------

def ws_frame(opcode: int, payload: bytes) -> bytes:
    mask = os.urandom(4)
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    else:
        head += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return head + mask + masked


def ws_send(stream: TLSClient, payload: bytes, opcode: int = 0x2) -> None:
    stream.write(ws_frame(opcode, payload))


def ws_recv_frame(stream: TLSClient, deadline: float | None,
                  stop: threading.Event | None):
    def exact(k: int) -> bytes:
        buf = b""
        while len(buf) < k:
            _check(stop, deadline)
            d = stream.read(k - len(buf), deadline=deadline)
            if not d:
                raise ProbeError("ws", "connection closed")
            buf += d
        return buf

    h = exact(2)
    op = h[0] & 0x0F
    ln = h[1] & 0x7F
    if ln == 126:
        ln = int.from_bytes(exact(2), "big")
    elif ln == 127:
        ln = int.from_bytes(exact(8), "big")
    if h[1] & 0x80:
        exact(4)
    payload = exact(ln) if ln else b""
    return op, payload


def ws_upgrade(tc: TLSClient, host_hdr: str, path: str, timeout: float,
               stop: threading.Event | None):
    deadline = time.perf_counter() + timeout
    key = base64.b64encode(os.urandom(16)).decode()
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
           ) % (path or "/", host_hdr or "localhost", key)
    t0 = time.perf_counter()
    tc.write(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 16384:
        _check(stop, deadline)
        d = tc.read(4096, deadline=deadline)
        if not d:
            break
        buf += d
    line = buf.split(b"\r\n", 1)[0].decode("latin1", "replace").strip()
    return (line or "no response"), (time.perf_counter() - t0) * 1000


# ---- real VLESS tunnel ------------------------------------------------------

class VlessTunnel:
    def __init__(self, tc: TLSClient, uuid_s: str, host: str, port,
                 stop: threading.Event | None):
        u = (uuid_s or "").strip()
        try:
            uid = uuid_mod.UUID(u).bytes
        except Exception:
            raise ProbeError("vless", "not a vless UUID (trojan/password/empty)")
        hdr = b"\x00" + bytes([16]) + uid + b"\x00" + b"\x01" \
            + int(port).to_bytes(2, "big")
        if IPV4_RE.match(host):
            hdr += b"\x01" + socket.inet_aton(host)
        else:
            hb = host.encode()
            hdr += b"\x02" + bytes([len(hb)]) + hb
        ws_send(tc, hdr)
        self.tc = tc
        self.stop = stop
        self._hdr_done = False

    def send(self, data: bytes) -> None:
        if data:
            ws_send(self.tc, data)

    def recv(self, deadline: float | None) -> bytes:
        while True:
            op, pl = ws_recv_frame(self.tc, deadline, self.stop)
            if op == 0x8:
                raise ProbeError("vless", "server closed (uuid/path rejected?)")
            if op == 0x9:
                ws_send(self.tc, b"", opcode=0xA)
                continue
            if op not in (0x0, 0x2):
                continue
            if not self._hdr_done:
                if len(pl) < 2 or pl[0] != 0:
                    raise ProbeError("vless", "bad vless reply header")
                pl = pl[2 + pl[1]:]
                self._hdr_done = True
                if not pl:
                    continue
            return pl


# ---- tiny HTTP client over any recv/send pair --------------------------------

def _dechunk(body: bytes, recv, deadline: float | None,
             stop: threading.Event | None) -> bytes:
    out = b""
    while True:
        while b"\r\n" not in body:
            _check(stop, deadline)
            d = recv(deadline)
            if not d:
                return out
            body += d
        line, _, body = body.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            return out
        if size == 0:
            return out
        while len(body) < size + 2:
            _check(stop, deadline)
            d = recv(deadline)
            if not d:
                return out
            body += d
        out += body[:size]
        body = body[size + 2:]


def _read_http(recv, deadline: float | None, stop: threading.Event | None):
    buf = b""
    while b"\r\n\r\n" not in buf:
        _check(stop, deadline)
        d = recv(deadline)
        if not d:
            break
        buf += d
        if len(buf) > 262144:
            break
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin1", "replace").split("\r\n")
    status = lines[0].strip() if lines else ""
    hdrs: dict[str, str] = {}
    for l in lines[1:]:
        if ":" in l:
            k, _, v = l.partition(":")
            hdrs[k.strip().lower()] = v.strip()
    body = rest
    cl = hdrs.get("content-length")
    if cl and cl.isdigit():
        need = int(cl)
        while len(body) < need:
            _check(stop, deadline)
            d = recv(deadline)
            if not d:
                break
            body += d
        body = body[:need]
    elif "chunked" in hdrs.get("transfer-encoding", "").lower():
        body = _dechunk(body, recv, deadline, stop)
    return {"status": status, "body": body}


def tunnel_http_get(tun: "VlessTunnel", host: str, path: str,
                    timeout: float, stop: threading.Event | None):
    deadline = time.perf_counter() + timeout
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
           f"Connection: close\r\n\r\n").encode()
    t0 = time.perf_counter()
    tun.send(req)
    raw = _read_http(tun.recv, deadline, stop)
    ms = (time.perf_counter() - t0) * 1000
    return ms, raw["status"], raw["body"]


def tunnel_https_get(tun: "VlessTunnel", host: str, path: str,
                     timeout: float, stop: threading.Event | None):
    deadline = time.perf_counter() + timeout
    inner = TLSClient(tun.send, lambda dl: tun.recv(dl), sni=host, stop=stop,
                      hs_timeout=max(1.0, deadline - time.perf_counter()))
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
           f"Connection: close\r\n\r\n").encode()
    t0 = time.perf_counter()
    inner.write(req)
    raw = _read_http(lambda dl: inner.read(65536, deadline=dl), deadline, stop)
    ms = (time.perf_counter() - t0) * 1000
    return ms, raw["status"], raw["body"]


def real_delay_http(tun: "VlessTunnel", host: str, path: str,
                    timeout: float, stop: threading.Event | None):
    ms, status, _body = tunnel_http_get(tun, host, path, timeout, stop)
    return ms, (status or "empty reply")


def real_delay_https(tun: "VlessTunnel", host: str, port, path: str,
                     timeout: float, stop: threading.Event | None):
    ms, status, _body = tunnel_https_get(tun, host, path, timeout, stop)
    return ms, (status or "empty reply")


def parse_test_target(s: str):
    s = (s or "").strip() or TEST_TARGET_DEFAULT
    if "://" not in s:
        s = "http://" + s
    p = urlsplit(s)
    sch = p.scheme.lower() or "http"
    host = p.hostname or "www.gstatic.com"
    port = p.port or (443 if sch == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return sch, host, port, path


# ---- exit-country detection (through the tunnel) ------------------------------

def _geo_detail(d: dict) -> str:
    conn = d.get("connection") if isinstance(d.get("connection"), dict) else {}
    parts = [
        str(d.get("city") or ""),
        str(d.get("isp") or d.get("org") or conn.get("isp")
            or conn.get("org") or ""),
        str(d.get("query") or d.get("ip") or ""),
    ]
    return " · ".join(p for p in parts if p)[:44]


def _cc_from_geo(d: Any, status: str) -> tuple[str, str, str]:
    """-> (country_code, exit_ip, detail)."""
    if not isinstance(d, dict):
        return "", "", (status or "bad geo reply")[:40]
    ip = str(d.get("query") or d.get("ip") or "")
    cc = d.get("countryCode") or d.get("country_code") or d.get("country")
    if isinstance(cc, str) and len(cc) == 2 and cc.isalpha():
        return cc.upper(), ip, _geo_detail(d)
    if d.get("status") == "fail":
        return "", ip, str(d.get("message") or "geo refused")[:40]
    return "", ip, (status or "no country in reply")[:40]


def probe_geo_source(t: dict, tc: TLSClient | None, sock: socket.socket | None,
                     sni: str | None, frag: tuple | None, sch: str,
                     ghost: str, gpath: str, timeout: float,
                     stop: threading.Event | None):
    """One geo source through the vless pipe. -> (cc, exit_ip, detail, ms)."""
    owns = False
    if tc is None:
        tc, sock, _info = tls_connect(t["host"], t["port"], sni=sni, frag=frag,
                                      timeout=timeout, stop=stop)
        owns = True
    try:
        gport = 80 if sch == "http" else 443
        tun = VlessTunnel(tc, t.get("uuid", ""), ghost, gport, stop)
        if sch == "http":
            ms, status, body = tunnel_http_get(tun, ghost, gpath, timeout, stop)
        else:
            ms, status, body = tunnel_https_get(tun, ghost, gpath, timeout,
                                                stop)
        try:
            d = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            d = None
        cc, ip, detail = _cc_from_geo(d, status)
        if cc:
            return cc, ip, detail, ms
        raise ProbeError("geo", detail or "no country")
    finally:
        if owns:
            try:
                sock.close()
            except Exception:
                pass


def rotated_geo(start: int):
    n = len(GEO_VIA_TUNNEL)
    k = start % n
    return GEO_VIA_TUNNEL[k:] + GEO_VIA_TUNNEL[:k]


# ---- anti-DPI direct fetching (DoH over IP-direct + fragmented hello) ---------

def doh_resolve(host: str, timeout: float = 4.0) -> list[str]:
    """A-records via DoH over IP-direct, no-SNI, FRAGMENTED TLS.
    Immune to DNS poisoning and to SNI-reading DPI."""
    for srv, path0 in _DOH_SERVERS:
        try:
            tc, sock, _ = tls_connect(srv, "443", sni=None,
                                      frag=parse_frag("rand:1-16@1"),
                                      timeout=timeout)
            try:
                req = (f"GET {path0}?name={quote(host)}&type=A HTTP/1.1\r\n"
                       f"Host: {srv}\r\naccept: application/dns-json\r\n"
                       f"User-Agent: vless-forge\r\nConnection: close\r\n\r\n")
                tc.write(req.encode())
                raw = _read_http(lambda dl: tc.read(65536, deadline=dl),
                                 time.perf_counter() + timeout, None)
                d = json.loads(raw["body"].decode("utf-8", "replace"))
                ans = [a["data"] for a in (d.get("Answer") or [])
                       if a.get("type") == 1]
                if ans:
                    return ans
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        except Exception:
            continue
    return []


def direct_get_json(url_str: str, timeout: float = 6.0):
    """HTTP(S) GET with DoH-resolved IP-direct connect + fragmented TLS
    hello — the Iran-proof version of urllib."""
    p = urlsplit(url_str)
    sch = p.scheme.lower()
    host = p.hostname or ""
    port = p.port or (443 if sch == "https" else 80)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    ips = doh_resolve(host, timeout) or resolve_domain(host)
    if not ips:
        raise ProbeError("dns", f"cannot resolve {host}")
    last = ""
    for ip in ips[:2]:
        try:
            if sch == "https":
                sni = None if (is_ip(host) or not host) else host
                tc, sock, _ = tls_connect(ip, str(port), sni=sni,
                                          frag=parse_frag("rand:1-16@1"),
                                          timeout=timeout)
                try:
                    raw = _read_http(lambda dl: tc.read(65536, deadline=dl),
                                     time.perf_counter() + timeout, None)
                finally:
                    sock.close()
            else:
                s = socket.create_connection((ip, port), timeout=timeout)
                try:
                    s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                               f"User-Agent: vless-forge\r\n"
                               f"Connection: close\r\n\r\n").encode())
                    raw = _read_http(sock_recv(s, None),
                                     time.perf_counter() + timeout, None)
                finally:
                    s.close()
            code = raw["status"].split(" ")[1] if " " in raw["status"] else ""
            if code.startswith("2") or code in ("301", "302"):
                return json.loads(raw["body"].decode("utf-8", "replace"))
            last = raw["status"]
        except Exception as e:
            last = str(e)
    raise ProbeError("geo", f"direct fetch failed: {last[:44]}")


def fetch_json(url: str, timeout: float = 8.0):
    """Robust: anti-DPI direct path first, urllib as fallback."""
    try:
        return direct_get_json(url, timeout=timeout)
    except Exception:
        req = urllib.request.Request(
            url, headers={"User-Agent": "vless-forge/1.0",
                          "accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))


# ---- optional chrome-impersonation probe --------------------------------------

def curl_cffi_probe(ip: str, port: str, sni: str | None, timeout: float = 4.0):
    if not HAS_CURL_CFFI:
        raise ProbeError("tls", "curl_cffi not installed")
    try:
        creq = importlib.import_module("curl_cffi.requests")
        curl_mod = importlib.import_module("curl_cffi.const")
        CurlOpt = curl_mod.CurlOpt
        host = sni or ip
        t0 = time.perf_counter()
        sess = creq.Session(impersonate="chrome")
        try:
            sess.curl.setopt(CurlOpt.RESOLVE, [f"{host}:{port}:{ip}"])
            r = sess.get(f"https://{host}:{port}/", timeout=timeout,
                         verify=False, allow_redirects=False)
            ver = getattr(r, "http_version", "") or "chrome-hello"
            return {"tls_ms": (time.perf_counter() - t0) * 1000,
                    "ver": str(ver).replace("HTTP/", "")[:9]}
        finally:
            sess.close()
    except ProbeError:
        raise
    except Exception as e:
        raise ProbeError("tls", f"curl: {type(e).__name__}")


# ===========================================================================
# DNS (anti-hijack), direct-IP geo, geo lookup
# ===========================================================================

def resolve_domain(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def udp_dns_a(name: str, server: str, timeout: float = 3.0) -> list[str]:
    tid = os.urandom(2)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".") if l) \
        + b"\x00"
    pkt = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q \
        + b"\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    if len(data) < 12 or data[:2] != tid:
        return []
    qd = int.from_bytes(data[4:6], "big")
    an = int.from_bytes(data[6:8], "big")
    off = 12
    for _ in range(qd):
        while off < len(data) and data[off] != 0:
            off += data[off] + 1
        off += 5
    ips: list[str] = []
    for _ in range(an):
        if off >= len(data):
            break
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += data[off] + 1
            off += 1
        typ = int.from_bytes(data[off:off + 2], "big")
        off += 8
        rdl = int.from_bytes(data[off:off + 2], "big")
        off += 2
        if typ == 1 and rdl == 4:
            ips.append(socket.inet_ntoa(data[off:off + 4]))
        off += rdl
    return ips


def resolve_dns_all(host: str) -> dict[str, list[str]]:
    found: dict[str, set[str]] = {}

    def add(ip: str, src: str) -> None:
        if ip:
            found.setdefault(ip, set()).add(src)

    for ep in DOH_ENDPOINTS:
        label = "DoH:" + urlsplit(ep).netloc
        try:
            d = fetch_json(f"{ep}?name={quote(host)}&type=A", timeout=5)
        except Exception:
            continue
        ans = [a["data"] for a in (d.get("Answer") or [])
               if a.get("type") == 1]
        if ans:
            for ip in ans:
                add(ip, label)
            break
    for srv, label in IRAN_UDP_RESOLVERS:
        try:
            ips = udp_dns_a(host, srv)
        except Exception:
            continue
        for ip in ips:
            add(ip, label)
        if ips:
            break
    for ip in resolve_domain(host):
        add(ip, "system")
    return {ip: sorted(srcs) for ip, srcs in found.items()}


_CC_CACHE: dict[str, str] = {}
_CC_LOCK = threading.Lock()


def cc_of_ip(ip: str, timeout: float = 4.0) -> str:
    """Country of an IP via direct lookup (EDGE approximation — marked '*')."""
    if not ip:
        return ""
    with _CC_LOCK:
        if ip in _CC_CACHE:
            return _CC_CACHE[ip]
    cc = ""
    for url in (f"http://ip-api.com/json/{ip}?fields=countryCode",
                f"https://ipwho.is/{ip}"):
        try:
            d = fetch_json(url, timeout=timeout)
        except Exception:
            continue
        if isinstance(d, dict):
            v = d.get("countryCode") or d.get("country_code")
            if isinstance(v, str) and len(v) == 2 and v.isalpha():
                cc = v.upper()
                break
    with _CC_LOCK:
        _CC_CACHE[ip] = cc
    return cc


def fmt_geo(d: Any) -> str:
    if not isinstance(d, dict):
        return str(d)[:200]

    def as_str(v: Any) -> str:
        if isinstance(v, dict):
            return str(v.get("id") or v.get("name") or v.get("timezone") or "")
        if v is None:
            return ""
        return str(v)

    ip = as_str(d.get("ip") or d.get("query")) or "?"
    place = ", ".join(as_str(d[k]) for k in ("city", "region", "regionName",
                                             "country", "country_name")
                      if d.get(k))
    org = as_str(d.get("org")) or as_str(d.get("as"))
    if not org:
        c = d.get("connection")
        if isinstance(c, dict):
            org = as_str(c.get("isp")) or as_str(c.get("org")) \
                or as_str(c.get("asn"))
    tz = as_str(d.get("timezone"))
    s = ip + (f"  —  {place}" if place else "")
    extra = [x for x in (org, tz) if x]
    if extra:
        s += "\n" + "   ·   ".join(extra)
    return s


def geo_lookup(ip: str = "") -> str:
    urls = [f"https://ipwho.is/{ip}".rstrip("/"),
            f"http://ip-api.com/json/{ip}?fields=query,country,city,"
            f"regionName,isp,as,timezone",
            f"https://ipinfo.io/{ip}/json".rstrip("/"),
            "https://api.myip.com"]
    for url in urls:
        try:
            d = fetch_json(url, timeout=6)
        except Exception:
            continue
        if not (isinstance(d, dict) and d.get("success") is not False):
            continue
        try:
            txt = fmt_geo(d)
        except Exception:
            continue
        if txt and "failed" not in txt:
            return txt
    return "lookup failed (all providers blocked?)"


def sample_cidr(cidr: str, count: int) -> list[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if net.num_addresses <= 2:
        return [str(net.network_address)]
    total = net.num_addresses - 2
    picks = random.sample(range(1, total + 1), min(count, total))
    base = int(net.network_address)
    return [str(ipaddress.ip_address(base + i)) for i in picks]


# ===========================================================================
# 🧩 Xray-core bridge — test configs through the REAL engine
# ===========================================================================

def find_xray_core() -> str:
    exe = "xray.exe" if os.name == "nt" else "xray"
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "") or os.path.join(home, "AppData",
                                                            "Roaming")
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


def build_xray_config(line: str, socks_port: int, frag_on: bool) -> dict:
    parts = urlsplit(line.strip())
    proto = parts.scheme.lower()
    if proto not in PROXY_SCHEMES:
        raise ProbeError("cfg", f"scheme {proto} unsupported")
    t = parse_target(line)
    if not t:
        raise ProbeError("cfg", "unparsable config")
    pd: dict[str, str] = {}
    for k, v in parse_qsl(parts.query):
        pd.setdefault(k.lower(), v)
    ntype = pd.get("type", "ws").lower()
    if ntype != "ws":
        raise ProbeError("cfg", f"transport '{ntype}' unsupported (ws only)")
    sec = pd.get("security", "").lower()
    tls_on = sec in ("tls", "reality")
    sni = t["sni"]
    stream: dict[str, Any] = {
        "network": "ws",
        "security": "tls" if sec == "tls" else ("reality" if sec == "reality"
                                                else "none"),
        "wsSettings": {"path": t["path"], "headers": {"Host": t["hdr"]}},
    }
    if sec == "reality":
        rs: dict[str, Any] = {"show": False,
                              "fingerprint": pd.get("fp", "chrome")}
        if sni and not is_ip(sni):
            rs["serverName"] = sni
        stream["realitySettings"] = rs
    elif tls_on:
        ts: dict[str, Any] = {"allowInsecure": True,
                              "fingerprint": pd.get("fp", "chrome")}
        if sni and not is_ip(sni):
            ts["serverName"] = sni
        if pd.get("cs"):
            ts["cipherSuites"] = pd["cs"]
        stream["tlsSettings"] = ts
    if proto == "trojan":
        out = {"tag": "proxy", "protocol": "trojan",
               "settings": {"servers": [{"address": t["host"],
                                         "port": int(t["port"]),
                                         "password": t["uuid"]}]},
               "streamSettings": stream}
    else:
        out = {"tag": "proxy", "protocol": "vless",
               "settings": {"vnext": [{"address": t["host"],
                                       "port": int(t["port"]),
                                       "users": [{"id": t["uuid"],
                                                  "encryption": "none",
                                                  "flow": ""}]}]},
               "streamSettings": stream}
    outs = [out]
    if frag_on and tls_on:
        stream["sockopt"] = {"dialerProxy": "frag"}
        outs.append({"tag": "frag", "protocol": "freedom",
                     "settings": {"fragment": {"packets": "tlshello",
                                               "length": "5-94",
                                               "interval": "1"}}})
    outs.append({"tag": "direct", "protocol": "freedom"})
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"tag": "socks", "protocol": "socks",
                          "listen": "127.0.0.1", "port": socks_port,
                          "settings": {"udp": False}}],
            "outbounds": outs}


def socks5_connect(socks_ip: str, socks_port: int, dst: str, dport: int,
                   timeout: float = 5.0) -> socket.socket:
    s = socket.create_connection((socks_ip, socks_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if len(r) < 2 or r[0] != 5 or r[1] != 0:
        s.close()
        raise ProbeError("socks", "handshake fail")
    if IPV4_RE.match(dst):
        req = b"\x05\x01\x00\x01" + socket.inet_aton(dst) \
            + int(dport).to_bytes(2, "big")
    else:
        hb = dst.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb \
            + int(dport).to_bytes(2, "big")
    s.sendall(req)
    r = s.recv(10)
    if len(r) < 2 or r[1] != 0:
        s.close()
        raise ProbeError("socks",
                         f"connect refused (code {r[1] if len(r) > 1 else '?'})")
    return s


def xray_probe(line: str, xray_path: str, frag_on: bool,
               timeout: float = 8.0) -> dict[str, Any]:
    """Run one config through real Xray-core; fetch exit IP/CC via its SOCKS.
    -> {'real': ms|None, 'cc': '', 'exit_ip': '', 'status': str}"""
    res: dict[str, Any] = {"real": None, "cc": "", "exit_ip": "", "status": ""}
    kw: dict[str, Any] = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    free = socket.socket()
    try:
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
    finally:
        free.close()
    cfg_fd, cfg_path = tempfile.mkstemp(suffix=".json")
    os.close(cfg_fd)
    err_fd, err_path = tempfile.mkstemp(suffix=".log")
    os.close(err_fd)
    proc: subprocess.Popen | None = None
    try:
        cfg = build_xray_config(line, port, frag_on)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        proc = subprocess.Popen([xray_path, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL,
                                stderr=open(err_path, "wb"), **kw)
        ok = False
        end = time.time() + 5
        while time.time() < end:
            if proc.poll() is not None:
                break
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
                s.close()
                ok = True
                break
            except OSError:
                time.sleep(0.1)
        if not ok:
            tail = ""
            try:
                with open(err_path, "r", encoding="utf-8",
                          errors="replace") as f:
                    lines = [l for l in f.read().strip().splitlines() if l]
                tail = lines[-1][:60] if lines else ""
            except OSError:
                pass
            res["status"] = ("core exited: " + tail) if tail else \
                "core failed to start"
            return res
        t0 = time.perf_counter()
        s = socks5_connect("127.0.0.1", port, "ip-api.com", 80,
                           timeout=timeout)
        try:
            s.sendall((b"GET /json?fields=status,countryCode,country,city,"
                       b"isp,query HTTP/1.1\r\nHost: ip-api.com\r\n"
                       b"User-Agent: vless-forge\r\nConnection: close\r\n\r\n"))
            raw = _read_http(sock_recv(s, None),
                             time.perf_counter() + timeout, None)
        finally:
            s.close()
        res["real"] = (time.perf_counter() - t0) * 1000
        try:
            d = json.loads(raw["body"].decode("utf-8", "replace"))
        except Exception:
            d = {}
        cc = str(d.get("countryCode") or "")
        if len(cc) == 2 and cc.isalpha():
            res["cc"] = cc.upper()
            res["exit_ip"] = str(d.get("query") or "")
            res["status"] = "core ok"
        else:
            res["status"] = f"core: geo odd ({raw['status'][:24]})"
        return res
    except ProbeError as pe:
        res["status"] = f"core: {pe.detail[:50]}"
        return res
    except Exception as e:
        res["status"] = f"core: {type(e).__name__}"
        return res
    finally:
        if proc and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
        for p in (cfg_path, err_path):
            try:
                os.unlink(p)
            except OSError:
                pass


# ===========================================================================
# Theme + custom widgets
# ===========================================================================

BG, PANEL, PANEL2 = "#0e1117", "#161b22", "#1e2633"
FIELD = "#0a141d"
FG, MUT = "#e6edf3", "#8b949e"
ACCENT, ACCENT_H, ACCENT_FG = "#3fa7ff", "#63b8ff", "#07131f"
GREEN, YELLOW, RED, PURPLE = "#3fb950", "#d29922", "#f85149", "#bc8cff"
MONO, SANS = "Courier", "Helvetica"


class Tooltip:
    def __init__(self, widget: tk.Misc, text: str, delay: int = 450):
        self.w = widget
        self.t = text
        self.d = delay
        self._id: str | None = None
        self._tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._sched, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _sched(self, _event=None) -> None:
        if self._id:
            self.w.after_cancel(self._id)
        self._id = self.w.after(self.d, self._show)

    def _show(self) -> None:
        if self._tip:
            return
        x = self.w.winfo_rootx() + 14
        y = self.w.winfo_rooty() + self.w.winfo_height() + 6
        self._tip = tw = tk.Toplevel(self.w)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self.t, justify="left", background="#212836",
                 foreground="#dbe4ee", relief="solid", borderwidth=1,
                 font=(MONO, 9), padx=9, pady=6).pack()

    def _hide(self, _event=None) -> None:
        if self._id:
            self.w.after_cancel(self._id)
            self._id = None
        if self._tip:
            self._tip.destroy()
            self._tip = None


class Switch(tk.Canvas):
    """Animated iOS-style toggle bound to a BooleanVar."""

    def __init__(self, master: tk.Misc, variable: tk.BooleanVar,
                 command=None, w: int = 44, h: int = 22,
                 on_color: str = PURPLE, off_color: str = "#30363d"):
        super().__init__(master, width=w, height=h, bg=BG,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.var = variable
        self.command = command
        self.w_, self.h_ = w, h
        self.on_color, self.off_color = on_color, off_color
        self._anim_id: str | None = None
        self._t = 1.0 if variable.get() else 0.0
        r = h // 2
        self._rect = self.create_rectangle(r, 2, w - r, h - 2,
                                           fill=self._mix(), outline="")
        self._ov1 = self.create_oval(2, 2, 2 + 2 * r, h - 2,
                                     fill=self._mix(), outline="")
        self._ov2 = self.create_oval(w - 2 - 2 * r, 2, w - 2, h - 2,
                                     fill=self._mix(), outline="")
        self._knob_r = (h - 8) // 2
        kx = self._knob_x(self._t)
        self._knob = self.create_oval(
            kx - self._knob_r, h // 2 - self._knob_r,
            kx + self._knob_r, h // 2 + self._knob_r,
            fill="#e6edf3", outline="")
        self.bind("<Button-1>", self._toggle)
        variable.trace_add("write", lambda *_a: self._sync())

    def _knob_x(self, t: float) -> float:
        x0 = 4 + self._knob_r
        x1 = self.w_ - 4 - self._knob_r
        return x0 + (x1 - x0) * t

    def _mix(self) -> str:
        c1 = tuple(int(self.off_color[i:i + 2], 16) for i in (1, 3, 5))
        c2 = tuple(int(self.on_color[i:i + 2], 16) for i in (1, 3, 5))
        return "#%02x%02x%02x" % tuple(
            int(a + (b - a) * self._t) for a, b in zip(c1, c2))

    def _render(self) -> None:
        col = self._mix()
        for item in (self._rect, self._ov1, self._ov2):
            self.itemconfigure(item, fill=col)
        kx = self._knob_x(self._t)
        self.coords(self._knob, kx - self._knob_r, self.h_ // 2 - self._knob_r,
                    kx + self._knob_r, self.h_ // 2 + self._knob_r)

    def _sync(self) -> None:
        target = 1.0 if self.var.get() else 0.0
        if self._anim_id:
            self.after_cancel(self._anim_id)
            self._anim_id = None
        self._animate(target)

    def _animate(self, target: float) -> None:
        step = 0.28
        if abs(target - self._t) <= step:
            self._t = target
            self._render()
            self._anim_id = None
            return
        self._t += step if target > self._t else -step
        self._render()
        self._anim_id = self.after(16, lambda: self._animate(target))

    def _toggle(self, _e=None) -> None:
        self.var.set(not self.var.get())
        if self.command:
            self.command()


SAMPLE = "\n".join([
    "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@188.114.97.6:443?encryption=none&security=tls&sni=edgestuff.pages.dev&fp=chrome&type=ws&host=edgestuff.pages.dev&path=%2Fchannel#CF%E5%AE%98%E6%96%B9%E4%BC%98%E9%80%891",
    "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@104.18.33.142:2083?encryption=none&security=tls&sni=edgestuff.pages.dev&fp=chrome&type=ws&host=edgestuff.pages.dev&path=%2Furls%2Fdoc#CF%E5%AE%98%E6%96%B9%E4%BC%98%E9%80%893",
    "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@8.35.211.156:8443?encryption=none&security=tls&sni=edgestuff.pages.dev&fp=chrome&type=ws&host=edgestuff.pages.dev&path=%2Fcollection#CF%E5%AE%98%E6%96%B9%E4%BC%98%E9%80%896",
])


# ===========================================================================
# GUI
# ===========================================================================

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("⚡ VLESS Forge — modes · fix · rename · override · tester · exit-country · xray-core · ip scanner")
        self.geometry("1380x980")
        self.minsize(1080, 760)
        self.configure(background=BG)
        self._job: str | None = None
        self._name_lines: list[tuple[str, str]] = []
        self._targets: list[dict[str, Any]] = []
        self._out_dirty = True
        self._testing = False
        self._scanning = False
        self._stop_test = threading.Event()
        self._stop_scan = threading.Event()
        self._test_done = 0
        self._test_total = 0
        self._scan_done = 0
        self._scan_total = 0
        self._scan_alive = 0
        self._scan_iid = 0
        self._scan_meta: dict[str, tuple[str, str, str | None, str]] = {}
        self._scan_frag: tuple | None = None
        self._test_ex: ThreadPoolExecutor | None = None
        self._scan_ex: ThreadPoolExecutor | None = None
        self.q: queue.Queue = queue.Queue()

        self._resolve_fonts()
        self._build_style()
        self._build_vars()
        self._build_ui()
        self._bind_keys()
        self.after(120, self._drain)
        self.after(900, self._startup_core_check)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _resolve_fonts(self) -> None:
        global MONO, SANS
        fams = set(tkfont.families(self))
        MONO = next((f for f in ("Cascadia Mono", "Consolas", "Menlo",
                                 "DejaVu Sans Mono", "Courier New")
                     if f in fams), "Courier")
        SANS = next((f for f in ("Segoe UI", "SF Pro Text", "Helvetica",
                                 "DejaVu Sans") if f in fams), "Helvetica")

    def _build_style(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, bordercolor=PANEL2,
                    lightcolor=PANEL2, darkcolor=PANEL2, troughcolor=PANEL)
        s.configure("TFrame", background=BG)
        s.configure("TLabelframe", background=BG, relief="flat", borderwidth=0)
        s.configure("TLabelframe.Label", background=BG, foreground=ACCENT,
                    font=(SANS, 10, "bold"))
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                    insertcolor=FG, bordercolor=PANEL2, padding=4)
        s.map("TEntry", bordercolor=[("focus", ACCENT)])
        s.configure("Field.TEntry", fieldbackground=FIELD, foreground="#9fe8ff",
                    insertcolor="#9fe8ff", bordercolor=PANEL2, padding=(6, 5))
        s.map("Field.TEntry", bordercolor=[("focus", PURPLE),
                                           ("disabled", PANEL2)])
        s.configure("TSpinbox", fieldbackground=PANEL, background=PANEL2,
                    foreground=FG, arrowcolor=FG, bordercolor=PANEL2,
                    insertcolor=FG, padding=3)
        s.configure("TCombobox", fieldbackground=PANEL, background=PANEL2,
                    foreground=FG, arrowcolor=FG, bordercolor=PANEL2,
                    padding=4)
        self.option_add("*TCombobox*Listbox.background", PANEL)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", ACCENT_FG)
        s.configure("Accent.TButton", background=ACCENT, foreground=ACCENT_FG,
                    font=(SANS, 10, "bold"), padding=(16, 9), borderwidth=0,
                    focusthickness=0)
        s.map("Accent.TButton", background=[("active", ACCENT_H),
                                            ("disabled", PANEL2)],
              foreground=[("disabled", MUT)])
        s.configure("Ghost.TButton", background=PANEL, foreground=FG,
                    padding=(11, 8), borderwidth=0, focusthickness=0)
        s.map("Ghost.TButton", background=[("active", PANEL2),
                                           ("disabled", BG)],
              foreground=[("disabled", MUT)])
        s.configure("TNotebook", background=BG, borderwidth=0,
                    tabmargins=(6, 4, 6, 0))
        s.configure("TNotebook.Tab", background=PANEL, foreground=MUT,
                    padding=(18, 8), borderwidth=0, font=(SANS, 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", PANEL2)],
              foreground=[("selected", FG)])
        s.configure("Treeview", background=PANEL, foreground=FG,
                    fieldbackground=PANEL, bordercolor=PANEL2, relief="flat",
                    rowheight=24, font=(MONO, 10))
        s.configure("Treeview.Heading", background=PANEL2, foreground=MUT,
                    font=(SANS, 9, "bold"), relief="flat", padding=(6, 6))
        s.map("Treeview.Heading", background=[("active", ACCENT)])
        s.map("Treeview", background=[("selected", ACCENT)],
              foreground=[("selected", ACCENT_FG)])
        for o in ("Vertical", "Horizontal"):
            s.configure(f"{o}.TScrollbar", background=PANEL2, troughcolor=BG,
                        bordercolor=BG, arrowcolor=MUT, relief="flat")
            s.map(f"{o}.TScrollbar", background=[("active", ACCENT)])
        s.configure("Good.TLabel", foreground=GREEN, background=BG,
                    font=(MONO, 9, "bold"))
        s.configure("Err.TLabel", foreground=RED, background=BG,
                    font=(MONO, 9, "bold"))
        s.configure("Dim.TLabel", foreground=MUT, background=BG,
                    font=(MONO, 9))
        s.configure("Preview.TLabel", foreground=PURPLE, background=BG,
                    font=(MONO, 10, "bold"))
        s.configure("Ok.TLabel", foreground=GREEN, background=PANEL,
                    font=(SANS, 10, "bold"))
        s.configure("Warn.TLabel", foreground=YELLOW, background=PANEL,
                    font=(SANS, 10, "bold"))
        s.configure("Bad.TLabel", foreground=RED, background=PANEL,
                    font=(SANS, 10, "bold"))
        s.configure("Msg.TLabel", foreground=MUT, background=PANEL)

    def _build_vars(self) -> None:
        # mode + feature switches
        self.mode_var = tk.StringVar(value=MODE_FULL)
        self.fp_on = tk.BooleanVar(value=True)
        self.cs_on = tk.BooleanVar(value=True)
        self.fm_on = tk.BooleanVar(value=True)
        self.rename_var = tk.BooleanVar(value=True)
        self.tls_only_var = tk.BooleanVar(value=True)
        self.auto_var = tk.BooleanVar(value=True)
        # fields
        self.fp_var = tk.StringVar(value=DEFAULT_FP)
        self.cs_var = tk.StringVar(value=DEFAULT_CS)
        self.fm_var = tk.StringVar(value=compact_json(DEFAULT_FM))
        self.tpl_var = tk.StringVar(value=DEFAULT_TEMPLATE)
        self.start_var = tk.IntVar(value=1)
        # mass override
        self.ip_on = tk.BooleanVar(value=False)
        self.port_on = tk.BooleanVar(value=False)
        self.ip_var = tk.StringVar(value="")
        self.port_var = tk.StringVar(value="")
        self.ip_badge = tk.StringVar(value="")
        self.port_badge = tk.StringVar(value="")
        self.ep_preview = tk.StringVar(value="")
        # tester
        self.mode_test_var = tk.StringVar(value="full (ws + REAL delay)")
        self.frag_var = tk.StringVar(value=FRAG_PRESETS[0])
        self.tmo_var = tk.StringVar(value="3")
        self.att_var = tk.IntVar(value=1)
        self.workers_test_var = tk.IntVar(value=16)
        self.target_var = tk.StringVar(value=TEST_TARGET_DEFAULT)
        self.cc_on = tk.BooleanVar(value=True)
        self.test_prog_var = tk.StringVar(value="")
        self.test_info_var = tk.StringVar(value="no configs loaded yet")
        # xray core
        self.core_var = tk.StringVar(value=find_xray_core())
        self.core_frag_on = tk.BooleanVar(value=True)
        self.core_workers_var = tk.IntVar(value=8)
        self.core_timeout_var = tk.StringVar(value="8")
        self.core_status_var = tk.StringVar(
            value="auto-detected — press ⟳ check to verify" if self.core_var.get()
            else "✖ no xray core found — press 📂 or auto-detect")
        # ip finder
        self.geo_ip_var = tk.StringVar(value="")
        self.geo_txt = tk.StringVar(
            value="check your public IP, or look up any IP / domain")
        self.scan_cidr_var = tk.StringVar(value=CF_RANGES[0])
        self.scan_count_var = tk.IntVar(value=120)
        self.scan_workers_var = tk.IntVar(value=100)
        self.scan_port_var = tk.StringVar(value="443")
        self.scan_sni_var = tk.StringVar(value="")
        self.scan_frag_var = tk.StringVar(value=FRAG_PRESETS[0])
        self.sni_mode_var = tk.StringVar(value="config sni")
        self.curl_var = tk.BooleanVar(value=False)
        self.res_host_var = tk.StringVar(value="")
        self.scan_prog_var = tk.StringVar(value="")
        # status
        self.msg_var = tk.StringVar(
            value="Paste configs on the left — conversion is live. Ctrl+Enter forces a run.")
        self.v_fixed = tk.StringVar(value="✎ 0 updated")
        self.v_same = tk.StringVar(value="↺ 0 unchanged")
        self.v_skip = tk.StringVar(value="⚠ 0 skipped")

    # ---------------------------------------------------------------- ui
    def _build_ui(self) -> None:
        head = tk.Frame(self, background=BG)
        head.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(head, text="⚡ VLESS Forge", background=BG, foreground=FG,
                 font=(SANS, 17, "bold")).pack(side="left")
        tk.Label(head, text="   modes · fix · tester · exit-country · xray-core · ip scanner",
                 background=BG, foreground=MUT, font=(SANS, 10))\
            .pack(side="left", pady=(4, 0))
        tk.Frame(self, height=2, background=ACCENT).pack(fill="x", padx=14)

        main = tk.Frame(self, background=BG)
        main.pack(fill="both", expand=True, padx=14, pady=10)

        # -- 1 · rules ------------------------------------------------------
        rules = ttk.Labelframe(main, text="  1 · Transformation rules  ")
        rules.pack(fill="x", pady=(0, 8))
        for c, w in ((0, 0), (1, 0), (2, 1), (3, 0), (4, 0)):
            rules.columnconfigure(c, weight=w)

        ttk.Label(rules, text="mode", font=(SANS, 10, "bold"))\
            .grid(row=0, column=0, sticky="w", padx=(10, 8), pady=(10, 2))
        mode_cb = ttk.Combobox(rules, textvariable=self.mode_var,
                               values=MODES, state="readonly", width=30,
                               font=(SANS, 10, "bold"))
        mode_cb.grid(row=0, column=1, sticky="w", pady=(10, 2))
        mode_cb.bind("<<ComboboxSelected>>", self._on_mode_change)
        Tooltip(mode_cb,
                "⚡ Full fix : fp→unsafe + cipher suites + fragment mask\n"
                "🎯 IP only  : inject NOTHING — only endpoint override / rename\n"
                "🛠 Custom   : the switches below decide")
        self.mode_desc = tk.Label(rules, text="", background=BG,
                                  foreground=ACCENT, font=(SANS, 9),
                                  anchor="w")
        self.mode_desc.grid(row=0, column=2, columnspan=3, sticky="w",
                            padx=(12, 10), pady=(10, 2))

        swrow = tk.Frame(rules, background=BG)
        swrow.grid(row=1, column=0, columnspan=5, sticky="w",
                   padx=(8, 10), pady=(2, 4))
        for var, text, cmd, tip in (
            (self.fp_on, "fp → unsafe", self._switch_touched,
             "Replace the fingerprint param with the value below."),
            (self.cs_on, "+ ciphers", self._switch_touched,
             "Inject the TLS cipher-suite list (cs=)."),
            (self.fm_on, "+ mask", self._switch_touched,
             "Inject the fragment-mask JSON (fm=)."),
            (self.rename_var, "rename", None,
             "Regenerate the #name of every config."),
            (self.tls_only_var, "only tls", None,
             "When injecting: skip configs whose security isn't tls."),
        ):
            sw = Switch(swrow, variable=var, command=cmd)
            sw.pack(side="left", padx=(4, 3), pady=2)
            lbl = tk.Label(swrow, text=text, background=BG, foreground=FG,
                           font=(SANS, 10))
            lbl.pack(side="left", padx=(0, 16))
            Tooltip(sw, tip)
            Tooltip(lbl, tip)

        ttk.Label(rules, text="fp (fingerprint)")\
            .grid(row=2, column=0, sticky="w", padx=(10, 6), pady=4)
        self.fp_entry = ttk.Entry(rules, textvariable=self.fp_var, width=14)
        self.fp_entry.grid(row=2, column=1, sticky="w", pady=4)
        ttk.Label(rules, text="cs (cipher suites)")\
            .grid(row=3, column=0, sticky="w", padx=(10, 6), pady=4)
        self.cs_entry = ttk.Entry(rules, textvariable=self.cs_var)
        self.cs_entry.grid(row=3, column=1, columnspan=4, sticky="ew",
                           padx=(0, 10), pady=4)
        ttk.Label(rules, text="fm (mask JSON)")\
            .grid(row=4, column=0, sticky="w", padx=(10, 6), pady=(4, 10))
        self.fm_entry = ttk.Entry(rules, textvariable=self.fm_var)
        self.fm_entry.grid(row=4, column=1, columnspan=4, sticky="ew",
                           padx=(0, 10), pady=(4, 10))
        self._sync_rule_fields()

        # -- 2 · naming -----------------------------------------------------
        naming = ttk.Labelframe(main, text="  2 · Naming  ")
        naming.pack(fill="x", pady=(0, 8))
        naming.columnconfigure(1, weight=1)
        ttk.Label(naming, text="template").grid(row=0, column=0, sticky="w",
                                                padx=(10, 6), pady=8)
        self.tpl_entry = ttk.Entry(naming, textvariable=self.tpl_var)
        self.tpl_entry.grid(row=0, column=1, sticky="ew", padx=(0, 4), pady=8)
        Tooltip(self.tpl_entry,
                "Keys: {id} {sub} {path} {ip} {port} {host} {net} {sni} "
                "{proto} {old}")
        ttk.Label(naming, text="start #").grid(row=0, column=2, sticky="e",
                                               padx=(8, 6), pady=8)
        self.start_spin = ttk.Spinbox(naming, from_=1, to=99999,
                                      textvariable=self.start_var, width=6)
        self.start_spin.grid(row=0, column=3, sticky="e", padx=(0, 10), pady=8)
        ttk.Button(naming, text="🔑 keys", style="Ghost.TButton",
                   command=self._show_keys, width=8)\
            .grid(row=0, column=4, padx=(0, 10), pady=8)

        # -- 3 · mass override ----------------------------------------------
        ov = ttk.Labelframe(
            main, text="  3 · Mass override — force one endpoint on EVERY config  ")
        ov.pack(fill="x", pady=(0, 8))
        for c, w in ((0, 0), (1, 0), (2, 1), (3, 0), (4, 0), (5, 0),
                     (6, 0), (7, 0)):
            ov.columnconfigure(c, weight=w)
        ip_sw = Switch(ov, variable=self.ip_on, command=self._toggle_override)
        ip_sw.grid(row=0, column=0, sticky="w", padx=(10, 4), pady=(10, 2))
        Tooltip(ip_sw, "Replace the connect address of every config.\n"
                       "Accepts IPv4, IPv6 or domain.\n"
                       "sni / host / path params are NOT touched.")
        tk.Label(ov, text="FORCE IP", background=BG, foreground=FG,
                 font=(SANS, 10, "bold")).grid(row=0, column=1, sticky="w",
                                               pady=(10, 2))
        self.ip_entry = ttk.Entry(ov, textvariable=self.ip_var,
                                  style="Field.TEntry", font=(MONO, 11),
                                  width=24)
        self.ip_entry.grid(row=0, column=2, sticky="w", padx=(10, 0),
                           pady=(10, 2))
        self.ip_badge_lbl = ttk.Label(ov, textvariable=self.ip_badge,
                                      style="Dim.TLabel")
        self.ip_badge_lbl.grid(row=0, column=3, sticky="w", padx=(8, 6),
                               pady=(10, 2))
        port_sw = Switch(ov, variable=self.port_on,
                         command=self._toggle_override)
        port_sw.grid(row=0, column=4, sticky="e", padx=(18, 4), pady=(10, 2))
        Tooltip(port_sw, "Replace the connect port of every config (1–65535).")
        tk.Label(ov, text="FORCE PORT", background=BG, foreground=FG,
                 font=(SANS, 10, "bold")).grid(row=0, column=5, sticky="w",
                                               pady=(10, 2))
        self.port_entry = ttk.Entry(ov, textvariable=self.port_var,
                                    style="Field.TEntry", font=(MONO, 11),
                                    width=8, justify="center")
        self.port_entry.grid(row=0, column=6, sticky="w", padx=(10, 10),
                             pady=(10, 2))
        self.port_badge_lbl = ttk.Label(ov, textvariable=self.port_badge,
                                        style="Dim.TLabel")
        self.port_badge_lbl.grid(row=0, column=7, sticky="w", pady=(10, 2))
        ttk.Button(ov, text="✕ clear override", style="Ghost.TButton",
                   command=self._clear_override)\
            .grid(row=1, column=0, columnspan=2, sticky="w", padx=10,
                  pady=(2, 4))
        self.ep_lbl = ttk.Label(ov, textvariable=self.ep_preview,
                                style="Preview.TLabel")
        self.ep_lbl.grid(row=1, column=2, columnspan=3, sticky="w", padx=10,
                         pady=(2, 4))
        Tooltip(self.ep_lbl, "Effective endpoint for every config.\n"
                             "'orig' = keep that line's own value.")
        ttk.Label(ov, text="endpoint only — the ws host/sni/path stay exactly as they are",
                  style="Dim.TLabel")\
            .grid(row=1, column=4, columnspan=4, sticky="e", padx=10,
                  pady=(2, 8))
        self._toggle_override()

        # -- buttons ----------------------------------------------------------
        bar = tk.Frame(main, background=BG)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text="⚡  Convert  (Ctrl+Enter)", style="Accent.TButton",
                   command=self.do_convert).pack(side="left")
        for text, cmd, tip in (
            ("📋 Copy output", self.copy_output, "Copy fixed configs (Ctrl+Shift+C)"),
            ("💾 Save as…", self.save_output, "Save output to .txt"),
            ("📂 Open file…", self.load_file, "Load configs from file"),
            ("🧪 Sample", self.load_sample, "Insert a demo set"),
            ("🧹 Clear", self.clear_all, "Clear in & out"),
            ("♻ Reset", self.reset_defaults, "Restore all defaults"),
        ):
            b = ttk.Button(bar, text=text, style="Ghost.TButton", command=cmd)
            b.pack(side="left", padx=(8, 0))
            Tooltip(b, tip)
        auto_cb = ttk.Checkbutton(bar, text="live convert",
                                  variable=self.auto_var)
        auto_cb.pack(side="right")

        # -- notebook ---------------------------------------------------------
        self.nb = ttk.Notebook(main)
        self.nb.pack(fill="both", expand=True)
        cfg_tab = tk.Frame(self.nb, background=BG)
        self.nb.add(cfg_tab, text="  ⚙ Configs  ")
        pane = ttk.Panedwindow(cfg_tab, orient="horizontal")
        pane.pack(fill="both", expand=True, pady=6)
        in_f = tk.Frame(pane, background=BG)
        out_f = tk.Frame(pane, background=BG)
        pane.add(in_f, weight=1)
        pane.add(out_f, weight=1)
        tk.Label(in_f, text="INPUT — paste raw configs", background=BG,
                 foreground=MUT, font=(SANS, 9, "bold"), anchor="w")\
            .pack(fill="x", pady=(0, 4))
        self.input_txt = self._make_text(in_f)
        tk.Label(out_f, text="OUTPUT — fixed configs", background=BG,
                 foreground=GREEN, font=(SANS, 9, "bold"), anchor="w")\
            .pack(fill="x", pady=(0, 4))
        self.output_txt = self._make_text(out_f, state="disabled",
                                          bg="#10241a")

        names_tab = tk.Frame(self.nb, background=BG)
        self.nb.add(names_tab, text="  🏷 Names  ")
        nb_bar = tk.Frame(names_tab, background=BG)
        nb_bar.pack(fill="x", pady=(6, 4))
        ttk.Button(nb_bar, text="📋 Copy names only", style="Ghost.TButton",
                   command=self.copy_names).pack(side="left")
        tk.Label(nb_bar, text="double-click a row to copy that full config",
                 background=BG, foreground=MUT).pack(side="left", padx=10)
        self.names_lb = tk.Listbox(names_tab, background=PANEL, foreground=FG,
                                   selectbackground=ACCENT,
                                   selectforeground=ACCENT_FG, relief="flat",
                                   highlightthickness=0, activestyle="none",
                                   font=(MONO, 10))
        n_sb = ttk.Scrollbar(names_tab, orient="vertical",
                             command=self.names_lb.yview)
        self.names_lb.configure(yscrollcommand=n_sb.set)
        self.names_lb.pack(side="left", fill="both", expand=True, pady=(0, 8))
        n_sb.pack(side="left", fill="y", pady=(0, 8), padx=(0, 2))
        self.names_lb.bind("<Double-Button-1>", self._copy_named_line)

        self.test_tab = tk.Frame(self.nb, background=BG)
        self.nb.add(self.test_tab, text="  📡 Tester  ")
        self._build_tester(self.test_tab)

        self.xray_tab = tk.Frame(self.nb, background=BG)
        self.nb.add(self.xray_tab, text="  🧩 Xray Core  ")
        self._build_xray(self.xray_tab)

        self.find_tab = tk.Frame(self.nb, background=BG)
        self.nb.add(self.find_tab, text="  🌐 IP Finder  ")
        self._build_finder(self.find_tab)

        status = tk.Frame(self, background=PANEL)
        status.pack(fill="x", side="bottom")
        tk.Frame(self, height=1, background=PANEL2).pack(fill="x",
                                                         side="bottom")
        ttk.Label(status, textvariable=self.msg_var, style="Msg.TLabel")\
            .pack(side="left", padx=12, pady=6)
        ttk.Label(status, textvariable=self.v_fixed, style="Ok.TLabel")\
            .pack(side="right", padx=8, pady=6)
        ttk.Label(status, textvariable=self.v_same, style="Warn.TLabel")\
            .pack(side="right", padx=8, pady=6)
        ttk.Label(status, textvariable=self.v_skip, style="Bad.TLabel")\
            .pack(side="right", padx=(8, 16), pady=6)
        self._update_mode_desc()

    # ------------------------------------------------------------- tester ui
    def _build_tester(self, parent: tk.Frame) -> None:
        tbar = tk.Frame(parent, background=BG)
        tbar.pack(fill="x", pady=(6, 2))
        self.btn_test_all = ttk.Button(tbar, text="▶  Test all",
                                       style="Accent.TButton",
                                       command=lambda: self._start_test(False))
        self.btn_test_all.pack(side="left")
        self.btn_test_sel = ttk.Button(tbar, text="▶  Test selected",
                                       style="Ghost.TButton",
                                       command=lambda: self._start_test(True))
        self.btn_test_sel.pack(side="left", padx=(8, 0))
        self.btn_stop_test = ttk.Button(tbar, text="■  Stop",
                                        style="Ghost.TButton",
                                        command=self._stop_test.set,
                                        state="disabled")
        self.btn_stop_test.pack(side="left", padx=(8, 14))

        ttk.Label(tbar, text="mode", style="Dim.TLabel").pack(side="left")
        tmode_cb = ttk.Combobox(tbar, textvariable=self.mode_test_var,
                                width=22, state="readonly",
                                values=("full (ws + REAL delay)", "ws only",
                                        "tls only", "tcp only"))
        tmode_cb.pack(side="left", padx=(4, 12))
        Tooltip(tmode_cb,
                "full : TCP ping + fragmented TLS + ws 101 + REAL delay/exit\n"
                "ws   : TCP + TLS + 101 upgrade (+ exit country)\n"
                "tls  : TCP + fragmented TLS handshake\n"
                "tcp  : TCP ping only (fastest)")
        ttk.Label(tbar, text="fragment", style="Dim.TLabel").pack(side="left")
        frag_cb = ttk.Combobox(tbar, textvariable=self.frag_var, width=12,
                               values=FRAG_PRESETS)
        frag_cb.pack(side="left", padx=(4, 12))
        Tooltip(frag_cb,
                "ClientHello fragmentation — THE anti-DPI trick.\n"
                "'5,94,1@2' = chunks of 5,94,1 bytes with 2 ms gaps\n"
                "(same as the fm= mask in your configs).")
        ttk.Label(tbar, text="timeout s", style="Dim.TLabel").pack(side="left")
        ttk.Spinbox(tbar, from_=1, to=15, increment=0.5, width=4,
                    textvariable=self.tmo_var).pack(side="left", padx=(4, 12))
        ttk.Label(tbar, text="attempts", style="Dim.TLabel").pack(side="left")
        ttk.Spinbox(tbar, from_=1, to=5, width=3,
                    textvariable=self.att_var).pack(side="left", padx=(4, 12))
        ttk.Label(tbar, text="workers", style="Dim.TLabel").pack(side="left")
        ttk.Spinbox(tbar, from_=1, to=64, width=4,
                    textvariable=self.workers_test_var)\
            .pack(side="left", padx=(4, 12))
        ttk.Label(tbar, textvariable=self.test_prog_var,
                  style="Preview.TLabel").pack(side="right", padx=8)
        ttk.Label(tbar, textvariable=self.test_info_var, style="Dim.TLabel")\
            .pack(side="right")

        tbar2 = tk.Frame(parent, background=BG)
        tbar2.pack(fill="x", pady=(0, 4))
        cc_sw = Switch(tbar2, variable=self.cc_on)
        cc_sw.pack(side="left", padx=(0, 3))
        tk.Label(tbar2, text="exit country", background=BG, foreground=FG,
                 font=(SANS, 10, "bold")).pack(side="left", padx=(0, 12))
        Tooltip(cc_sw,
                "After ws-101, fetch a geo API THROUGH the vless tunnel\n"
                "(ip-api → ipwho.is → ipinfo, rotated per row) to learn the\n"
                "country you will ACTUALLY appear to be in (+ exit IP).\n"
                "The geo request doubles as the REAL-delay probe.\n"
                "Fallback: geo of the edge IP, marked '*' (approximation).\n"
                "For trojan/odd-uuid configs use the 🧩 Xray Core tab.")
        self.btn_core_quick = ttk.Button(tbar2, text="⚙ via core",
                                         style="Ghost.TButton",
                                         command=lambda:
                                         self._start_core_test(False))
        self.btn_core_quick.pack(side="left", padx=(0, 12))
        Tooltip(self.btn_core_quick,
                "Run every config through the REAL xray core (set path in\n"
                "the 🧩 Xray Core tab) and fetch exit IP + country through\n"
                "it — v2rayN-parity results, works for trojan too.")
        tag_btn = ttk.Button(tbar2, text="🏷 tag names [CC]",
                             style="Ghost.TButton",
                             command=self._tag_names_with_cc)
        tag_btn.pack(side="left", padx=(0, 12))
        Tooltip(tag_btn,
                "Append the verified exit country to every #name,\n"
                "e.g. 07_edgestuff_sort[NL]. Uses verified results only\n"
                "('*' edge guesses are skipped).")
        ttk.Label(tbar2, text="REAL-delay target", style="Dim.TLabel")\
            .pack(side="left")
        tgt_e = ttk.Entry(tbar2, textvariable=self.target_var, width=28,
                          style="Field.TEntry", font=(MONO, 10))
        tgt_e.pack(side="left", padx=(6, 12))
        Tooltip(tgt_e,
                "URL fetched THROUGH the tunnel for the REAL delay\n"
                "(used when 'exit country' is OFF; when ON, the geo\n"
                "request doubles as the delay probe).")
        tk.Label(tbar2, background=BG, foreground=MUT, font=(SANS, 9),
                 text="fragment ON = probes survive Iranian DPI").pack(
            side="left")

        cols = {"name": (190, "w"), "endpoint": (165, "w"), "tcp": (55, "e"),
                "tls": (55, "e"), "ws": (55, "e"), "real": (60, "e"),
                "cc": (84, "w"), "status": (300, "w")}
        self.test_tree = self._make_tree(parent, cols,
                                         {"tcp", "tls", "ws", "real"})
        self.test_tree.pack(fill="both", expand=True, pady=(0, 2))
        self.test_tree.bind("<Double-Button-1>", self._copy_test_line)
        tk.Label(parent, background=BG, foreground=MUT,
                 text="double-click a row → copy that config · 101 = ws alive "
                      "· REAL = latency through the tunnel · cc = exit country "
                      "🇳🇱 NL, '*'=edge-IP guess",
                 font=(SANS, 9), anchor="w").pack(fill="x", pady=(0, 6))

    # ------------------------------------------------------------- xray ui
    def _build_xray(self, parent: tk.Frame) -> None:
        top = ttk.Labelframe(parent, text="  1 · Core executable  ")
        top.pack(fill="x", padx=10, pady=(8, 6))
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="path").grid(row=0, column=0, sticky="w",
                                         padx=(10, 6), pady=(10, 4))
        core_e = ttk.Entry(top, textvariable=self.core_var,
                           style="Field.TEntry", font=(MONO, 10))
        core_e.grid(row=0, column=1, sticky="ew", padx=(0, 6), pady=(10, 4))
        Tooltip(core_e,
                "Full path to xray / xray.exe.\n"
                "v2rayN ships one at:\n"
                "  %APPDATA%\\v2rayN\\bin\\xray\\xray.exe\n"
                "Searched automatically: env XRAY_CORE, v2rayN dirs, ./bin,\n"
                "script dir and PATH.")
        b_browse = ttk.Button(top, text="📂 browse…", style="Ghost.TButton",
                              command=self._pick_core)
        b_browse.grid(row=0, column=2, padx=(0, 4), pady=(10, 4))
        Tooltip(b_browse, "Pick the xray executable manually.")
        b_detect = ttk.Button(top, text="🔍 auto-detect", style="Ghost.TButton",
                              command=self._detect_core)
        b_detect.grid(row=0, column=3, padx=(0, 10), pady=(10, 4))
        Tooltip(b_detect, "Search the usual v2rayN / PATH locations again.")

        ttk.Label(top, text="status").grid(row=1, column=0, sticky="w",
                                           padx=(10, 6), pady=(4, 10))
        st_lbl = tk.Label(top, textvariable=self.core_status_var,
                          background=PANEL, foreground=FG, font=(MONO, 10),
                          anchor="w", padx=8, pady=3)
        st_lbl.grid(row=1, column=1, columnspan=2, sticky="ew", pady=(4, 10))
        b_check = ttk.Button(top, text="⟳ check", style="Ghost.TButton",
                             command=self._check_core_clicked)
        b_check.grid(row=1, column=3, padx=(0, 10), pady=(4, 10))
        Tooltip(b_check, "Run 'xray version' to verify the core works.")

        mid = ttk.Labelframe(parent, text="  2 · Core-test settings  ")
        mid.pack(fill="x", padx=10, pady=(0, 6))
        frag_sw = Switch(mid, variable=self.core_frag_on, on_color=GREEN)
        frag_sw.grid(row=0, column=0, sticky="w", padx=(10, 4), pady=10)
        tk.Label(mid, text="fragment (tlshello 5-94)",
                 background=BG, foreground=FG, font=(SANS, 10))\
            .grid(row=0, column=1, sticky="w", pady=10)
        Tooltip(frag_sw,
                "Route the core's own TLS through Xray's fragment dialer\n"
                "(packets=tlshello, length=5-94) — same anti-DPI idea as\n"
                "the fm= mask. Keep ON in Iran.")
        ttk.Label(mid, text="workers", style="Dim.TLabel")\
            .grid(row=0, column=2, padx=(24, 4))
        ttk.Spinbox(mid, from_=1, to=16, width=4,
                    textvariable=self.core_workers_var)\
            .grid(row=0, column=3, padx=(0, 20))
        Tooltip(mid.winfo_children()[-1],
                "Parallel xray instances. Each spawns a real core process —\n"
                "keep modest (4–8).")
        ttk.Label(mid, text="timeout s", style="Dim.TLabel")\
            .grid(row=0, column=4, padx=(0, 4))
        ttk.Spinbox(mid, from_=3, to=30, width=4,
                    textvariable=self.core_timeout_var)\
            .grid(row=0, column=5)

        run = ttk.Labelframe(parent, text="  3 · Run  ")
        run.pack(fill="x", padx=10, pady=(0, 6))
        self.btn_core_all = ttk.Button(run, text="⚙  Test via core — ALL",
                                       style="Accent.TButton",
                                       command=lambda:
                                       self._start_core_test(False))
        self.btn_core_all.pack(side="left", padx=10, pady=10)
        self.btn_core_sel = ttk.Button(run, text="⚙  Test via core — SELECTED",
                                       style="Ghost.TButton",
                                       command=lambda:
                                       self._start_core_test(True))
        self.btn_core_sel.pack(side="left", padx=(0, 10))
        tk.Label(run, background=BG, foreground=MUT, font=(SANS, 9),
                 text="tests the configs currently in the 📡 Tester list "
                      "(your converted output) — results (REAL delay + exit "
                      "IP + cc) are written into the Tester table").pack(
            side="left", padx=(4, 10))

        note = tk.Label(parent, background=BG, foreground=MUT, font=(SANS, 9),
                        justify="left", anchor="w",
                        text=(
                            "WHY: the native tester speaks hand-rolled VLESS — great for standard vless+ws, but "
                            "workers/trojan/impl quirks can refuse it.\n"
                            "This tab runs each config through REAL Xray-core (the same engine v2rayN uses) via a "
                            "local SOCKS port, then asks ip-api for the\n"
                            "EXIT IP + country through the tunnel. That is the definitive answer for "
                            "'where will this proxy put me'.\n\n"
                            "Searched by auto-detect:\n"
                            "  · %APPDATA%\\v2rayN\\bin\\xray\\xray.exe   (v2rayN default)\n"
                            "  · XRAY_CORE environment variable\n"
                            "  · ./bin/xray/xray   · script dir   · PATH"))
        note.pack(fill="x", padx=14, pady=(2, 10))

    # ------------------------------------------------------------- finder ui
    def _build_finder(self, parent: tk.Frame) -> None:
        top = tk.Frame(parent, background=BG)
        top.pack(fill="x", pady=(6, 4))
        ttk.Button(top, text="🌐 my IP", style="Ghost.TButton",
                   command=lambda: self._do_geo(None)).pack(side="left")
        ttk.Label(top, text="  lookup IP:", style="Dim.TLabel")\
            .pack(side="left", padx=(12, 4))
        geo_e = ttk.Entry(top, textvariable=self.geo_ip_var, width=24,
                          style="Field.TEntry", font=(MONO, 10))
        geo_e.pack(side="left")
        Tooltip(geo_e, "Any IPv4/IPv6/domain. Empty = your own IP.")
        ttk.Button(top, text="🔎 geo", style="Ghost.TButton",
                   command=lambda: self._do_geo(
                       self.geo_ip_var.get().strip()))\
            .pack(side="left", padx=(6, 0))
        tk.Label(top, textvariable=self.geo_txt, background=PANEL,
                 foreground=FG, font=(MONO, 10), justify="left",
                 anchor="w", padx=10, pady=4).pack(fill="x", pady=(4, 0))

        body = ttk.Labelframe(
            parent,
            text="  resolve host · scan CIDR for alive IPs (fragmented probes)  ")
        body.pack(fill="both", expand=True, pady=(6, 0))
        ctl = tk.Frame(body, background=BG)
        ctl.pack(fill="x", padx=8, pady=(6, 2))

        ttk.Label(ctl, text="cidr", style="Dim.TLabel")\
            .grid(row=0, column=0, padx=(0, 4))
        cidr_cb = ttk.Combobox(ctl, textvariable=self.scan_cidr_var,
                               values=CF_RANGES, width=16, font=(MONO, 10))
        cidr_cb.grid(row=0, column=1, padx=(0, 10))
        ttk.Label(ctl, text="count", style="Dim.TLabel").grid(row=0, column=2,
                                                              padx=(0, 4))
        ttk.Spinbox(ctl, from_=10, to=5000, increment=10, width=6,
                    textvariable=self.scan_count_var).grid(row=0, column=3,
                                                           padx=(0, 10))
        ttk.Label(ctl, text="workers", style="Dim.TLabel").grid(row=0,
                                                                column=4,
                                                                padx=(0, 4))
        ttk.Spinbox(ctl, from_=4, to=300, increment=4, width=5,
                    textvariable=self.scan_workers_var).grid(row=0, column=5,
                                                             padx=(0, 10))
        ttk.Label(ctl, text="port", style="Dim.TLabel").grid(row=0, column=6,
                                                             padx=(0, 4))
        self.scan_port_e = ttk.Entry(ctl, textvariable=self.scan_port_var,
                                     width=6, justify="center",
                                     font=(MONO, 10))
        self.scan_port_e.grid(row=0, column=7, padx=(0, 10))
        ttk.Label(ctl, text="sni", style="Dim.TLabel").grid(row=0, column=8,
                                                            padx=(0, 4))
        self.scan_sni_e = ttk.Entry(ctl, textvariable=self.scan_sni_var,
                                    width=22, font=(MONO, 10))
        self.scan_sni_e.grid(row=0, column=9, padx=(0, 10))
        ttk.Label(ctl, text="sni mode", style="Dim.TLabel")\
            .grid(row=1, column=0, padx=(0, 4), pady=(6, 2))
        sni_cb = ttk.Combobox(ctl, textvariable=self.sni_mode_var, width=11,
                              state="readonly",
                              values=("config sni", "no sni", "custom"))
        sni_cb.grid(row=1, column=1, sticky="w", pady=(6, 2))
        Tooltip(sni_cb,
                "config sni : hello carries your worker's SNI\n"
                "no sni     : raw IP aliveness (works even if SNI is blocked)\n"
                "custom     : use the sni field")
        ttk.Label(ctl, text="fragment", style="Dim.TLabel")\
            .grid(row=1, column=2, sticky="e", pady=(6, 2))
        sfrag_cb = ttk.Combobox(ctl, textvariable=self.scan_frag_var,
                                width=12, values=FRAG_PRESETS)
        sfrag_cb.grid(row=1, column=3, sticky="w", pady=(6, 2))
        Tooltip(sfrag_cb, "KEEP THIS ON in Iran — unfragmented scan hellos\n"
                          "get RST and every IP looks 'dead'.")
        curl_cb = ttk.Checkbutton(ctl, text="browser hello (curl_cffi)",
                                  variable=self.curl_var)
        curl_cb.grid(row=1, column=4, columnspan=3, sticky="w", pady=(6, 2))
        if not HAS_CURL_CFFI:
            curl_cb.config(state="disabled")
        self.btn_scan = ttk.Button(ctl, text="⚡  Scan", style="Accent.TButton",
                                   command=self._start_scan)
        self.btn_scan.grid(row=1, column=7, columnspan=2, sticky="e",
                           padx=(6, 4), pady=(6, 2))
        self.btn_stop_scan = ttk.Button(ctl, text="■", style="Ghost.TButton",
                                        width=3, command=self._stop_scan.set,
                                        state="disabled")
        self.btn_stop_scan.grid(row=1, column=9, sticky="e", pady=(6, 2))

        ttk.Label(ctl, text="resolve", style="Dim.TLabel")\
            .grid(row=2, column=0, columnspan=2, sticky="w", padx=(0, 4),
                  pady=(6, 2))
        self.res_host_e = ttk.Entry(ctl, textvariable=self.res_host_var,
                                    font=(MONO, 10))
        self.res_host_e.grid(row=2, column=2, columnspan=6, sticky="ew",
                             pady=(6, 2))
        self.res_host_e.bind("<Return>", lambda e: self._do_resolve())
        ttk.Button(ctl, text="➾ resolve DNS", style="Ghost.TButton",
                   command=self._do_resolve).grid(row=2, column=8,
                                                  columnspan=2, sticky="w",
                                                  pady=(6, 2))
        ttk.Label(ctl, textvariable=self.scan_prog_var,
                  style="Preview.TLabel").grid(row=2, column=10, sticky="e",
                                               pady=(6, 2))
        ctl.columnconfigure(2, weight=1)
        tk.Label(ctl, background=BG, foreground=MUT, font=(SANS, 9),
                 text="resolve compares DoH (1.1.1.1 / 8.8.8.8 / shecan / 403)"
                      " + Iranian UDP resolvers + system DNS — if they "
                      "disagree, your DNS is poisoned")\
            .grid(row=3, column=0, columnspan=11, sticky="w", pady=(2, 2))

        rbar = tk.Frame(body, background=BG)
        rbar.pack(fill="x", padx=8, pady=(2, 4))
        ttk.Button(rbar, text="🧪 test rows (TLS)", style="Ghost.TButton",
                   command=self._test_res_rows).pack(side="left")
        use_btn = ttk.Button(rbar, text="⤴ use as FORCE IP",
                             style="Ghost.TButton", command=self._use_force_ip)
        use_btn.pack(side="left", padx=(8, 0))
        Tooltip(use_btn, "Put the selected row's IP into FORCE IP on the "
                         "Configs tab.")
        ttk.Button(rbar, text="📋 copy IP", style="Ghost.TButton",
                   command=self._copy_res_ip).pack(side="left", padx=(8, 0))
        ttk.Button(rbar, text="🗑 clear", style="Ghost.TButton",
                   command=self._clear_res).pack(side="left", padx=(8, 0))
        tk.Label(rbar, text="double-click row → copy IP",
                 background=BG, foreground=MUT).pack(side="right")

        cols = {"ip": (150, "w"), "port": (60, "e"), "ms": (70, "e"),
                "tls": (90, "w"), "info": (250, "w")}
        self.res_tree = self._make_tree(body, cols, {"ms", "port"})
        self.res_tree.pack(fill="both", expand=True, padx=(8, 8), pady=(0, 8))
        self.res_tree.bind("<Double-Button-1>", self._copy_res_ip)

    # ------------------------------------------------------------ tree utils
    def _make_tree(self, parent: tk.Misc, cols: dict[str, tuple[int, str]],
                   numeric: set[str]) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=list(cols), show="headings",
                            selectmode="extended")
        for c, (w, anc) in cols.items():
            tree.heading(c, text=c)
            tree.column(c, width=w, anchor=anc, stretch=(anc == "w" or w > 100))
        for tag, color in (("ok", GREEN), ("mid", YELLOW), ("bad", RED),
                           ("dim", MUT)):
            tree.tag_configure(tag, foreground=color)
        st: dict[str, Any] = {"col": None, "rev": False}

        def sort(col: str) -> None:
            if st["col"] == col:
                st["rev"] = not st["rev"]
            else:
                st["col"] = col
                st["rev"] = False

            def key(iid: str) -> Any:
                v = str(tree.set(iid, col)).strip()
                if col in numeric:
                    try:
                        return float(v)
                    except ValueError:
                        return float("inf")
                return v

            ordered = sorted(tree.get_children(""), key=key,
                             reverse=st["rev"])
            for i, iid in enumerate(ordered):
                tree.move(iid, "", i)

        for c in cols:
            tree.heading(c, command=lambda c=c: sort(c))
        return tree

    def _make_text(self, parent: tk.Misc, state: TextState = "normal",
                   bg: str = PANEL) -> tk.Text:
        wrap = tk.Frame(parent, background=BG)
        wrap.pack(fill="both", expand=True)
        txt = tk.Text(wrap, wrap="none", state=state, undo=True,
                      background=bg, foreground=FG, insertbackground=FG,
                      selectbackground=ACCENT, selectforeground=ACCENT_FG,
                      inactiveselectbackground=PANEL2, relief="flat",
                      padx=10, pady=8, font=(MONO, 10), spacing1=1,
                      spacing3=1)
        ys = ttk.Scrollbar(wrap, orient="vertical", command=txt.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        txt.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        txt.bind("<Control-a>", self._select_all)
        return txt

    # ---------------------------------------------------------------- mode
    def _on_mode_change(self, *_a: Any) -> None:
        m = self.mode_var.get()
        if m == MODE_FULL:
            self.fp_on.set(True)
            self.cs_on.set(True)
            self.fm_on.set(True)
        elif m == MODE_IPONLY:
            self.fp_on.set(False)
            self.cs_on.set(False)
            self.fm_on.set(False)
        self._update_mode_desc()
        self._schedule()

    def _switch_touched(self) -> None:
        if self.mode_var.get() != MODE_CUSTOM:
            self.mode_var.set(MODE_CUSTOM)
        self._update_mode_desc()

    def _update_mode_desc(self) -> None:
        descs = {
            MODE_FULL: ("fp→unsafe + cipher suites + fragment mask — standard "
                        "hardening", ACCENT),
            MODE_IPONLY: ("nothing injected — only endpoint override / rename "
                          "apply", PURPLE),
            MODE_CUSTOM: ("custom mix — the switches decide what gets "
                          "injected", YELLOW),
        }
        txt, col = descs.get(self.mode_var.get(), ("", MUT))
        self.mode_desc.config(text=txt, foreground=col)

    def _sync_rule_fields(self) -> None:
        self.fp_entry.config(state="normal" if self.fp_on.get() else "disabled")
        self.cs_entry.config(state="normal" if self.cs_on.get() else "disabled")
        self.fm_entry.config(state="normal" if self.fm_on.get() else "disabled")

    # ------------------------------------------------------------- override
    def _toggle_override(self) -> None:
        self.ip_entry.config(state="normal" if self.ip_on.get() else "disabled")
        self.port_entry.config(
            state="normal" if self.port_on.get() else "disabled")
        self._refresh_override_indicators()

    def _clear_override(self) -> None:
        self.ip_on.set(False)
        self.port_on.set(False)
        self.ip_var.set("")
        self.port_var.set("")
        self.msg_var.set("mass override cleared — original endpoints kept")

    def _refresh_override_indicators(self) -> None:
        if self.ip_on.get():
            kind = classify_endpoint(self.ip_var.get())
            ok = bool(self.ip_var.get().strip()) and kind is not None
            self.ip_badge.set(f"✓ {kind}" if ok else "✗ ipv4 / ipv6 / domain")
            self.ip_badge_lbl.config(style="Good.TLabel" if ok else "Err.TLabel")
            self.ip_entry.config(foreground="#9fe8ff" if ok else "#ff8b8b")
        else:
            self.ip_badge.set("")
        if self.port_on.get():
            ok = valid_port(self.port_var.get().strip())
            self.port_badge.set("✓" if ok else "✗ 1-65535")
            self.port_badge_lbl.config(style="Good.TLabel" if ok else "Err.TLabel")
            self.port_entry.config(foreground="#9fe8ff" if ok else "#ff8b8b")
        else:
            self.port_badge.set("")
        ip = self.ip_var.get().strip() \
            if (self.ip_on.get() and classify_endpoint(self.ip_var.get())) \
            else "orig"
        pv = self.port_var.get().strip() \
            if (self.port_on.get() and valid_port(self.port_var.get())) \
            else "orig"
        self.ep_preview.set(
            f"endpoint → {ip}:{pv}"
            if (self.ip_on.get() or self.port_on.get()) else "")

    # ------------------------------------------------------------------ keys
    def _bind_keys(self) -> None:
        self.bind("<Control-Return>", self.do_convert)
        self.bind("<Control-Shift-C>", self.copy_output)
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        for seq in ("<KeyRelease>", "<<Paste>>", "<<Undo>>", "<<Redo>>"):
            self.input_txt.bind(seq, lambda e: self._schedule())
        for var in (self.fp_var, self.cs_var, self.fm_var, self.tpl_var,
                    self.ip_var, self.port_var):
            var.trace_add("write", lambda *a: self._schedule())
        for var in (self.fp_on, self.cs_on, self.fm_on):
            var.trace_add("write", lambda *a: self._sync_rule_fields())
        for var in (self.fp_on, self.cs_on, self.fm_on, self.rename_var,
                    self.tls_only_var, self.ip_on, self.port_on,
                    self.start_var):
            var.trace_add("write", lambda *a: self._schedule())
        self.rename_var.trace_add("write", lambda *a: self._toggle_rename())
        self.ip_on.trace_add("write",
                             lambda *a: self._refresh_override_indicators())
        self.port_on.trace_add("write",
                               lambda *a: self._refresh_override_indicators())
        reg = self.register(lambda P: P == "" or (P.isdigit() and len(P) <= 5))
        self.port_entry.config(validate="key", validatecommand=(reg, "%P"))
        self.scan_port_e.config(validate="key", validatecommand=(reg, "%P"))

    @staticmethod
    def _select_all(event: Any) -> str:
        event.widget.tag_add("sel", "1.0", "end")
        return "break"

    def _schedule(self) -> None:
        if not self.auto_var.get():
            return
        if self._job:
            self.after_cancel(self._job)
        self._job = self.after(450, self.do_convert)

    def _on_tab_changed(self, _event: Any) -> None:
        if self.nb.select() in (str(self.test_tab), str(self.xray_tab)) \
                and self._out_dirty:
            self._build_tester_list()

    def _toggle_rename(self) -> None:
        state = "normal" if self.rename_var.get() else "disabled"
        self.tpl_entry.config(state=state)
        self.start_spin.config(state=state)

    def _show_keys(self) -> None:
        messagebox.showinfo(
            "Naming template keys",
            "Template is a Python format string, e.g.\n"
            "    {id:02d}_{sub}_{path}   →  07_edgestuff_sort\n\n"
            "{id} index · {sub} subdomain · {path} decoded path\n"
            "{ip} endpoint IP · {port} endpoint port (OVERRIDDEN values\n"
            "when mass override is on) · {host} full domain · {net} domain\n"
            "without sub · {sni} · {proto} · {old} previous name\n\n"
            "Duplicates are auto-suffixed so names stay unique.",
            parent=self)

    # -------------------------------------------------------------- convert
    def do_convert(self, event: Any = None) -> None:
        text = self.input_txt.get("1.0", "end-1c")
        if not text.strip():
            self._set_output([])
            self._set_names([])
            self._set_counts(0, 0, 0)
            self.msg_var.set("Paste configs on the left — conversion is live.")
            return
        fp = self.fp_var.get().strip() or DEFAULT_FP
        cs = self.cs_var.get().strip()
        tpl = self.tpl_var.get().strip() or DEFAULT_TEMPLATE
        start = self.start_var.get() or 1
        want_fp = self.fp_on.get()
        want_cs = self.cs_on.get()
        want_fm = self.fm_on.get()

        fm = ""
        if want_fm:
            fm_raw = self.fm_var.get().strip()
            if fm_raw:
                try:
                    fm = compact_json(json.loads(fm_raw))
                except json.JSONDecodeError:
                    self.msg_var.set(
                        "✖ fm is not valid JSON — fix it to re-run live.")
                    return

        warn: list[str] = []
        ov_ip, ov_port = "", ""
        if self.ip_on.get():
            kind = classify_endpoint(self.ip_var.get())
            if kind:
                ov_ip = self.ip_var.get().strip()
            else:
                warn.append("invalid override IP (ignored)")
        if self.port_on.get():
            v = self.port_var.get().strip()
            if valid_port(v):
                ov_port = v
            else:
                warn.append("invalid override port (ignored)")

        lines, names, c = convert_block(
            text, fp, cs, fm, self.tls_only_var.get(),
            self.rename_var.get(), tpl, start, ov_ip, ov_port,
            want_fp, want_cs, want_fm)
        self._set_output(lines)
        self._set_names(names)
        self._set_counts(c["fixed"], c["unchanged"], c["skipped"])

        ep = ""
        if ov_ip or ov_port:
            ep = f"  ·  endpoint→{ov_ip or 'orig'}:{ov_port or 'orig'}"
        inj = "" if (want_fp or want_cs or want_fm) \
            else "  ·  no injection (IP-only)"
        msg = f"✔ done  ·  {self.mode_var.get()}{ep}{inj}"
        if warn:
            msg = "⚠ " + ", ".join(warn) + "  ·  " + msg
        self.msg_var.set(msg)

    def _set_output(self, lines: list[str]) -> None:
        self.output_txt.configure(state="normal")
        self.output_txt.delete("1.0", "end")
        if lines:
            self.output_txt.insert("1.0", "\n".join(lines))
        self.output_txt.configure(state="disabled")
        self._out_dirty = True

    def _set_names(self, pairs: list[tuple[str, str]]) -> None:
        self._name_lines = pairs
        self.names_lb.delete(0, "end")
        for name, _ in pairs:
            self.names_lb.insert("end", name)
        self.nb.tab(1, text=f"  🏷 Names ({len(pairs)})  ")

    def _set_counts(self, fixed: int, same: int, skip: int) -> None:
        self.v_fixed.set(f"✎ {fixed} updated")
        self.v_same.set(f"↺ {same} unchanged")
        self.v_skip.set(f"⚠ {skip} skipped")

    # --------------------------------------------------------------- tester
    def _build_tester_list(self) -> None:
        text = self.output_txt.get("1.0", "end-1c")
        self._targets = []
        self.test_tree.delete(*self.test_tree.get_children(""))
        i = 0
        for line in text.splitlines():
            if not line.strip():
                continue
            t = parse_target(line)
            if not t:
                continue
            t["iid"] = f"t{i}"
            t["line"] = line.strip()
            t["cc"] = ""
            t["cc_edge"] = False
            t["cc_info"] = ""
            t["exit_ip"] = ""
            self._targets.append(t)
            self.test_tree.insert("", "end", iid=t["iid"],
                                  values=(t["name"],
                                          f"{t['host']}:{t['port']}",
                                          "—", "—", "—", "—", "", ""),
                                  tags=("dim",))
            i += 1
        if self._targets:
            if not self.scan_sni_var.get().strip():
                self.scan_sni_var.set(self._targets[0]["sni"])
            if self.scan_port_var.get().strip() in ("", "443") \
                    and self._targets[0]["port"] != "443":
                self.scan_port_var.set(self._targets[0]["port"])
        self._out_dirty = False
        self.test_info_var.set(f"{len(self._targets)} configs loaded")

    def _start_test(self, only_selected: bool) -> None:
        if self._testing:
            return
        if self._out_dirty:
            self._build_tester_list()
        rows = self._targets
        if only_selected:
            sel = set(self.test_tree.selection())
            rows = [t for t in rows if t["iid"] in sel]
        if not rows:
            self.msg_var.set("nothing to test — convert some configs first")
            return
        try:
            tmo = max(1.0, float(self.tmo_var.get() or 3))
        except ValueError:
            tmo = 3.0
        att = max(1, int(self.att_var.get() or 1))
        try:
            workers = max(1, int(self.workers_test_var.get() or 16))
        except (ValueError, tk.TclError):
            workers = 16
        mode = self.mode_test_var.get()
        frag = parse_frag(self.frag_var.get())
        target = parse_test_target(self.target_var.get())
        cc_on = self.cc_on.get()
        self._testing = True
        self._stop_test.clear()
        self._test_done = 0
        self._test_total = len(rows)
        self._set_test_buttons(False)
        self.test_prog_var.set(f"0/{len(rows)}")
        self._test_ex = ThreadPoolExecutor(max_workers=workers)
        for i, t in enumerate(rows):
            self._test_ex.submit(self._test_job, t, mode, tmo, att, frag,
                                 target, cc_on, i)

    def _test_job(self, t: dict[str, Any], mode: str, tmo: float, att: int,
                  frag: tuple | None, target: tuple, cc_on: bool, rr: int) \
            -> None:
        stop = self._stop_test
        res: dict[str, Any] = {"tcp": None, "tls": None, "ws": None,
                               "real": None, "cc": "", "cc_edge": False,
                               "exit_ip": "", "status": ""}
        try:
            tcp = tcp_ping(t["host"], t["port"], timeout=tmo, attempts=att,
                           stop=stop)
            res["tcp"] = tcp
            if tcp is None:
                res["status"] = "tcp ✖ unreachable / filtered"
            elif mode == "tcp only":
                res["status"] = "tcp ok"
            else:
                sni = None if (is_ip(t["sni"]) or ":" in t["sni"]) \
                    else (t["sni"] or None)
                try:
                    tc, sock, info = tls_connect(t["host"], t["port"],
                                                 sni=sni, frag=frag,
                                                 timeout=tmo + 2, stop=stop)
                except ProbeError as pe:
                    res["status"] = f"tls ✖ {pe.detail}"
                    if frag is None:
                        res["status"] += "  · turn fragment ON"
                    raise _Done()
                res["tls"] = info["tls_ms"]
                try:
                    if mode == "tls only":
                        res["status"] = f"tls ok · {info['ver']}"
                    else:
                        line, wsms = ws_upgrade(tc, t["hdr"], t["path"],
                                                timeout=tmo + 2, stop=stop)
                        res["ws"] = wsms
                        if line.startswith("HTTP/1.1 101"):
                            if mode.startswith("full"):
                                self._stage_full(t, tc, sock, sni, frag, res,
                                                 target, cc_on, rr, tmo, stop)
                            else:
                                self._stage_ws(t, tc, sock, sni, frag, res,
                                               cc_on, rr, tmo, stop)
                        else:
                            res["status"] = line[:90] or "empty reply"
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
        except _Done:
            pass
        except ProbeError as pe:
            res["status"] = f"{pe.stage} ✖ {pe.detail}"
        except Exception as e:
            res["status"] = f"error: {type(e).__name__}"
        # last-resort: edge-IP country (marked '*')
        if cc_on and not res.get("cc") and is_ip(t["host"]) \
                and not stop.is_set():
            self._edge_cc(t, res)
        if stop.is_set():
            res["status"] = res["status"] or "stopped"
        self.q.put(("test", t["iid"], res))

    def _stage_full(self, t: dict[str, Any], tc: TLSClient,
                    sock: socket.socket, sni: str | None, frag: tuple | None,
                    res: dict[str, Any], target: tuple, cc_on: bool, rr: int,
                    tmo: float, stop: threading.Event | None) -> None:
        if not cc_on:
            try:
                sch, th, tp, tpath = target
                tun = VlessTunnel(tc, t.get("uuid", ""), th, tp, stop)
                if sch == "https":
                    ms, s2 = real_delay_https(tun, th, tp, tpath,
                                              timeout=tmo + 3, stop=stop)
                else:
                    ms, s2 = real_delay_http(tun, th, tpath,
                                             timeout=tmo + 3, stop=stop)
                res["real"] = ms
                res["status"] = f"101 · REAL {ms:.0f}ms · {s2[:44]}"
            except ProbeError as pe:
                res["status"] = f"101 ws ok · real ✖ {pe.stage}: " \
                                f"{pe.detail[:44]}"
            return
        last = ""
        for k, (sch, ghost, gpath) in enumerate(rotated_geo(rr)):
            try:
                cc, ip, detail, ms = probe_geo_source(
                    t, tc if k == 0 else None, sock if k == 0 else None,
                    sni, frag, sch, ghost, gpath, tmo + 4, stop)
                res["cc"] = cc
                res["cc_edge"] = False
                res["real"] = ms
                res["exit_ip"] = ip
                t["cc"], t["cc_edge"], t["cc_info"] = cc, False, detail
                t["exit_ip"] = ip
                res["status"] = f"101 · REAL {ms:.0f}ms · {cc_flag(cc)} {cc}" \
                                f" · {ip}"
                return
            except ProbeError as pe:
                last = pe.detail
                if stop is not None and stop.is_set():
                    break
        res["status"] = f"101 ws ok · geo ✖ {last[:44]}"

    def _stage_ws(self, t: dict[str, Any], tc: TLSClient,
                  sock: socket.socket, sni: str | None, frag: tuple | None,
                  res: dict[str, Any], cc_on: bool, rr: int, tmo: float,
                  stop: threading.Event | None) -> None:
        if not cc_on:
            res["status"] = "101 · ws path alive"
            return
        last = ""
        for k, (sch, ghost, gpath) in enumerate(rotated_geo(rr)):
            try:
                cc, ip, detail, _ms = probe_geo_source(
                    t, tc if k == 0 else None, sock if k == 0 else None,
                    sni, frag, sch, ghost, gpath, tmo + 4, stop)
                res["cc"] = cc
                res["cc_edge"] = False
                res["exit_ip"] = ip
                t["cc"], t["cc_edge"], t["cc_info"] = cc, False, detail
                t["exit_ip"] = ip
                res["status"] = f"101 · exit {cc_flag(cc)} {cc} · {ip}"
                return
            except ProbeError as pe:
                last = pe.detail
                if stop is not None and stop.is_set():
                    break
        res["status"] = f"101 · ws alive · geo ✖ {last[:40]}"

    def _edge_cc(self, t: dict[str, Any], res: dict[str, Any]) -> None:
        cc = cc_of_ip(t["host"])
        if cc:
            t["cc"], t["cc_edge"] = cc, True
            res["cc"], res["cc_edge"] = cc, True

    @staticmethod
    def _row_tag(status: str) -> str:
        s = status.upper()
        if "101" in s or s.startswith("CORE EXIT"):
            return "ok"
        if s.startswith("TLS OK") or s.startswith("TCP OK"):
            return "ok"
        if "HTTP/1.1 4" in s or "HTTP/1.1 5" in s:
            return "mid"
        if "STOPPED" in s:
            return "dim"
        return "bad"

    def _bump_test_done(self) -> None:
        self._test_done += 1
        self.test_prog_var.set(f"{self._test_done}/{self._test_total}")
        if self._test_done >= self._test_total:
            ok = 0
            for iid in self.test_tree.get_children(""):
                st = self.test_tree.set(iid, "status").upper()
                if st.startswith(("101", "TLS OK", "TCP OK", "CORE EXIT")):
                    ok += 1
            ccs = [t.get("cc", "") for t in self._targets if t.get("cc")]
            summary = ""
            if ccs:
                uniq = sorted(set(ccs))
                counts = [(c, ccs.count(c)) for c in uniq]
                counts.sort(key=lambda x: -x[1])
                summary = " · 🌍 " + ", ".join(
                    f"{c}×{n}" for c, n in counts[:6])
                if len(uniq) > 6:
                    summary += f" +{len(uniq) - 6}"
            self._testing = False
            self._set_test_buttons(True)
            if self._test_ex:
                self._test_ex.shutdown(wait=False)
                self._test_ex = None
            self.msg_var.set(f"📡 test finished — {ok}/{self._test_total} "
                             f"alive{summary}")

    def _set_test_buttons(self, enabled: bool) -> None:
        st = "normal" if enabled else "disabled"
        for b in (self.btn_test_all, self.btn_test_sel, self.btn_core_quick,
                  self.btn_core_all, self.btn_core_sel):
            b.config(state=st)
        self.btn_stop_test.config(state="disabled" if enabled else "normal")

    def _copy_test_line(self, _event: Any) -> None:
        sel = self.test_tree.selection()
        if not sel:
            return
        for t in self._targets:
            if t["iid"] == sel[0]:
                self.clipboard_clear()
                self.clipboard_append(t["line"])
                self.msg_var.set(f"📋 copied config for '{t['name']}'")
                return

    # ----------------------------------------------------------- xray core
    def _pick_core(self) -> None:
        p = filedialog.askopenfilename(
            parent=self, title="Locate xray / xray.exe",
            filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if p:
            self.core_var.set(p)
            self._check_core_clicked()

    def _detect_core(self) -> None:
        p = find_xray_core()
        if p:
            self.core_var.set(p)
            self.msg_var.set(f"🔍 core found: {p}")
            self._check_core_clicked()
        else:
            self.core_status_var.set(
                "✖ nothing found — browse to xray.exe manually")

    def _startup_core_check(self) -> None:
        if self.core_var.get().strip():
            self._check_core_async()

    def _check_core_clicked(self) -> None:
        core = self.core_var.get().strip()
        if not core:
            self.msg_var.set("set or auto-detect the core path first")
            return
        self.core_status_var.set("… checking …")
        self._check_core_async()

    def _check_core_async(self) -> None:
        core = self.core_var.get().strip()
        if not core:
            return

        def job() -> None:
            self.q.put(("corever", check_core_version(core)))

        threading.Thread(target=job, daemon=True).start()

    def _start_core_test(self, only_selected: bool) -> None:
        if self._testing:
            return
        core = self.core_var.get().strip()
        if not core or not os.path.isfile(core):
            self.msg_var.set("set a valid xray core path (🧩 Xray Core tab)")
            self.nb.select(self.xray_tab)
            return
        if self._out_dirty:
            self._build_tester_list()
        rows = self._targets
        if only_selected:
            sel = set(self.test_tree.selection())
            rows = [t for t in rows if t["iid"] in sel]
        if not rows:
            self.msg_var.set("nothing to test — convert some configs first")
            return
        snap = {t["iid"]: (self.test_tree.set(t["iid"], "tcp"),
                           self.test_tree.set(t["iid"], "tls"),
                           self.test_tree.set(t["iid"], "ws")) for t in rows}
        try:
            workers = max(1, min(16, int(self.core_workers_var.get() or 8)))
        except (ValueError, tk.TclError):
            workers = 8
        try:
            tmo = max(3.0, float(self.core_timeout_var.get() or 8))
        except ValueError:
            tmo = 8.0
        frag_on = self.core_frag_on.get()
        self._testing = True
        self._stop_test.clear()
        self._test_done = 0
        self._test_total = len(rows)
        self._set_test_buttons(False)
        self.test_prog_var.set(f"0/{len(rows)}")
        self.nb.select(self.test_tab)
        self._test_ex = ThreadPoolExecutor(max_workers=workers)
        for t in rows:
            self._test_ex.submit(self._core_job, t, core, frag_on, tmo,
                                 snap.get(t["iid"], ("—", "—", "—")))

    def _core_job(self, t: dict[str, Any], core: str, frag_on: bool,
                  tmo: float, snap: tuple) -> None:
        res: dict[str, Any] = {"tcp": snap[0], "tls": snap[1], "ws": snap[2],
                               "real": None, "cc": "", "cc_edge": False,
                               "exit_ip": "", "status": ""}
        if self._stop_test.is_set():
            res["status"] = "stopped"
            self.q.put(("test", t["iid"], res))
            return
        r = xray_probe(t["line"], core, frag_on, timeout=tmo)
        res["real"] = r.get("real")
        cc = r.get("cc", "")
        res["cc"] = cc
        res["exit_ip"] = r.get("exit_ip", "")
        if cc:
            t["cc"], t["cc_edge"] = cc, False
            t["exit_ip"] = r.get("exit_ip", "")
            t["cc_info"] = f"core · {t['exit_ip']}"
            res["status"] = (f"core · exit {cc_flag(cc)} {cc} · "
                             f"{t['exit_ip']}")
        else:
            res["status"] = r.get("status", "core failed")
        self.q.put(("test", t["iid"], res))

    # ----------------------------------------------------------- ip finder
    def _do_geo(self, ip: str | None) -> None:
        self.geo_txt.set("… looking up …")
        threading.Thread(target=self._geo_job, args=(ip or "",),
                         daemon=True).start()

    def _geo_job(self, ip: str) -> None:
        try:
            self.q.put(("geo", geo_lookup(ip)))
        except Exception as e:
            self.q.put(("geo", f"lookup error: {type(e).__name__}: {e}"))

    def _do_resolve(self) -> None:
        host = self.res_host_var.get().strip()
        if not host:
            self.msg_var.set("type a hostname to resolve")
            return
        self.msg_var.set(
            f"resolving {host} (DoH + Iranian resolvers + system) …")
        threading.Thread(target=self._resolve_job, args=(host,),
                         daemon=True).start()

    def _resolve_job(self, host: str) -> None:
        try:
            found = resolve_dns_all(host)
        except Exception as e:
            self.q.put(("resolve_err", str(e)))
            return
        self.q.put(("resolve", host, found))

    def _first_sni(self) -> str:
        return self._targets[0]["sni"] if self._targets else ""

    def _start_scan(self) -> None:
        if self._scanning:
            return
        cidr = self.scan_cidr_var.get().strip()
        try:
            count = max(1, int(self.scan_count_var.get() or 100))
        except (ValueError, tk.TclError):
            count = 100
        try:
            workers = max(4, int(self.scan_workers_var.get() or 100))
        except (ValueError, tk.TclError):
            workers = 100
        ips = sample_cidr(cidr, count)
        if not ips:
            self.msg_var.set("✖ bad CIDR — try e.g. 104.16.0.0/13")
            return
        port = self.scan_port_var.get().strip() or "443"
        if not valid_port(port):
            self.msg_var.set("✖ bad scan port (1-65535)")
            return
        mode = self.sni_mode_var.get()
        sni: str | None
        if mode == "no sni":
            sni = None
        elif mode == "custom":
            cand = self.scan_sni_var.get().strip() or None
            sni = None if (not cand or is_ip(cand) or ":" in cand) else cand
        else:
            cand = self._first_sni() or self.scan_sni_var.get().strip() or None
            sni = None if (not cand or is_ip(cand) or ":" in cand) else cand
        self._scan_frag = parse_frag(self.scan_frag_var.get())
        self._scanning = True
        self._stop_scan.clear()
        self._scan_done = 0
        self._scan_alive = 0
        self._scan_total = len(ips)
        self.btn_scan.config(state="disabled")
        self.btn_stop_scan.config(state="normal")
        self.scan_prog_var.set(f"0/{len(ips)}")
        info = f"{cidr}" + (f" · sni:{sni or 'none'}" if sni else " · sni:none")
        self._scan_ex = ThreadPoolExecutor(max_workers=workers)
        for ip in ips:
            iid = f"s{self._scan_iid}"
            self._scan_iid += 1
            self._scan_meta[iid] = (ip, port, sni, info)
            self.res_tree.insert("", "end", iid=iid,
                                 values=(ip, port, "…", "", info),
                                 tags=("dim",))
            self._scan_ex.submit(self._scan_job, iid, ip, port, sni)

    def _scan_job(self, iid: str, ip: str, port: str, sni: str | None) -> None:
        if self.curl_var.get() and HAS_CURL_CFFI:
            try:
                r = curl_cffi_probe(ip, port, sni, timeout=4.0)
            except ProbeError as pe:
                self.q.put(("scan", iid, None,
                            f"{pe.stage}: {pe.detail}"[:60]))
                return
            self.q.put(("scan", iid, r, ""))
            return
        try:
            _tc, sock, info = tls_connect(ip, port, sni=sni,
                                          frag=self._scan_frag, timeout=3.5,
                                          stop=self._stop_scan)
        except ProbeError as pe:
            self.q.put(("scan", iid, None, f"{pe.stage}: {pe.detail}"[:60]))
            return
        try:
            sock.close()
        except Exception:
            pass
        self.q.put(("scan", iid, info, ""))

    def _bump_scan_done(self) -> None:
        self._scan_done += 1
        self.scan_prog_var.set(f"{self._scan_done}/{self._scan_total}")
        if self._scan_done >= self._scan_total:
            self._scanning = False
            self.btn_scan.config(state="normal")
            self.btn_stop_scan.config(state="disabled")
            if self._scan_ex:
                self._scan_ex.shutdown(wait=False)
                self._scan_ex = None
            self.msg_var.set(
                f"🌐 scan finished — {self._scan_alive}/{self._scan_total} "
                f"alive")

    def _test_res_rows(self) -> None:
        if self._scanning:
            return
        iids = list(self.res_tree.selection()) or \
            list(self.res_tree.get_children(""))
        iids = [i for i in iids if i in self._scan_meta]
        if not iids:
            self.msg_var.set("no rows to test")
            return
        self._scanning = True
        self._stop_scan.clear()
        self._scan_done = 0
        self._scan_alive = 0
        self._scan_total = len(iids)
        self.btn_scan.config(state="disabled")
        self.btn_stop_scan.config(state="normal")
        self.scan_prog_var.set(f"0/{len(iids)}")
        self._scan_ex = ThreadPoolExecutor(max_workers=32)
        for iid in iids:
            ip, port, sni, _info = self._scan_meta[iid]
            self._scan_ex.submit(self._scan_job, iid, ip, port, sni)

    def _use_force_ip(self) -> None:
        sel = self.res_tree.selection()
        if not sel:
            self.msg_var.set("select a row first")
            return
        ip = self.res_tree.set(sel[0], "ip")
        self.ip_on.set(True)
        self.ip_var.set(ip)
        self._toggle_override()
        self.msg_var.set(f"⤴ FORCE IP set to {ip} — output re-converts live")
        self._schedule()

    def _copy_res_ip(self, _event: Any = None) -> None:
        sel = self.res_tree.selection()
        if not sel:
            return
        ip = self.res_tree.set(sel[0], "ip")
        self.clipboard_clear()
        self.clipboard_append(ip)
        self.msg_var.set(f"📋 copied {ip}")

    def _clear_res(self) -> None:
        self.res_tree.delete(*self.res_tree.get_children(""))
        self._scan_meta.clear()
        self.scan_prog_var.set("")

    # -------------------------------------------------------------- queue
    def _drain(self) -> None:
        try:
            for _ in range(400):
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "test":
                    iid, res = msg[1], msg[2]
                    if self.test_tree.exists(iid):
                        self.test_tree.item(iid, values=(
                            self.test_tree.set(iid, "name"),
                            self.test_tree.set(iid, "endpoint"),
                            fmt_ms(res.get("tcp")), fmt_ms(res.get("tls")),
                            fmt_ms(res.get("ws")), fmt_ms(res.get("real")),
                            cc_cell(res.get("cc", ""),
                                    bool(res.get("cc_edge"))),
                            res.get("status", "")),
                            tags=(self._row_tag(res.get("status", "")),))
                    self._bump_test_done()
                elif kind == "scan":
                    iid, res, detail = msg[1], msg[2], msg[3]
                    if self.res_tree.exists(iid):
                        ip, port, _sni, info = self._scan_meta.get(
                            iid, ("?", "", None, ""))
                        if res:
                            self._scan_alive += 1
                            tag = "ok" if res["tls_ms"] < 300 else "mid"
                            self.res_tree.item(iid, values=(
                                ip, port, f"{res['tls_ms']:.0f}",
                                str(res.get("ver", ""))[:9], info), tags=(tag,))
                        else:
                            self.res_tree.item(iid, values=(
                                ip, port, "✗", "",
                                f"{info} — {detail}"[:70]), tags=("bad",))
                    self._bump_scan_done()
                elif kind == "resolve":
                    host, found = msg[1], msg[2]
                    if not found:
                        self.msg_var.set(f"✖ could not resolve {host} "
                                         "(all resolvers failed/blocked)")
                    else:
                        port = self.scan_port_var.get().strip() or "443"
                        sni = self.scan_sni_var.get().strip() \
                            or self._first_sni()
                        for ip, srcs in found.items():
                            iid = f"r{self._scan_iid}"
                            self._scan_iid += 1
                            note = f"DNS {host} · via {', '.join(srcs)}"[:70]
                            self._scan_meta[iid] = (ip, port, sni, note)
                            self.res_tree.insert("", "end", iid=iid,
                                                 values=(ip, port, "—", "",
                                                         note), tags=("dim",))
                        self.msg_var.set(
                            f"🌐 {host} → {len(found)} IP(s) — hit "
                            f"'test rows' to probe them")
                elif kind == "resolve_err":
                    self.msg_var.set(f"✖ resolve error: {msg[1]}")
                elif kind == "geo":
                    self.geo_txt.set(msg[1])
                elif kind == "corever":
                    self.core_status_var.set(msg[1])
        except queue.Empty:
            pass
        self.after(120, self._drain)

    # -------------------------------------------------------------- actions
    def copy_output(self, event: Any = None) -> None:
        text = self.output_txt.get("1.0", "end-1c").strip()
        if not text:
            self.msg_var.set("Nothing to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.msg_var.set("📋 output copied")

    def copy_names(self) -> None:
        if not self._name_lines:
            self.msg_var.set("No names yet.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(n for n, _ in self._name_lines))
        self.msg_var.set("📋 names copied")

    def _copy_named_line(self, _event: Any) -> None:
        sel = self.names_lb.curselection()
        if not sel:
            return
        name, line = self._name_lines[sel[0]]
        self.clipboard_clear()
        self.clipboard_append(line)
        self.msg_var.set(f"📋 copied config for '{name}'")

    def _tag_names_with_cc(self) -> None:
        if self._testing:
            self.msg_var.set("wait for the test to finish first")
            return
        if not self._targets:
            self.msg_var.set("nothing to tag — test some configs first")
            return
        changed = 0
        for t in self._targets:
            cc = t.get("cc") or ""
            if not cc or t.get("cc_edge"):
                continue                      # only tunnel/core-verified exits
            if f"[{cc}]" in t.get("name", ""):
                continue
            old_line = t["line"]
            new_line = rename_fragment(old_line, f"[{cc}]")
            if new_line == old_line:
                continue
            t["line"] = new_line
            t["name"] = t["name"] + f"[{cc}]"
            self.output_txt.configure(state="normal")
            pos = self.output_txt.search(old_line, "1.0", exact=True)
            if pos:
                self.output_txt.delete(pos, f"{pos}+{len(old_line)}c")
                self.output_txt.insert(pos, new_line)
            self.output_txt.configure(state="disabled")
            for i, (n, l) in enumerate(self._name_lines):
                if l == old_line:
                    self._name_lines[i] = (t["name"], new_line)
                    self.names_lb.delete(i)
                    self.names_lb.insert(i, t["name"])
                    break
            iid = t["iid"]
            if self.test_tree.exists(iid):
                vals = list(self.test_tree.item(iid, "values"))
                vals[0] = t["name"]
                self.test_tree.item(iid, values=vals)
            changed += 1
        self.msg_var.set(f"🏷 tagged {changed} config name(s) with "
                         f"[exit-country]")

    def save_output(self) -> None:
        text = self.output_txt.get("1.0", "end-1c").strip()
        if not text:
            self.msg_var.set("Nothing to save.")
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".txt",
            initialfile="vless_fixed.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            self.msg_var.set(f"💾 saved → {path}")
        except OSError as e:
            messagebox.showerror("Save failed", str(e), parent=self)

    def load_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
        except OSError as e:
            messagebox.showerror("Open failed", str(e), parent=self)
            return
        self.input_txt.delete("1.0", "end")
        self.input_txt.insert("1.0", data)
        self.msg_var.set(f"📂 loaded {path}")
        self._schedule()

    def load_sample(self) -> None:
        self.input_txt.delete("1.0", "end")
        self.input_txt.insert("1.0", SAMPLE)
        self._schedule()

    def clear_all(self) -> None:
        self.input_txt.delete("1.0", "end")
        self._set_output([])
        self._set_names([])
        self._set_counts(0, 0, 0)
        self.msg_var.set("🧹 cleared")

    def reset_defaults(self) -> None:
        self.mode_var.set(MODE_FULL)
        self.fp_var.set(DEFAULT_FP)
        self.cs_var.set(DEFAULT_CS)
        self.fm_var.set(compact_json(DEFAULT_FM))
        self.tpl_var.set(DEFAULT_TEMPLATE)
        self.start_var.set(1)
        self.rename_var.set(True)
        self.tls_only_var.set(True)
        self.ip_on.set(False)
        self.port_on.set(False)
        self.ip_var.set("")
        self.port_var.set("")
        self.frag_var.set(FRAG_PRESETS[0])
        self.target_var.set(TEST_TARGET_DEFAULT)
        self.cc_on.set(True)
        self._on_mode_change()
        self.msg_var.set("♻ defaults restored (Full fix mode)")
        self._schedule()

    def _on_close(self) -> None:
        self._stop_test.set()
        self._stop_scan.set()
        self.destroy()


# ===========================================================================
# CLI
# ===========================================================================

def cli_test(lines: list[str], timeout: float, frag_s: str = "5,94,1@2",
             real: bool = True, cc_on: bool = True, workers: int = 12,
             core_path: str = "") -> None:
    frag = parse_frag(frag_s)
    targets = [t for t in (parse_target(l) for l in lines) if t]
    if not targets:
        print("nothing testable found")
        return
    print(f"testing {len(targets)} configs "
          f"(fragment={'on' if frag else 'off'}, timeout {timeout}s, "
          f"exit-country={'on' if cc_on else 'off'}"
          + (f", core={os.path.basename(core_path)}" if core_path else "")
          + ") ...")
    rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
    lock = threading.Lock()

    def job(pair):
        idx, t = pair
        res: dict[str, Any] = {"tcp": None, "tls": None, "ws": None,
                               "real": None, "cc": "", "status": ""}
        if core_path:
            r = xray_probe(t["line"], core_path, frag is not None,
                           timeout=timeout + 4)
            res["real"] = r.get("real")
            res["cc"] = r.get("cc", "")
            res["status"] = (f"core exit {res['cc']} {r.get('exit_ip', '')}"
                             if res["cc"] else r.get("status", "core failed"))
            return res
        try:
            tcp = tcp_ping(t["host"], t["port"], timeout=timeout, attempts=1)
            res["tcp"] = tcp
            if tcp is None:
                res["status"] = "tcp fail"
                return res
            sni = None if (is_ip(t["sni"]) or ":" in t["sni"]) \
                else (t["sni"] or None)
            tc, sock, info = tls_connect(t["host"], t["port"], sni=sni,
                                         frag=frag, timeout=timeout + 2)
            res["tls"] = info["tls_ms"]
            try:
                line, _wsms = ws_upgrade(tc, t["hdr"], t["path"],
                                         timeout=timeout + 2, stop=None)
                if line.startswith("HTTP/1.1 101"):
                    if cc_on:
                        last = ""
                        for k, (sch, gh, gp) in enumerate(rotated_geo(idx)):
                            try:
                                cc, ip, detail, ms = probe_geo_source(
                                    t, tc if k == 0 else None,
                                    sock if k == 0 else None, sni, frag,
                                    sch, gh, gp, timeout + 3, None)
                                res["cc"] = cc
                                if res["real"] is None:
                                    res["real"] = ms
                                res["status"] = \
                                    f"101 exit {cc} · {ip}"
                                break
                            except ProbeError as pe:
                                last = pe.detail
                        else:
                            res["status"] = f"101 (geo: {last[:26]})"
                        if not res["cc"] and is_ip(t["host"]):
                            res["cc"] = cc_of_ip(t["host"])
                    elif real and t.get("uuid"):
                        try:
                            sch, th, tp, tpath = parse_test_target(
                                TEST_TARGET_DEFAULT)
                            tun = VlessTunnel(tc, t["uuid"], th, tp, None)
                            ms, s2 = real_delay_http(tun, th, tpath,
                                                     timeout=timeout + 3,
                                                     stop=None)
                            res["real"] = ms
                            res["status"] = f"101 REAL {s2[:24]}"
                        except ProbeError as pe:
                            res["status"] = f"101 (real: {pe.detail[:24]})"
                    else:
                        res["status"] = "101 ws alive"
                else:
                    res["status"] = line[:40]
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        except ProbeError as pe:
            res["status"] = f"{pe.stage} fail: {pe.detail[:40]}"
        except Exception as e:
            res["status"] = type(e).__name__
        return res

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for t, res in zip(targets, ex.map(job, enumerate(targets))):
            with lock:
                rows.append((t, res))

    rows.sort(key=lambda r: r[1].get("real") or r[1].get("ws")
              or r[1].get("tls") or float("inf"))

    def f(v: Any) -> str:
        return "-" if v is None else f"{v:.0f}"

    print(f"{'real':>6} {'ws':>6} {'tls':>6} {'tcp':>6} {'cc':<4} "
          f"{'status':<34} {'endpoint':<24} name")
    for t, res in rows:
        ep = f"{t['host']}:{t['port']}"
        print(f"{f(res.get('real')):>6} {f(res.get('ws')):>6} "
              f"{f(res.get('tls')):>6} {f(res.get('tcp')):>6} "
              f"{res.get('cc', '') or '-':<4} "
              f"{res.get('status', '')[:34]:<34} {ep:<24} {t['name']}")
    alive = sum(1 for _t, res in rows
                if "101" in res.get("status", "")
                or res.get("status", "").startswith("core exit"))
    ccs = sorted({res["cc"] for _t, res in rows if res.get("cc")})
    print(f"-- {alive}/{len(rows)} alive"
          + (f" · exit countries: {', '.join(ccs)}" if ccs else ""))


def run_cli() -> None:
    ap = argparse.ArgumentParser(
        description="VLESS Forge — bulk-fix, test and scan vless:// configs")
    ap.add_argument("input", nargs="?", help="input file with configs")
    ap.add_argument("output", nargs="?", help="output file (default: stdout)")
    ap.add_argument("--ip", help="force this endpoint IP/domain on every config")
    ap.add_argument("--port", help="force this endpoint port on every config")
    ap.add_argument("--fp", default=DEFAULT_FP)
    ap.add_argument("--template", default=DEFAULT_TEMPLATE)
    ap.add_argument("--start", type=int, default=1)
    ap.add_argument("--no-rename", action="store_true")
    ap.add_argument("--ip-only", action="store_true",
                    help="inject NOTHING — only endpoint override / rename")
    ap.add_argument("--no-fp", action="store_true")
    ap.add_argument("--no-cs", action="store_true")
    ap.add_argument("--no-fm", action="store_true")
    ap.add_argument("--all-security", action="store_true",
                    help="also touch non-TLS configs")
    ap.add_argument("--test", action="store_true",
                    help="after converting, live-test every config")
    ap.add_argument("--core", default="",
                    help="path to xray core — --test runs through the real "
                         "engine (trojan-safe) and reports exit IP + country")
    ap.add_argument("--frag", default="5,94,1@2",
                    help="ClientHello fragment spec, e.g. '5,94,1@2' or 'off'")
    ap.add_argument("--no-real", action="store_true",
                    help="--test: skip the VLESS real-delay stage")
    ap.add_argument("--no-cc", action="store_true",
                    help="--test: skip exit-country detection")
    ap.add_argument("--scan", metavar="CIDR",
                    help="scan a CIDR for IPs that complete TLS with --sni")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--sni", default="")
    ap.add_argument("--no-sni", action="store_true",
                    help="scan with empty SNI (raw IP aliveness)")
    ap.add_argument("--sport", default="443")
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--geo", metavar="IP",
                    help="geo-lookup an IP (empty string = your own IP)")
    a = ap.parse_args()

    if a.geo is not None:
        print(geo_lookup(a.geo.strip()))
        return

    if a.scan:
        ips = sample_cidr(a.scan, a.count)
        if not ips:
            sys.exit(f"bad CIDR: {a.scan}")
        frag = parse_frag(a.frag)
        sni = None if a.no_sni else (a.sni or None)
        print(f"scanning {len(ips)} IPs from {a.scan} port {a.sport} "
              f"(sni={sni or 'none'}, fragment={'on' if frag else 'off'}) ...")
        alive: list[tuple[float, str, str]] = []
        lock = threading.Lock()

        def job(ip: str) -> None:
            try:
                _tc, sock, info = tls_connect(ip, a.sport, sni=sni, frag=frag,
                                              timeout=a.timeout)
                try:
                    sock.close()
                except Exception:
                    pass
                with lock:
                    alive.append((info["tls_ms"], ip, info["ver"]))
            except ProbeError:
                pass

        with ThreadPoolExecutor(max_workers=a.workers) as ex:
            list(ex.map(job, ips))
        alive.sort()
        for ms, ip, ver in alive:
            print(f"{ms:8.1f} ms  {ip:<16} {ver}")
        print(f"-- {len(alive)}/{len(ips)} alive")
        return

    if not a.input:
        ap.error("input file required (or use --scan / --geo)")
    if a.ip and not classify_endpoint(a.ip):
        sys.exit(f"invalid --ip: {a.ip}")
    if a.port and not valid_port(a.port):
        sys.exit(f"invalid --port: {a.port}")

    want_fp = not (a.ip_only or a.no_fp)
    want_cs = not (a.ip_only or a.no_cs)
    want_fm = not (a.ip_only or a.no_fm)

    with open(a.input, "r", encoding="utf-8") as f:
        text = f.read()
    lines, _names, c = convert_block(
        text, a.fp, DEFAULT_CS, compact_json(DEFAULT_FM),
        tls_only=not a.all_security, rename=not a.no_rename,
        template=a.template, start_id=a.start,
        ov_ip=a.ip or "", ov_port=a.port or "",
        want_fp=want_fp, want_cs=want_cs, want_fm=want_fm)
    if a.test:
        core = a.core or find_xray_core()
        cli_test(lines, a.timeout, frag_s=a.frag, real=not a.no_real,
                 cc_on=not a.no_cc, core_path=core)
    out = "\n".join(lines) + "\n"
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"wrote {a.output} | updated {c['fixed']} "
              f"unchanged {c['unchanged']} skipped {c['skipped']}")
    else:
        sys.stdout.write(out)


def main() -> None:
    if len(sys.argv) > 1:
        run_cli()
        return
    App().mainloop()


if __name__ == "__main__":
    main()