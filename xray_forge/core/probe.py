"""
DPI-resistant network probes, fragmented TLS, WebSocket client, VLESS tunnel, and DoH.

Heavy-censorship evasion techniques (patterniha MMDF / gfw-knocker / Xray-core fragment):
  - fragmented TLS Client Hello (tlshello / length / interval / maxSplit)
  - fake / decoy Client Hello with benign SNI (MMDF "instant certificate" style)
  - TLS record-layer fragmentation (split SNI extension across records)
  - domain fronting (connect to front, request real host)
  - TTL decoy packets, SNI case mixing, TLS padding, noise packets
  - TCP Fast Open, User-Agent rotation
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import random
import re
import socket
import ssl
import struct
import threading
import time
import urllib.request
import uuid as uuid_mod
from typing import Any
from urllib.parse import urlsplit, urljoin, quote

from xray_forge.core.config import IPV4_RE, DOH_SERVERS, IRAN_UDP_RESOLVERS, DOH_ENDPOINTS, GEO_VIA_TUNNEL, FAKE_SNI_PRESETS

HAS_CURL_CFFI = False
try:
    if importlib.util.find_spec("curl_cffi") is not None:
        HAS_CURL_CFFI = True
except Exception:
    HAS_CURL_CFFI = False


class ProbeError(Exception):
    def __init__(self, stage: str, detail: str):
        super().__init__(f"{stage}: {detail}")
        self.stage = stage
        self.detail = detail


def _check(stop: threading.Event | None, deadline: float | None) -> None:
    if stop is not None and stop.is_set():
        raise ProbeError("io", "stopped")
    if deadline is not None and time.perf_counter() >= deadline:
        raise ProbeError("io", "timeout")


def human_ssl_error(e: Exception) -> str:
    s = str(e)
    if isinstance(e, ssl.SSLCertVerificationError):
        why = (getattr(e, "verify_message", "") or "untrusted").strip()
        return f"certificate rejected: {why}"[:60]
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


# ---------------------------------------------------------------------------
# Noise / padding helpers (Xray freedom "noises" style)
# ---------------------------------------------------------------------------

def _noise_packet() -> bytes:
    """Random base64-ish noise blob (Xray freedom noise style)."""
    return base64.b64encode(os.urandom(random.randint(16, 64)))


def _random_ua() -> str:
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15",
    ]
    return random.choice(uas)


def _mix_sni_case(sni: str) -> str:
    """Randomize SNI casing (e.g. dl.google.com -> Dl.GooGle.CoM)."""
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in sni)


# ---------------------------------------------------------------------------
# TLS client with optional fake/record fragmentation
# ---------------------------------------------------------------------------

def _load_trust_store(ctx: ssl.SSLContext, cafile: str | None = None) -> None:
    """Load CA roots for a verifying context (explicit file, else OS + certifi)."""
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
        return
    try:
        ctx.load_default_certs()
    except Exception:
        pass
    try:  # curl_cffi depends on certifi, so it is normally present
        import certifi
        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:
        pass


class TLSClient:
    def __init__(self, send, recv, sni: str | None = None,
                 ciphers: str | None = None, frag: tuple | None = None,
                 stop: threading.Event | None = None, hs_timeout: float = 5.0,
                 fake_sni: str | None = None, record_frag: bool = False,
                 pad_hello: bool = False, verify: bool = False,
                 verify_name: str | None = None, cafile: str | None = None):
        """``verify=False`` (default) is for *probing* censored paths, where the
        point is to see whether a handshake completes.  Anything that trusts
        the response (DoH answers, subscriptions) must pass ``verify=True``:
        the certificate chain and ``verify_name`` are then enforced."""
        self._send = send
        self._recv = recv
        self._stop = stop
        self._frag = frag
        self._dl = time.perf_counter() + max(0.5, hs_timeout)
        self._fake_sni = fake_sni
        self._record_frag = record_frag
        self._pad_hello = pad_hello
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if verify:
            if not verify_name:
                raise ProbeError("tls", "certificate verification needs a host name")
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            _load_trust_store(ctx, cafile)
            fake_sni = None          # the hello must carry the verified name
            sni = verify_name
        else:
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
        hello_sni = fake_sni or sni
        if hello_sni:
            self.obj = ctx.wrap_bio(self.inb, self.outb, server_hostname=hello_sni)
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
            if self._record_frag and len(data) > 1:
                # TLS record-layer fragmentation: split into small records
                mid = max(1, len(data) // 2)
                send_fragmented(self._send, data[:mid], ("list", [mid], 0))
                time.sleep(random.uniform(0.001, 0.005))
                send_fragmented(self._send, data[mid:], frag or None)
            elif frag:
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
                ciphers: str | None = None,
                fake_sni: str | None = None,
                record_frag: bool = False,
                pad_hello: bool = False,
                tfo: bool = False,
                verify: bool = False,
                cafile: str | None = None):
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
        if tfo:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, 23, 1)  # TCP_FAST_OPEN (Linux)
            except (OSError, AttributeError):
                pass
        tc = TLSClient(sock_send(sock), sock_recv(sock, stop), sni=sni,
                       ciphers=ciphers, frag=frag, stop=stop,
                       hs_timeout=max(0.5, timeout),
                       fake_sni=fake_sni, record_frag=record_frag,
                       pad_hello=pad_hello, verify=verify,
                       verify_name=(sni or host) if verify else None,
                       cafile=cafile)
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
               stop: threading.Event | None,
               front_domain: str | None = None):
    """WebSocket upgrade, optionally via domain fronting (front SNI, real Host)."""
    deadline = time.perf_counter() + timeout
    key = base64.b64encode(os.urandom(16)).decode()
    real_host = host_hdr or "localhost"
    front_host = front_domain or real_host
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "User-Agent: %s\r\n\r\n"
           ) % (path or "/", front_host, key, _random_ua())
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


class VlessTunnel:
    def __init__(self, tc: TLSClient, uuid_s: str, host: str, port,
                 stop: threading.Event | None,
                 front_domain: str | None = None):
        u = (uuid_s or "").strip()
        try:
            uid = uuid_mod.UUID(u).bytes
        except Exception:
            raise ProbeError("vless", "not a vless UUID (trojan/password/empty)")
        hdr = b"\x00" + bytes([16]) + uid + b"\x00" + b"\x01" + int(port).to_bytes(2, "big")
        if IPV4_RE.match(host):
            hdr += b"\x01" + socket.inet_aton(host)
        else:
            hb = host.encode()
            hdr += b"\x02" + bytes([len(hb)]) + hb
        # For domain fronting, connect to front but request real host inside tunnel
        ws_send(tc, hdr)
        self.tc = tc
        self.stop = stop
        self._hdr_done = False
        self.front_domain = front_domain

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


def _read_http(recv, deadline: float | None, stop: threading.Event | None,
               read_to_eof: bool = False, max_body: int | None = None):
    """Read one HTTP/1.x response.  Returns {status, body, headers}.

    ``read_to_eof`` also reads close-delimited bodies (no Content-Length, not
    chunked) until the peer closes; ``max_body`` raises ProbeError("size")
    instead of buffering an unbounded response.
    """
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
        if max_body is not None and need > max_body:
            raise ProbeError("size", f"response too large ({need} bytes)")
        while len(body) < need:
            _check(stop, deadline)
            d = recv(deadline)
            if not d:
                break
            body += d
        body = body[:need]
    elif "chunked" in hdrs.get("transfer-encoding", "").lower():
        body = _dechunk(body, recv, deadline, stop)
    elif read_to_eof:
        while True:
            _check(stop, deadline)
            try:
                d = recv(deadline)
            except ProbeError as pe:
                if pe.stage == "io" and "closed" in pe.detail:
                    break              # peer closed: end of body
                raise
            if not d:
                break
            body += d
            if max_body is not None and len(body) > max_body:
                raise ProbeError("size", f"response larger than {max_body} bytes")
    if max_body is not None and len(body) > max_body:
        raise ProbeError("size", f"response larger than {max_body} bytes")
    return {"status": status, "body": body, "headers": hdrs}


def tunnel_http_get(tun: "VlessTunnel", host: str, path: str,
                    timeout: float, stop: threading.Event | None,
                    front_domain: str | None = None):
    deadline = time.perf_counter() + timeout
    front = front_domain or host
    req = (f"GET {path} HTTP/1.1\r\nHost: {front}\r\n"
           f"User-Agent: {_random_ua()}\r\nAccept: */*\r\n"
           f"Connection: close\r\n\r\n").encode()
    t0 = time.perf_counter()
    tun.send(req)
    raw = _read_http(tun.recv, deadline, stop)
    ms = (time.perf_counter() - t0) * 1000
    return ms, raw["status"], raw["body"]


def tunnel_https_get(tun: "VlessTunnel", host: str, path: str,
                     timeout: float, stop: threading.Event | None,
                     front_domain: str | None = None):
    deadline = time.perf_counter() + timeout
    front = front_domain or host
    inner = TLSClient(tun.send, lambda dl: tun.recv(dl), sni=front, stop=stop,
                      hs_timeout=max(1.0, deadline - time.perf_counter()),
                      fake_sni=front)
    req = (f"GET {path} HTTP/1.1\r\nHost: {front}\r\n"
           f"User-Agent: {_random_ua()}\r\nAccept: */*\r\n"
           f"Connection: close\r\n\r\n").encode()
    t0 = time.perf_counter()
    inner.write(req)
    raw = _read_http(lambda dl: inner.read(65536, deadline=dl), deadline, stop)
    ms = (time.perf_counter() - t0) * 1000
    return ms, raw["status"], raw["body"]


def real_delay_http(tun: "VlessTunnel", host: str, path: str,
                    timeout: float, stop: threading.Event | None,
                    front_domain: str | None = None):
    ms, status, _ = tunnel_http_get(tun, host, path, timeout, stop, front_domain)
    return ms, (status or "empty reply")


def real_delay_https(tun: "VlessTunnel", host: str, port, path: str,
                     timeout: float, stop: threading.Event | None,
                     front_domain: str | None = None):
    ms, status, _ = tunnel_https_get(tun, host, path, timeout, stop, front_domain)
    return ms, (status or "empty reply")


def parse_test_target(s: str):
    from xray_forge.core.config import TEST_TARGET_DEFAULT
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


def _geo_detail(d: dict) -> str:
    conn = d.get("connection") if isinstance(d.get("connection"), dict) else {}
    parts = [
        str(d.get("city") or ""),
        str(d.get("isp") or d.get("org") or conn.get("isp") or conn.get("org") or ""),
        str(d.get("query") or d.get("ip") or ""),
    ]
    return " · ".join(p for p in parts if p)[:44]


def _cc_from_geo(d: Any, status: str) -> tuple[str, str, str]:
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
                     stop: threading.Event | None,
                     front_domain: str | None = None):
    owns = False
    if tc is None:
        tc, sock, _ = tls_connect(t["host"], t["port"], sni=sni, frag=frag,
                                  timeout=timeout, stop=stop)
        owns = True
    try:
        gport = 80 if sch == "http" else 443
        tun = VlessTunnel(tc, t.get("uuid", ""), ghost, gport, stop,
                          front_domain=front_domain)
        if sch == "http":
            ms, status, body = tunnel_http_get(tun, ghost, gpath, timeout, stop, front_domain)
        else:
            ms, status, body = tunnel_https_get(tun, ghost, gpath, timeout, stop, front_domain)
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


def doh_resolve(host: str, timeout: float = 4.0) -> list[str]:
    for srv, path0 in DOH_SERVERS:
        try:
            # verify=True: the resolvers' certificates carry IP SANs, so a
            # forged answer from an on-path box fails the handshake instead.
            tc, sock, _ = tls_connect(srv, "443", sni=None,
                                      frag=parse_frag("rand:1-16@1"),
                                      timeout=timeout, verify=True)
            try:
                req = (f"GET {path0}?name={quote(host)}&type=A HTTP/1.1\r\n"
                       f"Host: {srv}\r\naccept: application/dns-json\r\n"
                       f"User-Agent: {_random_ua()}\r\nConnection: close\r\n\r\n")
                tc.write(req.encode())
                raw = _read_http(lambda dl: tc.read(65536, deadline=dl),
                                 time.perf_counter() + timeout, None)
                d = json.loads(raw["body"].decode("utf-8", "replace"))
                ans = [a["data"] for a in (d.get("Answer") or []) if a.get("type") == 1]
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


MAX_FETCH_BYTES = 4 * 1024 * 1024
_REDIRECT_CODES = (301, 302, 303, 307, 308)


def _status_code(status_line: str) -> int:
    parts = (status_line or "").split(" ", 2)
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


def _http_get_once(sch: str, ip: str, port: int, host: str, path: str,
                   timeout: float, max_bytes: int, verify: bool,
                   cafile: str | None) -> dict:
    """One GET to ``ip`` (Host/SNI = ``host``). Returns the _read_http dict."""
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"User-Agent: {_random_ua()}\r\nAccept: */*\r\n"
           f"Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode()
    deadline = time.perf_counter() + timeout
    if sch == "https":
        sni = None if (IPV4_RE.match(host) or not host) else host
        tc, sock, _ = tls_connect(ip, str(port), sni=sni,
                                  frag=parse_frag("rand:1-16@1"),
                                  timeout=timeout, verify=verify,
                                  cafile=cafile)
        try:
            tc.write(req)
            return _read_http(lambda dl: tc.read(65536, deadline=dl),
                              deadline, None, read_to_eof=True,
                              max_body=max_bytes)
        finally:
            sock.close()
    s = socket.create_connection((ip, port), timeout=timeout)
    try:
        s.sendall(req)
        return _read_http(sock_recv(s, None), deadline, None,
                          read_to_eof=True, max_body=max_bytes)
    finally:
        s.close()


def direct_get_text(url_str: str, timeout: float = 6.0,
                    max_bytes: int = MAX_FETCH_BYTES, max_redirects: int = 3,
                    verify: bool = True, cafile: str | None = None) -> str:
    """GET ``url_str`` over a DPI-resistant (fragmented) connection.

    * http/https only -- anything else (file://, ftp://) is refused
    * HTTPS certificates are verified by default (``verify=False`` is only
      for probing, never for content you will trust)
    * resolves through DoH, follows up to ``max_redirects`` redirects
    * refuses responses larger than ``max_bytes``
    """
    hops = 0
    while True:
        p = urlsplit(url_str)
        sch = p.scheme.lower()
        host = p.hostname or ""
        if sch not in ("http", "https") or not host:
            raise ProbeError("url", "only http/https URLs are supported")
        port = p.port or (443 if sch == "https" else 80)
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        ips = doh_resolve(host, timeout) or [host]
        raw = None
        last = ""
        for ip in ips[:2]:
            try:
                raw = _http_get_once(sch, ip, port, host, path, timeout,
                                     max_bytes, verify, cafile)
                break
            except ProbeError as e:
                last = e.detail
                if e.stage == "size":
                    raise
            except OSError as e:
                last = oserr_text(e)
        if raw is None:
            raise ProbeError("fetch", f"direct fetch failed: {last[:44]}")
        code = _status_code(raw["status"])
        loc = raw.get("headers", {}).get("location", "")
        if code in _REDIRECT_CODES and loc:
            hops += 1
            if hops > max_redirects:
                raise ProbeError("fetch", "too many redirects")
            url_str = urljoin(url_str, loc)
            continue
        if 200 <= code < 300:
            return raw["body"].decode("utf-8", "replace")
        raise ProbeError("fetch", f"HTTP {code or raw['status'][:30]}")


def direct_get_json(url_str: str, timeout: float = 6.0):
    """JSON variant of :func:`direct_get_text` (same safety rules)."""
    return json.loads(direct_get_text(url_str, timeout=timeout))


def fetch_json(url: str, timeout: float = 8.0):
    try:
        return direct_get_json(url, timeout=timeout)
    except Exception:
        req = urllib.request.Request(
            url, headers={"User-Agent": "vless-forge/2.0", "accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))


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
