"""
SOCKS5 client helpers shared by core adapters (xray, sing-box, mihomo).

``fetch_via_socks`` performs a plain HTTP GET through a SOCKS5 proxy and is
used by the staged health-check pipeline and by ``run_socks_probe``.
"""

from __future__ import annotations

import socket

from xray_forge.core.config import IPV4_RE
from xray_forge.core.probe import ProbeError, _read_http, sock_recv


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
        req = b"\x05\x01\x00\x01" + socket.inet_aton(dst) + int(dport).to_bytes(2, "big")
    else:
        hb = dst.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + int(dport).to_bytes(2, "big")
    s.sendall(req)
    r = s.recv(10)
    if len(r) < 2 or r[1] != 0:
        s.close()
        raise ProbeError("socks", f"connect refused (code {r[1] if len(r) > 1 else '?'})")
    return s


def fetch_via_socks(socks_ip: str, socks_port: int, host: str, port: int,
                    path: str, timeout: float = 8.0,
                    method: str = "GET", body: bytes | None = None) -> tuple[float, str, bytes]:
    """HTTP request through a SOCKS5 proxy. Returns (ms, status_line, body)."""
    s = socks5_connect(socks_ip, socks_port, host, port, timeout=timeout)
    try:
        head = (f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: xray-forge\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n")
        if body is not None:
            head += f"Content-Length: {len(body)}\r\n"
        head += "\r\n"
        t0 = __import__("time").perf_counter()
        s.sendall(head.encode() + (body or b""))
        raw = _read_http(sock_recv(s, None), __import__("time").perf_counter() + timeout, None)
        ms = (__import__("time").perf_counter() - t0) * 1000
        return ms, raw["status"], raw["body"]
    finally:
        try:
            s.close()
        except OSError:
            pass
