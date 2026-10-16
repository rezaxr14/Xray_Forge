"""
IP scanning, anti-hijack DNS resolution, CIDR sampling, and GeoIP lookup.
"""

from __future__ import annotations

import ipaddress
import os
import random
import socket
import threading
from typing import Any
from urllib.parse import quote, urlsplit

from xray_forge.core.config import DOH_ENDPOINTS, IRAN_UDP_RESOLVERS
from xray_forge.core.probe import fetch_json


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
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".") if l) + b"\x00"
    pkt = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q + b"\x00\x01\x00\x01"
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
        ans = [a["data"] for a in (d.get("Answer") or []) if a.get("type") == 1]
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

# (cc, isp) cache — keyed by ip
_META_CACHE: dict[str, tuple[str, str]] = {}
_META_LOCK = threading.Lock()


def ip_meta(ip: str, timeout: float = 5.0) -> tuple[str, str]:
    """Return (country_code, isp) for an IP, cached. ("","") on failure."""
    if not ip:
        return "", ""
    with _META_LOCK:
        if ip in _META_CACHE:
            return _META_CACHE[ip]
    cc, isp = "", ""
    try:
        d = fetch_json(
            f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp",
            timeout=timeout)
        if isinstance(d, dict):
            v = d.get("countryCode")
            if isinstance(v, str) and len(v) == 2 and v.isalpha():
                cc = v.upper()
            isp = str(d.get("isp") or "")[:40]
    except Exception:
        pass
    with _META_LOCK:
        _META_CACHE[ip] = (cc, isp)
    return cc, isp


def tcp_jitter(host: str, port: str, attempts: int = 3,
               timeout: float = 3.0) -> tuple[float | None, float]:
    """Best connect latency and jitter (max-min over successful samples)."""
    samples: list[float] = []
    for _ in range(max(2, attempts)):
        if len(samples) >= attempts:
            break
        t0 = __import__("time").perf_counter()
        try:
            s = socket.create_connection((host, int(port)), timeout=timeout)
            s.close()
        except OSError:
            continue
        samples.append((__import__("time").perf_counter() - t0) * 1000)
    if not samples:
        return None, 0.0
    best = min(samples)
    jitter = (max(samples) - min(samples)) if len(samples) > 1 else 0.0
    return best, jitter




def cc_of_ip(ip: str, timeout: float = 4.0) -> str:
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
    place = ", ".join(as_str(d[k]) for k in ("city", "region", "regionName", "country", "country_name") if d.get(k))
    org = as_str(d.get("org")) or as_str(d.get("as"))
    if not org:
        c = d.get("connection")
        if isinstance(c, dict):
            org = as_str(c.get("isp")) or as_str(c.get("org")) or as_str(c.get("asn"))
    tz = as_str(d.get("timezone"))
    s = ip + (f"  —  {place}" if place else "")
    extra = [x for x in (org, tz) if x]
    if extra:
        s += "\n" + "   ·   ".join(extra)
    return s


def geo_lookup(ip: str = "") -> str:
    urls = [
        f"https://ipwho.is/{ip}".rstrip("/"),
        f"http://ip-api.com/json/{ip}?fields=query,country,city,regionName,isp,as,timezone",
        f"https://ipinfo.io/{ip}/json".rstrip("/"),
        "https://api.myip.com"
    ]
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
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return []
    if net.num_addresses <= 2:
        return [str(net.network_address)]
    total = net.num_addresses - 2
    picks = random.sample(range(1, total + 1), min(count, total))
    base = int(net.network_address)
    return [str(ipaddress.ip_address(base + i)) for i in picks]
