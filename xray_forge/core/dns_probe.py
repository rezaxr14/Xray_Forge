"""Measure how fast each DNS server answers (plain UDP, IPv4)."""

from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

from xray_forge.core import scanner

TEST_NAME = "example.com"
MAX_SERVERS = 24


def probe(server: str, name: str = TEST_NAME, timeout: float = 2.0) -> dict:
    res = {"server": server, "ok": False, "ms": None, "answers": [], "error": ""}
    try:
        ip = ipaddress.ip_address(server)
    except ValueError:
        res["error"] = "not an IP address"
        return res
    if ip.version != 4:
        res["error"] = "IPv6 servers are not tested"
        return res
    t0 = time.perf_counter()
    try:
        answers = scanner.udp_dns_a(name, server, timeout)
    except OSError as e:
        res["error"] = "timed out" if "timed out" in str(e) else (str(e) or type(e).__name__)[:80]
        return res
    res["ms"] = round((time.perf_counter() - t0) * 1000)
    res["answers"], res["ok"] = answers, bool(answers)
    if not answers:
        res["error"] = "no answer for the test name"
    return res


def probe_many(servers: list[str], name: str = TEST_NAME, timeout: float = 2.0) -> list[dict]:
    servers = list(dict.fromkeys(servers))[:MAX_SERVERS]
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(servers)))) as ex:
        return list(ex.map(lambda s: probe(s, name, timeout), servers))
