"""
WireGuard / WARP support.

* :func:`x25519` — pure-python RFC 7748 X25519 (used to make device keys,
  no third-party dependency; NOT constant-time, which is fine for freshly
  generated throwaway keys)
* :func:`register_account` — create a WARP device via the Cloudflare client API
* :func:`scan_endpoints` — heuristic UDP endpoint scan for the WARP ranges
* :func:`account_to_outbound` / config rendering via the protocol registry

The WARP API is undocumented and changes; :func:`register_account` is
best-effort and reports clear errors when the API rejects a request.
"""

from __future__ import annotations

import base64
import json
import os
import random
import socket
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any

from xray_forge.core.config import (
    WARP_API_BASE, WARP_CLIENT_VERSION, WARP_DEFAULT_ENDPOINT, WARP_PORTS,
)
from xray_forge.core.models import Outbound

# ===========================================================================
# RFC 7748 X25519 (montgomery ladder)
# ===========================================================================

_P = 2 ** 255 - 19
_A24 = 121665
_BASE_POINT = (9).to_bytes(32, "little")


def _clamp(k: bytes) -> int:
    b = bytearray(k[:32])
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def x25519(scalar: bytes, u_coord: bytes) -> bytes:
    """RFC 7748 scalar multiplication (X25519)."""
    k = _clamp(scalar)
    u = int.from_bytes(u_coord[:32], "little") & ((1 << 255) - 1)
    x1 = u % _P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        if swap ^ k_t:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) % _P
        x3 = x3 * x3 % _P
        z3 = (da - cb) % _P
        z3 = z3 * z3 % _P
        z3 = z3 * x1 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_b64, public_key_b64) for WireGuard/WARP."""
    priv = os.urandom(32)
    pub = x25519(priv, _BASE_POINT)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


# ===========================================================================
# WARP device registration
# ===========================================================================

@dataclass
class WarpAccount:
    device_id: str = ""
    token: str = ""
    private_key: str = ""       # base64 wireguard secret key
    public_key: str = ""        # base64 wireguard public key (ours)
    peer_public_key: str = ""   # base64 server public key
    client_id: str = ""         # hex — maps to the `reserved` field
    ipv4: str = "172.16.0.2/32"
    ipv6: str = ""
    endpoint: str = WARP_DEFAULT_ENDPOINT
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "WarpAccount":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


def _warp_request(url: str, payload: dict | None = None, token: str = "",
                  method: str = "POST", timeout: float = 15.0) -> dict:
    headers = {
        "User-Agent": "okhttp/3.12.1",
        "CF-Client-Version": WARP_CLIENT_VERSION,
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        raise RuntimeError(f"warp api http {e.code}: {body}") from e
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"warp api unreachable: {e}") from e


def register_account(referral: str = "", timeout: float = 15.0) -> WarpAccount:
    """Register a new WARP device. Requires internet access."""
    priv_b64, pub_b64 = generate_keypair()
    install_id = os.urandom(16).hex()
    payload: dict[str, Any] = {
        "key": pub_b64,
        "install_id": install_id,
        "fcm_token": f"{install_id}:APA91b{os.urandom(70).hex()}",
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "model": "PC",
        "locale": "en_US",
        "type": "Android",
        "config": {
            "peers": [],
            "addresses": ["172.16.0.2/32", "2606:4700:110:888a::1/128"],
            "client_id": "",
        },
    }
    if referral:
        payload["referrer"] = referral
    d = _warp_request(WARP_API_BASE, payload, timeout=timeout)
    cfg = d.get("config") or {}
    peers = cfg.get("peers") or [{}]
    return WarpAccount(
        device_id=str(d.get("id") or ""),
        token=str(d.get("token") or ""),
        private_key=priv_b64,
        public_key=pub_b64,
        peer_public_key=str(peers[0].get("public_key") or ""),
        client_id=str(cfg.get("client_id") or ""),
        ipv4=(cfg.get("addresses") or ["172.16.0.2/32"])[0],
        ipv6=(cfg.get("addresses") or ["", ""])[1] if len(cfg.get("addresses") or []) > 1 else "",
        endpoint=WARP_DEFAULT_ENDPOINT,
        extra={"account_type": str(d.get("account_type") or "warp")},
    )


# ===========================================================================
# Account persistence (data_dir/warp_account.json)
# ===========================================================================

def _account_path() -> str:
    from xray_forge.core.settings import data_dir
    return os.path.join(data_dir(), "warp_account.json")


def save_account(acct: WarpAccount) -> str:
    path = _account_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(acct.to_dict(), f, indent=2)
    return path


def load_account() -> WarpAccount | None:
    path = _account_path()
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return WarpAccount.from_dict(json.load(f))
    except (OSError, json.JSONDecodeError, TypeError):
        return None


# ===========================================================================
# Outbound / config generation
# ===========================================================================

def account_to_outbound(acct: WarpAccount, endpoint: str = "",
                        name: str = "WARP") -> Outbound:
    ep = endpoint or acct.endpoint
    host, _, port = ep.partition(":")
    return Outbound(
        scheme="wireguard", name=name, host=host, port=port or "2408",
        credential="", transport="udp", security="",
        extra={
            "private_key": acct.private_key,
            "peer_public_key": acct.peer_public_key,
            "ipv4": acct.ipv4,
            "ipv6": acct.ipv6,
            "client_id": acct.client_id,
            "mtu": 1280,
        },
    )


def endpoint_candidates(count: int = 200, ranges: list[str] | None = None) -> list[str]:
    """Sample host:port candidates from the WARP ranges x known ports."""
    from xray_forge.core.scanner import sample_cidr
    from xray_forge.core.config import WARP_RANGES
    ranges = ranges or WARP_RANGES
    hosts: list[str] = []
    per = max(1, count // max(1, len(ranges)))
    for r in ranges:
        hosts.extend(sample_cidr(r, per))
    random.shuffle(hosts)
    out: list[str] = []
    for h in hosts[: max(1, count // len(WARP_PORTS) + 1)]:
        for p in WARP_PORTS:
            out.append(f"{h}:{p}")
    return out[: count * len(WARP_PORTS)]


def probe_endpoint(host: str, port: int, timeout: float = 2.0) -> float | None:
    """Heuristic UDP liveness check.

    A WireGuard server never replies to garbage, but a *closed* port usually
    answers with ICMP port-unreachable (surfacing as ECONNREFUSED).
    Timeout = port likely open (or filtered).  Returns RTT ms or None.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.sendto(os.urandom(32), (host, int(port)))
        try:
            s.recvfrom(64)
            # a reply to garbage is unexpected; treat as alive anyway
            return (time.perf_counter() - t0) * 1000
        except ConnectionRefusedError:
            return None
        except socket.timeout:
            return (time.perf_counter() - t0) * 1000
        finally:
            s.close()
    except OSError:
        return None


def scan_endpoints(count: int = 60, workers: int = 20,
                   progress=None) -> list[tuple[str, float]]:
    """Scan candidate endpoints; returns [(host:port, ms)] best-first."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    cands = endpoint_candidates(count)
    results: list[tuple[str, float]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {}
        for cand in cands[: count * 3]:
            host, _, port = cand.partition(":")
            futs[ex.submit(probe_endpoint, host, int(port or 2408))] = cand
        for i, fut in enumerate(as_completed(futs)):
            if progress and (i % 10 == 0):
                progress(i, len(futs))
            ms = fut.result()
            if ms is not None:
                results.append((futs[fut], ms))
    results.sort(key=lambda kv: kv[1])
    return results
