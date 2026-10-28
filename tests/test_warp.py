"""WARP/WireGuard tests: pure-python X25519 (RFC 7748 vectors) and configs."""

from __future__ import annotations

import base64

import pytest

from xray_forge.core.warp import (
    x25519, generate_keypair, WarpAccount, account_to_outbound,
    endpoint_candidates, _BASE_POINT,
)
from xray_forge.core.cores import get_core


def _h(s: str) -> bytes:
    return bytes.fromhex(s)


# RFC 7748 §5.2 — X25519 test vectors
def test_rfc7748_vector_1():
    out = x25519(
        _h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        _h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
    assert out == _h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")


def test_rfc7748_vector_2():
    out = x25519(
        _h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
        _h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))
    assert out == _h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")


# RFC 7748 §6.1 — Diffie-Hellman
def test_rfc7748_dh_shared_secret():
    a_priv = _h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b_priv = _h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    a_pub = x25519(a_priv, _BASE_POINT)
    b_pub = x25519(b_priv, _BASE_POINT)
    assert a_pub == _h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert b_pub == _h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert x25519(a_priv, b_pub) == x25519(b_priv, a_pub) == \
        _h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


def test_generate_keypair():
    priv_b64, pub_b64 = generate_keypair()
    priv = base64.b64decode(priv_b64)
    pub = x25519(priv, _BASE_POINT)
    assert base64.b64encode(pub).decode() == pub_b64


def test_account_roundtrip(tmp_path):
    acct = WarpAccount(device_id="id", token="tk", private_key="P=",
                       peer_public_key="S=", client_id="a1b2c3",
                       ipv4="172.16.0.2/32", ipv6="2606::1/128")
    d = acct.to_dict()
    assert WarpAccount.from_dict(d) == acct


def test_account_to_outbound():
    acct = WarpAccount(device_id="d", private_key="PRIV=", peer_public_key="PUB=",
                       client_id="0a0b0c", ipv4="172.16.0.2/32",
                       endpoint="engage.cloudflareclient.com:2408")
    out = account_to_outbound(acct)
    assert out.scheme == "wireguard"
    assert out.host == "engage.cloudflareclient.com"
    assert out.port == "2408"
    assert out.extra["private_key"] == "PRIV="
    assert out.extra["client_id"] == "0a0b0c"
    # renders for all three cores
    for name in ("xray", "singbox", "mihomo"):
        core = get_core(name)
        assert core.supports(out), f"{name} should support wireguard"
    x = get_core("xray").render_outbound(out)
    assert x["settings"]["reserved"] == [0x0A, 0x0B, 0x0C]


def test_endpoint_candidates(monkeypatch):
    from xray_forge.core import warp
    monkeypatch.setattr("xray_forge.core.scanner.sample_cidr",
                        lambda cidr, count: [f"10.0.0.{i}" for i in range(count)])
    cands = warp.endpoint_candidates(count=20)
    assert cands, "expected candidates"
    for c in cands:
        host, _, port = c.partition(":")
        assert host.startswith("10.0.0.")
        assert 1 <= int(port) <= 65535


def test_probe_endpoint_handles_closed_port():
    """UDP to a loopback port: closed→None (Linux) or timeout→ms (Windows);
    either way it must not raise."""
    from xray_forge.core.warp import probe_endpoint
    result = probe_endpoint("127.0.0.1", 1, timeout=0.2)
    assert result is None or result > 0
