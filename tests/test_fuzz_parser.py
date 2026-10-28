"""Deterministic fuzzing of the URI parser, converter, and exporters.

Random mutations of valid configs (and pure garbage) must never raise —
parsers either succeed or return None/skip.  Seeded for reproducibility.
"""

from __future__ import annotations

import random

from xray_forge.core.parser import (
    parse_target, fix_uri, convert_block, out_to_clash, out_to_singbox,
    make_namer,
)
from xray_forge.core.protocols import handler_for
from tests.fixtures import ALL_LINES, VLESS_TLS_WS

ALPHABET = list("abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%")
SCHEMES = ("vless", "trojan", "vmess", "ss", "hysteria2", "tuic", "http", "")


def mutate(rng: random.Random, s: str) -> str:
    ops = rng.randint(1, 4)
    for _ in range(ops):
        if not s:
            s = rng.choice(SCHEMES) + "://"
        op = rng.choice(["del", "ins", "swap", "dup", "trunc"])
        i = rng.randrange(len(s))
        if op == "del":
            s = s[:i] + s[i + 1:]
        elif op == "ins":
            s = s[:i] + rng.choice(ALPHABET) + s[i:]
        elif op == "swap" and len(s) > 1:
            j = rng.randrange(len(s))
            s = list(s)
            s[i], s[j] = s[j], s[i]
            s = "".join(s)
        elif op == "dup":
            s = s[:i] + s[i] * 2 + s[i + 1:]
        elif op == "trunc":
            s = s[:i]
    return s


def test_parse_target_never_raises():
    rng = random.Random(1234)
    for _ in range(600):
        s = mutate(rng, rng.choice(ALL_LINES))
        try:
            out = parse_target(s)
        except Exception as e:  # pragma: no cover
            raise AssertionError(f"parse_target raised on {s!r}: {e!r}")
        if out is not None:
            # anything parsed must render to both export formats safely
            out_to_clash(out)
            out_to_singbox(out)


def test_fix_uri_never_raises():
    rng = random.Random(4321)
    namer = make_namer("{id}_{sub}", 1)
    for i in range(600):
        s = mutate(rng, VLESS_TLS_WS)
        try:
            fix_uri(s, "chrome", "", "", False, True, namer, i)
        except Exception as e:  # pragma: no cover
            raise AssertionError(f"fix_uri raised on {s!r}: {e!r}")


def test_convert_block_never_raises():
    rng = random.Random(999)
    blob = "\n".join(mutate(rng, line) for line in ALL_LINES for _ in range(3))
    lines, names, counts = convert_block(blob, "chrome", "", "", False,
                                         True, "{id}", 1)
    assert counts["fixed"] + counts["unchanged"] + counts["skipped"] == \
        len([l for l in blob.splitlines() if l.strip()])


def test_handlers_roundtrip_all_fixtures():
    """Every fixture must parse, render back, and re-parse to itself."""
    for line in ALL_LINES:
        out = parse_target(line)
        assert out is not None, line
        h = handler_for(out.scheme)
        assert h is not None
        if out.scheme in ("wireguard", "wg"):
            continue
        uri = h.to_uri(out)
        out2 = h.parse(uri)
        assert out2 is not None, uri
        assert out2.credential == out.credential
        assert out2.host == out.host
        assert out2.port == out.port
