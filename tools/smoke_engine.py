#!/usr/bin/env python3
"""Smoke-test an engine executable (frozen or `python -m xray_forge`).

    python tools/smoke_engine.py -- dist/xray-forge-engine/xray-forge-engine serve
    python tools/smoke_engine.py -- python -m xray_forge serve

Starts the engine, asks for ``engine.info`` and parses a share link, then
closes stdin and expects a clean exit.  Exit code 0 means the binary can
serve the UI.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading

LINK = ("vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@188.114.97.6:443"
        "?security=tls&sni=x.example.com&fp=chrome&type=ws&host=x.example.com&path=%2F#smoke")


def smoke(cmd: list[str], timeout: float = 60.0) -> list[str]:
    """Returns a list of problems (empty = healthy)."""
    problems: list[str] = []
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8")
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    try:
        reqs = [{"jsonrpc": "2.0", "id": 1, "method": "engine.info"},
                {"jsonrpc": "2.0", "id": 2, "method": "config.parse", "params": {"line": LINK}}]
        out, err = proc.communicate("".join(json.dumps(r) + "\n" for r in reqs))
    finally:
        timer.cancel()
    replies = {}
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"non-JSON line on stdout: {line[:80]!r}")
            continue
        if "id" in msg:
            replies[msg["id"]] = msg
    info = replies.get(1, {}).get("result")
    if not info:
        problems.append(f"no engine.info result (stderr: {err[-300:]!r})")
    else:
        for need in ("vless", "wireguard"):
            if need not in info.get("schemes", []):
                problems.append(f"scheme missing from engine.info: {need}")
        if len(info.get("cores", [])) < 3:
            problems.append("fewer than 3 cores registered")
        if "mitm.build" not in info.get("methods", []):
            problems.append("scan/mitm methods not registered (module missing from the bundle?)")
    parsed = replies.get(2, {}).get("result")
    if not parsed or not parsed.get("ok"):
        problems.append("config.parse failed")
    if proc.returncode != 0:
        problems.append(f"engine exited with {proc.returncode}")
    return problems


def main(argv: list[str]) -> int:
    if "--" not in argv:
        print(__doc__)
        return 2
    cmd = argv[argv.index("--") + 1:]
    problems = smoke(cmd)
    for p in problems:
        print("FAIL:", p)
    if not problems:
        print("engine smoke test passed")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
