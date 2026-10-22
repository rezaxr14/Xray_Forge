#!/usr/bin/env python3
"""Live checks for the things CI and the sandbox cannot do.

Run on a real machine (by you or a local agent); writes a JSON report that is
safe to paste back: no links, UUIDs, tokens, SNI/host values, config contents
or (unless --include-endpoint) server addresses.

    python tools/live_check.py env
    python tools/live_check.py masque --masque-binary /path/to/sing-box-extended
    python tools/live_check.py psiphon --psiphon-binary ConsoleClient --psiphon-config client.config
    python tools/live_check.py vless --link-file my_link.txt
    python tools/live_check.py warp-scan
    python tools/live_check.py masque psiphon vless warp-scan ... --out report.json

Checks whose inputs are missing are reported as "skipped"; the exit code is 1
only when a check that ran failed (2 for bad arguments).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = ("env", "masque", "psiphon", "vless", "warp-scan")


def _skip(name: str, why: str) -> dict:
    return {"name": name, "status": "skipped", "ok": None, "detail": why}


def _env() -> dict:
    from xray_forge import __version__
    from xray_forge.core.cores import discover
    cores = []
    for name in discover.SPECS:
        path, source = discover.find(name)
        ok, ver = discover.version(name, path) if path else (False, "")
        cores.append({"name": name, "found": bool(path), "source": source, "ok": ok, "version": ver[:80]})
    return {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
            "xray_forge": __version__, "cores": cores}


def _probe_result(name: str, r: dict, t0: float) -> dict:
    ok = r.get("real") is not None and r.get("status") == "core ok"
    return {"name": name, "status": "ran", "ok": ok, "detail": str(r.get("status", ""))[:80],
            "ms": r.get("real"), "cc": r.get("cc", ""), "exit_ip_seen": bool(r.get("exit_ip")),
            "seconds": round(time.monotonic() - t0, 1)}


def check_masque(a) -> dict:
    from xray_forge.core import masque
    from xray_forge.core.cores import discover
    binary = a.masque_binary or discover.find_binary("singbox_extended")
    if not binary:
        return _skip("masque", "no sing-box-extended binary (--masque-binary)")
    t0 = time.monotonic()
    sup = masque.check_support(binary)
    if not sup["supported"]:
        return {"name": "masque", "status": "ran", "ok": False, "detail": sup["detail"], "seconds": round(time.monotonic() - t0, 1)}
    return _probe_result("masque", masque.probe(binary, masque.MasqueOptions(), timeout=a.timeout,
                                                start_timeout=a.start_timeout), t0)


def check_psiphon(a) -> dict:
    from xray_forge.core import psiphon
    from xray_forge.core.cores import discover
    binary = a.psiphon_binary or discover.find_binary("psiphon")
    config = a.psiphon_config or psiphon.configured_config()
    if not binary or not config:
        return _skip("psiphon", "needs --psiphon-binary and --psiphon-config")
    t0 = time.monotonic()
    try:
        r = psiphon.probe(binary, config, timeout=a.timeout, start_timeout=a.start_timeout)
    except ValueError as e:
        return {"name": "psiphon", "status": "ran", "ok": False, "detail": str(e)[:80]}
    return _probe_result("psiphon", r, t0)


def _link(a) -> str | None:
    if a.link_file:
        try:
            with open(a.link_file, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return None
    return os.environ.get("XF_LIVE_LINK", "").strip() or None


def check_vless(a, link: str | None) -> dict:
    if not link:
        return _skip("vless", "needs --link-file or XF_LIVE_LINK")
    from xray_forge.core import healthcheck as hc
    t0 = time.monotonic()
    rep = hc.run_health_check(link, timeout=a.timeout, core="auto")
    stages = []
    for s in rep.stages:
        nums = {k: v for k, v in s.data.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
        stages.append({"name": s.name, "ok": s.ok, "ms": s.ms, "detail": s.detail[:60], "numbers": nums})
    out = {"name": "vless", "status": "ran", "ok": rep.passed(), "scheme": rep.scheme, "score": rep.score,
           "techniques": list(rep.techniques), "stages": stages, "seconds": round(time.monotonic() - t0, 1),
           "detail": "" if rep.passed() else "a stage failed"}
    if a.include_endpoint:
        out["endpoint"] = rep.endpoint
    return out


def check_warp_scan(a) -> dict:
    from xray_forge.core import warp
    t0 = time.monotonic()
    res = warp.scan_endpoints(count=30, workers=10)
    return {"name": "warp-scan", "status": "ran", "ok": bool(res), "detail": f"{len(res)} responsive endpoint(s)",
            "best_ms": round(res[0][1]) if res else None, "seconds": round(time.monotonic() - t0, 1)}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("checks", nargs="+", choices=CHECKS)
    p.add_argument("--out", default="live_check_report.json")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--start-timeout", type=float, default=90.0)
    p.add_argument("--masque-binary")
    p.add_argument("--psiphon-binary")
    p.add_argument("--psiphon-config")
    p.add_argument("--link-file", help="file holding ONE share link (never put links on the command line)")
    p.add_argument("--include-endpoint", action="store_true", help="include the server address in the report")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    link = _link(a) if "vless" in a.checks else None
    if a.link_file and link is None:
        print("cannot read --link-file", file=sys.stderr)
        return 2
    report: dict = {"schema": 1, "env": _env(), "checks": []}
    for name in a.checks:
        try:
            if name == "masque":
                report["checks"].append(check_masque(a))
            elif name == "psiphon":
                report["checks"].append(check_psiphon(a))
            elif name == "vless":
                report["checks"].append(check_vless(a, link))
            elif name == "warp-scan":
                report["checks"].append(check_warp_scan(a))
        except Exception as e:                     # a crash in one check must not hide the others
            report["checks"].append({"name": name, "status": "ran", "ok": False, "detail": f"{type(e).__name__}"})
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    for c in report["checks"]:
        mark = {True: "PASS", False: "FAIL", None: "skip"}[c["ok"]]
        print(f"{mark}  {c['name']}: {c['detail']}")
    print(f"report written to {a.out}")
    return 1 if any(c["ok"] is False for c in report["checks"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
