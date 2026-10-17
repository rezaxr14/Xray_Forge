"""
Command-line interface — fully headless (no tkinter import).

Entry points:
* ``python -m xray_forge <cmd>`` (via xray_forge/__main__.py)
* ``python Xray_Forge.py <cmd>`` (root launcher)
* ``xray-forge <cmd>`` (installed console script)

Subcommands: gui · convert · export · test · scan · geo ·
             mitm · warp · subs · version
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import sys

from xray_forge import __version__
from xray_forge.core.config import (
    DEFAULT_FP, DEFAULT_CS, DEFAULT_FM, DEFAULT_TEMPLATE,
    FASTLY_RANGES, MITM_DEFAULT_CERT, MITM_DEFAULT_KEY,
)
from xray_forge.core.parser import (
    convert_block, parse_target,
    export_to_clash, export_to_singbox, export_to_sub,
)
from xray_forge.core.dedup import dedup_configs
from xray_forge.core.probe import (
    parse_frag, tcp_ping, tls_connect, ws_upgrade,
)
from xray_forge.core.scanner import sample_cidr, geo_lookup
from xray_forge.core.xray_bridge import xray_probe


# ===========================================================================
# Commands (also imported by tests)
# ===========================================================================

def cli_convert(infile: str, outfile: str, fp: str, cs: str, fm: str,
                ip: str | None, port: str | None, template: str,
                start: int, no_rename: bool, ip_only: bool,
                no_fp: bool, no_cs: bool, no_fm: bool,
                all_security: bool, dedup: bool) -> None:
    with open(infile, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    tls_only = not all_security
    rename = not no_rename
    want_fp = (not no_fp) and (not ip_only)
    want_cs = (not no_cs) and (not ip_only)
    want_fm = (not no_fm) and (not ip_only)
    ov_ip = ip or ""
    ov_port = port or ""
    lines, names, c = convert_block(
        text, fp, cs, fm, tls_only, rename, template, start,
        ov_ip, ov_port, want_fp, want_cs, want_fm)
    if dedup:
        lines, removed = dedup_configs(lines)
    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"converted {c['fixed']} fixed · {c['unchanged']} unchanged · "
          f"{c['skipped']} skipped → {outfile}")


def cli_export(infile: str, fmt_name: str, outfile: str) -> None:
    with open(infile, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    lines = [l for l in text.splitlines() if l.strip()]
    if fmt_name == "clash":
        out = export_to_clash(lines)
    elif fmt_name == "singbox":
        out = export_to_singbox(lines)
    elif fmt_name == "sub":
        out = export_to_sub(lines)
    else:
        raise SystemExit(f"unknown format: {fmt_name}")
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"exported {len(lines)} configs as {fmt_name} → {outfile}")


def cli_test(infile: str, timeout: float, frag_s: str = "5,94,1@2",
             core: str | None = None) -> None:
    with open(infile, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    lines = [l for l in text.splitlines() if l.strip()]
    frag = parse_frag(frag_s)
    for line in lines:
        t = parse_target(line)
        if not t:
            print(f"skip: {line[:60]}")
            continue
        if core:
            r = xray_probe(line, core, frag_on=True, timeout=timeout)
            print(f"{t.name} | real={r.get('real')} cc={r.get('cc')} "
                  f"ip={r.get('exit_ip')} status={r.get('status')}")
        else:
            try:
                tcp = tcp_ping(t.host, t.port, timeout=timeout)
                tc, sock, info = tls_connect(
                    t.host, t.port, sni=t.sni, frag=frag, timeout=timeout)
                line2, wms = ws_upgrade(tc, t.host_header, t.path, timeout)
                print(f"{t.name} | tcp={tcp} tls={info['tls_ms']:.0f} "
                      f"ws={wms:.0f} line={line2[:30]}")
                sock.close()
            except Exception as e:
                print(f"{t.name} | error: {e}")


def cli_scan(cidr: str, count: int, sni: str | None, port: str,
             workers: int, frag_s: str,
             resume: str | None = None,
             csv_out: str | None = None, json_out: str | None = None,
             geo: bool = False) -> None:
    from xray_forge.core.scan_session import ScanSession
    if resume:
        session = ScanSession(resume)
    else:
        import time as _t
        session = ScanSession(f"scan_{_t.strftime('%Y%m%d_%H%M%S')}")
    n = session.set_targets([cidr], count)
    print(f"scanning {n} ip(s) from {cidr} …")
    session.run(port=port, workers=workers, frag=frag_s, sni=sni, geo=geo,
                progress=lambda d, t: print(f"\r{d}/{t}", end="", flush=True))
    print()
    alive = session.alive()
    for r in alive[:20]:
        cc = f" {r.cc}" if r.cc else ""
        print(f"alive: {r.ip}:{r.port} ms={r.ms:.0f} jitter={r.jitter:.0f}{cc}")
    print(f"scan done — {len(alive)}/{len(session.results)} alive "
          f"({len(session.pending)} pending)")
    if csv_out:
        print("csv →", session.export_csv(csv_out))
    if json_out:
        print("json →", session.export_json(json_out))


def cli_geo(ip: str | None) -> None:
    print(geo_lookup(ip or ""))


def cli_snisearch(ips: str, snis: str, port: str, workers: int, frag_s: str,
                  timeout: float, resume: str | None = None,
                  from_scan: str | None = None, presets: bool = False,
                  no_http: bool = False, csv_out: str | None = None,
                  json_out: str | None = None) -> None:
    """SNI / fronting-host search: candidate SNIs × clean IPs."""
    from xray_forge.core.sni_search import SniSearch, DEFAULT_SNI_CANDIDATES, \
        targets_from_scan
    ip_list = SniSearch.parse_list(ips)
    if from_scan:
        scan_ips = targets_from_scan(from_scan)
        print(f"from scan '{from_scan}': {len(scan_ips)} alive ip(s)")
        ip_list = SniSearch.parse_list(ips + " " + " ".join(scan_ips))
    sni_list = SniSearch.parse_list(snis)
    if presets:
        for cand in DEFAULT_SNI_CANDIDATES:
            if cand not in sni_list:
                sni_list.append(cand)
    if not ip_list or not sni_list:
        print("need --ips and --snis (or --from-scan / --presets)")
        return
    import time as _t
    name = resume or f"sni_{_t.strftime('%Y%m%d_%H%M%S')}"
    search = SniSearch(name)
    n = search.set_targets(ip_list, sni_list, port=port, resume=bool(resume))
    print(f"probing {n} (ip, sni) pair(s) · {len(ip_list)} ip × "
          f"{len(sni_list)} sni …")
    search.run(port=port, workers=workers, frag=frag_s, timeout=timeout,
               http_check=not no_http,
               progress=lambda d, t: print(f"\r{d}/{t}", end="", flush=True))
    print()
    good = search.hits()
    for h in good[:20]:
        http = " http✓" if h.http_ok else ""
        print(f"ok: {h.ip}:{h.port} sni={h.sni} ms={h.tls_ms:.0f} "
              f"{h.tls_ver}{http}")
    print(f"sni search done — {len(good)}/{len(search.results)} working "
          f"({len(search.pending)} pending)")
    if csv_out:
        print("csv →", search.export_csv(csv_out))
    if json_out:
        print("json →", search.export_json(json_out))


def cli_mitm(out: str | None, cn: str, gen_cert: bool,
             groups: str, guide: bool) -> None:
    """Generate the MITM-DomainFronting Xray config (+ optional personal CA)."""
    from xray_forge.core.domainfront import (
        build_config, write_config, generate_ca, openssl_command, setup_guide,
    )
    out = out or "MITM-DomainFronting.json"
    overrides: dict = {}
    if groups and groups != "all":
        overrides["groups"] = [g.strip() for g in groups.split(",") if g.strip()]
    if gen_cert:
        try:
            crt, key = generate_ca(cn, MITM_DEFAULT_CERT, MITM_DEFAULT_KEY)
            print(f"personal CA generated: {crt} + {key} — TRUST it, never share it")
        except RuntimeError as e:
            print(f"cert generation skipped: {e}")
            print("openssl equivalent:")
            print("  " + openssl_command(cn))
    write_config(out, **overrides)
    print(f"config written → {out}")
    print("requires Xray-core >= 26.2.6 (custom config in v2rayN / v2rayNG)")
    if guide:
        print()
        print(setup_guide("windows"))
        print()
        print(setup_guide("android"))


def cli_warp(action: str, endpoint: str | None, scan_count: int,
             workers: int) -> None:
    """WARP account + WireGuard outbound management."""
    from xray_forge.core import warp
    from xray_forge.core.cores import get_core
    if action == "register":
        try:
            acct = warp.register_account()
        except RuntimeError as e:
            raise SystemExit(f"warp registration failed: {e}")
        path = warp.save_account(acct)
        print(f"WARP device registered: {acct.device_id[:12]}… → {path}")
        out = warp.account_to_outbound(acct)
        for core_name in ("xray", "singbox", "mihomo"):
            core = get_core(core_name)
            if core and core.supports(out):
                print(f"  {core_name}: supported ✓")
        print("warp config →", cli_warp_config())
    elif action == "config":
        acct = warp.load_account()
        if acct is None:
            raise SystemExit("no saved WARP account — run: warp register")
        print(cli_warp_config(acct, endpoint))
    elif action == "scan-endpoints":
        print(f"scanning ~{scan_count} WARP endpoints ({workers} workers) …")
        results = warp.scan_endpoints(scan_count, workers,
                                      progress=lambda d, t:
                                      print(f"\r{d}/{t}", end="", flush=True))
        print()
        for ep, ms in results[:15]:
            print(f"  {ep}  {ms:.0f} ms")
        print(f"{len(results)} responsive endpoint(s)")
    else:
        raise SystemExit(f"unknown warp action: {action}")


def cli_warp_config(acct=None, endpoint: str | None = None) -> str:
    from xray_forge.core import warp
    from xray_forge.core.cores import get_core
    acct = acct or warp.load_account()
    if acct is None:
        raise SystemExit("no saved WARP account — run: warp register")
    out = warp.account_to_outbound(acct, endpoint=endpoint or "")
    sb = get_core("singbox")
    return json.dumps(sb.render_outbound(out), indent=2)


def cli_subs(action: str, url: str, name: str, top_n: int, outfile: str,
             workers: int, timeout: float, no_throughput: bool,
             core: str | None = None) -> None:
    """Subscription source manager + staged health checks."""
    from xray_forge.core.sub_source import SourceManager
    from xray_forge.core import healthcheck as hc
    mgr = SourceManager()
    if action == "add":
        src = mgr.add(url, name)
        print(f"added source {src.url}")
    elif action == "list":
        for s in mgr.list_sources():
            label = f"{s.name} — " if s.name else ""
            print(f"[{'x' if s.enabled else ' '}] {label}{s.url}  "
                  f"etag={s.etag[:12] or '-'} last={s.last_fetch or '-'} "
                  f"status={s.last_status or '-'} count={s.last_count}")
    elif action == "remove":
        print("removed" if mgr.remove(url) else "not found")
    elif action == "fetch":
        for u, lines in mgr.fetch_all().items():
            print(f"{u}: {len(lines)} configs")
        lines, removed = mgr.combined_lines()
        print(f"combined: {len(lines)} configs ({removed} duplicates removed)")
    elif action == "check":
        lines, _ = mgr.combined_lines()
        if not lines:
            raise SystemExit("no cached configs — run: subs fetch")
        print(f"health-checking {len(lines)} configs "
              f"(core={core or 'native-only'}) …")
        reports = hc.run_health_checks(
            lines, workers=workers, timeout=timeout,
            do_throughput=not no_throughput, core=core,
            progress=lambda d, t: print(f"\r{d}/{t}", end="", flush=True))
        print()
        ranked = hc.rank_reports(reports)
        for r in ranked[:top_n or 20]:
            print("  " + r.summary())
        if outfile:
            best = hc.export_best_subscription(reports, top_n or 10)
            with open(outfile, "w", encoding="utf-8") as f:
                f.write(best)
            print(f"best-{top_n or 10} subscription → {outfile}")
        tags = hc.tagged_lines(reports)
        if tags:
            print(f"{len(tags)} working config(s) tagged with techniques")
    else:
        raise SystemExit(f"unknown subs action: {action}")


# ===========================================================================
# Argument parser
# ===========================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xray-forge",
        description="Xray Forge — VLESS/Trojan/VMess/SS/Hysteria2/TUIC/WARP utility")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log debug output to stderr (also ~/.xray_forge/logs)")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("gui", help="launch GUI (default)")
    sub.add_parser("version", help="print version")
    sub.add_parser("serve", help="run the engine API (JSON-RPC over stdin/stdout)")

    p_conv = sub.add_parser("convert", help="convert configs")
    p_conv.add_argument("infile")
    p_conv.add_argument("outfile")
    p_conv.add_argument("--fp", default=DEFAULT_FP)
    p_conv.add_argument("--cs", default=DEFAULT_CS)
    p_conv.add_argument("--fm", default=json.dumps(DEFAULT_FM, separators=(",", ":")))
    p_conv.add_argument("--ip")
    p_conv.add_argument("--port")
    p_conv.add_argument("--template", default=DEFAULT_TEMPLATE)
    p_conv.add_argument("--start", type=int, default=1)
    p_conv.add_argument("--no-rename", action="store_true")
    p_conv.add_argument("--ip-only", action="store_true")
    p_conv.add_argument("--no-fp", action="store_true")
    p_conv.add_argument("--no-cs", action="store_true")
    p_conv.add_argument("--no-fm", action="store_true")
    p_conv.add_argument("--all-security", action="store_true")
    p_conv.add_argument("--dedup", action="store_true")

    p_exp = sub.add_parser("export", help="export configs")
    p_exp.add_argument("infile")
    p_exp.add_argument("outfile")
    p_exp.add_argument("--format", choices=["clash", "singbox", "sub"],
                       required=True)

    p_test = sub.add_parser("test", help="test configs")
    p_test.add_argument("infile")
    p_test.add_argument("--timeout", type=float, default=8.0)
    p_test.add_argument("--frag", default="5,94,1@2")
    p_test.add_argument("--core", default=None)

    p_scan = sub.add_parser("scan", help="scan CIDR (resumable sessions)")
    p_scan.add_argument("cidr")
    p_scan.add_argument("--count", type=int, default=200)
    p_scan.add_argument("--sni", default=None)
    p_scan.add_argument("--port", default="443")
    p_scan.add_argument("--workers", type=int, default=64)
    p_scan.add_argument("--frag", default="5,94,1@2")
    p_scan.add_argument("--resume", default=None, metavar="NAME",
                        help="resume a named scan session")
    p_scan.add_argument("--csv", default=None, metavar="FILE")
    p_scan.add_argument("--json", default=None, dest="json_out", metavar="FILE")
    p_scan.add_argument("--geo", action="store_true",
                        help="tag results with country/ISP")

    p_sni = sub.add_parser("snisearch",
                           help="probe candidate SNIs against clean IPs")
    p_sni.add_argument("--ips", default="",
                       help="comma/space separated clean IPs")
    p_sni.add_argument("--snis", default="",
                       help="comma/space separated candidate SNIs")
    p_sni.add_argument("--presets", action="store_true",
                       help="add the built-in SNI candidate list")
    p_sni.add_argument("--from-scan", default=None, metavar="NAME",
                       help="merge alive IPs of a saved scan session")
    p_sni.add_argument("--port", default="443")
    p_sni.add_argument("--workers", type=int, default=32)
    p_sni.add_argument("--frag", default="5,94,1@2")
    p_sni.add_argument("--timeout", type=float, default=5.0)
    p_sni.add_argument("--no-http", action="store_true",
                       help="skip the plain GET check after the handshake")
    p_sni.add_argument("--resume", default=None, metavar="NAME",
                       help="resume a named sni-search session")
    p_sni.add_argument("--csv", default=None, metavar="FILE")
    p_sni.add_argument("--json", default=None, dest="json_out", metavar="FILE")

    p_geo = sub.add_parser("geo", help="geo lookup")
    p_geo.add_argument("ip", nargs="?", default=None)

    p_mitm = sub.add_parser("mitm", help="MITM-DomainFronting config generator")
    p_mitm.add_argument("-o", "--out", default=None, metavar="FILE")
    p_mitm.add_argument("--cn", default="Xray Forge MITM CA",
                        help="common name for the personal CA")
    p_mitm.add_argument("--gen-cert", action="store_true",
                        help="also generate a personal CA (needs cryptography)")
    p_mitm.add_argument("--groups", default="all",
                        help="comma list: google,meta,fastly (default all)")
    p_mitm.add_argument("--guide", action="store_true",
                        help="print setup instructions")

    p_warp = sub.add_parser("warp", help="WARP / WireGuard management")
    p_warp.add_argument("action", choices=["register", "config", "scan-endpoints"])
    p_warp.add_argument("--endpoint", default=None)
    p_warp.add_argument("--count", type=int, default=60)
    p_warp.add_argument("--workers", type=int, default=20)

    p_subs = sub.add_parser("subs", help="subscription sources + health checks")
    p_subs.add_argument("action",
                        choices=["add", "list", "remove", "fetch", "check"])
    p_subs.add_argument("--url", default="")
    p_subs.add_argument("--name", default="")
    p_subs.add_argument("--top", type=int, default=10, dest="top_n")
    p_subs.add_argument("--out", default=None, dest="outfile")
    p_subs.add_argument("--workers", type=int, default=8)
    p_subs.add_argument("--timeout", type=float, default=6.0)
    p_subs.add_argument("--no-throughput", action="store_true")
    p_subs.add_argument("--core", default=None,
                        choices=["auto", "xray", "singbox", "mihomo"],
                        help="check non-VLESS/WS configs via a real core")

    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to cp1252 and crash on unicode output.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.cmd
    from xray_forge.core.log import configure
    configure(verbose=args.verbose, stderr=args.verbose)

    if cmd == "version":
        print(f"xray-forge {__version__}")
        return 0
    if cmd == "serve":
        from xray_forge.engine.server import serve
        return serve()
    if cmd == "convert":
        cli_convert(args.infile, args.outfile, args.fp, args.cs, args.fm,
                    args.ip, args.port, args.template, args.start,
                    args.no_rename, args.ip_only, args.no_fp, args.no_cs,
                    args.no_fm, args.all_security, args.dedup)
    elif cmd == "export":
        cli_export(args.infile, args.format, args.outfile)
    elif cmd == "test":
        cli_test(args.infile, args.timeout, args.frag, args.core)
    elif cmd == "scan":
        cli_scan(args.cidr, args.count, args.sni, args.port,
                 args.workers, args.frag, resume=args.resume,
                 csv_out=args.csv, json_out=args.json_out, geo=args.geo)
    elif cmd == "snisearch":
        cli_snisearch(args.ips, args.snis, args.port, args.workers,
                      args.frag, args.timeout, resume=args.resume,
                      from_scan=args.from_scan, presets=args.presets,
                      no_http=args.no_http, csv_out=args.csv,
                      json_out=args.json_out)
    elif cmd == "geo":
        cli_geo(args.ip)
    elif cmd == "mitm":
        cli_mitm(args.out, args.cn, args.gen_cert, args.groups, args.guide)
    elif cmd == "warp":
        cli_warp(args.action, args.endpoint, args.count, args.workers)
    elif cmd == "subs":
        cli_subs(args.action, args.url, args.name, args.top_n, args.outfile,
                 args.workers, args.timeout, args.no_throughput, args.core)
    else:
        # default: launch GUI (imported lazily so the CLI stays headless)
        from xray_forge.app import App
        app = App()
        app.mainloop()
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
