"""
Real Xray-core bridge: config generation, local SOCKS5 proxy executor, version detection.
Includes MMDF-style domain-fronting and fake-SNI outbounds (patterniha tricks).
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit, parse_qsl

from xray_forge.core.config import PROXY_SCHEMES, IPV4_RE
from xray_forge.core.parser import parse_target
from xray_forge.core.probe import ProbeError, _read_http, sock_recv


def find_xray_core() -> str:
    exe = "xray.exe" if os.name == "nt" else "xray"
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "") or os.path.join(home, "AppData", "Roaming")
    here = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv else "."
    cands = [
        os.environ.get("XRAY_CORE", ""),
        os.path.join(appdata, "v2rayN", "bin", "xray", exe),
        os.path.join(home, "AppData", "Roaming", "v2rayN", "bin", "xray", exe),
        os.path.join(home, "v2rayN", "bin", "xray", exe),
        os.path.join(here, "bin", "xray", exe),
        os.path.join(here, exe),
        os.path.join("bin", "xray", exe),
        exe,
    ]
    for c in cands:
        if not c:
            continue
        w = shutil.which(c)
        if w:
            return w
        if os.path.isfile(c):
            return os.path.abspath(c)
    return ""


def check_core_version(path: str) -> str:
    kw: dict[str, Any] = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        out = subprocess.run([path, "version"], capture_output=True,
                             text=True, timeout=10, **kw)
    except OSError as e:
        return f"✖ cannot run core: {type(e).__name__}"
    except subprocess.TimeoutExpired:
        return "✖ core version check timed out"
    first = (out.stdout or out.stderr or "").strip().splitlines()
    return first[0].strip()[:90] if first else "✖ no version output"


def _stream_settings(t: dict, pd: dict, ntype: str, sec: str,
                     tls_on: bool, sni: str, fp: str,
                     frag_on: bool) -> dict[str, Any]:
    stream: dict[str, Any] = {
        "network": ntype,
        "security": "tls" if sec == "tls" else ("reality" if sec == "reality" else "none"),
    }

    if ntype == "ws":
        stream["wsSettings"] = {"path": t["path"], "headers": {"Host": t["hdr"]}}
    elif ntype == "grpc":
        stream["grpcSettings"] = {"serviceName": pd.get("servicename", "") or pd.get("service_name", "")}
    elif ntype == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": t["path"], "host": t["hdr"]}

    if sec == "reality":
        rs: dict[str, Any] = {"show": False, "fingerprint": fp}
        if sni and not IPV4_RE.match(sni):
            rs["serverName"] = sni
        stream["realitySettings"] = rs
    elif tls_on:
        ts: dict[str, Any] = {"allowInsecure": True, "fingerprint": fp}
        if sni and not IPV4_RE.match(sni):
            ts["serverName"] = sni
        if pd.get("cs"):
            ts["cipherSuites"] = pd["cs"]
        if pd.get("alpn"):
            ts["alpn"] = [x.strip() for x in pd["alpn"].split(",") if x.strip()]
        stream["tlsSettings"] = ts

    if frag_on and tls_on:
        stream["sockopt"] = {"dialerProxy": "frag"}
    return stream


def build_xray_config(line: str, socks_port: int, frag_on: bool,
                      front_domain: str | None = None) -> dict:
    parts = urlsplit(line.strip())
    proto = parts.scheme.lower()
    if proto not in PROXY_SCHEMES:
        raise ProbeError("cfg", f"scheme {proto} unsupported")
    t = parse_target(line)
    if not t:
        raise ProbeError("cfg", "unparsable config")
    pd: dict[str, str] = {}
    for k, v in parse_qsl(parts.query):
        pd.setdefault(k.lower(), v)

    ntype = pd.get("type", "ws").lower()
    sec = pd.get("security", "").lower()
    tls_on = sec in ("tls", "reality")
    sni = t["sni"]
    fp = pd.get("fp", "chrome")

    stream = _stream_settings(t, pd, ntype, sec, tls_on, sni, fp, frag_on)

    # MMDF-style domain fronting: real Host inside TLS, front SNI outside
    if front_domain and tls_on:
        if "tlsSettings" in stream:
            stream["tlsSettings"]["serverName"] = front_domain

    if proto == "trojan":
        out = {"tag": "proxy", "protocol": "trojan",
               "settings": {"servers": [{"address": t["host"],
                                         "port": int(t["port"]),
                                         "password": t["uuid"]}]},
               "streamSettings": stream}
    else:
        out = {"tag": "proxy", "protocol": "vless",
               "settings": {"vnext": [{"address": t["host"],
                                       "port": int(t["port"]),
                                       "users": [{"id": t["uuid"],
                                                  "encryption": "none",
                                                  "flow": ""}]}]},
               "streamSettings": stream}

    outs = [out]
    if frag_on and tls_on:
        outs.append({"tag": "frag", "protocol": "freedom",
                     "settings": {"fragment": {"packets": "tlshello",
                                               "length": "5-94",
                                               "interval": "1"}}})
    outs.append({"tag": "direct", "protocol": "freedom"})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks", "protocol": "socks",
                      "listen": "127.0.0.1", "port": socks_port,
                      "settings": {"udp": False}}],
        "outbounds": outs
    }


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


def xray_probe(line: str, xray_path: str, frag_on: bool,
               timeout: float = 8.0,
               front_domain: str | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"real": None, "cc": "", "exit_ip": "", "status": ""}
    kw: dict[str, Any] = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    free = socket.socket()
    try:
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
    finally:
        free.close()

    cfg_fd, cfg_path = tempfile.mkstemp(suffix=".json")
    os.close(cfg_fd)
    err_fd, err_path = tempfile.mkstemp(suffix=".log")
    os.close(err_fd)
    proc: subprocess.Popen | None = None
    try:
        cfg = build_xray_config(line, port, frag_on, front_domain=front_domain)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        proc = subprocess.Popen([xray_path, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL,
                                stderr=open(err_path, "wb"), **kw)
        ok = False
        end = time.time() + 5
        while time.time() < end:
            if proc.poll() is not None:
                break
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
                s.close()
                ok = True
                break
            except OSError:
                time.sleep(0.1)
        if not ok:
            tail = ""
            try:
                with open(err_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = [l for l in f.read().strip().splitlines() if l]
                tail = lines[-1][:60] if lines else ""
            except OSError:
                pass
            res["status"] = ("core exited: " + tail) if tail else "core failed to start"
            return res
        t0 = time.perf_counter()
        s = socks5_connect("127.0.0.1", port, "ip-api.com", 80, timeout=timeout)
        try:
            s.sendall((b"GET /json?fields=status,countryCode,country,city,isp,query HTTP/1.1\r\n"
                       b"Host: ip-api.com\r\nUser-Agent: vless-forge\r\nConnection: close\r\n\r\n"))
            raw = _read_http(sock_recv(s, None), time.perf_counter() + timeout, None)
        finally:
            s.close()
        res["real"] = (time.perf_counter() - t0) * 1000
        try:
            d = json.loads(raw["body"].decode("utf-8", "replace"))
        except Exception:
            d = {}
        cc = str(d.get("countryCode") or "")
        if len(cc) == 2 and cc.isalpha():
            res["cc"] = cc.upper()
            res["exit_ip"] = str(d.get("query") or "")
            res["status"] = "core ok"
        else:
            res["status"] = f"core: geo odd ({raw['status'][:24]})"
        return res
    except ProbeError as pe:
        res["status"] = f"core: {pe.detail[:50]}"
        return res
    except Exception as e:
        res["status"] = f"core: {type(e).__name__}"
        return res
    finally:
        if proc and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
        for p in (cfg_path, err_path):
            try:
                os.unlink(p)
            except OSError:
                pass
