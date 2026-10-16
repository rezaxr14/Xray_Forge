"""
Config parsing, normalization, URI mutation, naming engine, and multi-format exporters.
"""

import base64
import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote, unquote

from xray_forge.core.config import PROXY_SCHEMES, IPV4_RE


def classify_endpoint(v: str) -> str | None:
    import ipaddress
    v = (v or "").strip()
    if not v:
        return None
    try:
        ipaddress.IPv4Address(v)
        return "ipv4"
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(v)
        return "ipv6"
    except ValueError:
        pass
    if re.fullmatch(r"(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?:\.(?!-)[A-Za-z0-9_-]{1,63})+\.?", v):
        return "domain"
    return None


def valid_port(v: str) -> bool:
    return v.isdigit() and 1 <= int(v) <= 65535


def fmt_ms(v: Any) -> str:
    if isinstance(v, (int, float)):
        return f"{v:.0f}"
    if isinstance(v, str) and v.strip() not in ("", "—"):
        return v
    return "—"


def cc_flag(cc: str) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c.upper()) - 65) for c in cc)


def cc_cell(cc: str, edge: bool) -> str:
    if not cc:
        return ""
    return f"{cc_flag(cc)} {cc}{'*' if edge else ''}"


def sanitize(s: str, maxlen: int = 64) -> str:
    s = unquote(s or "")
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    s = re.sub(r"_{2,}", "_", s).strip("_.-")
    return s[:maxlen].strip("_.-")


def is_ip(host: str) -> bool:
    return bool(IPV4_RE.match(host or ""))


def split_netloc(netloc: str) -> tuple[str, str]:
    hostport = netloc.split("@", 1)[1] if "@" in netloc else netloc
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        return host, rest.lstrip(":")
    if ":" in hostport:
        host, _, port = hostport.rpartition(":")
        if port.isdigit():
            return host, port
    return hostport, ""


def build_netloc(userinfo: str, host: str, port: str) -> str:
    hostpart = f"[{host}]" if (":" in host and not host.startswith("[")) else host
    if port:
        hostpart = f"{hostpart}:{port}"
    return f"{userinfo}@{hostpart}" if userinfo else hostpart


def pick_domain(params: dict, netloc_host: str) -> str:
    for key in ("host", "sni"):
        v = params.get(key, "").strip()
        if v and not is_ip(v):
            return v
    for key in ("host", "sni"):
        v = params.get(key, "").strip()
        if v:
            return v
    return netloc_host or ""


def subdomain_of(host: str) -> str:
    host = (host or "").strip().strip(".").lower()
    if not host:
        return "host"
    if is_ip(host):
        return "ip"
    if ":" in host:
        return "v6"
    return sanitize(host.split(".")[0], 32) or "host"


def make_namer(template: str, start_id: int):
    used: set[str] = set()

    def name_for(i: int, params: dict, ip: str, port: str, scheme: str, old_name: str) -> str:
        dom = pick_domain(params, ip)
        keys = {
            "id": start_id + i,
            "sub": subdomain_of(dom),
            "path": sanitize(params.get("path", "")),
            "ip": (ip or "").replace(":", "-").strip("[]"),
            "port": port or "",
            "host": sanitize(dom),
            "net": sanitize(".".join(dom.split(".")[1:]) if "." in dom else dom),
            "sni": sanitize(params.get("sni", "")),
            "proto": scheme or "vless",
            "old": sanitize(old_name, 32),
        }
        try:
            base = template.format(**keys)
        except Exception:
            base = f"{start_id + i:03d}_{keys['sub']}"
        base = sanitize(base, 80) or f"cfg_{start_id + i:03d}"
        cand = base
        if cand in used and keys["ip"]:
            cand = f"{base}_{keys['ip']}"
        n = 2
        while cand in used:
            cand = f"{base}_{n}"
            n += 1
        used.add(cand)
        return cand

    return name_for


def fix_uri(line: str, fp: str, cs: str, fm: str, tls_only: bool,
            rename: bool, namer, idx: int, ov_ip: str = "", ov_port: str = "",
            want_fp: bool = True, want_cs: bool = True,
            want_fm: bool = True):
    line = line.strip()
    if not line:
        return line, "blank", None
    try:
        parts = urlsplit(line)
    except ValueError:
        return line, "skipped", None
    if parts.scheme.lower() not in PROXY_SCHEMES or "@" not in parts.netloc:
        return line, "skipped", None
    try:
        params = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return line, "skipped", None

    pd: dict[str, str] = {}
    for k, v in params:
        pd.setdefault(k.lower(), v)

    inject: list[tuple[str, str]] = []
    if want_fp and fp:
        inject.append(("fp", fp))
    if want_cs and cs:
        inject.append(("cs", cs))
    if want_fm and fm:
        inject.append(("fm", fm))
    injecting = bool(inject)

    security = pd.get("security")
    if injecting and tls_only and security is not None and security.lower() != "tls":
        return line, "skipped", None

    old_name = unquote(parts.fragment)
    ip, port = split_netloc(parts.netloc)

    userinfo = parts.netloc.rsplit("@", 1)[0] if "@" in parts.netloc else ""
    eff_ip = ov_ip or ip
    eff_port = ov_port or port
    if ov_ip or ov_port:
        netloc = build_netloc(userinfo, eff_ip, eff_port)
    else:
        netloc, eff_ip, eff_port = parts.netloc, ip, port

    name = namer(idx, pd, eff_ip, eff_port, parts.scheme.lower(), old_name)

    if injecting:
        drop = {k for k, _ in inject}
        lower = [k.lower() for k, _ in params]
        if want_fp and "fp" in lower:
            at = lower.index("fp")
        else:
            anchor = max((i for i, k in enumerate(lower) if k in ("sni", "security")), default=-1)
            at = anchor + 1
        out: list[tuple[str, str]] = []
        placed = False
        for i, (k, v) in enumerate(params):
            if i == at and not placed:
                out.extend(inject)
                placed = True
            if k.lower() in drop:
                continue
            out.append((k, v))
        if not placed:
            out.extend(inject)
        query = urlencode(out, quote_via=quote)
    else:
        query = parts.query

    frag = quote(name, safe="") if rename else parts.fragment
    new = urlunsplit((parts.scheme, netloc, parts.path, query, frag))
    return new, ("unchanged" if new == line else "fixed"), name


def convert_block(text: str, fp: str, cs: str, fm: str, tls_only: bool,
                  rename: bool, template: str, start_id: int,
                  ov_ip: str = "", ov_port: str = "",
                  want_fp: bool = True, want_cs: bool = True,
                  want_fm: bool = True):
    namer = make_namer(template, start_id)
    lines: list[str] = []
    names: list[tuple[str, str]] = []
    counts = {"fixed": 0, "unchanged": 0, "skipped": 0}
    idx = 0
    for raw in text.splitlines():
        if not raw.strip():
            continue
        idx += 1
        new, st, name = fix_uri(raw, fp, cs, fm, tls_only, rename, namer, idx,
                                ov_ip, ov_port, want_fp, want_cs, want_fm)
        if st in ("fixed", "unchanged"):
            counts[st] += 1
            lines.append(new)
            names.append((name or "", new))
        elif st == "skipped":
            counts["skipped"] += 1
            lines.append(raw.strip())
    return lines, names, counts


def parse_target(line: str) -> dict[str, str] | None:
    try:
        parts = urlsplit(line.strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in PROXY_SCHEMES or "@" not in parts.netloc:
        return None
    host, port = split_netloc(parts.netloc)
    if not host:
        return None
    pd: dict[str, str] = {}
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        pd.setdefault(k.lower(), v)
    sni = pd.get("sni", "") or pd.get("host", "") or host
    hdr = pd.get("host", "") or sni
    path = pd.get("path", "") or "/"
    if not path.startswith("/"):
        path = "/" + path
    name = unquote(parts.fragment) or f"{host}:{port}"
    uuid_s = unquote(parts.username or "")
    transport = pd.get("type", "ws").lower()
    security = pd.get("security", "").lower()
    fp = pd.get("fp", "chrome")
    alpn = pd.get("alpn", "")
    service_name = pd.get("servicename", "") or pd.get("service_name", "")
    return {
        "name": name,
        "scheme": parts.scheme.lower(),
        "host": host,
        "port": port or "443",
        "sni": sni,
        "hdr": hdr,
        "path": path,
        "uuid": uuid_s,
        "type": transport,
        "security": security,
        "fp": fp,
        "alpn": alpn,
        "service_name": service_name,
        "raw": line.strip()
    }


# ===========================================================================
# Exporters: Clash Meta / Sing-box / Subscription
# ===========================================================================

def export_to_clash(lines: list[str]) -> str:
    """Export proxy lines to Clash Meta (Mihomo) YAML format."""
    proxies = []
    names = []
    for line in lines:
        t = parse_target(line)
        if not t:
            continue
        px: dict[str, Any] = {
            "name": t["name"],
            "type": t["scheme"],
            "server": t["host"],
            "port": int(t["port"]),
        }
        if t["scheme"] == "vless":
            px["uuid"] = t["uuid"]
            px["cipher"] = "auto"
        elif t["scheme"] == "trojan":
            px["password"] = t["uuid"]

        if t["security"] in ("tls", "reality"):
            px["tls"] = True
            px["servername"] = t["sni"]
            px["client-fingerprint"] = t["fp"]
            if t["security"] == "reality":
                px["reality-opts"] = {"public-key": "", "short-id": ""}

        if t["type"] == "ws":
            px["network"] = "ws"
            px["ws-opts"] = {
                "path": t["path"],
                "headers": {"Host": t["hdr"]}
            }
        elif t["type"] == "grpc":
            px["network"] = "grpc"
            px["grpc-opts"] = {"grpc-service-name": t["service_name"]}
        elif t["type"] == "httpupgrade":
            px["network"] = "httpupgrade"
            px["httpupgrade-opts"] = {"path": t["path"], "host": t["hdr"]}

        proxies.append(px)
        names.append(t["name"])

    import yaml
    try:
        yaml_out = yaml.dump({"proxies": proxies}, sort_keys=False, allow_unicode=True)
    except ImportError:
        # Fallback JSON-like YAML dump
        lines_out = ["proxies:"]
        for p in proxies:
            lines_out.append(f"  - name: \"{p['name']}\"")
            lines_out.append(f"    type: {p['type']}")
            lines_out.append(f"    server: {p['server']}")
            lines_out.append(f"    port: {p['port']}")
            if "uuid" in p:
                lines_out.append(f"    uuid: {p['uuid']}")
            if "password" in p:
                lines_out.append(f"    password: {p['password']}")
            if p.get("tls"):
                lines_out.append("    tls: true")
                lines_out.append(f"    servername: {p.get('servername')}")
                lines_out.append(f"    client-fingerprint: {p.get('client-fingerprint', 'chrome')}")
            if p.get("network") == "ws":
                lines_out.append("    network: ws")
                lines_out.append("    ws-opts:")
                lines_out.append(f"      path: \"{p['ws-opts']['path']}\"")
                lines_out.append("      headers:")
                lines_out.append(f"        Host: \"{p['ws-opts']['headers']['Host']}\"")
        yaml_out = "\n".join(lines_out)
    return yaml_out


def export_to_singbox(lines: list[str]) -> str:
    """Export proxy lines to Sing-box outbounds format."""
    outbounds = []
    for line in lines:
        t = parse_target(line)
        if not t:
            continue
        ob: dict[str, Any] = {
            "tag": t["name"],
            "type": t["scheme"],
            "server": t["host"],
            "server_port": int(t["port"]),
        }
        if t["scheme"] == "vless":
            ob["uuid"] = t["uuid"]
        elif t["scheme"] == "trojan":
            ob["password"] = t["uuid"]

        if t["security"] in ("tls", "reality"):
            ob["tls"] = {
                "enabled": True,
                "server_name": t["sni"],
                "utls": {
                    "enabled": True,
                    "fingerprint": t["fp"]
                }
            }
        if t["type"] == "ws":
            ob["transport"] = {
                "type": "ws",
                "path": t["path"],
                "headers": {"Host": t["hdr"]}
            }
        elif t["type"] == "grpc":
            ob["transport"] = {
                "type": "grpc",
                "service_name": t["service_name"]
            }
        elif t["type"] == "httpupgrade":
            ob["transport"] = {
                "type": "httpupgrade",
                "path": t["path"],
                "host": t["hdr"]
            }
        outbounds.append(ob)
    return json.dumps({"outbounds": outbounds}, indent=2, ensure_ascii=False)


def export_to_sub(lines: list[str]) -> str:
    """Export configs to Base64 standard subscription."""
    raw = "\n".join(line.strip() for line in lines if line.strip())
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")
