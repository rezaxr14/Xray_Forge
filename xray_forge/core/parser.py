"""
Config parsing, normalization, URI mutation, naming engine, and multi-format exporters.

``parse_target`` returns a typed :class:`xray_forge.core.models.Outbound`
(kept dict-accessible for backwards compatibility).
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote, unquote

from xray_forge.core.config import PROXY_SCHEMES, IPV4_RE
from xray_forge.core.models import Outbound, b64_decode_pad, vmess_json_to_outbound

# Schemes that parse_target understands (superset of PROXY_SCHEMES, which is
# the set the converter is allowed to inject fp/cs/fm into).
PARSE_SCHEMES = PROXY_SCHEMES | {"hysteria2", "hy2", "tuic", "wireguard", "wg"}


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


def tag_name_with_cc(line: str, cc: str) -> tuple[str, str, bool]:
    """Append ``[CC]`` (an exit-country code) to a config's name.

    Returns ``(new_line, name, changed)``.  Idempotent: a name that already
    ends with ``[CC]`` is left alone, and an invalid country code or an
    unparsable line returns the line unchanged.  Link schemes keep their
    query untouched (only the ``#name`` fragment is rewritten); VMess stores
    its name inside the base64 JSON, so it is re-rendered through its
    handler.
    """
    line = line.strip()
    code = (cc or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return line, "", False
    tag = f"[{code}]"
    if line.lower().startswith("vmess://"):
        from xray_forge.core.protocols import handler_for
        out = parse_target(line)
        handler = handler_for("vmess") if out is not None else None
        if out is None or handler is None:
            return line, "", False
        if out.name.endswith(tag):
            return line, out.name, False
        out.name = f"{out.name}{tag}"
        return handler.to_uri(out), out.name, True
    try:
        parts = urlsplit(line)
    except ValueError:
        return line, "", False
    if parts.scheme.lower() not in PARSE_SCHEMES:
        return line, "", False
    name = unquote(parts.fragment)
    if name.endswith(tag):
        return line, name, False
    name = f"{name}{tag}"
    new = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query,
                      quote(name, safe="")))
    return new, name, True


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


# ---------------------------------------------------------------------------
# parse_target -> Outbound
# ---------------------------------------------------------------------------

def _parse_ss(line: str, parts) -> Outbound | None:
    """SIP002 (ss://base64url(method:pass)@host:port) and legacy
    (ss://base64(method:password@host:port)) forms."""
    params = {}
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        params.setdefault(k.lower(), v)
    name = unquote(parts.fragment) or ""
    userinfo = parts.username or ""
    if parts.netloc and "@" not in parts.netloc:
        # legacy: whole netloc is base64 of method:password@host:port
        try:
            decoded = b64_decode_pad(parts.netloc)
        except ValueError:
            return None
        cred, _, hostport_ = decoded.rpartition("@")
        host, port = split_netloc(hostport_)
        method, _, password = cred.partition(":")
        if not host:
            return None
        return Outbound(scheme="ss", name=name or f"{host}:{port}", host=host,
                        port=port or "443", credential=password,
                        ss_method=method, transport="tcp", raw=line.strip(),
                        extra={"plugin": params.get("plugin", "")})
    # SIP002: userinfo may be plain "method:password" or base64url of it
    method, password = "", ""
    if ":" in userinfo:
        method, password = userinfo.split(":", 1)
    else:
        try:
            cred = b64_decode_pad(userinfo)
            method, _, password = cred.partition(":")
        except ValueError:
            return None
    host, port = split_netloc(parts.netloc)
    if not host or not method:
        return None
    return Outbound(scheme="ss", name=name or f"{host}:{port}", host=host,
                    port=port or "443", credential=unquote(password),
                    ss_method=unquote(method), transport="tcp",
                    allow_insecure=False, raw=line.strip(),
                    extra={"plugin": params.get("plugin", "")},
                    extra_params=_unmodeled_params(parts.query))


def _parse_hysteria2(line: str, parts) -> Outbound | None:
    host, port = split_netloc(parts.netloc)
    if not host:
        return None
    params: dict[str, str] = {}
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        params.setdefault(k.lower(), v)
    password = unquote(parts.username or "") or parts.password or ""
    name = unquote(parts.fragment) or f"{host}:{port}"
    return Outbound(
        scheme="hysteria2", name=name, host=host, port=port or "443",
        credential=password,
        transport="udp", security="tls",
        sni=params.get("sni", "") or host,
        fingerprint=params.get("fp", "chrome"),
        allow_insecure=params.get("insecure", "0") in ("1", "true"),
        alpn="h3",
        extra={"obfs": params.get("obfs", ""),
               "obfs-password": params.get("obfs-password", ""),
               "up": params.get("up", ""), "down": params.get("down", "")},
        extra_params=_unmodeled_params(parts.query),
        raw=line.strip())


def _parse_tuic(line: str, parts) -> Outbound | None:
    host, port = split_netloc(parts.netloc)
    if not host:
        return None
    params: dict[str, str] = {}
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        params.setdefault(k.lower(), v)
    uuid_s = unquote(parts.username or "")
    password = unquote(parts.password or "") if parts.password else ""
    name = unquote(parts.fragment) or f"{host}:{port}"
    return Outbound(
        scheme="tuic", name=name, host=host, port=port or "443",
        credential=uuid_s,
        transport="udp", security="tls",
        sni=params.get("sni", "") or host,
        fingerprint=params.get("fp", "chrome"),
        allow_insecure=params.get("insecure", "0") in ("1", "true"),
        alpn=params.get("alpn", "h3"),
        extra={"password": password,
               "congestion_control": params.get("congestion_control", "bbr"),
               "udp_relay_mode": params.get("udp_relay_mode", "native")},
        extra_params=_unmodeled_params(parts.query),
        raw=line.strip())


# Query keys (lower-case) that some Outbound field models.  Everything else is
# kept in ``Outbound.extra_params`` and re-emitted by the handlers.
_MODELED_PARAMS = frozenset({
    "security", "sni", "host", "path", "type", "fp", "alpn", "servicename",
    "service_name", "headertype", "flow", "pbk", "sid", "spx", "allowinsecure",
    "insecure", "cs", "encryption", "mode", "plugin", "obfs", "obfs-password",
    "up", "down", "congestion_control", "udp_relay_mode",
})
_TRANSPORT_ALIASES = {"raw": "tcp", "splithttp": "xhttp"}


def _unmodeled_params(query: str, transport: str = "") -> dict[str, str]:
    """Query params no Outbound field models (first occurrence wins)."""
    kept: dict[str, str] = {}
    seen: set[str] = set()
    for k, v in parse_qsl(query, keep_blank_values=True):
        lk = k.lower()
        if lk in seen:
            continue
        seen.add(lk)
        if lk in _MODELED_PARAMS:
            if lk == "mode" and transport != "xhttp":
                pass                      # only modeled for xhttp
            elif lk == "encryption" and v.strip().lower() != "none":
                pass                      # VLESS encryption (mlkem...) is real data
            else:
                continue
        kept[k] = v
    return kept


def parse_target(line: str) -> Outbound | None:
    """Parse any supported share-link into an :class:`Outbound`.

    Returns ``None`` for lines that are not recognized proxy URIs.
    """
    line = (line or "").strip()
    if not line or "://" not in line:
        return None
    try:
        parts = urlsplit(line)
    except ValueError:
        return None
    scheme = parts.scheme.lower()

    if scheme == "vmess":
        if "@" in parts.netloc:
            # rare plain vmess URI — treat like vless-style netloc
            pass
        else:
            return vmess_json_to_outbound(line[len("vmess://"):], line)
    if scheme == "ss":
        return _parse_ss(line, parts)
    if scheme in ("hysteria2", "hy2"):
        return _parse_hysteria2(line, parts)
    if scheme == "tuic":
        return _parse_tuic(line, parts)
    if scheme in ("wireguard", "wg"):
        return None  # wireguard has no share-link form; built from accounts

    if scheme not in PROXY_SCHEMES or "@" not in parts.netloc:
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
    credential = unquote(parts.username or "")
    if parts.password:
        credential += ":" + unquote(parts.password)
    security = pd.get("security", "").lower()
    # Xray share-link spec: `type` defaults to tcp (a Reality link without it
    # is NOT a websocket); `raw` is the new name of tcp, `splithttp` of xhttp.
    transport = pd.get("type", "tcp").lower() or "tcp"
    transport = _TRANSPORT_ALIASES.get(transport, transport)
    return Outbound(
        name=name,
        scheme=scheme,
        host=host,
        port=port or "443",
        credential=credential,
        transport=transport,
        security="reality" if security == "reality" else security,
        sni=sni,
        host_header=hdr,
        path=path,
        fingerprint=pd.get("fp", "chrome"),
        alpn=pd.get("alpn", ""),
        service_name=pd.get("servicename", "") or pd.get("service_name", ""),
        header_type=pd.get("headertype", ""),
        flow=pd.get("flow", ""),
        public_key=pd.get("pbk", ""),
        short_id=pd.get("sid", ""),
        spider_x=pd.get("spx", ""),
        allow_insecure=pd.get("allowinsecure", "0") in ("1", "true"),
        extra={"cs": pd.get("cs", ""), "mode": pd.get("mode", "")},
        extra_params=_unmodeled_params(parts.query, transport),
        raw=line,
    )


# ===========================================================================
# Exporters: Clash Meta (Mihomo) / Sing-box / Subscription
# ===========================================================================

def _transport_fields(t: Outbound) -> dict[str, Any]:
    """Common transport fields used by both exporters."""
    tr = t.transport.lower()
    fields: dict[str, Any] = {}
    if tr == "ws":
        fields["network"] = "ws"
        fields["ws_path"] = t.path
        fields["ws_host"] = t.host_header
    elif tr == "grpc":
        fields["network"] = "grpc"
        fields["service_name"] = t.service_name
    elif tr == "httpupgrade":
        fields["network"] = "httpupgrade"
        fields["ws_path"] = t.path
        fields["ws_host"] = t.host_header
    elif tr == "xhttp":
        fields["network"] = "xhttp"
        fields["ws_path"] = t.path
        fields["ws_host"] = t.host_header
        fields["xhttp_mode"] = t.extra.get("mode", "auto")
    return fields


# Transports only Xray-core can run.  Rendering them for sing-box / Clash as
# plain TCP would silently produce a *different*, non-working proxy, so the
# exporters refuse (return None) and the cores report them as unsupported.
XRAY_ONLY_TRANSPORTS = frozenset({"xhttp", "kcp", "mkcp"})


def needs_xray(t: Outbound) -> bool:
    return (t.scheme in ("vless", "vmess", "trojan")
            and (t.transport or "").lower() in XRAY_ONLY_TRANSPORTS)


def out_to_clash(t: Outbound) -> dict[str, Any] | None:
    """One Clash Meta (Mihomo) proxy mapping from an Outbound.

    Returns None for transports Mihomo export does not implement (xhttp...).
    """
    if needs_xray(t):
        return None
    px: dict[str, Any] = {
        "name": t.name,
        "type": {"hysteria2": "hysteria2", "tuic": "tuic",
                 "wireguard": "wireguard"}.get(t.scheme, t.scheme),
        "server": t.host,
        "port": int(t.port) if str(t.port).isdigit() else 443,
    }
    tr = _transport_fields(t)
    if t.scheme == "vless":
        px["uuid"] = t.credential
        px["cipher"] = "none" if t.security == "reality" else "auto"
        if t.flow:
            px["flow"] = t.flow
    elif t.scheme == "vmess":
        px["uuid"] = t.credential
        px["alterId"] = int(t.alter_id) if str(t.alter_id).isdigit() else 0
        px["cipher"] = t.encryption or "auto"
    elif t.scheme == "trojan":
        px["password"] = t.credential
    elif t.scheme == "ss":
        method, password = t.ss_split()
        px["cipher"] = method
        px["password"] = password
        if t.extra.get("plugin"):
            px["plugin"] = t.extra["plugin"]
        return px  # ss has no transport/tls section
    elif t.scheme == "hysteria2":
        px["password"] = t.credential
        px["up"] = t.extra.get("up", "") or "50 Mbps"
        px["down"] = t.extra.get("down", "") or "100 Mbps"
        if t.extra.get("obfs"):
            px["obfs"] = t.extra["obfs"]
            if t.extra.get("obfs-password"):
                px["obfs-password"] = t.extra["obfs-password"]
    elif t.scheme == "tuic":
        px["uuid"] = t.credential
        px["password"] = t.extra.get("password", "")
        px["congestion-controller"] = t.extra.get("congestion_control", "bbr")
        px["udp-relay-mode"] = t.extra.get("udp_relay_mode", "native")
    elif t.scheme == "wireguard":
        ex = t.extra
        px["private-key"] = ex.get("private_key", "")
        px["public-key"] = ex.get("peer_public_key", "")
        px["ip"] = (ex.get("ipv4") or "172.16.0.2").split("/")[0]
        px["ipv6"] = (ex.get("ipv6") or "").split("/")[0] or None
        px["mtu"] = int(ex.get("mtu", 1280))
        if ex.get("reserved"):
            px["reserved"] = ex["reserved"]
        px = {k: v for k, v in px.items() if v not in (None, "")}
        return px
    else:
        return None

    if t.security in ("tls", "reality"):
        px["tls"] = True
        px["servername"] = t.sni or t.host
        px["client-fingerprint"] = t.fingerprint or "chrome"
        px["skip-cert-verify"] = t.allow_insecure
        if t.security == "reality":
            ro: dict[str, str] = {}
            if t.public_key:
                ro["public-key"] = t.public_key
            if t.short_id:
                ro["short-id"] = t.short_id
            px["reality-opts"] = ro
        if t.alpn:
            px["alpn"] = [a.strip() for a in t.alpn.split(",") if a.strip()]
    elif t.scheme in ("hysteria2", "tuic"):
        px["sni"] = t.sni or t.host
        px["skip-cert-verify"] = t.allow_insecure

    if tr.get("network") == "ws":
        px["network"] = "ws"
        px["ws-opts"] = {"path": tr["ws_path"], "headers": {"Host": tr["ws_host"]}}
    elif tr.get("network") == "grpc":
        px["network"] = "grpc"
        px["grpc-opts"] = {"grpc-service-name": tr["service_name"]}
    elif tr.get("network") == "httpupgrade":
        px["network"] = "httpupgrade"
        px["httpupgrade-opts"] = {"path": tr["ws_path"], "host": tr["ws_host"]}
    # xhttp is xray-only: no clash transport emitted
    return px


def out_to_singbox(t: Outbound) -> dict[str, Any] | None:
    """One sing-box outbound mapping from an Outbound.

    Returns None for Xray-only transports (xhttp, kcp).
    """
    if needs_xray(t):
        return None
    ob: dict[str, Any] = {
        "tag": t.name,
        "type": t.scheme,
        "server": t.host,
        "server_port": int(t.port) if str(t.port).isdigit() else 443,
    }
    tr = _transport_fields(t)
    if t.scheme == "vless":
        ob["uuid"] = t.credential
        if t.flow:
            ob["flow"] = t.flow
    elif t.scheme == "vmess":
        ob["uuid"] = t.credential
        ob["alter_id"] = int(t.alter_id) if str(t.alter_id).isdigit() else 0
        ob["security"] = t.encryption or "auto"
    elif t.scheme == "trojan":
        ob["password"] = t.credential
    elif t.scheme == "ss":
        method, password = t.ss_split()
        ob["method"] = method
        ob["password"] = password
        return ob
    elif t.scheme == "hysteria2":
        ob["password"] = t.credential
        if t.extra.get("obfs"):
            ob["obfs"] = {"type": t.extra["obfs"],
                          "password": t.extra.get("obfs-password", "")}
    elif t.scheme == "tuic":
        ob["uuid"] = t.credential
        ob["password"] = t.extra.get("password", "")
        ob["congestion_control"] = t.extra.get("congestion_control", "bbr")
        ob["udp_relay_mode"] = t.extra.get("udp_relay_mode", "native")
    elif t.scheme == "wireguard":
        ex = t.extra
        ob["type"] = "wireguard"
        ob["local_address"] = [a for a in (ex.get("ipv4"), ex.get("ipv6")) if a]
        ob["private_key"] = ex.get("private_key", "")
        ob["peer_public_key"] = ex.get("peer_public_key", "")
        if ex.get("reserved"):
            ob["reserved"] = ex["reserved"]
        ob["mtu"] = int(ex.get("mtu", 1280))
        ob["local_address"] = [a for a in ob["local_address"] if a] or ["172.16.0.2/32"]
        return ob
    else:
        return None

    if t.security in ("tls", "reality"):
        tls: dict[str, Any] = {
            "enabled": True,
            "server_name": t.sni or t.host,
            "insecure": t.allow_insecure,
        }
        if t.security == "reality":
            tls["reality"] = {"enabled": True}
            if t.public_key:
                tls["reality"]["public_key"] = t.public_key
            if t.short_id:
                tls["reality"]["short_id"] = t.short_id
        else:
            tls["utls"] = {"enabled": True,
                           "fingerprint": t.fingerprint or "chrome"}
        if t.alpn:
            tls["alpn"] = [a.strip() for a in t.alpn.split(",") if a.strip()]
        ob["tls"] = tls
    elif t.scheme in ("hysteria2", "tuic"):
        ob["tls"] = {"enabled": True, "server_name": t.sni or t.host,
                     "insecure": t.allow_insecure}

    if tr.get("network") == "ws":
        ob["transport"] = {"type": "ws", "path": tr["ws_path"],
                           "headers": {"Host": tr["ws_host"]}}
    elif tr.get("network") == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": tr["service_name"]}
    elif tr.get("network") == "httpupgrade":
        ob["transport"] = {"type": "httpupgrade", "path": tr["ws_path"],
                           "host": tr["ws_host"]}
    return ob


def export_to_clash(lines: list[str] | list[Outbound]) -> str:
    """Export proxy lines/outbounds to Clash Meta (Mihomo) YAML format."""
    proxies: list[dict[str, Any]] = []
    for item in lines:
        t = item if isinstance(item, Outbound) else parse_target(item)
        if not t:
            continue
        px = out_to_clash(t)
        if px:
            proxies.append(px)
    try:
        import yaml
    except ImportError:
        # Minimal fallback (no PyYAML available): JSON flow-style YAML.
        out = ["proxies:"]
        for p in proxies:
            out.append("  - " + json.dumps(p, ensure_ascii=False))
        return "\n".join(out)
    return yaml.dump({"proxies": proxies}, sort_keys=False, allow_unicode=True)


def export_to_singbox(lines: list[str] | list[Outbound]) -> str:
    """Export proxy lines/outbounds to Sing-box outbounds format."""
    outbounds: list[dict[str, Any]] = []
    for item in lines:
        t = item if isinstance(item, Outbound) else parse_target(item)
        if not t:
            continue
        ob = out_to_singbox(t)
        if ob:
            outbounds.append(ob)
    return json.dumps({"outbounds": outbounds}, indent=2, ensure_ascii=False)


def export_to_sub(lines: list[str]) -> str:
    """Export configs to Base64 standard subscription."""
    raw = "\n".join(line.strip() for line in lines if line.strip())
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")
