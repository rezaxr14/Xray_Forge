"""
Remote subscription fetcher and multi-format decoder.

Understands:
* base64-encoded subscriptions (the classic form)
* plain-text lists of share links
* Clash / Clash.Meta YAML (``proxies:``) — converted back to share links
* sing-box JSON (``outbounds:``) — converted back to share links

The URI conversions go through the protocol registry, so every registered
protocol round-trips.
"""

from __future__ import annotations

import base64
import json
import re

from xray_forge.core.probe import direct_get_json, ProbeError
from xray_forge.core.models import Outbound
from xray_forge.core.protocols import handler_for

JSON_SUFFIX = ".json"


def is_base64_config(text: str) -> bool:
    """Heuristic: text looks like a base64-encoded subscription."""
    stripped = text.strip()
    if not stripped:
        return False
    # Remove whitespace/newlines
    compact = re.sub(r"\s+", "", stripped)
    if len(compact) < 16:
        return False
    # Must be valid base64 alphabet
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return False
    # Try decode — if it yields proxy:// URIs, treat as base64 sub
    try:
        padded = compact + "=" * (-len(compact) % 4)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8", "replace")
    except Exception:
        return False
    return any(
        decoded.startswith(scheme + "://")
        for scheme in ("vless", "trojan", "vmess", "ss", "socks", "http", "hysteria2", "tuic")
    ) or "vless://" in decoded or "trojan://" in decoded


def decode_subscription(text: str) -> list[str]:
    """Decode a subscription text (base64 or plain) into config lines."""
    text = text.strip()
    if not text:
        return []
    if is_base64_config(text):
        compact = re.sub(r"\s+", "", text)
        padded = compact + "=" * (-len(compact) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode("utf-8", "replace")
        except Exception:
            decoded = text
    else:
        decoded = text
    lines: list[str] = []
    for raw in decoded.splitlines():
        line = raw.strip()
        if line and ("://" in line):
            lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# Clash / sing-box -> share links (via protocol registry)
# ---------------------------------------------------------------------------

def _clash_proxy_to_uri(px: dict) -> str | None:
    ptype = str(px.get("type", "")).lower()
    name = str(px.get("name", ""))
    server = str(px.get("server", ""))
    port = str(px.get("port", ""))
    if not server or not port.isdigit():
        return None
    transport = str(px.get("network", "")).lower()
    common = {
        "security": "tls" if px.get("tls") else "",
        "sni": str(px.get("servername") or px.get("sni") or ""),
        "fingerprint": str(px.get("client-fingerprint") or "chrome"),
        "alpn": ",".join(px["alpn"]) if isinstance(px.get("alpn"), list) else "",
    }
    ro = px.get("reality-opts") or {}
    if ro.get("public-key"):
        common["security"] = "reality"
    ws_opts = px.get("ws-opts") or {}
    httpup_opts = px.get("httpupgrade-opts") or {}
    grpc_opts = px.get("grpc-opts") or {}
    path = str(ws_opts.get("path") or httpup_opts.get("path") or "")
    host = ""
    if isinstance(ws_opts.get("headers"), dict):
        host = str(ws_opts["headers"].get("Host") or "")
    host = host or str(httpup_opts.get("host") or "")

    if ptype == "vless":
        h = handler_for("vless")
        out = Outbound(scheme="vless", name=name, host=server, port=port,
                       credential=str(px.get("uuid", "")),
                       transport=transport or "tcp", **common)
        if ro.get("public-key"):
            out.public_key = str(ro["public-key"])
            out.short_id = str(ro.get("short-id", ""))
        if px.get("flow"):
            out.flow = str(px["flow"])
        if transport in ("ws", "httpupgrade"):
            out.path, out.host_header = path or "/", host
        if transport == "grpc":
            out.service_name = str(grpc_opts.get("grpc-service-name", ""))
        return h.to_uri(out) if h else None
    if ptype == "trojan":
        h = handler_for("trojan")
        out = Outbound(scheme="trojan", name=name, host=server, port=port,
                       credential=str(px.get("password", "")),
                       transport=transport or "tcp", **common)
        if ro.get("public-key"):
            out.public_key = str(ro["public-key"])
            out.short_id = str(ro.get("short-id", ""))
        if transport in ("ws", "httpupgrade"):
            out.path, out.host_header = path or "/", host
        if transport == "grpc":
            out.service_name = str(grpc_opts.get("grpc-service-name", ""))
        return h.to_uri(out) if h else None
    if ptype == "vmess":
        h = handler_for("vmess")
        out = Outbound(scheme="vmess", name=name, host=server, port=port,
                       credential=str(px.get("uuid", "")),
                       transport=transport or "tcp",
                       encryption=str(px.get("cipher", "auto")),
                       alter_id=str(px.get("alterId", 0)), **common)
        if transport in ("ws", "httpupgrade"):
            out.path, out.host_header = path or "/", host
        if transport == "grpc":
            out.service_name = str(grpc_opts.get("grpc-service-name", ""))
        return h.to_uri(out) if h else None
    if ptype == "ss":
        h = handler_for("ss")
        out = Outbound(scheme="ss", name=name, host=server, port=port,
                       credential=f"{px.get('cipher', 'aes-256-gcm')}:{px.get('password', '')}",
                       ss_method=str(px.get("cipher", "")),
                       transport="tcp",
                       extra={"plugin": str(px.get("plugin", ""))})
        return h.to_uri(out) if h else None
    if ptype == "hysteria2":
        h = handler_for("hysteria2")
        out = Outbound(scheme="hysteria2", name=name, host=server, port=port,
                       credential=str(px.get("password", "")),
                       transport="udp", security="tls",
                       sni=str(px.get("sni") or server),
                       allow_insecure=bool(px.get("skip-cert-verify")),
                       extra={"obfs": str(px.get("obfs", "")),
                              "obfs-password": str(px.get("obfs-password", "")),
                              "up": str(px.get("up", "")),
                              "down": str(px.get("down", ""))})
        return h.to_uri(out) if h else None
    if ptype == "tuic":
        h = handler_for("tuic")
        out = Outbound(scheme="tuic", name=name, host=server, port=port,
                       credential=str(px.get("uuid", "")),
                       transport="udp", security="tls",
                       sni=str(px.get("sni") or server),
                       allow_insecure=bool(px.get("skip-cert-verify")),
                       extra={"password": str(px.get("password", "")),
                              "congestion_control": str(px.get("congestion-controller", "bbr")),
                              "udp_relay_mode": str(px.get("udp-relay-mode", "native"))})
        return h.to_uri(out) if h else None
    return None


def _singbox_outbound_to_uri(ob: dict) -> str | None:
    otype = str(ob.get("type", "")).lower()
    name = str(ob.get("tag", ""))
    server = str(ob.get("server", ""))
    port = str(ob.get("server_port", ""))
    if not server or not str(port).isdigit():
        return None
    tls = ob.get("tls") or {}
    transport = (ob.get("transport") or {})
    tr_type = str(transport.get("type", "")).lower()
    common = {
        "security": "reality" if tls.get("reality", {}).get("enabled") else
                    ("tls" if tls.get("enabled") else ""),
        "sni": str(tls.get("server_name") or ""),
        "fingerprint": str((tls.get("utls") or {}).get("fingerprint") or "chrome"),
        "alpn": ",".join(tls["alpn"]) if isinstance(tls.get("alpn"), list) else "",
    }
    reality = tls.get("reality") or {}
    path = str(transport.get("path", ""))
    host = ""
    if isinstance(transport.get("headers"), dict):
        host = str(transport["headers"].get("Host") or "")
    host = host or str(transport.get("host") or "")

    if otype == "vless":
        h = handler_for("vless")
        out = Outbound(scheme="vless", name=name, host=server, port=port,
                       credential=str(ob.get("uuid", "")),
                       transport=tr_type or "tcp", **common)
        out.flow = str(ob.get("flow", ""))
        if reality.get("enabled"):
            out.public_key = str(reality.get("public_key", ""))
            out.short_id = str(reality.get("short_id", ""))
        if tr_type in ("ws", "httpupgrade"):
            out.path, out.host_header = path or "/", host
        if tr_type == "grpc":
            out.service_name = str(transport.get("service_name", ""))
        return h.to_uri(out) if h else None
    if otype == "trojan":
        h = handler_for("trojan")
        out = Outbound(scheme="trojan", name=name, host=server, port=port,
                       credential=str(ob.get("password", "")),
                       transport=tr_type or "tcp", **common)
        if reality.get("enabled"):
            out.public_key = str(reality.get("public_key", ""))
            out.short_id = str(reality.get("short_id", ""))
        if tr_type in ("ws", "httpupgrade"):
            out.path, out.host_header = path or "/", host
        if tr_type == "grpc":
            out.service_name = str(transport.get("service_name", ""))
        return h.to_uri(out) if h else None
    if otype == "vmess":
        h = handler_for("vmess")
        out = Outbound(scheme="vmess", name=name, host=server, port=port,
                       credential=str(ob.get("uuid", "")),
                       transport=tr_type or "tcp",
                       encryption=str(ob.get("security", "auto")),
                       alter_id=str(ob.get("alter_id", 0)), **common)
        if tr_type in ("ws", "httpupgrade"):
            out.path, out.host_header = path or "/", host
        if tr_type == "grpc":
            out.service_name = str(transport.get("service_name", ""))
        return h.to_uri(out) if h else None
    if otype == "ss":
        h = handler_for("ss")
        out = Outbound(scheme="ss", name=name, host=server, port=port,
                       credential=f"{ob.get('method', 'aes-256-gcm')}:{ob.get('password', '')}",
                       ss_method=str(ob.get("method", "")), transport="tcp")
        return h.to_uri(out) if h else None
    if otype == "hysteria2":
        h = handler_for("hysteria2")
        obfs = ob.get("obfs") or {}
        out = Outbound(scheme="hysteria2", name=name, host=server, port=port,
                       credential=str(ob.get("password", "")),
                       transport="udp", security="tls",
                       sni=str(tls.get("server_name") or server),
                       allow_insecure=bool(tls.get("insecure")),
                       extra={"obfs": str(obfs.get("type", "")),
                              "obfs-password": str(obfs.get("password", ""))})
        return h.to_uri(out) if h else None
    if otype == "tuic":
        h = handler_for("tuic")
        out = Outbound(scheme="tuic", name=name, host=server, port=port,
                       credential=str(ob.get("uuid", "")),
                       transport="udp", security="tls",
                       sni=str(tls.get("server_name") or server),
                       allow_insecure=bool(tls.get("insecure")),
                       extra={"password": str(ob.get("password", "")),
                              "congestion_control": str(ob.get("congestion_control", "bbr")),
                              "udp_relay_mode": str(ob.get("udp_relay_mode", "native"))})
        return h.to_uri(out) if h else None
    return None


def sniff_format(text: str) -> str:
    """Classify subscription text: base64 | plain | clash | singbox."""
    stripped = text.strip()
    if not stripped:
        return "plain"
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return "plain"
        if isinstance(data, dict) and ("outbounds" in data or "inbounds" in data):
            return "singbox"
        return "plain"
    if ("proxies:" in stripped and ("- name" in stripped or "- {" in stripped)) \
            or stripped.startswith("proxies:"):
        return "clash"
    if is_base64_config(stripped):
        return "base64"
    return "plain"


def text_to_lines(text: str) -> list[str]:
    """Any supported format -> list of share-link lines."""
    fmt = sniff_format(text)
    if fmt == "clash":
        try:
            import yaml
            data = yaml.safe_load(text)
        except Exception:
            return []
        if not isinstance(data, dict):
            return []
        out: list[str] = []
        for px in data.get("proxies") or []:
            if isinstance(px, dict):
                uri = _clash_proxy_to_uri(px)
                if uri:
                    out.append(uri)
        return out
    if fmt == "singbox":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        out = []
        for ob in data.get("outbounds") or []:
            if isinstance(ob, dict) and ob.get("type") not in ("direct", "block", "dns", "selector", "urltest"):
                uri = _singbox_outbound_to_uri(ob)
                if uri:
                    out.append(uri)
        return out
    return decode_subscription(text)


def fetch_subscription(url: str, timeout: float = 10.0) -> list[str]:
    """Fetch a subscription URL and return decoded config lines (any format)."""
    try:
        # Try anti-DPI direct fetch first
        data = direct_get_json(url, timeout=timeout)
        text = data if isinstance(data, str) else str(data)
    except Exception:
        try:
            import urllib.request
            req = urllib.request.Request(
                url, headers={"User-Agent": "vless-forge/2.0-subscriber"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                text = r.read().decode("utf-8", "replace")
        except Exception as e:
            raise ProbeError("sub", f"cannot fetch subscription: {e}")
    return text_to_lines(text)
