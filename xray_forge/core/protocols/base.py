"""
Protocol handler abstraction and shared per-core stream builders.

Every protocol (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC,
WireGuard/WARP, …) is implemented as a :class:`ProtocolHandler` registered in
``xray_forge.core.protocols``.  Handlers know how to

* parse a share-link into an :class:`~xray_forge.core.models.Outbound`
* render the Outbound back to a share-link (``to_uri``)
* render it as an outbound object for each supported core
  (``xray_outbound`` / ``singbox_outbound`` / ``clash_proxy`` — returning
  ``None`` means "this core cannot run this protocol")

The core adapters in ``core/cores/`` derive their supported-protocol list from
these renderers, so the UI can offer exactly what the chosen core can run.
"""

from __future__ import annotations

from typing import Any

from xray_forge.core.config import IPV4_RE
from xray_forge.core.models import Outbound
from xray_forge.core.parser import out_to_clash, out_to_singbox, parse_target


class ProtocolHandler:
    """Base class for one proxy protocol."""

    name: str = ""                 # short id, e.g. "vless"
    label: str = ""                # human label
    schemes: tuple[str, ...] = ()  # uri schemes handled
    default_transport: str = "tcp"

    # ----------------------------------------------------------- parsing
    def parse(self, line: str) -> Outbound | None:
        out = parse_target(line)
        if out and out.scheme in self.schemes:
            return out
        return None

    # -------------------------------------------------------- share links
    def to_uri(self, out: Outbound) -> str:
        raise NotImplementedError(f"{type(self).__name__}.to_uri")

    # ------------------------------------------------------------ cores
    def xray_outbound(self, out: Outbound) -> dict[str, Any] | None:
        return None

    def singbox_outbound(self, out: Outbound) -> dict[str, Any] | None:
        return out_to_singbox(out)

    def clash_proxy(self, out: Outbound) -> dict[str, Any] | None:
        return out_to_clash(out)

    # -------------------------------------------------------- metadata
    def supports_core(self, core_name: str) -> bool:
        """Capability probe using a minimal dummy Outbound."""
        dummy = Outbound(scheme=self.schemes[0], name="probe", host="127.0.0.1",
                         port="443", credential="x")
        try:
            if core_name == "xray":
                return self.xray_outbound(dummy) is not None
            if core_name == "singbox":
                return self.singbox_outbound(dummy) is not None
            if core_name in ("mihomo", "clash"):
                return self.clash_proxy(dummy) is not None
        except Exception:
            return False
        return False


# ===========================================================================
# Shared Xray streamSettings builder (transport + security layers)
# ===========================================================================

def xray_transport_settings(out: Outbound) -> dict[str, Any]:
    """Transport section of an Xray streamSettings for ``out``."""
    tr = out.transport.lower()
    stream: dict[str, Any] = {"network": tr or "tcp"}
    if tr == "ws":
        stream["wsSettings"] = {"path": out.path,
                                "headers": {"Host": out.host_header}}
    elif tr == "grpc":
        stream["grpcSettings"] = {"serviceName": out.service_name}
    elif tr == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": out.path, "host": out.host_header}
    elif tr == "xhttp":
        xs: dict[str, Any] = {"path": out.path}
        if out.host_header:
            xs["host"] = out.host_header
        if out.extra.get("mode"):
            xs["mode"] = out.extra["mode"]
        stream["xhttpSettings"] = xs
    else:  # raw tcp
        stream["network"] = "tcp"
        if out.header_type:
            stream["tcpSettings"] = {"header": {"type": out.header_type}}
    return stream


def xray_security_settings(out: Outbound, front_domain: str | None = None) -> dict[str, Any]:
    """Security (tls/reality) section of an Xray streamSettings for ``out``."""
    sec = (out.security or "").lower()
    stream: dict[str, Any] = {"security": sec if sec in ("tls", "reality") else "none"}
    fp = out.fingerprint or "chrome"
    if sec == "reality":
        rs: dict[str, Any] = {"show": False, "fingerprint": fp}
        sni = out.sni or out.host_header
        if sni and not IPV4_RE.match(sni):
            rs["serverName"] = sni
        if out.public_key:
            rs["publicKey"] = out.public_key
        if out.short_id:
            rs["shortId"] = out.short_id
        if out.spider_x:
            rs["spiderX"] = out.spider_x
        stream["realitySettings"] = rs
    elif sec == "tls":
        ts: dict[str, Any] = {"allowInsecure": out.allow_insecure, "fingerprint": fp}
        sni = out.sni or out.host_header
        if sni and not IPV4_RE.match(sni):
            ts["serverName"] = sni
        cs = out.extra.get("cs")
        if cs:
            ts["cipherSuites"] = cs
        if out.alpn:
            ts["alpn"] = [a.strip() for a in out.alpn.split(",") if a.strip()]
        if front_domain:
            # MMDF-style domain fronting: front SNI in the hello, real Host inside
            ts["serverName"] = front_domain
        stream["tlsSettings"] = ts
    return stream


def xray_stream(out: Outbound, frag_on: bool = False,
                front_domain: str | None = None) -> dict[str, Any]:
    stream = xray_transport_settings(out)
    stream.update(xray_security_settings(out, front_domain))
    if frag_on and out.is_tls():
        stream["sockopt"] = {"dialerProxy": "frag"}
    return stream


# ===========================================================================
# Shared URI helpers
# ===========================================================================

def hostport(out: Outbound) -> str:
    host = f"[{out.host}]" if ":" in out.host and not out.host.startswith("[") else out.host
    return f"{host}:{out.port or '443'}"


def userinfo_password(out: Outbound) -> str:
    from urllib.parse import quote
    cred = out.credential
    if ":" in cred and out.scheme not in ("tuic",):
        # only the part before the first ':' is the username for cred:pass schemes
        user, _, pwd = cred.partition(":")
        return f"{quote(user, safe='')}:{quote(pwd, safe='')}"
    return quote(cred, safe="")
