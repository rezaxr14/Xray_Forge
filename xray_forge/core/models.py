"""
Typed outbound model — the single representation of a proxy config.

``Outbound`` replaces the plain dict that ``parse_target`` used to return.
Every protocol handler (``core/protocols/``) and every core adapter
(``core/cores/``) consumes and produces ``Outbound`` objects.

Backwards compatibility: the legacy code (tester/scanner/xray bridge, tabs)
still uses dict-style access such as ``t["uuid"]`` or ``t.get("sni")``.
``Outbound`` implements ``__getitem__`` / ``get`` / ``__contains__`` with the
old key names mapped onto dataclass fields, so existing call-sites keep
working unchanged.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field, asdict


# Legacy dict key -> (attribute, needs_transformation)
_LEGACY_ALIASES: dict[str, tuple[str, object]] = {
    "uuid": ("credential", None),
    "hdr": ("host_header", None),
    "type": ("transport", None),
    "fp": ("fingerprint", None),
}


@dataclass
class Outbound:
    """One proxy configuration, protocol-agnostic.

    ``credential`` holds whatever the scheme authenticates with:
    a UUID (vless/vmess), a password (trojan/hysteria2), ``uuid:password``
    (tuic) or ``method:password`` (shadowsocks — see ``ss_method``).
    """

    scheme: str = "vless"
    name: str = ""
    host: str = ""
    port: str = "443"
    credential: str = ""

    transport: str = "tcp"      # tcp / ws / grpc / httpupgrade / xhttp
    security: str = ""          # "" / "none" / "tls" / "reality"
    sni: str = ""
    host_header: str = ""       # ws/httpupgrade Host header (camouflage)
    path: str = "/"
    fingerprint: str = "chrome"
    alpn: str = ""
    service_name: str = ""      # grpc serviceName
    header_type: str = ""       # tcp header obfs ("http"…)

    # Reality (vless/trojan)
    public_key: str = ""        # pbk=
    short_id: str = ""          # sid=
    spider_x: str = ""          # spx=
    flow: str = ""              # e.g. xtls-rprx-vision
    allow_insecure: bool = False

    # Shadowsocks
    ss_method: str = ""         # aes-256-gcm, chacha20-ietf-poly1305, …

    # VMess
    alter_id: str = "0"
    encryption: str = "none"    # scy= (auto/none/aes-128-gcm/chacha20-poly1305)

    # WireGuard / WARP (kept in ``extra`` by the wireguard handler)
    extra: dict = field(default_factory=dict)

    # Share-link query parameters (vmess: JSON keys) that no field above
    # models -- ech, pcs, vcn, pqv, extra (XHTTP), fm, authority, ... --
    # kept verbatim so parse -> edit -> to_uri never silently drops them.
    extra_params: dict = field(default_factory=dict)

    raw: str = ""

    # ------------------------------------------------------------ legacy API
    def __getitem__(self, key: str):
        if key in _LEGACY_ALIASES:
            attr, _ = _LEGACY_ALIASES[key]
            return getattr(self, attr)
        if hasattr(self, key):
            return getattr(self, key)
        if key in self.extra:
            return self.extra[key]
        raise KeyError(key)

    def get(self, key: str, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: str) -> bool:
        try:
            self[key]
            return True
        except KeyError:
            return False

    # ------------------------------------------------------------- helpers
    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def effective_sni(self) -> str:
        """SNI actually presented in the TLS hello."""
        return self.sni or self.host_header or self.host

    def is_tls(self) -> bool:
        return self.security.lower() in ("tls", "reality")

    def is_reality(self) -> bool:
        return self.security.lower() == "reality"

    def ss_split(self) -> tuple[str, str]:
        """Return (method, password) for shadowsocks outbounds.

        Contract: ``credential`` holds the password; ``ss_method`` the method.
        Tolerates legacy outbounds where credential is still "method:password".
        """
        cred = self.credential
        if self.ss_method:
            if cred.startswith(self.ss_method + ":"):
                return self.ss_method, cred.partition(":")[2]
            return self.ss_method, cred
        if ":" in cred:
            method, _, password = cred.partition(":")
            return method, password
        return "aes-256-gcm", cred

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Outbound":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def copy_with(self, **changes) -> "Outbound":
        data = self.to_dict()
        data.update(changes)
        return Outbound.from_dict(data)


def b64_decode_pad(text: str) -> str:
    """Base64 (url-safe or standard, padded or not) -> str. Raises ValueError."""
    compact = "".join(text.split())
    compact = compact.replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    return base64.b64decode(compact, validate=True).decode("utf-8", "replace")


def b64_encode(text: str, urlsafe: bool = False) -> str:
    raw = text.encode("utf-8")
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return enc(raw).decode("ascii")


_VMESS_MODELED = frozenset({
    "v", "ps", "add", "port", "id", "aid", "scy", "security", "net", "type",
    "host", "path", "tls", "sni", "alpn", "fp"})


def vmess_json_to_outbound(payload: str, raw_line: str = "") -> Outbound | None:
    """Parse a vmess://<base64 json> link."""
    try:
        data = json.loads(b64_decode_pad(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not data.get("add"):
        return None
    return Outbound(
        extra_params={k: v for k, v in data.items()
                      if k not in _VMESS_MODELED and v not in (None, "")},
        scheme="vmess",
        name=str(data.get("ps") or "vmess"),
        host=str(data.get("add") or ""),
        port=str(data.get("port") or "443"),
        credential=str(data.get("id") or ""),
        transport=str(data.get("net") or "tcp").lower(),
        security="tls" if str(data.get("tls", "")).lower() == "tls" else "",
        sni=str(data.get("sni") or ""),
        host_header=str(data.get("host") or ""),
        path=str(data.get("path") or "/"),
        fingerprint=str(data.get("fp") or "chrome"),
        alpn=str(data.get("alpn") or ""),
        header_type=str(data.get("type") or ""),
        alter_id=str(data.get("aid") or "0"),
        encryption=str(data.get("scy") or data.get("security") or "auto"),
        raw=raw_line,
    )
