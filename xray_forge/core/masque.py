"""MASQUE (Cloudflare WARP over HTTP/3) through the opt-in sing-box-extended fork.

Why a fork: official sing-box, Xray-core and mihomo have no MASQUE outbound
(docs/spikes-masque-psiphon.md).  The ``shtorm-7/sing-box-extended`` fork
documents one; its example client config (``examples/masque/client.json``) is
the only source of the schema used here.  The fork creates the Cloudflare
device profile itself when ``profile.id`` is empty, so Xray Forge does no
enrollment of its own.

What this module does and does not prove: it builds that documented config,
asks the fork's own ``check`` command whether the binary knows the ``masque``
outbound, and can run it and fetch a page through the local SOCKS port.  It has
not been run against a real fork binary or Cloudflare in the project's tests.

The profile ``auth_token`` and ``license_key`` are credentials: they are kept
out of ``repr()``, redacted by :func:`redact`, and only ever written to a
0600 temp file that is deleted after use.
"""

from __future__ import annotations

import copy
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field, fields
from typing import Any

from xray_forge.core.cores.base import CoreAdapter, _free_port, run_socks_probe
from xray_forge.core.log import get_logger
from xray_forge.core.parser import classify_endpoint

log = get_logger(__name__)

TAG = "masque-out"
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_CC_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_NO_MASQUE = re.compile(r"unknown outbound type:?\s*\"?masque|masque.{0,40}(unknown|not (supported|included|found))", re.I)
NEEDS_FORK = ("this sing-box build has no MASQUE outbound (masque); "
              "use the sing-box-extended fork")


DNS_MODES = ("auto", "system", "doh")
# IP literals: the resolver must not itself need resolving.  Google first: 1.1.1.1:443 is
# blackholed on some networks and the core does not fall through to the next server.
DOH_SERVERS = ("8.8.8.8", "1.1.1.1")
FAKE_IP_PROBES = ("api.cloudflareclient.com", "cloudflare.com", "example.com")   # first = what the core dials


def system_dns_is_fake() -> bool:
    """True when the system resolver answers with fake-IP addresses (198.18.0.0/15),
    as TUN-mode proxies do (or loopback / reserved ones); a core that resolves that way connects to dead addresses."""
    import ipaddress
    import socket
    # fake-IP ranges: the usual 198.18.0.0/15, loopback (some resolvers answer 127.x) and 240.0.0.0/4 (reserved)
    nets = [ipaddress.ip_network(n) for n in ("198.18.0.0/15", "127.0.0.0/8", "240.0.0.0/4")]
    for name in FAKE_IP_PROBES:               # split DNS can answer some names for real and others fake
        try:
            infos = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            continue
        if any(any(ipaddress.ip_address(i[4][0]) in n for n in nets) for i in infos):
            return True
    return False


def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False
    return True


def _dns_servers(mode: str, doh: tuple[str, ...] = DOH_SERVERS) -> list[dict[str, Any]]:
    if mode == "auto":
        mode = "doh" if system_dns_is_fake() else "system"
    if mode == "system":
        return [{"type": "local", "tag": "default"}]
    return [{"type": "https", "tag": "default" if i == 0 else f"doh{i}", "server": ip, "server_port": 443}
            for i, ip in enumerate(doh)]


def _bool(v: Any, what: str) -> bool:
    if not isinstance(v, bool):
        raise ValueError(f"{what} must be true or false")
    return v


def _text(v: Any, what: str, limit: int = 256) -> str:
    if not isinstance(v, str) or len(v) > limit or any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise ValueError(f"{what} must be text of at most {limit} characters without control characters")
    return v


@dataclass(frozen=True)
class MasqueOptions:
    use_http2: bool = False
    use_l4_proxy: bool = False          # TCP-only CONNECT proxy instead of a CONNECT-IP tunnel
    use_ipv6: bool = False
    address: str = ""                   # override the endpoint Cloudflare returns
    port: int = 0
    server_name: str = ""               # TLS SNI; empty = the fork's default
    insecure: bool = False
    fragment: bool = False
    record_fragment: bool = False
    congestion_controller: str = "bbr"
    dns: str = "auto"                   # "system" | "doh" (IP-literal DoH) | "auto" (doh only if the resolver is fake-IP)
    doh_servers: tuple = DOH_SERVERS    # IP literals used by dns="doh" (and "auto" on fake-IP resolvers)
    bind_interface: bool = False        # route.auto_detect_interface; broke HTTP/2 on a TUN machine, so opt-in
    profile_id: str = ""                # an existing device profile; empty = the fork creates one
    auth_token: str = field(default="", repr=False)
    license_key: str = field(default="", repr=False)

    def validate(self) -> "MasqueOptions":
        if (not isinstance(self.doh_servers, tuple) or not 1 <= len(self.doh_servers) <= 4
                or not all(isinstance(s, str) and _is_ip(s) for s in self.doh_servers)):
            raise ValueError("doh_servers must be 1 to 4 IP addresses (IP literals, not host names)")
        if self.dns not in DNS_MODES:
            raise ValueError("dns must be one of: " + ", ".join(DNS_MODES))
        for name in ("use_http2", "use_l4_proxy", "use_ipv6", "insecure", "fragment", "record_fragment", "bind_interface"):
            _bool(getattr(self, name), name)
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 0 <= self.port <= 65535:
            raise ValueError("port must be 0 (default) or 1..65535")
        if not isinstance(self.address, str) or len(self.address) > 253 or (
                self.address and classify_endpoint(self.address) is None):
            raise ValueError("address must be an IPv4/IPv6 address or a host name")
        if self.port and not self.address:
            raise ValueError("port needs an address")
        if not isinstance(self.server_name, str) or (self.server_name and not _HOST_RE.match(self.server_name)):
            raise ValueError("server_name must be a plain host name")
        if not isinstance(self.congestion_controller, str) or not _CC_RE.match(self.congestion_controller):
            raise ValueError("congestion_controller must be a short lowercase name such as bbr")
        _text(self.profile_id, "profile_id")
        _text(self.auth_token, "auth_token")
        _text(self.license_key, "license_key")
        return self

    @classmethod
    def from_params(cls, params: Any) -> "MasqueOptions":
        if params is None:
            return cls()
        if not isinstance(params, dict):
            raise ValueError("options must be an object")
        known = {f.name for f in fields(cls)}
        for key in params:
            if key not in known:
                raise ValueError(f"unknown option {str(key)[:40]!r}")
        params = dict(params)
        if "doh_servers" in params:
            ds = params["doh_servers"]
            if not isinstance(ds, (list, tuple)):
                raise ValueError("doh_servers must be a list of IP addresses")
            params["doh_servers"] = tuple(ds)
        return cls(**params).validate()


def build_client_config(opts: MasqueOptions, socks_port: int) -> dict[str, Any]:
    """sing-box-extended client config: a local mixed (SOCKS/HTTP) inbound and
    one MASQUE outbound, following the fork's documented example."""
    opts.validate()
    tls: dict[str, Any] = {"insecure": opts.insecure, "fragment": opts.fragment,
                           "record_fragment": opts.record_fragment}
    if opts.server_name:
        tls["server_name"] = opts.server_name
    outbound: dict[str, Any] = {
        "type": "masque", "tag": TAG, "system": False, "name": "masque0",
        "use_http2": opts.use_http2, "use_l4_proxy": opts.use_l4_proxy, "use_ipv6": opts.use_ipv6,
        "profile": {"detour": "direct", "id": opts.profile_id,
                    "auth_token": opts.auth_token, "license_key": opts.license_key},
        "congestion_controller": opts.congestion_controller,
        "tls": tls,
    }
    if opts.address:
        outbound["address"] = opts.address
        if opts.port:
            outbound["port"] = opts.port
    route: dict[str, Any] = {"final": TAG, "default_domain_resolver": "default"}
    if opts.bind_interface:
        route["auto_detect_interface"] = True
    return {
        "log": {"level": "warn"},
        "dns": {"servers": _dns_servers(opts.dns, opts.doh_servers)},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [{"type": "direct", "tag": "direct"}, outbound],
        "route": route,
    }


def redact(cfg: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``cfg`` that is safe to show or log: credentials become ``***``."""
    out = copy.deepcopy(cfg)
    for ob in out.get("outbounds", []):
        prof = ob.get("profile")
        if isinstance(prof, dict):
            for key in ("auth_token", "license_key"):
                if prof.get(key):
                    prof[key] = "***"
    return out


class _ExtendedCore(CoreAdapter):
    """Only used to run the fork's binary through the shared probe runner."""
    name = "singbox_extended"
    display_name = "sing-box-extended"
    config_suffix = ".json"
    run_args = ("run", "-c")


def _write_private(cfg: dict[str, Any]) -> str:
    import json
    fd, path = tempfile.mkstemp(suffix=".json")            # mkstemp creates the file 0600
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    return path


def check_support(binary: str, timeout: float = 20.0) -> dict[str, Any]:
    """Does ``binary`` know the ``masque`` outbound?  Uses the core's own
    ``check`` command on a credential-free config; nothing is started."""
    if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        return {"supported": False, "detail": "sing-box-extended binary not found"}
    path = _write_private(build_client_config(MasqueOptions(), 1080))
    kw: dict[str, Any] = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        proc = subprocess.run([binary, "check", "-c", path], capture_output=True, text=True,
                              timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return {"supported": False, "detail": "check timed out"}
    except OSError as e:
        return {"supported": False, "detail": f"cannot run: {type(e).__name__}"}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if proc.returncode == 0:
        return {"supported": True, "detail": ""}
    text = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
    if _NO_MASQUE.search(text):
        return {"supported": False, "detail": NEEDS_FORK}
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return {"supported": False, "detail": (lines[-1].strip()[:120] if lines else f"exit code {proc.returncode}")}


def probe(binary: str, opts: MasqueOptions, timeout: float = 8.0,
          start_timeout: float = 60.0, stop=None) -> dict[str, Any]:
    """Run the fork with a MASQUE outbound and fetch a page through it.

    ``start_timeout`` is generous because a first run may have to create the
    Cloudflare device profile before the local port opens.  Returns the same
    ``{real, cc, exit_ip, status}`` dict as the other cores' probes."""
    opts.validate()
    support = check_support(binary)
    if not support["supported"]:
        return {"real": None, "cc": "", "exit_ip": "", "status": support["detail"]}
    port = _free_port()
    cfg = build_client_config(opts, port)
    log.debug("masque probe on 127.0.0.1:%s with config %s", port, redact(cfg))
    return run_socks_probe(_ExtendedCore(), binary, cfg, port, timeout=timeout,
                           start_timeout=start_timeout, stop=stop)
