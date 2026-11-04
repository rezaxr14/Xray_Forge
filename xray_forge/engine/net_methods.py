"""Engine methods ``net.*``: system DNS and proxy, the DNS catalog, saved entries and a speed test."""

from __future__ import annotations

from typing import Any

from xray_forge.core import dns_presets, dns_probe, netstore, sysnet
from xray_forge.engine.rpc import APP_ERROR, Dispatcher, RpcError, invalid_params, seconds

MAX_FILE = 200_000


def _be():
    return sysnet.backend()


def _guard(fn):
    """Run a backend call; turn its errors into RPC errors the UI can show."""
    try:
        return fn()
    except sysnet.NetConfigError as e:
        # the desktop bridge only passes the message text on, so the hint rides along in it
        raise RpcError(APP_ERROR, f"{e}. {e.hint}" if e.hint else str(e), {"hint": e.hint} if e.hint else None) from None
    except ValueError as e:
        raise invalid_params(str(e)) from None


def _servers(preset: Any, servers: Any, ipv6: Any, saved: Any = None) -> list[str]:
    if isinstance(ipv6, bool) is False:
        raise invalid_params("ipv6 must be true or false")
    given = sum(x is not None for x in (preset, servers, saved))
    if given != 1:
        raise invalid_params("give exactly one of preset, saved or servers")
    if preset is not None:
        p = dns_presets.find(preset) if isinstance(preset, str) else None
        if not p:
            raise invalid_params(f"unknown preset: {str(preset)[:40]}")
        return dns_presets.servers_of(p, ipv6)
    if saved is not None:
        e = netstore.load()["dns"].get(saved) if isinstance(saved, str) else None
        if not e:
            raise invalid_params(f"no saved DNS entry named {str(saved)[:40]!r}")
        return e["servers"]
    return _guard(lambda: sysnet.clean_servers(servers))


def register(d: Dispatcher) -> None:
    @d.method("net.info")
    def net_info() -> dict:
        return {"platform": sysnet.platform_name(), "admin": sysnet.is_admin()}

    @d.method("net.interfaces")
    def net_interfaces() -> dict:
        return {"interfaces": _guard(lambda: _be().interfaces())}

    @d.method("net.dns.presets")
    def dns_list() -> dict:
        custom = [{"name": n, **e} for n, e in sorted(netstore.load()["dns"].items())]
        return {"categories": list(dns_presets.CATEGORIES), "presets": list(dns_presets.PRESETS), "custom": custom}

    @d.method("net.dns.current")
    def dns_current(interface: str) -> dict:
        def run():
            be = _be()
            return be.get_dns(be.find(interface))
        return _guard(run)

    @d.method("net.dns.apply")
    def dns_apply(interface: str, preset: Any = None, servers: Any = None, ipv6: Any = False, saved: Any = None) -> dict:
        """Set the DNS servers of one interface from a catalog preset, a saved entry or a list."""
        chosen = _servers(preset, servers, ipv6, saved)

        def run():
            be = _be()
            iface = be.find(interface)
            before = be.get_dns(iface)["servers"]
            be.set_dns(iface, chosen)
            return {"servers": chosen, "previous": before, "interface": iface["name"]}
        return _guard(run)

    @d.method("net.dns.reset")
    def dns_reset(interface: str) -> dict:
        def run():
            be = _be()
            iface = be.find(interface)
            be.reset_dns(iface)
            return {"interface": iface["name"]}
        return _guard(run)

    @d.method("net.dns.test")
    def dns_test(preset: Any = None, servers: Any = None, saved: Any = None, ipv6: Any = False,
                 timeout: Any = 2.0) -> dict:
        """Time a plain-DNS lookup of example.com against each server; blocks for a few seconds."""
        if preset is None and servers is None and saved is None:
            addrs = [a for p in dns_presets.PRESETS for a in p["v4"][:1]]
        else:
            addrs = _servers(preset, servers, ipv6, saved)
        return {"results": dns_probe.probe_many(addrs, timeout=seconds(timeout, "timeout", 0.2, 10.0))}

    @d.method("net.dns.save")
    def dns_save(name: Any, servers: Any, note: Any = "") -> dict:
        return _guard(lambda: netstore.save_dns(name, servers, note))

    @d.method("net.dns.delete")
    def dns_delete(name: Any) -> dict:
        return {"deleted": netstore.delete("dns", name)}

    @d.method("net.import")
    def net_import(dns: Any = None, proxies: Any = None) -> dict:
        """Bring in the old DNS & Proxy Changer files (dns_servers.json, proxies.json) as parsed JSON."""
        for label, v in (("dns", dns), ("proxies", proxies)):
            if v is not None and not isinstance(v, dict):
                raise invalid_params(f"{label} must be an object")
        return _guard(lambda: netstore.import_legacy(dns, proxies))

    @d.method("net.proxy.get")
    def proxy_get() -> dict:
        cur = _guard(lambda: _be().get_proxy())
        return {"current": cur, "saved": [{"name": n, **e} for n, e in sorted(netstore.load()["proxies"].items())]}

    @d.method("net.proxy.set")
    def proxy_set(host: Any, port: Any, kind: Any = "http") -> dict:
        h, p, k = _guard(lambda: sysnet.clean_proxy(host, port, kind))
        _guard(lambda: _be().set_proxy(h, p, k))
        return {"host": h, "port": p, "kind": k}

    @d.method("net.proxy.disable")
    def proxy_disable() -> dict:
        _guard(lambda: _be().disable_proxy())
        return {"enabled": False}

    @d.method("net.proxy.save")
    def proxy_save(name: Any, host: Any, port: Any, kind: Any = "http") -> dict:
        return _guard(lambda: netstore.save_proxy(name, host, port, kind))

    @d.method("net.proxy.delete")
    def proxy_delete(name: Any) -> dict:
        return {"deleted": netstore.delete("proxies", name)}
