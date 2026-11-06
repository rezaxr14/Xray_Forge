"""System DNS/proxy backends (command lines only, no machine is touched), the catalog, the saved
entries and the net.* engine methods."""

from __future__ import annotations

import ipaddress
import json

import pytest

from xray_forge.core import dns_presets, dns_probe, netstore, sysnet
from xray_forge.engine import methods


class Fake:
    """Runner that records argv and answers from a table keyed by the first matching fragment."""

    def __init__(self, answers=None):
        self.calls, self.answers = [], answers or {}

    def __call__(self, argv, timeout=20.0):
        self.calls.append(list(argv))
        joined = " ".join(argv)
        for frag, res in self.answers.items():
            if frag in joined:
                return res
        return 0, "", ""


# ------------------------------------------------------------------ catalog
def test_catalog_is_well_formed():
    cats = {c["id"] for c in dns_presets.CATEGORIES}
    ids = set()
    for p in dns_presets.PRESETS:
        assert p["id"] not in ids
        ids.add(p["id"])
        assert p["category"] in cats and p["v4"]
        for a in p["v4"]:
            assert ipaddress.ip_address(a).version == 4
        for a in p["v6"]:
            assert ipaddress.ip_address(a).version == 6
        assert not p["doh"] or p["doh"].startswith("https://")


def test_catalog_covers_the_wanted_kinds():
    cats = {p["category"] for p in dns_presets.PRESETS}
    assert {"ads", "privacy", "malware", "family", "sanctions"} <= cats


def test_clean_servers_validates_and_dedups():
    assert sysnet.clean_servers(["1.1.1.1", " 1.1.1.1 ", "2606:4700:4700::1111"]) == ["1.1.1.1", "2606:4700:4700::1111"]
    for bad in ([], "1.1.1.1", ["1.1.1.1; calc"], ["dns.google"], ["1.1.1.1"] * 0 + ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]):
        with pytest.raises(ValueError):
            sysnet.clean_servers(bad)


def test_clean_proxy():
    assert sysnet.clean_proxy("127.0.0.1", "10808", "socks") == ("127.0.0.1", 10808, "socks")
    for args in (("", 1, "http"), ("a b", 1, "http"), ("h", 0, "http"), ("h", 70000, "http"), ("h", True, "http"), ("h", 1, "ftp"), ("h;x", 1, "http")):
        with pytest.raises(ValueError):
            sysnet.clean_proxy(*args)


# ------------------------------------------------------------------ Windows
def test_windows_lists_sets_and_resets_by_index():
    run = Fake({"Get-NetAdapter": (0, json.dumps([{"Name": "tun0", "InterfaceDescription": "Wintun", "ifIndex": 5, "HardwareInterface": False},
                                                  {"Name": "Wi-Fi", "InterfaceDescription": "Intel", "ifIndex": 12, "HardwareInterface": True}]), ""),
                "Get-DnsClientServerAddress": (0, json.dumps({"AddressFamily": 2, "ServerAddresses": ["1.1.1.1", "1.0.0.1"]}), "")})
    be = sysnet.WindowsBackend(run)
    assert [i["name"] for i in be.interfaces()] == ["Wi-Fi", "tun0"]       # the real adapter comes first
    iface = be.find("12")
    assert iface["name"] == "Wi-Fi"
    be.set_dns(iface, ["1.1.1.1", "1.0.0.1"])
    script = next(c[-1] for c in run.calls if "Set-DnsClientServerAddress" in c[-1])
    assert "$ErrorActionPreference='Stop'" in script
    assert "-InterfaceIndex 12" in script and "('1.1.1.1','1.0.0.1')" in script and "Clear-DnsClientCache" in script
    assert run.calls[-1][0] == "powershell.exe"
    be.reset_dns(iface)
    assert "-ResetServerAddresses" in run.calls[-1][-1]


def test_windows_reports_a_change_that_did_not_stick():
    run = Fake({"Get-DnsClientServerAddress": (0, json.dumps({"AddressFamily": 2, "ServerAddresses": ["192.168.1.1"]}), "")})
    with pytest.raises(sysnet.NetConfigError) as e:
        sysnet.WindowsBackend(run).set_dns({"id": "12", "name": "Wi-Fi"}, ["1.1.1.1"])
    assert "administrator" in e.value.hint


def test_windows_access_denied_gets_the_administrator_hint():
    run = Fake({"Set-DnsClientServerAddress": (1, "", "Set-DnsClientServerAddress : Access is denied.")})
    with pytest.raises(sysnet.NetConfigError) as e:
        sysnet.WindowsBackend(run).set_dns({"id": "12", "name": "Wi-Fi"}, ["1.1.1.1"])
    assert "administrator" in e.value.hint.lower()


def test_windows_single_adapter_json_object_and_unknown_interface():
    run = Fake({"Get-NetAdapter": (0, json.dumps({"Name": "Eth", "InterfaceDescription": "", "ifIndex": 3}), "")})
    be = sysnet.WindowsBackend(run)
    assert [i["id"] for i in be.interfaces()] == ["3"]
    with pytest.raises(sysnet.NetConfigError):
        be.find("999")


def test_windows_reads_dns_from_both_families():
    out = json.dumps([{"AddressFamily": 2, "ServerAddresses": ["8.8.8.8", "8.8.4.4"]}, {"AddressFamily": 23, "ServerAddresses": []}])
    be = sysnet.WindowsBackend(Fake({"Get-DnsClientServerAddress": (0, out, "")}))
    assert be.get_dns({"id": "5"})["servers"] == ["8.8.8.8", "8.8.4.4"]


def test_admin_refusal_carries_a_hint():
    be = sysnet.WindowsBackend(Fake({"Set-DnsClientServerAddress": (1, "", "Set-DnsClientServerAddress : Access is denied")}))
    with pytest.raises(sysnet.NetConfigError) as e:
        be.set_dns({"id": "1"}, ["1.1.1.1"])
    assert "denied" in str(e.value) and e.value.hint


class FakeReg:
    HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ, REG_DWORD = "HKCU", 1, 2, "SZ", "DWORD"

    def __init__(self):
        self.values = {}

    def OpenKey(self, *a):
        return self

    def CloseKey(self, k):
        pass

    def SetValueEx(self, k, name, _r, kind, val):
        self.values[name] = val

    def QueryValueEx(self, k, name):
        if name not in self.values:
            raise OSError(name)
        return self.values[name], "x"


def test_windows_proxy_roundtrip_in_the_registry():
    reg, refreshed = FakeReg(), []
    be = sysnet.WindowsBackend(Fake(), reg=reg, refresh=lambda: refreshed.append(1))
    be.set_proxy("127.0.0.1", 8080, "http")
    assert reg.values == {"ProxyServer": "127.0.0.1:8080", "ProxyOverride": "<local>", "ProxyEnable": 1}
    assert be.get_proxy() == {"enabled": True, "kind": "http", "host": "127.0.0.1", "port": 8080}
    be.set_proxy("127.0.0.1", 10808, "socks")
    assert reg.values["ProxyServer"] == "socks=127.0.0.1:10808"
    assert be.get_proxy()["kind"] == "socks"
    be.disable_proxy()
    assert be.get_proxy()["enabled"] is False and len(refreshed) == 3


# -------------------------------------------------------------------- macOS
def test_macos_services_and_dns():
    listing = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nEthernet Adapter\n"
    run = Fake({"-listallnetworkservices": (0, listing, ""), "-getdnsservers": (0, "There aren't any DNS Servers set on Wi-Fi.\n", "")})
    be = sysnet.MacBackend(run)
    assert [i["id"] for i in be.interfaces()] == ["Wi-Fi", "Ethernet Adapter"]
    assert be.get_dns(be.find("Wi-Fi")) == {"servers": [], "automatic": True}
    be.set_dns({"id": "Wi-Fi"}, ["9.9.9.9"])
    assert run.calls[-1] == ["networksetup", "-setdnsservers", "Wi-Fi", "9.9.9.9"]
    be.reset_dns({"id": "Wi-Fi"})
    assert run.calls[-1][-1] == "Empty"


def test_macos_proxy_applies_to_every_service():
    run = Fake({"-listallnetworkservices": (0, "note\nWi-Fi\nEthernet\n", "")})
    be = sysnet.MacBackend(run)
    be.set_proxy("127.0.0.1", 8080, "http")
    sets = [c for c in run.calls if c[1] in ("-setwebproxy", "-setsecurewebproxy")]
    assert len(sets) == 4 and all(c[3:] == ["127.0.0.1", "8080"] for c in sets)


# -------------------------------------------------------------------- Linux
def test_linux_interfaces_dns_and_proxy():
    ip = "1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\n" \
         "2: enp3s0: <BROADCAST,UP> mtu 1500 qdisc fq state UP mode DEFAULT\n" \
         "3: wlan0: <BROADCAST> mtu 1500 qdisc noop state DOWN mode DEFAULT\n" \
         "4: veth1@if3: <BROADCAST,UP> mtu 1500 qdisc noqueue state UP mode DEFAULT\n"
    run = Fake({"ip -o link": (0, ip, ""), "resolvectl dns": (0, "Link 2 (enp3s0): 1.1.1.1 2606:4700:4700::1111\n", "")})
    be = sysnet.LinuxBackend(run)
    assert [i["id"] for i in be.interfaces()] == ["enp3s0", "veth1"]
    assert be.get_dns({"id": "enp3s0"})["servers"] == ["1.1.1.1", "2606:4700:4700::1111"]
    be.set_dns({"id": "enp3s0"}, ["9.9.9.9"])
    assert ["resolvectl", "dns", "enp3s0", "9.9.9.9"] in run.calls
    be.set_proxy("127.0.0.1", 8080, "http")
    assert ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"] in run.calls
    be.disable_proxy()
    assert run.calls[-1] == ["gsettings", "set", "org.gnome.system.proxy", "mode", "none"]


def test_missing_tool_is_a_clear_error(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError()
    monkeypatch.setattr(sysnet.subprocess, "run", boom)
    with pytest.raises(sysnet.NetConfigError, match="not installed"):
        sysnet.default_runner(["resolvectl"])


# -------------------------------------------------------------------- store
def test_store_saves_validates_and_imports_the_old_files():
    netstore.save_dns("Home", ["192.168.1.1", "1.1.1.1"])
    assert netstore.load()["dns"]["Home"]["servers"] == ["192.168.1.1", "1.1.1.1"]
    with pytest.raises(ValueError):
        netstore.save_dns("", ["1.1.1.1"])
    r = netstore.import_legacy(
        {"Google": ["8.8.8.8", "8.8.4.4"], "Broken": ["nope", "8.8.8.8"], "Radar": ["10.202.10.10", "10.202.10.11"]},
        {"No Proxy": {"server": "", "port": "", "type": "Disabled"},
         "Office": {"server": "192.168.1.159", "port": "8080", "user": "u", "pass": "secret", "type": "HTTP"}})
    assert r == {"dns": 2, "proxies": 1, "skipped": 1}
    saved = netstore.load()
    assert saved["proxies"]["Office"] == {"host": "192.168.1.159", "port": 8080, "kind": "http"}
    assert "secret" not in json.dumps(saved)
    assert netstore.delete("dns", "Home") and not netstore.delete("dns", "Home")


# ------------------------------------------------------------------- probe
def test_probe_measures_and_reports_failures(monkeypatch):
    monkeypatch.setattr(dns_probe.scanner, "udp_dns_a", lambda name, server, timeout: ["93.184.216.34"] if server == "1.1.1.1" else (_ for _ in ()).throw(OSError("timed out")))
    ok, bad, v6 = dns_probe.probe_many(["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
    assert ok["ok"] and isinstance(ok["ms"], int)
    assert bad["error"] == "timed out" and not bad["ok"]
    assert "IPv6" in v6["error"]


# ------------------------------------------------------------------ engine
@pytest.fixture
def rpc(monkeypatch):
    run = Fake({"-listallnetworkservices": (0, "note\nWi-Fi\n", ""), "-getdnsservers": (0, "8.8.8.8\n", "")})
    monkeypatch.setattr(sysnet, "platform_name", lambda: "macos")
    monkeypatch.setattr("xray_forge.engine.net_methods._be", lambda: sysnet.MacBackend(run))
    d, _ = methods.build(lambda e: None)

    def call(method, **params):
        r = d.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        return r.get("result", r.get("error"))
    call.run = run
    return call


def test_apply_from_a_preset_reports_what_was_there(rpc):
    r = rpc("net.dns.apply", interface="Wi-Fi", preset="adguard")
    assert r["servers"] == ["94.140.14.14", "94.140.15.15"] and r["previous"] == ["8.8.8.8"]
    assert rpc.run.calls[-1] == ["networksetup", "-setdnsservers", "Wi-Fi", "94.140.14.14", "94.140.15.15"]
    r6 = rpc("net.dns.apply", interface="Wi-Fi", preset="cloudflare", ipv6=True)
    assert len(r6["servers"]) == 4


def test_apply_rejects_bad_input(rpc):
    assert rpc("net.dns.apply", interface="Wi-Fi")["code"] == -32602
    assert rpc("net.dns.apply", interface="Wi-Fi", preset="x", servers=["1.1.1.1"])["code"] == -32602
    assert rpc("net.dns.apply", interface="Wi-Fi", preset="nope")["code"] == -32602
    assert rpc("net.dns.apply", interface="Wi-Fi", servers=["1.1.1.1;rm"])["code"] == -32602
    assert rpc("net.dns.apply", interface="Missing", preset="adguard")["code"] == -32000
    assert not any(c[1] == "-setdnsservers" for c in rpc.run.calls)


def test_saved_entries_flow_through_apply_and_list(rpc):
    rpc("net.dns.save", name="Home", servers=["192.168.1.1"])
    assert rpc("net.dns.presets")["custom"][0]["name"] == "Home"
    assert rpc("net.dns.apply", interface="Wi-Fi", saved="Home")["servers"] == ["192.168.1.1"]
    assert rpc("net.dns.delete", name="Home") == {"deleted": True}


def test_proxy_methods(rpc):
    assert rpc("net.proxy.set", host="127.0.0.1", port=8080)["kind"] == "http"
    assert rpc("net.proxy.set", host="x y", port=8080)["code"] == -32602
    rpc("net.proxy.save", name="Local", host="127.0.0.1", port=10808, kind="socks")
    assert rpc("net.proxy.get")["saved"][0]["name"] == "Local"
    assert rpc("net.proxy.disable") == {"enabled": False}


# --------------------------------------------------------------------- CLI
def test_cli_dns_list_and_errors(capsys):
    from xray_forge import cli
    assert cli.main(["dns", "list"]) == 0
    out = capsys.readouterr().out
    assert "adguard" in out and "Anti-sanction" in out
    assert cli.main(["dns", "apply", "--preset", "adguard"]) == 2
    assert cli.main(["dns", "test", "--preset", "nope"]) == 2
    assert cli.main(["proxy", "set", "--host", "bad host", "--port", "1"]) == 1
