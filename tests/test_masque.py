"""MASQUE support through the opt-in sing-box-extended fork.

The config schema is the one in the fork's own example
(examples/masque/client.json).  No real core runs here: a fake executable
plays the fork, so these tests prove Xray Forge's side (config, gating, probe,
secret handling), not that Cloudflare or the fork accept the config.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from xray_forge.core import masque
from xray_forge.core.cores import base as cores_base
from tests.fakebin import WATCHDOG, make_exe


# ------------------------------------------------------------------ fake core
FAKE_CORE = '''\
#!{python}
import json, os, socket, stat, sys, threading, time
cmd, cfg_path = sys.argv[1], sys.argv[3] if len(sys.argv) > 3 else ""
if cmd == "version":
    print("sing-box version 1.12.0-extended"); sys.exit(0)
{watchdog}
mode = os.environ.get("FAKE_MODE", "ok")
cfg = json.load(open(cfg_path))
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "a") as f:
        f.write(json.dumps({{"cmd": cmd, "mode_bits": oct(stat.S_IMODE(os.stat(cfg_path).st_mode)), "cfg": cfg}}) + "\\n")
types = [o.get("type") for o in cfg.get("outbounds", [])]
if cmd == "check":
    if "masque" in types and mode == "unsupported":
        sys.stderr.write("FATAL[0000] decode config at x: initialize outbound[1]: unknown outbound type: masque\\n")
        sys.exit(1)
    if mode == "badconfig":
        sys.stderr.write("FATAL[0000] decode config: json: cannot unmarshal\\n")
        sys.exit(1)
    sys.exit(0)
if cmd == "run":
    if mode == "crash":
        sys.stderr.write("FATAL[0000] start service: enrollment failed\\n")
        sys.exit(1)
    time.sleep(float(os.environ.get("FAKE_DELAY", "0")))
    port = [i for i in cfg["inbounds"] if i["type"] == "mixed"][0]["listen_port"]
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(8)
    body = json.dumps({{"status": "success", "countryCode": "DE", "query": "203.0.113.9"}}).encode()
    def serve(c):
        try:
            c.recv(262); c.sendall(b"\\x05\\x00")                    # greeting
            hdr = c.recv(4); atyp = hdr[3]
            if atyp == 3: n = c.recv(1)[0]; c.recv(n + 2)
            elif atyp == 1: c.recv(6)
            else: c.recv(18)
            c.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
            c.recv(4096)
            c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n" % len(body) + body)
        finally:
            c.close()
    while True:
        c, _ = srv.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
'''


@pytest.fixture
def core(tmp_path, monkeypatch):
    path = make_exe(tmp_path, "sing-box-fake", FAKE_CORE.format(python=sys.executable, watchdog=WATCHDOG))
    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.delenv("FAKE_MODE", raising=False)
    monkeypatch.delenv("FAKE_DELAY", raising=False)

    class C:
        binary = path

        @staticmethod
        def calls():
            return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    return C


# ------------------------------------------------------------------- config
REAL_DETECT = masque.system_dns_is_fake          # the autouse fixture below replaces the module attribute


@pytest.fixture(autouse=True)
def real_dns(monkeypatch):
    """Config tests must not depend on the machine's resolver."""
    monkeypatch.setattr(masque, "system_dns_is_fake", lambda: False)


def test_default_config_matches_the_documented_example_shape():
    cfg = masque.build_client_config(masque.MasqueOptions(), 7897)
    ob = next(o for o in cfg["outbounds"] if o["type"] == "masque")
    assert ob["tag"] == "masque-out" and cfg["route"]["final"] == "masque-out"
    assert ob["use_http2"] is False and ob["use_l4_proxy"] is False and ob["use_ipv6"] is False
    assert ob["profile"] == {"detour": "direct", "id": "", "auth_token": "", "license_key": ""}
    assert ob["congestion_controller"] == "bbr"
    assert {"type": "direct", "tag": "direct"} in cfg["outbounds"]
    inb = cfg["inbounds"][0]
    assert inb["type"] == "mixed" and inb["listen"] == "127.0.0.1" and inb["listen_port"] == 7897
    assert cfg["dns"]["servers"][0] == {"type": "local", "tag": "default"}     # plain system DNS when it is trustworthy
    assert cfg["route"]["default_domain_resolver"] == "default"
    assert "auto_detect_interface" not in cfg["route"]
    json.dumps(cfg)                                          # plain JSON (the example's comments are not copied)


def test_options_reach_the_outbound():
    opts = masque.MasqueOptions(use_http2=True, use_l4_proxy=True, use_ipv6=True,
                                address="162.159.198.1", port=443, server_name="masque.example.com",
                                insecure=False, fragment=True, record_fragment=True,
                                congestion_controller="bbr", profile_id="pid", auth_token="tok",
                                license_key="lic")
    ob = next(o for o in masque.build_client_config(opts, 1080)["outbounds"] if o["type"] == "masque")
    assert (ob["use_http2"], ob["use_l4_proxy"], ob["use_ipv6"]) == (True, True, True)
    assert (ob["address"], ob["port"]) == ("162.159.198.1", 443)
    assert ob["tls"]["server_name"] == "masque.example.com"
    assert ob["tls"]["fragment"] is True and ob["tls"]["record_fragment"] is True
    assert ob["profile"] == {"detour": "direct", "id": "pid", "auth_token": "tok", "license_key": "lic"}


def test_optional_fields_are_left_out_when_unset():
    ob = next(o for o in masque.build_client_config(masque.MasqueOptions(), 1)["outbounds"] if o["type"] == "masque")
    assert "address" not in ob and "port" not in ob and "server_name" not in ob["tls"]


@pytest.mark.parametrize("kw", [
    {"port": 70000}, {"port": "443"}, {"port": True}, {"address": "bad host"}, {"address": "a/b"},
    {"address": ""} if False else {"address": "x" * 300}, {"server_name": "bad host"}, {"server_name": "a" * 300},
    {"congestion_controller": "bbr; rm"}, {"congestion_controller": ""}, {"use_http2": "yes"}, {"use_l4_proxy": 1},
    {"profile_id": "x" * 300}, {"auth_token": "a\nb"}, {"license_key": "\x00"}, {"port": 443},   # port without address
])
def test_invalid_options_are_rejected(kw):
    if kw == {"port": 443}:
        with pytest.raises(ValueError, match="address"):
            masque.MasqueOptions(**kw).validate()
        return
    with pytest.raises(ValueError):
        masque.MasqueOptions(**kw).validate()


def test_zero_port_and_empty_address_are_the_defaults():
    masque.MasqueOptions(port=0).validate()
    masque.MasqueOptions(address="example.com", port=0).validate()
    masque.MasqueOptions(address="2606:4700::1", port=443).validate()


def test_from_params_rejects_unknown_keys_and_non_objects():
    with pytest.raises(ValueError, match="bogus"):
        masque.MasqueOptions.from_params({"bogus": 1})
    for bad in ("x", 5, [1]):
        with pytest.raises(ValueError):
            masque.MasqueOptions.from_params(bad)
    assert masque.MasqueOptions.from_params(None) == masque.MasqueOptions()
    assert masque.MasqueOptions.from_params({"use_http2": True}).use_http2 is True


def test_secrets_never_appear_in_repr_or_redacted_config():
    opts = masque.MasqueOptions(profile_id="PID-1", auth_token="TOKEN-SECRET", license_key="LICENSE-SECRET")
    assert "SECRET" not in repr(opts) and "SECRET" not in str(opts)
    red = json.dumps(masque.redact(masque.build_client_config(opts, 1)))
    assert "TOKEN-SECRET" not in red and "LICENSE-SECRET" not in red
    assert "PID-1" in red                                    # the profile id is an identifier, not a credential
    assert "***" in red


# ------------------------------------------------------------------ support
def test_check_support_ok(core):
    r = masque.check_support(core.binary)
    assert r == {"supported": True, "detail": ""}
    assert core.calls()[0]["cmd"] == "check" and any(o["type"] == "masque" for o in core.calls()[0]["cfg"]["outbounds"])


def test_check_support_says_which_core_is_needed_when_masque_is_unknown(core, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "unsupported")
    r = masque.check_support(core.binary)
    assert r["supported"] is False and "sing-box-extended" in r["detail"] and "masque" in r["detail"]


def test_check_support_distinguishes_other_failures(core, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "badconfig")
    r = masque.check_support(core.binary)
    assert r["supported"] is False and "sing-box-extended" not in r["detail"] and "unmarshal" in r["detail"]


def test_check_support_missing_binary(tmp_path):
    for path in ("", str(tmp_path / "nope")):
        r = masque.check_support(path)
        assert r["supported"] is False and r["detail"]


def test_check_support_uses_no_secrets_and_a_private_temp_file(core):
    masque.check_support(core.binary)
    call = core.calls()[0]
    assert os.name == "nt" or call["mode_bits"] == "0o600"
    ob = next(o for o in call["cfg"]["outbounds"] if o["type"] == "masque")
    assert ob["profile"]["auth_token"] == "" and ob["profile"]["license_key"] == ""


# -------------------------------------------------------------------- probe
def test_probe_reaches_the_internet_through_the_fake_core(core):
    r = masque.probe(core.binary, masque.MasqueOptions(), timeout=5.0)
    assert r["status"] == "core ok" and r["cc"] == "DE" and r["exit_ip"] == "203.0.113.9" and r["real"] is not None
    run = [c for c in core.calls() if c["cmd"] == "run"][0]
    assert os.name == "nt" or run["mode_bits"] == "0o600"                       # the config may hold the profile token


def test_probe_reports_a_core_that_dies_on_start(core, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "crash")
    r = masque.probe(core.binary, masque.MasqueOptions(), timeout=3.0)
    assert r["real"] is None and "enrollment failed" in r["status"]


def test_probe_waits_long_enough_for_a_first_run_enrolment(core, monkeypatch):
    monkeypatch.setenv("FAKE_DELAY", "1.5")
    quick = masque.probe(core.binary, masque.MasqueOptions(), timeout=3.0, start_timeout=0.5)
    assert quick["real"] is None
    slow = masque.probe(core.binary, masque.MasqueOptions(), timeout=3.0, start_timeout=10.0)
    assert slow["status"] == "core ok"


def test_probe_leaves_no_secret_in_temp_files_or_logs(core, caplog, tmp_path):
    import glob
    import tempfile
    caplog.set_level("DEBUG")
    opts = masque.MasqueOptions(auth_token="TOKEN-SECRET", license_key="LICENSE-SECRET")
    masque.probe(core.binary, opts, timeout=3.0)
    assert "SECRET" not in caplog.text
    for f in glob.glob(os.path.join(tempfile.gettempdir(), "tmp*.json")):
        assert "TOKEN-SECRET" not in open(f, errors="ignore").read()


def test_run_socks_probe_default_start_timeout_is_unchanged():
    import inspect
    assert inspect.signature(cores_base.run_socks_probe).parameters["start_timeout"].default == 5.0


def test_probe_can_be_cancelled_while_the_core_is_still_starting(core, monkeypatch):
    import threading
    import time
    monkeypatch.setenv("FAKE_DELAY", "30")
    stop = threading.Event()
    threading.Timer(0.5, stop.set).start()
    t0 = time.monotonic()
    r = masque.probe(core.binary, masque.MasqueOptions(), timeout=3.0, start_timeout=60.0, stop=stop)
    assert time.monotonic() - t0 < 10
    assert r["real"] is None and "cancel" in r["status"]


# ------------------------------------------------- DNS and interface binding
def _dns(cfg):
    return cfg["dns"]["servers"]


def test_doh_mode_uses_ip_literal_servers_so_it_never_needs_resolution():
    cfg = masque.build_client_config(masque.MasqueOptions(dns="doh"), 1080)
    servers = _dns(cfg)
    assert [s["server"] for s in servers] == ["8.8.8.8", "1.1.1.1"]
    assert all(s["type"] == "https" and s["server_port"] == 443 for s in servers)
    assert servers[0]["tag"] == "default" and len({s["tag"] for s in servers}) == 2
    assert not any("domain_resolver" in s for s in servers)             # a self-referencing resolver broke it
    assert cfg["route"]["default_domain_resolver"] == "default"


def test_system_mode_stays_local_even_when_the_resolver_is_fake(monkeypatch):
    monkeypatch.setattr(masque, "system_dns_is_fake", lambda: True)
    assert _dns(masque.build_client_config(masque.MasqueOptions(dns="system"), 1080)) == [{"type": "local", "tag": "default"}]


def test_auto_mode_switches_to_doh_only_when_the_system_resolver_is_fake(monkeypatch):
    monkeypatch.setattr(masque, "system_dns_is_fake", lambda: True)
    assert _dns(masque.build_client_config(masque.MasqueOptions(), 1080))[0]["type"] == "https"
    monkeypatch.setattr(masque, "system_dns_is_fake", lambda: False)
    assert _dns(masque.build_client_config(masque.MasqueOptions(), 1080))[0]["type"] == "local"


@pytest.mark.parametrize("answers,expected", [
    (["198.18.0.7"], True), (["198.19.255.255"], True), (["203.0.113.9", "198.18.1.1"], True),
    (["198.17.255.255"], False), (["198.20.0.0"], False), (["104.16.0.1"], False), (["2606:4700::1"], False), ([], False)])
def test_fake_ip_detection(monkeypatch, answers, expected):
    import socket
    fam = lambda a: socket.AF_INET6 if ":" in a else socket.AF_INET
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(fam(x), 1, 6, "", (x, 0)) for x in answers])
    assert REAL_DETECT() is expected


def test_fake_ip_detection_survives_a_resolver_failure(monkeypatch):
    import socket

    def boom(*a, **k):
        raise socket.gaierror("no")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert REAL_DETECT() is False


def test_bind_interface_is_opt_in():
    on = masque.build_client_config(masque.MasqueOptions(bind_interface=True), 1080)
    assert on["route"]["auto_detect_interface"] is True


@pytest.mark.parametrize("bad", [{"dns": "udp"}, {"dns": 1}, {"dns": None}, {"bind_interface": "yes"}, {"bind_interface": 1}])
def test_new_options_are_validated(bad):
    with pytest.raises(ValueError):
        masque.MasqueOptions.from_params(bad)


# ------------------------------------- split-horizon fake-IP and DoH server choice
def test_fake_ip_detection_checks_the_host_the_core_will_dial(monkeypatch):
    """Split DNS: cloudflare.com can resolve for real while api.cloudflareclient.com is fake-IP."""
    import socket
    real, fake = "104.16.133.229", "198.18.6.66"

    def gai(host, *a, **k):
        ip = fake if host == "api.cloudflareclient.com" else real
        return [(socket.AF_INET, 1, 6, "", (ip, 0))]
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    assert REAL_DETECT() is True


def test_fake_ip_detection_survives_one_name_failing(monkeypatch):
    import socket

    def gai(host, *a, **k):
        if host == "api.cloudflareclient.com":
            raise socket.gaierror("no")
        return [(socket.AF_INET, 1, 6, "", ("198.19.0.5" if host == "cloudflare.com" else "104.16.0.1", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    assert REAL_DETECT() is True


def test_doh_server_order_puts_the_google_resolver_first_and_is_configurable():
    cfg = masque.build_client_config(masque.MasqueOptions(dns="doh"), 1080)
    assert [s["server"] for s in cfg["dns"]["servers"]] == ["8.8.8.8", "1.1.1.1"]      # 1.1.1.1:443 is blackholed in some networks
    custom = masque.build_client_config(masque.MasqueOptions(dns="doh", doh_servers=("9.9.9.9", "149.112.112.112")), 1080)
    assert [(s["tag"], s["server"]) for s in custom["dns"]["servers"]] == [("default", "9.9.9.9"), ("doh1", "149.112.112.112")]
    assert masque.MasqueOptions.from_params({"doh_servers": ["9.9.9.9"]}).doh_servers == ("9.9.9.9",)


@pytest.mark.parametrize("bad", [[], ["dns.google"], ["1.1.1.1", "not-an-ip"], "8.8.8.8", [8], ["1.1.1.1"] * 5, [["1.1.1.1"]], None, ["10.0.0.1 "]])
def test_doh_servers_must_be_a_short_list_of_ip_literals(bad):
    with pytest.raises(ValueError):
        masque.MasqueOptions.from_params({"doh_servers": bad})
