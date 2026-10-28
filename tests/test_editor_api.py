"""Editor API: config.render validation, config.from_json, option lists (step 5.2)."""

from __future__ import annotations

import json

import pytest

from tests.fixtures import (
    SS_SIP002, TROJAN_TLS, VLESS_REALITY, VLESS_TLS_WS, VMESS_B64,
)
from tests.test_engine import Client
from xray_forge.core.config import FLOWS, SECURITIES, TRANSPORTS, XHTTP_MODES
from xray_forge.core.parser import parse_target

XHTTP = ("vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@1.2.3.4:443?security=tls"
         "&sni=a.com&type=xhttp&mode=packet-up&path=%2Fp&host=a.com&ech=AEX#x")


def parsed(c, line):
    return c.result("config.parse", line=line)["outbound"]


def test_engine_info_lists_editor_options():
    ed = Client().result("engine.info")["editor"]
    assert ed == {"transports": TRANSPORTS, "flows": FLOWS,
                  "securities": SECURITIES, "xhttp_modes": XHTTP_MODES}
    assert "xhttp" in ed["transports"] and "packet-up" in ed["xhttp_modes"]


# ------------------------------------------------------------ field editing
def test_every_editor_field_reaches_the_link():
    c = Client()
    ob = parsed(c, VLESS_REALITY)
    ob.update(public_key="NEWKEY", short_id="ff00", spider_x="/spx", flow="",
              allow_insecure=True, header_type="http", sni="new.example.com")
    ob["extra"] = {**ob["extra"], "cs": "TLS_AES_128_GCM_SHA256"}
    uri = c.result("config.render", outbound=ob)["uri"]
    back = parse_target(uri)
    assert (back.public_key, back.short_id, back.spider_x) == ("NEWKEY", "ff00", "/spx")
    assert back.allow_insecure is True and back.header_type == "http"
    assert back.sni == "new.example.com" and back.flow == ""
    assert back.extra["cs"] == "TLS_AES_128_GCM_SHA256"


def test_xhttp_mode_and_extra_params_survive_editing():
    c = Client()
    ob = parsed(c, XHTTP)
    assert ob["extra"]["mode"] == "packet-up" and ob["extra_params"]["ech"] == "AEX"
    ob["extra"]["mode"] = "stream-up"
    ob["path"] = "/new"
    back = parse_target(c.result("config.render", outbound=ob)["uri"])
    assert back.extra["mode"] == "stream-up" and back.path == "/new"
    assert back.extra_params["ech"] == "AEX"


def test_vmess_fields_edit():
    c = Client()
    ob = parsed(c, VMESS_B64)
    ob.update(encryption="aes-128-gcm", alter_id="4", header_type="http",
              allow_insecure=False, name="renamed")
    back = parse_target(c.result("config.render", outbound=ob)["uri"])
    assert (back.encryption, back.alter_id, back.header_type, back.name) == \
        ("aes-128-gcm", "4", "http", "renamed")


def test_shadowsocks_method_edit():
    c = Client()
    ob = parsed(c, SS_SIP002)
    ob["ss_method"] = "chacha20-ietf-poly1305"
    back = parse_target(c.result("config.render", outbound=ob)["uri"])
    assert back.ss_split()[0] == "chacha20-ietf-poly1305"


@pytest.mark.parametrize("line", [VLESS_TLS_WS, VLESS_REALITY, TROJAN_TLS, VMESS_B64, SS_SIP002, XHTTP])
def test_parse_render_parse_is_stable(line):
    c = Client()
    ob = parsed(c, line)
    again = parse_target(c.result("config.render", outbound=ob)["uri"])
    for k in ("scheme", "host", "port", "credential", "transport", "security",
              "sni", "path", "host_header", "public_key", "short_id", "flow",
              "allow_insecure", "name"):
        assert getattr(again, k) == ob[k], k
    assert again.extra_params == ob["extra_params"]


# --------------------------------------------------------------- validation
@pytest.mark.parametrize("patch", [
    {"port": "0"}, {"port": "65536"}, {"port": "abc"}, {"port": True},
    {"host": 5}, {"name": None}, {"path": ["x"]}, {"allow_insecure": "yes"},
    {"allow_insecure": 1}, {"extra": []}, {"extra_params": "x"},
    {"extra_params": {"k": {"nested": 1}}},
    {"alter_id": 1.5}, {"zzz": 1}, {"scheme": "nope"},
])
def test_render_rejects_bad_payloads(patch):
    c = Client()
    ob = {**parsed(c, VLESS_TLS_WS), **patch}
    resp = c.call("config.render", outbound=ob)
    assert resp["error"]["code"] == -32602, resp


def test_render_accepts_integer_port_and_alter_id():
    c = Client()
    ob = {**parsed(c, VMESS_B64), "port": 8443, "alter_id": 2}
    back = parse_target(c.result("config.render", outbound=ob)["uri"])
    assert (back.port, back.alter_id) == ("8443", "2")


def test_render_ignores_client_supplied_raw():
    c = Client()
    ob = {**parsed(c, VLESS_TLS_WS), "raw": "vless://evil"}
    assert "evil" not in c.result("config.render", outbound=ob)["uri"]


def test_render_requires_an_object():
    assert Client().call("config.render", outbound="x")["error"]["code"] == -32602


# ---------------------------------------------------------------- from_json
def test_from_json_roundtrip_and_core_support():
    c = Client()
    ob = parsed(c, VLESS_TLS_WS)
    r = c.result("config.from_json", text=json.dumps(ob))
    assert r["outbound"] == ob and r["supports"]["xray"] is True
    assert "raw" not in r["outbound"]


def test_from_json_accepts_tk_style_dump_with_raw_and_int_port():
    c = Client()
    ob = {**parsed(c, VLESS_TLS_WS), "raw": "vless://x", "port": 2053}
    r = c.result("config.from_json", text=json.dumps(ob))
    assert r["outbound"]["port"] == "2053"


@pytest.mark.parametrize("text", [
    "{bad", "[]", "42", "null", '{"scheme":"vless","bogus":1}',
    '{"scheme":"nope"}', '{"scheme":"vless","port":"99999"}',
    '{"scheme":"vless","allow_insecure":"yes"}',
])
def test_from_json_rejects_bad_input(text):
    assert Client().call("config.from_json", text=text)["error"]["code"] == -32602


def test_from_json_requires_a_string():
    assert Client().call("config.from_json", text=5)["error"]["code"] == -32602
