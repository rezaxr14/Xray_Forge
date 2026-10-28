"""Converter rules over the engine API (Electron Convert tab, step 5.1)."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fixtures import SS_SIP002, TROJAN_TLS, VLESS_REALITY, VLESS_TLS_WS, VMESS_B64
from tests.test_engine import Client
from xray_forge.core.config import DEFAULT_CS, DEFAULT_FM, TEMPLATE_KEYS
from xray_forge.core.parser import parse_target, tag_name_with_cc

NO_INJECT = dict(want_fp=False, want_cs=False, want_fm=False)


def q(line: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(line).query, keep_blank_values=True).items()}


def convert(**kw):
    return Client().result("config.convert", **kw)


# ----------------------------------------------------------- injection rules
def test_full_fix_injects_fp_cs_fm():
    line = convert(text=VLESS_TLS_WS, fp="firefox")["lines"][0]
    p = q(line)
    assert p["fp"] == "firefox" and p["cs"] == DEFAULT_CS
    assert json.loads(p["fm"]) == DEFAULT_FM


def test_want_flags_choose_what_is_injected():
    p = q(convert(text=VLESS_TLS_WS, want_cs=False, want_fm=False)["lines"][0])
    assert p["fp"] == "chrome" and "cs" not in p and "fm" not in p
    p = q(convert(text=VLESS_TLS_WS, want_fp=False, want_fm=False)["lines"][0])
    assert "cs" in p and "fm" not in p


def test_ip_only_mode_injects_nothing_but_overrides_endpoint():
    r = convert(text=VLESS_TLS_WS, ip="9.9.9.9", port="2053", **NO_INJECT)
    line = r["lines"][0]
    p = q(line)
    assert "cs" not in p and "fm" not in p
    assert p["sni"] == "edgestuff.pages.dev" and p["host"] == "edgestuff.pages.dev"
    out = parse_target(line)
    assert (out.host, out.port) == ("9.9.9.9", "2053")


def test_tls_only_skips_reality_when_injecting_but_not_in_ip_only():
    r = convert(text=VLESS_REALITY, tls_only=True)
    assert r["counts"]["skipped"] == 1 and r["lines"] == [VLESS_REALITY]
    r = convert(text=VLESS_REALITY, tls_only=False)
    assert r["counts"]["skipped"] == 0 and "cs" in q(r["lines"][0])
    r = convert(text=VLESS_REALITY, tls_only=True, **NO_INJECT)
    assert r["counts"]["skipped"] == 0


def test_force_port_only_and_force_ip_only_keep_the_other_value():
    base = parse_target(VLESS_TLS_WS)
    out = parse_target(convert(text=VLESS_TLS_WS, port="8443", **NO_INJECT)["lines"][0])
    assert (out.host, out.port) == (base.host, "8443")
    out = parse_target(convert(text=VLESS_TLS_WS, ip="example.org", **NO_INJECT)["lines"][0])
    assert (out.host, out.port) == ("example.org", base.port)


def test_force_ipv6_is_bracketed():
    out = parse_target(convert(text=VLESS_TLS_WS, ip="2001:db8::1", **NO_INJECT)["lines"][0])
    assert out.host == "2001:db8::1"


# ------------------------------------------------------------------- naming
def test_rename_template_and_start_number():
    r = convert(text=VLESS_TLS_WS + "\n" + TROJAN_TLS, template="cfg{id:03d}_{proto}", start=10)
    assert [n["name"] for n in r["names"]] == ["cfg011_vless", "cfg012_trojan"]
    assert parse_target(r["lines"][0]).name == "cfg011_vless"


def test_rename_off_keeps_original_names():
    r = convert(text=VLESS_TLS_WS, rename=False)
    assert parse_target(r["lines"][0]).name == "CF worker"


def test_names_report_the_real_link_name_when_rename_is_off():
    r = convert(text=VLESS_TLS_WS, rename=False)
    assert r["names"] == [{"name": "CF worker", "line": r["lines"][0]}]


def test_blank_template_falls_back_to_default():
    r = convert(text=VLESS_TLS_WS, template="   ")
    assert r["names"][0]["name"].startswith("02_")


def test_names_follow_output_after_dedup():
    r = convert(text=VLESS_TLS_WS + "\n" + VLESS_TLS_WS + "\n" + TROJAN_TLS, dedup=True)
    assert r["removed"] == 1 and len(r["lines"]) == 2
    assert [n["line"] for n in r["names"]] == r["lines"]


def test_skipped_lines_have_no_name_entry():
    r = convert(text="garbage\n" + VLESS_TLS_WS)
    assert r["counts"]["skipped"] == 1 and len(r["names"]) == 1


def test_engine_info_lists_template_keys():
    info = Client().result("engine.info")
    assert info["template_keys"] == list(TEMPLATE_KEYS)
    # every advertised key must actually be usable in a template
    tpl = "_".join("{" + k + "}" for k in TEMPLATE_KEYS)
    assert Client().result("config.convert", text=VLESS_TLS_WS, template=tpl)["names"][0]["name"]


# --------------------------------------------------------------- validation
@pytest.mark.parametrize("params", [
    dict(ip="not an ip!"), dict(ip="-bad.example"), dict(port="0"), dict(port="65536"),
    dict(port="http"), dict(start=-1), dict(start=100000), dict(start="x"),
    dict(start=True), dict(fm="{not json"), dict(fm="42"), dict(fp=5), dict(cs=None),
    dict(template=7), dict(rename="yes"), dict(dedup=1), dict(want_fp="no"),
])
def test_invalid_rule_params_are_rejected(params):
    resp = Client().call("config.convert", text=VLESS_TLS_WS, **params)
    assert resp["error"]["code"] == -32602, resp


def test_bad_fm_is_fine_when_fm_injection_is_off():
    r = convert(text=VLESS_TLS_WS, fm="{not json", want_fm=False)
    assert "fm" not in q(r["lines"][0])


def test_override_accepts_int_port_and_blank_values():
    r = convert(text=VLESS_TLS_WS, ip="", port=8443, **NO_INJECT)
    assert parse_target(r["lines"][0]).port == "8443"


def test_non_proxy_schemes_pass_through_untouched():
    r = convert(text=SS_SIP002 + "\nwireguard://x@1.1.1.1:51820", ip="9.9.9.9")
    assert r["counts"]["skipped"] >= 1


# ----------------------------------------------------------- check_override
def test_check_override_classifies():
    c = Client()
    assert c.result("config.check_override", ip="1.2.3.4", port="443") == {"ip": "ipv4", "port": True}
    assert c.result("config.check_override", ip="::1", port="0") == {"ip": "ipv6", "port": False}
    assert c.result("config.check_override", ip="a.example.com")["ip"] == "domain"
    assert c.result("config.check_override", ip="nope nope")["ip"] is None
    assert c.result("config.check_override") == {"ip": "", "port": None}
    assert c.call("config.check_override", ip=[1])["error"]["code"] == -32602


# ----------------------------------------------------------------- tag [CC]
def test_tag_name_with_cc_link_schemes():
    new, name, changed = tag_name_with_cc(VLESS_TLS_WS, "de")
    assert changed and name == "CF worker[DE]"
    assert parse_target(new).name == "CF worker[DE]"
    assert urlsplit(new).query == urlsplit(VLESS_TLS_WS).query   # query untouched
    again, name2, changed2 = tag_name_with_cc(new, "DE")
    assert not changed2 and again == new and name2 == name


def test_tag_name_with_cc_vmess_roundtrips_through_handler():
    new, name, changed = tag_name_with_cc(VMESS_B64, "us")
    assert changed and name == "vm-test[US]"
    out = parse_target(new)
    assert out.name == "vm-test[US]" and out.host == "104.18.1.1"
    assert tag_name_with_cc(new, "US")[2] is False


@pytest.mark.parametrize("cc", ["", "D", "DEU", "1A", None])
def test_tag_name_with_cc_ignores_bad_codes(cc):
    new, name, changed = tag_name_with_cc(VLESS_TLS_WS, cc)
    assert not changed and new == VLESS_TLS_WS.strip()


def test_tag_name_with_cc_ignores_garbage():
    assert tag_name_with_cc("not a link", "DE") == ("not a link", "", False)
    assert tag_name_with_cc("vmess://!!!", "DE")[2] is False
    assert tag_name_with_cc("http://example.com/#x", "DE")[2] is False


def test_tag_cc_method():
    c = Client()
    r = c.result("config.tag_cc", items=[
        {"line": VLESS_TLS_WS, "cc": "DE"}, {"line": TROJAN_TLS, "cc": ""},
        {"line": VMESS_B64, "cc": "nl"}])
    assert r["tagged"] == 2
    assert [i["changed"] for i in r["items"]] == [True, False, True]
    assert r["items"][1]["line"] == TROJAN_TLS
    for bad in ([{"line": 1, "cc": "DE"}], [{"line": "x", "cc": 5}], ["x"], "x"):
        assert c.call("config.tag_cc", items=bad)["error"]["code"] == -32602
