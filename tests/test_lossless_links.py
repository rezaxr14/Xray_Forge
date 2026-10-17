"""parse -> (edit) -> to_uri must never silently drop share-link parameters."""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qsl, quote, urlsplit

import pytest

from xray_forge.core.models import Outbound
from xray_forge.core.parser import parse_target
from xray_forge.core.protocols import handler_for

U = "13b8ac3f-e8de-4b2d-82db-e9130d288a54"
XMUX = quote(json.dumps({"xmux": {"maxConcurrency": 16}, "xPaddingBytes": "100-1000"}),
             safe="")

LINKS = {
    "vless-xhttp-extra": (
        f"vless://{U}@1.2.3.4:443?security=tls&sni=a.com&type=xhttp&mode=packet-up"
        f"&path=%2Fp&host=a.com&extra={XMUX}&alpn=h2&fp=chrome#x"),
    "vless-reality-pqv": (
        f"vless://{U}@1.2.3.4:443?security=reality&pbk=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
        "&sid=ab12&sni=a.com&fp=chrome&flow=xtls-rprx-vision&spx=%2F&pqv=XYZ123&type=tcp#r"),
    "vless-tls-ech-pin": (
        f"vless://{U}@1.2.3.4:443?security=tls&sni=a.com&type=ws&path=%2F"
        "&ech=AEX_abc&pcs=deadbeef&vcn=a.com&fm=%7B%22t%22%3A1%7D#e"),
    "vless-grpc-mode-authority": (
        f"vless://{U}@1.2.3.4:443?security=tls&sni=a.com&type=grpc&serviceName=s"
        "&mode=multi&authority=a.com#g"),
    "vless-encryption-mlkem": (
        f"vless://{U}@1.2.3.4:443?encryption=mlkem768x25519plus.native.0rtt.KEYDATA"
        "&security=none&type=tcp&flow=xtls-rprx-vision#vle"),
    "trojan-flow-spx-cs": (
        "trojan://pw@1.2.3.4:443?security=reality&pbk=KEY&sid=ab&spx=%2Fx&flow=xtls-rprx-vision"
        "&cs=TLS_AES_128_GCM_SHA256&sni=a.com&type=tcp&future=1#t"),
    "hysteria2-extras": (
        "hysteria2://pw@1.2.3.4:443?sni=a.com&insecure=1&pinSHA256=AA%3ABB&mport=20000-30000"
        "&obfs=salamander&obfs-password=op#h"),
    "tuic-extras": (
        "tuic://id:pw@1.2.3.4:443?sni=a.com&alpn=h3&congestion_control=bbr"
        "&udp_relay_mode=native&disable_sni=1&reduce_rtt=1#tu"),
    "ss-extras": (
        "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=")
        + "@1.2.3.4:8388?plugin=v2ray-plugin&uot=1#s"),
}


def _qs(link: str) -> dict[str, str]:
    return {k.lower(): v for k, v in parse_qsl(urlsplit(link).query,
                                               keep_blank_values=True)}


@pytest.mark.parametrize("name", sorted(LINKS))
def test_no_query_param_is_lost_or_changed(name):
    link = LINKS[name]
    out = parse_target(link)
    assert out is not None
    back = handler_for(out.scheme).to_uri(out)
    before, after = _qs(link), _qs(back)
    lost = {k: v for k, v in before.items() if k not in after}
    changed = {k: (v, after[k]) for k, v in before.items()
               if k in after and after[k] != v}
    assert not lost, f"{name}: dropped {lost}"
    assert not changed, f"{name}: altered {changed}"


@pytest.mark.parametrize("name", sorted(LINKS))
def test_second_round_trip_is_stable(name):
    out1 = parse_target(LINKS[name])
    link2 = handler_for(out1.scheme).to_uri(out1)
    out2 = parse_target(link2)
    assert out2.extra_params == out1.extra_params
    assert handler_for(out2.scheme).to_uri(out2) == link2


def test_unmodeled_params_land_in_extra_params():
    out = parse_target(LINKS["vless-tls-ech-pin"])
    assert out.extra_params == {"ech": "AEX_abc", "pcs": "deadbeef",
                                "vcn": "a.com", "fm": '{"t":1}'}


def test_vless_encryption_none_is_not_kept_but_real_encryption_is():
    plain = parse_target(f"vless://{U}@1.2.3.4:443?encryption=none&type=tcp#a")
    assert "encryption" not in plain.extra_params
    real = parse_target(LINKS["vless-encryption-mlkem"])
    assert real.extra_params["encryption"].startswith("mlkem768x25519plus")
    ob = handler_for("vless").xray_outbound(real)
    assert ob["settings"]["vnext"][0]["users"][0]["encryption"].startswith("mlkem")


def test_clearing_a_modeled_field_does_not_resurrect_it():
    """Editor semantics: emptying `sni` must really remove it."""
    out = parse_target(LINKS["vless-xhttp-extra"])
    edited = out.copy_with(sni="", alpn="")
    back = handler_for("vless").to_uri(edited)
    q = _qs(back)
    assert "sni" not in q and "alpn" not in q
    assert "extra" in q                      # the unmodeled one survives


def test_edited_value_beats_extra_params():
    out = parse_target(LINKS["vless-reality-pqv"])
    edited = out.copy_with(short_id="ff00")
    assert _qs(handler_for("vless").to_uri(edited))["sid"] == "ff00"


def test_outbound_dict_round_trip_keeps_extra_params():
    """The editor's raw-JSON pane goes through to_dict/from_dict."""
    out = parse_target(LINKS["vless-xhttp-extra"])
    again = Outbound.from_dict(json.loads(json.dumps(out.to_dict())))
    assert again.extra_params == out.extra_params
    assert again == out


def test_vmess_unknown_json_keys_survive():
    payload = {"v": "2", "ps": "n", "add": "1.2.3.4", "port": "443", "id": U,
               "aid": "0", "net": "ws", "path": "/", "tls": "tls",
               "future_field": "keep-me"}
    link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
    out = parse_target(link)
    assert out.extra_params == {"future_field": "keep-me"}
    back = handler_for("vmess").to_uri(out)
    data = json.loads(base64.b64decode(back[len("vmess://"):]))
    assert data["future_field"] == "keep-me"


@pytest.mark.parametrize("raw,expected", [
    ("", "tcp"), ("tcp", "tcp"), ("raw", "tcp"),
    ("splithttp", "xhttp"), ("xhttp", "xhttp"), ("ws", "ws"), ("grpc", "grpc"),
])
def test_transport_defaults_and_aliases(raw, expected):
    q = f"&type={raw}" if raw else ""
    out = parse_target(f"vless://{U}@1.2.3.4:443?security=tls{q}#x")
    assert out.transport == expected


def test_reality_link_without_type_is_tcp_not_ws():
    out = parse_target(f"vless://{U}@1.2.3.4:443?security=reality&pbk=K&sid=1"
                       "&sni=a.com&flow=xtls-rprx-vision#r")
    assert out.transport == "tcp"
