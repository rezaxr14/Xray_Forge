"""MITM-DomainFronting generator tests."""

from __future__ import annotations

import json

import pytest

from xray_forge.core.domainfront import (
    build_config, write_config, openssl_command, setup_guide,
    default_options, ROUTE_GROUPS,
)


def test_config_structure_defaults():
    cfg = build_config()
    inb_tags = [i["tag"] for i in cfg["inbounds"]]
    assert "mixed-in" in inb_tags
    assert "tls-decrypt-h11" in inb_tags and "tls-decrypt-h211" in inb_tags
    # tunnel inbounds issue certificates from the personal CA
    for tag in ("tls-decrypt-h11", "tls-decrypt-h211"):
        inb = next(i for i in cfg["inbounds"] if i["tag"] == tag)
        cert = inb["streamSettings"]["tlsSettings"]["certificates"][0]
        assert cert["usage"] == "issue"
        assert cert["certificateFile"] == "mycert.crt"
        assert cert["keyFile"] == "mycert.key"
    out_tags = [o["tag"] for o in cfg["outbounds"]]
    for needed in ("tls-repack-google", "tls-repack-meta", "tls-repack-fastly",
                   "tls-repack-dns", "direct", "block"):
        assert needed in out_tags
    # repack outbounds use the fromMitM verification + chrome fingerprint
    google = next(o for o in cfg["outbounds"] if o["tag"] == "tls-repack-google")
    tls = google["streamSettings"]["tlsSettings"]
    assert tls["serverName"] == "www.google.com"
    assert tls["alpn"] == ["fromMitM"]
    assert tls["verifyPeerCertByName"].startswith("fromMitM")
    assert tls["fingerprint"] == "chrome"
    assert cfg["fakedns"]


def test_routing_rules():
    cfg = build_config()
    rules = cfg["routing"]["rules"]
    tags = [r["outboundTag"] for r in rules]
    assert "block" in tags and "direct" in tags
    # ir/private traffic goes direct
    direct = next(r for r in rules if r.get("outboundTag") == "direct"
                  and "domain" in r)
    assert "domain:ir" in direct["domain"]
    # ads blocked first
    assert rules[0]["outboundTag"] == "block"


def test_group_filtering():
    cfg = build_config(groups=["google"])
    out_tags = [o["tag"] for o in cfg["outbounds"]]
    assert "tls-repack-google" in out_tags
    assert "tls-repack-meta" not in out_tags
    assert "tls-repack-fastly" not in out_tags


def test_overrides():
    cfg = build_config(socks_port=2080, cert_file="c.crt", key_file="k.key")
    mixed = next(i for i in cfg["inbounds"] if i["tag"] == "mixed-in")
    assert mixed["port"] == 2080
    cert = cfg["inbounds"][1]["streamSettings"]["tlsSettings"]["certificates"][0]
    assert cert["certificateFile"] == "c.crt"
    assert cert["keyFile"] == "k.key"


def test_write_config_valid_json(tmp_path):
    path = tmp_path / "mdf.json"
    write_config(str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["remarks"].startswith("Xray-Forge")


def test_route_groups_cover_fronting_friendly_services():
    assert set(ROUTE_GROUPS) >= {"google", "meta", "fastly"}
    for g in ROUTE_GROUPS.values():
        assert g["cover_sni"]
        assert g["verify"].startswith("fromMitM")
        assert g["domains"]


def test_default_options_consistent():
    o = default_options()
    assert o["h11_port"] != o["h2_port"] != o["socks_port"]
    assert o["groups"] == list(ROUTE_GROUPS.keys())


def test_openssl_command():
    cmd = openssl_command("Test CA")
    assert "openssl" in cmd and "keyCertSign" in cmd
    assert "mycert.crt" in cmd and "mycert.key" in cmd


def test_setup_guides():
    for platform, needle in (("windows", "Trusted Root"),
                             ("android", "v2rayNG"),
                             ("firefox", "Authorities")):
        guide = setup_guide(platform)
        assert needle in guide
    # security warning present in all guides
    for p in ("windows", "android", "firefox"):
        assert "never share" in setup_guide(p)


def test_ca_generation_optional():
    cryptography = pytest.importorskip("cryptography")
    import tempfile, os
    from xray_forge.core.domainfront import generate_ca
    with tempfile.TemporaryDirectory() as td:
        crt = os.path.join(td, "t.crt")
        key = os.path.join(td, "t.key")
        generate_ca("Test CA", crt, key)
        with open(crt, "r", encoding="utf-8") as f:
            assert "BEGIN CERTIFICATE" in f.read()
        with open(key, "r", encoding="utf-8") as f:
            assert "PRIVATE KEY" in f.read()
