"""Secrets are written owner-only; the MITM CA is short-lived and constrainable."""

from __future__ import annotations

import os
import stat
import sys

import pytest

from xray_forge.core.fsutil import write_private

posix_only = pytest.mark.skipif(sys.platform.startswith("win"),
                                reason="POSIX mode bits")


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


@posix_only
def test_write_private_is_owner_only(tmp_path):
    p = tmp_path / "sub" / "secret.json"
    write_private(str(p), "hello")
    assert p.read_text() == "hello"
    assert _mode(p) == 0o600


@posix_only
def test_write_private_tightens_existing_file(tmp_path):
    p = tmp_path / "s"
    p.write_text("old")
    os.chmod(p, 0o666)
    write_private(str(p), b"new")
    assert p.read_bytes() == b"new" and _mode(p) == 0o600


def test_write_private_leaves_no_temp_files(tmp_path):
    d = tmp_path / "clean"
    d.mkdir()
    write_private(str(d / "a"), "x")
    assert [f.name for f in d.iterdir()] == ["a"]


@posix_only
def test_warp_account_saved_private(tmp_path, monkeypatch):
    from xray_forge.core import settings, warp
    monkeypatch.setattr(settings, "data_dir", lambda: str(tmp_path))
    acct = warp.WarpAccount(private_key="k", device_id="i", token="t")
    path = warp.save_account(acct)
    assert _mode(path) == 0o600


@posix_only
def test_settings_saved_private(tmp_path, monkeypatch):
    from xray_forge.core import settings
    monkeypatch.setattr(settings, "settings_path", lambda: str(tmp_path / "s.json"))
    settings.save_settings({"a": 1})
    assert _mode(tmp_path / "s.json") == 0o600


def test_ca_defaults_and_permissions(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography import x509
    from xray_forge.core.domainfront import generate_ca
    crt, key = generate_ca("T", str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
    cert = x509.load_pem_x509_certificate(open(crt, "rb").read())
    life = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert life.days <= 366
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.NameConstraints)
    if not sys.platform.startswith("win"):
        assert _mode(key) == 0o600


def test_ca_name_constrained(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography import x509
    from xray_forge.core.domainfront import generate_ca
    crt, _ = generate_ca("T", str(tmp_path / "c.pem"), str(tmp_path / "k.pem"),
                         permitted_domains=["example.com", "*.cdn.test"])
    cert = x509.load_pem_x509_certificate(open(crt, "rb").read())
    ext = cert.extensions.get_extension_for_class(x509.NameConstraints)
    assert ext.critical
    assert sorted(n.value for n in ext.value.permitted_subtrees) == \
        ["cdn.test", "example.com"]
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca
