"""Verified fetches over a real local TLS server (no mocks)."""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from xray_forge.core import probe                       # noqa: E402
from xray_forge.core.probe import ProbeError, direct_get_text, tls_connect  # noqa: E402
from tests.localserver import LocalServer               # noqa: E402

ROUTES = {
    "/sub": (200, {}, b"hello-sub", True),
    "/a": (302, {"Location": "/b"}, b"", True),
    "/b": (200, {}, b"final", True),
    "/to-file": (302, {"Location": "file:///etc/passwd"}, b"", True),
    "/loop": (302, {"Location": "/loop"}, b"", True),
    "/big": (200, {}, b"x" * 100_000, True),
    "/stream": (200, {}, b"y" * 50_000, False),      # close-delimited body
    "/gone": (404, {}, b"missing", True),
}


@pytest.fixture
def https(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "doh_resolve", lambda host, timeout=4.0: [])
    srv = LocalServer(str(tmp_path), ROUTES, tls=True)
    yield srv
    srv.close()


def test_verified_fetch_accepts_trusted_ca(https):
    assert direct_get_text(https.base + "/sub", cafile=https.cafile) == "hello-sub"


def test_verified_fetch_rejects_untrusted_certificate(https):
    # The same server, but nobody told us to trust its CA -> must refuse.
    with pytest.raises(ProbeError, match="certificate rejected"):
        direct_get_text(https.base + "/sub")


def test_tls_connect_verify_checks_ip_san(https):
    tc, sock, _ = tls_connect("127.0.0.1", str(https.port), sni=None,
                              verify=True, cafile=https.cafile)
    sock.close()
    with pytest.raises(ProbeError):
        tls_connect("127.0.0.1", str(https.port), sni=None, verify=True)


def test_probe_mode_still_accepts_unverified(https):
    """Default (verify=False) is for censorship probing and must keep working."""
    tc, sock, info = tls_connect("127.0.0.1", str(https.port), sni=None)
    sock.close()
    assert info["ver"]


def test_unverified_fetch_is_explicit_opt_in(https):
    assert direct_get_text(https.base + "/sub", verify=False) == "hello-sub"


def test_redirects_are_followed(https):
    assert direct_get_text(https.base + "/a", cafile=https.cafile) == "final"


def test_redirect_to_file_scheme_is_refused(https):
    with pytest.raises(ProbeError, match="http/https"):
        direct_get_text(https.base + "/to-file", cafile=https.cafile)


def test_redirect_loop_is_bounded(https):
    with pytest.raises(ProbeError, match="redirects"):
        direct_get_text(https.base + "/loop", cafile=https.cafile)


def test_response_size_cap(https):
    with pytest.raises(ProbeError) as ei:
        direct_get_text(https.base + "/big", cafile=https.cafile, max_bytes=1000)
    assert ei.value.stage == "size"


def test_close_delimited_body_is_read_completely(https):
    body = direct_get_text(https.base + "/stream", cafile=https.cafile)
    assert body == "y" * 50_000


def test_http_error_status_raises(https):
    with pytest.raises(ProbeError, match="404"):
        direct_get_text(https.base + "/gone", cafile=https.cafile)


def test_plain_http_works(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "doh_resolve", lambda host, timeout=4.0: [])
    srv = LocalServer(str(tmp_path), ROUTES, tls=False)
    try:
        assert direct_get_text(srv.base + "/sub") == "hello-sub"
    finally:
        srv.close()


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x",
                                 "javascript:alert(1)", "http:///nohost"])
def test_non_http_urls_are_refused(url):
    with pytest.raises(ProbeError):
        direct_get_text(url)
