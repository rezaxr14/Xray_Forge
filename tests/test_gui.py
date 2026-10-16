"""
GUI interaction tests — the harness beyond the boot smoke test.

Skips automatically when tkinter or a display is unavailable (headless CI
runs these explicitly under ``xvfb-run``).  All per-user state (settings,
sources, scans) is redirected into tmp dirs by ``tests/conftest.py``.
"""

from __future__ import annotations

import pytest

tk = pytest.importorskip("tkinter")

from tests.fixtures import VLESS_TLS_WS, TROJAN_TLS  # noqa: E402


@pytest.fixture(scope="module")
def app():
    """One App instance for the whole module.

    Creating many sequential Tk roots in a single process occasionally trips
    Tcl re-initialization ("Can't find a usable tk.tcl") — sharing one root
    avoids that and is much faster.  A single retry absorbs first-boot
    flakiness; a real headless environment skips the module.
    """
    from xray_forge.app import App
    a = None
    last_err: Exception | None = None
    for _ in range(2):
        try:
            a = App()
            break
        except tk.TclError as e:  # headless: no $DISPLAY / no window station
            last_err = e
    if a is None:
        pytest.skip(f"no usable display: {last_err}")
    yield a
    try:
        a.update()
        a.destroy()
    except Exception:
        pass


def _feed(app, *lines: str) -> None:
    app.input_txt.delete("1.0", "end")
    app.input_txt.insert("1.0", "\n".join(lines))
    app.do_convert()


# ------------------------------------------------------------------- boot

def test_boot_tabs(app):
    texts = [app.nb.tab(t, "text") for t in app.nb.tabs()]
    assert any("Configs" in t for t in texts)
    assert any("Tester" in t for t in texts)
    assert any("Subscriptions" in t for t in texts)
    assert any("IP Finder" in t for t in texts)


def test_settings_capture_includes_new_tabs(app):
    s = app._capture_settings()
    for key in ("sub_core_var", "sub_workers_var", "sub_thr_var",
                "scan_session_var", "scan_geo_var"):
        assert key in s


# --------------------------------------------------------------- converter

def test_convert_updates_output_and_counts(app):
    _feed(app, VLESS_TLS_WS)
    out = app.output_txt.get("1.0", "end-1c")
    assert "vless://" in out
    assert app.v_fixed.get().startswith("✎")


def test_tester_list_follows_conversion(app):
    _feed(app, VLESS_TLS_WS, TROJAN_TLS)
    assert len(app.test_tree.get_children("")) == 2


def test_apply_test_result_formats_row(app):
    _feed(app, VLESS_TLS_WS)
    iid = app.test_tree.get_children("")[0]
    app._apply_test_result(iid, {"name": "x", "tcp": 12.4, "tls": None,
                                 "ws": 33.3, "real": 150.0, "cc": "NL",
                                 "ip": "1.2.3.4", "status": "ok"})
    assert app.test_tree.set(iid, "tcp") == "12"
    assert app.test_tree.set(iid, "tls") == "—"
    assert app.test_tree.set(iid, "cc") == "NL"


# ----------------------------------------------------------- subscriptions

def test_subs_source_list_roundtrip(app):
    from xray_forge.core.sub_source import SourceManager
    mgr = SourceManager()
    mgr.add("https://example.com/sub", "test-src")
    app._subs_refresh_list()
    rows = app.subs_tree.get_children("")
    assert len(rows) == 1
    assert app.subs_tree.set(rows[0], "url") == "https://example.com/sub"
    assert app.subs_tree.set(rows[0], "name") == "test-src"


def test_subs_check_without_cache_reports_missing(app):
    app._subs_check()
    assert "fetch first" in app.sub_status_var.get()


def test_subs_results_tree_fills_from_reports(app):
    from xray_forge.core import healthcheck as hc
    rep = hc.HealthReport(line=VLESS_TLS_WS, name="node-a", scheme="vless")
    rep.stages = [hc.StageResult("request", True, ms=120.0),
                  hc.StageResult("download", True, data={"bps": 2_400_000})]
    rep.score = 42
    app._sub_reports = [rep]
    app._subs_fill_results()
    rows = app.subres_tree.get_children("")
    assert len(rows) == 1
    assert app.subres_tree.set(rows[0], "name") == "node-a"
    assert app.subres_tree.set(rows[0], "score") == "42"
    assert app.subres_tree.set(rows[0], "down") == "2.3MB/s"


def test_fmt_bps():
    from xray_forge.app import _fmt_bps
    from xray_forge.core import healthcheck as hc
    assert _fmt_bps(None) == "—"
    assert _fmt_bps(hc.StageResult("up", False)) == "—"
    s = hc.StageResult("up", True, data={"bps": 524288})
    assert _fmt_bps(s) == "512KB/s"
    s = hc.StageResult("up", True, data={"bps": 1_500_000})
    assert _fmt_bps(s) == "1.4MB/s"


# ------------------------------------------------------------- scan sessions

def test_scan_session_load_populates_tree(app):
    from xray_forge.core.scan_session import ScanResult, ScanSession
    s = ScanSession("guitest")
    s.results["203.0.113.1"] = ScanResult(
        ip="203.0.113.1", port="443", alive=True, ms=42.0, jitter=3.0,
        tls="TLSv1.3", cc="NL", info="ok")
    s.pending = ["203.0.113.2"]
    s.save()
    app.scan_load_var.set("guitest")
    app._scan_load_session()
    rows = app.res_tree.get_children("")
    assert len(rows) == 1
    assert app.res_tree.set(rows[0], "ip") == "203.0.113.1"
    assert app.res_tree.set(rows[0], "jitter") == "3"
    assert app.res_tree.set(rows[0], "cc") == "NL"


def test_scan_sessions_refresh_lists_saved(app):
    from xray_forge.core.scan_session import ScanSession
    ScanSession("alpha").save()
    ScanSession("beta").save()
    app._scan_sessions_refresh()
    values = app.sessions_cb.cget("values")
    assert "alpha" in values and "beta" in values
