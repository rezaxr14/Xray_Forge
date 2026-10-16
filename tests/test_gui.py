"""
GUI interaction tests — the harness beyond the boot smoke test.

Skips automatically when tkinter or a display is unavailable (headless CI
runs these explicitly under ``xvfb-run``).  All per-user state (settings,
sources, scans) is redirected into tmp dirs by ``tests/conftest.py``.
"""

from __future__ import annotations

import json

import pytest

tk = pytest.importorskip("tkinter")

from tests.fixtures import VLESS_TLS_WS, VLESS_REALITY, TROJAN_TLS  # noqa: E402


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


# -------------------------------------------------------------------- editor

def test_editor_loads_reality_fields(app):
    _feed(app, VLESS_REALITY)
    assert app.ed_scheme_var.get() == "vless"
    assert app.ed_security_var.get() == "reality"
    assert app.ed_pbk_var.get() == "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
    assert app.ed_sid_var.get() == "6ba85179"
    assert app.ed_flow_var.get() == "xtls-rprx-vision"
    # the raw JSON pane mirrors the loaded Outbound
    data = json.loads(app.ed_json_txt.get("1.0", "end-1c"))
    assert data["public_key"] == app.ed_pbk_var.get()
    assert data["security"] == "reality"


def test_editor_apply_rewrites_output_line(app):
    _feed(app, VLESS_REALITY)
    app.ed_port_var.set("8443")
    app.ed_name_var.set("edited-node")
    app._editor_apply()
    line = app.output_txt.get("1.0", "end-1c").splitlines()[0]
    assert ":8443" in line and "edited-node" in line
    # tester targets and names follow the edit
    assert app._targets[0].port == "8443"
    assert any(n == "edited-node" for n, _l in app._name_lines)
    # the picker label reflects the new name
    assert "edited-node" in app.ed_pick_cb.cget("values")[0]


def test_editor_json_roundtrip(app):
    _feed(app, VLESS_TLS_WS)
    data = json.loads(app.ed_json_txt.get("1.0", "end-1c"))
    data["path"] = "/viajson"
    data["flow"] = "xtls-rprx-vision"
    app.ed_json_txt.delete("1.0", "end")
    app.ed_json_txt.insert("1.0", json.dumps(data))
    app._editor_from_json()
    assert app.ed_path_var.get() == "/viajson"
    assert app.ed_flow_var.get() == "xtls-rprx-vision"
    app._editor_apply()
    line = app.output_txt.get("1.0", "end-1c").splitlines()[0]
    assert "%2Fviajson" in line and "flow=xtls-rprx-vision" in line


def test_editor_xhttp_mode_roundtrip(app):
    _feed(app, VLESS_TLS_WS)
    app.ed_transport_var.set("xhttp")
    app.ed_mode_var.set("stream-one")
    app._editor_apply()
    line = app.output_txt.get("1.0", "end-1c").splitlines()[0]
    assert "type=xhttp" in line and "mode=stream-one" in line
    assert app._targets[0].extra["mode"] == "stream-one"


def test_editor_form_to_json(app):
    _feed(app, VLESS_REALITY)
    app.ed_pbk_var.set("NEWKEY=")
    app._editor_to_json()
    data = json.loads(app.ed_json_txt.get("1.0", "end-1c"))
    assert data["public_key"] == "NEWKEY="


def test_editor_bad_json_reports_error(app):
    _feed(app, VLESS_TLS_WS)
    app.ed_json_txt.delete("1.0", "end")
    app.ed_json_txt.insert("1.0", "{not json")
    app._editor_from_json()
    assert "bad JSON" in app.ed_status_var.get()


def test_editor_refresh_clears_without_configs(app):
    _feed(app, "this is not a config line")
    assert app._editor_items == []
    assert "no convertible config" in app.ed_status_var.get()


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


# ---------------------------------------------------------------- sni search

def test_snis_tab_and_presets(app):
    texts = [app.nb.tab(t, "text") for t in app.nb.tabs()]
    assert any("SNI Search" in t for t in texts)
    app.snis_names_var.set("a.example")
    app._snis_presets()
    assert "a.example" in app.snis_names_var.get()
    assert "www.speedtest.net" in app.snis_names_var.get()


def test_snis_from_results_pulls_scan_ips(app):
    from xray_forge.core.scan_session import ScanResult, ScanSession
    s = ScanSession("guisnis")
    s.results["203.0.113.9"] = ScanResult(ip="203.0.113.9", port="443",
                                          alive=True, ms=12.0)
    s.results["203.0.113.8"] = ScanResult(ip="203.0.113.8", port="443",
                                          alive=True, ms=40.0)
    s.save()
    app.scan_load_var.set("guisnis")
    app._scan_load_session()
    app.snis_ips_var.set("")
    app._snis_from_results()
    ips = app.snis_ips_var.get().split()
    assert "203.0.113.9" in ips and "203.0.113.8" in ips


def test_snis_clear_and_settings(app):
    app._snis_clear()
    assert app.snis_prog_var.get() == "0/0"
    s = app._capture_settings()
    for key in ("snis_ips_var", "snis_names_var", "snis_port_var",
                "snis_http_var", "snis_workers_var"):
        assert key in s


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
