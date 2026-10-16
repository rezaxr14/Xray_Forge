"""
Main Tkinter application — ties together all tabs, state, and logic.

Xray Forge — modular edition.  Entry point lives at repo root (xray_forge.py)
while the package (xray_forge/) holds the real code.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.request
import uuid as uuid_mod
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import ttk, filedialog, messagebox, font as tkfont
from typing import Any, Literal
from urllib.parse import (urlsplit, urlunsplit, parse_qsl, urlencode,
                          quote, unquote)
import ipaddress

from xray_forge import __version__
from xray_forge.core.config import (
    MODE_FULL, MODE_IPONLY, MODE_CUSTOM, MODES,
    DEFAULT_FP, DEFAULT_CS, DEFAULT_FM, DEFAULT_TEMPLATE,
    CF_RANGES, FRAG_PRESETS, TEST_TARGET_DEFAULT,
    GEO_VIA_TUNNEL, compact_json,
    FAKE_SNI_PRESETS, DOMAIN_FRONT_FRONTS,
)
from xray_forge.core.parser import (
    convert_block, fix_uri, parse_target, classify_endpoint,
    valid_port, is_ip, cc_flag, cc_cell, fmt_ms,
    export_to_clash, export_to_singbox, export_to_sub,
)
from xray_forge.core.settings import load_settings, save_settings
from xray_forge.core.models import Outbound
from xray_forge.core.protocols import handler_for
from xray_forge.core.subscription import fetch_subscription
from xray_forge.core.dedup import dedup_configs
from xray_forge.core.prober_utils import cc_cell as _cc_cell, cc_flag as _cc_flag
from xray_forge.core.probe import (
    ProbeError, tls_connect, tcp_ping, TLSClient, ws_frame, ws_send,
    ws_recv_frame, ws_upgrade, VlessTunnel, _read_http, _dechunk,
    tunnel_http_get, tunnel_https_get, real_delay_http, real_delay_https,
    parse_test_target, _geo_detail, _cc_from_geo, probe_geo_source,
    rotated_geo, doh_resolve, direct_get_json, fetch_json,
    curl_cffi_probe, _random_ua, _mix_sni_case,
)
from xray_forge.core.scanner import (
    resolve_domain, udp_dns_a, resolve_dns_all, cc_of_ip, fmt_geo,
    geo_lookup, sample_cidr,
)
from xray_forge.core.xray_bridge import (
    find_xray_core, check_core_version, build_xray_config,
    socks5_connect, xray_probe,
)
from xray_forge.ui.widgets import Tooltip, Switch
from xray_forge.ui.tabs.converter_tab import build_rules, build_naming, build_override
from xray_forge.ui.tabs.converter_tab import build as build_converter_pane
from xray_forge.ui.tabs.editor_tab import build as build_editor
from xray_forge.ui.tabs.snis_tab import build as build_snis
from xray_forge.ui.tabs.tester_tab import build as build_tester
from xray_forge.ui.tabs.xray_tab import build as build_xray_tab
from xray_forge.ui.tabs.scanner_tab import build as build_scanner
from xray_forge.ui.tabs.subs_tab import build as build_subs

from tkinter import simpledialog  # noqa: F401  (tk.simpledialog usage below)

TextState = Literal["normal", "disabled"]

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
BG, PANEL, PANEL2 = "#0e1117", "#161b22", "#1e2633"
FIELD = "#0a141d"
FG, MUT = "#e6edf3", "#8b949e"
ACCENT, ACCENT_H, ACCENT_FG = "#3fa7ff", "#63b8ff", "#07131f"
GREEN, YELLOW, RED, PURPLE = "#3fb950", "#d29922", "#f85149", "#bc8cff"
MONO, SANS = "Courier", "Helvetica"

SAMPLE = "\n".join([
    "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@188.114.97.6:443?encryption=none&security=tls&sni=edgestuff.pages.dev&fp=chrome&type=ws&host=edgestuff.pages.dev&path=%2Fchannel#CF%E5%AE%98%E6%96%B9%E4%BC%98%E9%80%891",
    "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@104.18.33.142:2083?encryption=none&security=tls&sni=edgestuff.pages.dev&fp=chrome&type=ws&host=edgestuff.pages.dev&path=%2Furls%2Fdoc#CF%E5%AE%98%E6%96%B9%E4%BC%98%E9%80%893",
    "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@8.35.211.156:8443?encryption=none&security=tls&sni=edgestuff.pages.dev&fp=chrome&type=ws&host=edgestuff.pages.dev&path=%2Fcollection#CF%E5%AE%98%E6%96%B9%E4%BC%98%E9%80%896",
])

HAS_CURL_CFFI = False
try:
    import importlib.util
    if importlib.util.find_spec("curl_cffi") is not None:
        HAS_CURL_CFFI = True
except Exception:
    HAS_CURL_CFFI = False


class _Done(Exception):
    pass


def _fmt_bps(stage) -> str:
    """Format a throughput StageResult as KB/s or MB/s ('—' when absent)."""
    if stage is None or not stage.ok:
        return "—"
    bps = (stage.data or {}).get("bps")
    if not bps:
        return "—"
    if bps >= 1_048_576:
        return f"{bps / 1_048_576:.1f}MB/s"
    return f"{bps / 1024:.0f}KB/s"


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(
            f"⚡ VLESS Forge v{__version__} — fix · test · exit-country · "
            f"xray-core · ip scanner · export")
        self.geometry("1400x1000")
        self.minsize(1080, 760)
        self.configure(background=BG)
        self._job: str | None = None
        self._name_lines: list[tuple[str, str]] = []
        self._targets: list[dict[str, Any]] = []
        self._out_dirty = True
        self._testing = False
        self._scanning = False
        self._stop_test = threading.Event()
        self._stop_scan = threading.Event()
        self._test_done = 0
        self._test_total = 0
        self._scan_done = 0
        self._scan_total = 0
        self._scan_alive = 0
        self._scan_iid = 0
        self._scan_meta: dict[str, tuple[str, str, str | None, str]] = {}
        self._scan_frag: tuple | None = None
        self._scan_session = None
        self._test_ex: ThreadPoolExecutor | None = None
        self._scan_ex: ThreadPoolExecutor | None = None
        self._cc_cache: dict[str, str] = {}
        self._cc_lock = threading.Lock()
        self._sub_reports: list = []
        self._sub_stop = threading.Event()
        self._subs_checking = False
        # sni search (candidate SNIs × clean IPs)
        self._stop_snis = threading.Event()
        self._snis_running = False
        self._snis_search = None
        # editor (per-config field editor + raw JSON round-trip)
        self._editor_items: list[tuple[int, str, Outbound]] = []
        self._editor_sel: int | None = None
        self.HAS_CURL_CFFI = HAS_CURL_CFFI
        # settings
        self._settings = load_settings()
        self._build_vars()
        self._build_ui()
        self._apply_settings()
        self._bind_keys()
        self._build_menu()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._schedule()

    # ------------------------------------------------------------------ vars
    def _build_vars(self) -> None:
        a = self
        # mode / rules
        a.mode_var = tk.StringVar(value=MODE_FULL)
        a.fp_on = tk.BooleanVar(value=True)
        a.cs_on = tk.BooleanVar(value=True)
        a.fm_on = tk.BooleanVar(value=True)
        a.rename_var = tk.BooleanVar(value=True)
        a.tls_only_var = tk.BooleanVar(value=False)
        a.fp_var = tk.StringVar(value=DEFAULT_FP)
        a.cs_var = tk.StringVar(value=DEFAULT_CS)
        a.fm_var = tk.StringVar(value=json.dumps(DEFAULT_FM, separators=(",", ":")))
        # naming
        a.tpl_var = tk.StringVar(value=DEFAULT_TEMPLATE)
        a.start_var = tk.IntVar(value=1)
        # override
        a.ip_on = tk.BooleanVar(value=False)
        a.port_on = tk.BooleanVar(value=False)
        a.ip_var = tk.StringVar(value="")
        a.port_var = tk.StringVar(value="")
        a.ip_badge = tk.StringVar(value="")
        a.port_badge = tk.StringVar(value="")
        a.ep_preview = tk.StringVar(value="orig : orig")
        # tester
        a.mode_test_var = tk.StringVar(value="full (ws + REAL delay)")
        a.frag_var = tk.StringVar(value="5,94,1@2")
        a.tmo_var = tk.StringVar(value="8")
        a.att_var = tk.StringVar(value="2")
        a.workers_test_var = tk.StringVar(value="8")
        a.test_prog_var = tk.StringVar(value="0/0")
        a.test_info_var = tk.StringVar(value="idle")
        a.cc_on = tk.BooleanVar(value=True)
        a.target_var = tk.StringVar(value=TEST_TARGET_DEFAULT)
        # censorship evasion (new)
        a.fake_sni_var = tk.StringVar(value="letsencrypt.org")
        a.domain_front_var = tk.StringVar(value="")
        a.record_frag_var = tk.BooleanVar(value=False)
        a.sni_case_var = tk.BooleanVar(value=False)
        # xray core
        a.core_var = tk.StringVar(value="")
        a.core_status_var = tk.StringVar(value="not detected")
        a.core_frag_on = tk.BooleanVar(value=True)
        a.core_workers_var = tk.StringVar(value="4")
        a.core_timeout_var = tk.StringVar(value="8")
        # scanner
        a.scan_cidr_var = tk.StringVar(value=CF_RANGES[0])
        a.scan_count_var = tk.StringVar(value="200")
        a.scan_workers_var = tk.StringVar(value="64")
        a.scan_port_var = tk.StringVar(value="443")
        a.scan_sni_var = tk.StringVar(value="")
        a.sni_mode_var = tk.StringVar(value="config sni")
        a.scan_frag_var = tk.StringVar(value="5,94,1@2")
        a.curl_var = tk.BooleanVar(value=HAS_CURL_CFFI)
        a.geo_ip_var = tk.StringVar(value="")
        a.geo_txt = tk.StringVar(value="")
        a.res_host_var = tk.StringVar(value="")
        a.scan_prog_var = tk.StringVar(value="0/0")
        # scan sessions (resumable, exported to csv/json)
        a.scan_session_var = tk.StringVar(value="")
        a.scan_load_var = tk.StringVar(value="")
        a.scan_resume_var = tk.BooleanVar(value=False)
        a.scan_geo_var = tk.BooleanVar(value=False)
        # subscription / dedup / filter / best
        a.sub_url_var = tk.StringVar(value="")
        a.filter_var = tk.StringVar(value="")
        a.dedup_var = tk.BooleanVar(value=False)
        a.show_best_var = tk.BooleanVar(value=False)
        # subscriptions tab (source manager + staged health checks)
        a.sub_workers_var = tk.StringVar(value="8")
        a.sub_timeout_var = tk.StringVar(value="6")
        a.sub_top_var = tk.StringVar(value="10")
        a.sub_core_var = tk.StringVar(value="auto")
        a.sub_thr_var = tk.BooleanVar(value=True)
        a.sub_status_var = tk.StringVar(value="idle")
        a.sub_prog_var = tk.StringVar(value="0/0")
        # sni search (candidate SNIs × clean IPs)
        a.snis_ips_var = tk.StringVar(value="")
        a.snis_names_var = tk.StringVar(value="")
        a.snis_port_var = tk.StringVar(value="443")
        a.snis_workers_var = tk.StringVar(value="32")
        a.snis_frag_var = tk.StringVar(value="5,94,1@2")
        a.snis_session_var = tk.StringVar(value="")
        a.snis_resume_var = tk.BooleanVar(value=False)
        a.snis_http_var = tk.BooleanVar(value=True)
        a.snis_prog_var = tk.StringVar(value="0/0")
        # counts / status
        a.msg_var = tk.StringVar(
            value="Paste configs on the left — conversion is live. "
                  "Ctrl+Enter forces a run.")
        a.v_fixed = tk.StringVar(value="✎ 0 updated")
        a.v_same = tk.StringVar(value="↺ 0 unchanged")
        a.v_skip = tk.StringVar(value="⚠ 0 skipped")

    # ------------------------------------------------------------------ ui
    def _build_ui(self) -> None:
        a = self
        # style
        style = ttk.Style(a)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background=BG)
        style.configure("TLabelframe", background=BG, foreground=MUT,
                        bordercolor="#30363d")
        style.configure("TLabelframe.Label", background=BG, foreground=MUT)
        style.configure("TButton", background="#212836", foreground=FG,
                        bordercolor="#30363d", focuscolor=ACCENT)
        style.map("TButton", background=[("active", "#30363d")])
        style.configure("Accent.TButton", background=ACCENT,
                        foreground=ACCENT_FG, bordercolor=ACCENT)
        style.map("Accent.TButton", background=[("active", ACCENT_H)])
        style.configure("Ghost.TButton", background="#212836",
                        foreground=FG, bordercolor="#30363d")
        style.configure("Field.TEntry", fieldbackground=FIELD, foreground=FG,
                        bordercolor="#30363d", insertcolor=FG)
        style.configure("Dim.TLabel", background=BG, foreground=MUT)
        style.configure("Preview.TLabel", background=BG, foreground=ACCENT,
                        font=(MONO, 9, "bold"))

        container = tk.Frame(a, background=BG)
        container.pack(fill="both", expand=True, padx=8, pady=6)

        nb = ttk.Notebook(container)
        nb.pack(fill="both", expand=True)
        a.nb = nb

        # tabs
        conv_tab = tk.Frame(container, background=BG)
        nb.add(conv_tab, text="  ⚙ Configs  ")
        build_converter_pane(a)
        build_rules(a)
        build_naming(a)
        build_override(a)

        build_editor(a)  # adds the "✎ Editor" notebook page (a.edit_tab)

        test_tab = tk.Frame(container, background=BG)
        nb.add(test_tab, text="  📡 Tester  ")
        a.test_tab = test_tab
        build_tester(a)

        xray_tab = tk.Frame(container, background=BG)
        nb.add(xray_tab, text="  🧩 Xray Core  ")
        a.xray_tab = xray_tab
        build_xray_tab(a)

        find_tab = tk.Frame(container, background=BG)
        nb.add(find_tab, text="  🌐 IP Finder  ")
        a.find_tab = find_tab
        build_scanner(a)

        build_snis(a)  # adds the "🎯 SNI Search" notebook page (a.snis_tab)

        subs_tab = tk.Frame(container, background=BG)
        nb.add(subs_tab, text="  📥 Subscriptions  ")
        a.subs_tab = subs_tab
        build_subs(a)

        a._subs_refresh_list()
        a._scan_sessions_refresh()

        # bottom status bar
        status = tk.Frame(a, background=PANEL, height=26)
        status.pack(fill="x", side="bottom")
        status.pack_propagate(False)
        tk.Label(status, textvariable=a.msg_var, background=PANEL,
                 foreground=FG, font=(MONO, 9), anchor="w",
                 padx=8).pack(side="left")
        tk.Label(status, textvariable=a.v_fixed, background=PANEL,
                 foreground=GREEN, font=(MONO, 9), padx=8).pack(side="right")
        tk.Label(status, textvariable=a.v_same, background=PANEL,
                 foreground=MUT, font=(MONO, 9), padx=8).pack(side="right")
        tk.Label(status, textvariable=a.v_skip, background=PANEL,
                 foreground=RED, font=(MONO, 9), padx=8).pack(side="right")

    def _build_menu(self) -> None:
        a = self
        menubar = tk.Menu(a, background=PANEL, foreground=FG,
                          activebackground=ACCENT, activeforeground=ACCENT_FG,
                          tearoff=0)
        a.config(menu=menubar)

        m_file = tk.Menu(menubar, tearoff=0, background=PANEL,
                         foreground=FG, activebackground=ACCENT,
                         activeforeground=ACCENT_FG)
        menubar.add_cascade(label="File", menu=m_file)
        m_file.add_command(label="📂 Open configs…", command=a._open_file)
        m_file.add_command(label="💾 Save output…", command=a.save_output)
        m_file.add_separator()
        m_file.add_command(label="⬇ Fetch subscription…",
                           command=a._fetch_subscription_dialog)
        m_file.add_command(label="🔀 Deduplicate input",
                           command=a._dedup_configs)
        m_file.add_separator()
        m_file.add_command(label="❌ Exit", command=a._on_close)

        m_tools = tk.Menu(menubar, tearoff=0, background=PANEL,
                          foreground=FG, activebackground=ACCENT,
                          activeforeground=ACCENT_FG)
        menubar.add_cascade(label="Tools", menu=m_tools)
        m_tools.add_command(label="📋 Copy output", command=a.copy_output)
        m_tools.add_command(label="📋 Copy names", command=a.copy_names)
        m_tools.add_command(label="🏷 Tag names [CC]",
                            command=a._tag_names_with_cc)
        m_tools.add_separator()
        m_tools.add_command(label="⚙ Detect xray core",
                            command=a._detect_core)
        m_tools.add_command(label="⟳ Check core version",
                            command=a._check_core_clicked)

        m_help = tk.Menu(menubar, tearoff=0, background=PANEL,
                         foreground=FG, activebackground=ACCENT,
                         activeforeground=ACCENT_FG)
        menubar.add_cascade(label="Help", menu=m_help)
        m_help.add_command(label="About", command=lambda: messagebox.showinfo(
            "About", f"Xray Forge v{__version__}\n"
                     "Modular VLESS/Trojan/VMess/SS utility.\n"
                     "License: CC BY 4.0"))

    # ------------------------------------------------------------------ keys
    def _bind_keys(self) -> None:
        a = self
        a.bind("<Control-Return>", lambda e: (a._schedule(), "break"))
        a.bind("<Control-o>", lambda e: (a._open_file(), "break"))
        a.bind("<Control-s>", lambda e: (a.save_output(), "break"))

    # ------------------------------------------------------------------ apply / capture settings
    def _apply_settings(self) -> None:
        a = self
        s = self._settings
        if not s:
            return
        var_map = {
            "mode_var": str, "fp_var": str, "cs_var": str, "fm_var": str,
            "tpl_var": str, "ip_var": str, "port_var": str,
            "sub_url_var": str, "filter_var": str,
            "frag_var": str, "tmo_var": str, "target_var": str,
            "scan_cidr_var": str, "scan_port_var": str,
            "scan_sni_var": str, "scan_frag_var": str, "sni_mode_var": str,
            "geo_ip_var": str, "res_host_var": str,
            "scan_session_var": str, "scan_load_var": str,
            "core_var": str, "core_timeout_var": str,
            "fake_sni_var": str, "domain_front_var": str,
            "sub_core_var": str,
        }
        bool_vars = [
            "fp_on", "cs_on", "fm_on", "rename_var", "tls_only_var",
            "auto_var", "ip_on", "port_on", "cc_on", "core_frag_on",
            "curl_var", "dedup_var", "show_best_var",
            "record_frag_var", "sni_case_var", "sub_thr_var",
            "scan_resume_var", "scan_geo_var",
        ]
        int_vars = ["start_var", "att_var", "workers_test_var",
                    "scan_count_var", "scan_workers_var",
                    "core_workers_var", "sub_workers_var", "sub_timeout_var",
                    "sub_top_var"]
        for key, cast in var_map.items():
            if key in s and hasattr(a, key):
                try:
                    getattr(a, key).set(cast(s[key]))
                except Exception:
                    pass
        for key in bool_vars:
            if key in s and hasattr(a, key):
                try:
                    getattr(a, key).set(bool(s[key]))
                except Exception:
                    pass
        for key in int_vars:
            if key in s and hasattr(a, key):
                try:
                    getattr(a, key).set(int(s[key]))
                except Exception:
                    pass
        if "geometry" in s:
            try:
                a.geometry(s["geometry"])
            except Exception:
                pass

    def _capture_settings(self) -> dict[str, Any]:
        a = self
        s: dict[str, Any] = {}
        simple_vars = [
            "mode_var", "fp_var", "cs_var", "fm_var", "tpl_var",
            "ip_var", "port_var", "sub_url_var", "filter_var",
            "frag_var", "tmo_var", "target_var",
            "scan_cidr_var", "scan_port_var", "scan_sni_var",
            "scan_frag_var", "sni_mode_var", "geo_ip_var",
            "res_host_var", "scan_session_var", "scan_load_var",
            "core_var", "core_timeout_var",
            "fake_sni_var", "domain_front_var", "sub_core_var",
            "snis_ips_var", "snis_names_var", "snis_port_var",
            "snis_frag_var", "snis_session_var",
        ]
        bool_vars = [
            "fp_on", "cs_on", "fm_on", "rename_var", "tls_only_var",
            "auto_var", "ip_on", "port_on", "cc_on", "core_frag_on",
            "curl_var", "dedup_var", "show_best_var",
            "record_frag_var", "sni_case_var", "sub_thr_var",
            "scan_resume_var", "scan_geo_var",
            "snis_resume_var", "snis_http_var",
        ]
        int_vars = ["start_var", "att_var", "workers_test_var",
                    "scan_count_var", "scan_workers_var",
                    "core_workers_var", "sub_workers_var", "sub_timeout_var",
                    "sub_top_var", "snis_workers_var"]
        for key in simple_vars:
            if hasattr(a, key):
                try:
                    s[key] = getattr(a, key).get()
                except Exception:
                    pass
        for key in bool_vars:
            if hasattr(a, key):
                try:
                    s[key] = bool(getattr(a, key).get())
                except Exception:
                    pass
        for key in int_vars:
            if hasattr(a, key):
                try:
                    s[key] = int(getattr(a, key).get())
                except Exception:
                    pass
        try:
            s["geometry"] = a.geometry()
        except Exception:
            pass
        return s

    # ------------------------------------------------------------------ schedule / convert
    def _make_tree(self, parent, cols: dict, numeric: set) -> ttk.Treeview:
        a = self
        style = ttk.Style(a)
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=FG, bordercolor="#30363d")
        style.configure("Treeview.Heading", background="#212836",
                        foreground=ACCENT, bordercolor="#30363d")
        style.map("Treeview", background=[("selected", ACCENT)],
                  foreground=[("selected", ACCENT_FG)])
        tree = ttk.Treeview(parent, columns=list(cols.keys()), show="headings",
                            selectmode="extended")
        for col, (w, align) in cols.items():
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor=align, stretch=False)
        return tree

    def _schedule(self) -> None:
        a = self
        if a._job is not None:
            try:
                a.after_cancel(a._job)
            except Exception:
                pass
        a._job = a.after(300, a.do_convert)

    def do_convert(self) -> None:
        a = self
        a._job = None
        text = a.input_txt.get("1.0", "end-1c")
        if not text.strip():
            a._set_output([])
            a._set_names([])
            a._set_counts(0, 0, 0)
            a._editor_refresh()
            a.msg_var.set("paste configs to convert")
            return
        fp = a.fp_var.get().strip()
        cs = a.cs_var.get().strip()
        fm = a.fm_var.get().strip()
        tls_only = a.tls_only_var.get()
        rename = a.rename_var.get()
        tpl = a.tpl_var.get().strip() or DEFAULT_TEMPLATE
        try:
            start = int(a.start_var.get())
        except Exception:
            start = 1
        ov_ip = a.ip_var.get().strip() if a.ip_on.get() else ""
        ov_port = a.port_var.get().strip() if a.port_on.get() else ""
        mode = a.mode_var.get()
        want_fp = a.fp_on.get() and mode != MODE_IPONLY
        want_cs = a.cs_on.get() and mode != MODE_IPONLY
        want_fm = a.fm_on.get() and mode != MODE_IPONLY
        if mode == MODE_IPONLY:
            want_fp = want_cs = want_fm = False
        try:
            lines, names, c = convert_block(
                text, fp, cs, fm, tls_only,
                rename, tpl, start, ov_ip, ov_port,
                want_fp, want_cs, want_fm)
            if a.dedup_var.get():
                lines, removed = dedup_configs(lines)
                if removed:
                    a.msg_var.set(f"auto-dedup removed {removed} duplicate(s)")
            a._set_output(lines)
            a._set_names(names)
            a._set_counts(c["fixed"], c["unchanged"], c["skipped"])
            a._targets = [parse_target(l) for l in lines if parse_target(l)]
            a._build_tester_list()
            a._editor_refresh()
            ep = ""
            if ov_ip or ov_port:
                ep = f"  ·  endpoint→{ov_ip or 'orig'}:{ov_port or 'orig'}"
            a.msg_var.set(
                f"converted {c['fixed']} fixed · {c['unchanged']} unchanged · "
                f"{c['skipped']} skipped{ep}")
        except Exception as e:
            a.msg_var.set(f"convert error: {e}")

    def _set_output(self, lines: list[str]) -> None:
        a = self
        txt = "\n".join(lines)
        a.output_txt.configure(state="normal")
        a.output_txt.delete("1.0", "end")
        a.output_txt.insert("1.0", txt)
        a.output_txt.configure(state="disabled")
        a._out_dirty = True

    def _set_names(self, names: list[tuple[str, str]]) -> None:
        a = self
        a._name_lines = names
        a.names_lb.delete(0, "end")
        for name, _ in names:
            a.names_lb.insert("end", name)

    def _set_counts(self, fixed: int, same: int, skip: int) -> None:
        a = self
        a.v_fixed.set(f"✎ {fixed} updated")
        a.v_same.set(f"↺ {same} unchanged")
        a.v_skip.set(f"⚠ {skip} skipped")

    def copy_output(self) -> None:
        a = self
        txt = a.output_txt.get("1.0", "end-1c")
        if not txt.strip():
            a.msg_var.set("nothing to copy")
            return
        a.clipboard_clear()
        a.clipboard_append(txt)
        a.msg_var.set("output copied to clipboard")

    def copy_names(self) -> None:
        a = self
        if not a._name_lines:
            a.msg_var.set("no names to copy")
            return
        txt = "\n".join(n for n, _ in a._name_lines)
        a.clipboard_clear()
        a.clipboard_append(txt)
        a.msg_var.set(f"{len(a._name_lines)} names copied")

    def _copy_named_line(self, event=None) -> None:
        a = self
        sel = a.names_lb.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx < len(a._name_lines):
            _, line = a._name_lines[idx]
            a.clipboard_clear()
            a.clipboard_append(line)
            a.msg_var.set("config copied")

    def _select_all(self, event=None) -> None:
        w = self.focus_get()
        if isinstance(w, tk.Text):
            w.tag_add("sel", "1.0", "end")
        return "break"

    def _open_file(self) -> None:
        a = self
        path = filedialog.askopenfilename(
            parent=a, filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            a.input_txt.delete("1.0", "end")
            a.input_txt.insert("1.0", text)
            a.msg_var.set(f"loaded {path}")
            a._schedule()
        except Exception as e:
            messagebox.showerror("open failed", str(e), parent=a)

    def save_output(self) -> None:
        a = self
        text = a.output_txt.get("1.0", "end-1c").strip()
        if not text:
            a.msg_var.set("Nothing to save.")
            return
        path = filedialog.asksaveasfilename(
            parent=a, defaultextension=".txt",
            initialfile="vless_fixed.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            a.msg_var.set(f"saved {path}")
        except Exception as e:
            messagebox.showerror("save failed", str(e), parent=a)

    def _sync_rule_fields(self) -> None:
        pass

    def _switch_touched(self) -> None:
        self._schedule()

    def _toggle_override(self) -> None:
        a = self
        ip = a.ip_var.get().strip() if a.ip_on.get() else ""
        port = a.port_var.get().strip() if a.port_on.get() else ""
        a.ep_preview.set(f"{ip or 'orig'} : {port or 'orig'}")
        a._schedule()

    def _clear_override(self) -> None:
        a = self
        a.ip_var.set("")
        a.port_var.set("")
        a.ip_on.set(False)
        a.port_on.set(False)
        a.ep_preview.set("orig : orig")
        a._schedule()

    def _show_keys(self) -> None:
        keys = ("{id} {sub} {path} {ip} {port} {host} {net} {sni} {proto} {old}")
        messagebox.showinfo("naming keys", keys, parent=self)

    def _on_mode_change(self, event=None) -> None:
        a = self
        mode = a.mode_var.get()
        if mode == MODE_IPONLY:
            a.fp_on.set(False); a.cs_on.set(False); a.fm_on.set(False)
            a.fp_entry.configure(state="disabled")
            a.cs_entry.configure(state="disabled")
            a.fm_entry.configure(state="disabled")
        else:
            a.fp_entry.configure(state="normal")
            a.cs_entry.configure(state="normal")
            a.fm_entry.configure(state="normal")
        a._schedule()

    # ------------------------------------------------------------------ editor
    # Per-config field editor (Configs ▸ ✎ Editor): pick a line from the
    # OUTPUT pane, edit Outbound fields (incl. Reality / XHTTP / flow),
    # optionally round-trip through the raw JSON, and write the regenerated
    # share link back into the output.
    def _editor_out_lines(self) -> list[str]:
        return self.output_txt.get("1.0", "end-1c").splitlines()

    @staticmethod
    def _editor_label(out: Outbound) -> str:
        return (f"{out.name or out.host} · "
                f"{out.scheme}/{out.transport}/{out.security or 'none'}")

    def _editor_refresh(self, keep_selection: bool = True) -> None:
        """Re-scan the OUTPUT pane; keeps the selected slot when possible."""
        a = self
        prev = a._editor_sel if keep_selection else None
        a._editor_items = []
        for i, line in enumerate(a._editor_out_lines()):
            out = parse_target(line)
            if out is not None:
                a._editor_items.append((i, line, out))
        values = tuple(f"{n + 1} · {a._editor_label(out)}"
                       for n, (_i, _l, out) in enumerate(a._editor_items))
        a.ed_pick_cb.configure(values=values)
        if not a._editor_items:
            a.ed_pick_var.set("")
            a._editor_sel = None
            a.ed_status_var.set("no convertible config in output")
            return
        sel = prev if (prev is not None and 0 <= prev < len(a._editor_items)) \
            else 0
        a._editor_sel = sel
        a.ed_pick_cb.current(sel)
        a._editor_load()

    def _editor_load(self, _event=None) -> None:
        a = self
        sel = a._editor_sel
        if not a._editor_items or sel is None \
                or not (0 <= sel < len(a._editor_items)):
            return
        _idx, _line, out = a._editor_items[sel]
        a._editor_fill(out)
        a._editor_json_dump(out)
        a.ed_status_var.set(f"loaded #{sel + 1} — edit fields, then apply")

    def _editor_fill(self, out: Outbound) -> None:
        a = self
        a.ed_scheme_var.set(out.scheme)
        a.ed_name_var.set(out.name)
        a.ed_host_var.set(out.host)
        a.ed_port_var.set(out.port)
        a.ed_cred_var.set(out.credential)
        a.ed_transport_var.set(out.transport or "")
        a.ed_path_var.set(out.path or "/")
        a.ed_hosthdr_var.set(out.host_header)
        a.ed_service_var.set(out.service_name)
        a.ed_hdrtype_var.set(out.header_type)
        a.ed_mode_var.set(out.extra.get("mode", "") or "")
        a.ed_security_var.set(out.security or "")
        a.ed_sni_var.set(out.sni)
        a.ed_fp_var.set(out.fingerprint)
        a.ed_alpn_var.set(out.alpn)
        a.ed_insecure_var.set(bool(out.allow_insecure))
        a.ed_flow_var.set(out.flow)
        a.ed_pbk_var.set(out.public_key)
        a.ed_sid_var.set(out.short_id)
        a.ed_spx_var.set(out.spider_x)
        a.ed_cs_var.set(out.extra.get("cs", "") or "")
        a.ed_scy_var.set(out.encryption or "")
        a.ed_aid_var.set(out.alter_id or "0")

    def _editor_collect(self) -> Outbound:
        a = self
        sel = a._editor_sel
        base: Outbound | None = None
        if a._editor_items and sel is not None \
                and 0 <= sel < len(a._editor_items):
            base = a._editor_items[sel][2]
        extra = dict(base.extra) if base else {}
        for key, var in (("mode", a.ed_mode_var), ("cs", a.ed_cs_var)):
            val = var.get().strip()
            if val:
                extra[key] = val
            else:
                extra.pop(key, None)
        sec = a.ed_security_var.get().strip()
        return Outbound(
            scheme=a.ed_scheme_var.get().strip()
            or (base.scheme if base else "vless"),
            name=a.ed_name_var.get().strip(),
            host=a.ed_host_var.get().strip(),
            port=a.ed_port_var.get().strip() or "443",
            credential=a.ed_cred_var.get().strip(),
            transport=a.ed_transport_var.get().strip() or "tcp",
            security=sec,
            sni=a.ed_sni_var.get().strip(),
            host_header=a.ed_hosthdr_var.get().strip(),
            path=a.ed_path_var.get().strip() or "/",
            fingerprint=a.ed_fp_var.get().strip(),
            alpn=a.ed_alpn_var.get().strip(),
            service_name=a.ed_service_var.get().strip(),
            header_type=a.ed_hdrtype_var.get().strip(),
            flow=a.ed_flow_var.get().strip(),
            public_key=a.ed_pbk_var.get().strip(),
            short_id=a.ed_sid_var.get().strip(),
            spider_x=a.ed_spx_var.get().strip(),
            allow_insecure=bool(a.ed_insecure_var.get()),
            encryption=a.ed_scy_var.get().strip()
            or (base.encryption if base else "none"),
            alter_id=a.ed_aid_var.get().strip() or "0",
            extra=extra,
            raw=base.raw if base else "",
        )

    def _editor_uri(self, out: Outbound) -> str:
        h = handler_for(out.scheme)
        if h is None:
            raise ValueError(f"unsupported protocol: {out.scheme!r}")
        return h.to_uri(out)

    def _editor_apply(self) -> None:
        a = self
        sel = a._editor_sel
        if not a._editor_items or sel is None \
                or not (0 <= sel < len(a._editor_items)):
            a.ed_status_var.set("pick a config first")
            return
        idx, old_line, _old = a._editor_items[sel]
        try:
            out = a._editor_collect()
            new_line = a._editor_uri(out)
        except Exception as e:
            a.ed_status_var.set(f"apply failed: {e}")
            return
        lines = a._editor_out_lines()
        if not (0 <= idx < len(lines)):
            a.ed_status_var.set("output changed — press ⟳ reload list")
            return
        lines[idx] = new_line
        a._set_output(lines)
        # names list mirrors the edited line (incl. a renamed config)
        new_name = out.name
        a._name_lines = [(new_name if l == old_line else n,
                          new_line if l == old_line else l)
                         for n, l in a._name_lines]
        a._set_names(a._name_lines)
        a._targets = [parse_target(l) for l in lines if parse_target(l)]
        a._build_tester_list()
        a._editor_items[sel] = (idx, new_line, out)
        values = list(a.ed_pick_cb.cget("values"))
        values[sel] = f"{sel + 1} · {a._editor_label(out)}"
        a.ed_pick_cb.configure(values=values)
        a.ed_pick_cb.current(sel)
        a._editor_json_dump(out)
        a.ed_status_var.set(f"applied — output line {idx + 1} replaced")

    def _editor_json_dump(self, out: Outbound) -> None:
        a = self
        a.ed_json_txt.delete("1.0", "end")
        a.ed_json_txt.insert("1.0", json.dumps(
            out.to_dict(), ensure_ascii=False, indent=2))

    def _editor_to_json(self) -> None:
        a = self
        try:
            out = a._editor_collect()
        except Exception as e:
            a.ed_status_var.set(f"form error: {e}")
            return
        a._editor_json_dump(out)
        a.ed_status_var.set("form → JSON")

    def _editor_from_json(self) -> None:
        a = self
        try:
            out = Outbound.from_dict(
                json.loads(a.ed_json_txt.get("1.0", "end-1c")))
        except Exception as e:
            a.ed_status_var.set(f"bad JSON: {e}")
            return
        a._editor_fill(out)
        a.ed_status_var.set("JSON → form (press apply to write the link)")

    def _editor_copy(self) -> None:
        a = self
        try:
            uri = a._editor_uri(a._editor_collect())
        except Exception as e:
            a.ed_status_var.set(f"copy failed: {e}")
            return
        a.clipboard_clear()
        a.clipboard_append(uri)
        a.ed_status_var.set("URI copied to clipboard")

    # ------------------------------------------------------------------ tester list
    def _build_tester_list(self) -> None:
        a = self
        if not hasattr(a, "test_tree"):
            return
        a.test_tree.delete(*a.test_tree.get_children(""))
        for t in a._targets:
            name = t["name"]
            ep = f"{t['host']}:{t['port']}"
            vals = (name, ep, "—", "—", "—", "—", "", "queued")
            a.test_tree.insert("", "end", values=vals)
        a.test_info_var.set(f"{len(a._targets)} configs queued")
        a._filter_list()

    def _filter_list(self) -> None:
        a = self
        if not hasattr(a, "test_tree"):
            return
        needle = a.filter_var.get().strip().lower()
        if not needle:
            for iid in a.test_tree.get_children(""):
                a.test_tree.item(iid, tags=())
            return
        for iid in a.test_tree.get_children(""):
            values = a.test_tree.item(iid, "values")
            hay = " ".join(str(v) for v in values).lower()
            if needle in hay:
                a.test_tree.item(iid, tags=())
            else:
                a.test_tree.item(iid, tags=("hidden",))
        a.test_tree.tag_configure("hidden", foreground="#30363d")

    def _mark_best_configs(self) -> None:
        a = self
        if not hasattr(a, "test_tree"):
            return
        best_iid = None
        best_ms = float("inf")
        for iid in a.test_tree.get_children(""):
            if not a.test_tree.exists(iid):
                continue
            real = a.test_tree.set(iid, "real")
            ws = a.test_tree.set(iid, "ws")
            tls = a.test_tree.set(iid, "tls")
            ms = None
            for v in (real, ws, tls):
                if v and v not in ("—", ""):
                    try:
                        ms = float(v)
                        break
                    except ValueError:
                        pass
            if ms is not None and ms < best_ms:
                best_ms = ms
                best_iid = iid
        for iid in a.test_tree.get_children(""):
            a.test_tree.item(iid, tags=())
        if best_iid is not None:
            a.test_tree.item(best_iid, tags=("best",))
            a.test_tree.tag_configure("best", background="#1b3a5c")
            name = a.test_tree.set(best_iid, "name")
            a.msg_var.set(f"★ best: {name} (~{best_ms:.0f} ms)")

    # ------------------------------------------------------------------ subscription / dedup
    def _fetch_subscription(self) -> None:
        a = self
        url = a.sub_url_var.get().strip()
        if not url:
            a.msg_var.set("enter a subscription URL first")
            return
        a.msg_var.set(f"fetching subscription from {url[:60]} …")
        threading.Thread(target=a._sub_job, args=(url,), daemon=True).start()

    def _fetch_subscription_dialog(self) -> None:
        a = self
        url = tk.simpledialog.askstring(
            "subscription", "paste subscription URL:", parent=a,
            initialvalue=a.sub_url_var.get())
        if url:
            a.sub_url_var.set(url.strip())
            a._fetch_subscription()

    def _sub_job(self, url: str) -> None:
        a = self
        try:
            lines = fetch_subscription(url)
        except Exception as e:
            a.q_put(("sub_err", str(e)))
            return
        a.q_put(("sub_ok", lines))

    def _dedup_configs(self) -> None:
        a = self
        text = a.input_txt.get("1.0", "end-1c")
        lines = [l for l in text.splitlines() if l.strip()]
        if not lines:
            a.msg_var.set("nothing to deduplicate")
            return
        out, removed = dedup_configs(lines)
        a.input_txt.delete("1.0", "end")
        a.input_txt.insert("1.0", "\n".join(out))
        a.msg_var.set(f"🔀 deduplicated — removed {removed} duplicate(s)")
        a._schedule()

    # ------------------------------------------------------------------ subscriptions tab
    def _subs_mgr(self):
        from xray_forge.core.sub_source import SourceManager
        return SourceManager()

    def _subs_refresh_list(self) -> None:
        a = self
        if not hasattr(a, "subs_tree"):
            return
        a.subs_tree.delete(*a.subs_tree.get_children(""))
        try:
            for src in a._subs_mgr().list_sources():
                a.subs_tree.insert("", "end", values=(
                    "✓" if src.enabled else "—", src.name, src.url,
                    src.etag[:12] or "—", src.last_fetch or "—",
                    src.last_status or "—", src.last_count))
        except Exception as e:
            a.msg_var.set(f"sources error: {e}")

    def _subs_add(self) -> None:
        a = self
        url = tk.simpledialog.askstring("add source", "subscription URL:",
                                        parent=a)
        if not url or not url.strip():
            return
        name = tk.simpledialog.askstring("add source", "label (optional):",
                                         parent=a) or ""
        a._subs_mgr().add(url.strip(), name.strip())
        a._subs_refresh_list()
        a.msg_var.set(f"source added: {url.strip()[:60]}")

    def _subs_selected_url(self) -> str:
        a = self
        sel = a.subs_tree.selection()
        if not sel:
            a.msg_var.set("select a source row first")
            return ""
        return str(a.subs_tree.set(sel[0], "url"))

    def _subs_remove(self) -> None:
        a = self
        url = a._subs_selected_url()
        if not url:
            return
        removed = a._subs_mgr().remove(url)
        a._subs_refresh_list()
        a.msg_var.set("source removed" if removed else "source not found")

    def _subs_toggle(self) -> None:
        a = self
        url = a._subs_selected_url()
        if not url:
            return
        sel = a.subs_tree.selection()[0]
        enabled = str(a.subs_tree.set(sel, "on")) == "✓"
        a._subs_mgr().set_enabled(url, not enabled)
        a._subs_refresh_list()

    def _subs_copy_url(self, _event=None) -> None:
        a = self
        iid = a.subs_tree.focus()
        if not iid:
            return
        a.clipboard_clear()
        a.clipboard_append(str(a.subs_tree.set(iid, "url")))
        a.msg_var.set("source URL copied")

    def _subs_fetch(self) -> None:
        a = self
        a.sub_status_var.set("fetching …")
        threading.Thread(target=a._subs_fetch_job, daemon=True).start()

    def _subs_fetch_job(self) -> None:
        a = self
        try:
            out = a._subs_mgr().fetch_all()
            lines, removed = a._subs_mgr().combined_lines()
        except Exception as e:
            a.after(0, lambda err=e: a.sub_status_var.set(f"fetch error: {err}"))
            return
        n_src = len(out)
        a.after(0, a._subs_refresh_list)
        a.after(0, lambda: a.sub_status_var.set(
            f"{n_src} source(s) · {len(lines)} configs ({removed} dup removed)"))
        a.after(0, lambda: a.msg_var.set(
            f"subscriptions fetched — {len(lines)} unique configs ready to check"))

    def _subs_check(self) -> None:
        a = self
        if getattr(a, "_subs_checking", False):
            return
        lines, _removed = a._subs_mgr().combined_lines()
        if not lines:
            a.sub_status_var.set("no cached configs — fetch first")
            return
        a._subs_checking = True
        a._sub_reports = []
        a._sub_stop.clear()
        a.subres_tree.delete(*a.subres_tree.get_children(""))
        a.sub_prog_var.set(f"0/{len(lines)}")
        a.btn_subs_check.configure(state="disabled")
        a.btn_subs_stop.configure(state="normal")
        core = a.sub_core_var.get()
        if core == "native only":
            core = ""
        kwargs = dict(
            workers=max(1, int(a.sub_workers_var.get() or "8")),
            timeout=float(a.sub_timeout_var.get() or "6"),
            do_throughput=a.sub_thr_var.get(),
            core=core or None,
            stop=a._sub_stop,
            progress=lambda d, t: a.after(0, a._subs_progress, d, t),
        )
        threading.Thread(target=a._subs_check_job, args=(list(lines), kwargs),
                         daemon=True).start()

    def _subs_progress(self, done: int, total: int) -> None:
        self.sub_prog_var.set(f"{done}/{total}")
        self.sub_status_var.set(f"checking {done}/{total} …")

    def _subs_check_job(self, lines: list, kwargs: dict) -> None:
        a = self
        from xray_forge.core import healthcheck as hc
        try:
            reports = hc.run_health_checks(lines, **kwargs)
        except Exception as e:
            a.after(0, lambda err=e: a.sub_status_var.set(f"check error: {err}"))
            a.after(0, a._subs_finish)
            return
        a._sub_reports = reports
        a.after(0, a._subs_fill_results)
        a.after(0, a._subs_finish)

    def _subs_fill_results(self) -> None:
        a = self
        from xray_forge.core import healthcheck as hc
        a.subres_tree.delete(*a.subres_tree.get_children(""))
        for r in hc.rank_reports(a._sub_reports):
            req = r.stage("request")
            dl = r.stage("download")
            ul = r.stage("upload")
            failing = next((s.name for s in r.stages if not s.ok), None)
            status = ("ok" if r.passed()
                      else f"{failing}: {r.stage(failing).detail[:34]}"
                      if failing else "—")
            a.subres_tree.insert("", "end", values=(
                r.name or r.line[:28], r.scheme, f"{r.score:.0f}",
                f"{req.ms:.0f}" if (req and req.ms is not None) else "—",
                _fmt_bps(dl), _fmt_bps(ul),
                ",".join(r.techniques) or "—", status))

    def _subs_finish(self) -> None:
        a = self
        a._subs_checking = False
        a.btn_subs_check.configure(state="normal")
        a.btn_subs_stop.configure(state="disabled")
        n_ok = sum(1 for r in a._sub_reports if r.passed())
        a.sub_status_var.set(
            f"done — {n_ok}/{len(a._sub_reports)} working")
        a.msg_var.set(f"health check complete — {n_ok} working config(s)")

    def _subs_export(self) -> None:
        a = self
        from xray_forge.core import healthcheck as hc
        if not a._sub_reports:
            a.msg_var.set("run a health check first")
            return
        try:
            top = int(a.sub_top_var.get() or "10")
        except Exception:
            top = 10
        path = filedialog.asksaveasfilename(
            parent=a, defaultextension=".txt", initialfile="best_sub.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(hc.export_best_subscription(a._sub_reports, top))
            a.msg_var.set(f"best-{top} subscription saved → {path}")
        except Exception as e:
            messagebox.showerror("export failed", str(e), parent=a)

    def _subs_use(self) -> None:
        a = self
        from xray_forge.core import healthcheck as hc
        if not a._sub_reports:
            a.msg_var.set("run a health check first")
            return
        tags = hc.tagged_lines(a._sub_reports)
        if not tags:
            a.msg_var.set("no working configs to send")
            return
        a.input_txt.delete("1.0", "end")
        a.input_txt.insert("1.0", "\n".join(tags))
        a.nb.select(0)
        a._schedule()
        a.msg_var.set(f"{len(tags)} working config(s) sent to Configs tab")

    def _subs_copy_config(self, _event=None) -> None:
        a = self
        iid = a.subres_tree.focus()
        if not iid:
            return
        name = str(a.subres_tree.set(iid, "name"))
        for r in a._sub_reports:
            if (r.name or r.line[:28]) == name:
                a.clipboard_clear()
                a.clipboard_append(r.line)
                a.msg_var.set("config copied")
                return

    # ------------------------------------------------------------------ test worker
    def _start_test(self, selected: bool = False) -> None:
        a = self
        if a._testing:
            return
        rows = a.test_tree.get_children("")
        if selected:
            sel = a.test_tree.selection()
            rows = [iid for iid in rows if iid in sel]
        if not rows:
            a.msg_var.set("nothing to test")
            return
        a._testing = True
        a._stop_test.clear()
        a._test_done = 0
        a._test_total = len(rows)
        a.test_prog_var.set(f"0/{a._test_total}")
        a.btn_test_all.configure(state="disabled")
        a.btn_test_sel.configure(state="disabled")
        a.btn_stop_test.configure(state="normal")
        a.btn_core_all.configure(state="disabled")
        a.btn_core_sel.configure(state="disabled")
        targets = []
        for iid in rows:
            vals = a.test_tree.item(iid, "values")
            name = vals[0]
            t = next((t for t in a._targets if t["name"] == name), None)
            if t:
                targets.append((iid, t))
        a._test_ex = ThreadPoolExecutor(
            max_workers=max(1, int(a.workers_test_var.get() or "8")))
        futs = {}
        for iid, t in targets:
            futs[a._test_ex.submit(a._worker_test, t)] = iid
        threading.Thread(target=a._poll_test, args=(futs,), daemon=True).start()

    def _worker_test(self, t: dict) -> dict:
        a = self
        res = {"name": t["name"], "tcp": None, "tls": None, "ws": None,
               "real": None, "cc": "", "ip": "", "status": ""}
        frag = parse_frag_if_avail(a.frag_var.get())
        tmo = float(a.tmo_var.get() or "8")
        try:
            # tcp
            tcp = tcp_ping(t["host"], t["port"], timeout=tmo,
                           stop=a._stop_test)
            res["tcp"] = tcp
            if a._stop_test.is_set():
                res["status"] = "stopped"; return res
            # tls (fragmented hello)
            tc, sock, info = tls_connect(
                t["host"], t["port"], sni=t["sni"], frag=frag,
                timeout=tmo, stop=a._stop_test,
                fake_sni=a.fake_sni_var.get() or None,
                record_frag=a.record_frag_var.get(),
                pad_hello=a.sni_case_var.get())
            res["tls"] = info["tls_ms"]
            # ws upgrade
            front = a.domain_front_var.get() or None
            line, wms = ws_upgrade(tc, t["hdr"], t["path"], tmo,
                                   a._stop_test, front_domain=front)
            res["ws"] = wms
            res["status"] = line[:40]
            if a._stop_test.is_set():
                res["status"] = "stopped"; return res
            # exit country / real delay via tunnel
            if a.cc_on.get():
                ghost = t["sni"] or t["host"]
                gpath = "/json/?fields=status,countryCode,country,city,isp,query"
                cc, ip, detail, ms = probe_geo_source(
                    t, tc, sock, t["sni"], frag, "http", ghost, gpath, tmo,
                    a._stop_test, front_domain=front)
                res["cc"] = cc
                res["ip"] = ip
                res["real"] = ms
                res["status"] = f"{detail} · {line[:20]}"
            else:
                path = a.target_var.get().strip() or TEST_TARGET_DEFAULT
                sch, host, port, tpath = parse_test_target(path)
                ms, status = real_delay_http(
                    VlessTunnel(tc, t.get("uuid", ""), ghost, 80, a._stop_test,
                                front_domain=front),
                    host, tpath, tmo, a._stop_test, front_domain=front)
                res["real"] = ms
                res["status"] = f"{status} · {line[:20]}"
            try:
                sock.close()
            except Exception:
                pass
            tc_read = getattr(tc, "read", None)
        except ProbeError as pe:
            res["status"] = f"{pe.stage}: {pe.detail[:40]}"
        except Exception as e:
            res["status"] = f"error: {type(e).__name__}"
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return res

    def _poll_test(self, futs: dict) -> None:
        a = self
        done = 0
        for fut in as_completed(futs):
            if a._stop_test.is_set():
                break
            iid = futs[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"name": "", "tcp": None, "tls": None, "ws": None,
                       "real": None, "cc": "", "ip": "", "status": str(e)}
            done += 1
            a.after(0, a._apply_test_result, iid, res)
            a._test_done = done
            a.after(0, lambda: a.test_prog_var.set(f"{done}/{a._test_total}"))
        a.after(0, a._finish_test)

    def _apply_test_result(self, iid: str, res: dict) -> None:
        a = self
        if not a.test_tree.exists(iid):
            return
        def fmt(v):
            if v is None:
                return "—"
            if isinstance(v, (int, float)):
                return f"{v:.0f}"
            return str(v)
        a.test_tree.item(iid, values=(
            res.get("name", ""),
            a.test_tree.set(iid, "endpoint"),
            fmt(res.get("tcp")), fmt(res.get("tls")),
            fmt(res.get("ws")), fmt(res.get("real")),
            res.get("cc", ""), res.get("status", "")))

    def _finish_test(self) -> None:
        a = self
        a._testing = False
        a.btn_test_all.configure(state="normal")
        a.btn_test_sel.configure(state="normal")
        a.btn_stop_test.configure(state="disabled")
        a.btn_core_all.configure(state="normal")
        a.btn_core_sel.configure(state="normal")
        if a.show_best_var.get():
            a._mark_best_configs()
        a.test_info_var.set("test complete")
        ok = 0
        for iid in a.test_tree.get_children(""):
            st = a.test_tree.set(iid, "status").upper()
            if st.startswith(("101", "TLS OK", "TCP OK", "CORE EXIT", "HTTP")):
                ok += 1
        a.msg_var.set(f"test complete — {ok}/{a._test_total} working")
        if a._test_ex:
            try:
                a._test_ex.shutdown(wait=False)
            except Exception:
                pass
            a._test_ex = None

    def _stop_test(self) -> None:
        self._stop_test.set()

    # ------------------------------------------------------------------ tag names cc
    def _tag_names_with_cc(self) -> None:
        a = self
        changed = 0
        for iid in a.test_tree.get_children(""):
            cc = a.test_tree.set(iid, "cc")
            if not cc or cc in ("—", ""):
                continue
            if "*" in cc:
                continue
            t = next((t for t in a._targets if t["name"] == a.test_tree.set(iid, "name")), None)
            if not t:
                continue
            old = t["name"]
            new = f"{old}[{cc}]" if not old.endswith(f"[{cc}]") else old
            if new != old:
                vals = list(a.test_tree.item(iid, "values"))
                vals[0] = new
                a.test_tree.item(iid, values=vals)
                changed += 1
        a.msg_var.set(f"🏷 tagged {changed} config name(s) with [exit-country]")

    def _copy_test_line(self, event=None) -> None:
        a = self
        iid = a.test_tree.focus()
        if not iid:
            return
        name = a.test_tree.set(iid, "name")
        t = next((t for t in a._targets if t["name"] == name), None)
        if t:
            a.clipboard_clear()
            a.clipboard_append(t["raw"])
            a.msg_var.set("config copied")

    # ------------------------------------------------------------------ xray core
    def _pick_core(self) -> None:
        a = self
        path = filedialog.askopenfilename(
            parent=a, title="select xray core",
            filetypes=[("xray executable", "xray.exe"), ("All files", "*.*")])
        if path:
            a.core_var.set(path)
            a._check_core_clicked()

    def _detect_core(self) -> None:
        a = self
        path = find_xray_core()
        if path:
            a.core_var.set(path)
            a.core_status_var.set("detected")
        else:
            a.core_status_var.set("not found")
        a._check_core_clicked()

    def _check_core_clicked(self) -> None:
        a = self
        path = a.core_var.get().strip()
        if not path:
            path = find_xray_core()
            if path:
                a.core_var.set(path)
        if not path:
            a.core_status_var.set("no core path set")
            return
        ver = check_core_version(path)
        a.core_status_var.set(ver)

    def _start_core_test(self, selected: bool = False) -> None:
        a = self
        path = a.core_var.get().strip()
        if not path:
            path = find_xray_core()
        if not path:
            messagebox.showwarning("no core",
                                   "xray core not found — set path in 🧩 tab",
                                   parent=a)
            return
        if a._testing:
            return
        rows = a.test_tree.get_children("")
        if selected:
            rows = [iid for iid in rows if iid in a.test_tree.selection()]
        if not rows:
            a.msg_var.set("nothing to test")
            return
        a._testing = True
        a._stop_test.clear()
        a._test_done = 0
        a._test_total = len(rows)
        a.test_prog_var.set(f"0/{a._test_total}")
        a.btn_test_all.configure(state="disabled")
        a.btn_test_sel.configure(state="disabled")
        a.btn_stop_test.configure(state="normal")
        a.btn_core_all.configure(state="disabled")
        a.btn_core_sel.configure(state="disabled")
        targets = []
        for iid in rows:
            vals = a.test_tree.item(iid, "values")
            name = vals[0]
            t = next((t for t in a._targets if t["name"] == name), None)
            if t:
                targets.append((iid, t))
        workers = max(1, int(a.core_workers_var.get() or "4"))
        a._test_ex = ThreadPoolExecutor(max_workers=workers)
        futs = {}
        for iid, t in targets:
            futs[a._test_ex.submit(a._worker_core_test, t, path)] = iid
        threading.Thread(target=a._poll_test, args=(futs,), daemon=True).start()

    def _worker_core_test(self, t: dict, xray_path: str) -> dict:
        a = self
        res = {"name": t["name"], "tcp": None, "tls": None, "ws": None,
               "real": None, "cc": "", "ip": "", "status": ""}
        try:
            r = xray_probe(
                t["raw"], xray_path,
                frag_on=a.core_frag_on.get(),
                timeout=float(a.core_timeout_var.get() or "8"),
                front_domain=a.domain_front_var.get() or None)
            res["real"] = r.get("real")
            res["cc"] = r.get("cc", "")
            res["ip"] = r.get("exit_ip", "")
            res["status"] = r.get("status", "")
        except Exception as e:
            res["status"] = f"core error: {type(e).__name__}"
        return res

    # ------------------------------------------------------------------ scanner
    def _start_scan(self) -> None:
        a = self
        if a._scanning:
            return
        cidr = a.scan_cidr_var.get().strip()
        try:
            count = int(a.scan_count_var.get())
        except Exception:
            count = 200
        try:
            workers = int(a.scan_workers_var.get())
        except Exception:
            workers = 64
        port = a.scan_port_var.get().strip() or "443"
        from xray_forge.core.scan_session import ScanSession
        name = a.scan_session_var.get().strip()
        if not name:
            name = "scan_" + time.strftime("%Y%m%d_%H%M%S")
            a.scan_session_var.set(name)
        session = ScanSession(name)
        pending = session.set_targets([cidr], count,
                                      resume=a.scan_resume_var.get())
        if not pending:
            a.msg_var.set("session has no pending IPs — uncheck resume "
                          "or pick a new session name")
            return
        a._scan_session = session
        a._scanning = True
        a._stop_scan.clear()
        a._scan_done = 0
        a._scan_total = pending
        a._scan_alive = 0
        a.res_tree.delete(*a.res_tree.get_children(""))
        a._scan_meta.clear()
        a.scan_prog_var.set(f"0/{pending}")
        a.btn_scan.configure(state="disabled")
        a.btn_stop_scan.configure(state="normal")
        sni = a.scan_sni_var.get().strip() if a.sni_mode_var.get() == "custom" else ""
        a.msg_var.set(f"scan '{name}' — {pending} ip(s) from {cidr}")
        threading.Thread(
            target=a._scan_job,
            args=(session, port, workers, a.scan_frag_var.get(), sni),
            daemon=True).start()

    def _scan_job(self, session, port: str, workers: int, frag: str,
                  sni: str) -> None:
        a = self
        try:
            session.run(port=port, workers=workers, frag=frag, sni=sni or None,
                        use_curl=a.curl_var.get() and HAS_CURL_CFFI,
                        geo=a.scan_geo_var.get(),
                        timeout=float(a.tmo_var.get() or "5"),
                        stop=a._stop_scan,
                        progress=lambda d, t: a.after(0, a._scan_progress, d, t))
        except Exception as e:
            a.after(0, lambda err=e: a.msg_var.set(f"scan error: {err}"))
        a.after(0, a._finish_scan)

    def _scan_progress(self, done: int, total: int) -> None:
        a = self
        a._scan_done = done
        a.scan_prog_var.set(f"{done}/{total}")
        a.msg_var.set(f"scanning … {done}/{total}")

    def _add_scan_row(self, r) -> None:
        """Insert a ScanResult row into the results tree."""
        a = self
        iid = a.res_tree.insert("", "end", values=(
            r.ip, r.port,
            f"{r.ms:.0f}" if r.ms is not None else "—",
            f"{r.jitter:.0f}" if getattr(r, "jitter", None) is not None else "—",
            getattr(r, "tls", "") or "",
            getattr(r, "cc", "") or "",
            getattr(r, "info", "") or ""))
        a._scan_meta[iid] = (r.ip, r.port, r.ms, getattr(r, "info", "") or "")

    def _finish_scan(self) -> None:
        a = self
        a._scanning = False
        a.btn_scan.configure(state="normal")
        a.btn_stop_scan.configure(state="disabled")
        s = a._scan_session
        if s is not None:
            a.res_tree.delete(*a.res_tree.get_children(""))
            alive = s.alive()
            for r in alive:
                a._add_scan_row(r)
            a.msg_var.set(f"scan '{s.name}' — {len(alive)}/{len(s.results)} "
                          f"alive · {len(s.pending)} pending · session saved "
                          f"(resume or export below)")
        if a._scan_ex:
            try:
                a._scan_ex.shutdown(wait=False)
            except Exception:
                pass
            a._scan_ex = None

    # ------------------------------------------------------------------ sni search
    # Phase 4: probe candidate SNI names against the clean IPs the IP Finder
    # (or any saved scan session) produced.  Working pairs = (clean IP, SNI)
    # combinations the local censorship box currently lets through.
    def _snis_start(self) -> None:
        a = self
        if a._snis_running:
            return
        from xray_forge.core.sni_search import SniSearch
        ips = SniSearch.parse_list(a.snis_ips_var.get())
        snis = SniSearch.parse_list(a.snis_names_var.get())
        if not ips or not snis:
            a.msg_var.set("sni search: need clean ips AND candidate snis "
                          "(try 'presets' / 'from results')")
            return
        try:
            workers = int(a.snis_workers_var.get())
        except Exception:
            workers = 32
        name = a.snis_session_var.get().strip()
        if not name:
            name = "sni_" + time.strftime("%Y%m%d_%H%M%S")
            a.snis_session_var.set(name)
        search = SniSearch(name)
        pending = search.set_targets(ips, snis,
                                     port=a.snis_port_var.get().strip()
                                     or "443",
                                     resume=a.snis_resume_var.get())
        if not pending:
            a.msg_var.set("sni search: session has no pending pairs — "
                          "uncheck resume or pick a new name")
            return
        a._snis_search = search
        a._snis_running = True
        a._stop_snis.clear()
        a.snis_prog_var.set(f"0/{pending}")
        a.btn_stop_snis.configure(state="normal")
        a.msg_var.set(f"sni search '{name}' — {pending} pair(s), "
                      f"{len(ips)} ip × {len(snis)} sni")
        threading.Thread(
            target=a._snis_job,
            args=(search, workers, pending),
            daemon=True).start()

    def _snis_job(self, search, workers: int, pending: int) -> None:
        a = self
        try:
            search.run(port=search.port, workers=workers,
                       frag=a.snis_frag_var.get() or "5,94,1@2",
                       timeout=float(a.tmo_var.get() or "5"),
                       http_check=a.snis_http_var.get(),
                       stop=a._stop_snis,
                       progress=lambda d, t: a.after(
                           0, a._snis_progress, d, t))
        except Exception as e:
            a.after(0, lambda err=e: a.msg_var.set(f"sni search error: {err}"))
        a.after(0, a._snis_finish, pending)

    def _snis_progress(self, done: int, total: int) -> None:
        a = self
        a.snis_prog_var.set(f"{done}/{total}")
        a.msg_var.set(f"sni searching … {done}/{total}")

    def _snis_finish(self, pending: int) -> None:
        a = self
        a._snis_running = False
        a.btn_stop_snis.configure(state="disabled")
        s = a._snis_search
        if s is not None:
            a.snis_tree.delete(*a.snis_tree.get_children(""))
            for h in s.hits():
                a._snis_add_row(h)
            good = len(s.hits())
            a.msg_var.set(f"sni search '{s.name}' — {good}/{len(s.results)} "
                          f"working · {len(s.pending)} pending · session "
                          f"saved (resume to continue)")
            a.snis_prog_var.set(f"{len(s.results)}/{pending}")

    def _snis_add_row(self, h) -> None:
        a = self
        a.snis_tree.insert("", "end", values=(
            h.ip, h.port, h.sni,
            f"{h.tls_ms:.0f}" if h.tls_ms is not None else "—",
            h.tls_ver or "",
            "✓" if h.http_ok else ("—" if h.ok else ""),
            (h.info or "")[:120]))

    def _snis_from_results(self) -> None:
        """Pull alive IPs from the IP Finder results tree."""
        a = self
        ips = []
        for iid in a.res_tree.get_children(""):
            ip = a.res_tree.set(iid, "ip").strip()
            if ip and ip not in ips:
                ips.append(ip)
        if not ips:
            a.msg_var.set("no scan results — run the IP Finder first")
            return
        have = a.snis_ips_var.get().strip()
        merged = (have + " " if have else "") + " ".join(ips[:200])
        a.snis_ips_var.set(merged)
        a.msg_var.set(f"added {len(ips[:200])} ip(s) from the scan results")

    def _snis_presets(self) -> None:
        a = self
        from xray_forge.core.sni_search import DEFAULT_SNI_CANDIDATES
        have = a.snis_names_var.get().strip()
        merged = (have + " " if have else "") + " ".join(DEFAULT_SNI_CANDIDATES)
        a.snis_names_var.set(merged)
        a.msg_var.set(f"added {len(DEFAULT_SNI_CANDIDATES)} preset SNIs")

    def _snis_export_csv(self) -> None:
        a = self
        if a._snis_search is None or not a._snis_search.results:
            a.msg_var.set("no sni search results to export")
            return
        path = filedialog.asksaveasfilename(
            parent=a, defaultextension=".csv",
            filetypes=[("CSV", "*.csv")], initialfile="sni_search.csv")
        if not path:
            return
        a.msg_var.set("csv → " + a._snis_search.export_csv(path))

    def _snis_export_json(self) -> None:
        a = self
        if a._snis_search is None or not a._snis_search.results:
            a.msg_var.set("no sni search results to export")
            return
        path = filedialog.asksaveasfilename(
            parent=a, defaultextension=".json",
            filetypes=[("JSON", "*.json")], initialfile="sni_search.json")
        if not path:
            return
        a.msg_var.set("json → " + a._snis_search.export_json(path))

    def _snis_copy_pair(self, _event=None) -> None:
        """Double-click a row → copy 'IP' and 'sni' hint to clipboard."""
        a = self
        iid = a.snis_tree.focus()
        if not iid:
            return
        ip = a.snis_tree.set(iid, "ip")
        sni = a.snis_tree.set(iid, "sni")
        a.clipboard_clear()
        a.clipboard_append(f"{ip}  sni={sni}")
        a.msg_var.set("copied ip + sni — paste the IP into FORCE IP")

    def _snis_clear(self) -> None:
        a = self
        a.snis_tree.delete(*a.snis_tree.get_children(""))
        a._snis_search = None
        a.snis_prog_var.set("0/0")
        a.msg_var.set("sni search results cleared")

    def _do_geo(self, ip: str | None) -> None:
        a = self
        if ip is None:
            ip = a.geo_ip_var.get().strip()
        if not ip:
            ip = ""
        a.msg_var.set("geo lookup …")
        threading.Thread(target=a._geo_job, args=(ip,), daemon=True).start()

    def _geo_job(self, ip: str) -> None:
        a = self
        txt = geo_lookup(ip)
        a.after(0, lambda: a.geo_txt.set(txt))
        a.after(0, lambda: a.msg_var.set("geo lookup done"))

    def _do_resolve(self) -> None:
        a = self
        host = a.res_host_var.get().strip()
        if not host:
            a.msg_var.set("enter a host")
            return
        a.msg_var.set(f"resolving {host} …")
        threading.Thread(target=a._resolve_job, args=(host,), daemon=True).start()

    def _resolve_job(self, host: str) -> None:
        a = self
        found = resolve_dns_all(host)
        lines = []
        for ip, srcs in found.items():
            lines.append(f"{ip}  ←  {', '.join(srcs)}")
        txt = "\n".join(lines) if lines else "no answers"
        a.after(0, lambda: a.msg_var.set(f"resolved {len(found)} ip(s)"))
        a.after(0, lambda: a._show_resolve_txt(txt))

    def _show_resolve_txt(self, txt: str) -> None:
        # show in geo area temporarily
        self.geo_txt.set(txt)

    def _test_res_rows(self) -> None:
        a = self
        rows = a.res_tree.get_children("")
        if not rows:
            a.msg_var.set("no scan rows")
            return
        a.msg_var.set("testing scan rows (coming in next build)")

    def _use_force_ip(self) -> None:
        a = self
        sel = a.res_tree.selection()
        if not sel:
            a.msg_var.set("select a scan row first")
            return
        iid = sel[0]
        ip = a.res_tree.set(iid, "ip")
        port = a.res_tree.set(iid, "port")
        a.ip_var.set(ip)
        a.port_var.set(port)
        a.ip_on.set(True)
        a.port_on.set(True)
        a._toggle_override()
        a.msg_var.set(f"force ip set to {ip}:{port}")

    def _copy_res_ip(self, event=None) -> None:
        a = self
        iid = a.res_tree.focus()
        if not iid:
            return
        ip = a.res_tree.set(iid, "ip")
        a.clipboard_clear()
        a.clipboard_append(ip)
        a.msg_var.set("ip copied")

    def _clear_res(self) -> None:
        a = self
        a.res_tree.delete(*a.res_tree.get_children(""))
        a.msg_var.set("scan cleared")

    def _scans_dir(self) -> str:
        import os
        from xray_forge.core.settings import data_dir
        return os.path.join(data_dir(), "scans")

    def _scan_sessions_refresh(self) -> None:
        a = self
        import os
        d = a._scans_dir()
        names = []
        if os.path.isdir(d):
            names = sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json"))
        a.sessions_cb.configure(values=names)
        if names and not a.scan_load_var.get():
            a.scan_load_var.set(names[-1])
        a.msg_var.set(f"{len(names)} saved scan session(s)")

    def _scan_load_session(self) -> None:
        a = self
        name = a.scan_load_var.get().strip()
        if not name:
            a.msg_var.set("pick a session to load (or ⟳ refresh)")
            return
        from xray_forge.core.scan_session import ScanSession
        s = ScanSession(name)
        a._scan_session = s
        a.scan_session_var.set(name)
        a.res_tree.delete(*a.res_tree.get_children(""))
        a._scan_meta.clear()
        alive = s.alive()
        for r in alive:
            a._add_scan_row(r)
        a.msg_var.set(f"loaded session '{name}' — {len(alive)} alive, "
                      f"{len(s.pending)} pending")

    def _scan_export(self, kind: str) -> None:
        a = self
        if a._scan_session is None:
            a.msg_var.set("no scan session — run or load one first")
            return
        path = filedialog.asksaveasfilename(
            parent=a, defaultextension=f".{kind}",
            initialfile=f"{a._scan_session.name}.{kind}",
            filetypes=[(f"{kind.upper()} files", f"*.{kind}"),
                       ("All files", "*.*")])
        if not path:
            return
        try:
            (a._scan_session.export_csv if kind == "csv"
             else a._scan_session.export_json)(path)
            a.msg_var.set(f"{kind} exported → {path}")
        except Exception as e:
            messagebox.showerror("export failed", str(e), parent=a)

    def _scan_export_csv(self) -> None:
        self._scan_export("csv")

    def _scan_export_json(self) -> None:
        self._scan_export("json")

    # ------------------------------------------------------------------ close
    def _on_close(self) -> None:
        a = self
        a._stop_test.set()
        a._stop_scan.set()
        a._sub_stop.set()
        a._stop_snis.set()
        try:
            save_settings(a._capture_settings())
        except Exception:
            pass
        a.destroy()


# Compatibility alias (the CLI and GUI both use parse_frag directly).
from xray_forge.core.probe import parse_frag as parse_frag_if_avail  # noqa: E402

# Headless CLI entry point: keep `from xray_forge.app import main` working.
from xray_forge.cli import main  # noqa: E402,F401
