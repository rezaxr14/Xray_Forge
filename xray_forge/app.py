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
        self._test_ex: ThreadPoolExecutor | None = None
        self._scan_ex: ThreadPoolExecutor | None = None
        self._cc_cache: dict[str, str] = {}
        self._cc_lock = threading.Lock()
        self._sub_reports: list = []
        self._sub_stop = threading.Event()
        self._subs_checking = False
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

        subs_tab = tk.Frame(container, background=BG)
        nb.add(subs_tab, text="  📥 Subscriptions  ")
        a.subs_tab = subs_tab
        build_subs(a)

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
            "core_var": str, "core_timeout_var": str,
            "fake_sni_var": str, "domain_front_var": str,
            "sub_core_var": str,
        }
        bool_vars = [
            "fp_on", "cs_on", "fm_on", "rename_var", "tls_only_var",
            "auto_var", "ip_on", "port_on", "cc_on", "core_frag_on",
            "curl_var", "dedup_var", "show_best_var",
            "record_frag_var", "sni_case_var", "sub_thr_var",
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
            "res_host_var", "core_var", "core_timeout_var",
            "fake_sni_var", "domain_front_var", "sub_core_var",
        ]
        bool_vars = [
            "fp_on", "cs_on", "fm_on", "rename_var", "tls_only_var",
            "auto_var", "ip_on", "port_on", "cc_on", "core_frag_on",
            "curl_var", "dedup_var", "show_best_var",
            "record_frag_var", "sni_case_var", "sub_thr_var",
        ]
        int_vars = ["start_var", "att_var", "workers_test_var",
                    "scan_count_var", "scan_workers_var",
                    "core_workers_var", "sub_workers_var", "sub_timeout_var",
                    "sub_top_var"]
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
            a.after(0, lambda: a.sub_status_var.set(f"fetch error: {e}"))
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
            a.after(0, lambda: a.sub_status_var.set(f"check error: {e}"))
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
        ips = sample_cidr(cidr, count)
        if not ips:
            a.msg_var.set("invalid CIDR")
            return
        a._scanning = True
        a._stop_scan.clear()
        a._scan_done = 0
        a._scan_total = len(ips)
        a._scan_alive = 0
        a.res_tree.delete(*a.res_tree.get_children(""))
        a.scan_prog_var.set(f"0/{a._scan_total}")
        a.btn_scan.configure(state="disabled")
        a.btn_stop_scan.configure(state="normal")
        a._scan_ex = ThreadPoolExecutor(max_workers=workers)
        sni = a.scan_sni_var.get().strip() if a.sni_mode_var.get() == "custom" else ""
        frag = parse_frag_if_avail(a.scan_frag_var.get())
        futs = {}
        for ip in ips:
            futs[a._scan_ex.submit(a._scan_one, ip, port, sni, frag)] = None
        # track order via dict of future->ip
        fut_map = {}
        for ip in ips:
            fut_map[a._scan_ex.submit(a._scan_one, ip, port, sni, frag)] = ip
        threading.Thread(target=a._poll_scan, args=(fut_map,),
                         daemon=True).start()

    def _scan_one(self, ip: str, port: str, sni: str, frag) -> dict:
        a = self
        res = {"ip": ip, "port": port, "ms": None, "tls": "", "info": "",
               "alive": False}
        tmo = float(a.tmo_var.get() or "8")
        try:
            use_sni = sni
            if a.sni_mode_var.get() == "config sni":
                use_sni = None  # raw ip
            elif a.sni_mode_var.get() == "no sni":
                use_sni = None
            if a.curl_var.get() and HAS_CURL_CFFI:
                info = curl_cffi_probe(ip, port, use_sni, timeout=tmo)
                res["ms"] = info["tls_ms"]
                res["tls"] = info["ver"]
                res["alive"] = True
                res["info"] = f"curl_cffi {info['ver']}"
            else:
                tc, sock, info = tls_connect(
                    ip, port, sni=use_sni, frag=frag, timeout=tmo,
                    stop=a._stop_test, fake_sni=a.fake_sni_var.get() or None,
                    record_frag=a.record_frag_var.get())
                res["ms"] = info["tls_ms"]
                res["tls"] = info["ver"]
                res["alive"] = True
                res["info"] = f"{info['ver']} tls ok"
                try:
                    sock.close()
                except Exception:
                    pass
        except ProbeError as pe:
            res["info"] = f"{pe.stage}: {pe.detail[:30]}"
        except Exception as e:
            res["info"] = f"err: {type(e).__name__}"
        return res

    def _poll_scan(self, fut_map: dict) -> None:
        a = self
        done = 0
        for fut in as_completed(fut_map):
            if a._stop_scan.is_set():
                break
            ip = fut_map[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"ip": ip, "port": a.scan_port_var.get(), "ms": None,
                       "tls": "", "info": str(e), "alive": False}
            done += 1
            a._scan_done = done
            a.after(0, lambda: a.scan_prog_var.set(f"{done}/{a._scan_total}"))
            if res.get("alive"):
                a._scan_alive += 1
                a.after(0, a._add_scan_row, res)
        a.after(0, a._finish_scan)

    def _add_scan_row(self, res: dict) -> None:
        a = self
        iid = a.res_tree.insert("", "end", values=(
            res["ip"], res["port"],
            f"{res['ms']:.0f}" if res.get("ms") is not None else "—",
            res.get("tls", ""), res.get("info", "")))
        a._scan_meta[iid] = (res["ip"], res["port"], res.get("ms"), "")

    def _finish_scan(self) -> None:
        a = self
        a._scanning = False
        a.btn_scan.configure(state="normal")
        a.btn_stop_scan.configure(state="disabled")
        a.msg_var.set(f"scan complete — {a._scan_alive}/{a._scan_total} alive")
        if a._scan_ex:
            try:
                a._scan_ex.shutdown(wait=False)
            except Exception:
                pass
            a._scan_ex = None

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

    # ------------------------------------------------------------------ close
    def _on_close(self) -> None:
        a = self
        a._stop_test.set()
        a._stop_scan.set()
        a._sub_stop.set()
        try:
            save_settings(a._capture_settings())
        except Exception:
            pass
        a.destroy()


# Compatibility alias (the CLI and GUI both use parse_frag directly).
from xray_forge.core.probe import parse_frag as parse_frag_if_avail  # noqa: E402

# Headless CLI entry point: keep `from xray_forge.app import main` working.
from xray_forge.cli import main  # noqa: E402,F401
