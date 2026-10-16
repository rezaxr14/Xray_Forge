"""
Tab · Xray Core: core detection, version check, real-engine testing.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from xray_forge.core.xray_bridge import find_xray_core, check_core_version
from xray_forge.ui.widgets import Switch, Tooltip

# Theme constants
BG = "#0e1117"
PANEL = "#161b22"
FG = "#e6edf3"
MUT = "#8b949e"
ACCENT = "#3fa7ff"
ACCENT_FG = "#07131f"
GREEN = "#3fb950"
MONO = "Courier"
SANS = "Helvetica"


def build(app):
    a = app
    top = ttk.Labelframe(a.xray_tab, text="  1 · Core executable  ")
    top.pack(fill="x", padx=10, pady=(8, 6))
    top.columnconfigure(1, weight=1)

    ttk.Label(top, text="path").grid(row=0, column=0, sticky="w",
                                     padx=(10, 6), pady=(10, 4))
    core_e = ttk.Entry(top, textvariable=a.core_var,
                       style="Field.TEntry", font=(MONO, 10))
    core_e.grid(row=0, column=1, sticky="ew", padx=(0, 6), pady=(10, 4))
    Tooltip(core_e,
            "Full path to xray / xray.exe.\n"
            "v2rayN ships one at:\n"
            "  %APPDATA%\\v2rayN\\bin\\xray\\xray.exe\n"
            "Searched automatically: env XRAY_CORE, v2rayN dirs, ./bin,\n"
            "script dir and PATH.")
    b_browse = ttk.Button(top, text="📂 browse…", style="Ghost.TButton",
                          command=a._pick_core)
    b_browse.grid(row=0, column=2, padx=(0, 4), pady=(10, 4))
    Tooltip(b_browse, "Pick the xray executable manually.")
    b_detect = ttk.Button(top, text="🔍 auto-detect", style="Ghost.TButton",
                          command=a._detect_core)
    b_detect.grid(row=0, column=3, padx=(0, 10), pady=(10, 4))
    Tooltip(b_detect, "Search the usual v2rayN / PATH locations again.")

    ttk.Label(top, text="status").grid(row=1, column=0, sticky="w",
                                       padx=(10, 6), pady=(4, 10))
    st_lbl = tk.Label(top, textvariable=a.core_status_var,
                      background=PANEL, foreground=FG,
                      font=(MONO, 10), anchor="w", padx=8, pady=3)
    st_lbl.grid(row=1, column=1, columnspan=2, sticky="ew", pady=(4, 10))
    b_check = ttk.Button(top, text="⟳ check", style="Ghost.TButton",
                         command=a._check_core_clicked)
    b_check.grid(row=1, column=3, padx=(0, 10), pady=(4, 10))
    Tooltip(b_check, "Run 'xray version' to verify the core works.")

    mid = ttk.Labelframe(a.xray_tab, text="  2 · Core-test settings  ")
    mid.pack(fill="x", padx=10, pady=(0, 6))

    frag_sw = Switch(mid, variable=a.core_frag_on, on_color=GREEN)
    frag_sw.grid(row=0, column=0, sticky="w", padx=(10, 4), pady=10)
    tk.Label(mid, text="fragment (tlshello 5-94)",
             background=BG, foreground=FG, font=(SANS, 10))\
        .grid(row=0, column=1, sticky="w", pady=10)
    Tooltip(frag_sw,
            "Route the core's own TLS through Xray's fragment dialer\n"
            "(packets=tlshello, length=5-94) — same anti-DPI idea as\n"
            "the fm= mask. Keep ON in Iran.")
    ttk.Label(mid, text="workers", style="Dim.TLabel")\
        .grid(row=0, column=2, padx=(24, 4))
    ttk.Spinbox(mid, from_=1, to=16, width=4,
                textvariable=a.core_workers_var)\
        .grid(row=0, column=3, padx=(0, 20))
    Tooltip(mid.winfo_children()[-1],
            "Parallel xray instances. Each spawns a real core process —\n"
            "keep modest (4–8).")
    ttk.Label(mid, text="timeout s", style="Dim.TLabel")\
        .grid(row=0, column=4, padx=(0, 4))
    ttk.Spinbox(mid, from_=3, to=30, width=4,
                textvariable=a.core_timeout_var)\
        .grid(row=0, column=5)

    run = ttk.Labelframe(a.xray_tab, text="  3 · Run  ")
    run.pack(fill="x", padx=10, pady=(0, 6))
    a.btn_core_all = ttk.Button(run, text="⚙  Test via core — ALL",
                                style="Accent.TButton",
                                command=lambda: a._start_core_test(False))
    a.btn_core_all.pack(side="left", padx=10, pady=10)
    a.btn_core_sel = ttk.Button(run, text="⚙  Test via core — SELECTED",
                                style="Ghost.TButton",
                                command=lambda: a._start_core_test(True))
    a.btn_core_sel.pack(side="left", padx=(0, 10))
    tk.Label(run, background=BG, foreground=MUT, font=(SANS, 9),
             text="tests the configs currently in the 📡 Tester list "
                  "(your converted output) — results (REAL delay + exit "
                  "IP + cc) are written into the Tester table").pack(
        side="left", padx=(4, 10))

    note = tk.Label(a.xray_tab, background=BG, foreground=MUT,
                    font=(SANS, 9), justify="left", anchor="w",
                    text=(
                        "WHY: the native tester speaks hand-rolled VLESS — great for standard vless+ws, but "
                        "workers/trojan/impl quirks can refuse it.\n"
                        "This tab runs each config through REAL Xray-core (the same engine v2rayN uses) via a "
                        "local SOCKS port, then asks ip-api for the\n"
                        "EXIT IP + country through the tunnel. That is the definitive answer for "
                        "'where will this proxy put me'.\n\n"
                        "Searched by auto-detect:\n"
                        "  · %APPDATA%\\v2rayN\\bin\\xray\\xray.exe   (v2rayN default)\n"
                        "  · XRAY_CORE environment variable\n"
                        "  · ./bin/xray/xray   · script dir   · PATH"))
    note.pack(fill="x", padx=14, pady=(2, 10))
