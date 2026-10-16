"""
Tab · Tester: fragmented probes, REAL delay, exit-country, core testing.
"""

import tkinter as tk
from tkinter import ttk

from xray_forge.core.config import FRAG_PRESETS, TEST_TARGET_DEFAULT
from xray_forge.core.prober_utils import fmt_ms, cc_cell
from xray_forge.ui.widgets import Switch, Tooltip

# Theme constants
BG = "#0e1117"
FG = "#e6edf3"
MUT = "#8b949e"
ACCENT = "#3fa7ff"
GREEN = "#3fb950"
MONO = "Courier"
SANS = "Helvetica"


def build(app):
    a = app
    tbar = tk.Frame(a.test_tab, background=BG)
    tbar.pack(fill="x", pady=(6, 2))

    a.btn_test_all = ttk.Button(tbar, text="▶  Test all",
                                style="Accent.TButton",
                                command=lambda: a._start_test(False))
    a.btn_test_all.pack(side="left")
    a.btn_test_sel = ttk.Button(tbar, text="▶  Test selected",
                                style="Ghost.TButton",
                                command=lambda: a._start_test(True))
    a.btn_test_sel.pack(side="left", padx=(8, 0))
    a.btn_stop_test = ttk.Button(tbar, text="■  Stop",
                                 style="Ghost.TButton",
                                 command=a._stop_test.set,
                                 state="disabled")
    a.btn_stop_test.pack(side="left", padx=(8, 14))

    ttk.Label(tbar, text="mode", style="Dim.TLabel").pack(side="left")
    tmode_cb = ttk.Combobox(tbar, textvariable=a.mode_test_var,
                            width=22, state="readonly",
                            values=("full (ws + REAL delay)", "ws only",
                                    "tls only", "tcp only"))
    tmode_cb.pack(side="left", padx=(4, 12))
    Tooltip(tmode_cb,
            "full : TCP ping + fragmented TLS + ws 101 + REAL delay/exit\n"
            "ws   : TCP + TLS + 101 upgrade (+ exit country)\n"
            "tls  : TCP + fragmented TLS handshake\n"
            "tcp  : TCP ping only (fastest)")
    ttk.Label(tbar, text="fragment", style="Dim.TLabel").pack(side="left")
    frag_cb = ttk.Combobox(tbar, textvariable=a.frag_var, width=12,
                           values=FRAG_PRESETS)
    frag_cb.pack(side="left", padx=(4, 12))
    Tooltip(frag_cb,
            "ClientHello fragmentation — THE anti-DPI trick.\n"
            "'5,94,1@2' = chunks of 5,94,1 bytes with 2 ms gaps\n"
            "(same as the fm= mask in your configs).")
    ttk.Label(tbar, text="timeout s", style="Dim.TLabel").pack(side="left")
    ttk.Spinbox(tbar, from_=1, to=15, increment=0.5, width=4,
                textvariable=a.tmo_var).pack(side="left", padx=(4, 12))
    ttk.Label(tbar, text="attempts", style="Dim.TLabel").pack(side="left")
    ttk.Spinbox(tbar, from_=1, to=5, width=3,
                textvariable=a.att_var).pack(side="left", padx=(4, 12))
    ttk.Label(tbar, text="workers", style="Dim.TLabel").pack(side="left")
    ttk.Spinbox(tbar, from_=1, to=64, width=4,
                textvariable=a.workers_test_var)\
        .pack(side="left", padx=(4, 12))
    ttk.Label(tbar, textvariable=a.test_prog_var,
              style="Preview.TLabel").pack(side="right", padx=8)
    ttk.Label(tbar, textvariable=a.test_info_var, style="Dim.TLabel")\
        .pack(side="right")

    tbar2 = tk.Frame(a.test_tab, background=BG)
    tbar2.pack(fill="x", pady=(0, 4))

    cc_sw = Switch(tbar2, variable=a.cc_on)
    cc_sw.pack(side="left", padx=(0, 3))
    tk.Label(tbar2, text="exit country", background=BG, foreground=FG,
             font=(SANS, 10, "bold")).pack(side="left", padx=(0, 12))
    Tooltip(cc_sw,
            "After ws-101, fetch a geo API THROUGH the vless tunnel\n"
            "(ip-api → ipwho.is → ipinfo, rotated per row) to learn the\n"
            "country you will ACTUALLY appear to be in (+ exit IP).\n"
            "The geo request doubles as the REAL-delay probe.\n"
            "Fallback: geo of the edge IP, marked '*' (approximation).\n"
            "For trojan/odd-uuid configs use the 🧩 Xray Core tab.")
    a.btn_core_quick = ttk.Button(tbar2, text="⚙ via core",
                                  style="Ghost.TButton",
                                  command=lambda:
                                  a._start_core_test(False))
    a.btn_core_quick.pack(side="left", padx=(0, 12))
    Tooltip(a.btn_core_quick,
            "Run every config through the REAL xray core (set path in\n"
            "the 🧩 Xray Core tab) and fetch exit IP + country through\n"
            "it — v2rayN-parity results, works for trojan too.")
    tag_btn = ttk.Button(tbar2, text="🏷 tag names [CC]",
                         style="Ghost.TButton",
                         command=a._tag_names_with_cc)
    tag_btn.pack(side="left", padx=(0, 12))
    Tooltip(tag_btn,
            "Append the verified exit country to every #name,\n"
            "e.g. 07_edgestuff_sort[NL]. Uses verified results only\n"
            "('*' edge guesses are skipped).")
    ttk.Label(tbar2, text="REAL-delay target", style="Dim.TLabel")\
        .pack(side="left")
    tgt_e = ttk.Entry(tbar2, textvariable=a.target_var, width=28,
                      style="Field.TEntry", font=(MONO, 10))
    tgt_e.pack(side="left", padx=(6, 12))
    Tooltip(tgt_e,
            "URL fetched THROUGH the tunnel for the REAL delay\n"
            "(used when 'exit country' is OFF; when ON, the geo\n"
            "request doubles as the delay probe).")
    tk.Label(tbar2, background=BG, foreground=MUT, font=(SANS, 9),
             text="fragment ON = probes survive Iranian DPI").pack(
        side="left")

    cols = {"name": (190, "w"), "endpoint": (165, "w"), "tcp": (55, "e"),
            "tls": (55, "e"), "ws": (55, "e"), "real": (60, "e"),
            "cc": (84, "w"), "status": (300, "w")}
    a.test_tree = a._make_tree(a.test_tab, cols,
                               {"tcp", "tls", "ws", "real"})
    a.test_tree.pack(fill="both", expand=True, pady=(0, 2))
    a.test_tree.bind("<Double-Button-1>", a._copy_test_line)
    tk.Label(a.test_tab, background=BG, foreground=MUT,
             font=(SANS, 9), anchor="w",
             text="double-click a row → copy that config · 101 = ws alive "
                  "· REAL = latency through the tunnel · cc = exit country "
                  "🇳🇱 NL, '*'=edge-IP guess").pack(fill="x", pady=(0, 6))
