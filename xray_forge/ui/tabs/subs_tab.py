"""
Tab · Subscriptions: source manager + staged health checks + best-N export.

Wraps :mod:`xray_forge.core.sub_source` (URL sources, ETag cache, format
auto-detection, dedup) and :mod:`xray_forge.core.healthcheck` (staged
DNS → TCP → TLS → request → download/upload pipeline with scoring).

All long work runs in daemon threads; UI updates go through ``a.after``.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from xray_forge.core.cores import core_names
from xray_forge.ui.widgets import Tooltip

# Theme constants (same palette as the other tabs)
BG = "#0e1117"
FG = "#e6edf3"
MUT = "#8b949e"
ACCENT = "#3fa7ff"
GREEN = "#3fb950"
MONO = "Courier"
SANS = "Helvetica"


def build(app):
    a = app

    # ------------------------------------------------------------- sources
    bar = tk.Frame(a.subs_tab, background=BG)
    bar.pack(fill="x", pady=(6, 4))

    ttk.Button(bar, text="➕ add source", style="Accent.TButton",
               command=a._subs_add).pack(side="left")
    ttk.Button(bar, text="🗑 remove", style="Ghost.TButton",
               command=a._subs_remove).pack(side="left", padx=(8, 0))
    toggle_btn = ttk.Button(bar, text="⇄ enable/disable",
                            style="Ghost.TButton", command=a._subs_toggle)
    toggle_btn.pack(side="left", padx=(8, 0))
    Tooltip(toggle_btn,
            "Disabled sources are skipped by fetch/checks but kept.\n"
            "Double-click a source row to copy its URL.")
    ttk.Button(bar, text="⬇ fetch all", style="Ghost.TButton",
               command=a._subs_fetch).pack(side="left", padx=(14, 0))
    ttk.Button(bar, text="⟳ refresh", style="Ghost.TButton",
               command=a._subs_refresh_list).pack(side="left", padx=(8, 0))
    ttk.Label(bar, textvariable=a.sub_status_var, style="Dim.TLabel")\
        .pack(side="right")

    cols = {"on": (30, "center"), "name": (150, "w"), "url": (330, "w"),
            "etag": (100, "w"), "last fetch": (130, "w"),
            "status": (150, "w"), "count": (50, "e")}
    a.subs_tree = a._make_tree(a.subs_tab, cols, set())
    a.subs_tree.pack(fill="both", expand=True, pady=(0, 4))
    a.subs_tree.bind("<Double-Button-1>", a._subs_copy_url)

    # -------------------------------------------------------- health check
    hc_frame = ttk.Labelframe(
        a.subs_tab,
        text="  health check — dns → tcp → tls(frag variants) → request → "
             "down/up throughput  ")
    hc_frame.pack(fill="x", pady=(2, 4))

    row = tk.Frame(hc_frame, background=BG)
    row.pack(fill="x", padx=8, pady=(6, 2))

    a.btn_subs_check = ttk.Button(row, text="▶  Check all sources",
                                  style="Accent.TButton",
                                  command=a._subs_check)
    a.btn_subs_check.pack(side="left")
    a.btn_subs_stop = ttk.Button(row, text="■  Stop", style="Ghost.TButton",
                                 command=a._sub_stop.set, state="disabled")
    a.btn_subs_stop.pack(side="left", padx=(8, 14))

    ttk.Label(row, text="workers", style="Dim.TLabel").pack(side="left")
    ttk.Spinbox(row, from_=1, to=64, width=4,
                textvariable=a.sub_workers_var).pack(side="left", padx=(4, 12))
    ttk.Label(row, text="timeout s", style="Dim.TLabel").pack(side="left")
    ttk.Spinbox(row, from_=2, to=30, increment=0.5, width=4,
                textvariable=a.sub_timeout_var).pack(side="left", padx=(4, 12))
    ttk.Label(row, text="top N", style="Dim.TLabel").pack(side="left")
    ttk.Spinbox(row, from_=1, to=200, width=5,
                textvariable=a.sub_top_var).pack(side="left", padx=(4, 12))

    ttk.Label(row, text="core", style="Dim.TLabel").pack(side="left")
    core_cb = ttk.Combobox(row, textvariable=a.sub_core_var, width=9,
                           state="readonly",
                           values=("native only", "auto", *core_names()))
    core_cb.pack(side="left", padx=(4, 12))
    Tooltip(core_cb,
            "native only : probes run in-process (vless/ws only)\n"
            "auto / xray / singbox / mihomo : non-vless configs (trojan,\n"
            "vmess, ss, hy2, tuic, warp) are checked through a real core\n"
            "binary spawned locally with a socks inbound.")
    thr_sw = ttk.Checkbutton(row, text="throughput (down+up)",
                             variable=a.sub_thr_var)
    thr_sw.pack(side="left", padx=(0, 12))
    Tooltip(thr_sw,
            "Upload throttling is common on Iranian networks: a config\n"
            "can pass latency checks yet be unusable — measure both ways.")

    prog = tk.Frame(hc_frame, background=BG)
    prog.pack(fill="x", padx=8, pady=(0, 6))
    a.btn_subs_export = ttk.Button(prog, text="⭳ export best-N subscription",
                                   style="Ghost.TButton",
                                   command=a._subs_export)
    a.btn_subs_export.pack(side="left")
    a.btn_subs_use = ttk.Button(prog, text="➾ send working → Configs tab",
                                style="Ghost.TButton",
                                command=a._subs_use)
    a.btn_subs_use.pack(side="left", padx=(8, 0))
    ttk.Label(prog, textvariable=a.sub_prog_var, style="Preview.TLabel")\
        .pack(side="right")

    # ------------------------------------------------------------ results
    rcols = {"name": (170, "w"), "scheme": (62, "w"), "score": (44, "e"),
             "req": (48, "e"), "down": (80, "e"), "up": (80, "e"),
             "technique tags": (170, "w"), "status": (230, "w")}
    a.subres_tree = a._make_tree(a.subs_tab, rcols, set())
    a.subres_tree.pack(fill="both", expand=True, pady=(0, 4))
    a.subres_tree.bind("<Double-Button-1>", a._subs_copy_config)
    tk.Label(a.subs_tab, background=BG, foreground=MUT,
             font=(SANS, 9), anchor="w",
             text="double-click a result row → copy that config · "
                  "score = staged pipeline (100 = fast + full throughput) · "
                  "tags = anti-DPI techniques that worked").pack(
        fill="x", pady=(0, 6))
