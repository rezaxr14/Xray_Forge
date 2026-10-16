"""
Tab · SNI Search: probe candidate SNIs (fronting hosts) against clean IPs.

Pairs the IP Finder's clean-IP output with a list of candidate SNI names:
each (ip, sni) pair gets a fragmented TLS handshake (+ an optional plain
GET through the tunnel).  Working pairs are the (clean IP, live SNI)
combinations you can use in the converter's FORCE IP field.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from xray_forge.core.config import FRAG_PRESETS
from xray_forge.core.sni_search import DEFAULT_SNI_CANDIDATES
from xray_forge.ui.widgets import Tooltip

# Theme constants (same palette as the other tabs)
BG = "#0e1117"
FG = "#e6edf3"
MUT = "#8b949e"
ACCENT = "#3fa7ff"
MONO = "Courier"
SANS = "Helvetica"


def build(app):
    a = app
    page = tk.Frame(a, background=BG)
    a.nb.add(page, text="  🎯 SNI Search  ")
    a.snis_tab = page

    ctl = tk.Frame(page, background=BG)
    ctl.pack(fill="x", padx=8, pady=(8, 2))
    for c in range(10):
        ctl.columnconfigure(c, weight=0)
    ctl.columnconfigure(1, weight=1)

    # ------------------------------------------------------ ips + snis
    ttk.Label(ctl, text="clean ips", style="Dim.TLabel")\
        .grid(row=0, column=0, padx=(0, 4), pady=(2, 2), sticky="w")
    ips_e = ttk.Entry(ctl, textvariable=a.snis_ips_var, font=(MONO, 10),
                      style="Field.TEntry")
    ips_e.grid(row=0, column=1, columnspan=6, sticky="ew", pady=(2, 2))
    Tooltip(ips_e, "Clean IPs to probe (comma / space separated).\n"
                   "Use '⤴ from results' to pull the alive IPs the\n"
                   "IP Finder just found.")
    ttk.Button(ctl, text="⤴ from results", style="Ghost.TButton",
               command=a._snis_from_results).grid(row=0, column=7,
                                                  padx=(6, 0), pady=(2, 2))
    ttk.Label(ctl, text="candidate snis", style="Dim.TLabel")\
        .grid(row=1, column=0, padx=(0, 4), pady=(2, 2), sticky="w")
    snis_e = ttk.Entry(ctl, textvariable=a.snis_names_var, font=(MONO, 10),
                       style="Field.TEntry")
    snis_e.grid(row=1, column=1, columnspan=6, sticky="ew", pady=(2, 2))
    Tooltip(snis_e, "SNI candidates (comma / space separated).\n"
                    "Every candidate × every IP is probed with a\n"
                    "fragmented TLS handshake.")
    ttk.Button(ctl, text="presets", style="Ghost.TButton",
               command=a._snis_presets).grid(row=1, column=7, padx=(6, 0),
                                             pady=(2, 2))

    # ------------------------------------------------------ controls row
    ttk.Label(ctl, text="port", style="Dim.TLabel")\
        .grid(row=2, column=0, padx=(0, 4), pady=(6, 2), sticky="w")
    ttk.Entry(ctl, textvariable=a.snis_port_var, width=6, justify="center",
              font=(MONO, 10), style="Field.TEntry")\
        .grid(row=2, column=1, sticky="w", pady=(6, 2))
    ttk.Label(ctl, text="workers", style="Dim.TLabel")\
        .grid(row=2, column=2, padx=(10, 4), pady=(6, 2))
    ttk.Spinbox(ctl, from_=1, to=200, increment=4, width=5,
                textvariable=a.snis_workers_var)\
        .grid(row=2, column=3, sticky="w", pady=(6, 2))
    ttk.Label(ctl, text="fragment", style="Dim.TLabel")\
        .grid(row=2, column=4, padx=(10, 4), pady=(6, 2))
    ttk.Combobox(ctl, textvariable=a.snis_frag_var, width=12,
                 values=FRAG_PRESETS).grid(row=2, column=5, sticky="w",
                                           pady=(6, 2))
    http_cb = ttk.Checkbutton(ctl, text="http check", variable=a.snis_http_var)
    http_cb.grid(row=2, column=6, sticky="w", padx=(10, 0), pady=(6, 2))
    Tooltip(http_cb, "After the handshake, send a plain GET / — an HTTP\n"
                     "answer is a strong 'fronting works here' signal.")
    ttk.Label(ctl, text="session", style="Dim.TLabel")\
        .grid(row=2, column=7, padx=(14, 4), pady=(6, 2), sticky="e")
    ttk.Entry(ctl, textvariable=a.snis_session_var, width=14,
              font=(MONO, 10), style="Field.TEntry")\
        .grid(row=2, column=8, sticky="w", pady=(6, 2))
    res_cb = ttk.Checkbutton(ctl, text="resume", variable=a.snis_resume_var)
    res_cb.grid(row=2, column=9, sticky="w", pady=(6, 2))

    # ------------------------------------------------------ run row
    ttk.Button(ctl, text="⚡ Search", style="Accent.TButton",
               command=a._snis_start).grid(row=3, column=0, columnspan=2,
                                           sticky="w", pady=(8, 2))
    a.btn_stop_snis = ttk.Button(ctl, text="■ stop", style="Ghost.TButton",
                                 command=a._stop_snis.set, state="disabled")
    a.btn_stop_snis.grid(row=3, column=2, sticky="w", padx=(8, 0),
                         pady=(8, 2))
    ttk.Label(ctl, textvariable=a.snis_prog_var, style="Preview.TLabel")\
        .grid(row=3, column=3, sticky="w", padx=(12, 0), pady=(8, 2))
    ttk.Button(ctl, text="⭳ csv", style="Ghost.TButton",
               command=a._snis_export_csv).grid(row=3, column=6, sticky="e",
                                                pady=(8, 2))
    ttk.Button(ctl, text="⭳ json", style="Ghost.TButton",
               command=a._snis_export_json).grid(row=3, column=7,
                                                 sticky="e", pady=(8, 2))
    ttk.Button(ctl, text="🗑 clear", style="Ghost.TButton",
               command=a._snis_clear).grid(row=3, column=8, sticky="w",
                                           padx=(8, 0), pady=(8, 2))

    tk.Label(ctl, background=BG, foreground=MUT, font=(SANS, 9),
             text="working (ip, sni) pairs → put the IP in FORCE IP and the "
                  "SNI in the config's sni= (Configs tab)")\
        .grid(row=4, column=0, columnspan=10, sticky="w", pady=(2, 2))

    # ------------------------------------------------------ results tree
    cols = {"ip": (140, "w"), "port": (55, "e"), "sni": (190, "w"),
            "ms": (60, "e"), "tls": (85, "w"), "http": (60, "w"),
            "info": (250, "w")}
    a.snis_tree = a._make_tree(page, cols, {"ms", "port"})
    a.snis_tree.pack(fill="both", expand=True, padx=(8, 8), pady=(4, 8))
    a.snis_tree.bind("<Double-Button-1>", a._snis_copy_pair)
    return page
