"""
Tab · IP Finder: geo lookup, DNS resolve, CIDR scanning.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from xray_forge.core.config import FRAG_PRESETS, CF_RANGES
from xray_forge.ui.widgets import Tooltip

# Theme constants
BG = "#0e1117"
FG = "#e6edf3"
MUT = "#8b949e"
ACCENT = "#3fa7ff"
PANEL = "#161b22"
MONO = "Courier"
SANS = "Helvetica"


def build(app):
    a = app
    top = tk.Frame(a.find_tab, background=BG)
    top.pack(fill="x", pady=(6, 4))

    ttk.Button(top, text="🌐 my IP", style="Ghost.TButton",
               command=lambda: a._do_geo(None)).pack(side="left")
    ttk.Label(top, text="  lookup IP:", style="Dim.TLabel")\
        .pack(side="left", padx=(12, 4))
    geo_e = ttk.Entry(top, textvariable=a.geo_ip_var, width=24,
                      style="Field.TEntry", font=(MONO, 10))
    geo_e.pack(side="left")
    Tooltip(geo_e, "Any IPv4/IPv6/domain. Empty = your own IP.")
    ttk.Button(top, text="🔎 geo", style="Ghost.TButton",
               command=lambda: a._do_geo(
                   a.geo_ip_var.get().strip()))\
        .pack(side="left", padx=(6, 0))
    tk.Label(top, textvariable=a.geo_txt, background=PANEL,
             foreground=FG, font=(MONO, 10), justify="left",
             anchor="w", padx=10, pady=4).pack(fill="x", pady=(4, 0))

    body = ttk.Labelframe(
        a.find_tab,
        text="  resolve host · scan CIDR for alive IPs (fragmented probes)  ")
    body.pack(fill="both", expand=True, pady=(6, 0))
    ctl = tk.Frame(body, background=BG)
    ctl.pack(fill="x", padx=8, pady=(6, 2))

    ttk.Label(ctl, text="cidr", style="Dim.TLabel")\
        .grid(row=0, column=0, padx=(0, 4))
    cidr_cb = ttk.Combobox(ctl, textvariable=a.scan_cidr_var,
                           values=CF_RANGES, width=16, font=(MONO, 10))
    cidr_cb.grid(row=0, column=1, padx=(0, 10))
    ttk.Label(ctl, text="count", style="Dim.TLabel").grid(row=0, column=2,
                                                          padx=(0, 4))
    ttk.Spinbox(ctl, from_=10, to=5000, increment=10, width=6,
                textvariable=a.scan_count_var).grid(row=0, column=3,
                                                    padx=(0, 10))
    ttk.Label(ctl, text="workers", style="Dim.TLabel").grid(row=0,
                                                            column=4,
                                                            padx=(0, 4))
    ttk.Spinbox(ctl, from_=4, to=300, increment=4, width=5,
                textvariable=a.scan_workers_var).grid(row=0, column=5,
                                                      padx=(0, 10))
    ttk.Label(ctl, text="port", style="Dim.TLabel").grid(row=0, column=6,
                                                         padx=(0, 4))
    a.scan_port_e = ttk.Entry(ctl, textvariable=a.scan_port_var,
                              width=6, justify="center",
                              font=(MONO, 10))
    a.scan_port_e.grid(row=0, column=7, padx=(0, 10))
    ttk.Label(ctl, text="sni", style="Dim.TLabel").grid(row=0, column=8,
                                                        padx=(0, 4))
    a.scan_sni_e = ttk.Entry(ctl, textvariable=a.scan_sni_var,
                             width=22, font=(MONO, 10))
    a.scan_sni_e.grid(row=0, column=9, padx=(0, 10))
    ttk.Label(ctl, text="sni mode", style="Dim.TLabel")\
        .grid(row=1, column=0, padx=(0, 4), pady=(6, 2))
    sni_cb = ttk.Combobox(ctl, textvariable=a.sni_mode_var, width=11,
                          state="readonly",
                          values=("config sni", "no sni", "custom"))
    sni_cb.grid(row=1, column=1, sticky="w", pady=(6, 2))
    Tooltip(sni_cb,
            "config sni : hello carries your worker's SNI\n"
            "no sni     : raw IP aliveness (works even if SNI is blocked)\n"
            "custom     : use the sni field")
    ttk.Label(ctl, text="fragment", style="Dim.TLabel")\
        .grid(row=1, column=2, sticky="e", pady=(6, 2))
    sfrag_cb = ttk.Combobox(ctl, textvariable=a.scan_frag_var,
                            width=12, values=FRAG_PRESETS)
    sfrag_cb.grid(row=1, column=3, sticky="w", pady=(6, 2))
    Tooltip(sfrag_cb, "KEEP THIS ON in Iran — unfragmented scan hellos\n"
                      "get RST and every IP looks 'dead'.")
    curl_cb = ttk.Checkbutton(ctl, text="browser hello (curl_cffi)",
                              variable=a.curl_var)
    curl_cb.grid(row=1, column=4, columnspan=3, sticky="w", pady=(6, 2))
    # HAS_CURL_CFFI defined in app.py
    try:
        curl_cb.config(state="normal" if app.HAS_CURL_CFFI else "disabled")
    except Exception:
        pass
    a.btn_scan = ttk.Button(ctl, text="⚡  Scan", style="Accent.TButton",
                            command=a._start_scan)
    a.btn_scan.grid(row=1, column=7, columnspan=2, sticky="e",
                    padx=(6, 4), pady=(6, 2))
    a.btn_stop_scan = ttk.Button(ctl, text="■", style="Ghost.TButton",
                                 width=3, command=a._stop_scan.set,
                                 state="disabled")
    a.btn_stop_scan.grid(row=1, column=9, sticky="e", pady=(6, 2))

    ttk.Label(ctl, text="resolve", style="Dim.TLabel")\
        .grid(row=2, column=0, columnspan=2, sticky="w", padx=(0, 4),
              pady=(6, 2))
    a.res_host_e = ttk.Entry(ctl, textvariable=a.res_host_var,
                             font=(MONO, 10))
    a.res_host_e.grid(row=2, column=2, columnspan=6, sticky="ew",
                      pady=(6, 2))
    a.res_host_e.bind("<Return>", lambda e: a._do_resolve())
    ttk.Button(ctl, text="➾ resolve DNS", style="Ghost.TButton",
               command=a._do_resolve).grid(row=2, column=8,
                                           columnspan=2, sticky="w",
                                           pady=(6, 2))
    ttk.Label(ctl, textvariable=a.scan_prog_var,
              style="Preview.TLabel").grid(row=2, column=10, sticky="e",
                                           pady=(6, 2))
    ctl.columnconfigure(2, weight=1)
    tk.Label(ctl, background=BG, foreground=MUT, font=(SANS, 9),
             text="resolve compares DoH (1.1.1.1 / 8.8.8.8 / shecan / 403)"
                  " + Iranian UDP resolvers + system DNS — if they "
                  "disagree, your DNS is poisoned")\
        .grid(row=3, column=0, columnspan=11, sticky="w", pady=(2, 2))

    rbar = tk.Frame(body, background=BG)
    rbar.pack(fill="x", padx=8, pady=(2, 4))
    ttk.Button(rbar, text="🧪 test rows (TLS)", style="Ghost.TButton",
               command=a._test_res_rows).pack(side="left")
    use_btn = ttk.Button(rbar, text="⤴ use as FORCE IP",
                         style="Ghost.TButton", command=a._use_force_ip)
    use_btn.pack(side="left", padx=(8, 0))
    Tooltip(use_btn, "Put the selected row's IP into FORCE IP on the "
                     "Configs tab.")
    ttk.Button(rbar, text="📋 copy IP", style="Ghost.TButton",
               command=a._copy_res_ip).pack(side="left", padx=(8, 0))
    ttk.Button(rbar, text="🗑 clear", style="Ghost.TButton",
               command=a._clear_res).pack(side="left", padx=(8, 0))
    tk.Label(rbar, text="double-click row → copy IP",
             background=BG, foreground=MUT).pack(side="right")

    cols = {"ip": (150, "w"), "port": (60, "e"), "ms": (70, "e"),
            "tls": (90, "w"), "info": (250, "w")}
    a.res_tree = a._make_tree(body, cols, {"ms", "port"})
    a.res_tree.pack(fill="both", expand=True, padx=(8, 8), pady=(0, 8))
    a.res_tree.bind("<Double-Button-1>", a._copy_res_ip)
