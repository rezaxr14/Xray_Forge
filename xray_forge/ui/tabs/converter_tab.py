"""
Tab · Converter: live config fixing, renaming, and mass override.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from xray_forge.core.config import (
    MODE_FULL, MODE_IPONLY, MODE_CUSTOM, MODES,
    DEFAULT_FP, DEFAULT_CS, DEFAULT_FM, DEFAULT_TEMPLATE,
    compact_json,
)
from xray_forge.core.parser import classify_endpoint, valid_port
from xray_forge.ui.widgets import Switch, Tooltip

# Theme constants (mirror of app.py module-level values)
BG = "#0e1117"
PANEL = "#161b22"
PANEL2 = "#1e2633"
FIELD = "#0a141d"
FG = "#e6edf3"
MUT = "#8b949e"
ACCENT = "#3fa7ff"
ACCENT_H = "#63b8ff"
ACCENT_FG = "#07131f"
GREEN = "#3fb950"
YELLOW = "#d29922"
RED = "#f85149"
PURPLE = "#bc8cff"
MONO = "Courier"
SANS = "Helvetica"


def build(app):
    a = app
    pane = ttk.Panedwindow(a, orient="horizontal")
    pane.pack(fill="both", expand=True, pady=6)

    in_f = tk.Frame(a, background=BG)
    out_f = tk.Frame(a, background=BG)
    pane.add(in_f, weight=1)
    pane.add(out_f, weight=1)

    tk.Label(in_f, text="INPUT — paste raw configs", background=BG,
             foreground=MUT, font=(SANS, 9, "bold"), anchor="w")\
        .pack(fill="x", pady=(0, 4))
    a.input_txt = _make_text(in_f, app=a)
    tk.Label(out_f, text="OUTPUT — fixed configs", background=BG,
             foreground=GREEN, font=(SANS, 9, "bold"), anchor="w")\
        .pack(fill="x", pady=(0, 4))
    a.output_txt = _make_text(out_f, state="disabled", bg="#10241a", app=a)

    # Names sub-tab
    names_tab = tk.Frame(a, background=BG)
    a.nb.add(names_tab, text="  🏷 Names  ")
    nb_bar = tk.Frame(names_tab, background=BG)
    nb_bar.pack(fill="x", pady=(6, 4))
    ttk.Button(nb_bar, text="📋 Copy names only", style="Ghost.TButton",
               command=a.copy_names).pack(side="left")
    tk.Label(nb_bar, text="double-click a row to copy that full config",
             background=BG, foreground=MUT).pack(side="left", padx=10)
    a.names_lb = tk.Listbox(names_tab, background=PANEL, foreground=FG,
                            selectbackground=ACCENT,
                            selectforeground=ACCENT_FG,
                            relief="flat", highlightthickness=0,
                            activestyle="none", font=(MONO, 10))
    n_sb = ttk.Scrollbar(names_tab, orient="vertical",
                         command=a.names_lb.yview)
    a.names_lb.configure(yscrollcommand=n_sb.set)
    a.names_lb.pack(side="left", fill="both", expand=True, pady=(0, 8))
    n_sb.pack(side="left", fill="y", pady=(0, 8), padx=(0, 2))
    a.names_lb.bind("<Double-Button-1>", a._copy_named_line)

    return pane


def _make_text(parent, state="normal", bg=None, app=None):
    bg = bg or PANEL
    wrap = tk.Frame(parent, background=BG)
    wrap.pack(fill="both", expand=True)
    txt = tk.Text(wrap, wrap="none", state=state, undo=True,
                  background=bg, foreground=FG,
                  insertbackground=FG,
                  selectbackground=ACCENT,
                  selectforeground=ACCENT_FG,
                  inactiveselectbackground=PANEL2, relief="flat",
                  padx=10, pady=8, font=(MONO, 10),
                  spacing1=1, spacing3=1)
    ys = ttk.Scrollbar(wrap, orient="vertical", command=txt.yview)
    xs = ttk.Scrollbar(wrap, orient="horizontal", command=txt.xview)
    txt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
    txt.grid(row=0, column=0, sticky="nsew")
    ys.grid(row=0, column=1, sticky="ns")
    xs.grid(row=1, column=0, sticky="ew")
    wrap.rowconfigure(0, weight=1)
    wrap.columnconfigure(0, weight=1)
    txt.bind("<Control-a>", app._select_all)
    return txt


# ===========================================================================
# Rules / naming / override section (added above the notebook by App)
# ===========================================================================

def build_rules(app):
    """Build section 1 · Transformation rules above the notebook."""
    a = app
    rules = ttk.Labelframe(a, text="  1 · Transformation rules  ")
    rules.pack(fill="x", pady=(0, 8))
    for c, w in ((0, 0), (1, 0), (2, 1), (3, 0), (4, 0)):
        rules.columnconfigure(c, weight=w)

    ttk.Label(rules, text="mode", font=(SANS, 10, "bold"))\
        .grid(row=0, column=0, sticky="w", padx=(10, 8), pady=(10, 2))
    mode_cb = ttk.Combobox(rules, textvariable=a.mode_var,
                           values=MODES, state="readonly", width=30,
                           font=(SANS, 10, "bold"))
    mode_cb.grid(row=0, column=1, sticky="w", pady=(10, 2))
    mode_cb.bind("<<ComboboxSelected>>", a._on_mode_change)
    Tooltip(mode_cb,
            "⚡ Full fix : fp→chrome + cipher suites + fragment mask\n"
            "🎯 IP only  : inject NOTHING — only endpoint override / rename\n"
            "🛠 Custom   : the switches below decide")
    a.mode_desc = tk.Label(rules, text="", background=BG,
                           foreground=ACCENT, font=(SANS, 9),
                           anchor="w")
    a.mode_desc.grid(row=0, column=2, columnspan=3, sticky="w",
                     padx=(12, 10), pady=(10, 2))

    swrow = tk.Frame(rules, background=BG)
    swrow.grid(row=1, column=0, columnspan=5, sticky="w",
               padx=(8, 10), pady=(2, 4))
    for var, text, cmd, tip in (
        (a.fp_on, "fp → chrome", a._switch_touched,
         "Replace the fingerprint param with the value below."),
        (a.cs_on, "+ ciphers", a._switch_touched,
         "Inject the TLS cipher-suite list (cs=)."),
        (a.fm_on, "+ mask", a._switch_touched,
         "Inject the fragment-mask JSON (fm=)."),
        (a.rename_var, "rename", None,
         "Regenerate the #name of every config."),
        (a.tls_only_var, "only tls", None,
         "When injecting: skip configs whose security isn't tls."),
    ):
        sw = Switch(swrow, variable=var, command=cmd)
        sw.pack(side="left", padx=(4, 3), pady=2)
        lbl = tk.Label(swrow, text=text, background=BG, foreground=FG,
                       font=(SANS, 10))
        lbl.pack(side="left", padx=(0, 16))
        Tooltip(sw, tip)
        Tooltip(lbl, tip)

    ttk.Label(rules, text="fp (fingerprint)")\
        .grid(row=2, column=0, sticky="w", padx=(10, 6), pady=4)
    a.fp_entry = ttk.Entry(rules, textvariable=a.fp_var, width=14)
    a.fp_entry.grid(row=2, column=1, sticky="w", pady=4)
    ttk.Label(rules, text="cs (cipher suites)")\
        .grid(row=3, column=0, sticky="w", padx=(10, 6), pady=4)
    a.cs_entry = ttk.Entry(rules, textvariable=a.cs_var)
    a.cs_entry.grid(row=3, column=1, columnspan=4, sticky="ew",
                    padx=(0, 10), pady=4)
    ttk.Label(rules, text="fm (mask JSON)")\
        .grid(row=4, column=0, sticky="w", padx=(10, 6), pady=(4, 10))
    a.fm_entry = ttk.Entry(rules, textvariable=a.fm_var)
    a.fm_entry.grid(row=4, column=1, columnspan=4, sticky="ew",
                    padx=(0, 10), pady=(4, 10))
    a._sync_rule_fields()


def build_naming(app):
    """Build section 2 · Naming."""
    a = app
    naming = ttk.Labelframe(a, text="  2 · Naming  ")
    naming.pack(fill="x", pady=(0, 8))
    naming.columnconfigure(1, weight=1)
    ttk.Label(naming, text="template").grid(row=0, column=0, sticky="w",
                                            padx=(10, 6), pady=8)
    a.tpl_entry = ttk.Entry(naming, textvariable=a.tpl_var)
    a.tpl_entry.grid(row=0, column=1, sticky="ew", padx=(0, 4), pady=8)
    Tooltip(a.tpl_entry,
            "Keys: {id} {sub} {path} {ip} {port} {host} {net} {sni} "
            "{proto} {old}")
    ttk.Label(naming, text="start #").grid(row=0, column=2, sticky="e",
                                           padx=(8, 6), pady=8)
    a.start_spin = ttk.Spinbox(naming, from_=1, to=99999,
                               textvariable=a.start_var, width=6)
    a.start_spin.grid(row=0, column=3, sticky="e", padx=(0, 10), pady=8)
    ttk.Button(naming, text="🔑 keys", style="Ghost.TButton",
               command=a._show_keys, width=8)\
        .grid(row=0, column=4, padx=(0, 10), pady=8)


def build_override(app):
    """Build section 3 · Mass override."""
    a = app
    ov = ttk.Labelframe(
        a, text="  3 · Mass override — force one endpoint on EVERY config  ")
    ov.pack(fill="x", pady=(0, 8))
    for c, w in ((0, 0), (1, 0), (2, 1), (3, 0), (4, 0), (5, 0),
                 (6, 0), (7, 0)):
        ov.columnconfigure(c, weight=w)

    ip_sw = Switch(ov, variable=a.ip_on, command=a._toggle_override)
    ip_sw.grid(row=0, column=0, sticky="w", padx=(10, 4), pady=(10, 2))
    Tooltip(ip_sw, "Replace the connect address of every config.\n"
                   "Accepts IPv4, IPv6 or domain.\n"
                   "sni / host / path params are NOT touched.")
    tk.Label(ov, text="FORCE IP", background=BG, foreground=FG,
             font=(SANS, 10, "bold")).grid(row=0, column=1, sticky="w",
                                           pady=(10, 2))
    a.ip_entry = ttk.Entry(ov, textvariable=a.ip_var,
                           style="Field.TEntry", font=(MONO, 11),
                           width=24)
    a.ip_entry.grid(row=0, column=2, sticky="w", padx=(10, 0),
                    pady=(10, 2))
    a.ip_badge_lbl = ttk.Label(ov, textvariable=a.ip_badge,
                               style="Dim.TLabel")
    a.ip_badge_lbl.grid(row=0, column=3, sticky="w", padx=(8, 6),
                        pady=(10, 2))
    port_sw = Switch(ov, variable=a.port_on,
                     command=a._toggle_override)
    port_sw.grid(row=0, column=4, sticky="e", padx=(18, 4), pady=(10, 2))
    Tooltip(port_sw, "Replace the connect port of every config (1–65535).")
    tk.Label(ov, text="FORCE PORT", background=BG, foreground=FG,
             font=(SANS, 10, "bold")).grid(row=0, column=5, sticky="w",
                                           pady=(10, 2))
    a.port_entry = ttk.Entry(ov, textvariable=a.port_var,
                             style="Field.TEntry", font=(MONO, 11),
                             width=8, justify="center")
    a.port_entry.grid(row=0, column=6, sticky="w", padx=(10, 10),
                      pady=(10, 2))
    a.port_badge_lbl = ttk.Label(ov, textvariable=a.port_badge,
                                 style="Dim.TLabel")
    a.port_badge_lbl.grid(row=0, column=7, sticky="w", pady=(10, 2))
    ttk.Button(ov, text="✕ clear override", style="Ghost.TButton",
               command=a._clear_override)\
        .grid(row=1, column=0, columnspan=2, sticky="w", padx=10,
              pady=(2, 4))
    a.ep_lbl = ttk.Label(ov, textvariable=a.ep_preview,
                         style="Preview.TLabel")
    a.ep_lbl.grid(row=1, column=2, columnspan=3, sticky="w", padx=10,
                  pady=(2, 4))
    Tooltip(a.ep_lbl, "Effective endpoint for every config.\n"
                      "'orig' = keep that line's own value.")
    ttk.Label(ov, text="endpoint only — the ws host/sni/path stay exactly "
                       "as they are",
              style="Dim.TLabel")\
        .grid(row=1, column=4, columnspan=4, sticky="e", padx=10,
              pady=(2, 8))
    a._toggle_override()
