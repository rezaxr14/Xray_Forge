"""
Tab · Editor: per-config field editor + raw-JSON round-trip.

Phase-1 GUI work: the core APIs (``Outbound`` fields, protocol handlers'
``to_uri``) were already Reality/XHTTP/flow-ready — this tab surfaces them.

Layout:

    [ toolbar: config picker · reload · apply · copy          status ]
    [ form: Basic | Transport | Security | Reality/VMess ] [ raw JSON ]

The form covers the common vless / vmess / trojan fields; the JSON pane is
the full-fidelity view of the underlying :class:`Outbound` (any extra
protocol params stay editable there).  Logic lives in ``app.py``
(``a._editor_*`` methods), mirroring the other tabs.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from xray_forge.core.config import FLOWS, TRANSPORTS
from xray_forge.ui.widgets import Switch, Tooltip

# Theme constants (mirror of app.py module-level values)
BG = "#0e1117"
PANEL = "#161b22"
FIELD = "#0a141d"
FG = "#e6edf3"
MUT = "#8b949e"
ACCENT = "#3fa7ff"
ACCENT_FG = "#07131f"
GREEN = "#3fb950"
MONO = "Courier"
SANS = "Helvetica"

XHTTP_MODES = ["", "auto", "packet-up", "stream-up", "stream-one"]
SECURITIES = ["", "none", "tls", "reality"]


def build(app):
    a = app
    page = tk.Frame(a, background=BG)
    a.nb.add(page, text="  ✎ Editor  ")
    a.edit_tab = page

    # ------------------------------------------------------------ toolbar
    bar = tk.Frame(page, background=BG)
    bar.pack(fill="x", pady=(6, 4))
    ttk.Label(bar, text="config", style="Dim.TLabel").pack(side="left")
    a.ed_pick_var = tk.StringVar(value="")
    a.ed_pick_cb = ttk.Combobox(bar, textvariable=a.ed_pick_var,
                                state="readonly", width=58, font=(MONO, 9))
    a.ed_pick_cb.pack(side="left", padx=(6, 8))
    a.ed_pick_cb.bind("<<ComboboxSelected>>", a._editor_load)
    Tooltip(a.ed_pick_cb, "Configs from the OUTPUT pane, in order.\n"
                          "Pick one, edit the fields, then apply.")
    ttk.Button(bar, text="⟳ reload list", style="Ghost.TButton",
               command=lambda: a._editor_refresh(False))\
        .pack(side="left")
    a.ed_apply_btn = ttk.Button(bar, text="✓ apply → output",
                                style="Accent.TButton",
                                command=a._editor_apply)
    a.ed_apply_btn.pack(side="left", padx=(8, 0))
    Tooltip(a.ed_apply_btn, "Regenerate the share link from the form and\n"
                            "replace that line in the OUTPUT pane.\n"
                            "(re-converting the input discards edits)")
    ttk.Button(bar, text="📋 copy URI", style="Ghost.TButton",
               command=a._editor_copy).pack(side="left", padx=(8, 0))
    a.ed_status_var = tk.StringVar(value="no config loaded")
    ttk.Label(bar, textvariable=a.ed_status_var, style="Dim.TLabel")\
        .pack(side="right", padx=(8, 2))

    # ------------------------------------------------------- form + JSON
    split = ttk.Panedwindow(page, orient="horizontal")
    split.pack(fill="both", expand=True, pady=(0, 6))
    form = tk.Frame(split, background=BG)
    jsn = tk.Frame(split, background=BG)
    split.add(form, weight=3)
    split.add(jsn, weight=2)

    # editor field vars
    a.ed_scheme_var = tk.StringVar(value="")
    a.ed_name_var = tk.StringVar(value="")
    a.ed_host_var = tk.StringVar(value="")
    a.ed_port_var = tk.StringVar(value="")
    a.ed_cred_var = tk.StringVar(value="")
    a.ed_transport_var = tk.StringVar(value="ws")
    a.ed_path_var = tk.StringVar(value="")
    a.ed_hosthdr_var = tk.StringVar(value="")
    a.ed_service_var = tk.StringVar(value="")
    a.ed_hdrtype_var = tk.StringVar(value="")
    a.ed_mode_var = tk.StringVar(value="")
    a.ed_security_var = tk.StringVar(value="")
    a.ed_sni_var = tk.StringVar(value="")
    a.ed_fp_var = tk.StringVar(value="chrome")
    a.ed_alpn_var = tk.StringVar(value="")
    a.ed_insecure_var = tk.BooleanVar(value=False)
    a.ed_flow_var = tk.StringVar(value="")
    a.ed_pbk_var = tk.StringVar(value="")
    a.ed_sid_var = tk.StringVar(value="")
    a.ed_spx_var = tk.StringVar(value="")
    a.ed_cs_var = tk.StringVar(value="")
    a.ed_scy_var = tk.StringVar(value="")
    a.ed_aid_var = tk.StringVar(value="0")

    _form_grid(form, a)
    _json_pane(jsn, a)
    a.ed_security_var.trace_add("write", lambda *_: _reality_state(a))
    _reality_state(a)
    return page


def _entry(parent, var, width=22, mono=True):
    e = ttk.Entry(parent, textvariable=var, style="Field.TEntry",
                  width=width, font=(MONO, 10) if mono else None)
    return e


def _row(parent, row, label, widget, tip=None):
    ttk.Label(parent, text=label, style="Dim.TLabel")\
        .grid(row=row, column=0, sticky="w", padx=(8, 6), pady=2)
    widget.grid(row=row, column=1, sticky="ew", padx=(0, 8), pady=2)
    parent.columnconfigure(1, weight=1)
    if tip:
        Tooltip(widget, tip)
    return widget


def _form_grid(form, a):
    """2×2 grid of Labelframes with the editable Outbound fields."""
    for c, w in ((0, 1), (1, 1)):
        form.columnconfigure(c, weight=1, uniform="ed")

    # ---- basic -----------------------------------------------------------
    b = ttk.Labelframe(form, text="  basic  ")
    b.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 6))
    sch = ttk.Entry(b, textvariable=a.ed_scheme_var, width=10,
                    state="readonly", font=(MONO, 10, "bold"))
    _row(b, 0, "protocol", sch)
    _row(b, 1, "name", _entry(b, a.ed_name_var, 26))
    _row(b, 2, "address", _entry(b, a.ed_host_var, 26),
         "Connect address (IP or domain).")
    p = _entry(b, a.ed_port_var, 7)
    p.configure(justify="center")
    _row(b, 3, "port", p)
    _row(b, 4, "credential", _entry(b, a.ed_cred_var, 26),
         "uuid (vless/vmess) or password (trojan/ss/hy2/tuic).")

    # ---- transport -------------------------------------------------------
    t = ttk.Labelframe(form, text="  transport  ")
    t.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=(0, 6))
    tr = ttk.Combobox(t, textvariable=a.ed_transport_var,
                      values=[""] + TRANSPORTS, width=13, font=(MONO, 10))
    _row(t, 0, "type", tr)
    _row(t, 1, "path", _entry(t, a.ed_path_var, 24),
         "ws / httpupgrade / xhttp path (leading /).")
    _row(t, 2, "host hdr", _entry(t, a.ed_hosthdr_var, 24),
         "ws/httpupgrade Host header (camouflage domain).")
    _row(t, 3, "serviceName", _entry(t, a.ed_service_var, 24),
         "grpc serviceName.")
    _row(t, 4, "headerType", _entry(t, a.ed_hdrtype_var, 24),
         "raw tcp header obfs (http…).")
    md = ttk.Combobox(t, textvariable=a.ed_mode_var, values=XHTTP_MODES,
                      width=13, font=(MONO, 10))
    _row(t, 5, "xhttp mode", md,
         "xhttp transport mode (extra['mode']).")

    # ---- security --------------------------------------------------------
    s = ttk.Labelframe(form, text="  security (tls)  ")
    s.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(0, 0))
    sec = ttk.Combobox(s, textvariable=a.ed_security_var,
                       values=SECURITIES, width=13, font=(MONO, 10))
    _row(s, 0, "security", sec, "empty/none · tls · reality")
    _row(s, 1, "sni", _entry(s, a.ed_sni_var, 26),
         "serverName presented in the TLS hello.")
    _row(s, 2, "fp", _entry(s, a.ed_fp_var, 13),
         "uTLS fingerprint (chrome, firefox, unsafe…).")
    _row(s, 3, "alpn", _entry(s, a.ed_alpn_var, 26),
         "comma separated ALPN list.")
    row = tk.Frame(s, background=BG)
    row.grid(row=4, column=0, columnspan=2, sticky="w",
             padx=(8, 8), pady=(4, 6))
    Switch(row, variable=a.ed_insecure_var)
    tk.Label(row, text="allowInsecure", background=BG, foreground=FG,
             font=(SANS, 10)).pack(side="left", padx=(6, 0))
    Tooltip(row, "Skip certificate verification (self-signed servers).")

    # ---- reality / vmess -------------------------------------------------
    r = ttk.Labelframe(form, text="  reality · vmess  ")
    r.grid(row=1, column=1, sticky="nsew", padx=(0, 0), pady=(0, 0))
    fl = ttk.Combobox(r, textvariable=a.ed_flow_var, values=FLOWS,
                      width=20, font=(MONO, 10))
    _row(r, 0, "flow", fl,
         "xtls flow (vision is required for REALITY on xray).")
    a.ed_pbk_entry = _entry(r, a.ed_pbk_var, 26)
    _row(r, 1, "pbk", a.ed_pbk_entry, "REALITY public key (server).")
    a.ed_sid_entry = _entry(r, a.ed_sid_var, 12)
    _row(r, 2, "sid", a.ed_sid_entry, "REALITY short id.")
    a.ed_spx_entry = _entry(r, a.ed_spx_var, 12)
    _row(r, 3, "spx", a.ed_spx_entry, "REALITY spiderX path.")
    _row(r, 4, "cs", _entry(r, a.ed_cs_var, 26),
         "cipher-suite list injected into the TLS hello (cs=).")
    _row(r, 5, "scy (vmess)", _entry(r, a.ed_scy_var, 13),
         "vmess encryption: auto / none / aes-128-gcm …")
    aid = _entry(r, a.ed_aid_var, 5)
    aid.configure(justify="center")
    _row(r, 6, "alterId", aid, "vmess alterId (usually 0).")

    form.rowconfigure(0, weight=1)
    form.rowconfigure(1, weight=1)


def _json_pane(jsn, a):
    """Raw Outbound JSON — the full-fidelity editable view."""
    head = tk.Frame(jsn, background=BG)
    head.pack(fill="x", pady=(0, 4))
    tk.Label(head, text="RAW JSON — Outbound", background=BG,
             foreground=MUT, font=(SANS, 9, "bold"), anchor="w")\
        .pack(side="left")
    to_form_btn = ttk.Button(head, text="⟲ form → JSON", style="Ghost.TButton",
                             command=a._editor_to_json)
    to_form_btn.pack(side="right")
    from_json_btn = ttk.Button(head, text="⇄ JSON → form", style="Ghost.TButton",
                               command=a._editor_from_json)
    from_json_btn.pack(side="right", padx=(0, 6))
    Tooltip(to_form_btn, "Serialize the form (with your edits) to JSON.")
    Tooltip(from_json_btn, "Parse the JSON text back into the form.\n"
                           "Unknown keys are kept in ``extra``.")

    wrap = tk.Frame(jsn, background=BG)
    wrap.pack(fill="both", expand=True)
    a.ed_json_txt = tk.Text(wrap, wrap="char", undo=True,
                            background=PANEL, foreground=FG,
                            insertbackground=FG, selectbackground=ACCENT,
                            selectforeground=ACCENT_FG,
                            inactiveselectbackground=FIELD, relief="flat",
                            padx=8, pady=6, font=(MONO, 9))
    ys = ttk.Scrollbar(wrap, orient="vertical", command=a.ed_json_txt.yview)
    a.ed_json_txt.configure(yscrollcommand=ys.set)
    a.ed_json_txt.grid(row=0, column=0, sticky="nsew")
    ys.grid(row=0, column=1, sticky="ns")
    wrap.rowconfigure(0, weight=1)
    wrap.columnconfigure(0, weight=1)
    a.ed_json_txt.bind("<Control-a>", a._select_all)

    hint = tk.Label(jsn, text="JSON → form re-parses this text into the "
                              "form (extra protocol params included).",
                    background=BG, foreground=MUT, wraplength=260,
                    justify="left", font=(SANS, 8))
    hint.pack(fill="x", pady=(4, 0))


def _reality_state(a):
    """Enable the REALITY key fields only when security == reality."""
    on = a.ed_security_var.get().strip().lower() == "reality"
    for ent in (getattr(a, "ed_pbk_entry", None),
                getattr(a, "ed_sid_entry", None),
                getattr(a, "ed_spx_entry", None)):
        if ent is None:
            continue
        try:
            ent.configure(state="normal" if on else "disabled")
        except Exception:
            pass
