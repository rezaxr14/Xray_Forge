#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xray Forge — VLESS / Trojan / VMess / Shadowsocks / Hysteria2 / TUIC / WARP
config utility.

This is the repo-root entry point.  The real code lives in the
``xray_forge/`` package (core/, engine/); this thin launcher just boots the
CLI (the desktop UI is the Electron app in electron/).

Run:
    python Xray_Forge.py --help
    python Xray_Forge.py convert in.txt out.txt
    python Xray_Forge.py test in.txt --core /path/to/xray.exe
    python Xray_Forge.py scan 104.16.0.0/13 --sni example.com --csv out.csv
    python Xray_Forge.py geo 1.2.3.4
    python Xray_Forge.py mitm --gen-cert --guide
    python Xray_Forge.py warp register
    python Xray_Forge.py subs add --url https://... && python Xray_Forge.py subs check
"""
from xray_forge.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
