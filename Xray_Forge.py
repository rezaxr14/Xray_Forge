#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xray Forge — VLESS / Trojan / VMess / Shadowsocks config utility.

This is the repo-root entry point.  The real code lives in the
``xray_forge/`` package (core/, ui/, ui/tabs/) which is intentionally kept
as sub-folders; this thin launcher just boots it.

Run:
    python Xray_Forge.py                 # GUI
    python Xray_Forge.py convert in.txt out.txt
    python Xray_Forge.py test in.txt --core /path/to/xray.exe
    python Xray_Forge.py scan 104.16.0.0/13 --sni example.com
    python Xray_Forge.py geo 1.2.3.4
"""
from xray_forge.app import main

if __name__ == "__main__":
    raise SystemExit(main())
