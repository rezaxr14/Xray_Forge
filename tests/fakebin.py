"""Fake external-core executables that work on POSIX and Windows.

POSIX: the script itself, made executable (it has a ``#!python`` first line).
Windows: ``name.py`` plus a ``name.cmd`` wrapper that runs it with the same
interpreter; the .cmd is the "binary" the code under test spawns.  A killed
wrapper can leave its Python child behind on Windows, so the fakes carry a
watchdog (see WATCHDOG) that makes them exit on their own.
"""

from __future__ import annotations

import os
import pathlib
import sys

IS_WINDOWS = os.name == "nt"

# Put this at the top of a fake's "run" path: never outlive the test run by long.
WATCHDOG = "import os, threading; _w = threading.Timer(120, lambda: os._exit(0)); _w.daemon = True; _w.start()"


def make_exe(directory, name: str, source: str) -> str:
    """Write ``source`` (a complete Python script) as an executable called ``name``."""
    d = pathlib.Path(directory)
    if not IS_WINDOWS:
        path = d / name
        path.write_text(source)
        path.chmod(0o755)
        return str(path)
    script = d / (name + ".py")
    script.write_text(source)
    cmd = d / (name + ".cmd")
    cmd.write_text(f'@"{sys.executable}" "{script}" %*\r\n')
    return str(cmd)
