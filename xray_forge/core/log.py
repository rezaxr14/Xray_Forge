"""Logging setup.

Library code uses ``get_logger(__name__)`` and stays silent unless an entry
point calls :func:`configure` (the CLI does for ``-v``; the GUI always logs to
a rotating file).  Set ``XRAY_FORGE_LOG=DEBUG`` to force a level.
"""

from __future__ import annotations

import logging
import logging.handlers
import os

ROOT = "xray_forge"
_FMT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

logging.getLogger(ROOT).addHandler(logging.NullHandler())
_configured = False


def get_logger(name: str) -> logging.Logger:
    if name == ROOT or name.startswith(ROOT + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{ROOT}.{name}")


def log_path() -> str:
    from xray_forge.core.settings import data_dir
    d = os.path.join(data_dir(), "logs")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "xray_forge.log")


def _level(verbose: bool, level: str | int | None) -> int:
    env = os.environ.get("XRAY_FORGE_LOG", "").strip().upper()
    if env:
        value = logging.getLevelName(env)
        if isinstance(value, int):
            return value
    if level is not None:
        if isinstance(level, int):
            return level
        value = logging.getLevelName(str(level).upper())
        if isinstance(value, int):
            return value
    return logging.DEBUG if verbose else logging.INFO


def configure(verbose: bool = False, stderr: bool = False, file: bool = True,
              level: str | int | None = None) -> logging.Logger:
    """Idempotently attach handlers to the ``xray_forge`` logger."""
    global _configured
    root = logging.getLogger(ROOT)
    root.setLevel(_level(verbose, level))
    if _configured:
        return root
    fmt = logging.Formatter(_FMT)
    if stderr:
        h = logging.StreamHandler()
        h.setFormatter(fmt)
        root.addHandler(h)
    if file:
        try:
            fh = logging.handlers.RotatingFileHandler(
                log_path(), maxBytes=512 * 1024, backupCount=3, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError:
            pass  # logging must never stop the app
    _configured = True
    return root
