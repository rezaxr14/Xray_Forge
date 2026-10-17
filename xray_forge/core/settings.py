"""
Settings persistence for Xray Forge.

Saves/restores GUI state (form values, window size, tab positions) to a JSON
file next to the application so the user's preferences survive restarts.
"""

from __future__ import annotations

import json
import os
from typing import Any

from xray_forge.core.log import get_logger

log = get_logger(__name__)


def settings_path() -> str:
    """Return the path to the settings JSON file."""
    here = os.path.dirname(os.path.abspath(__file__))
    # Store settings next to the package for simplicity (portable).
    return os.path.join(os.path.dirname(here), "settings.json")


def data_dir() -> str:
    """Per-user data directory (~/.xray_forge) for caches, sources, accounts.

    Created on first use.  Keeps user data out of the install directory so
    the package works both from a source checkout and from an installed copy.
    """
    path = os.path.join(os.path.expanduser("~"), ".xray_forge")
    os.makedirs(path, exist_ok=True)
    return path


def load_settings() -> dict[str, Any]:
    path = settings_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except OSError as e:
        log.warning("cannot read settings %s: %s", path, e)
    except json.JSONDecodeError as e:
        log.warning("settings %s is not valid JSON (%s); using defaults", path, e)
    return {}


def save_settings(data: dict[str, Any]) -> None:
    path = settings_path()
    try:
        from xray_forge.core.fsutil import write_private
        write_private(path, json.dumps(data, indent=2, ensure_ascii=False))
    except OSError as e:
        log.warning("cannot save settings %s: %s", path, e)  # best-effort
