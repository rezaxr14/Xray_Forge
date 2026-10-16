"""
Settings persistence for Xray Forge.

Saves/restores GUI state (form values, window size, tab positions) to a JSON
file next to the application so the user's preferences survive restarts.
"""

import json
import os
from typing import Any


def settings_path() -> str:
    """Return the path to the settings JSON file."""
    here = os.path.dirname(os.path.abspath(__file__))
    # Store settings next to the package for simplicity (portable).
    return os.path.join(os.path.dirname(here), "settings.json")


def load_settings() -> dict[str, Any]:
    path = settings_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_settings(data: dict[str, Any]) -> None:
    path = settings_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except OSError:
        pass  # best-effort persistence
