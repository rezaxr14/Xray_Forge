"""Engine methods for the Electron UI's own state (step 5.5)."""

from __future__ import annotations

import json
import math
import os
import re
from typing import Any

from xray_forge.core import settings as _settings
from xray_forge.core.fsutil import write_private
from xray_forge.core.log import get_logger
from xray_forge.engine.rpc import Dispatcher, invalid_params

log = get_logger(__name__)

MAX_KEYS = 200
MAX_STR = 4096
KEY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
FILE_NAME = "ui_settings.json"


def _path() -> str:
    return os.path.join(_settings.data_dir(), FILE_NAME)   # looked up lazily (tests redirect it)


def _valid_value(v: Any) -> bool:
    if isinstance(v, bool):
        return True
    if isinstance(v, int):
        return True
    if isinstance(v, float):
        return math.isfinite(v)
    return isinstance(v, str) and len(v) <= MAX_STR


def _valid_entry(k: Any, v: Any) -> bool:
    return isinstance(k, str) and bool(KEY_RE.match(k)) and _valid_value(v)


def load() -> dict[str, Any]:
    """Saved settings; anything unreadable or malformed is dropped."""
    try:
        with open(_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        log.warning("cannot read UI settings: %s", e)
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in list(data.items())[:MAX_KEYS] if _valid_entry(k, v)}


def register(d: Dispatcher) -> None:
    @d.method("ui.settings_get")
    def settings_get() -> dict:
        return {"settings": load()}

    @d.method("ui.settings_set")
    def settings_set(settings: Any) -> dict:
        """Replace the saved UI settings: a flat ``{key: str|bool|number}``.

        Stored under the per-user data directory (never next to the install,
        which may be read-only) with owner-only permissions.
        """
        if not isinstance(settings, dict):
            raise invalid_params("settings must be an object")
        if len(settings) > MAX_KEYS:
            raise invalid_params(f"at most {MAX_KEYS} settings")
        for k, v in settings.items():
            if not _valid_entry(k, v):
                raise invalid_params(
                    f"invalid setting {str(k)[:40]!r}: keys are lowercase [a-z0-9_-], "
                    f"values a string (<= {MAX_STR}), boolean or finite number")
        try:
            write_private(_path(), json.dumps(settings, indent=2, ensure_ascii=False))
        except OSError as e:
            raise invalid_params(f"cannot save settings: {e.strerror or e}") from e
        return {"saved": len(settings)}
