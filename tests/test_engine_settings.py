"""UI settings persistence over the engine API (step 5.5)."""

from __future__ import annotations

import json
import os

from tests.test_engine import Client
from xray_forge.core import settings


def path():
    return os.path.join(settings.data_dir(), "ui_settings.json")


def test_defaults_to_empty():
    assert Client().result("ui.settings_get") == {"settings": {}}


def test_round_trip_and_replace_semantics():
    c = Client()
    s = {"cv-mode": "custom", "cv-start": 5, "cv-rename": False, "cv-ratio": 0.5, "cv-ip": "1.2.3.4"}
    assert c.result("ui.settings_set", settings=s) == {"saved": 5}
    assert c.result("ui.settings_get")["settings"] == s
    assert c.result("ui.settings_set", settings={"a": 1}) == {"saved": 1}   # replaces, not merges
    assert Client().result("ui.settings_get")["settings"] == {"a": 1}      # survives a new engine


def test_file_is_private_and_not_next_to_the_package():
    Client().result("ui.settings_set", settings={"a": "x"})
    assert os.path.isfile(path())
    if os.name == "posix":
        assert os.stat(path()).st_mode & 0o077 == 0
    assert os.path.abspath(path()) != os.path.abspath(settings.settings_path())  # Tk's file untouched


def test_rejects_bad_payloads_and_keeps_the_old_file():
    c = Client()
    c.result("ui.settings_set", settings={"keep": "me"})
    big = {f"k{i}": 1 for i in range(201)}
    bad = [
        "x", [1], None, {"": 1}, {"Bad Key": 1}, {"a": None}, {"a": [1]}, {"a": {"b": 1}},
        {"a": "x" * 4097}, {"x" * 65: 1}, big, {"a": float("inf")},
    ]
    for payload in bad:
        r = c.call("ui.settings_set", settings=payload)
        assert r["error"]["code"] == -32602, payload
    assert c.result("ui.settings_get")["settings"] == {"keep": "me"}


def test_nan_and_infinity_never_reach_the_file():
    c = Client()
    assert c.call("ui.settings_set", settings={"a": float("nan")})["error"]["code"] == -32602


def test_corrupt_or_hostile_file_is_ignored_entry_by_entry():
    with open(path(), "w", encoding="utf-8") as f:
        f.write("{not json")
    assert Client().result("ui.settings_get") == {"settings": {}}
    with open(path(), "w", encoding="utf-8") as f:
        json.dump({"ok": "v", "Bad Key": 1, "nested": {"a": 1}, "n": 3, "none": None}, f)
    assert Client().result("ui.settings_get")["settings"] == {"ok": "v", "n": 3}
    with open(path(), "w", encoding="utf-8") as f:
        json.dump([1, 2], f)
    assert Client().result("ui.settings_get") == {"settings": {}}


def test_bool_is_not_confused_with_int():
    c = Client()
    c.result("ui.settings_set", settings={"t": True, "i": 1})
    got = c.result("ui.settings_get")["settings"]
    assert got["t"] is True and got["i"] == 1 and got["i"] is not True
