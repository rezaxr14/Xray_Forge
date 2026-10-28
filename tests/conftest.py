"""
Shared test configuration: isolate all per-user data (settings, sources,
scans, WARP accounts) into a temporary directory so tests never touch the
real ~/.xray_forge or the repo's settings.json.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    data_root = tmp_path / ".xray_forge"
    data_root.mkdir()

    import xray_forge.core.settings as settings_mod
    monkeypatch.setattr(settings_mod, "data_dir", lambda: str(data_root))
    monkeypatch.setattr(settings_mod, "settings_path",
                        lambda: str(tmp_path / "settings.json"))

    # modules that imported the names directly at import time
    import xray_forge.core.sub_source as sub_source_mod
    monkeypatch.setattr(sub_source_mod, "data_dir", lambda: str(data_root))
    import xray_forge.core.scan_session as scan_mod
    monkeypatch.setattr(scan_mod, "data_dir", lambda: str(data_root))
    # (warp.py imports data_dir lazily inside _account_path(), so patching
    #  the settings module above covers it)
    yield data_root
