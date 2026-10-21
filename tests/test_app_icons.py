"""App icons for the desktop installers (electron-builder reads them from buildResources)."""

from __future__ import annotations

import json
import pathlib
import struct
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
ASSETS = ROOT / "electron" / "assets"
PKG = json.loads((ROOT / "electron" / "package.json").read_text(encoding="utf-8"))


def png_header(path: pathlib.Path) -> tuple[int, int, int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    assert data[12:16] == b"IHDR"
    w, h, depth, ctype = struct.unpack(">IIBB", data[16:26])
    return w, h, depth, ctype


def ico_sizes(path: pathlib.Path) -> list[int]:
    data = path.read_bytes()
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    assert (reserved, kind) == (0, 1), "not an ICO"
    sizes = []
    for i in range(count):
        w, h = data[6 + 16 * i], data[7 + 16 * i]
        assert w == h
        sizes.append(w or 256)                       # 0 means 256 in the ICO directory
    return sizes


def test_png_is_512_square_with_alpha():
    w, h, depth, ctype = png_header(ASSETS / "icon.png")
    assert (w, h) == (512, 512) and depth == 8 and ctype == 6


def test_ico_has_every_size_windows_asks_for():
    assert set(ico_sizes(ASSETS / "icon.ico")) >= {16, 24, 32, 48, 64, 128, 256}


def test_builder_reads_them_from_the_committed_assets_folder():
    assert PKG["build"]["directories"]["buildResources"] == "assets"
    assert "assets/icon.png" in PKG["build"]["files"]          # the window icon is loaded at runtime


def test_the_icons_are_not_gitignored():
    for name in ("icon.png", "icon.ico"):
        r = subprocess.run(["git", "check-ignore", "-q", f"electron/assets/{name}"], cwd=ROOT)
        assert r.returncode == 1, f"{name} is ignored by .gitignore (build/ is, assets/ must not be)"


def test_the_window_uses_the_icon():
    assert "assets', 'icon.png'" in (ROOT / "electron" / "main.js").read_text(encoding="utf-8")


def test_the_icon_is_a_real_drawing_not_a_blank_square():
    pil = pytest.importorskip("PIL.Image")
    im = pil.open(ASSETS / "icon.png").convert("RGBA")
    colours = im.getcolors(maxcolors=1 << 20)
    assert colours is None or len(colours) > 8
    assert im.getpixel((0, 0))[3] == 0, "corners are transparent (rounded square)"
    assert im.getpixel((256, 256))[3] == 255


def test_generator_is_reproducible(tmp_path):
    pytest.importorskip("PIL.Image")
    out = tmp_path / "assets"
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "make_icons.py"), str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert png_header(out / "icon.png")[:2] == (512, 512)
    assert set(ico_sizes(out / "icon.ico")) >= {16, 256}
    from PIL import Image
    a, b = Image.open(out / "icon.png").convert("RGBA"), Image.open(ASSETS / "icon.png").convert("RGBA")
    assert a.tobytes() == b.tobytes(), "assets/ is stale: rerun tools/make_icons.py electron/assets"
