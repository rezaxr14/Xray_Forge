#!/usr/bin/env python3
"""Draw the Xray Forge app icon (an original mark) and write icon.png + icon.ico.

    python tools/make_icons.py electron/assets

Needs Pillow (a development-time tool only; the committed output is what ships).
Deterministic: the same Pillow-independent drawing at 2048 px, downsampled with
LANCZOS, so tests/test_app_icons.py can check that assets/ is up to date.
"""

from __future__ import annotations

import pathlib
import sys

from PIL import Image, ImageDraw

BG_TOP, BG_BOTTOM = (22, 30, 41), (11, 15, 20)      # matches the app's dark background
AMBER, CYAN, SPARK = (245, 158, 11), (56, 189, 248), (254, 243, 199)
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]
S = 2048                                              # drawing canvas


def _stroke(d: ImageDraw.ImageDraw, a, b, width, fill):
    d.line([a, b], fill=fill, width=width)
    r = width // 2
    for x, y in (a, b):                               # round caps
        d.ellipse([x - r, y - r, x + r, y + r], fill=fill)


def draw() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # background: rounded square with a vertical gradient
    grad = Image.new("RGBA", (S, S))
    gp = grad.load()
    for y in range(S):
        t = y / (S - 1)
        c = tuple(round(BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * t) for i in range(3)) + (255,)
        for x in range(S):
            gp[x, y] = c
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * 0.225), fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    m, w = int(S * 0.27), int(S * 0.17)
    _stroke(d, (m, m), (S - m, S - m), w, AMBER)               # the "X": one hot stroke...
    _stroke(d, (S - m, m), (m, S - m), w, CYAN)                # ...one cool stroke, crossing
    # a bright spark where they cross, plus two flying off
    cx = cy = S // 2
    for (x, y, r) in ((cx, cy, int(S * 0.085)), (int(S * 0.74), int(S * 0.20), int(S * 0.03)),
                      (int(S * 0.80), int(S * 0.29), int(S * 0.018))):
        d.ellipse([x - r, y - r, x + r, y + r], fill=SPARK)
    return img


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    out = pathlib.Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)
    big = draw()
    png = big.resize((512, 512), Image.LANCZOS)
    png.save(out / "icon.png", optimize=True)
    big.resize((256, 256), Image.LANCZOS).save(
        out / "icon.ico", format="ICO", sizes=[(s, s) for s in ICO_SIZES])
    print(f"wrote {out / 'icon.png'} and {out / 'icon.ico'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
