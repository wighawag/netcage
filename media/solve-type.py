#!/usr/bin/env python3
"""Solve the card's type sizes to a MEASURED ink box, and report placement.

Nominal point size is not comparable across faces, and SVG places text by
BASELINE while the ink box is what the layout actually cares about. So: render,
trim, measure, rescale. Run this only when the copy or the face changes; the
solved numbers get baked into preview.src.svg.

    FONTCONFIG_FILE=/tmp/fc/fonts.conf ./solve-type.py
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CANVAS_W, CANVAS_H = 2400, 600

# string, style spec, target ink width, and the x/baseline it must land on
# The tagline target is 650 not BUILD.md's 560: this is a MONOSPACE face, so a
# 560px target drove the ink height down to 21px against a 146px wordmark.
JOBS = [
    ("netcage", "font-family:'JetBrains Mono';font-weight:800;letter-spacing:-0.03em", 640),
    (
        "Forced egress for Podman. Fail-closed.",
        "font-family:'JetBrains Mono';font-weight:500",
        650,
    ),
]


def measure(text, spec, size):
    """Render at `size` and return the ink box (x, y, w, h) relative to baseline."""
    svg = (
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{CANVAS_W}' height='{CANVAS_H}'>"
        f"<text x='100' y='400' style=\"{spec};font-size:{size}px\">{text}</text></svg>"
    )
    with open("/tmp/solve.svg", "w") as f:
        f.write(svg)
    subprocess.run(
        ["inkscape", "/tmp/solve.svg", "-o", "/tmp/solve.png", "-w", str(CANVAS_W)],
        check=True,
        capture_output=True,
    )
    out = subprocess.run(
        ["magick", "/tmp/solve.png", "-trim", "-format", "%w %h %X %Y", "info:"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    w, h, x, y = (int(v) for v in re.findall(r"-?\d+", out)[:4])
    # offsets are relative to the text anchor at (100, 400)
    return w, h, x - 100, y - 400


def solve(text, spec, target):
    size = 100.0
    for _ in range(5):
        w, _h, _dx, _dy = measure(text, spec, size)
        size = round(size * target / w, 3)
    w, h, dx, dy = measure(text, spec, size)
    # VERIFY, do not trust. An earlier run of this script returned 164.1px for a
    # 640px target while a direct render of that very size gave 536px of ink: a
    # cold fontconfig cache had made the first measurement land on a fallback
    # face. A solver that does not check its own answer will ship that silently.
    if abs(w - target) > 1:
        raise SystemExit(f"solve did not converge: {size}px gives {w}px ink, wanted {target}px")
    return size, w, h, dx, dy


def check_font_resolved():
    """Fail loudly if 'JetBrains Mono' is not actually the face being rendered.

    A missing family falls back silently and only shows up as type that is the
    wrong width. In a MONOSPACE face every glyph has the same advance, so
    'iiiiiii' and 'mmmmmmm' must render to within a pixel of each other.
    """
    widths = []
    for s in ("iiiiiii", "mmmmmmm"):
        w, _h, _dx, _dy = measure(s, "font-family:'JetBrains Mono';font-weight:800", 120)
        widths.append(w)
    if abs(widths[0] - widths[1]) > 6:
        raise SystemExit(
            f"'JetBrains Mono' did not resolve: proportional fallback detected "
            f"(iiiiiii={widths[0]}px vs mmmmmmm={widths[1]}px)"
        )
    print(f"font check: monospace confirmed (iiiiiii={widths[0]} mmmmmmm={widths[1]})\n")


if __name__ == "__main__":
    if "FONTCONFIG_FILE" not in os.environ:
        print("warning: FONTCONFIG_FILE unset, may not be using media/fonts", file=sys.stderr)
    measure("warmup", "font-family:'JetBrains Mono';font-weight:800", 100)  # warm the fc cache
    check_font_resolved()
    for text, spec, target in JOBS:
        size, w, h, dx, dy = solve(text, spec, target)
        print(f"{text[:28]!r}")
        print(f"  spec       {spec}")
        print(f"  font-size  {size}px   (for {target}px ink width)")
        print(f"  ink box    {w} x {h}")
        print(f"  ink offset dx={dx} dy={dy}  (ink topleft relative to the x/baseline anchor)")
