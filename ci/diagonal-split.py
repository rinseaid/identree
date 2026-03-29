#!/usr/bin/env python3
"""
ci/diagonal-split.py

For each pair of light/dark screenshots in ./screenshots/, produces a diagonal
split composite saved as ./screenshots/{page}-split.png.

The split runs from top-left to bottom-right (45-degree line).

Regular splits: dark at top-right, light at bottom-left.
Expanded splits (*-expanded-*): dark at bottom-left, light at top-right.

Requirements: Pillow (pip install Pillow)
"""

import sys
from pathlib import Path
from PIL import Image, ImageDraw

SCREENSHOTS_DIR = Path("./screenshots")

SSAA = 4  # supersampling factor for anti-aliased diagonal edge


def diagonal_split(light_img: Image.Image, dark_img: Image.Image,
                   dark_at_top: bool = True) -> Image.Image:
    """
    Combine two same-size images along a top-left → bottom-right diagonal.

    dark_at_top=True  (regular):  dark in upper-right, light in lower-left.
    dark_at_top=False (expanded): light in upper-right, dark in lower-left.

    The mask is rendered at SSAA× resolution and downsampled for a smooth edge.
    """
    if light_img.size != dark_img.size:
        dark_img = dark_img.resize(light_img.size, Image.LANCZOS)

    w, h = light_img.size
    sw, sh = w * SSAA, h * SSAA

    hi_mask = Image.new("L", (sw, sh), 0)
    draw = ImageDraw.Draw(hi_mask)

    if dark_at_top:
        # Light in upper-right triangle (top-left, top-right, bottom-right).
        # Dark fills the lower-left triangle.
        draw.polygon([(0, 0), (sw, 0), (sw, sh)], fill=255)
    else:
        # Light in lower-left triangle (top-left, bottom-left, bottom-right).
        # Dark fills the upper-right triangle.
        draw.polygon([(0, 0), (0, sh), (sw, sh)], fill=255)

    mask = hi_mask.resize((w, h), Image.LANCZOS)

    # Composite: start with dark, paste light over it using the smooth mask.
    light = light_img.convert("RGBA")
    dark = dark_img.convert("RGBA")
    result = dark.copy()
    result.paste(light, mask=mask)

    return result.convert("RGB")


def main() -> None:
    if not SCREENSHOTS_DIR.exists():
        print(f"ERROR: {SCREENSHOTS_DIR} does not exist.", file=sys.stderr)
        sys.exit(1)

    # Find all light screenshots and pair them with dark counterparts.
    light_files = sorted(SCREENSHOTS_DIR.glob("*-light.png"))
    if not light_files:
        print("No *-light.png files found — nothing to do.", file=sys.stderr)
        sys.exit(0)

    count = 0
    for light_path in light_files:
        stem = light_path.stem[: -len("-light")]          # strip "-light"
        dark_path = SCREENSHOTS_DIR / f"{stem}-dark.png"

        if not dark_path.exists():
            print(f"  skip  {stem}: no matching dark screenshot", file=sys.stderr)
            continue

        # Expanded screenshots flip the diagonal so the expanded panel
        # (lower portion) shows dark mode, header shows light.
        is_expanded = "-expanded-" in stem
        dark_at_top = not is_expanded

        print(f"  split {stem}  (dark_at_top={dark_at_top})")
        light_img = Image.open(light_path)
        dark_img = Image.open(dark_path)

        composite = diagonal_split(light_img, dark_img, dark_at_top=dark_at_top)

        out_path = SCREENSHOTS_DIR / f"{stem}-split.png"
        composite.save(out_path, optimize=True)
        count += 1

    print(f"\nDone — {count} split(s) written to {SCREENSHOTS_DIR}")


if __name__ == "__main__":
    main()
