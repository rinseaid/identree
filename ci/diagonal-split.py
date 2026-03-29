#!/usr/bin/env python3
"""
ci/diagonal-split.py

For each pair of light/dark screenshots in ./screenshots/, produces a diagonal
split composite saved as ./screenshots/{page}-split.png.

The split runs from top-left to bottom-right (45-degree line).
Light mode occupies the upper-left triangle; dark mode the lower-right.
A thin white 2 px line marks the cut.

Also produces ./screenshots/hero.png — a grid of all split images.

Requirements: Pillow (pip install Pillow)
"""

import sys
from pathlib import Path
from PIL import Image, ImageDraw

SCREENSHOTS_DIR = Path("./screenshots")
SPLIT_LINE_COLOR = (255, 255, 255, 220)   # semi-transparent white
SPLIT_LINE_WIDTH = 2
HERO_COLS = 3
HERO_PADDING = 8
HERO_BG = (18, 18, 28)                    # dark background for hero


def diagonal_split(light_img: Image.Image, dark_img: Image.Image) -> Image.Image:
    """
    Combine two same-size images along a top-left → bottom-right diagonal.

    The upper-left triangle comes from light_img; the lower-right from dark_img.
    A 2 px white line marks the boundary.
    """
    if light_img.size != dark_img.size:
        dark_img = dark_img.resize(light_img.size, Image.LANCZOS)

    w, h = light_img.size

    # Convert to RGBA so we can use alpha masks.
    light = light_img.convert("RGBA")
    dark = dark_img.convert("RGBA")

    # Build a mask: white = show light, black = show dark.
    # The diagonal runs from (0, 0) to (w, h).
    # Pixels above/left of the diagonal: show light.
    # Pixels below/right: show dark.
    mask = Image.new("L", (w, h), 0)
    draw = ImageDraw.Draw(mask)
    draw.polygon([(0, 0), (w, 0), (0, h)], fill=255)

    # Composite: start with dark, paste light over it using the mask.
    result = dark.copy()
    result.paste(light, mask=mask)

    # Draw the diagonal split line.
    line_draw = ImageDraw.Draw(result)
    # Draw SPLIT_LINE_WIDTH lines offset from the main diagonal for thickness.
    for offset in range(-SPLIT_LINE_WIDTH // 2, SPLIT_LINE_WIDTH // 2 + 1):
        line_draw.line([(0, offset), (w, h + offset)], fill=SPLIT_LINE_COLOR, width=1)

    return result.convert("RGB")


def make_hero(splits: list[tuple[str, Image.Image]]) -> Image.Image:
    """
    Arrange split images in a HERO_COLS-wide grid on a dark background.
    Each cell is labeled with the page name.
    """
    if not splits:
        return Image.new("RGB", (100, 100), HERO_BG)

    from PIL import ImageFont

    # Use default bitmap font — no external dependency.
    try:
        font = ImageFont.load_default(size=13)
    except TypeError:
        font = ImageFont.load_default()

    cell_w, cell_h = splits[0][1].size
    label_h = 22
    cols = min(HERO_COLS, len(splits))
    rows = (len(splits) + cols - 1) // cols

    total_w = cols * cell_w + (cols + 1) * HERO_PADDING
    total_h = rows * (cell_h + label_h) + (rows + 1) * HERO_PADDING

    hero = Image.new("RGB", (total_w, total_h), HERO_BG)
    draw = ImageDraw.Draw(hero)

    for idx, (name, img) in enumerate(splits):
        col = idx % cols
        row = idx // cols
        x = HERO_PADDING + col * (cell_w + HERO_PADDING)
        y = HERO_PADDING + row * (cell_h + label_h + HERO_PADDING)

        hero.paste(img, (x, y))

        # Label below the image
        label = name.replace("-split", "").replace("-", " ").title()
        draw.text(
            (x + cell_w // 2, y + cell_h + 4),
            label,
            fill=(180, 170, 220),
            font=font,
            anchor="mt" if hasattr(font, "getbbox") else None,
        )

    return hero


def main() -> None:
    if not SCREENSHOTS_DIR.exists():
        print(f"ERROR: {SCREENSHOTS_DIR} does not exist.", file=sys.stderr)
        sys.exit(1)

    # Find all light screenshots and pair them with dark counterparts.
    light_files = sorted(SCREENSHOTS_DIR.glob("*-light.png"))
    if not light_files:
        print("No *-light.png files found — nothing to do.", file=sys.stderr)
        sys.exit(0)

    splits: list[tuple[str, Image.Image]] = []

    for light_path in light_files:
        stem = light_path.stem[: -len("-light")]          # strip "-light"
        dark_path = SCREENSHOTS_DIR / f"{stem}-dark.png"

        if not dark_path.exists():
            print(f"  skip  {stem}: no matching dark screenshot", file=sys.stderr)
            continue

        print(f"  split {stem}")
        light_img = Image.open(light_path)
        dark_img = Image.open(dark_path)

        composite = diagonal_split(light_img, dark_img)

        out_path = SCREENSHOTS_DIR / f"{stem}-split.png"
        composite.save(out_path, optimize=True)
        splits.append((stem, composite))

    if not splits:
        print("No pairs found — hero image not generated.")
        return

    # Scale thumbnails for the hero grid (keep aspect ratio).
    thumb_w = 480
    thumb_splits = []
    for name, img in splits:
        ratio = thumb_w / img.width
        thumb_h = int(img.height * ratio)
        thumb = img.resize((thumb_w, thumb_h), Image.LANCZOS)
        thumb_splits.append((name, thumb))

    print("Building hero grid...")
    hero = make_hero(thumb_splits)
    hero_path = SCREENSHOTS_DIR / "hero.png"
    hero.save(hero_path, optimize=True)
    print(f"  saved {hero_path} ({hero.width}x{hero.height})")

    print(f"\nDone — {len(splits)} split(s) + hero written to {SCREENSHOTS_DIR}")


if __name__ == "__main__":
    main()
