"""Renders the Krypta logo (same shapes as logo.svg) to PNG and ICO files.

Usage:  python assets/make_icons.py      (needs Pillow: pip install pillow)
"""
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
TOP, BOTTOM = (0x4F, 0x8C, 0xFF), (0x27, 0x43, 0xC4)


def render(size: int) -> Image.Image:
    scale = 8  # draw large, then shrink for smooth edges
    big = size * scale
    unit = big / 64

    gradient = Image.new("RGB", (big, big))
    pixels = gradient.load()
    for y in range(big):
        for x in range(big):
            t = (x + y) / (2 * (big - 1))
            pixels[x, y] = tuple(round(a + (b - a) * t) for a, b in zip(TOP, BOTTOM))

    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, big - 1, big - 1), radius=14 * unit, fill=255)
    image = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    image.paste(gradient, (0, 0), mask)

    draw = ImageDraw.Draw(image)
    for x, y, w, h, r in ((11, 27, 34, 10, 5), (19, 16, 7, 16, 3.5), (48, 20, 6, 24, 3)):
        draw.rounded_rectangle((x * unit, y * unit, (x + w) * unit - 1, (y + h) * unit - 1), radius=r * unit, fill="white")
    return image.resize((size, size), Image.LANCZOS)


def main() -> None:
    render(256).save(ROOT / "assets" / "logo.png")
    render(256).save(ROOT / "src" / "Krypta.App" / "Resources" / "krypta.ico",
                     sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    icons = ROOT / "extension" / "icons"
    icons.mkdir(exist_ok=True)
    for size in (16, 48, 128):
        render(size).save(icons / f"icon{size}.png")


if __name__ == "__main__":
    main()
