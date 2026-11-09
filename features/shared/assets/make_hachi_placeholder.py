"""Draw the placeholder Hachi mascot used by every Olfa feature.

    python features/shared/assets/make_hachi_placeholder.py

Writes hachi.png (512x512, transparent) next to this file. Replace the PNG with
the real artwork when it exists - same filename, nothing else changes.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

SIZE = 512
FUR = (243, 154, 74, 255)      # shiba orange
FUR_DARK = (206, 118, 52, 255)
CREAM = (255, 245, 232, 255)
DARK = (52, 41, 34, 255)
INK = (24, 28, 38, 255)


def main() -> None:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # ears
    d.polygon([(90, 180), (118, 44), (238, 126)], fill=FUR_DARK)
    d.polygon([(422, 180), (394, 44), (274, 126)], fill=FUR_DARK)
    # head
    d.ellipse([64, 92, 448, 452], fill=FUR)
    # cream muzzle + blaze
    d.ellipse([148, 236, 364, 436], fill=CREAM)
    d.polygon([(256, 150), (196, 250), (316, 250)], fill=CREAM)
    # eyes
    d.ellipse([158, 198, 214, 254], fill=DARK)
    d.ellipse([298, 198, 354, 254], fill=DARK)
    # nose
    d.ellipse([228, 278, 284, 324], fill=DARK)
    # mouth
    d.line([(256, 324), (256, 350)], fill=DARK, width=7)
    d.arc([204, 330, 256, 384], start=0, end=90, fill=DARK, width=7)
    d.arc([256, 330, 308, 384], start=90, end=180, fill=DARK, width=7)
    # cheeks
    d.ellipse([132, 268, 176, 300], fill=(255, 194, 170, 160))
    d.ellipse([336, 268, 380, 300], fill=(255, 194, 170, 160))

    try:
        font = ImageFont.load_default(size=26)
        label = "HACHI placeholder"
        width = d.textlength(label, font=font)
        d.text(((SIZE - width) / 2, 464), label, fill=INK, font=font)
    except Exception:  # very old Pillow: the label is cosmetic, skip it
        pass

    out = Path(__file__).with_name("hachi.png")
    img.save(out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
