"""Create SnowEdge application icons from the approved high-resolution master."""
from pathlib import Path
import io
import struct
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "app/static/brand"
MASTER = ROOT / "design/brand/snowedge-logo-master.png"


def prepare_master(source: Image.Image) -> Image.Image:
    image = source.convert("RGB")
    pixels = image.load()
    bounds = [image.width, image.height, 0, 0]
    found = False
    for y in range(image.height):
        for x in range(image.width):
            red, green, blue = pixels[x, y]
            if blue > 120 and blue > red + 32 and blue > green + 32:
                found = True
                bounds = [min(bounds[0], x), min(bounds[1], y), max(bounds[2], x), max(bounds[3], y)]
    if not found:
        raise RuntimeError("The SnowEdge master image contains no visible indigo tile.")
    tile = image.crop((bounds[0] + 4, bounds[1] + 4, bounds[2] - 3, bounds[3] - 3))
    tile = tile.resize((1024, 1024), Image.Resampling.LANCZOS).convert("RGBA")
    mask = Image.new("L", tile.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, 1023, 1023), radius=185, fill=255)
    tile.putalpha(mask)
    return tile


def build_small_frame(size: int) -> Image.Image:
    """Draw a legible SnowEdge mark for Windows list and taskbar sizes."""
    scale = 8
    canvas = Image.new("RGBA", (size * scale, size * scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    unit = size * scale / 16
    points = lambda values: [(round(x * unit), round(y * unit)) for x, y in values]
    draw.rounded_rectangle((0, 0, size * scale - 1, size * scale - 1), radius=round(3.1 * unit), fill="#4F46E5")
    mountain = [(1, 13), (5, 8), (6, 9.5), (9, 2.5), (15, 13), (12, 10.6), (10, 6.4), (8, 10.8), (6.2, 12), (5, 11)]
    facet = [(9.3, 4.4), (11, 9.2), (14.6, 12.5), (10.6, 8.6)]
    draw.polygon(points(mountain), fill="white")
    draw.polygon(points(facet), fill="#20D6A4")
    return canvas.resize((size, size), Image.Resampling.LANCZOS)


def save_windows_icon(path: Path, image: Image.Image) -> None:
    sizes = (16, 20, 24, 32, 40, 48, 64, 128, 256)
    frames = [build_small_frame(size) if size <= 48 else image.resize((size, size), Image.Resampling.LANCZOS) for size in sizes]
    blobs = []
    for frame in frames:
        buffer = io.BytesIO()
        frame.save(buffer, format="PNG", optimize=True)
        blobs.append(buffer.getvalue())
    offset = 6 + 16 * len(blobs)
    with path.open("wb") as stream:
        stream.write(struct.pack("<HHH", 0, 1, len(blobs)))
        for size, blob in zip(sizes, blobs):
            encoded_size = 0 if size == 256 else size
            stream.write(struct.pack("<BBBBHHII", encoded_size, encoded_size, 0, 0, 1, 32, len(blob), offset))
            offset += len(blob)
        for blob in blobs:
            stream.write(blob)


def main() -> None:
    if not MASTER.is_file():
        raise FileNotFoundError(f"Missing approved SnowEdge master: {MASTER}")
    OUT.mkdir(parents=True, exist_ok=True)
    image = prepare_master(Image.open(MASTER))
    image.save(OUT / "snowedge-app.png")
    for size in (32, 48, 64):
        image.resize((size, size), Image.Resampling.LANCZOS).save(OUT / f"snowedge-app-{size}.png")
    save_windows_icon(OUT / "snowedge.ico", image)
    with Image.open(OUT / "snowedge.ico") as icon:
        assert {(16, 16), (32, 32), (48, 48), (256, 256)} <= icon.ico.sizes()
    print("Built SnowEdge icon from the approved master: 9 Windows sizes.")


if __name__ == "__main__":
    main()
