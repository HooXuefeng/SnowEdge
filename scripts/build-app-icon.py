"""Rasterize the application's geometric mark into a multi-resolution Windows icon."""
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "app/static/brand"
OUT.mkdir(parents=True, exist_ok=True)
# Same silhouette as snowedge.svg; white-on-indigo application variant.
blade = [(64,7),(80,37),(76,44),(94,81),(90,67),(111,87),(125,110),
         (87,96),(70,111),(70,40),(64,23),(58,40),(58,111),(39,96),
         (3,110),(43,56),(34,87),(46,78),(52,94),(45,66),(52,44),(48,37)]
facet = [(88,49),(83,61),(108,83)]
image = Image.new("RGBA", (1024,1024), (0,0,0,0))
draw = ImageDraw.Draw(image)
draw.rounded_rectangle((16,16,1008,1008),radius=220,fill="#4F46E5")
for polygon in (blade,facet):
    draw.polygon([(128+x*6,128+y*6) for x,y in polygon],fill="white")
image.save(OUT / "snowedge-app.png")
image.save(OUT / "snowedge.ico", sizes=[(s,s) for s in (16,20,24,32,40,48,64,128,256)])
with Image.open(OUT / "snowedge.ico") as icon:
    assert {(16,16),(32,32),(48,48),(256,256)} <= icon.ico.sizes()
print("Built SnowEdge app icon: 9 Windows sizes.")
