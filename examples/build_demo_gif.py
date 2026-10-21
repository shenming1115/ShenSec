"""Assemble an edited walkthrough from real, locally captured Windows frames.

This script encodes existing captures; it does not generate UI or scan results.
Requires Pillow. See docs/screenshots.md for the recording and manifest format.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageOps


def font(size, bold=False):
    windows = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    candidates = [windows / ("segoeuib.ttf" if bold else "segoeui.ttf"),
                  Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")]
    for path in candidates:
        if path.is_file():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default(size=size)


def compose(frame, root, index, total, width):
    with Image.open(root / frame["file"]) as source:
        image = source.convert("RGB")
    # Crop only to the recorded application area. Optional detail views are
    # editorial zooms into the same unmodified pixels, never recreated controls.
    region = frame.get("crop", [0, 0, image.width, min(740, image.height)])
    left, top, right, bottom = region
    if not (0 <= left < right <= image.width and 0 <= top < bottom <= image.height):
        raise ValueError(f"Invalid crop for {frame['file']}")
    area_height = round(width * 740 / 1322)
    canvas = Image.new("RGB", (width, area_height + 100), "#101820")
    view = ImageOps.contain(image.crop(region), (width, area_height), Image.Resampling.LANCZOS)
    canvas.paste(view, ((width-view.width)//2, (area_height-view.height)//2))
    draw = ImageDraw.Draw(canvas)
    title_font, detail_font, label_font = font(23, True), font(17), font(12)
    draw.rectangle((0, area_height, width, area_height+3), fill="#233447")
    draw.rectangle((0, area_height, round(width*(index+1)/total), area_height+3), fill="#72dbc6")
    if draw.textlength(frame["title"], font=title_font) > width-42:
        raise ValueError(f"Title is too wide: {frame['title']}")
    draw.text((21, area_height+13), frame["title"], font=title_font, fill="#92e6d5")
    detail = frame["detail"]
    if draw.textlength(detail, font=detail_font) > width-42:
        raise ValueError(f"Caption is too wide: {detail}")
    draw.text((22, area_height+46), detail, font=detail_font, fill="#e0e9ef")
    draw.text((22, area_height+77), "REAL WINDOWS CAPTURE  /  synthetic localhost fixture  /  waits condensed", font=label_font, fill="#91a2b2")
    page = f"{index+1:02d} / {total:02d}"
    draw.text((width-22-draw.textlength(page,font=label_font), area_height+77), page, font=label_font, fill="#91a2b2")
    return canvas


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path("docs/demo-workflow.gif"))
    parser.add_argument("--width", type=int, default=1180)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    frames = [f for f in manifest["frames"] if not f.get("skip", False)]
    if not frames:
        raise ValueError("No captured frames")
    preview = manifest.get("preview")
    sources = ([preview] if preview else []) + frames
    images = [compose(frame, args.manifest.parent, i, len(sources), args.width) for i, frame in enumerate(sources)]
    # One shared palette keeps the dark UI and green/red status cells stable.
    samples = Image.new("RGB", (320, 200*len(images)))
    for i, image in enumerate(images):
        samples.paste(ImageOps.fit(image, (320,200), method=Image.Resampling.LANCZOS), (0,200*i))
    palette = samples.quantize(colors=256, method=Image.Quantize.MEDIANCUT)
    encoded = [image.quantize(palette=palette, dither=Image.Dither.NONE) for image in images]
    durations = [round(frame.get("duration", 1800)/10)*10 for frame in sources]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded[0].save(args.output, save_all=True, append_images=encoded[1:], duration=durations,
                    loop=0, optimize=True, disposal=1,
                    comment=b"Actual ShenSec 0.5.0b1 Windows exe captures. Editorial captions/zooms; waits condensed. Local synthetic fixture; not a speed benchmark.")
    # Decode every encoded frame and inspect the loop/durations after encoding.
    with Image.open(args.output) as animation:
        assert animation.is_animated and animation.info["loop"] == 0
        decoded_duration = 0
        for i in range(animation.n_frames):
            animation.seek(i)
            animation.load()
            decoded_duration += animation.info["duration"]
        assert decoded_duration == sum(durations)
        frame_count = animation.n_frames
    metadata = {"source":manifest["source"], "source_release":"https://github.com/shenming1115/ShenSec/releases/tag/v0.5.0b1",
                "source_exe_sha256":manifest.get("source_exe_sha256"),
                "recorded_on":manifest.get("recorded_on"), "edited":True,
                "edits":["selected native window captures", "waits condensed", "application-area crop and detail zooms", "explanatory captions below the captured UI"],
                "fixture":"Synthetic credentials and loopback HTTP only; four roles, two endpoints.",
                "gif":{"width":images[0].width,"height":images[0].height,"frames":frame_count,"duration_ms":sum(durations),"loop":0,"bytes":args.output.stat().st_size,
                       "sha256":hashlib.sha256(args.output.read_bytes()).hexdigest()},
                "scenes":[{"capture":f["file"],"captured_at":f.get("captured_at"),"caption":f["title"],"duration_ms":d,
                           "source_frame_sha256":hashlib.sha256((args.manifest.parent/f["file"]).read_bytes()).hexdigest()} for f,d in zip(sources,durations)]}
    args.output.with_suffix(".json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    sheet_width = 4*360
    thumb_height = round(360*images[0].height/images[0].width)
    sheet = Image.new("RGB", (sheet_width, ((len(images)+3)//4)*(thumb_height+30)), "#101820")
    draw = ImageDraw.Draw(sheet)
    for i, image in enumerate(images):
        x, y = i%4*360, i//4*(thumb_height+30)
        sheet.paste(image.resize((360,thumb_height), Image.Resampling.LANCZOS), (x,y))
        draw.text((x+8,y+thumb_height+4),f"{i+1:02d} · {durations[i]/1000:g} s", font=font(15),fill="#dce8ef")
    sheet.save(args.manifest.parent/"contact-sheet.jpg",quality=93)
    images[0].save(args.manifest.parent/"poster.png")
    images[-1].save(args.manifest.parent/"last-frame.png")
    print(json.dumps(metadata["gif"], indent=2))


if __name__ == "__main__":
    main()
