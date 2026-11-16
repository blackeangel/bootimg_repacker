#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""abr's PNG reader and writer (the `png` coder of the unit tests, as `png-encode` and `png-decode`) against Pillow, and against ImageMagick where it is
there: abr encodes, Pillow decodes; Pillow encodes every colour type and bit depth, abr decodes; interlaced, 16-bit and 4-bit paletted files from ImageMagick.
One FAIL line for every check that does not hold and a last line with the counts; exit status 1 when there is a FAIL line.

  png_oracle.py ABR_UNIT_TESTS WORKDIR      Needs Pillow.
"""
import os
import random
import subprocess
import sys
import traceback

from PIL import Image

UNIT, WORK = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)
random.seed(5)
passed = 0
failed = []
skipped = []


def check(ok, what):
    global passed
    if ok:
        passed += 1
    else:
        failed.append(what)
        print("FAIL:", what)


def unit(*args):
    return subprocess.run([UNIT, *args], capture_output=True, text=True, timeout=120)


def path(name):
    return os.path.join(WORK, name)


def slurp(name):
    with open(path(name), "rb") as f:
        return f.read()


def section(label, body):
    """A check that falls over is a FAIL line, and the next section runs."""
    try:
        body()
    except Exception as e:  # noqa: BLE001
        check(False, "%s: the check itself stopped (%s: %s, line %d)" % (label, type(e).__name__, e, traceback.extract_tb(e.__traceback__)[-1].lineno))


def pixels_of(png):
    im = Image.open(png)
    im.load()
    return im.convert("RGBA").tobytes()


# ------------------------------------------------------------------------------------------------------------- 1. abr encodes, Pillow decodes
def encode_then_decode():
    for w, h in ((1, 1), (17, 9), (320, 200), (1080, 64)):
        rgba = bytes(random.getrandbits(8) if (i // 4) % 5 == 0 else (i * 3) & 255 for i in range(w * h * 4))
        with open(path("in.rgba"), "wb") as f:
            f.write(rgba)
        for noalpha in (False, True):
            r = unit("png-encode", path("in.rgba"), str(w), str(h), path("out.png"), *(["noalpha"] if noalpha else []))
            check(r.returncode == 0, "encode %dx%d%s: %s" % (w, h, " without alpha" if noalpha else "", r.stderr.strip()))
            if r.returncode:
                continue
            im = Image.open(path("out.png"))
            im.load()
            check(im.size == (w, h) and im.mode == ("RGB" if noalpha else "RGBA"), "mode and size of %dx%d (got %s %s)" % (w, h, im.mode, im.size))
            want = Image.frombytes("RGBA", (w, h), rgba)
            if noalpha:
                want = Image.merge("RGBA", (*want.split()[:3], Image.new("L", (w, h), 255)))
            check(im.convert("RGBA").tobytes() == want.tobytes(), "pixels of %dx%d, noalpha=%s" % (w, h, noalpha))


section("abr encodes, Pillow decodes", encode_then_decode)


# ------------------------------------------------------------------------------------------------------------- 2. Pillow encodes, abr decodes
W, H = 37, 23
BASE = Image.frombytes("RGB", (W, H), bytes(random.getrandbits(8) for _ in range(W * H * 3)))


def decode_of(image, name, **kw):
    png = path("p_%s.png" % name)
    image.save(png, **kw)
    r = unit("png-decode", png, path("p.rgba"))
    check(r.returncode == 0, "decode %s: %s" % (name, r.stderr.strip()))
    if r.returncode == 0:
        check(slurp("p.rgba") == pixels_of(png), "pixels of %s" % name)


def pillow_encodes():
    decode_of(BASE, "rgb")
    decode_of(BASE.convert("RGBA"), "rgba")
    decode_of(BASE.convert("L"), "gray")
    decode_of(BASE.convert("LA"), "graya")
    decode_of(BASE.convert("P"), "pal")
    decode_of(BASE.convert("P", palette=Image.ADAPTIVE, colors=7), "pal7")
    decode_of(BASE.convert("1"), "bilevel")
    decode_of(BASE.convert("L").point(lambda v: v // 64 * 64), "gray_q")
    decode_of(BASE.convert("L"), "gray_opt", optimize=True)
    decode_of(BASE, "rgb_opt", optimize=True)
    decode_of(BASE.convert("RGBA"), "rgba_opt", optimize=True, compress_level=9)
    palette_alpha = BASE.convert("P")
    palette_alpha.info["transparency"] = 3
    decode_of(palette_alpha, "pal_trns", transparency=3)


section("Pillow encodes, abr decodes", pillow_encodes)


def sixteen_bit():
    im16 = Image.frombytes("I;16", (W, H), bytes(random.getrandbits(8) for _ in range(W * H * 2)))
    im16.save(path("p_16.png"))
    r = unit("png-decode", path("p_16.png"), path("p.rgba"))
    check(r.returncode == 0, "decode 16-bit gray: %s" % r.stderr.strip())
    if r.returncode == 0:
        got, raw = slurp("p.rgba"), im16.tobytes()
        # I;16 is little-endian in Pillow; the high byte is the second one
        check(all(got[4 * i] == raw[2 * i + 1] for i in range(W * H)), "the high bytes of 16-bit gray")


section("16-bit gray", sixteen_bit)


# ------------------------------------------------------------------------------------------------------------- 3. ImageMagick, where it is there
def magick():
    BASE.save(path("src.png"))
    for name, args in (("adam7", ["-interlace", "PNG"]), ("rgb16", ["-depth", "16"]), ("pal4", ["-colors", "11", "-depth", "4"])):
        png = path("m_%s.png" % name)
        try:
            r = subprocess.run(["convert", path("src.png"), *args, png], capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            skipped.append("ImageMagick is not installed")
            return
        if r.returncode:
            skipped.append("%s (%s)" % (name, r.stderr.strip()[:80]))
            continue
        r = unit("png-decode", png, path("p.rgba"))
        check(r.returncode == 0, "decode %s: %s" % (name, r.stderr.strip()))
        if r.returncode == 0:
            check(slurp("p.rgba") == pixels_of(png), "pixels of %s (interlace=%s)" % (name, Image.open(png).info.get("interlace")))


section("ImageMagick", magick)

if skipped:
    print("note: not compared: " + "; ".join(skipped))
print("png: %d checks passed, %d failed" % (passed, len(failed)))
sys.exit(1 if failed else 0)
