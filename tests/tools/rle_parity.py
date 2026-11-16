#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Is the RLE24 that abr writes the RLE24 that Qualcomm's logo_gen.py writes (as transcribed in mk_splash.py)? Every picture is made into a raw SPLASH!!
image, unpacked, set to rle24 and packed; the result must be the bytes of the transcription. One case is judged another way: a picture one pixel wide
(the loop of the coder, as transcribed, ends a row from inside its loop over the pixels but the last, so a row of one pixel makes no entry at all); abr's
image must decode to that picture.

  rle_parity.py ABR WORKDIR      Needs Pillow. Exit status 1 when a picture differs.
"""
import importlib.util, os, subprocess, sys, shutil
ABR, WORK = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("mk_splash", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mk_splash.py"))
ms = importlib.util.module_from_spec(spec); spec.loader.exec_module(ms)
from PIL import Image, ImageDraw
import random
env = dict(os.environ, NO_COLOR="1", ABR_PROGRESS="0")
shutil.rmtree(WORK, ignore_errors=True); os.makedirs(WORK)

def pics():
    yield "gradient64x48", ms.make_picture(64, 48, 1)
    yield "noisy123x77", ms.make_picture(123, 77, 2)
    c = ms.make_picture(300, 20, 3); px = c.load()
    for x in range(300):
        px[x, 5] = (9, 9, 9); px[x, 6] = (200, 10, 10) if x < 150 else (10, 10, 200)
    yield "wide300x20", c
    yield "flat40x30", Image.new("RGB", (40, 30), (12, 34, 56))
    yield "stripes257x9", Image.frombytes("RGB", (257, 9), bytes([(x // 3) % 7 * 30 for y in range(9) for x in range(257) for _ in range(3)]))
    rnd = random.Random(5)
    yield "random50x40", Image.frombytes("RGB", (50, 40), bytes(rnd.randrange(256) for _ in range(50 * 40 * 3)))
    two = Image.new("RGB", (6, 4), (1, 2, 3)); d = ImageDraw.Draw(two); d.point((3, 1), fill=(9, 9, 9)); d.point((0, 3), fill=(9, 9, 9))
    yield "tiny6x4", two
    yield "single_px_rows", Image.frombytes("RGB", (1, 5), bytes(range(15)))
    yield "w2", Image.frombytes("RGB", (2, 6), bytes([5, 5, 5, 5, 5, 5, 1, 2, 3, 1, 2, 3, 7, 7, 7, 8, 8, 8] * 2)[:36])

ok = bad = 0
for name, img in pics():
    raw_img = os.path.join(WORK, name + ".raw.img"); open(raw_img, "wb").write(ms.splash_single(img, False))
    want = ms.splash_single(img, True)
    out = os.path.join(WORK, name)
    r = subprocess.run([ABR, "unpack", "-i", raw_img, "-o", out], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    m = os.path.join(out, "manifest.txt"); s = open(m).read().replace("picture0_compression=none", "picture0_compression=rle24"); open(m, "w").write(s)
    got_img = os.path.join(WORK, name + ".rle.img")
    r = subprocess.run([ABR, "pack", "-i", out, "-o", got_img], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    got = open(got_img, "rb").read()
    if img.size[0] == 1:
        dec = os.path.join(WORK, name + ".dec"); ms.decode("splash", got_img, dec)
        good = ms.pixels(os.path.join(dec, "00.png")) == (img.size, img.convert("RGB").tobytes())
        print(("decodes  " if good else "WRONG    "), name, "(one pixel wide: abr writes %d bytes, the transcription %d)" % (len(got), len(want)))
    else:
        good = got == want
        print(("same     " if good else "DIFFERENT"), name, len(got), len(want))
    ok += good
    bad += not good
print("RLE24 of abr is the transcription of logo_gen.py's coder (a picture one pixel wide: decodes to the picture): %d, different: %d" % (ok, bad))
sys.exit(1 if bad else 0)
