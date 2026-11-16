#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs abr on the images of mk_splash.py and judges the result with the independent decoders of mk_splash.py: info, unpack, an untouched pack (byte for
byte), edited pictures (another size, another coding), and damaged images (cut short, bytes changed: abr must refuse or take them, and what it takes must
pack again). Prints one FAIL line for every check that does not hold and a last line with the counts; the exit status is 1 when there is a FAIL line.

  splash_live.py ABR GENDIR WORKDIR      (GENDIR is what `mk_splash.py gen` made)
"""
import importlib.util
import os
import random
import shutil
import struct
import subprocess
import sys

ABR, GEN, WORK = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("mk_splash", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mk_splash.py"))
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)
from PIL import Image  # noqa: E402

ENV = dict(os.environ, NO_COLOR="1", ABR_PROGRESS="0")
passed = 0
failed = []


def check(ok, what, detail=""):
    global passed
    if ok:
        passed += 1
    else:
        failed.append(what)
        print("FAIL:", what, detail)


def abr(*args):
    r = subprocess.run([ABR, *args], capture_output=True, text=True, env=ENV, timeout=120)
    return r.returncode, r.stdout + r.stderr


def kind_of(name):
    for k, v in (("splash", "splash"), ("oplus", "oplus"), ("xiaomi", "xiaomi"), ("moto", "moto")):
        if name.startswith(k):
            return v
    raise SystemExit(name)


def files_of(d):
    return sorted(f for f in os.listdir(d) if not f.startswith(".") and f not in ("manifest.txt", "preamble.bin"))


def pixels(path):
    img = Image.open(path)
    img.load()
    return img.size, img.convert("RGB").tobytes()


def same_picture(a, b):
    return pixels(a) == pixels(b)


def same_bytes(a, b):
    return open(a, "rb").read() == open(b, "rb").read()


def judge_set(kind, got_dir, want_dir, replaced=None):
    """compare the files in got_dir (what abr unpacked, or what the independent decoder read) with the expectation in want_dir; replaced = {index: path} of pictures that were edited"""
    replaced = replaced or {}
    got = files_of(got_dir)
    want = files_of(want_dir)
    if len(got) != len(want):
        return False, "count %d != %d (%s)" % (len(got), len(want), got)
    for i, (g, w) in enumerate(zip(got, want)):
        ext = w.rsplit(".", 1)[1]
        ref = replaced.get(i, os.path.join(want_dir, w))
        gp = os.path.join(got_dir, g)
        pixelwise = kind == "splash" or (kind == "moto" and ext == "png")
        ok = same_picture(gp, ref) if pixelwise else same_bytes(gp, ref)
        if not ok:
            return False, "picture %d (%s vs %s) differs" % (i, g, ref)
    return True, ""


def fresh(*parts):
    p = os.path.join(WORK, *parts)
    if os.path.exists(p):
        shutil.rmtree(p)
    return p


def unpack(img, out):
    rc, text = abr("unpack", "-i", img, "-o", out)
    return rc, text


def manifest_set(folder, key, value):
    p = os.path.join(folder, "manifest.txt")
    lines = open(p).read().split("\n")
    done = False
    for i, l in enumerate(lines):
        if l.startswith(key + "="):
            lines[i] = "%s=%s" % (key, value)
            done = True
    if not done:
        lines.insert(len(lines) - 1 if lines[-1] == "" else len(lines), "%s=%s" % (key, value))
    open(p, "w").write("\n".join(lines))


def manifest_get(folder, key):
    for l in open(os.path.join(folder, "manifest.txt")).read().split("\n"):
        if l.startswith(key + "="):
            return l.split("=", 1)[1]
    return None


os.makedirs(WORK, exist_ok=True)
names = sorted(f[:-4] for f in os.listdir(GEN) if f.endswith(".img"))

# ------------------------------------------------------------------------------------------------- 1. info, unpack, untouched repack
for name in names:
    kind = kind_of(name)
    img = os.path.join(GEN, name + ".img")
    want = os.path.join(GEN, name + ".expect")
    rc, text = abr("info", "-i", img)
    check(rc == 0 and "layout" in text.lower() or "offset" in text.lower(), name + ": info", text[:300])
    out = fresh(name)
    rc, text = unpack(img, out)
    check(rc == 0, name + ": unpack rc", text[-500:])
    ok, why = judge_set(kind, out, want)
    check(ok, name + ": unpacked pictures are the expected ones", why)
    check("byte-for-byte" in text, name + ": unpack says the repack is identical", text[-300:])
    new = os.path.join(WORK, name + ".new.img")
    rc, text = abr("pack", "-i", out, "-o", new)
    check(rc == 0, name + ": pack rc", text[-500:])
    check(os.path.exists(new) and same_bytes(img, new), name + ": untouched repack is byte-identical")
    # the independent decoder reads what abr wrote, too
    dec = fresh(name + ".dec")
    ms.decode(kind, new, dec)
    ok, why = judge_set(kind, dec, want)
    check(ok, name + ": independent decode of the repack", why)

# the DDPH preamble of an OPLUS image is a file of its own, and stays as it is in an edited image
img = open(os.path.join(GEN, "oplus_ddph.img"), "rb").read()
pre = os.path.join(WORK, "oplus_ddph", "preamble.bin")
check(os.path.exists(pre) and open(pre, "rb").read() == img[:0x4000], "oplus_ddph: the preamble is kept as a file, byte for byte")
check(not os.path.exists(os.path.join(WORK, "oplus_gzip", "preamble.bin")), "oplus_gzip: zeros in front of the header are no file")

# ------------------------------------------------------------------------------------------------------------------ 2. edits
def edit_scenario(name, index, ext, size=None, set_keys=None, label=""):
    kind = kind_of(name)
    img = os.path.join(GEN, name + ".img")
    want = os.path.join(GEN, name + ".expect")
    out = fresh(name + ".edit" + label)
    rc, text = unpack(img, out)
    assert rc == 0, text
    fl = files_of(out)
    target = os.path.join(out, fl[index])
    edited = os.path.join(WORK, "%s.edited%s.%s" % (name, label, ext))
    args = ["edit", target, edited]
    if size:
        args += ["--size", str(size[0]), str(size[1])]
    subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mk_splash.py"), *args], check=True)
    shutil.copy(edited, target)
    for k, v in (set_keys or {}).items():
        manifest_set(out, k, v)
    new = os.path.join(WORK, "%s.edit%s.img" % (name, label))
    rc, text = abr("pack", "-i", out, "-o", new)
    check(rc == 0, "%s%s: edited pack rc" % (name, label), text[-600:])
    if rc != 0:
        return None
    dec = fresh(name + ".editdec" + label)
    try:
        ms.decode(kind, new, dec)
    except Exception as e:  # noqa: BLE001
        check(False, "%s%s: independent decode of the edited image" % (name, label), repr(e))
        return new
    ok, why = judge_set(kind, dec, want, {index: edited})
    check(ok, "%s%s: edited image decodes to the edited set" % (name, label), why)
    # abr reads its own result the same way
    out2 = fresh(name + ".edit2" + label)
    rc, text = unpack(new, out2)
    check(rc == 0, "%s%s: abr unpacks its own edited image" % (name, label), text[-400:])
    if rc == 0:
        ok, why = judge_set(kind, out2, want, {index: edited})
        check(ok, "%s%s: abr's re-unpack of the edited image" % (name, label), why)
    return new


# Qualcomm
new = edit_scenario("splash_rle", 0, "png", label="")
new = edit_scenario("splash_rle", 0, "png", label="_none", set_keys={"picture0_compression": "none"})
if new:
    d = open(new, "rb").read()
    check(struct.unpack_from("<I", d, 16)[0] == 0, "splash_rle: switching to none writes type 0")
new = edit_scenario("splash_raw", 0, "png", label="_rle", set_keys={"picture0_compression": "rle24"})
if new:
    d = open(new, "rb").read()
    check(struct.unpack_from("<I", d, 16)[0] == 1, "splash_raw: switching to rle24 writes type 1")
new = edit_scenario("splash_raw0", 0, "png", label="")
if new:
    d = open(new, "rb").read()
    check(struct.unpack_from("<I", d, 20)[0] == 0, "splash_raw0: a raw picture that said 0 blocks still says 0")
new = edit_scenario("splash_raw0", 0, "png", label="_rle", set_keys={"picture0_compression": "rle24"})
if new:
    d = open(new, "rb").read()
    check(struct.unpack_from("<I", d, 20)[0] != 0, "splash_raw0: coded as RLE24 it gets a block count")
edit_scenario("splash_rle", 0, "png", size=(100, 60), label="_resized")
edit_scenario("splash_several", 1, "png", label="")
edit_scenario("splash_several", 1, "png", size=(150, 90), label="_resized")
edit_scenario("splash_several", 2, "png", label="_last")
edit_scenario("splash_several_mixed", 0, "png", label="")
edit_scenario("splash_several_mixed", 2, "png", size=(60, 60), label="_flat")
edit_scenario("splash_rle_wide", 0, "png", label="")
edit_scenario("splash_raw_pad", 0, "png", label="")
# OPLUS
for name in ("oplus_gzip", "oplus_plain", "oplus_ddph"):
    edit_scenario(name, 1, "bmp", label="")
    edit_scenario(name, 0, "bmp", size=(200, 100), label="_resized")
# Xiaomi
for name in ("xiaomi", "xiaomi_tail"):
    edit_scenario(name, 0, "bmp", size=(90, 70), label="_bigger")
    edit_scenario(name, 1, "bmp", size=(20, 10), label="_smaller")
edit_scenario("xiaomi", 2, "png", label="_png")
d = open(os.path.join(WORK, "oplus_ddph.edit.img"), "rb").read()
check(d[:0x4000] == img[:0x4000], "oplus_ddph: an edited image keeps the preamble")
# Motorola
edit_scenario("moto", 0, "png", label="")
edit_scenario("moto", 1, "png", size=(80, 60), label="_resized")
edit_scenario("moto_slot", 0, "png", label="")

# gzip level of an OPLUS entry that is edited: the header says plain size = the file size, the entry is a gzip stream
img = os.path.join(GEN, "oplus_gzip.img")
out = fresh("oplus_lvl")
unpack(img, out)
manifest_set(out, "entry1_level", "1")
new = os.path.join(WORK, "oplus_lvl.img")
rc, text = abr("pack", "-i", out, "-o", new)
check(rc == 0, "oplus: a changed level packs", text[-300:])
d = open(new, "rb").read()
off, size, stored = struct.unpack_from("<III", d, 0x4000 + 288 + 128 * 1)
check(size == 28698, "oplus: plain size in the table stays the size of the BMP", str(size))
import gzip  # noqa: E402
check(gzip.decompress(d[0x8000 + off:0x8000 + off + stored]) == open(os.path.join(GEN, "oplus_gzip.expect", "01.bmp"), "rb").read(), "oplus: level 1 entry is the same BMP")

# Moto: pictures sit at multiples of align after an edit
new = os.path.join(WORK, "moto.edit_resized.img")
if os.path.exists(new):
    d = open(new, "rb").read()
    size = struct.unpack_from("<I", d, 9)[0]
    offs = [struct.unpack_from("<II", d, at + 24) for at in range(13, size, 32)]
    check(all(o % 512 == 0 for o, _ in offs), "moto: edited image keeps its pictures at multiples of 512", str(offs))
    check(len(d) % 512 == 0, "moto: edited image is a whole number of 512-byte blocks")

# ----------------------------------------------------------------------------------------------------------- 3. damaged images
rnd = random.Random(20261111)
crash = 0
mutations = 0
for name in names:
    img = open(os.path.join(GEN, name + ".img"), "rb").read()
    # cut-offs
    cases = []
    for cut in (1, 7, 100, 513, len(img) // 2):
        if cut < len(img):
            cases.append(("cut%d" % cut, img[:-cut]))
    # words changed in the first 0x5200 bytes (headers and tables)
    for _ in range(int(os.environ.get("ABR_LIVE_MUTANTS", 24))):  # (fewer under wine, where every run of abr starts a process of its own)
        b = bytearray(img)
        for _ in range(rnd.randrange(1, 4)):
            at = rnd.randrange(0, min(len(b), 0x5200))
            b[at] = rnd.randrange(256)
        cases.append(("mut", bytes(b)))
    for tag, data in cases:
        p = os.path.join(WORK, "damaged.img")
        open(p, "wb").write(data)
        for verb in ("info", "unpack"):
            mutations += 1
            args = [verb, "-i", p] + (["-o", fresh("damaged_out")] if verb == "unpack" else [])
            try:
                r = subprocess.run([ABR, *args], capture_output=True, text=True, env=ENV, timeout=60)
            except subprocess.TimeoutExpired:
                crash += 1
                check(False, "%s %s: hangs" % (name, tag))
                continue
            text = r.stdout + r.stderr
            if r.returncode < 0 or r.returncode >= 124 or "terminate called" in text or "Assertion" in text or "Segmentation" in text:
                crash += 1
                check(False, "%s %s %s: died (rc %d)" % (name, tag, verb, r.returncode), text[-300:])
            elif r.returncode != 0 and not text.strip():
                check(False, "%s %s %s: failed without a word" % (name, tag, verb))
            else:
                # what unpack accepted must pack again
                if verb == "unpack" and r.returncode == 0:
                    rc2, t2 = abr("pack", "-i", os.path.join(WORK, "damaged_out"), "-o", os.path.join(WORK, "damaged_back.img"))
                    check(rc2 == 0, "%s %s: accepted image packs again" % (name, tag), t2[-300:])
                else:
                    passed += 1

# ----------------------------------------------------------------------------------------------------------- 4. the names of an image are not obeyed by a terminal
# What a terminal would act on -- ESC, BEL, the C1 controls, bytes that are not UTF-8 -- in a name that the image holds is written as \xNN by abr itself
# (quote_shown, and escape_for_terminal in the table of the layout); the filter that stands between abr and a terminal is turned off here
# (ABR_UNFILTERED_OUTPUT=1), so that it is abr's own care that is judged, as the fuzzers do.
RAW_ENV = dict(ENV, ABR_UNFILTERED_OUTPUT="1")


def terminal_trouble(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        return "not UTF-8 at byte %d (%r)" % (e.start, raw[max(0, e.start - 12):e.start + 6])
    for ch in text:
        o = ord(ch)
        if (o < 0x20 and ch not in "\n\t") or o == 0x7F or 0x80 <= o <= 0x9F:
            return "the control character U+%04X" % o
    return None


def raw_abr(*args):
    r = subprocess.run([ABR, *args], capture_output=True, env=RAW_ENV, timeout=120)
    return r.returncode, r.stdout + r.stderr


HOSTILE = (b"\x1b[2J\x1b[Hxy", b"a\x07b\x08c\x7fd", b"cut\xe2\x82", b"c1\xc2\x9b31mx", b"\xff\xfe\x80ab", b"tab\there", b"two\nlines")
# (the image, where a name is in it, how long its field is): the entry of the table that names a picture
NAME_FIELDS = (("moto", 13, 24), ("moto_slot", 13 + 32 * 2, 24), ("oplus_gzip", 0x4000 + 288 + 12, 116))
for skeleton, at, width in NAME_FIELDS:
    src = os.path.join(GEN, skeleton + ".img")
    if not os.path.exists(src):
        continue
    img = open(src, "rb").read()
    for bad in HOSTILE:
        d = bytearray(img)
        d[at:at + width] = bad.ljust(width, b"\0")
        d = bytes(d)
        p = os.path.join(WORK, "hostile.img")
        open(p, "wb").write(d)
        out_dir = os.path.join(WORK, "hostile_out")
        shutil.rmtree(out_dir, ignore_errors=True)
        for verb, args in (("info", ["info", "-i", p]), ("unpack", ["unpack", "-i", p, "-o", out_dir])):
            rc, raw = raw_abr(*args)
            trouble = terminal_trouble(raw)
            check(trouble is None, "%s with the name %r: %s prints %s" % (skeleton, bad, verb, trouble), raw[-400:].decode("utf-8", "replace"))
            check(rc in (0, 1), "%s with the name %r: %s exit status %d" % (skeleton, bad, verb, rc))
            if verb == "unpack" and rc == 0:
                back = os.path.join(WORK, "hostile_back.img")
                rc2, raw2 = raw_abr("pack", "-i", out_dir, "-o", back)
                trouble = terminal_trouble(raw2)
                check(trouble is None, "%s with the name %r: pack prints %s" % (skeleton, bad, trouble), raw2[-400:].decode("utf-8", "replace"))
                check(rc2 == 0, "%s with the name %r: the unpacked image packs again" % (skeleton, bad), raw2[-300:].decode("utf-8", "replace"))
                if rc2 == 0:
                    check(open(back, "rb").read() == d, "%s with the name %r: packs back to the same bytes" % (skeleton, bad))

print("passed %d, failed %d, damaged-image runs %d (died %d)" % (passed, len(failed), mutations, crash))
for f in failed:
    print("  -", f)
sys.exit(1 if failed else 0)
