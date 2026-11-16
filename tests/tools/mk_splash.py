#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic images of the picture partitions (Qualcomm splash, OPLUS oplus_logo, Xiaomi xiaomi_logo, Motorola moto_logo), made and read WITHOUT abr.

The layouts are those of the public tools of each family -- Qualcomm's logo_gen.py (the 512-byte SPLASH!! header, the RLE24 coder), Magic-Splash-Wand's
splash.php and splash_oplus.php, xiaomi-bootlogo-editor's main.c, moto-bootlogo's BinFile and BinImage -- written again here, so that this is a second
writer and a second reader to compare abr with, not a copy of it. Needs Pillow.

  mk_splash.py gen DIR               writes the test images DIR/<name>.img and the pictures they hold (DIR/<name>.expect/NN.png, the BMP/PNG files as they are)
  mk_splash.py decode KIND IMG OUT   decodes an image (made by abr) independently: OUT/NN.png (decoded pixels) or OUT/NN.<ext> (files as they are)
  mk_splash.py same A.png B.png      exit 0 when the pixels of the two pictures are equal
  mk_splash.py edit IN.png OUT.png [--size W H]   draws a mark into a picture (for the edit scenarios), optionally resized first
"""
import argparse
import gzip
import io
import json
import os
import random
import struct
import sys

from PIL import Image, ImageDraw

BLOCK = 512


def align_up(v, a):
    return (v + a - 1) // a * a


# ------------------------------------------------------------------------------------------------------------------------------ pictures
def make_picture(w, h, seed):
    rnd = random.Random(seed)
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = (x * 255 // max(1, w - 1), y * 255 // max(1, h - 1), (x + y) % 256)
    d = ImageDraw.Draw(img)
    d.rectangle([w // 8, h // 8, w // 2, h // 2], fill=(rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)))
    d.rectangle([w // 2 + 1, h // 2 + 1, w - 2, h - 2], fill=(0, 0, 0))
    for _ in range(w * h // 25):
        px[rnd.randrange(w), rnd.randrange(h)] = (rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
    return img


def bgr(img):
    return img.convert("RGB").tobytes("raw", "BGR")


def from_bgr(data, w, h):
    return Image.frombytes("RGB", (w, h), data, "raw", "BGR")


def png_bytes(img):
    b = io.BytesIO()
    img.save(b, "PNG")
    return b.getvalue()


def bmp_bytes(img):
    b = io.BytesIO()
    img.convert("RGB").save(b, "BMP")
    return b.getvalue()


# ------------------------------------------------------------------------------------------------------- RLE24 (logo_gen.py, Python 3)
def rle_line(line):
    # a transcription of encode() of logo_gen.py (QRD): (count, run) entries, count > 128: a pixel repeated count - 128 times
    count = 0
    lst = []
    repeat = -1
    run = []
    total = len(line) - 1
    for index, current in enumerate(line[:-1]):
        if current != line[index + 1]:
            run.append(current)
            count += 1
            if repeat == 1:
                lst.append((count + 128, run))
                count = 0
                run = []
                repeat = -1
                if index == total - 1:
                    run = [line[index + 1]]
                    lst.append((1, run))
            else:
                repeat = 0
                if count == 128:
                    lst.append((128, run))
                    count = 0
                    run = []
                    repeat = -1
                if index == total - 1:
                    run.append(line[index + 1])
                    lst.append((count + 1, run))
        else:
            if repeat == 0:
                lst.append((count, run))
                count = 0
                run = []
                repeat = -1
                if index == total - 1:
                    run.append(line[index + 1])
                    run.append(line[index + 1])
                    lst.append((2 + 128, run))
                    break
            run.append(current)
            repeat = 1
            count += 1
            if count == 128:
                lst.append((256, run))
                count = 0
                run = []
                repeat = -1
            if index == total - 1:
                if count == 0:
                    run = [line[index + 1]]
                    lst.append((1, run))
                else:
                    run.append(current)
                    lst.append((count + 1 + 128, run))
    return lst


def rle24_encode(img):
    w, h = img.size
    px = img.convert("RGB").load()
    out = bytearray()
    for y in range(h):
        line = [(px[x, y][0] << 16) + (px[x, y][1] << 8) + px[x, y][2] for x in range(w)]
        for count, pixel in rle_line(line):
            out.append(count - 1)
            items = [pixel[0]] if count > 128 else pixel
            for item in items:
                out += bytes([item & 0xFF, (item >> 8) & 0xFF, (item >> 16) & 0xFF])
    return bytes(out)


def rle24_decode(data, w, h, strict_rows=False):
    # as the PHP tool reads it: a packet is a count byte (bit 7: one pixel repeated; else count pixels), pixels are blue, green, red
    out = bytearray()
    pos = 0
    x = 0
    while len(out) < w * h * 3:
        if pos >= len(data):
            raise ValueError("RLE24 stream cut short")
        c = data[pos]
        pos += 1
        n = (c & 127) + 1
        if c & 128:
            out += data[pos:pos + 3] * n
            pos += 3
        else:
            out += data[pos:pos + 3 * n]
            pos += 3 * n
        x += n
        if strict_rows:
            if x > w:
                raise ValueError("a packet crosses the end of a row")
            if x == w:
                x = 0
    if len(out) != w * h * 3:
        raise ValueError("RLE24 stream overruns the picture")
    return bytes(out), pos


# ---------------------------------------------------------------------------------------------------------------- MotoRun (moto-bootlogo)
def motorun_encode(img):
    w, h = img.size
    px = img.convert("RGB").load()
    out = bytearray(b"MotoRun\0" + struct.pack(">HH", w, h))
    for y in range(h):
        row = [bytes((px[x, y][2], px[x, y][1], px[x, y][0])) for x in range(w)]
        x = 0
        while x < w:
            n = 1
            while x + n < w and row[x + n] == row[x] and n < 4095:
                n += 1
            if n >= 3:
                out += bytes([0x80 | (n >> 8), n & 0xFF]) + row[x]
                x += n
                continue
            m = x
            while m < w and m - x < 4095:
                k = 1
                while m + k < w and row[m + k] == row[m]:
                    k += 1
                if k >= 3:
                    break
                m += 1
            n = max(m - x, 1)
            out += bytes([n >> 8, n & 0xFF]) + b"".join(row[x:x + n])
            x += n
    return bytes(out)


def motorun_decode(data):
    # as BinImage::_decode() reads it
    if data[:8] != b"MotoRun\0":
        raise ValueError("not MotoRun")
    w, h = struct.unpack(">HH", data[8:12])
    pos = 12
    out = bytearray()
    while pos < len(data):
        b = data[pos]
        pos += 1
        if b & 0x70:
            raise ValueError("invalid nybble")
        n = ((b & 0x0F) << 8) | data[pos]
        pos += 1
        if b >> 7:
            out += data[pos:pos + 3] * n
            pos += 3
        else:
            out += data[pos:pos + 3 * n]
            pos += 3 * n
    if len(out) != w * h * 3 or pos != len(data):
        raise ValueError("MotoRun stream does not make the picture")
    return from_bgr(bytes(out), w, h)


# ------------------------------------------------------------------------------------------------------------------------------ containers
def splash_single(img, rle, blocks="real", pad=False):
    body = rle24_encode(img) if rle else bgr(img)
    w, h = img.size
    real = (len(body) + BLOCK - 1) // BLOCK
    word = real if blocks == "real" else 0
    head = b"SPLASH!!" + struct.pack("<IIII", w, h, 1 if rle else 0, word)
    head = head.ljust(BLOCK, b"\0")
    if pad:
        body = body.ljust(real * BLOCK, b"\0")
    return head + body


def splash_several(imgs, rles):
    head = b"SPLASH!!" + struct.pack("<I", len(imgs))
    payload = b""
    for img, rle in zip(imgs, rles):
        body = rle24_encode(img) if rle else bgr(img)
        blocks = (len(body) + BLOCK - 1) // BLOCK
        head += struct.pack("<IIIII", img.size[0], img.size[1], 1 if rle else 0, blocks, BLOCK + len(payload))
        payload += body.ljust(blocks * BLOCK, b"\0")
    return head.ljust(BLOCK, b"\0") + payload


def oplus_image(entries, version=1, width=1080, height=2400, compress=True, descriptions=("", "", "", ""), preamble=None, level=9):
    # splash_oplus.php: 0x4000 bytes, the header (the magic, 4 descriptions of 64 bytes, count, version, width, height, compress, the table of 128-byte
    # entries from 288), padded to 0x8000, then the pictures one behind the other
    table = b""
    payload = b""
    for name, bmp in entries:
        out = gzip.compress(bmp, level, mtime=0) if compress else bmp
        table += struct.pack("<III", len(payload), len(bmp), len(out)) + name.encode()[:116].ljust(116, b"\0")
        payload += out
    head = (preamble if preamble is not None else bytes(0x4000)) + b"SPLASH LOGO!"
    for i in range(4):
        head += descriptions[i].encode()[:64].ljust(64, b"\0")
    head += struct.pack("<IIIII", len(entries), version, width, height, 1 if compress else 0)
    head = (head + table).ljust(0x8000, b"\0")
    return head + payload


def xiaomi_image(files, preamble=None, fill=b""):
    # xiaomi-bootlogo-editor: 0x4000 bytes, a 4096-byte table at 0x4000 (the magic, pairs of offset and size in units of 4096 -- the first picture at unit 5), the
    # pictures from 0x5000, each in whole units
    table = bytearray(0x1000)
    table[:8] = b"LOGO!!!!"
    unit = 5
    payload = b""
    for i, f in enumerate(files):
        units = (len(f) + 0xFFF) >> 12
        struct.pack_into("<II", table, 8 + 8 * i, unit, units)
        payload += f.ljust(units * 0x1000, b"\0")
        unit += units
    return (preamble if preamble is not None else bytes(0x4000)) + bytes(table) + payload + fill


def moto_image(entries, align=512, header_fill=0xFF, gap_fill=0xFF, pad_end=True):
    # moto-bootlogo (the example header of BinFile.cpp): "MotoLogo\0", the size of the table (13 + 32 per entry), the entries (a name of 24 bytes, the offset and the
    # size of the picture), 0xFF up to the first picture, the pictures at multiples of align
    table_size = 13 + 32 * len(entries)
    ent = b""
    cursor = align_up(table_size, align)
    pictures = []
    for name, data in entries:
        if data:
            ent += name.encode().ljust(24, b"\0") + struct.pack("<II", cursor, len(data))
            pictures.append((cursor, data))
            cursor = align_up(cursor + len(data), align)
        else:
            ent += name.encode().ljust(24, b"\0") + struct.pack("<II", 0, 0)
    out = bytearray(b"MotoLogo\0" + struct.pack("<I", table_size) + ent)
    for at, data in pictures:
        out += bytes([header_fill if at == pictures[0][0] else gap_fill]) * (at - len(out))
        out += data
    if pad_end:
        out += bytes([gap_fill]) * (align_up(len(out), align) - len(out))
    return bytes(out)


# ------------------------------------------------------------------------------------------------------------------------- the test set
def gen(d):
    os.makedirs(d, exist_ok=True)
    expect = {}

    def put(name, image, pictures):
        open(os.path.join(d, name + ".img"), "wb").write(image)
        e = os.path.join(d, name + ".expect")
        os.makedirs(e, exist_ok=True)
        for i, (ext, content) in enumerate(pictures):
            open(os.path.join(e, "%02d.%s" % (i, ext)), "wb").write(content)
        expect[name] = [ext for ext, _ in pictures]

    a = make_picture(64, 48, 1)
    b = make_picture(123, 77, 2)
    c = make_picture(300, 20, 3)  # wide: runs longer than 128 and 256 pixels
    px = c.load()
    for x in range(300):
        px[x, 5] = (9, 9, 9)  # a whole row of one colour
        px[x, 6] = (200, 10, 10) if x < 150 else (10, 10, 200)
    flat = Image.new("RGB", (40, 30), (12, 34, 56))  # one colour

    # sanity of the transcription: what the vendor encoder writes is what the decoder reads
    for img in (a, b, c, flat):
        data, used = rle24_decode(rle24_encode(img), img.size[0], img.size[1], strict_rows=True)
        assert data == bgr(img), "logo_gen transcription does not round trip"

    pic = lambda im: ("png", png_bytes(im))
    put("splash_raw0", splash_single(b, False, blocks="zero"), [pic(b)])  # as Qualcomm's sample images (blocks 0, exactly the pixels)
    put("splash_raw", splash_single(b, False, blocks="real"), [pic(b)])
    put("splash_raw_pad", splash_single(b, False, blocks="real", pad=True) + bytes(3000), [pic(b)])
    put("splash_rle", splash_single(b, True), [pic(b)])
    put("splash_rle_wide", splash_single(c, True), [pic(c)])
    put("splash_rle_flat", splash_single(flat, True), [pic(flat)])
    put("splash_several", splash_several([a, b, c], [True, True, True]), [pic(a), pic(b), pic(c)])
    put("splash_several_mixed", splash_several([a, b, flat], [False, True, True]), [pic(a), pic(b), pic(flat)])

    bmps = [("logo", bmp_bytes(a)), ("fhd_wallpaper.bmp", bmp_bytes(b)), ("charge", bmp_bytes(flat))]
    put("oplus_gzip", oplus_image(bmps, descriptions=("OPLUS test logo", "", "second", "")), [("bmp", x) for _, x in bmps])
    put("oplus_plain", oplus_image(bmps, compress=False), [("bmp", x) for _, x in bmps])
    ddph = struct.pack("<II", 0x48504444, 1) + bytes(range(256)) * 3 + bytes(0x4000 - 8 - 768)
    put("oplus_ddph", oplus_image(bmps, preamble=ddph) + bytes(5000), [("bmp", x) for _, x in bmps])

    pngs = png_bytes(c)
    xi = [bmp_bytes(a), bmp_bytes(b), pngs]
    put("xiaomi", xiaomi_image(xi), [("bmp", xi[0]), ("bmp", xi[1]), ("png", xi[2])])
    put("xiaomi_tail", xiaomi_image(xi, fill=bytes(0x3000)), [("bmp", xi[0]), ("bmp", xi[1]), ("png", xi[2])])

    mo = [("logo_boot", motorun_encode(a)), ("logo_battery", motorun_encode(c)), ("raw_data", b"\x01\x02\x03 not a picture \xff" * 20)]
    put("moto", moto_image(mo), [("png", png_bytes(a)), ("png", png_bytes(c)), ("bin", mo[2][1])])
    mo2 = [("logo_boot", motorun_encode(b)), ("empty", b""), ("logo_unlocked", motorun_encode(flat))]
    put("moto_slot", moto_image(mo2, pad_end=False), [("png", png_bytes(b)), None, ("png", png_bytes(flat))] if False else [("png", png_bytes(b)), ("png", png_bytes(flat))])
    json.dump(expect, open(os.path.join(d, "expect.json"), "w"), indent=1)


def decode(kind, path, out):
    d = open(path, "rb").read()
    os.makedirs(out, exist_ok=True)
    n = 0

    def save(ext, content):
        nonlocal n
        open(os.path.join(out, "%02d.%s" % (n, ext)), "wb").write(content)
        n += 1

    if kind == "splash":
        assert d[:8] == b"SPLASH!!"
        first = struct.unpack_from("<I", d, 8)[0]
        # the single form has zeros at 24..32 (the rest of the header); the table form has the offset of the first picture (at least 512) at 28
        if struct.unpack_from("<I", d, 28)[0] >= 512:
            for i in range(first):
                w, h, t, blocks, off = struct.unpack_from("<IIIII", d, 12 + 20 * i)
                body = d[off:off + blocks * BLOCK]
                if t == 1:
                    raw, _ = rle24_decode(body, w, h, strict_rows=True)
                else:
                    raw = body[:w * h * 3]
                save("png", png_bytes(from_bgr(raw, w, h)))
        else:
            w, h, t, blocks = struct.unpack_from("<IIII", d, 8)
            body = d[BLOCK:BLOCK + blocks * BLOCK] if blocks else d[BLOCK:]
            if t == 1:
                raw, _ = rle24_decode(body, w, h, strict_rows=True)
            else:
                raw = body[:w * h * 3]
                assert len(raw) == w * h * 3
            save("png", png_bytes(from_bgr(raw, w, h)))
    elif kind == "oplus":
        assert d[0x4000:0x400C] == b"SPLASH LOGO!"
        h = d[0x4000:0x8000]
        count, version, width, height, comp = struct.unpack_from("<IIIII", h, 268)
        for i in range(count):
            off, size, stored = struct.unpack_from("<III", h, 288 + 128 * i)
            raw = d[0x8000 + off:0x8000 + off + stored]
            if comp == 1:
                raw = gzip.decompress(raw)
            assert len(raw) == size
            save("bmp", raw)
    elif kind == "xiaomi":
        assert d[0x4000:0x4008] == b"LOGO!!!!"
        i = 0
        while True:
            off, units = struct.unpack_from("<II", d, 0x4008 + 8 * i)
            if off == 0:
                break
            raw = d[off << 12:(off + units) << 12]
            if raw[:4] == b"\x89PNG":
                raw = raw[:raw.index(b"IEND") + 8]  # the picture ends with the IEND chunk (and its CRC); zeros fill the unit
                save("png", raw)
            else:
                assert raw[:2] == b"BM"
                save("bmp", raw[:struct.unpack_from("<I", raw, 2)[0]])  # the BMP header says how long the file is
            i += 1
    elif kind == "moto":
        assert d[:9] == b"MotoLogo\0"
        size = struct.unpack_from("<I", d, 9)[0]
        for at in range(13, size, 32):
            off, length = struct.unpack_from("<II", d, at + 24)
            if not length:
                continue
            raw = d[off:off + length]
            if raw[:8] == b"MotoRun\0":
                save("png", png_bytes(motorun_decode(raw)))
            else:
                save("bin", raw)
    else:
        raise SystemExit("kind: splash oplus xiaomi moto")


def pixels(path):
    img = Image.open(path)
    img.load()
    return img.size, img.convert("RGB").tobytes()


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen")
    g.add_argument("dir")
    dd = sub.add_parser("decode")
    dd.add_argument("kind")
    dd.add_argument("img")
    dd.add_argument("out")
    s = sub.add_parser("same")
    s.add_argument("a")
    s.add_argument("b")
    e = sub.add_parser("edit")
    e.add_argument("src")
    e.add_argument("dst")
    e.add_argument("--size", nargs=2, type=int, default=None)
    a = ap.parse_args()
    if a.cmd == "gen":
        gen(a.dir)
    elif a.cmd == "decode":
        decode(a.kind, a.img, a.out)
    elif a.cmd == "same":
        sys.exit(0 if pixels(a.a) == pixels(a.b) else 1)
    elif a.cmd == "edit":
        img = Image.open(a.src).convert("RGB")
        if a.size:
            img = img.resize((a.size[0], a.size[1]), Image.NEAREST)
        w, h = img.size
        ImageDraw.Draw(img).rectangle([1, 1, max(2, w // 3), max(2, h // 3)], fill=(250, 10, 120))
        px = img.load()
        for i in range(0, min(w, 40)):
            px[i, h - 1] = ((i * 37) % 256, (i * 11) % 256, 77)
        img.save(a.dst)  # the format follows the extension (.png, .bmp)


if __name__ == "__main__":
    main()
