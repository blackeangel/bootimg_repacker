#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic MediaTek images, made and read WITHOUT abr.

  mk_mtk.py make DIR                  the containers of the small images (a 512-byte partition header, its data, padding up to the next header):
                                      md1img.img (a modem: three sections, one gzip), logo.bin (a table of three zlib pictures, 32-bit), logo565.bin (16-bit
                                      pictures, one of a size nobody knows, one that is no zlib stream, one cut short), logoalpha.bin (constant and
                                      changing alpha), legacy.img (headers without the extension, a name with a path in it, two sections of one name,
                                      padding that is not uniform), align512.img (alignment 512)
  mk_mtk.py boot DIR MKBOOTIMG        ordinary AOSP boot images (header version 0, made by the AOSP mkbootimg.py) whose kernel and ramdisk have the 512-byte
                                      MediaTek header in front: boot_plain.img (the plain header: magic, size, name, 0xFF), boot_odd.img (headers that are
                                      not: an address, bytes behind the name, a size that is not the size of the payload), boot_cut.img (kernel and ramdisk
                                      are gzip streams that end before their end), boot_whole.img (the same streams, whole)
  mk_mtk.py parse IMAGE               the sections of a container, as this script reads them

The layout is that of the partition header of MediaTek's boot loader (part_hdr_t) as the loader reads it.
"""
import gzip
import os
import random
import struct
import subprocess
import sys
import zlib

MAGIC = 0x58881688
EXT_MAGIC = 0x58891689
ANY = 0xFFFFFFFF


def header(name, size, maddr=ANY, mode=ANY, ext=True, last=False, align=16, typ=0):
    b = bytearray(b"\xff" * 512)
    struct.pack_into("<I", b, 0, MAGIC)
    struct.pack_into("<I", b, 4, size & 0xFFFFFFFF)
    b[8:40] = name.encode().ljust(32, b"\0")
    struct.pack_into("<II", b, 40, maddr, mode)
    if ext:
        struct.pack_into("<IIIIIIII", b, 48, EXT_MAGIC, 512, 1, typ, 1 if last else 0, align, size >> 32, 0)
    return bytes(b)


def chain(sections, align=16, pad=b"\0"):
    """sections: (name, data, keywords of header()); every header is on a multiple of `align`, filled up with `pad`."""
    out = bytearray()
    for i, (name, data, kw) in enumerate(sections):
        last = i == len(sections) - 1
        out += header(name, len(data), last=last, align=align, **kw)
        out += data
        if not last:
            out += pad * ((-len(out)) % align)
    return bytes(out)


def logo_table(streams):
    count = len(streams)
    off = 8 + 4 * count
    offs = []
    for s in streams:
        offs.append(off)
        off += len(s)
    return struct.pack("<II", count, off) + b"".join(struct.pack("<I", o) for o in offs) + b"".join(streams)


def bgra(w, h, seed):
    return b"".join(bytes(((x * 255) // w, (y * 255) // h, (x + y + seed) & 255, 255)) for y in range(h) for x in range(w))


def containers(out):
    os.makedirs(out, exist_ok=True)
    rnd = random.Random(7)

    def put(name, data):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)

    rom = bytes(rnd.randrange(256) for _ in range(5000)) + bytes(range(256)) * 20
    dsp = gzip.compress((b"DSP-DATA-" + bytes(range(200))) * 300, 6, mtime=0)
    fmap = b"md1rom=md1rom.img\nmd1dsp=md1dsp.img\n"
    put("md1img.img", chain([("md1rom", rom, dict(maddr=0x0, mode=0)), ("md1dsp", dsp, dict(maddr=0x10000000, mode=0)), ("md1_file_map", fmap, dict())]) + b"\xff" * 100)

    streams = [zlib.compress(bgra(240, 320, 1), 6), zlib.compress(bgra(240, 320, 2), 6), zlib.compress(bgra(480, 800, 3), 6)]
    tbl = logo_table(streams)
    put("logo.bin", header("logo", len(tbl), last=True) + tbl)

    # RGB565 pictures, a size that is in no table, bytes that are no zlib stream, and a stream that is cut short
    w, h = 480, 800
    px565 = b"".join(struct.pack("<H", ((x * 31 // w) << 11) | ((y * 63 // h) << 5) | ((x + y) & 31)) for y in range(h) for x in range(w))
    odd = bytes(range(256)) * 13 + b"xyz"
    streams = [zlib.compress(px565, 9), zlib.compress(px565[::-1], 1), zlib.compress(odd, 6), b"NOT-A-ZLIB-STREAM-AT-ALL", zlib.compress(px565)[:-9]]
    tbl = logo_table(streams)
    put("logo565.bin", header("logo", len(tbl), last=True) + tbl)

    w, h = 240, 320
    a1 = b"".join(bytes((x % 256, y % 256, 7, 128)) for y in range(h) for x in range(w))
    a2 = b"".join(bytes((x % 256, y % 256, 9, (x * 255) // w)) for y in range(h) for x in range(w))
    tbl = logo_table([zlib.compress(a1), zlib.compress(a2)])
    put("logoalpha.bin", header("logo", len(tbl), last=True) + tbl)

    # headers of the older kind (no extension: bytes 48 to 511 all 0xFF), a name that is a path, two sections of one name, padding that is not uniform
    def old(name, size):
        b = bytearray(b"\xff" * 512)
        struct.pack_into("<II", b, 0, MAGIC, size)
        b[8:40] = name.encode().ljust(32, b"\0")
        struct.pack_into("<II", b, 40, 0x80000000, 0)
        return bytes(b)

    a = bytes(range(250)) * 3
    b = b"B" * 1000
    img = old("../evil/name", len(a)) + a
    img += bytes((i * 7) & 0xFF for i in range((-len(img)) % 16))
    img += old("dup", len(b)) + b
    img += b"\0" * ((-len(img)) % 16)
    img += old("dup", 5) + b"12345"
    put("legacy.img", img)

    put("align512.img", chain([("tee1", b"T" * 700, dict(maddr=0x1000)), ("tee2", b"U" * 33, dict())], align=512))


def parse(d):
    """The sections of a container: [{name, size, at (of the data), data, last, align}]. Independent of abr; stops at the last section or at bytes that
    are no header."""
    out, pos = [], 0
    while pos + 512 <= len(d) and struct.unpack_from("<I", d, pos)[0] == MAGIC:
        size = struct.unpack_from("<I", d, pos + 4)[0]
        name = d[pos + 8:pos + 40].split(b"\0")[0].decode("latin1")
        ext = struct.unpack_from("<I", d, pos + 48)[0] == EXT_MAGIC
        last = ext and struct.unpack_from("<I", d, pos + 64)[0] == 1
        align = struct.unpack_from("<I", d, pos + 68)[0] if ext else 16
        if not (4 <= align <= 65536 and align & (align - 1) == 0):
            align = 16
        if ext:
            size |= struct.unpack_from("<I", d, pos + 72)[0] << 32
        at = pos + 512
        out.append(dict(name=name, size=size, at=at, data=d[at:at + size], last=last, align=align, header_at=pos))
        if last:
            break
        pos = (at + size + align - 1) // align * align
    return out


# ------------------------------------------------------------------------------------------------------------------------ boot images


def newc(entries):
    """A cpio archive in the SVR4 'newc' format: entries are (name, mode, data)."""
    out = bytearray()
    for ino, (name, mode, data) in enumerate(entries + [("TRAILER!!!", 0, b"")], 1):
        nm = name.encode() + b"\0"
        out += b"070701" + b"".join(b"%08X" % v for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0))
        out += nm + b"\0" * ((-(110 + len(nm))) % 4)
        out += data + b"\0" * ((-len(data)) % 4)
    return bytes(out)


def mtk_hdr(name, declared, tail=b"", maddr=ANY, mode=ANY):
    """The header in front of the kernel or the ramdisk of an MTK boot image: magic, size, name (then `tail` behind the zero of the name), 0xFF."""
    b = bytearray(b"\xff" * 512)
    struct.pack_into("<II", b, 0, MAGIC, declared)
    b[8:40] = (name.encode() + b"\0" + tail).ljust(32, b"\0")
    struct.pack_into("<II", b, 40, maddr, mode)
    return bytes(b)


def boot_images(out, mkbootimg):
    os.makedirs(out, exist_ok=True)
    rnd = random.Random(11)
    kernel_plain = bytes(rnd.randrange(256) for _ in range(9000))
    rd = newc([("init", 0o100755, b"#!/bin/sh\n" * 20), ("etc", 0o040755, b""), ("etc/fstab", 0o100644, b"/dev/block/mmcblk0p1 /data ext4 defaults 0 0\n")])
    k_gz = gzip.compress(kernel_plain + b"MTK kernel" * 50, 6, mtime=0)
    r_gz = gzip.compress(rd, 6, mtime=0)

    def boot(name, kernel, ramdisk):
        kf, rf = os.path.join(out, name + ".kernel"), os.path.join(out, name + ".ramdisk")
        for p, data in ((kf, kernel), (rf, ramdisk)):
            with open(p, "wb") as f:
                f.write(data)
        subprocess.run([sys.executable, mkbootimg, "--header_version", "0", "--kernel", kf, "--ramdisk", rf, "--pagesize", "2048", "--base", "0x80000000",
                        "--cmdline", "bootopt=64S3,32N2,32N2", "-o", os.path.join(out, name + ".img")], check=True, stdout=subprocess.DEVNULL)
        os.unlink(kf)
        os.unlink(rf)

    boot("boot_plain", mtk_hdr("KERNEL", len(k_gz)) + k_gz, mtk_hdr("ROOTFS", len(r_gz)) + r_gz)
    # the loader's own header: an address and a mode, bytes behind the name; the ramdisk's size field says 12 less than the payload (12 bytes of padding),
    # and one byte of its 0xFF fill is not 0xFF
    boot("boot_odd", mtk_hdr("KERNEL", len(k_gz), tail=b"junk", maddr=0x80008000, mode=0) + k_gz,
         mtk_hdr("ROOTFS", len(r_gz), tail=b"", maddr=0x84000000, mode=0)[:100] + b"\x11" + mtk_hdr("ROOTFS", len(r_gz))[101:] + r_gz + bytes(12))
    # the streams end before their end: what a copy that stopped half way, or a tool that wrote the size wrong, leaves
    boot("boot_cut", mtk_hdr("KERNEL", len(k_gz) - 40) + k_gz[:-40], mtk_hdr("ROOTFS", len(r_gz) - 30) + r_gz[:-30])
    boot("boot_whole", mtk_hdr("KERNEL", len(k_gz)) + k_gz, mtk_hdr("ROOTFS", len(r_gz)) + r_gz)
    return kernel_plain, rd


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "make":
        containers(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "boot":
        boot_images(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "parse":
        with open(sys.argv[2], "rb") as f:
            for s in parse(f.read()):
                print("%-16s %8d bytes at 0x%x, alignment %d%s" % (s["name"], s["size"], s["at"], s["align"], ", last" if s["last"] else ""))
    else:
        print(__doc__)
        sys.exit(2)
