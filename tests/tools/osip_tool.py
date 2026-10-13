#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Intel OSIP boot images for the tests of tests/run_tests.sh, written independently of abr.

usage: osip_tool.py header <out> [--attribute N]
                                  a standard 512-byte OSIP header: "$OS$" 00 00 01, one OSII entry (the sector
                                  count and the checksum are left for `make`), attribute N (default 1)
       osip_tool.py make <out> [--hdr FILE] [--sig FILE] --cmdline TEXT [--parameter HEX] --bootstub FILE
                               --kernel FILE --ramdisk FILE [--pad BYTE|none]
                                  an image, packed the way mboot packs it (see below); --pad is the byte that
                                  fills it up to a whole sector (default 0xFF), `none` leaves it unpadded
       osip_tool.py list <image>  how mboot would take the image apart: hdr, sig, cmdline, parameter, bootstub,
                                  kernel, ramdisk (sizes), end (where the ramdisk ends)
       osip_tool.py extract <image> <dir>
                                  writes hdr, sig, cmdline.txt, parameter, bootstub, kernel and ramdisk.cpio.gz
                                  into <dir> (the names mboot -u uses)
       osip_tool.py check <image> the header's sector count, checksum and "unsigned" bit are what mboot makes
                                  them (exit 1, saying which is not)

The format is read from osm0sis' mboot.c (after Jocelyn Falempe's mboot.py): an optional 512-byte header, a
signature of 0, 480, 728 or 1024 bytes, a 1024-byte cmdline, 3072 bytes of image info (u32 kernel size, u32
ramdisk size, 8 bytes of parameter, then padding -- BD 02 BD 02 BD 12 BD 12 right behind the parameter in a
signed image), a bootstub of 4096 (or 8192) bytes, the kernel, the ramdisk, and padding up to a whole sector.
`make` does what mboot's pack does: the header gets the sector count (offset 48), the "unsigned" bit (offset 52,
when there is no signature) and the XOR checksum of its first 56 bytes (byte 7, itself counted as zero).
"""
import struct
import sys


def le32(d, pos):
    return struct.unpack_from("<I", d, pos)[0]


def alnum(c):
    return 48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122


def check_byte(d, pos, size, minimum):
    return sum(1 for c in d[pos:pos + size] if alnum(c)) >= minimum


def checksum(header):
    x = 0
    for i, c in enumerate(header[:56]):
        if i != 7:
            x ^= c
    return x


def standard_header(attribute=1):
    h = bytearray(512)
    h[0:7] = b"$OS$\x00\x00\x01"
    h[8] = 1                              # number of pointers
    h[9] = 1                              # number of images
    struct.pack_into("<H", h, 10, 56)     # header size
    struct.pack_into("<HHIII", h, 32, 0, 1, 1, 0x01100000, 0x01101000)  # OSII: revision, start block, load, entry
    h[52] = attribute
    return bytes(h)


def make(hdr, sig, cmdline, parameter, bootstub, kernel, ramdisk, pad=0xFF):
    """mboot's pack. `pad` None: no padding up to a whole sector."""
    img_size = len(hdr) + len(sig) + 4096 + len(bootstub) + len(kernel) + len(ramdisk)
    padding = 0 if pad is None or img_size % 512 == 0 else 512 - img_size % 512
    out = bytearray(img_size + padding)
    out[0:len(hdr)] = hdr
    base = len(hdr) + len(sig)
    if sig:
        out[len(hdr):base] = sig
        out[base + 1024 + 16:base + 1024 + 24] = b"\xbd\x02\xbd\x02\xbd\x12\xbd\x12"
    elif hdr:
        out[52] |= 1
    out[base:base + len(cmdline)] = cmdline
    struct.pack_into("<II", out, base + 1024, len(kernel), len(ramdisk))
    out[base + 1032:base + 1032 + len(parameter)] = parameter
    pos = base + 4096
    for part in (bootstub, kernel, ramdisk):
        out[pos:pos + len(part)] = part
        pos += len(part)
    if padding:
        out[img_size:] = bytes([pad]) * padding
    if hdr:
        struct.pack_into("<I", out, 48, (img_size + padding) // 512 - 1)
        out[7] = 0
        out[7] = checksum(out[:56])
    return bytes(out)


def unpack(d):
    """mboot's unpack, as a dict of the pieces."""
    pos = 0
    hdr = b""
    if not check_byte(d, 0, 1, 1):
        hdr = d[:512]
        pos = 512
    for delta in (0, 480, 248, 296):
        pos += delta
        if check_byte(d, pos, 4, 4):
            break
    sig = d[len(hdr):pos]
    cmdline = d[pos:pos + 1024]
    kernel_size = le32(d, pos + 1024)
    ramdisk_size = le32(d, pos + 1028)
    parameter = d[pos + 1032:pos + 1040]
    pos += 4096
    stub = 8192 if check_byte(d, pos + 4096, 2, 1) else 4096
    bootstub = d[pos:pos + stub]
    pos += stub
    kernel = d[pos:pos + kernel_size]
    pos += kernel_size
    ramdisk = d[pos:pos + ramdisk_size]
    pos += ramdisk_size
    return {"hdr": hdr, "sig": sig, "cmdline": cmdline.split(b"\0")[0], "parameter": parameter, "bootstub": bootstub,
            "kernel": kernel, "ramdisk": ramdisk, "end": pos, "kernel_size": kernel_size, "ramdisk_size": ramdisk_size}


def main(argv):
    if len(argv) >= 3 and argv[1] == "header":
        attribute = int(argv[argv.index("--attribute") + 1], 0) if "--attribute" in argv else 1
        open(argv[2], "wb").write(standard_header(attribute))
        return 0
    if len(argv) >= 3 and argv[1] == "make":
        opts = {}
        rest = argv[3:]
        while rest:
            if not rest[0].startswith("--") or len(rest) < 2:
                sys.exit(__doc__)
            opts[rest[0][2:]] = rest[1]
            rest = rest[2:]

        def piece(name):
            return open(opts[name], "rb").read() if name in opts else b""

        pad = 0xFF
        if "pad" in opts:
            pad = None if opts["pad"] == "none" else int(opts["pad"], 0)
        image = make(piece("hdr"), piece("sig"), opts.get("cmdline", "").encode("utf-8"),
                     bytes.fromhex(opts.get("parameter", "")), piece("bootstub"), piece("kernel"), piece("ramdisk"), pad)
        open(argv[2], "wb").write(image)
        return 0
    if len(argv) == 3 and argv[1] == "list":
        u = unpack(open(argv[2], "rb").read())
        print("hdr %d" % len(u["hdr"]))
        print("sig %d" % len(u["sig"]))
        print("cmdline %s" % u["cmdline"].decode("latin-1"))
        print("parameter %s" % u["parameter"].hex())
        print("bootstub %d" % len(u["bootstub"]))
        print("kernel %d" % u["kernel_size"])
        print("ramdisk %d" % u["ramdisk_size"])
        print("end %d" % u["end"])
        return 0
    if len(argv) == 4 and argv[1] == "extract":
        import os
        u = unpack(open(argv[2], "rb").read())
        os.makedirs(argv[3], exist_ok=True)
        for name, key in (("hdr", "hdr"), ("sig", "sig"), ("cmdline.txt", "cmdline"), ("parameter", "parameter"),
                          ("bootstub", "bootstub"), ("kernel", "kernel"), ("ramdisk.cpio.gz", "ramdisk")):
            if key in ("hdr", "sig") and not u[key]:
                continue
            open(os.path.join(argv[3], name), "wb").write(u[key])
        return 0
    if len(argv) == 3 and argv[1] == "check":
        d = open(argv[2], "rb").read()
        u = unpack(d)
        if not u["hdr"]:
            print("no header: nothing to check")
            return 0
        problems = []
        padded = (u["end"] + 511) // 512 * 512
        if le32(d, 48) != padded // 512 - 1:
            problems.append("sectors %d, expected %d" % (le32(d, 48), padded // 512 - 1))
        if d[7] != checksum(d[:56]):
            problems.append("checksum 0x%02x, expected 0x%02x" % (d[7], checksum(d[:56])))
        if not u["sig"] and not d[52] & 1:
            problems.append("an image without a signature has the attribute 0x%02x, not an unsigned one" % d[52])
        for p in problems:
            print(p)
        return 1 if problems else 0
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
