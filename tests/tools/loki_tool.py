#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""An independent reader of LOKI images (Dan Rosenberg's loki_tool, https://github.com/djrbliss/loki), written
from the layout and not from abr's code, and the synthetic bootloader images the real `loki_tool patch` needs.

    loki_tool.py targets                         the synthetic targets
    loki_tool.py aboot <target> <out>            a bootloader image the real loki_tool accepts as <target>
    loki_tool.py patch <target> boot|recovery <aboot> <plain> <out>   what `loki_tool patch` makes of <plain>
    loki_tool.py list <lok>                      one line: the layout of a LOKI image
    loki_tool.py unlok <lok> <plain>             the boot image as it was (the dt is not padded, as loki_tool's)
    loki_tool.py check <lok> <plain> [aboot]     does <lok> hold <plain>, the way loki_tool patch makes it?

An aboot made here is random bytes with the function loki_tool looks for (one of its byte patterns) at the
address that gives the target's check_sigs, and a base address at byte 12: all that `loki_tool patch` reads of
it. The image is no bootloader; it only has what the tool takes from one (the block of its code that is put
behind the ramdisk).

Exit status 0 = fine, 1 = mismatch (details on stderr), 2 = usage.
"""
import random
import struct
import sys
import zlib
from pathlib import Path

PATTERNS = {  # loki.h
    1: b"\xf0\xb5\x8f\xb0\x06\x46\xf0\xf7",
    2: b"\xf0\xb5\x8f\xb0\x07\x46\xf0\xf7",
    3: b"\x2d\xe9\xf0\x41\x86\xb0\xf1\xf7",
    4: b"\x2d\xe9\xf0\x4f\xad\xf5\xc6\x6d",
    5: b"\x2d\xe9\xf0\x4f\xad\xf5\x21\x7d",
    6: b"\x2d\xe9\xf0\x4f\xf3\xb0\x05\x46",
}

# name -> (check_sigs, aboot base, pattern, size of the file). The values are those of entries of loki_tool's own
# table of targets, so that `loki_tool patch` takes the image for that target; the base is where the bootloader
# is loaded (the word at byte 12 of the image, less 0x28).
TARGETS = {
    "a": (0x88E0FF98, 0x88DFFFD8, 1, 0x20000),     # a 512-byte block, the patch code 8 bytes into it
    "b": (0x88F1079C, 0x88EFFFD8, 4, 0x30000),     # a block of one page, the patch code 12 bytes into it
    "c": (0x0F8132AC, 0x0F7FFFD8, 6, 0x30000),     # a block of one page (the second search of the tool)
    "d": (0x4010FE18, 0x400FFFD8, 2, 0x30000),     # a block of one page; loki_tool unlok guesses its size wrong
    "e": (0x88E0F5C0, 0x88DFFFD8, 3, 0x20000),     # a 512-byte block, the patch code at its very start
    "f": (0x88F11084, 0x88EFFFD8, 5, 0x30000),     # a block of one page, the patch code 4 bytes into it
}

# What the tool's table has for each of them besides check_sigs: the build it names, the address that goes into
# the patch code (hdr), and whether the block is a page (lg) instead of 512 bytes.
EXTRA = {
    "a": ("JDQ39.I337UCUAMDB or JDQ39.I337UCUAMDL", 0x88F3BAFC, 0),
    "b": ("D52010c", 0x88F64508, 1),
    "c": ("D80010d", 0x0F906440, 1),
    "d": ("LS840ZVK", 0x40194198, 1),
    "e": ("IMM76D.I200VRALH2", 0x88ED32E0, 0),
    "f": ("E98010g or E98810b", 0x88F54418, 1),
}

# The 56 bytes of code of the patch (PATCH in loki.h, up to its two words).
CODE = bytes.fromhex(
    "feb50d4dd5f88804ab689842" "12d0d5f890640a4cd5f88c74" "07f580570fce0fc4103ffbdc"
    "d5f888040449d5f88c24a860" "6961" "2a61" "0020" "febd")
assert len(CODE) == 56


def fail(msg):
    print("loki_tool: " + msg, file=sys.stderr)
    sys.exit(1)


def make_aboot(target):
    check_sigs, base, pat, size = TARGETS[target]
    rnd = random.Random(zlib.crc32(("aboot-" + target).encode()))
    d = bytearray(rnd.randbytes(size))
    # the random bytes must not hold another place that looks like the function
    for p in PATTERNS.values():
        at = d.find(p)
        while at >= 0:
            d[at] ^= 0xFF
            at = d.find(p)
    struct.pack_into("<I", d, 12, base + 0x28)
    at = check_sigs - base
    d[at:at + 8] = PATTERNS[pat]
    return bytes(d)


def u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def patch(target, recovery, aboot, plain):
    """What `loki_tool patch` writes for a boot image without a second stage: the header page with the three
    fields changed and the LOKI header in it, the padded kernel and ramdisk, a block of the bootloader's code
    with the patch code laid over its start, and the device tree (dt_size bytes, no padding)."""
    check_sigs, base, _pat, _size = TARGETS[target]
    build, hdr, lg = EXTRA[target]
    if u32(aboot, 12) != base + 0x28:
        fail("this bootloader image is not the synthetic one of target " + target)
    page = u32(plain, 36)
    pad = lambda n: -(-n // page) * page
    ks, ka, rs, ra = u32(plain, 8), u32(plain, 12), u32(plain, 16), u32(plain, 20)
    word10 = u32(plain, 40)
    dt_size = word10 if word10 > 8 else 0
    offset = check_sigs & 0xF
    fake = page if lg else 0x200
    h = bytearray(plain[:page])
    struct.pack_into("<III", h, 8, pad(ks) + rs, ka, page if lg else 0)  # kernel_size, kernel_addr, ramdisk_size
    struct.pack_into("<I", h, 20, check_sigs - offset)                    # ramdisk_addr
    h[0x400:0x404] = b"LOKI"
    struct.pack_into("<I", h, 0x404, recovery)
    h[0x408:0x488] = build.encode().ljust(128, b"\0")
    struct.pack_into("<III", h, 0x488, ks, rs, (ka + pad(ks)) & 0xFFFFFFFF)
    block = bytearray(aboot[check_sigs - base - offset:][:fake])
    block[offset:offset + 65] = CODE + struct.pack("<II", hdr, ra) + b"\0"
    body = plain[page:page + pad(ks) + pad(rs)].ljust(pad(ks) + pad(rs), b"\0")
    dt = plain[page + pad(ks) + pad(rs):][:dt_size].ljust(dt_size, b"\0")
    return bytes(h) + body + bytes(block) + dt


class Lok:
    """The fields of a LOKI image; fails when it is not laid out the way loki_tool makes one."""

    def __init__(self, d):
        if d[:8] != b"ANDROID!" or d[0x400:0x404] != b"LOKI":
            fail("not a LOKI image")
        self.d = d
        (self.ks, self.ka, self.rs, self.ra, self.ss, _sa, _ta, self.page, self.word10) = struct.unpack_from("<9I", d, 8)
        (self.recovery,) = struct.unpack_from("<I", d, 0x404)
        self.build = d[0x408:0x488]
        self.orig_k, self.orig_r, self.hdr_ra = struct.unpack_from("<3I", d, 0x488)
        if self.ss:
            fail("a second stage")
        if 0 < self.word10 <= 8:
            fail("a header of version %d" % self.word10)
        self.dt_size = self.word10
        pad = lambda n: -(-n // self.page) * self.page
        self.pk, self.pr = pad(self.orig_k), pad(self.orig_r)
        if self.ks != self.pk + self.orig_r:
            fail("kernel_size %d is not the padded kernel %d + the ramdisk %d" % (self.ks, self.pk, self.orig_r))
        # the size of the block: 512 bytes, or a page (where the ramdisk size field is a page)
        if self.rs == 0:
            self.fake = 0x200
        elif self.rs == self.page:
            self.fake = self.page
        else:
            fail("ramdisk_size field %d" % self.rs)
        self.base = self.page + self.pk + self.pr
        at = d.find(CODE, self.base, self.base + 16 + len(CODE))
        if at < 0:
            fail("the patch code is not in the first 16 bytes behind the ramdisk")
        self.patch_at = at - self.base
        (self.addr_word, self.orig_ra) = struct.unpack_from("<2I", d, at + len(CODE))
        self.core = self.base + self.fake + self.dt_size
        if len(d) < self.core:
            fail("cut short: %d bytes, %d needed" % (len(d), self.core))

    def plain(self):
        """What loki_tool unlok writes, with the block's size read from the header."""
        h = bytearray(self.d[:self.page])
        struct.pack_into("<I", h, 8, self.orig_k)
        struct.pack_into("<I", h, 16, self.orig_r)
        struct.pack_into("<I", h, 20, self.orig_ra)
        h[0x400:0x400 + 148] = bytes(148)
        return (bytes(h) + self.d[self.page:self.base] + self.d[self.base + self.fake:self.core])


def cmd_list(path):
    k = Lok(Path(path).read_bytes())
    print("%s: page %d, kernel %d, ramdisk %d, dt %d, block %d at %d, patch at +%d, recovery %d, build %r, tail %d" % (
        path, k.page, k.orig_k, k.orig_r, k.dt_size, k.fake, k.base, k.patch_at, k.recovery,
        k.build.split(b"\0")[0].decode("latin-1"), len(k.d) - k.core))


def cmd_unlok(path, out):
    Path(out).write_bytes(Lok(Path(path).read_bytes()).plain())


def cmd_check(path, plain_path, aboot_path=None):
    """The LOKI image is what loki_tool patch makes of the plain image: the header's fields, the kernel and the
    ramdisk, the block (bootloader code with the patch code in it), the device tree."""
    k = Lok(Path(path).read_bytes())
    p = Path(plain_path).read_bytes()
    d = k.d
    page = k.page
    pks, pka, prs, pra, pss, _, _, ppage, pword = struct.unpack_from("<9I", p, 8)
    if ppage != page:
        fail("page size differs")
    if (k.orig_k, k.orig_r) != (pks, prs):
        fail("the LOKI header has other original sizes than the plain image")
    if k.orig_ra != pra:
        fail("the patch code carries ramdisk address 0x%x, the plain image has 0x%x" % (k.orig_ra, pra))
    if k.ka != pka:
        fail("kernel_addr changed")
    if k.hdr_ra != (pka + k.pk) & 0xFFFFFFFF:
        fail("the LOKI header's ramdisk_addr 0x%x is not kernel_addr + padded kernel" % k.hdr_ra)
    if k.recovery not in (0, 1):
        fail("recovery word %d" % k.recovery)
    # the header page differs from the plain one in the three fields and the LOKI header only
    a, b = bytearray(d[:page]), bytearray(p[:page])
    for off in (8, 16, 20):
        a[off:off + 4] = b[off:off + 4] = b"\0\0\0\0"
    a[0x400:0x400 + 148] = bytes(148)
    if a != b:
        fail("the header page differs from the plain image's outside kernel_size, ramdisk_size, ramdisk_addr, the LOKI header")
    pad = lambda n: -(-n // page) * page
    if d[page:k.base] != p[page:page + k.pk + k.pr].ljust(k.pk + k.pr, b"\0"):
        fail("the padded kernel and ramdisk differ from the plain image's")
    dt = p[page + pad(pks) + pad(prs):][:k.dt_size]
    if d[k.base + k.fake:k.core] != dt:
        fail("the device tree differs from the plain image's")
    if k.patch_at >= 16:
        fail("the patch code is not in the first 16 bytes of the block")
    # the block: the bootloader's code but for the patch code and the byte behind it (loki_tool writes a NUL there)
    if aboot_path:
        a = Path(aboot_path).read_bytes()
        check_sigs = None
        for t, (cs, base, _pat, _sz) in TARGETS.items():
            if struct.unpack_from("<I", a, 12)[0] == base + 0x28 and (cs & ~0xF) == k.ra:
                check_sigs = cs
        if check_sigs is None:
            fail("no synthetic target has the ramdisk_addr 0x%x of this image" % k.ra)
        base = struct.unpack_from("<I", a, 12)[0] - 0x28
        want = bytearray(a[check_sigs - base - (check_sigs & 0xF):][:k.fake])
        want[k.patch_at:k.patch_at + 65] = d[k.base + k.patch_at:k.base + k.patch_at + 65]
        if bytes(want) != d[k.base:k.base + k.fake]:
            fail("the block is not the bootloader's code with the patch code laid over it")
        if k.patch_at != check_sigs & 0xF:
            fail("the patch code is at +%d, check_sigs & 15 is %d" % (k.patch_at, check_sigs & 0xF))
    print("loki check ok: %s" % path)


def main(argv):
    try:
        if argv[1] == "targets" and len(argv) == 2:
            for t, (cs, base, pat, size) in TARGETS.items():
                print("%s check_sigs=0x%08x base=0x%08x pattern=%d size=0x%x" % (t, cs, base, pat, size))
            return
        if argv[1] == "aboot" and len(argv) == 4:
            Path(argv[3]).write_bytes(make_aboot(argv[2]))
            return
        if argv[1] == "patch" and len(argv) == 7 and argv[3] in ("boot", "recovery"):
            Path(argv[6]).write_bytes(patch(argv[2], 1 if argv[3] == "recovery" else 0, Path(argv[4]).read_bytes(),
                                            Path(argv[5]).read_bytes()))
            return
        if argv[1] == "list" and len(argv) == 3:
            return cmd_list(argv[2])
        if argv[1] == "unlok" and len(argv) == 4:
            return cmd_unlok(argv[2], argv[3])
        if argv[1] == "check" and len(argv) in (4, 5):
            return cmd_check(argv[2], argv[3], argv[4] if len(argv) == 5 else None)
    except IndexError:
        pass
    print(__doc__, file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main(sys.argv)
