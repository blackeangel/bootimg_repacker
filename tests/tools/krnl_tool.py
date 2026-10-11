#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Rockchip KRNL images for the tests of tests/run_tests.sh, written independently of abr.

usage: krnl_tool.py make <payload> <out> [--crc 0xNNNNNNNN] [--size N]
                                  "KRNL", the payload's size (u32 le), the payload, the CRC (u32 le);
                                  --crc writes that value instead of the right one, --size fills the
                                  file with zeros up to N bytes (a partition dump)
       krnl_tool.py payload <image> <out>
                                  writes the payload of an image; exits 1 (saying why) if the header,
                                  the size or the CRC is not right
       krnl_tool.py crc <file>    the CRC of a file, as 8 hex digits

The CRC is Rockchip's (rkflashtool's rkcrc.h): most significant bit first, start value 0, no final
inversion, polynomial 0x04C10DB7 -- the usual CRC-32 polynomial is 0x04C11DB7: the one digit differs
-- over the payload only.
"""
import sys

POLY = 0x04C10DB7


def make_table():
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ POLY) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
        table.append(c)
    return table


TABLE = make_table()


def rkcrc32(data, crc=0):
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ TABLE[(crc >> 24) ^ b]
    return crc


def main(argv):
    if len(argv) >= 4 and argv[1] == "make":
        payload = open(argv[2], "rb").read()
        crc = rkcrc32(payload)
        size = None
        rest = argv[4:]
        while rest:
            if rest[0] == "--crc":
                crc = int(rest[1], 0)
            elif rest[0] == "--size":
                size = int(rest[1], 0)
            else:
                sys.exit("unknown option " + rest[0])
            rest = rest[2:]
        out = b"KRNL" + len(payload).to_bytes(4, "little") + payload + crc.to_bytes(4, "little")
        if size is not None:
            if size < len(out):
                sys.exit("--size is smaller than the image (%d bytes)" % len(out))
            out += b"\0" * (size - len(out))
        open(argv[3], "wb").write(out)
        return 0
    if len(argv) == 4 and argv[1] == "payload":
        data = open(argv[2], "rb").read()
        if data[:4] != b"KRNL":
            print("%s: no KRNL magic" % argv[2], file=sys.stderr)
            return 1
        n = int.from_bytes(data[4:8], "little")
        if 8 + n + 4 > len(data):
            print("%s: the header declares %d bytes of payload, the file is cut short" % (argv[2], n), file=sys.stderr)
            return 1
        payload = data[8:8 + n]
        stored = int.from_bytes(data[8 + n:12 + n], "little")
        if stored != rkcrc32(payload):
            print("%s: the CRC is 0x%08x, the payload's is 0x%08x" % (argv[2], stored, rkcrc32(payload)), file=sys.stderr)
            return 1
        open(argv[3], "wb").write(payload)
        return 0
    if len(argv) == 3 and argv[1] == "crc":
        print("%08x" % rkcrc32(open(argv[2], "rb").read()))
        return 0
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
