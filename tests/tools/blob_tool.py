#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""ASUS "MSM-RADIO-UPDATE" blobs for the tests of tests/run_tests.sh, written independently of abr.

usage: blob_tool.py make <out> [--secure DATALEN:SIGLEN] [--tail FILE] NAME[@VERSION]=FILE ...
                                  a blob of the partitions, in that order (NAME is a word, or 0x and 8 hex
                                  digits for four arbitrary bytes); --secure puts the 28-byte
                                  "-SIGNED-BY-SIGNBLOB-" header in front (DATALEN "auto" = the length of
                                  the blob proper), --tail appends the file (a signature) behind the data
       blob_tool.py list <blob>   what is in it (secure header, partitions: name offset size version, tail);
                                  exits 1, saying why, if the layout is not the one blobpack writes
       blob_tool.py extract <blob> <dir>
                                  writes <dir>/<index>_<name> for every partition, <dir>/tail for the tail

The format is AndroidRoot's BlobTools (shared/blob.h, blobpack.cpp, blobunpack.cpp): a 60-byte header (the magic
"MSM-RADIO-UPDATE", version 0x00010000, its own size 60, the table's offset 60, the number of partitions, seven
zero words), the table (name[4], offset, size, version per partition; offsets count from the start of the blob
proper), the data of the partitions one after the other. A signed blob has "-SIGNED-BY-SIGNBLOB-", datalen and
siglen (28 bytes) in front of all that.
"""
import os
import struct
import sys

MAGIC = b"MSM-RADIO-UPDATE"
SECURE = b"-SIGNED-BY-SIGNBLOB-"


def make(parts, secure=None, tail=b""):
    """parts: [(name bytes, version, data)]; secure: None or (datalen or None for auto, siglen)."""
    n = len(parts)
    header = MAGIC + struct.pack("<IIII", 0x00010000, 60, 60, n) + b"\0" * 28
    assert len(header) == 60
    offset = 60 + 16 * n
    table = b""
    for name, version, data in parts:
        table += name.ljust(4, b"\0")[:4] + struct.pack("<III", offset, len(data), version)
        offset += len(data)
    blob = header + table + b"".join(data for _, _, data in parts)
    if secure is None:
        return blob + tail
    datalen, siglen = secure
    if datalen is None:
        datalen = len(blob)
    return SECURE + struct.pack("<II", datalen, siglen) + blob + tail


def parse(data):
    """Returns (secure or None, [(name, offset, size, version, bytes)], tail); raises ValueError."""
    base = 0
    secure = None
    if data[:20] == SECURE:
        secure = struct.unpack("<II", data[20:28])
        base = 28
    if data[base:base + 16] != MAGIC:
        raise ValueError("no blob header")
    version, size, part_offset, count = struct.unpack("<IIII", data[base + 16:base + 32])
    if (size, part_offset) != (60, 60):
        raise ValueError("header size %d, table at %d" % (size, part_offset))
    parts = []
    expect = 60 + 16 * count
    for i in range(count):
        entry = data[base + 60 + 16 * i:base + 76 + 16 * i]
        if len(entry) != 16:
            raise ValueError("table cut short")
        name = entry[:4]
        offset, psize, pversion = struct.unpack("<III", entry[4:])
        if offset != expect:
            raise ValueError("partition %d at %d, expected %d" % (i, offset, expect))
        body = data[base + offset:base + offset + psize]
        if len(body) != psize:
            raise ValueError("partition %d cut short" % i)
        parts.append((name, offset, psize, pversion, body))
        expect += psize
    return secure, parts, data[base + expect:], expect


def main(argv):
    if len(argv) >= 3 and argv[1] == "make":
        secure = None
        tail = b""
        parts = []
        rest = argv[3:]
        while rest:
            if rest[0] == "--secure":
                datalen, siglen = rest[1].split(":")
                secure = (None if datalen == "auto" else int(datalen, 0), int(siglen, 0))
                rest = rest[2:]
            elif rest[0] == "--tail":
                tail = open(rest[1], "rb").read()
                rest = rest[2:]
            else:
                spec, path = rest[0].split("=", 1)
                name, _, version = spec.partition("@")
                raw = bytes.fromhex(name[2:]) if name.startswith("0x") else name.encode("latin-1")
                parts.append((raw, int(version or "1", 0), open(path, "rb").read()))
                rest = rest[1:]
        open(argv[2], "wb").write(make(parts, secure, tail))
        return 0
    if len(argv) == 3 and argv[1] == "list":
        try:
            secure, parts, tail, blob_len = parse(open(argv[2], "rb").read())
        except ValueError as e:
            print("%s: %s" % (argv[2], e), file=sys.stderr)
            return 1
        if secure:
            print("secure datalen=%d siglen=%d" % secure)
        print("blob %d" % blob_len)
        for i, (name, offset, size, version, _) in enumerate(parts):
            print("part %d %s %d %d %d" % (i, name.rstrip(b"\0").decode("latin-1"), offset, size, version))
        print("tail %d" % len(tail))
        return 0
    if len(argv) == 4 and argv[1] == "extract":
        secure, parts, tail, _ = parse(open(argv[2], "rb").read())
        os.makedirs(argv[3], exist_ok=True)
        for i, (name, _, _, _, body) in enumerate(parts):
            open(os.path.join(argv[3], "%d_%s" % (i, name.rstrip(b"\0").decode("latin-1"))), "wb").write(body)
        open(os.path.join(argv[3], "tail"), "wb").write(tail)
        return 0
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
