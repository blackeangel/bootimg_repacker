#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Judge of a QCDT table (the device tree table of Qualcomm boot images): reads it by the description of dtbTool's format, not by abr's code, and
checks what dtbTool guarantees: the sorted entries, the trees one behind the other at multiples of the page size, zeros after each tree.

  qcdt_check.py TABLE [PAGESIZE]     (default 2048). Prints what the table holds and `ok`; any broken rule is an AssertionError (exit status 1).

As a module: read(path_or_bytes) -> (version, entries, bytes), judge(path_or_bytes, page, sort=True) -> the same after the rules were checked.
"""
import struct
import sys


def read(source):
    d = source if isinstance(source, (bytes, bytearray)) else open(source, "rb").read()
    assert d[:4] == b"QCDT", "magic"
    ver, n = struct.unpack_from("<II", d, 4)
    words = {1: 5, 2: 6, 3: 10}[ver]
    ents = []
    for i in range(n):
        w = struct.unpack_from("<%dI" % words, d, 12 + 4 * words * i)
        if ver == 1:
            chip, plat, rev, off, size = w
            sub = 0
            pm = (0,) * 4
        elif ver == 2:
            chip, plat, sub, rev, off, size = w
            pm = (0,) * 4
        else:
            chip, plat, sub, rev, p0, p1, p2, p3, off, size = w
            pm = (p0, p1, p2, p3)
        ents.append(dict(chipset=chip, platform=plat, subtype=sub, revision=rev, pmic=pm, offset=off, size=size))
    end_word = struct.unpack_from("<I", d, 12 + 4 * words * n)[0]
    assert end_word == 0, "the word that ends the table"
    for e in ents:
        blob = d[e["offset"]:e["offset"] + e["size"]]
        assert blob[:4] == b"\xd0\x0d\xfe\xed", "tree magic at %#x" % e["offset"]
        total = struct.unpack_from(">I", blob, 4)[0]
        assert all(b == 0 for b in blob[total:]), "padding of the tree at %#x is zeros" % e["offset"]
        e["tree"] = bytes(blob[:total])
    return ver, ents, bytes(d)


def judge(source, page=2048, sort=True):
    ver, ents, d = read(source)
    if sort:
        keys = [(e["chipset"], e["platform"], e["subtype"], e["revision"]) for e in ents]
        assert keys == sorted(keys), "sorted as dtbTool sorts"
    assert all(e["offset"] % page == 0 and e["size"] % page == 0 for e in ents), "page multiples"
    table_end = 12 + 4 * {1: 5, 2: 6, 3: 10}[ver] * len(ents) + 4
    offs = sorted({(e["offset"], e["size"]) for e in ents})
    cursor = (table_end + page - 1) // page * page
    if table_end % page == 0:
        cursor = table_end + page  # a table that ends on a page gets a whole page of zeros behind it, as dtbTool does
    assert not any(d[table_end:cursor]), "zeros between the table and the first tree"
    for o, s in offs:
        assert o == cursor, "trees one behind the other (the one at %#x should be at %#x)" % (o, cursor)
        assert s >= page and s % page == 0, "size of the tree at %#x" % o
        assert s > len(next(e["tree"] for e in ents if e["offset"] == o)), "a tree that ends on a page gets a whole page of zeros"
        cursor = o + s
    assert cursor == len(d), "the table ends where the last tree's padding ends"
    return ver, ents, d


if __name__ == "__main__":
    page = int(sys.argv[2]) if len(sys.argv) > 2 else 2048
    ver, ents, d = judge(sys.argv[1], page)
    print("version", ver, "entries", len(ents), "size", len(d))
    print("ok")
