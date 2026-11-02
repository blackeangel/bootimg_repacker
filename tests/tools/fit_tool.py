#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""A reader of U-Boot FIT images (flattened device trees) for tests/run_tests.sh, written independently of abr's own.

usage: fit_tool.py dump <file>                      every property of the tree: "path:name len=N value=<hex or sha256> pad=<hex>"
       fit_tool.py get <file> <path> <property>     the value of one property, as hex (nothing else on the line)
       fit_tool.py zero <in> <out> <name>...        a copy with the values of the named properties set to zeros: `timestamp`
                                                    (wherever it is), `signature-1:value` (the parent's name, a colon, the name) or
                                                    `+hashed-nodes` (a plus: the bytes behind the value, which a tool may leave as they
                                                    were in memory)
       fit_tool.py verify <file>                    the data of every image where the tree says it is (in the tree: `data`; behind
                                                    it: `data-size` with `data-offset`, counted from the end of the tree rounded up to
                                                    4, or with `data-position`, counted from the start of the file) against every hash
                                                    node (crc32, md5, sha1, sha256, sha384, sha512); one line per hash, status 1
                                                    when one is wrong or an image is not inside the file
       fit_tool.py images <file>                    one line per image: name, size, where its data is

The tree is read the way libfdt reads it: the header, the structure block (tokens BEGIN_NODE 1, END_NODE 2, PROP 3, NOP 4, END 9),
the strings block. The bytes behind a value, up to a multiple of 4, are kept apart (`pad`): mkimage leaves what was there behind the
`hashed-nodes` of a signature, and a test that says "the same FIT" has to see them.
"""
import hashlib
import struct
import sys
import zlib

FDT_MAGIC = 0xD00DFEED


class Prop:
    def __init__(self, path, name, voff, length, parent):
        self.path = path
        self.name = name
        self.voff = voff
        self.length = length
        self.parent = parent  # the name of the node the property is in ("" for the root)

    @property
    def pad_len(self):
        return (-self.length) % 4


def read_tree(d):
    """Returns (header, props) where props are Prop records in the order of the structure block."""
    if len(d) < 40:
        raise ValueError("shorter than a header")
    magic, total, off_struct, off_str, off_rsv, version, last_comp, boot_cpu, size_str, size_struct = struct.unpack(">10I", d[:40])
    if magic != FDT_MAGIC:
        raise ValueError("not a flattened device tree")
    if version < 17:
        raise ValueError("version %d: this reader takes 17" % version)
    if total > len(d):
        raise ValueError("totalsize %d is more than the file (%d)" % (total, len(d)))
    pos, end = off_struct, off_struct + size_struct
    stack, props = [], []
    while pos < end:
        (tag,) = struct.unpack(">I", d[pos : pos + 4])
        pos += 4
        if tag == 1:
            e = d.index(b"\0", pos)
            stack.append(d[pos:e].decode("utf-8", "replace"))
            pos = (e + 1 + 3) & ~3
        elif tag == 2:
            stack.pop()
        elif tag == 3:
            length, nameoff = struct.unpack(">II", d[pos : pos + 8])
            pos += 8
            e = d.index(b"\0", off_str + nameoff)
            name = d[off_str + nameoff : e].decode("utf-8", "replace")
            path = "/" + "/".join(stack[1:])
            props.append(Prop(path, name, pos, length, stack[-1]))
            pos = (pos + length + 3) & ~3
        elif tag == 4:
            pass
        elif tag == 9:
            break
        else:
            raise ValueError("token %#x at %d" % (tag, pos - 4))
    return {"total": total, "version": version}, props


def value_of(d, p):
    return d[p.voff : p.voff + p.length]


def find(props, path, name):
    for p in props:
        if p.path == path and p.name == name:
            return p
    return None


def cstring(b):
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


def u32(b):
    return struct.unpack(">I", b)[0] if len(b) == 4 else None


def cmd_dump(argv):
    d = open(argv[0], "rb").read()
    _, props = read_tree(d)
    for p in props:
        v = value_of(d, p)
        shown = v.hex() if len(v) <= 64 else "sha256:" + hashlib.sha256(v).hexdigest()
        pad = d[p.voff + p.length : p.voff + p.length + p.pad_len]
        print("%s:%s len=%d value=%s pad=%s" % (p.path, p.name, p.length, shown, pad.hex()))


def cmd_get(argv):
    d = open(argv[0], "rb").read()
    _, props = read_tree(d)
    p = find(props, argv[1], argv[2])
    if p is None:
        sys.exit("no property %s of %s" % (argv[2], argv[1]))
    print(value_of(d, p).hex())


def cmd_zero(argv):
    d = bytearray(open(argv[0], "rb").read())
    _, props = read_tree(bytes(d))
    names = argv[2:]
    for p in props:
        if p.name in names or (p.parent + ":" + p.name) in names:
            d[p.voff : p.voff + p.length] = bytes(p.length)
        if ("+" + p.name) in names:
            d[p.voff + p.length : p.voff + p.length + p.pad_len] = bytes(p.pad_len)
    open(argv[1], "wb").write(bytes(d))


def images_of(d):
    """[(name, data or None, where)] for the children of /images; raises ValueError for an image that is not in the file."""
    header, props = read_tree(d)
    names = []
    for p in props:
        if p.path.startswith("/images/") and p.path.count("/") == 2 and p.path[len("/images/") :] not in names:
            names.append(p.path[len("/images/") :])
    # (a node without any property is not seen here; a FIT image has some)
    base = (header["total"] + 3) & ~3
    out = []
    for n in names:
        path = "/images/" + n
        data_p = find(props, path, "data")
        size_p = find(props, path, "data-size")
        off_p = find(props, path, "data-offset")
        pos_p = find(props, path, "data-position")
        if data_p is not None:
            out.append((n, value_of(d, data_p), "inline"))
        elif size_p is not None and off_p is not None:
            size, off = u32(value_of(d, size_p)), u32(value_of(d, off_p))
            if size is None or off is None or base + off + size > len(d):
                raise ValueError("%s: data-offset %s + data-size %s is not inside the file" % (n, off, size))
            out.append((n, d[base + off : base + off + size], "offset %d" % off))
        elif size_p is not None and pos_p is not None:
            size, pos = u32(value_of(d, size_p)), u32(value_of(d, pos_p))
            if size is None or pos is None or pos + size > len(d):
                raise ValueError("%s: data-position %s + data-size %s is not inside the file" % (n, pos, size))
            out.append((n, d[pos : pos + size], "position %d" % pos))
        else:
            out.append((n, None, "none"))
    return out, props


def digest(algo, data):
    if algo == "crc32":
        return struct.pack(">I", zlib.crc32(data) & 0xFFFFFFFF)
    if algo in ("md5", "sha1", "sha256", "sha384", "sha512"):
        return hashlib.new(algo, data).digest()
    return None


def cmd_images(argv):
    d = open(argv[0], "rb").read()
    images, _ = images_of(d)
    for n, data, where in images:
        print("%s %s %s" % (n, "-" if data is None else len(data), where))


def cmd_verify(argv):
    d = open(argv[0], "rb").read()
    try:
        images, props = images_of(d)
    except ValueError as e:
        print("BAD: %s" % e)
        sys.exit(1)
    bad = 0
    for n, data, where in images:
        if data is None:
            continue
        hashes = []
        for p in props:
            if p.path.startswith("/images/%s/hash" % n) and p.path.count("/") == 3 and p.name == "algo":
                hashes.append(p.path.split("/")[3])
        for h in hashes:
            algo_p = find(props, "/images/%s/%s" % (n, h), "algo")
            value_p = find(props, "/images/%s/%s" % (n, h), "value")
            algo = cstring(value_of(d, algo_p))
            want = digest(algo, data)
            if want is None:
                print("%s %s %s skipped" % (n, h, algo))
                continue
            if value_p is None:
                print("%s %s %s MISSING (no value)" % (n, h, algo))
                bad += 1
            elif value_of(d, value_p) != want:
                print("%s %s %s MISMATCH" % (n, h, algo))
                bad += 1
            else:
                print("%s %s %s ok" % (n, h, algo))
    sys.exit(1 if bad else 0)


COMMANDS = {"dump": (cmd_dump, 1), "get": (cmd_get, 3), "zero": (cmd_zero, 3), "verify": (cmd_verify, 1), "images": (cmd_images, 1)}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.exit(__doc__)
    fn, need = COMMANDS[sys.argv[1]]
    if len(sys.argv) - 2 < need:
        sys.exit(__doc__)
    try:
        fn(sys.argv[2:])
    except (ValueError, struct.error, IndexError, OSError) as e:
        sys.exit("fit_tool: %s" % e)


if __name__ == "__main__":
    main()
