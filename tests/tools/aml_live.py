#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs abr on the multi-tree container of Amlogic ("AML_": the device trees of the boards of one family of SoCs, and the names of the boards each is
for) and judges what comes out with two computations that are written here and share nothing with abr:

  * a writer of the container from the description of the format (an id is its text and spaces, every word of four characters stored reversed; the
    entries; every tree at the next multiple of the page size, padded to the next multiple -- a whole page when it ends on one), and
  * a reader that does what the u-boot of an Amlogic board does with the container (common/aml_dt.c): it reads the three ids of an entry as
    little-endian words, takes the characters of a word from the top byte down, turns the spaces into the end of the text, and finds the tree for
    the name of a board ("gxl_p212_2g": the SoC, the platform, the variant) by the three of them. It never looks at the size of an entry (u-boot
    does not), only at the offset and at the `totalsize` of the tree there.

The trees are made by `dtc` from sources written here (with the property `amlogic-dt-id` that the boards' own trees have). The cases: containers of both
versions, page sizes from 512 to 4096, trees that end on a page, trees that several entries share, ids that are empty and ids of the longest length,
unpacked, packed again byte for byte and read by the u-boot reader; edits (a tree that grows past a page, an id changed, an entry added, a new page
size); what is refused; the container as the `second` of a boot image of header version 0 (the place a TWRP image for an Amlogic box has it); the
container of a real device's image where one is at hand; and damaged containers. One FAIL line for each check that does not hold; exit status 1 when
there is one.

  aml_live.py ABR WORKDIR [REAL_IMAGE]      REAL_IMAGE: a boot image whose second is an AML_ container (TWRP Recovery Amlogic S9xx.img), or "-" / nothing
"""
import hashlib
import importlib.util
import os
import re
import struct
import subprocess
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
from livelib import Live, manifest_get, manifest_set, read, same_bytes, write  # noqa: E402

ABR, WORK = sys.argv[1:3]
REAL = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else None
live = Live(ABR, WORK)
spec = importlib.util.spec_from_file_location("fixtures", os.path.join(TOOLS, "fixtures.py"))
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)


# ------------------------------------------------------------------------------------------------------------------------- the trees
def dtc_compile(text, name):
    """The blob `dtc` makes of a source (the judge of the sources abr unpacks)."""
    path = live.path("src_%s.dts" % name)
    write(path, text.encode())
    r = subprocess.run(["dtc", "-q", "-I", "dts", "-O", "dtb", "-o", "-", path], capture_output=True)
    if r.returncode != 0:
        raise SystemExit("dtc cannot compile %s: %s" % (path, r.stderr.decode(errors="replace")))
    return r.stdout


def dtc_text(blob):
    """The source `dtc` makes of a blob ("" for what is no tree, or for a tree that was not found: the check on it then fails, the run goes on)."""
    if not blob:
        return ""
    r = subprocess.run(["dtc", "-q", "-I", "dtb", "-O", "dts", "-o", "-", "-"], input=blob, capture_output=True)
    return r.stdout.decode() if r.returncode == 0 else ""


def tree_text(board, pad=0, tweak=0):
    props = ""
    if pad:
        # (`tweak` letters more in the name of the property make the tree longer by that many bytes: the cells themselves come in fours)
        props = "\tpadding%s = [%s];\n" % ("x" * tweak, " ".join("%02x" % ((i * 7 + 3) & 255) for i in range(pad)))
    # (the properties of a node come before its subnodes, which `dtc` insists on)
    return ('/dts-v1/;\n/ {\n\tmodel = "Amlogic";\n\tcompatible = "amlogic, Gxbb";\n\tamlogic-dt-id = "%s";\n%s'
            '\tmemory@0 {\n\t\tdevice_type = "memory";\n\t\treg = <0x0 0x0 0x0 0x80000000>;\n\t};\n};\n' % (board, props))


def tree(board, size=0):
    """The blob of a tree for `board`; `size`, when given, is its exact length (a tree that ends on a page, or the lengths of a real container)."""
    if not size:
        return dtc_compile(tree_text(board), "tree_" + board)
    base = len(dtc_compile(tree_text(board, 4), "tree_" + board))
    extra = size - base
    assert extra >= 0, (board, size, base)
    blob = dtc_compile(tree_text(board, 4 + extra // 4 * 4, extra % 4), "tree_" + board)
    assert len(blob) == size, (len(blob), size)
    return blob


# ---------------------------------------------------------------------------------------------------- the container, written again
def enc_id(text, idlen):
    chars = text.encode().ljust(idlen, b" ")
    return b"".join(chars[w:w + 4][::-1] for w in range(0, idlen, 4))


def padded(n, page):
    """dtbTool: up to the next multiple of the page size, and a whole page when `n` is one already."""
    return n + (page - n % page)


def write_container(version, page, entries, trees):
    """`entries`: (soc, platform, variant, index of its tree); `trees`: blobs. The trees are laid out in the order given."""
    idlen = 4 if version == 1 else 16
    table_end = 12 + (3 * idlen + 8) * len(entries)
    first = padded(table_end, page)
    offsets, sizes, at = [], [], first
    for t in trees:
        offsets.append(at)
        sizes.append(padded(len(t), page))
        at += sizes[-1]
    out = b"AML_" + struct.pack("<II", version, len(entries))
    for soc, platform, variant, j in entries:
        out += enc_id(soc, idlen) + enc_id(platform, idlen) + enc_id(variant, idlen) + struct.pack("<II", offsets[j], sizes[j])
    out = out.ljust(first, b"\0")
    for t, size in zip(trees, sizes):
        out += t.ljust(size, b"\0")
    return out


# ----------------------------------------------------------------------------------------------------------------- the u-boot reader
def uboot_entries(data):
    """The container as the u-boot of the board reads it: (version, [(soc, platform, variant, offset, size)])."""
    assert data[:4] == b"AML_", "no AML_ magic"
    version, count = struct.unpack_from("<II", data, 4)
    idlen = {1: 4, 2: 16}[version]
    entries = []
    for i in range(count):
        at = 12 + (3 * idlen + 8) * i
        ids = []
        for k in range(3):
            text = b""
            for w in range(0, idlen, 4):
                (word,) = struct.unpack_from("<I", data, at + k * idlen + w)
                text += bytes([(word >> 24) & 255, (word >> 16) & 255, (word >> 8) & 255, word & 255])
            ids.append(text.replace(b" ", b"\0").split(b"\0")[0].decode("latin-1"))
        offset, size = struct.unpack_from("<II", data, at + 3 * idlen)
        entries.append((ids[0], ids[1], ids[2], offset, size))
    return version, entries


def uboot_tree(data, board):
    """The tree u-boot takes for the board named `board` ("gxl_p212_2g"), or None: the entry whose three ids are the three pieces of the name, the
    `totalsize` of the tree at its offset (the size of the entry is not read)."""
    pieces = board.split("_")
    want = tuple((pieces + ["", ""])[:3])
    _, entries = uboot_entries(data)
    for soc, platform, variant, offset, _size in entries:
        if (soc, platform, variant) == want:
            assert data[offset:offset + 4] == b"\xd0\x0d\xfe\xed", "no tree at offset %d" % offset
            (total,) = struct.unpack_from(">I", data, offset + 4)
            return data[offset:offset + total]
    return None


def layout_problem(data, page):
    """What is wrong with the layout of the container for this page size (the rules of the tool that makes it), or None."""
    version, entries = uboot_entries(data)
    idlen = 4 if version == 1 else 16
    table_end = 12 + (3 * idlen + 8) * len(entries)
    offsets = sorted({(e[3], e[4]) for e in entries})
    expect = padded(table_end, page)
    if any(b != 0 for b in data[table_end:expect]):
        return "the fill behind the table is not zeros"
    for offset, size in offsets:
        if offset != expect:
            return "a tree is at %d, the layout says %d" % (offset, expect)
        (total,) = struct.unpack_from(">I", data, offset + 4)
        if size != padded(total, page):
            return "the entry says %d bytes for a tree of %d (page %d)" % (size, total, page)
        if any(b != 0 for b in data[offset + total:offset + size]):
            return "the padding behind the tree at %d is not zeros" % offset
        expect = offset + size
    if expect != len(data):
        return "the container is %d bytes, the layout says %d" % (len(data), expect)
    return None


def layout_rows(text):
    """The rows of the layout table that `unpack` prints: (name, offset, size, note) of every line "  0x00000800   2048  header   a few words"."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"\s*0x([0-9a-f]+)\s+(\d+)\s+(.+?)(?:\s{2,}(.*))?$", line)
        if m:
            rows.append((m.group(3).strip(), int(m.group(1), 16), int(m.group(2)), m.group(4) or ""))
    return rows


def expected_rows(version, page, entries, trees, base=0):
    """Where the layout of `unpack` has to put the table and the trees of the container that starts at `base` of the file it was unpacked from."""
    idlen = 4 if version == 1 else 16
    table = 12 + (3 * idlen + 8) * len(entries)
    rows = [("AML_ table", base, table)]
    at = padded(table, page)
    for j, t in enumerate(trees):
        rows.append(("device tree %d" % j, base + at, padded(len(t), page)))
        at += padded(len(t), page)
    return rows


def container_rows(text):
    return [(n, o, sz) for n, o, sz, _ in layout_rows(text) if n == "AML_ table" or n.startswith("device tree ")]


# ------------------------------------------------------------------------------------------------------------------------ the cases
def judge(label, data, page, entries, trees):
    """The container `data` (made by abr) is laid out by the rules, and u-boot finds for every board the tree that the entries and `trees` say."""
    problem = layout_problem(data, page)
    live.check(problem is None, "%s: the layout follows the rules of the tool (page %d)" % (label, page), problem)
    wrong = []
    for soc, platform, variant, j in entries:
        name = "_".join((soc, platform, variant))  # ("g12b_w400_": the name of a board that has no variant, cut at its underscores)
        if uboot_tree(data, name) != trees[j]:
            wrong.append(name)
    live.check(not wrong, "%s: u-boot finds the right tree for every board" % label, wrong)


def unpack(label, src, out_name):
    folder = live.fresh(out_name)
    rc, text = live.run("unpack", "-i", src, "-o", folder)
    live.check(rc == 0 and "byte-for-byte" in text, "%s: unpack, and the repack is identical" % label, text[-300:])
    return folder, text


def pack(label, folder, out_name, ok=True):
    out = live.fresh(out_name)
    rc, text = live.run("pack", "-i", folder, "-o", out)
    live.check((rc == 0) == ok, "%s: pack %s" % (label, "works" if ok else "is refused"), text[-400:])
    return out, rc, text


def edit_tree_source(folder, key, extra):
    """The source of the tree `key` ("dtb0") with a property added to the root."""
    path = os.path.join(folder, manifest_get(folder, key + "_file"))
    with open(path, encoding="utf-8") as f:
        text = f.read()
    new, n = re.subn(r"(\n/ \{\n)", r"\1" + extra.replace("\\", "\\\\") + "\n", text, count=1)
    assert n == 1, "no root node in " + path
    write(path, new.encode())
    return path


GROW = "\tabr-grown = <" + " ".join("0x%x" % (0x1000 + i) for i in range(900)) + ">;"  # 3600 bytes more


def board_names(entries):
    return ["_".join(p for p in (s, p, v) if p) for s, p, v, _ in entries]


SETS = {}
with live.section("0. the trees and the containers"):
    t_real = [tree("gxl_p212_1g", 36670), tree("gxl_p212_2g", 37224)]
    SETS["real_like"] = (2, 2048, [("gxl", "p212", "1g", 0), ("gxl", "p212", "2g", 1)], t_real)
    t_small = [tree("gxl_p20_1g"), tree("gxm_q20_2g")]
    SETS["v1_small"] = (1, 512, [("gxl", "p20", "1g", 0), ("gxm", "q20", "2g", 1), ("gxl", "p20", "2g", 0)], t_small)
    t_shared = [tree("g12a_u200_2g"), tree("g12b_w400")]
    SETS["v2_shared_4k"] = (2, 4096, [("g12a", "u200", "2g", 0), ("g12a", "u200", "4g", 0), ("g12b", "w400", "", 1), ("sm1", "ac200", "1g", 1),
                                      ("abcdefghijklmnop", "ABCDEFGHIJKLMNOP", "0123456789~!@#$%", 0)], t_shared)
    t_exact = [tree("axg_s400_1g", 512), tree("axg_s400_2g", 1024)]
    SETS["v2_exact_pages"] = (2, 512, [("axg", "s400", "1g", 0), ("axg", "s400", "2g", 1)], t_exact)
    t_v1 = [tree("gxl_p21_2g", 1000)]
    SETS["v1_one_tree"] = (1, 1024, [("gxl", "p21", "2g", 0)], t_v1)
    live.check(all(len(t) in (512, 1024) for t in t_exact), "the trees of the set with exact pages are as long as a page and two pages")

CONTAINERS = {}
for name, (version, page, entries, trees) in sorted(SETS.items()):
    CONTAINERS[name] = write_container(version, page, entries, trees)
    write(live.path(name + ".aml"), CONTAINERS[name])

# ------------------------------------------------------------------------------------------ 1. unpacked, packed again, read by u-boot
with live.section("1. containers unpacked and packed again"):
    for name, (version, page, entries, trees) in sorted(SETS.items()):
        src = live.path(name + ".aml")
        # the writer and the reader agree with each other (a check of this driver)
        judge(name + " as written here", CONTAINERS[name], page, entries, trees)
        rc, text = live.run("info", "-i", src)
        live.check(rc == 0 and re.search(r"^format: aml$", text, re.M) and
                   ("container:   version %d, page size %d, %d %s, %d device tree" % (version, page, len(entries), "entry" if len(entries) == 1 else "entries", len(trees))) in text,
                   "%s: info names the format, the version, the page size and the numbers of entries and trees" % name, text[:500])
        # (a line for every entry, with the whole name of its board -- the layout below also names the boards, which must not stand in for these lines)
        lines = [l.strip() for l in text.splitlines() if re.match(r"\s*\[\d+\] ", l)]
        live.check(lines == ["[%d] %s -> device tree %d" % (i, "_".join((e[0], e[1], e[2])), e[3]) for i, e in enumerate(entries)],
                   "%s: info has a line for every entry, with the name of its board and its tree" % name, lines)
        u, text = unpack(name, src, name + ".u")
        live.check(container_rows(text) == expected_rows(version, page, entries, trees), "%s: the layout of unpack has the table and the trees where they are" % name, container_rows(text))
        live.check(manifest_get(u, "type") == "aml" and manifest_get(u, "version") == str(version) and manifest_get(u, "page_size") == str(page) and
                   manifest_get(u, "entry_count") == str(len(entries)) and manifest_get(u, "dtb_count") == str(len(trees)),
                   "%s: the manifest has the version, the page size and the counts" % name)
        for i, (soc, platform, variant, j) in enumerate(entries):
            live.check(manifest_get(u, "entry%d_soc" % i) == soc and manifest_get(u, "entry%d_platform" % i) == platform and
                       manifest_get(u, "entry%d_variant" % i) == variant and manifest_get(u, "entry%d_dtb" % i) == str(j),
                       "%s: entry %d is in the manifest as the container has it" % (name, i))
        live.check(all(os.path.isfile(os.path.join(u, "dtb%d.dts" % j)) for j in range(len(trees))), "%s: every tree is a source file" % name)
        back, rc, text = pack(name, u, name + ".back")
        live.check(rc == 0 and same_bytes(back, src), "%s: an untouched pack is the container" % name, text[-200:])
        if rc == 0:
            judge(name + " packed by abr", read(back), page, entries, trees)

# ----------------------------------------------------------------------------------------------------------------------- 2. edits
with live.section("2. edits"):
    version, page, entries, trees = SETS["real_like"]
    src = live.path("real_like.aml")
    # a tree that grows past a page: the next tree moves on by the pages it needs, and u-boot finds both
    u, _ = unpack("edit: grow", src, "edit_grow.u")
    edit_tree_source(u, "dtb0", GROW)
    out, rc, text = pack("edit: a grown tree", u, "edit_grow.aml")
    if rc == 0:
        data = read(out)
        grown = uboot_tree(data, "gxl_p212_1g")
        live.check(grown is not None and len(grown) > len(trees[0]) + 3000, "edit: the first tree is the grown one")
        live.check(grown is not None and "abr-grown" in dtc_text(grown), "edit: the first tree has the property that was added")
        before = dtc_text(trees[0]).splitlines()
        after = [l for l in dtc_text(grown).splitlines() if "abr-grown" not in l]
        live.check(before == after, "edit: the grown tree is the old one and the property that was added, nothing else")
        live.check(uboot_tree(data, "gxl_p212_2g") == trees[1], "edit: the second tree is as it was")
        judge("edit: a grown tree", data, page, entries, [grown, trees[1]])
        live.check(len(data) > len(read(src)) and len(data) % page == 0, "edit: the container is longer and ends on a page", len(data))
    # an id changed in the manifest
    u, _ = unpack("edit: id", src, "edit_id.u")
    manifest_set(u, "entry1_variant", "4g")
    out, rc, text = pack("edit: an id changed", u, "edit_id.aml")
    if rc == 0:
        data = read(out)
        live.check(uboot_tree(data, "gxl_p212_4g") == trees[1] and uboot_tree(data, "gxl_p212_2g") is None, "edit: u-boot finds the tree by the new id, and no longer by the old")
        live.check(len(data) == len(read(src)), "edit: the container is as long as it was")
    # an entry added, for the tree that the first entry is for; the table is a few bytes longer but still inside its page
    u, _ = unpack("edit: entry", src, "edit_entry.u")
    manifest_set(u, "entry_count", "3")
    manifest_set(u, "entry2_soc", "gxm")
    manifest_set(u, "entry2_platform", "q200")
    manifest_set(u, "entry2_variant", "")
    manifest_set(u, "entry2_dtb", "0")
    out, rc, text = pack("edit: an entry added", u, "edit_entry.aml")
    if rc == 0:
        data = read(out)
        live.check(uboot_tree(data, "gxm_q200") == trees[0] and uboot_tree(data, "gxl_p212_2g") == trees[1], "edit: the new entry finds the first tree, the old ones are as they were")
        judge("edit: an entry added", data, page, entries + [("gxm", "q200", "", 0)], trees)
        live.check(len(data) == len(read(src)), "edit: the container is as long as it was (the table still fits its page)")
    # the page size of the manifest: the container is laid out again
    u, _ = unpack("edit: page", src, "edit_page.u")
    manifest_set(u, "page_size", "4096")
    out, rc, text = pack("edit: page_size=4096", u, "edit_page.aml")
    if rc == 0:
        data = read(out)
        judge("edit: page_size=4096", data, 4096, entries, trees)
        live.check(len(data) % 4096 == 0 and data[4096:4096 + len(trees[0])] == trees[0], "edit: the first tree is at the second page now")
    # a version change: the ids are cut to the four characters of version 1 (only what fits), or refused
    u, _ = unpack("edit: version", live.path("v1_small.aml"), "edit_version.u")
    manifest_set(u, "version", "2")
    out, rc, text = pack("edit: version 2 for a container that had version 1", u, "edit_version.aml")
    if rc == 0:
        data = read(out)
        live.check(uboot_entries(data)[0] == 2 and uboot_tree(data, "gxl_p20_1g") == SETS["v1_small"][3][0], "edit: the container is of version 2 now, with the same boards")
        judge("edit: version 2", data, 512, SETS["v1_small"][2], SETS["v1_small"][3])
    # an edited source that is no longer a tree of a size abr can put in: the new source replaces the blob, and the file may be a blob too
    u, _ = unpack("edit: blob", src, "edit_blob.u")
    blob_path = os.path.join(u, "dtb1.dtb")
    write(blob_path, tree("gxl_p212_2g", 2222))
    manifest_set(u, "dtb1_file", "dtb1.dtb")
    out, rc, text = pack("edit: a tree given as a blob", u, "edit_blob.aml")
    if rc == 0:
        live.check(uboot_tree(read(out), "gxl_p212_2g") == read(blob_path), "edit: the blob is the tree in the container")

# --------------------------------------------------------------------------------------------------------------------- 3. refusals
with live.section("3. what is refused"):
    version, page, entries, trees = SETS["real_like"]
    src = live.path("real_like.aml")

    def refused(label, change, want, ok_text=None):
        u = live.fresh("refuse.u")
        rc, text = live.run("unpack", "-i", src, "-o", u)
        if not live.check(rc == 0, "%s: (the unpack for the case)" % label, text[-200:]):
            return
        change(u)
        out, rc, text = pack(label, u, "refuse.aml", ok=False)
        live.check(want in text, "%s: the message says %r" % (label, want), text[-400:])
        live.check(not os.path.exists(out), "%s: no container is left behind" % label)

    refused("an id with a space", lambda u: manifest_set(u, "entry0_soc", '"g xl"'), "space")
    refused("an id longer than 16", lambda u: manifest_set(u, "entry0_platform", "x" * 17), "17 characters")
    refused("an id with a byte that is no character", lambda u: manifest_set(u, "entry0_variant", '"a\\x01b"'), "printable")
    refused("a version that is none", lambda u: manifest_set(u, "version", "3"), "version 1 or 2")
    refused("a page size of 0", lambda u: manifest_set(u, "page_size", "0"), "page size")
    refused("a page size beyond 1 MiB", lambda u: manifest_set(u, "page_size", str(2 << 20)), "page size")
    refused("an entry for a tree there is not", lambda u: manifest_set(u, "entry1_dtb", "2"), "device tree 2")
    refused("a tree that no entry is for", lambda u: manifest_set(u, "entry1_dtb", "0"), "for no entry")
    refused("no entries", lambda u: manifest_set(u, "entry_count", "0"), "at least one entry")
    refused("an entry without its soc", lambda u: manifest_set(u, "entry0_soc", None), "entry0_soc")
    refused("an entry without its variant", lambda u: manifest_set(u, "entry1_variant", None), "entry1_variant")
    refused("an entry without its tree", lambda u: manifest_set(u, "entry0_dtb", None), "entry0_dtb")
    refused("a tree without its file", lambda u: manifest_set(u, "dtb1_file", None), "dtb1_file")
    refused("no version", lambda u: manifest_set(u, "version", None), "version")
    refused("a tree that is none", lambda u: write(os.path.join(u, manifest_get(u, "dtb0_file")), b"this is not a device tree source\n"), "dtb0.dts")

    # containers abr cannot put back: unpack says so and leaves nothing behind
    def unpack_refused(label, data, want, info=True):
        path = live.fresh("refuse_unpack.aml")
        write(path, data)
        out = live.fresh("refuse_unpack.u")
        rc, text = live.run("unpack", "-i", path, "-o", out)
        live.check(rc != 0 and want in text, "%s: unpack refuses, and says %r" % (label, want), text[-400:])
        live.check(not os.path.exists(out), "%s: no folder is left behind" % label)
        rc, text = live.run("info", "-i", path)
        if info:
            live.check(rc == 0 and "unpack:      no" in text, "%s: info says the container cannot be unpacked" % label, text[-300:])
        else:
            live.check("format: unknown" in text, "%s: info does not take it for a container" % label, text[-300:])

    good = CONTAINERS["real_like"]
    unpack_refused("padding that is not zeros", good[:700] + b"\x01" + good[701:], "is not zeros")
    behind = 0x800 + len(trees[0]) + 10  # (in the zeros that fill the first tree's last page)
    unpack_refused("padding behind a tree that is not zeros", good[:behind] + b"\x01" + good[behind + 1:], "is not zeros")
    unpack_refused("a gap of a page before the first tree (the entries still say where the trees were)", good[:2048] + bytes(2048) + good[2048:], "no device tree at offset")
    # (the entries of that container say where the trees were; here they are changed to say they moved by a page)
    shifted = bytearray(good[:2048] + bytes(2048) + good[2048:])
    for i in range(2):
        at = 12 + 56 * i + 48
        struct.pack_into("<I", shifted, at, struct.unpack_from("<I", shifted, at)[0] + 2048)
    unpack_refused("a gap of a page before the first tree, in the offsets too", bytes(shifted), "not laid out")
    swapped = bytearray(good)
    struct.pack_into("<I", swapped, 12 + 52, len(trees[0]) + 30)  # a size that holds the tree and is not the tree with its padding
    unpack_refused("a size that is not the padded size of its tree", bytes(swapped), "not laid out")
    small = bytearray(good)
    struct.pack_into("<I", small, 12 + 52, 2048)  # a size that does not even hold the tree
    unpack_refused("a size that is smaller than the tree", bytes(small), "says in its own header")
    two = bytearray(good)
    struct.pack_into("<I", two, 12 + 56 + 48, struct.unpack_from("<I", good, 12 + 48)[0])
    unpack_refused("two entries for one offset with two sizes", bytes(two), "two sizes")
    spaced = bytearray(good)
    spaced[12:16] = bytes([ord("l"), ord(" "), ord("x"), ord("g")])  # an id of "g xl": the reader would cut it at the space
    unpack_refused("an id with a space inside", bytes(spaced), "space")
    zeros = bytearray(good)
    zeros[28:44] = bytes(16)  # the platform of the first entry, NULs where spaces belong
    unpack_refused("an id padded with NULs", bytes(zeros), "printable")
    unpack_refused("a header that is cut short", good[:11], "", info=False)
    unpack_refused("entries that run past the end of the file", good[:100], "says it has 2 entries")
    unpack_refused("a count of zero", good[:8] + struct.pack("<I", 0) + good[12:], "no entries")
    unpack_refused("a tree that is not at its offset", good[:2048] + b"\x00" * 64 + good[2048 + 64:], "no device tree at offset")

# ---------------------------------------------------------------------------------------------------- 4. the container in a boot image
with live.section("4. the container in a boot image"):
    version, page, entries, trees = SETS["real_like"]
    container = CONTAINERS["real_like"]
    kernel, ramdisk = fx.blob(30000), fx.gz(fx.blob(20000))
    img = live.fresh("boot_second.img")
    write(img, fx.boot_v012(0, kernel, ramdisk, second=container, cmdline="console=ttyS0", id_bytes=fx.boot_id(hashlib.sha1, 0, kernel, ramdisk, container)))
    rc, text = live.run("info", "-i", img)
    live.check(rc == 0 and "Amlogic device tree container" in text and "version 2" in text and "2 entries" in text, "boot with a container: info names the container", text[:700])
    u, text = unpack("boot with a container", img, "boot_second.u")
    second_at = 2048 * (1 + -(-len(kernel) // 2048) + -(-len(ramdisk) // 2048))
    live.check(container_rows(text) == expected_rows(version, page, entries, trees, base=second_at),
               "boot with a container: the layout of unpack has the table and the trees where they are in the image", container_rows(text))
    live.check(("second", second_at, len(container)) in [(n, o, sz) for n, o, sz, _ in layout_rows(text)], "boot with a container: the layout has the second where it is, as long as the container")
    live.check("AML_" in text and "gxl_p212_1g" in text and "gxl_p212_2g" in text, "boot with a container: the layout names the container, its trees and their boards", text[-700:])
    live.check(manifest_get(u, "second_format") == "aml" and manifest_get(u, "second_version") == "2" and manifest_get(u, "second_page_size") == "2048" and
               manifest_get(u, "second_entry_count") == "2" and manifest_get(u, "second_entry1_variant") == "2g", "boot with a container: the manifest has the container")
    live.check(manifest_get(u, "second_file") is None and os.path.isdir(os.path.join(u, "second")),
               "boot with a container: there is no file `second`, the folder `second/` has the trees")
    live.check(all(os.path.isfile(os.path.join(u, "second", "dtb%d.dts" % j)) for j in range(2)), "boot with a container: the trees are sources in second/")
    back, rc, text = pack("boot with a container", u, "boot_second.back")
    live.check(rc == 0 and same_bytes(back, img), "boot with a container: an untouched repack is the image", text[-300:])
    # a tree that grows: the container is made again, the size in the header and the id follow, the kernel and the ramdisk are what they were
    edit_tree_source(u, "second_dtb1", GROW)
    new, rc, text = pack("boot with a container: a grown tree", u, "boot_second.edited.img")
    if rc == 0:
        d = read(new)
        ksz, _, rsz, _, ssz, _, _, pg, _ = struct.unpack_from("<9I", d, 8)
        second_at = pg * (1 + -(-ksz // pg) + -(-rsz // pg))
        second = d[second_at:second_at + ssz]
        live.check(ssz > len(container) and ssz % 2048 == 0, "boot with a container: the size of the second in the header is the new container's", "second_size %d" % ssz)
        live.check(d[pg:pg + ksz] == kernel, "boot with a container: the kernel is as it was")
        problem = layout_problem(second, 2048) if second[:4] == b"AML_" else "not a container"
        live.check(problem is None, "boot with a container: the second in the image is a container laid out by the rules", problem)
        grown = uboot_tree(second, "gxl_p212_2g")
        live.check(grown is not None and "abr-grown" in dtc_text(grown) and uboot_tree(second, "gxl_p212_1g") == trees[0], "boot with a container: u-boot finds the grown tree for the second board, the first is as it was")
        live.check(d[576:596] == fx.boot_id(hashlib.sha1, 0, kernel, ramdisk, second)[:20], "boot with a container: the id is the SHA-1 over the parts, the container included, made again")
    # the container with bytes behind it inside second_size: it stays a file (abr puts back the bytes, not a container it would write itself)
    for label, tail in (("a few bytes behind the container", b"\xa5" * 100), ("zeros behind the container", bytes(2048))):
        odd = container + tail
        img2 = live.fresh("boot_second_tail.img")
        write(img2, fx.boot_v012(0, kernel, ramdisk, second=odd, cmdline="x", id_bytes=fx.boot_id(hashlib.sha1, 0, kernel, ramdisk, odd)))
        u2 = live.fresh("boot_second_tail.u")
        rc, text = live.run("unpack", "-i", img2, "-o", u2)
        live.check(rc == 0 and "byte-for-byte" in text and "kept as the file second" in text, "boot with %s: unpack keeps the second as a file, says so, and repacks identically" % label, text[-500:])
        live.check(manifest_get(u2, "second_file") == "second" and manifest_get(u2, "second_format") is None, "boot with %s: the manifest has the file" % label)
    # a container abr cannot write again, as the second: kept as the file, the image repacks identically
    odd = container[:700] + b"\x01" + container[701:]
    img3 = live.fresh("boot_second_odd.img")
    write(img3, fx.boot_v012(0, kernel, ramdisk, second=odd, cmdline="x", id_bytes=fx.boot_id(hashlib.sha1, 0, kernel, ramdisk, odd)))
    u3 = live.fresh("boot_second_odd.u")
    rc, text = live.run("unpack", "-i", img3, "-o", u3)
    live.check(rc == 0 and "kept as the file second" in text and "is not zeros" in text, "boot with a container abr cannot write again: unpack keeps the second as a file and says why", text[-500:])
    back3, rc, text = pack("boot with a container abr cannot write again", u3, "boot_second_odd.back")
    live.check(rc == 0 and same_bytes(back3, img3), "boot with a container abr cannot write again: an untouched repack is the image")
    # both a file and a container in the manifest: abr cannot know which is meant
    u4, _ = unpack("boot with a container (both)", img, "boot_second_both.u")
    manifest_set(u4, "second_file", "second_x")
    write(os.path.join(u4, "second_x"), b"x")
    _, rc, text = pack("boot with second_file and second_format=aml", u4, "boot_second_both.img", ok=False)
    live.check("second_file" in text and "second_format" in text, "boot with second_file and second_format=aml: the message names both keys", text[-300:])
    u5, _ = unpack("boot with a container (format)", img, "boot_second_fmt.u")
    manifest_set(u5, "second_format", "qcdt")
    _, rc, text = pack("boot with second_format=qcdt", u5, "boot_second_fmt.img", ok=False)
    live.check("second_format" in text and "aml" in text, "boot with second_format=qcdt: the message says what abr knows", text[-300:])

# ---------------------------------------------------------------------------------------------------------------- 5. a real device's container
with live.section("5. a real device's container"):
    if REAL and os.path.isfile(REAL):
        d = read(REAL)
        ksz, _, rsz, _, ssz, _, _, pg, _ = struct.unpack_from("<9I", d, 8)
        second_at = pg * (1 + -(-ksz // pg) + -(-rsz // pg))
        real = d[second_at:second_at + ssz]  # (read from the header here, not by abr)
        live.check(real[:4] == b"AML_", "the real image: its second is an AML_ container (read from the header, not by abr)")
        version, ents = uboot_entries(real)
        live.check(layout_problem(real, pg) is None, "the real container follows the layout rules (version %d, %d entries)" % (version, len(ents)), layout_problem(real, pg))
        names = board_names([(e[0], e[1], e[2], 0) for e in ents])
        live.check(all(uboot_tree(real, n) is not None for n in names), "u-boot finds a tree for every board of the real container (%s)" % ", ".join(names))
        cut = live.fresh("real.aml")
        write(cut, real)
        u, _ = unpack("the real container alone", cut, "real.aml.u")
        back, rc, text = pack("the real container alone", u, "real.aml.back")
        live.check(rc == 0 and same_bytes(back, cut), "the real container alone: an untouched repack is the container")
        u, text = unpack("the real image", REAL, "real.img.u")
        distinct = sorted({(e[3], e[4]) for e in ents})
        live.check(container_rows(text) == [("AML_ table", second_at, 12 + (3 * (4 if version == 1 else 16) + 8) * len(ents))] +
                   [("device tree %d" % j, second_at + o, sz) for j, (o, sz) in enumerate(distinct)],
                   "the real image: the layout of unpack has the table and the trees where the entries of the container say", container_rows(text))
        live.check(manifest_get(u, "second_format") == "aml" and manifest_get(u, "second_entry_count") == str(len(ents)), "the real image: the manifest has the container with its entries")
        back, rc, text = pack("the real image", u, "real.img.back")
        live.check(rc == 0 and same_bytes(back, REAL), "the real image: an untouched repack is the image")
        # the second tree grows past its page: the container is made again, u-boot finds both trees, the rest of the image is moved on whole
        n_trees = int(manifest_get(u, "second_dtb_count") or 0)
        if live.check(n_trees == len({(e[3]) for e in ents}), "the real image: as many trees as the container has", n_trees):
            edit_tree_source(u, "second_dtb%d" % (n_trees - 1), GROW)
            new, rc, text = pack("the real image with its last tree grown", u, "real.img.edited")
            if rc == 0:
                n = read(new)
                ksz2, _, rsz2, _, ssz2, _, _, pg2, _ = struct.unpack_from("<9I", n, 8)
                at2 = pg2 * (1 + -(-ksz2 // pg2) + -(-rsz2 // pg2))
                second2 = n[at2:at2 + ssz2]
                live.check(layout_problem(second2, pg2) is None, "the real image edited: the container follows the layout rules", layout_problem(second2, pg2))
                _, ents2 = uboot_entries(second2)
                live.check([e[:3] for e in ents2] == [e[:3] for e in ents], "the real image edited: the entries are what they were")
                last = names[-1]
                live.check("abr-grown" in dtc_text(uboot_tree(second2, last)) and uboot_tree(second2, names[0]) == uboot_tree(real, names[0]),
                           "the real image edited: the last tree is the grown one, the first is as it was")
                live.check(n[pg2:pg2 + ksz2] == d[pg:pg + ksz] and ssz2 > ssz, "the real image edited: the kernel is as it was, the second is longer")
    else:
        print("note: no real container was tried (no ABR_REAL_IMAGES, or no TWRP Recovery Amlogic S9xx.img in it)")

# ---------------------------------------------------------------------------------------------------------------- 6. damaged containers
with live.section("6. damaged containers"):
    runs = 0
    for name, data in sorted(CONTAINERS.items()):
        runs += live.damaged("aml_" + name, data, seed=20261122, head=300)
    if REAL and os.path.isfile(REAL):
        d = read(REAL)
        ksz, _, rsz, _, ssz, _, _, pg, _ = struct.unpack_from("<9I", d, 8)
        at = pg * (1 + -(-ksz // pg) + -(-rsz // pg))
        runs += live.damaged("aml_real", d[at:at + ssz], seed=20261123, head=300)
print("damaged-container runs: %d" % runs)
sys.exit(live.finish("aml"))
