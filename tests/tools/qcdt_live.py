#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs abr on Qualcomm device tree tables (QCDT) and judges what comes out with qcdt_check.py (dtbTool's layout rules, read from the bytes) and with a
second computation, written here, of what dtbTool makes of a set of trees (the boards each tree is for, the sorting, the version, the order of the
trees). The trees are made by `dtc` from sources written here. The cases: a folder of trees packed (versions 1, 2 and 3, page sizes, a version that
is forced, trees without a board, trees in subfolders, a tree that is exactly a page long), a table unpacked and edited (a tree replaced by a bigger one,
an entry added, the page size changed), what is refused, a table inside a boot image of header version 0 (the `dt` of Qualcomm's old boot images), a
table cut out of a real device's boot image, and damaged tables. One FAIL line for each check that does not hold; exit status 1 when there is one.

  qcdt_live.py ABR WORKDIR [REAL_IMAGE]      REAL_IMAGE: a boot image whose dt is a QCDT (boot_lk2nd.img), or "-" / nothing
"""
import hashlib
import importlib.util
import os
import shutil
import struct
import subprocess
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
import qcdt_check  # noqa: E402
from livelib import Live, manifest_get, manifest_set, read, same_bytes, write  # noqa: E402

ABR, WORK = sys.argv[1:3]
REAL = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else None
live = Live(ABR, WORK)
spec = importlib.util.spec_from_file_location("fixtures", os.path.join(TOOLS, "fixtures.py"))
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)


# ------------------------------------------------------------------------------------------------------ the real dtbTool, where it is at hand
# ABR_DTBTOOL: the dtbTool of the Code Aurora Forum (LineageOS/android_device_qcom_common), built from its source by .github/scripts/build_oracles.sh. It
# is a judge of this driver and nothing of it is in abr. It needs `dtc` (it decompiles every tree to read the boards from the text).
DTBTOOL = os.environ.get("ABR_DTBTOOL", "")
HAVE_DTBTOOL = bool(DTBTOOL) and os.path.isfile(DTBTOOL) and os.access(DTBTOOL, os.X_OK) and shutil.which("dtc") is not None
DTBTOOL_RUNS = 0


def same_as_dtbtool(name, src, table, page=2048, force=0):
    """The table abr made of the folder `src` is the table the real dtbTool makes of it (same page size, same forced version), byte for byte."""
    global DTBTOOL_RUNS
    if not HAVE_DTBTOOL:
        return
    ref = live.fresh(name.replace(" ", "_").replace("/", "_") + ".dtbtool.img")
    # (dtbTool puts the name of a file right behind the path it is given, without a separator: the folder has to end in one)
    cmd = [DTBTOOL, "-s", str(page)] + (["-%d" % force] if force else []) + ["-o", ref, os.path.join(src, "")]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=120)
    if not live.check(r.returncode == 0 and os.path.isfile(ref), "%s: the real dtbTool makes a table of the folder" % name, r.stdout + r.stderr):
        return
    DTBTOOL_RUNS += 1
    theirs = read(ref)
    first = next((i for i, (a, b) in enumerate(zip(table, theirs)) if a != b), min(len(table), len(theirs)))
    live.check(table == theirs, "%s: abr's table is the table of the real dtbTool, byte for byte" % name,
               "abr %d bytes, dtbTool %d bytes, first difference at %d" % (len(table), len(theirs), first))


# ----------------------------------------------------------------------------------------------------------------- the trees
def dtc(src, dst):
    r = subprocess.run(["dtc", "-I", "dts", "-O", "dtb", "-o", dst, src], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("dtc failed on %s: %s" % (src, r.stderr))
    return read(dst)


class Tree:
    """A device tree for some boards: `msm`, `board` and `pmic` are lists of groups of cells (see the header of include/abr/qcdt.hpp)."""

    def __init__(self, name, msm, board=None, pmic=None, pad=0, tweak=0):
        self.name, self.msm, self.board, self.pmic, self.pad, self.tweak = name, msm, board, pmic, pad, tweak
        self.dtb = b""

    def text(self):
        cells = lambda groups: " ".join("0x%x" % c for g in groups for c in g)
        props = ["qcom,msm-id = <%s>;" % cells(self.msm)]
        if self.board:
            props.append("qcom,board-id = <%s>;" % cells(self.board))
        if self.pmic:
            props.append("qcom,pmic-id = <%s>;" % cells(self.pmic))
        if self.pad:
            # (`tweak` letters more in the name of the property make the tree longer by that many bytes: the cells themselves come in fours)
            props.append("padding%s = [%s];" % ("x" * self.tweak, " ".join("%02x" % ((i * 7 + 3) & 255) for i in range(self.pad))))
        return '/dts-v1/;\n/ {\n\tmodel = "%s";\n\tcompatible = "qcom,test";\n\t%s\n};\n' % (self.name, "\n\t".join(props))

    def version(self):
        return 3 if self.pmic else 2 if self.board else 1

    def chips(self):
        """Every board this tree is for: (chipset, platform, subtype, revision, pmic)."""
        out = []
        for m in self.msm:
            for b in self.board or [None]:
                for p in self.pmic or [None]:
                    chip, plat, sub, rev = (m[0], m[1], 0, m[2]) if self.version() == 1 else (m[0], b[0], b[1], m[1])
                    out.append((chip, plat, sub, rev, tuple(p) if p else (0, 0, 0, 0)))
        return out

    def make(self, folder, filename=None):
        src = os.path.join(WORK, "src_" + self.name + ".dts")
        write(src, self.text().encode())
        self.dtb = dtc(src, os.path.join(folder, filename or (self.name + ".dtb")))
        return self


def exact_page_tree(name, msm, page):
    """A tree whose size is exactly one page (dtbTool gives it a whole page of zeros behind it, then)."""
    measured = len(Tree(name, msm, pad=4).make(WORK).dtb)  # one more byte of the name of the padding property is one more byte of the tree
    extra = page - measured
    assert extra >= 0
    tree = Tree(name, msm, pad=4 + extra // 4 * 4, tweak=extra % 4).make(WORK)
    assert len(tree.dtb) == page, (len(tree.dtb), page)
    return tree


def expected(trees, version=0):
    """(version, entries, trees in the order of their first entry) as dtbTool would make them: an entry for every board of every tree, sorted by chipset,
    platform, subtype and revision (equal ones in the order of the sources), the words a version has no place for left out."""
    v = version or max(t.version() for t in trees)
    ents = []
    for t in trees:
        for chip, plat, sub, rev, pmic in t.chips():
            ents.append((chip, plat, sub if v >= 2 else 0, rev, pmic if v >= 3 else (0, 0, 0, 0), t))
    ents.sort(key=lambda e: e[:4])
    order = []
    for e in ents:
        if e[5] not in order:
            order.append(e[5])
    return v, ents, order


def judge(label, table, trees, version=0, page=2048):
    """The table against the layout rules and against what the trees say. -> the entries the judge read, or None."""
    try:
        ver, ents, _ = qcdt_check.judge(table, page)
    except AssertionError as e:
        live.check(False, "%s: the layout rules of dtbTool: %s" % (label, e))
        return None
    except Exception as e:  # noqa: BLE001  (a table the judge cannot even read)
        live.check(False, "%s: the judge cannot read it: %r" % (label, e))
        return None
    want_v, want, order = expected(trees, version)
    live.check(ver == want_v, "%s: the table is version %d (the trees need %d)" % (label, ver, want_v))
    got = sorted((e["chipset"], e["platform"], e["subtype"], e["revision"], e["pmic"], e["tree"]) for e in ents)
    exp = sorted((c, p, s, r, pm, t.dtb) for c, p, s, r, pm, t in want)
    live.check(got == exp, "%s: the entries are the boards of the trees, each with its own tree" % label,
               "%d entries, expected %d" % (len(got), len(exp)))
    seen = []
    for e in sorted(ents, key=lambda e: e["offset"]):
        if e["tree"] not in seen:
            seen.append(e["tree"])
    live.check(seen == [t.dtb for t in order], "%s: the trees are in the order of the first entry that has them" % label)
    live.check(len({e["offset"] for e in ents}) == len(order), "%s: a tree for several boards is in the table once" % label)
    return ents


def folder(name, trees, extra=None):
    d = live.fresh(name)
    os.makedirs(d)
    for t in trees:
        t.make(d)
    for rel, data in (extra or {}).items():
        os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
        write(os.path.join(d, rel), data)
    return d


def recipe(d, **keys):
    write(os.path.join(d, "manifest.txt"), ("type=qcdt\n" + "".join("%s=%s\n" % kv for kv in keys.items())).encode())


# ------------------------------------------------------------------------------------------------------ 1. a folder of trees
with live.section('1. a folder of trees'):
    SETS = {
        "v1": [Tree("a", [(0x100, 8, 0x10000)]), Tree("b", [(0x101, 8, 0), (0x102, 9, 0x10001)]), Tree("c", [(0xFF, 7, 0)], pad=3000)],
        "v2": [Tree("a", [(0x1A0, 0x10000)], board=[(8, 1)]), Tree("b", [(0x1A0, 0x10000), (0x1A1, 0x10000)], board=[(8, 2), (9, 3)]),
               Tree("c", [(0x150, 0)], board=[(0x20, 4)], pad=100)],
        "v3": [Tree("a", [(0x1A0, 0x10000)], board=[(8, 1)], pmic=[(0x11, 0x22, 0x33, 0x44)]),
               Tree("b", [(0x1B0, 0)], board=[(8, 1), (9, 1)], pmic=[(1, 2, 3, 4), (5, 6, 7, 8)]),
               Tree("c", [(0x1A0, 0x10000)], board=[(7, 1)])],
    }
    tables = {}
    for name, trees in SETS.items():
        src = folder("set_" + name, trees)
        out = live.fresh("set_%s.img" % name)
        rc, text = live.run("pack", "-i", src, "-o", out)
        if not live.check(rc == 0, "%s: pack of a folder of trees" % name, text[-400:]):
            continue
        live.check(("version %d" % SETS[name][0].version() if name == "v1" else "version") in text and "device trees" in text, "%s: pack says what it made" % name, text[-300:])
        tables[name] = read(out)
        judge("%s folder" % name, tables[name], trees)
        same_as_dtbtool("%s folder" % name, src, tables[name])
        again = live.fresh("set_%s.again.img" % name)
        live.run("pack", "-i", src, "-o", again)
        live.check(same_bytes(out, again), "%s: the same folder gives the same table" % name)

        # the table unpacks and an untouched repack is the table
        rc, text = live.run("info", "-i", out)
        live.check(rc == 0 and "format: qcdt" in text and ("version %d" % max(t.version() for t in trees)) in text and "0x" in text, "%s: info" % name, text[:300])
        u = live.fresh("set_%s.u" % name)
        rc, text = live.run("unpack", "-i", out, "-o", u)
        live.check(rc == 0 and "byte-for-byte" in text, "%s: unpack says the repack is identical" % name, text[-300:])
        back = live.fresh("set_%s.back.img" % name)
        rc, text = live.run("pack", "-i", u, "-o", back)
        live.check(rc == 0 and same_bytes(back, out), "%s: an untouched repack is the table, byte for byte" % name, text[-300:])

    # the output name when none is given: next to the folder
    src = folder("set_default", SETS["v1"])
    rc, text = live.run("pack", "-i", src)
    live.check(rc == 0 and os.path.isfile(src + ".img") and read(src + ".img") == tables.get("v1"), "pack without -o writes <folder>.img next to the folder", text[-300:])

    # page sizes: a table is padded with the page size of the boot image it goes into
    for page in (512, 4096, 8192):
        src = folder("page%d" % page, SETS["v2"])
        recipe(src, page_size=page)
        out = live.fresh("page%d.img" % page)
        rc, text = live.run("pack", "-i", src, "-o", out)
        if live.check(rc == 0 and ("page size %d" % page) in text, "page_size=%d: pack" % page, text[-300:]):
            judge("page size %d" % page, read(out), SETS["v2"], page=page)
            same_as_dtbtool("page size %d" % page, src, read(out), page=page)

    # a version that is forced: what the older table has no word for is left out
    for name, version in (("v3", 2), ("v3", 1), ("v2", 1)):
        src = folder("force_%s_%d" % (name, version), SETS[name])
        recipe(src, table_version=version)
        out = live.fresh("force_%s_%d.img" % (name, version))
        rc, text = live.run("pack", "-i", src, "-o", out)
        if live.check(rc == 0, "table_version=%d for the trees of %s" % (version, name), text[-300:]):
            judge("%s trees as version %d" % (name, version), read(out), SETS[name], version=version)
            live.check(("version %d" % version) in text, "pack says the table is version %d" % version, text[-300:])
            if version >= 2:
                same_as_dtbtool("%s trees as version %d" % (name, version), src, read(out), force=version)

    # a version that is newer than the trees need (dtbTool: --force-v2, --force-v3): the words the trees do not have are zeros
    for name, version in (("v1", 2), ("v1", 3), ("v2", 3)):
        src = folder("up_%s_%d" % (name, version), SETS[name])
        recipe(src, table_version=version)
        out = live.fresh("up_%s_%d.img" % (name, version))
        rc, text = live.run("pack", "-i", src, "-o", out)
        if live.check(rc == 0, "table_version=%d for the trees of %s (newer than they need)" % (version, name), text[-300:]):
            judge("%s trees as version %d (newer than they need)" % (name, version), read(out), SETS[name], version=version)
            same_as_dtbtool("%s trees as version %d (newer than they need)" % (name, version), src, read(out), force=version)

    # a tree that is exactly one page long gets a whole page of zeros behind it, and so does a table whose entries end on a page
    page_tree = exact_page_tree("exact", [(0x200, 1, 0)], 2048)
    src = live.fresh("exact")
    os.makedirs(src)
    write(os.path.join(src, "exact.dtb"), page_tree.dtb)
    out = live.fresh("exact.img")
    rc, text = live.run("pack", "-i", src, "-o", out)
    if live.check(rc == 0, "a tree of exactly one page: pack", text[-300:]):
        judge("a tree of exactly one page", read(out), [page_tree])
        same_as_dtbtool("a tree of exactly one page", src, read(out))
        live.check(len(read(out)) == 2048 + 2048 + 2048, "a tree of exactly one page: the table, the tree and a whole page of zeros", str(len(read(out))))

    # trees in subfolders are found, those in a folder whose name starts with a dot are not, and a file that does not end in .dtb is not a tree
    trees = [Tree("p", [(0x110, 1, 0)]), Tree("q", [(0x111, 1, 0)]), Tree("r", [(0x112, 1, 0)])]
    src = live.fresh("subfolders")
    for rel, t in (("p.dtb", trees[0]), (os.path.join("sub", "deeper", "q.dtb"), trees[1])):
        os.makedirs(os.path.dirname(os.path.join(src, rel)), exist_ok=True)
        t.make(os.path.dirname(os.path.join(src, rel)), os.path.basename(rel))
    os.makedirs(os.path.join(src, ".hidden"))
    trees[2].make(os.path.join(src, ".hidden"))
    write(os.path.join(src, "notes.txt"), b"not a tree\n")
    write(os.path.join(src, "x.dtbo"), b"not a tree either\n")
    out = live.fresh("subfolders.img")
    rc, text = live.run("pack", "-i", src, "-o", out)
    if live.check(rc == 0, "subfolders: pack", text[-300:]):
        judge("trees in subfolders (not the one in .hidden)", read(out), trees[:2])

    # a tree that is not for a board (no qcom,msm-id) is left out, with a note; a folder of such trees is refused
    plain = os.path.join(WORK, "plain.dts")
    write(plain, b'/dts-v1/;\n/ { model = "plain"; };\n')
    src = folder("noboard", SETS["v1"][:2])
    write(os.path.join(src, "plain.dtb"), dtc(plain, os.path.join(WORK, "plain.dtb")))
    out = live.fresh("noboard.img")
    rc, text = live.run("pack", "-i", src, "-o", out)
    if live.check(rc == 0 and "plain.dtb" in text and "qcom,msm-id" in text, "a tree without qcom,msm-id is left out, and the note names it and the property", text[-400:]):
        judge("the trees that are for a board", read(out), SETS["v1"][:2])
    src = live.fresh("onlyplain")
    os.makedirs(src)
    write(os.path.join(src, "plain.dtb"), read(os.path.join(WORK, "plain.dtb")))
    out = live.fresh("onlyplain.img")
    rc, text = live.run("pack", "-i", src, "-o", out)
    live.check(rc != 0 and not os.path.exists(out) and "qcom,msm-id" in text, "trees none of which is for a board are refused", text[-300:])

# ---------------------------------------------------------------------------------------------------------------- 2. refused
with live.section('2. refused'):
    def refused(label, src, want, *, out_name="refused.img"):
        out = live.fresh(out_name)
        rc, text = live.run("pack", "-i", src, "-o", out)
        live.check(rc != 0 and not os.path.exists(out) and want in text and "terminate called" not in text and "std::" not in text,
                   "refused: %s (says %r, and writes nothing)" % (label, want), "rc=%d %s" % (rc, text[-300:]))


    empty = live.fresh("empty")
    os.makedirs(empty)
    refused("a folder with no tree", empty, "no file whose name ends in .dtb")
    src = folder("twice", [Tree("a", [(0x100, 8, 0x10000)]), Tree("b", [(0x100, 8, 0x10000)])])
    refused("two trees for the same board", src, "same board")
    src = folder("nottree", [Tree("a", [(0x100, 8, 0x10000)])], {"junk.dtb": b"this is not a flattened device tree, it is some text of a length\n" * 4})
    refused("a .dtb that is no device tree", src, "junk.dtb")
    a = Tree("a", [(0x100, 8, 0x10000)]).make(WORK)
    src = folder("cutdtb", [], {"short.dtb": a.dtb[:-1], "ok.dtb": a.dtb})
    refused("a tree a byte short of its totalsize", src, "short.dtb")
    src = folder("pmicalone", [Tree("a", [(0x100, 0x10000)], pmic=[(1, 2, 3, 4)])])
    refused("qcom,pmic-id without qcom,board-id", src, "qcom,pmic-id")
    src = folder("badcells", [], {"bad.dtb": dtc((lambda p: (write(p, b'/dts-v1/;\n/ { qcom,msm-id = <0x100 0x8>; qcom,board-id = <1 2 3>; };\n'), p)[1])(os.path.join(WORK, "badcells.dts")), os.path.join(WORK, "badcells.dtb"))})
    refused("a qcom,board-id that is not whole groups of two cells", src, "bad.dtb")
    src = folder("badpage", SETS["v1"])
    recipe(src, page_size=0)
    refused("page_size=0", src, "page_size")
    src = folder("badpage2", SETS["v1"])
    recipe(src, page_size=2 << 20)
    refused("page_size of 2 MiB", src, "page_size")
    src = folder("badver", SETS["v1"])
    recipe(src, table_version=4)
    refused("table_version=4", src, "table_version")
    # the table is not written over a tree it was made of
    src = folder("overwrite", SETS["v1"])
    rc, text = live.run("pack", "-i", src, "-o", os.path.join(src, "a.dtb"))
    live.check(rc != 0 and "a file this run has read" in text and read(os.path.join(src, "a.dtb")) == SETS["v1"][0].dtb, "-o that is one of the trees is refused, and the tree is as it was", text[-300:])

# ---------------------------------------------------------------------------------------------------- 3. an unpacked table, edited
with live.section('3. an unpacked table, edited'):
    v2 = tables.get("v2")
    if v2:
        base = live.fresh("edit.base")
        live.run("unpack", "-i", live.path("set_v2.img"), "-o", base)
        trees = SETS["v2"]
        order = expected(trees)[2]  # the trees as the table has them: dtb0.dtb is the first of these
        files = [manifest_get(base, "dtb%d_file" % i) for i in range(len(order))]
        live.check(all(files) and all(read(os.path.join(base, f)) == t.dtb for f, t in zip(files, order)), "edit: dtb<N>.dtb are the trees, in the order of the table")
        entries0 = qcdt_check.read(v2)[1]

        def entries_of(table):
            return [(e["chipset"], e["platform"], e["subtype"], e["revision"], e["pmic"]) for e in qcdt_check.read(table)[1]]

        # a tree replaced by a bigger one
        work = live.fresh("edit.bigger")
        shutil.copytree(base, work)
        bigger = Tree("bigger", [(0x1A0, 0x10000)], board=[(8, 1)], pad=5000).make(WORK)
        write(os.path.join(work, files[0]), bigger.dtb)
        out = live.fresh("edit.bigger.img")
        rc, text = live.run("pack", "-i", work, "-o", out)
        if live.check(rc == 0, "edit: pack with the first tree replaced by one of 5000 bytes more", text[-300:]):
            t = read(out)
            try:
                qcdt_check.judge(t, 2048)
                live.check(True, "edit: the table with the bigger tree follows the layout rules (every offset made again)")
            except AssertionError as e:
                live.check(False, "edit: the table with the bigger tree follows the layout rules: %s" % e)
            live.check(entries_of(t) == entries_of(v2), "edit: the entries are what they were")
            got = {e["tree"] for e in qcdt_check.read(t)[1]}
            live.check(bigger.dtb in got and all(o.dtb in got for o in order[1:]) and order[0].dtb not in got, "edit: the first tree is the new one and the others are as they were")
        # an entry added, for the tree that is there
        work = live.fresh("edit.entry")
        shutil.copytree(base, work)
        n = int(manifest_get(work, "entry_count"))
        manifest_set(work, "entry_count", n + 1)
        for k, v in (("chipset", "0x777"), ("platform", "0x5"), ("subtype", "0x6"), ("revision", "0x0"), ("dtb", "1")):
            manifest_set(work, "entry%d_%s" % (n, k), v)
        out = live.fresh("edit.entry.img")
        rc, text = live.run("pack", "-i", work, "-o", out)
        if live.check(rc == 0, "edit: pack with an entry added", text[-300:]):
            t = read(out)
            live.check(qcdt_check.judge(t, 2048)[0] == 2 and (0x777, 5, 6, 0, (0, 0, 0, 0)) in entries_of(t) and len(entries_of(t)) == n + 1, "edit: the table has the new entry, which points at the second tree")
        # an entry made to point at a tree there is not
        work = live.fresh("edit.nosuch")
        shutil.copytree(base, work)
        manifest_set(work, "entry0_dtb", "9")
        refused("an entry that points at a tree there is not", work, "tree", out_name="edit.nosuch.img")
        # a tree that no entry points at
        work = live.fresh("edit.orphan")
        shutil.copytree(base, work)
        for i in range(n):
            if manifest_get(work, "entry%d_dtb" % i) == "1":
                manifest_set(work, "entry%d_dtb" % i, "0")
        refused("a tree that no entry points at", work, "tree", out_name="edit.orphan.img")
        # a tree that is no device tree, and one that is not as long as its header says
        for label, data, want in (("a text", b"text of some length, more than the bytes of a header of a device tree " * 3, files[0]),
                                  ("a byte short", read(os.path.join(base, files[0]))[:-1], files[0])):
            work = live.fresh("edit.badtree")
            shutil.copytree(base, work)
            write(os.path.join(work, files[0]), data)
            refused("a replaced tree that is %s" % label, work, want, out_name="edit.badtree.img")
        # the page size of the table changed
        work = live.fresh("edit.page")
        shutil.copytree(base, work)
        manifest_set(work, "page_size", "4096")
        out = live.fresh("edit.page.img")
        rc, text = live.run("pack", "-i", work, "-o", out)
        if live.check(rc == 0, "edit: pack with page_size=4096", text[-300:]):
            judge("the table with page_size=4096", read(out), trees, page=4096)

# ----------------------------------------------------------------------------------------------- 4. the table in a boot image
with live.section('4. the table in a boot image'):
    if "v2" in tables:
        table = tables["v2"]
        kernel, ramdisk = fx.blob(30000), fx.gz(fx.blob(20000))
        img = live.fresh("boot_dt.img")
        write(img, fx.boot_v012(0, kernel, ramdisk, dt=table, cmdline="console=ttyHSL0", id_bytes=fx.boot_id(hashlib.sha1, 0, kernel, ramdisk, b"", dt=table)))
        rc, text = live.run("info", "-i", img)
        live.check(rc == 0 and "QCDT" in text and "version 2" in text, "boot with a table: info names the table", text[:500])
        u = live.fresh("boot_dt.u")
        rc, text = live.run("unpack", "-i", img, "-o", u)
        live.check(rc == 0 and "byte-for-byte" in text and "dt" in text and "QCDT" in text, "boot with a table: unpack names it, and the repack is identical", text[-400:])
        live.check(manifest_get(u, "dt_format") == "qcdt" and manifest_get(u, "dt_version") == "2" and manifest_get(u, "dt_page_size") == "2048", "boot with a table: the manifest has the table")
        back = live.fresh("boot_dt.back.img")
        rc, text = live.run("pack", "-i", u, "-o", back)
        live.check(rc == 0 and same_bytes(back, img), "boot with a table: an untouched repack is the image", text[-300:])
        # a tree replaced by a bigger one: the table is made again, the size in the header and the id follow
        order = expected(SETS["v2"])[2]
        bigger = Tree("bigger", [(0x1A0, 0x10000)], board=[(8, 1)], pad=4000).make(WORK)
        write(os.path.join(u, manifest_get(u, "dt_dtb0_file")), bigger.dtb)
        new = live.fresh("boot_dt.edited.img")
        rc, text = live.run("pack", "-i", u, "-o", new)
        if live.check(rc == 0, "boot with a table: pack after a tree was replaced", text[-300:]):
            d = read(new)
            ksz, _, rsz, _, ssz, _, _, page, dtsz = struct.unpack_from("<9I", d, 8)
            dt_at = page * (1 + -(-ksz // page) + -(-rsz // page) + -(-ssz // page))
            live.check(dt_at + dtsz <= len(d) and dtsz >= 4096, "boot with a table: the dt size in the header is the size of the new table", "dt_size %d" % dtsz)
            edited = d[dt_at:dt_at + dtsz]
            try:
                ver, ents, _ = qcdt_check.judge(edited, page)
                live.check(ver == 2 and len(ents) == len(qcdt_check.read(table)[1]) and bigger.dtb in {e["tree"] for e in ents}, "boot with a table: the table in the image is the new one, with the entries it had")
            except AssertionError as e:
                live.check(False, "boot with a table: the table in the image follows the layout rules: %s" % e)
            live.check(d[page:page + ksz] == kernel, "boot with a table: the kernel is as it was")
            live.check(d[576:596] == fx.boot_id(hashlib.sha1, 0, kernel, ramdisk, b"", dt=edited)[:20], "boot with a table: the id is the SHA-1 over the parts, the table included, made again")

# ------------------------------------------------------------------------------------------------------ 5. a real device's table
with live.section("5. a real device's table"):
    if REAL and os.path.isfile(REAL):
        d = read(REAL)
        ksz, _, rsz, _, ssz, _, _, page, dtsz = struct.unpack_from("<9I", d, 8)
        dt_at = page * (1 + -(-ksz // page) + -(-rsz // page) + -(-ssz // page))
        real = d[dt_at:dt_at + dtsz]
        live.check(real[:4] == b"QCDT", "the real image: its dt is a QCDT (read from the header, not by abr)")
        try:
            ver, ents, _ = qcdt_check.judge(real, page)
            live.check(True, "the real table follows the layout rules of dtbTool (version %d, %d entries)" % (ver, len(ents)))
        except AssertionError as e:
            live.check(False, "the real table follows the layout rules of dtbTool: %s" % e)
            ver, ents = 0, []
        cut = live.fresh("real.qcdt")
        write(cut, real)
        u = live.fresh("real.qcdt.u")
        rc, text = live.run("unpack", "-i", cut, "-o", u)
        live.check(rc == 0 and "byte-for-byte" in text, "the real table alone: unpack, and the repack is identical", text[-300:])
        back = live.fresh("real.qcdt.back")
        rc, text = live.run("pack", "-i", u, "-o", back)
        live.check(rc == 0 and same_bytes(back, cut), "the real table alone: an untouched repack is the table", text[-300:])
        # the two trees of the real table, put through abr and through the real dtbTool, make the table of the device again
        u = live.fresh("real.img.u")
        rc, text = live.run("unpack", "-i", REAL, "-o", u)
        trees_dir = live.fresh("real.trees")
        os.makedirs(trees_dir)
        n_trees = 0
        while manifest_get(u, "dt_dtb%d_file" % n_trees):
            shutil.copy(os.path.join(u, manifest_get(u, "dt_dtb%d_file" % n_trees)), os.path.join(trees_dir, "dtb%d.dtb" % n_trees))
            n_trees += 1
        if live.check(rc == 0 and n_trees >= 1, "the real image: its device trees are files", text[-300:]):
            recipe(trees_dir, page_size=page)
            from_trees = live.fresh("real.from_trees.img")
            prc, ptext = live.run("pack", "-i", trees_dir, "-o", from_trees)
            if live.check(prc == 0, "the trees of the real table: pack", ptext[-300:]):
                live.check(read(from_trees) == real, "the trees of the real table make the table of the device again, byte for byte (%d bytes)" % len(real))
                same_as_dtbtool("the trees of the real table", trees_dir, real, page=page)
        # a tree of the real table replaced by a bigger one: the entries stay, the offsets are made again, the image behind the table is moved on whole
        if live.check(rc == 0 and "byte-for-byte" in text, "the real image: unpack, and the repack is identical", text[-300:]) and ents:
            bigger = Tree("bigger", [(0x125, 0x44, 0)], pad=4000).make(WORK)
            write(os.path.join(u, manifest_get(u, "dt_dtb1_file")), bigger.dtb)
            new = live.fresh("real.img.edited")
            rc, text = live.run("pack", "-i", u, "-o", new)
            if live.check(rc == 0, "the real image: pack after the last tree was replaced by a bigger one", text[-300:]):
                n = read(new)
                ksz2, _, rsz2, _, ssz2, _, _, page2, dtsz2 = struct.unpack_from("<9I", n, 8)
                at2 = page2 * (1 + -(-ksz2 // page2) + -(-rsz2 // page2) + -(-ssz2 // page2))
                table2 = n[at2:at2 + dtsz2]
                try:
                    ver2, ents2, _ = qcdt_check.judge(table2, page2)
                    key = lambda es: [(e["chipset"], e["platform"], e["subtype"], e["revision"]) for e in es]
                    live.check(key(ents2) == key(ents) and ver2 == ver, "the real image edited: the table has the entries it had")
                    live.check(bigger.dtb in {e["tree"] for e in ents2} and dtsz2 > dtsz, "the real image edited: the last tree is the new one, and the table is longer")
                except AssertionError as e:
                    live.check(False, "the real image edited: the table follows the layout rules: %s" % e)
                tail = read(os.path.join(u, "tail.bin"))  # (what follows the table; the zeros after it were the fill up to the size of the old image, which the longer table made unneeded)
                live.check(n[at2 + dtsz2:] == tail, "the real image edited: what follows the table (%d bytes) is moved on as it was" % len(tail))
                live.check(n[page2:page2 + ksz2] == d[page:page + ksz], "the real image edited: the kernel is as it was")

# --------------------------------------------------------------------------------------------------------- 6. damaged tables
with live.section('6. damaged tables'):
    runs = 0
    for name, table in sorted(tables.items()):
        runs += live.damaged("qcdt_" + name, table, seed=20261114, head=600)
    if REAL and os.path.isfile(REAL):
        d = read(REAL)
        ksz, _, rsz, _, ssz, _, _, page, dtsz = struct.unpack_from("<9I", d, 8)
        dt_at = page * (1 + -(-ksz // page) + -(-rsz // page) + -(-ssz // page))
        runs += live.damaged("qcdt_real", d[dt_at:dt_at + dtsz], seed=20261115, head=400)
print("damaged-table runs: %d" % runs)
if HAVE_DTBTOOL:
    print("the real dtbTool made %d tables to compare with" % DTBTOOL_RUNS)
else:
    print("note: the real dtbTool was not used (ABR_DTBTOOL is not a built dtbTool, or `dtc` is missing): abr's tables were judged by qcdt_check.py only")
sys.exit(live.finish("qcdt"))
