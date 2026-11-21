#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs abr on `dtb` images (flattened device trees one behind the other) whose trees are not back to back, and on the ones that carry an AVB hash
footer; the trees are made by `dtc` and the images laid out here, not by abr. Judged by readers written here (the trees of an image by their headers and
the zeros between them, the footer by its fields) and, for the footers, by avbtool.

  gaps    trees at multiples of an alignment (the gap is what is left up to the next multiple, and a bigger tree moves the ones behind it), gaps that follow no
          rule (kept one by one), a gap of bytes that are not zeros (the trees end there, the rest is a trailer), gaps and an alignment a person wrote
  footer  a hash footer without a signature, one signed with a key whose private half is in keys/, one signed with a key that abr does not have (signed with
          its test key, with a warning), a tree that does not fit the partition (refused)

  dtb_live.py ABR AVBTOOL WORKDIR      exit status 1 when a check fails
"""
import os
import shutil
import struct
import subprocess
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
from livelib import Live, manifest_get, manifest_set, read, same_bytes, write  # noqa: E402

ABR, AVBTOOL, WORK = sys.argv[1:4]
live = Live(ABR, WORK)
MAGIC = b"\xd0\x0d\xfe\xed"


def dtc(name, body):
    src = os.path.join(WORK, name + ".dts")
    write(src, ('/dts-v1/;\n/ {\n\tmodel = "%s";\n\tcompatible = "test,%s";\n%s};\n' % (name, name, body)).encode())
    out = os.path.join(WORK, name + ".dtb")
    r = subprocess.run(["dtc", "-I", "dts", "-O", "dtb", "-o", out, src], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("dtc failed: " + r.stderr)
    return read(out)


def cells(n, seed):
    return "\tdata = [%s];\n" % " ".join("%02x" % ((i * seed + 3) & 255) for i in range(n))


def compile_source(path):
    """What `dtc` makes of a source: the blob."""
    r = subprocess.run(["dtc", "-q", "-I", "dts", "-O", "dtb", "-o", "-", path], capture_output=True)
    if r.returncode != 0:
        raise SystemExit("dtc cannot compile %s: %s" % (path, r.stderr.decode(errors="replace")))
    return r.stdout


def decompile(blob):
    """What `dtc` makes of a blob: its source."""
    r = subprocess.run(["dtc", "-q", "-I", "dtb", "-O", "dts", "-o", "-"], input=blob, capture_output=True)
    if r.returncode != 0:
        raise SystemExit("dtc cannot read a blob: " + r.stderr.decode(errors="replace"))
    return r.stdout


def tree_file(f, i):
    """The file of tree i of an unpacked folder (a source, NAME.dts, or a blob)."""
    return os.path.join(f, manifest_get(f, "blob%d_file" % i))


def tree_of(f, i):
    """The tree that the file of tree i stands for: the blob that dtc makes of a source."""
    p = tree_file(f, i)
    return compile_source(p) if p.endswith(".dts") else read(p)


def put_tree(f, i, blob):
    """Tree i of the folder is `blob` from now on: its source (what dtc says of it) goes where the old file is."""
    p = tree_file(f, i)
    write(p, decompile(blob) if p.endswith(".dts") else blob)


A = dtc("tree_a", "")
B = dtc("tree_b", cells(16, 3))
C = dtc("tree_c", cells(520, 5))
D = dtc("tree_d", cells(160, 7))
BIG = dtc("tree_big", cells(3000, 11))
trees = [A, B, C, D]


def trees_of(data):
    """The trees at the start of an image, found the way a reader of the format finds them: by the totalsize of each header, the zeros between them
    skipped. -> [(offset, bytes)]; stops at the first nonzero byte that does not start a tree."""
    out, pos = [], 0
    while pos + 40 <= len(data):
        while pos < len(data) and data[pos] == 0 and out:
            pos += 1
        if data[pos:pos + 4] != MAGIC:
            break
        total = struct.unpack_from(">I", data, pos + 4)[0]
        out.append((pos, data[pos:pos + total]))
        pos += total
    return out


def layout(blobs, gaps):
    """The image of `blobs` with `gaps[i]` zero bytes in front of blob i."""
    return b"".join(b"\0" * g + b for g, b in zip(gaps, blobs))


def aligned_gaps(blobs, n):
    at, gaps = 0, []
    for i, b in enumerate(blobs):
        g = (-at) % n if i else 0
        gaps.append(g)
        at += g + len(b)
    return gaps


def roundtrip(label, img_path, expect_exact=True):
    """info, unpack, untouched pack. -> the folder, or None."""
    rc, text = live.run("info", "-i", img_path)
    live.check(rc == 0 and "format: dtb" in text, label + ": info", text[:300])
    out = live.fresh(label + ".u")
    rc, text = live.run("unpack", "-i", img_path, "-o", out)
    if not live.check(rc == 0, label + ": unpack", text[-400:]):
        return None
    live.check(("byte-for-byte" in text) == expect_exact, label + ": unpack says whether the repack is identical", text[-300:])
    new = live.fresh(label + ".new")
    rc, text = live.run("pack", "-i", out, "-o", new)
    live.check(rc == 0 and same_bytes(new, img_path), label + ": an untouched pack is the image, byte for byte", text[-300:])
    return out


# ============================================================================================================================= 1. gaps
with live.section('1. gaps'):
    # trees at multiples of an alignment: whatever alignment abr records explains every gap, and a repack with a bigger tree puts the trees behind it at the
    # next multiples of it
    for n in (8, 64, 512, 4096):
        gaps = aligned_gaps(trees, n)
        img = live.path("aligned%d.dtb" % n)
        write(img, layout(trees, gaps))
        f = roundtrip("aligned%d" % n, img)
        if not f:
            continue
        align = manifest_get(f, "blob_align")
        live.check(align is not None and 1 <= int(align) <= n and n % int(align) == 0, "aligned%d: blob_align is recorded and divides %d" % (n, n), str(align))
        live.check(all(manifest_get(f, "blob%d_pad" % i) is None for i in range(4)), "aligned%d: with an alignment there is no blob<N>_pad" % n)
        live.check([tree_of(f, i) for i in range(4)] == trees and all(tree_file(f, i).endswith(".dts") for i in range(4)),
                   "aligned%d: the files are the sources of the trees (dtc compiles them to the trees)" % n)
        a = int(align or 1)
        # a bigger tree 1: the trees behind it move on to their next multiples of the alignment
        put_tree(f, 1, BIG)
        out = live.fresh("aligned%d.edited" % n)
        rc, text = live.run("pack", "-i", f, "-o", out)
        if live.check(rc == 0, "aligned%d: pack with a bigger tree" % n, text[-300:]):
            got = trees_of(read(out))
            live.check([b for _, b in got] == [A, BIG, C, D], "aligned%d edited: the four trees, the second one the new one" % n, str(len(got)))
            live.check(all(off % a == 0 for off, _ in got), "aligned%d edited: every tree is at a multiple of %d" % (n, a), str([off for off, _ in got]))
            ends = [off + len(b) for off, b in got]
            live.check(all(got[i + 1][0] - ends[i] < a for i in range(len(got) - 1)), "aligned%d edited: the gaps are the least that reach the next multiple" % n)
            live.check(len(read(out)) == got[-1][0] + len(D), "aligned%d edited: nothing behind the last tree" % n)

    # gaps that follow no rule are kept one by one (blob<N>_pad), and an edit keeps the counts
    gaps = [0, 3, 12, 0]
    img = live.path("irregular.dtb")
    write(img, layout(trees, gaps))
    f = roundtrip("irregular", img)
    if f:
        live.check(manifest_get(f, "blob_align") is None, "irregular: no blob_align where the gaps follow no rule")
        live.check([manifest_get(f, "blob%d_pad" % i) for i in range(4)] == [None, "3", "12", None], "irregular: blob<N>_pad are the gaps that are not zero in size")
        put_tree(f, 0, BIG)
        out = live.fresh("irregular.edited")
        rc, text = live.run("pack", "-i", f, "-o", out)
        if live.check(rc == 0, "irregular: pack with a bigger first tree", text[-300:]):
            d = read(out)
            live.check(d == layout([BIG, B, C, D], gaps), "irregular edited: the new tree, and the others with the gaps they had")

    # a gap of bytes that are not zeros: the trees end there, and what follows is the trailer, kept as it is
    img = live.path("junk.dtb")
    write(img, A + b"JUNKJUNK" + B)
    f = roundtrip("junk", img)
    if f:
        live.check(manifest_get(f, "blob_count") == "1" and read(os.path.join(f, "tail.bin")) == b"JUNKJUNK" + B, "junk: one tree, and the rest (junk and the tree behind it) is tail.bin")
    # bytes that are not zeros and a tree after the zeros are a trailer as well; zeros before a tree are a gap
    img = live.path("zeros_then_junk.dtb")
    write(img, A + b"\0" * 5 + B + b"\0" * 3 + b"TRAILER")
    f = roundtrip("zeros_then_junk", img)
    if f:
        live.check(manifest_get(f, "blob_count") == "2" and manifest_get(f, "blob1_pad") == "5" and read(os.path.join(f, "tail.bin")) == b"\0" * 3 + b"TRAILER",
                   "zeros_then_junk: two trees with a gap of 5, and the zeros and the text behind the last tree are the trailer")

    # gaps and an alignment that a person wrote in manifest.txt
    img = live.path("tight.dtb")
    write(img, A + B + C)
    base = roundtrip("tight", img)
    if base:
        f = live.fresh("tight.pad")
        shutil.copytree(base, f)
        manifest_set(f, "blob1_pad", "7")
        manifest_set(f, "blob2_pad", "1")
        out = live.fresh("tight.pad.img")
        rc, text = live.run("pack", "-i", f, "-o", out)
        live.check(rc == 0 and read(out) == layout([A, B, C], [0, 7, 1]), "blob1_pad=7 and blob2_pad=1 put that many zeros in front of the tree", text[-300:])
        f = live.fresh("tight.align")
        shutil.copytree(base, f)
        manifest_set(f, "blob_align", "64")
        out = live.fresh("tight.align.img")
        rc, text = live.run("pack", "-i", f, "-o", out)
        live.check(rc == 0 and read(out) == layout([A, B, C], aligned_gaps([A, B, C], 64)), "blob_align=64 puts the trees at multiples of 64", text[-300:])
        f = live.fresh("tight.both")
        shutil.copytree(base, f)
        manifest_set(f, "blob_align", "64")
        manifest_set(f, "blob2_pad", "2")
        out = live.fresh("tight.both.img")
        rc, text = live.run("pack", "-i", f, "-o", out)
        g = aligned_gaps([A, B, C], 64)
        g[2] = 2
        live.check(rc == 0 and read(out) == layout([A, B, C], g), "blob2_pad wins over blob_align for its tree", text[-300:])
        for label, key, value, want in (("blob0_pad", "blob0_pad", "3", "blob0_pad"), ("blob_align=0", "blob_align", "0", "blob_align"),
                                        ("a gap that is not a number", "blob1_pad", "many", "blob1_pad"), ("blob_align of 2 GiB", "blob1_pad", "3000000000", "blob1_pad")):
            f = live.fresh("tight.bad")
            shutil.copytree(base, f)
            manifest_set(f, key, value)
            out = live.fresh("tight.bad.img")
            rc, text = live.run("pack", "-i", f, "-o", out)
            live.check(rc != 0 and want in text and not os.path.exists(out), "refused: %s (says %r, writes nothing)" % (label, want), "rc=%d %s" % (rc, text[-300:]))

# ========================================================================================================================== 2. footers
with live.section('2. footers'):
    PARTITION = 1 << 20


    def with_footer(name, image, key=None):
        """`image` with an AVB hash footer, made by avbtool: partition `dtb` of 1 MiB."""
        path = live.path(name)
        write(path, image)
        args = [sys.executable, AVBTOOL, "add_hash_footer", "--image", path, "--partition_size", str(PARTITION), "--partition_name", "dtb"]
        if key:
            args += ["--algorithm", "SHA256_RSA2048", "--key", key]
        r = subprocess.run(args, capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("avbtool failed: " + r.stdout + r.stderr)
        return path


    def avb_verdict(image, key=None):
        """avbtool's verify_image of `image` (it looks for the partition's file next to the image, so the image is copied as dtb.img): (ok, output)."""
        d = live.fresh("avbcheck")
        os.makedirs(d)
        shutil.copy(image, os.path.join(d, "dtb.img"))
        args = [sys.executable, AVBTOOL, "verify_image", "--image", os.path.join(d, "dtb.img")] + (["--key", key] if key else [])
        r = subprocess.run(args, capture_output=True, text=True)
        return r.returncode == 0, r.stdout + r.stderr


    def footer_of(data):
        """The AVB footer at the end of an image, read by its fields: (original_image_size, vbmeta_offset, vbmeta_size) or None."""
        magic, major, minor, original, vbmeta_at, vbmeta_size = struct.unpack_from(">4sIIQQQ", data, len(data) - 64)[:6]
        return (original, vbmeta_at, vbmeta_size) if magic == b"AVBf" else None


    KEY = live.path("avb_key.pem")
    subprocess.run(["openssl", "genrsa", "-out", KEY, "2048"], capture_output=True)
    have_key = os.path.isfile(KEY)
    if not have_key:
        print("SKIP: signed footers (openssl cannot make a key here)")

    content = A + B
    cases = [("unsigned", with_footer("footer_unsigned.img", content))]
    if have_key:
        cases.append(("signed", with_footer("footer_signed.img", content, KEY)))

    for label, img in cases:
        f = roundtrip("footer_" + label, img)
        if not f:
            continue
        rc, text = live.run("info", "-i", img)
        live.check("avb footer:" in text and ("signed" if label == "signed" else "unsigned") in text and "hash check:   OK" in text, "footer_%s: info says there is a footer and that the hash matches" % label, text[:600])
        live.check(manifest_get(f, "has_avb_footer") == "true" and manifest_get(f, "avb_partition_size") == str(PARTITION), "footer_%s: the manifest has the footer and the size of the partition" % label)
        live.check([tree_of(f, i) for i in range(2)] == [A, B], "footer_%s: the files are the trees (not the footer)" % label)

        # a tree replaced by a bigger one; and, for the signed image, the three ways the signature can come out
        variants = [("", {})]
        if label == "signed":
            variants = [(".nokey", {}), (".key", {"keys/avb_key.pem": KEY})]
        for suffix, keys in variants:
            work = live.fresh("footer_%s.edit%s" % (label, suffix))
            shutil.copytree(f, work)
            put_tree(work, 1, C)
            for rel, src in keys.items():
                os.makedirs(os.path.dirname(os.path.join(work, rel)), exist_ok=True)
                shutil.copy(src, os.path.join(work, rel))
            out = live.fresh("footer_%s.edited%s.img" % (label, suffix))
            rc, text = live.run("pack", "-i", work, "-o", out)
            tag = "footer_%s%s edited" % (label, suffix)
            if not live.check(rc == 0, tag + ": pack", text[-400:]):
                continue
            d = read(out)
            live.check(len(d) == PARTITION, tag + ": the image is as long as the partition", str(len(d)))
            got = trees_of(d)
            live.check([b for _, b in got] == [A, C], tag + ": the trees are the new ones")
            end = got[-1][0] + len(C)
            ft = footer_of(d)
            live.check(ft is not None and ft[0] == end, tag + ": the footer protects the size of the new trees (%d)" % end, str(ft))
            live.check(ft is not None and d[end:ft[1]] == b"\0" * (ft[1] - end) and ft[1] % 4096 == 0, tag + ": zeros up to the vbmeta block, which is on a multiple of 4096")
            ok, out_text = avb_verdict(out, KEY if (label == "signed" and keys) else None)
            live.check(ok, tag + ": avbtool verifies the image" + (" against the key" if keys else ""), out_text[-300:])
            if label == "signed" and not keys:
                live.check("abr does not have the private half" in text and "keys/avb_key.pem" in text, tag + ": pack warns that it signed with its test key, and where a key goes", text[:600])
            elif label == "signed":
                live.check("warning" not in text, tag + ": no warning when the key is in keys/", text[:400])
            # unpack again: the repack of what abr wrote is identical
            again = live.fresh("footer_%s.edited%s.u" % (label, suffix))
            rc, t2 = live.run("unpack", "-i", out, "-o", again)
            back = live.fresh("footer_%s.edited%s.back" % (label, suffix))
            rc2, t3 = live.run("pack", "-i", again, "-o", back, env={})
            live.check(rc == 0 and rc2 == 0 and ("byte-for-byte" in t2), tag + ": abr unpacks what it wrote, and says the repack is identical", (t2 + t3)[-300:])

        # the trees do not fit the partition: refused, with the sizes, and nothing is written
        work = live.fresh("footer_%s.huge" % label)
        shutil.copytree(f, work)
        put_tree(work, 1, dtc("tree_huge", cells(PARTITION, 13)))
        out = live.fresh("footer_%s.huge.img" % label)
        rc, text = live.run("pack", "-i", work, "-o", out)
        live.check(rc != 0 and not os.path.exists(out) and "partition" in text and "terminate called" not in text and "std::" not in text,
                   "footer_%s: trees that do not fit the partition are refused, naming the partition" % label, "rc=%d %s" % (rc, text[-300:]))

    # the footer of an image whose trees have gaps: the gaps are kept, and the footer follows the end of the last tree
    gaps = [0, 3, 12]
    img = with_footer("footer_gaps.img", layout([A, B, C], gaps))
    f = roundtrip("footer_gaps", img)
    if f:
        put_tree(f, 0, BIG)
        out = live.fresh("footer_gaps.edited.img")
        rc, text = live.run("pack", "-i", f, "-o", out)
        if live.check(rc == 0, "footer_gaps: pack with a bigger first tree", text[-300:]):
            d = read(out)
            want = layout([BIG, B, C], gaps)
            ft = footer_of(d)
            live.check(d[:len(want)] == want and ft is not None and ft[0] == len(want), "footer_gaps edited: the trees with the gaps they had, and the footer protects them (%d bytes)" % len(want), str(ft))
            live.check(avb_verdict(out)[0], "footer_gaps edited: avbtool verifies the image")

# ====================================================================================================================== 3. damaged images
with live.section('3. damaged images'):
    runs = 0
    for name, path in (("aligned512", live.path("aligned512.dtb")), ("irregular", live.path("irregular.dtb")), ("junk", live.path("junk.dtb"))):
        runs += live.damaged(name, read(path), seed=20261116)
    for label, img in cases:
        runs += live.damaged("footer_" + label, read(img), seed=20261117, head=0x1400)
print("damaged-image runs: %d" % runs)
sys.exit(live.finish("dtb"))
