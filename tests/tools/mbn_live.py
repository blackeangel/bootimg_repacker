#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs abr on the images of mk_mbn.py (Qualcomm's secure boot images, flat and ELF) and judges the result with the independent check of mk_mbn.py: info,
unpack, an untouched pack (byte for byte), a changed code or segment (the sizes and the table of hashes are made again: `mk_mbn.py verify` reads every size
and every hash of the image abr wrote), what is not an MBN (refused with the reason, or an ELF that is taken for another kind and says it does not
repack as it was), and damaged images. Prints one FAIL line for every check that does not hold and a last line with the counts; exit status 1 when there is one.

  mbn_live.py ABR GENDIR WORKDIR      (GENDIR is what `mk_mbn.py make` made)
"""
import gzip
import importlib.util
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from livelib import Live, manifest_get, read, same_bytes, script_dir, write  # noqa: E402

ABR, GEN, WORK = sys.argv[1], sys.argv[2], sys.argv[3]
live = Live(ABR, WORK)
MK = os.path.join(script_dir(), "mk_mbn.py")
spec = importlib.util.spec_from_file_location("mk_mbn", MK)
mk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mk)


def verify(path):
    r = subprocess.run([sys.executable, "-I", MK, "verify", path], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()[-300:]


NOT_MBN = {"not_mbn_plain.elf", "not_mbn_split.mdt", "sbl_nand_preamble.bin", "truncated_v3.mbn"}
NO_VERIFY = {"elf32_unknown_table.mbn"}  # (the table of hashes is one that nobody can make of the segments: abr keeps it as it is)
images = sorted(f for f in os.listdir(GEN) if f.endswith(".mbn") and f not in NOT_MBN)

# ------------------------------------------------------------------------------------------------- 1. info, unpack, untouched pack
with live.section('1. info, unpack, untouched pack'):
    for name in images:
        img = os.path.join(GEN, name)
        elf = read(img)[:4] == b"\x7fELF"
        rc, text = live.run("info", "-i", img)
        live.check(rc == 0 and ("format: mbn_elf" if elf else "format: mbn\n") in text + "\n", name + ": info says what it is", text[:300])
        live.check("layout" in text and "offset" in text, name + ": info has the layout with offsets", text[:300])
        out = live.fresh(name + ".u")
        rc, text = live.run("unpack", "-i", img, "-o", out)
        live.check(rc == 0, name + ": unpack", text[-500:])
        live.check("byte-for-byte" in text, name + ": unpack says the repack is identical", text[-300:])
        live.check("0x" in text and "image" in text, name + ": unpack writes offsets and sizes", text[-300:])
        new = live.fresh(name + ".new")
        rc, text = live.run("pack", "-i", out, "-o", new)
        live.check(rc == 0 and same_bytes(img, new), name + ": an untouched pack is byte-identical", text[-300:])
        if name not in NO_VERIFY:
            ok, why = verify(new)
            live.check(ok, name + ": the independent check of the repack", why)

# ---------------------------------------------------------------------------------------- 2. a changed code or segment is made consistent
with live.section('2. a changed code or segment is made consistent'):
    rnd_bytes = lambda n, seed: bytes((seed + i * 31 + (i >> 8)) & 0xFF for i in range(n))  # noqa: E731


    def edit_flat(name, new_len):
        img = os.path.join(GEN, name)
        out = live.fresh(name + ".e")
        rc, text = live.run("unpack", "-i", img, "-o", out)
        if not live.check(rc == 0, name + ": unpack for the edit", text[-300:]):
            return
        code = rnd_bytes(new_len, 9)
        write(os.path.join(out, "code.bin"), code)
        new = live.fresh(name + ".edited")
        rc, text = live.run("pack", "-i", out, "-o", new)
        if not live.check(rc == 0, name + ": pack after the code changed (%d bytes)" % new_len, text[-400:]):
            return
        ok, why = verify(new)
        live.check(ok, name + ": sizes of the edited image (code %d bytes)" % new_len, why)
        d = read(new)
        version, sizes, code_at, got, end = mk.verify_block(d, 0, len(d))
        compression = manifest_get(out, "code_compression")
        if compression == "gzip":
            live.check(gzip.decompress(got) == code, name + ": the edited code is in the image, compressed again as it was")
        else:
            live.check(got == code, name + ": the edited code is in the image")
        signed = any(os.path.exists(os.path.join(out, part + ".bin")) for part in ("signature", "cert_chain"))
        live.check(("abr cannot sign" in text) == signed, name + ": pack says the signature no longer matches, when there is one", text[-300:])
        # the other parts of the structure stay: the signature and the chain are the old ones
        for part in ("signature", "cert_chain"):
            f = os.path.join(out, part + ".bin")
            if os.path.exists(f):
                live.check(read(f) in d, name + ": %s is kept as it was" % part)
        # abr reads what it wrote
        out2 = live.fresh(name + ".e2")
        rc, text = live.run("unpack", "-i", new, "-o", out2)
        live.check(rc == 0 and "byte-for-byte" in text, name + ": unpack of the edited image, and that repacks identically", text[-300:])


    for name in ("flat_v3.mbn", "flat_v3_round.mbn", "flat_v5.mbn", "flat_v6.mbn", "flat_v7.mbn", "flat_sbl.mbn", "flat_v3_gzip.mbn", "flat_v3_unsigned.mbn"):
        edit_flat(name, 4001)  # (not a multiple of 4)
        edit_flat(name, 9000)
    edit_flat("flat_v3.mbn", 16)


    def edit_elf(name, seg, new_len):
        img = os.path.join(GEN, name)
        out = live.fresh(name + ".e")
        rc, text = live.run("unpack", "-i", img, "-o", out)
        if not live.check(rc == 0, name + ": unpack for the edit", text[-300:]):
            return
        f = os.path.join(out, "seg%d.bin" % seg)
        if not live.check(os.path.exists(f), name + ": the file of segment %d is there" % seg, str(sorted(os.listdir(out)))):
            return
        data = rnd_bytes(new_len, 3)
        write(f, data)
        new = live.fresh(name + ".edited")
        rc, text = live.run("pack", "-i", out, "-o", new)
        if not live.check(rc == 0, name + ": pack after segment %d changed (%d bytes)" % (seg, new_len), text[-400:]):
            return
        ok, why = verify(new)
        live.check(ok, name + ": the table of hashes of the edited image (segment %d, %d bytes)" % (seg, new_len), why)
        live.check(data in read(new), name + ": the new bytes of segment %d are in the image" % seg)
        out2 = live.fresh(name + ".e2")
        rc, text = live.run("unpack", "-i", new, "-o", out2)
        live.check(rc == 0 and "byte-for-byte" in text, name + ": unpack of the edited image, and that repacks identically", text[-300:])
        live.check(read(os.path.join(out2, "seg%d.bin" % seg)) == data, name + ": the segment comes back as it was written")


    for name in ("elf32.mbn", "elf64.mbn", "elf32_sha1.mbn", "elf32_v6_sha384.mbn", "elf32_signed.mbn", "elf32_padded.mbn", "elf32_hashpad.mbn"):
        edit_elf(name, 2, 7000)   # bigger than it was
        edit_elf(name, 3, 100)    # smaller
    edit_elf("elf32_gzip.mbn", 3, 5000)
    # a paged segment is hashed page by page: a whole number of pages is made again, anything else is refused with that reason
    edit_elf("elf32_paged.mbn", 2, 12288)
    edit_elf("elf32_paged.mbn", 3, 100)
    out = live.fresh("elf32_paged.partial")
    rc, text = live.run("unpack", "-i", os.path.join(GEN, "elf32_paged.mbn"), "-o", out)
    write(os.path.join(out, "seg2.bin"), rnd_bytes(7000, 3))
    new = live.fresh("elf32_paged.partial.img")
    rc, text = live.run("pack", "-i", out, "-o", new)
    live.check(rc != 0 and "whole pages" in text and not os.path.exists(new), "elf32_paged: a paged segment that is not whole pages is refused, and nothing is written", text[-300:])

    # the table that nobody can make is kept, with and without a change of a segment
    out = live.fresh("elf32_unknown_table.e")
    rc, text = live.run("unpack", "-i", os.path.join(GEN, "elf32_unknown_table.mbn"), "-o", out)
    table = read(os.path.join(out, "hash_table.bin")) if rc == 0 else b""
    write(os.path.join(out, "seg3.bin"), rnd_bytes(500, 4))
    new = live.fresh("elf32_unknown_table.edited")
    rc, text = live.run("pack", "-i", out, "-o", new)
    live.check(rc == 0 and table and table in read(new), "elf32_unknown_table: a table abr cannot make stays as it was when a segment changes", text[-300:])

# ----------------------------------------------------------------------------------------------------------------- 3. what is not an MBN
with live.section('3. what is not an MBN'):
    for name, words in (("not_mbn_split.mdt", ("split",)), ("sbl_nand_preamble.bin", ("SBL",)), ("truncated_v3.mbn", ("do not fit",))):
        out = live.fresh(name + ".u")
        rc, text = live.run("unpack", "-i", os.path.join(GEN, name), "-o", out)
        live.check(rc != 0 and all(w in text for w in words) and not os.path.exists(out), name + ": refused with the reason, and no folder is left", text[-400:])
        rc, text = live.run("info", "-i", os.path.join(GEN, name))
        live.check(all(w in text for w in words), name + ": info says the same", text[-400:])
    out = live.fresh("not_mbn_plain.u")
    rc, text = live.run("unpack", "-i", os.path.join(GEN, "not_mbn_plain.elf"), "-o", out)
    live.check(rc != 0 or "does NOT reproduce" in text, "not_mbn_plain.elf: an ELF without a hash segment is refused, or taken as another kind and not silent about the repack", text[-400:])

# ------------------------------------------------------------------------------------------------------------------- 4. damaged images
with live.section('4. damaged images'):
    runs = 0
    for name in images:
        runs += live.damaged(name, read(os.path.join(GEN, name)), seed=20261112, head=0x1400)
print("damaged-image runs: %d" % runs)
sys.exit(live.finish("mbn"))
