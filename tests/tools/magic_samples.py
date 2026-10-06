#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Samples for `abr identify`, and what each one must be called.

Every signature in Android Image Kitchen's bin/androidbootimg.magic gets a
sample here (plus the awkward combinations: a prefix signature in front of an
"ANDROID!" image, two weak signatures in one file, ...). EXPECT holds the label
file(1) prints for the sample when it is run with that magic file
(`file -m androidbootimg.magic -b SAMPLE`) -- measured with file-5.45 -- except
for the samples listed in DEVIATIONS, where abr knowingly answers differently
and says why.

    magic_samples.py write DIR                         write the samples
    magic_samples.py check ABR [ANDROIDBOOTIMG.MAGIC]  run `abr identify` on them

`check` compares abr with the table. Given AIK's magic file (and a `file`
command) it also compares abr with file(1) itself, sample by sample -- the table
is only a snapshot of that, so the two checks agree unless the table is stale.
The magic file is not part of this repository.
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile

BUMP = bytes([0x41, 0xA9, 0xE4, 0x67, 0x74, 0x4D, 0x1D, 0x1B, 0xA4, 0x29, 0xF2, 0xEC, 0xEA, 0x65, 0x52, 0x79])
MTK = b"\x88\x16\x88\x58"
AVB1 = b"\x02\x01\x01\x30\x82"


def pad(b, n=4096):
    return b + b"\0" * (n - len(b)) if len(b) < n else b


def elf(cls, osabi, machine):
    e = bytearray(64)
    e[0:4] = b"\x7fELF"
    e[4], e[5], e[6], e[7] = cls, 1, 1, osabi
    e[18] = machine
    return pad(bytes(e))


def mtk_part(name):
    return MTK + struct.pack("<I", 100) + name.ljust(32, b"\0") + b"\0" * 500


def aosp_header():
    return bytearray(b"ANDROID!" + b"\0" * 2040)


def samples():
    s = {}
    hdr = aosp_header()
    s["blob"] = pad(b"-SIGNED-BY-SIGNBLOB-")
    for i, name in enumerate([b"Red Loader", b"Green Loader", b"Green Recovery",
                              b"eMMC boot.img+secondloader", b"eMMC recovery.img+secondloader"]):
        s[f"nook{i}"] = pad(b"\0" * 64 + name)
    s["nooktab"] = pad(b"\0" * 48 + b"BauwksBoot")
    s["chromeos"] = pad(b"CHROMEOS" + b"\0" * 100)
    s["dhtb"] = pad(b"DHTB\x01\0\0" + b"\0" * 100)
    s["sin1"] = pad(b"\x01\0\0\0abc")
    s["sin2"] = pad(b"\x02\0\0\0abc")
    s["sin3"] = pad(b"\x03SINabc")

    s["aosp"] = bytes(hdr)
    s["aosp_at_100"] = b"\0" * 100 + bytes(hdr)
    s["aosp_in_window"] = b"\0" * 40000 + bytes(hdr)
    s["aosp_beyond_window"] = b"\0" * 70000 + bytes(hdr)
    for tag, v in (("pxa020", b"\0\0\0\2"), ("pxa028", b"\0\0\x80\2"), ("pxa030", b"\0\0\0\3")):
        h = bytearray(hdr)
        h[36:40] = v
        s[tag] = pad(bytes(h))
    h = bytearray(hdr); h[1024:1032] = b"ANDROID!"; h[100:111] = b"microloader"
    s["amonet"] = pad(bytes(h), 8192)
    h = bytearray(hdr); h[100:111] = b"microloader"
    s["microloader_only"] = pad(bytes(h), 8192)
    for tag, v in (("loki_boot", 0), ("loki_rec", 1), ("loki_other", 2)):
        h = bytearray(hdr); h[1024:1028] = b"LOKI"; h[1028] = v
        s[tag] = pad(bytes(h), 8192)
    s["aosp_mtk"] = pad(bytes(hdr), 4096) + MTK + b"\0" * 100
    s["aosp_mtk_2048"] = bytes(hdr) + MTK + b"\0" * 100
    s["aosp_bump"] = pad(bytes(hdr)) + BUMP
    s["aosp_avb1"] = pad(bytes(hdr)) + AVB1 + b"\0" * 20 + b"/boot"
    s["aosp_seandroid_avb"] = pad(bytes(hdr)) + b"SEANDROIDENFORCE" + b"AVBf" + b"\0" * 10
    s["aosp_krnl"] = bytes(hdr) + b"KRNL"
    s["aosp_qcdt"] = bytes(hdr) + b"QCDT"
    s["aosp_vndr"] = bytes(hdr) + b"VNDRBOOT"

    s["vndr"] = pad(b"VNDRBOOT" + b"\0" * 100)
    s["vndr_aosp"] = pad(b"VNDRBOOT", 4096) + bytes(hdr)
    s["aosp_then_vndr"] = pad(bytes(hdr), 4096) + b"VNDRBOOT"
    s["uboot"] = pad(b"\x27\x05\x19\x56" + b"\0" * 100)
    s["krnl"] = pad(b"KRNL" + b"\0" * 100)
    s["qcdt"] = pad(b"QCDT" + b"\0" * 100)

    s["osip"] = pad(b"$OS$\0\0\1")
    for tag, v in (("osip_bs", 0), ("osip_bu", 1), ("osip_rs", 0x0C), ("osip_ru", 0x0D), ("osip_other", 5)):
        h = bytearray(b"$OS$\0\0\1" + b"\0" * 100); h[52:56] = struct.pack("<I", v)
        s[tag] = pad(bytes(h))
    s["osip_hl"] = pad(b"\0" * 1000 + b"\xFC\xFA\xBC\x00")
    s["osip_hl_early"] = pad(b"\0" * 900 + b"\xFC\xFA\xBC\x00")

    s["elf_arm"] = elf(1, 0x61, 0x28)
    s["elf_arm64"] = elf(2, 0x61, 0x28)
    s["elf_x86"] = elf(1, 0x61, 3)
    s["elf_x86_64"] = elf(2, 0x61, 3)
    s["elf_mips"] = elf(1, 0x61, 8)
    s["elf_plain"] = elf(1, 0, 0x28)
    s["elf_other"] = elf(1, 0x61, 0xB7)
    s["elf_noclass"] = elf(0, 0x61, 0x28)
    s["elf_arm_mtk"] = elf(1, 0x61, 0x28) + MTK + b"\0" * 100
    s["elf_aosp"] = elf(1, 0x61, 0x28) + bytes(hdr)

    s["mtk_kernel"] = mtk_part(b"KERNEL")
    s["mtk_rootfs"] = mtk_part(b"ROOTFS")
    s["mtk_recovery"] = mtk_part(b"RECOVERY")
    s["mtk_bare"] = MTK + b"\0" * 500
    s["mtk_inner"] = b"\0" * 40 + mtk_part(b"KERNEL")
    s["zeros_mtk_deep"] = b"\0" * 5000 + MTK
    s["mtk_aosp"] = pad(MTK + b"\0" * 100, 4096) + bytes(hdr)

    s["avb1"] = pad(b"\0" * 100 + AVB1 + b"\0" * 40)
    s["avb1_boot"] = pad(b"\0" * 100 + AVB1 + b"\0" * 20 + b"/boot" + b"\0" * 20)
    s["avb1_rec"] = pad(b"\0" * 100 + AVB1 + b"\0" * 20 + b"/recovery" + b"\0" * 20)
    s["avb2"] = pad(b"\0" * 100 + b"AVBf" + b"\0" * 40)
    s["bump"] = pad(b"\0" * 100 + BUMP)
    s["seandroid"] = pad(b"\0" * 100 + b"SEANDROIDENFORCE")
    s["avb2_avb1"] = pad(AVB1 + b"\0" * 20 + b"/boot", 4096) + b"AVBf"
    s["avb1_bump"] = pad(AVB1 + b"\0" * 20 + b"/boot", 4096) + BUMP
    s["bump_seandroid"] = pad(BUMP, 4096) + b"SEANDROIDENFORCE"
    s["mtk_avb1"] = MTK + b"\0" * 100 + AVB1 + b"\0" * 20 + b"/boot"

    # a prefix signature in front of an "ANDROID!" image names the wrapper
    for tag, front in (("chromeos", b"CHROMEOS"), ("dhtb", b"DHTB\x01\0\0"), ("blob", b"-SIGNED-BY-SIGNBLOB-"),
                       ("osip", b"$OS$\0\0\1"), ("uboot", b"\x27\x05\x19\x56"), ("qcdt", b"QCDT"),
                       ("sin1", b"\x01\0\0\0")):
        s[tag + "_aosp"] = pad(front + b"\0" * 100, 4096) + bytes(hdr)

    # the weak signatures against each other, one pair per file
    weak = {"osiphl": (1000, b"\xFC\xFA\xBC\x00"), "mtk": (0, MTK), "avb1": (2000, AVB1),
            "avb2": (3000, b"AVBf"), "bump": (4000, BUMP), "sea": (5000, b"SEANDROIDENFORCE")}
    names = list(weak)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            buf = bytearray(8192)
            for n in (a, b):
                off, data = weak[n]
                buf[off:off + len(data)] = data
            s[f"weak_{a}+{b}"] = bytes(buf)

    s["zeros"] = b"\0" * 4096
    s["empty"] = b""
    s["text"] = b"hello world\n"
    return s


# What file(1) says with AIK's magic (file-5.45), except the DEVIATIONS below.
EXPECT = {
    "aosp": "AOSP bootimg",
    "aosp_at_100": "AOSP bootimg",
    "aosp_in_window": "AOSP bootimg",
    "pxa020": "AOSP bootimg, PXA variant (020)",
    "pxa028": "AOSP bootimg, PXA variant (028)",
    "pxa030": "AOSP bootimg, PXA variant (030)",
    "amonet": "AOSP bootimg, AMONET header",
    "microloader_only": "AOSP bootimg",
    "loki_boot": "AOSP bootimg, LOKI header (boot)",
    "loki_rec": "AOSP bootimg, LOKI header (recovery)",
    "loki_other": "AOSP bootimg, LOKI header",
    "aosp_mtk": "AOSP bootimg, MTK headers",
    "aosp_mtk_2048": "AOSP bootimg, MTK headers",
    "aosp_bump": "AOSP bootimg",
    "aosp_avb1": "AOSP bootimg",
    "aosp_seandroid_avb": "AOSP bootimg",
    "aosp_krnl": "AOSP bootimg",
    "aosp_qcdt": "AOSP bootimg",
    "aosp_vndr": "AOSP bootimg",
    "aosp_then_vndr": "AOSP bootimg",
    "vndr": "AOSP_VNDR bootimg",
    "uboot": "U-Boot bootimg",
    "krnl": "KRNL bootimg",
    "qcdt": "QCDT header",
    "blob": "BLOB signing",
    "nook0": "NOOK signing (red loader)",
    "nook1": "NOOK signing (green loader)",
    "nook2": "NOOK signing (green recovery)",
    "nook3": "NOOK signing (emmc boot)",
    "nook4": "NOOK signing (emmc recovery)",
    "nooktab": "NOOKTAB signing (bauwks)",
    "chromeos": "CHROMEOS signing",
    "dhtb": "DHTB signing",
    "sin1": "SINv1 signing",
    "sin2": "SINv2 signing",
    "sin3": "SINv3 signing",
    "osip": "OSIP bootimg, boot (signed)",
    "osip_bs": "OSIP bootimg, boot (signed)",
    "osip_bu": "OSIP bootimg, boot (unsigned)",
    "osip_rs": "OSIP bootimg, recovery (signed)",
    "osip_ru": "OSIP bootimg, recovery (unsigned)",
    "osip_other": "OSIP bootimg",
    "osip_hl": "OSIP bootimg (headerless)",
    "osip_hl_early": "data",
    "elf_arm": "ELF bootimg (ARM)",
    "elf_arm64": "ELF bootimg (ARM64)",
    "elf_x86": "ELF bootimg (x86_)",
    "elf_x86_64": "ELF bootimg (x86_64)",
    "elf_mips": "ELF bootimg (MIPS)",
    "elf_plain": "ELF (ARM)",
    "elf_other": "ELF bootimg)",
    "elf_arm_mtk": "ELF bootimg (ARM), MTK headers",
    "elf_aosp": "ELF bootimg (ARM)",
    "mtk_kernel": "MTK header, kernel type",
    "mtk_rootfs": "MTK header, rootfs type",
    "mtk_recovery": "MTK header, recovery type",
    "mtk_bare": "MTK header",
    "mtk_aosp": "AOSP bootimg",
    "avb1": "AVBv1 signing footer",
    "avb1_boot": "AVBv1 signing footer, boot type",
    "avb1_rec": "AVBv1 signing footer, recovery type",
    "avb2": "AVBv2 signing footer",
    "bump": "Bump footer",
    "seandroid": "SEAndroid footer",
    "avb2_avb1": "AVBv1 signing footer, boot type",
    "avb1_bump": "AVBv1 signing footer, boot type",
    "bump_seandroid": "Bump footer",
    "mtk_avb1": "AVBv1 signing footer, boot type",
    "chromeos_aosp": "CHROMEOS signing",
    "dhtb_aosp": "DHTB signing",
    "blob_aosp": "BLOB signing",
    "osip_aosp": "OSIP bootimg, boot (signed)",
    "uboot_aosp": "U-Boot bootimg",
    "qcdt_aosp": "QCDT header",
    "sin1_aosp": "SINv1 signing",
    "zeros": "data",
    "empty": "empty",
}
# ranks among the weak signatures, as file(1) has them: OSIP headerless, AVBv1, AVBv2, Bump, SEAndroid, MTK
_WEAK_ORDER = [("osiphl", "OSIP bootimg (headerless)"), ("avb1", "AVBv1 signing footer"),
               ("avb2", "AVBv2 signing footer"), ("bump", "Bump footer"),
               ("sea", "SEAndroid footer"), ("mtk", "MTK header")]
for _i, (_a, _la) in enumerate(_WEAK_ORDER):
    for _b, _lb in _WEAK_ORDER[_i + 1:]:
        _key = "weak_%s+%s" % tuple(sorted((_a, _b), key=["osiphl", "mtk", "avb1", "avb2", "bump", "sea"].index))
        EXPECT[_key] = _la

# Where abr deliberately differs from file(1) (see include/abr/identify.hpp).
DEVIATIONS = {
    # the search window: abr looks for "ANDROID!" in the first 64 KiB, what the unpackers can open
    "aosp_beyond_window": "data",
    # ... and it does not take a vendor_boot (VNDRBOOT first) for a boot image
    "vndr_aosp": "AOSP_VNDR bootimg",
    # an MTK header is recognised where it is (offset 0), not anywhere in the file
    "mtk_inner": "data",
    "zeros_mtk_deep": "data",
    # file(1)'s own ELF code adds its words when the class byte is nonsense; abr stops at the signature file's
    "elf_noclass": "ELF bootimg (ARM",
    # abr does not guess at text
    "text": "data",
}


def write(dirpath):
    os.makedirs(dirpath, exist_ok=True)
    for name, data in samples().items():
        with open(os.path.join(dirpath, name), "wb") as f:
            f.write(data)


def check(abr, magic):
    work = tempfile.mkdtemp(prefix="abr-magic-")
    bad = 0
    try:
        write(work)
        names = sorted(samples())
        out = subprocess.run([abr, "identify", "-b"] + [os.path.join(work, n) for n in names],
                             capture_output=True, text=True)
        got = out.stdout.split("\n")[:-1]
        if len(got) != len(names):
            print("abr identify printed %d lines for %d files:\n%s" % (len(got), len(names), out.stderr))
            return 1
        file_cmd = shutil.which("file") if magic else None
        for name, label in zip(names, got):
            want = DEVIATIONS.get(name, EXPECT.get(name))
            if want is None:
                print("  no expectation for sample %s" % name)
                bad += 1
            elif label != want:
                print("  %-22s abr says %r, expected %r" % (name, label, want))
                bad += 1
            if file_cmd and name not in DEVIATIONS:
                ref = subprocess.run([file_cmd, "-m", magic, "-b", os.path.join(work, name)],
                                     capture_output=True, text=True).stdout.strip()
                if ref != label:
                    print("  %-22s abr says %r, file(1) says %r" % (name, label, ref))
                    bad += 1
        print("%d samples, %d problem(s)%s" % (len(names), bad, "" if file_cmd else " (file(1) comparison skipped)"))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "write":
        write(sys.argv[2])
    elif len(sys.argv) >= 3 and sys.argv[1] == "check":
        sys.exit(check(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None))
    else:
        print(__doc__)
        sys.exit(2)
