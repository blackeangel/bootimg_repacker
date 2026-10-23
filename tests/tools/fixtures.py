#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic images that reproduce, one by one, the quirks found while
round-tripping real device dumps (see PROGRESS.md, "Real-image findings").

    fixtures.py <outdir>

Every builder below follows the *format* (AOSP bootimg.h / vendor_boot.h /
avbtool), written independently of abr's C++ code, so the tests cross-check
abr instead of agreeing with it by construction. Content is deterministic.
"""
import gzip
import hashlib
import random
import struct
import sys
from pathlib import Path

_rnd = random.Random(20261001)


def blob(n):
    return _rnd.randbytes(n)


def gz(data):
    return gzip.compress(data, 9, mtime=0)


def le32(x):
    return struct.pack("<I", x)


def page_pad(b, page):
    return b + b"\0" * ((-len(b)) % page)


def with_tail(field, tail):
    """A text field (text, zero filled) with `tail` behind the NUL that ends its text, as far as the field has room
    for it: what a command line that was cut short in place leaves in an image (the rest of the old one), and what a
    tool that never clears the field leaves."""
    b = bytearray(field)
    n = b.index(0) if 0 in b else len(b)
    for i, c in enumerate(tail[:max(0, len(b) - n - 1)]):
        b[n + 1 + i] = c
    return bytes(b)


# --------------------------------------------------------------- boot ----

def boot_id(hash_ctor, version, kernel, ramdisk, second, dt=None, dtbo=b"", dtb=b""):
    """The `id` field the way vendor tools compute it: every part as
    data || le32(size). `dt` (v0 only) adds the CAF device-tree entry, which
    some tools feed even when it is empty (a lone le32(0))."""
    h = hash_ctor()

    def feed(d):
        h.update(d)
        h.update(le32(len(d)))

    feed(kernel)
    feed(ramdisk)
    feed(second)
    if dt is not None:
        feed(dt)
    if version >= 1:
        feed(dtbo)
    if version >= 2:
        feed(dtb)
    return h.digest()


def boot_v012(version, kernel, ramdisk, second=b"", dt=b"", dtbo=b"", dtb=b"", *, page=2048,
              cmdline="", name="", os_version=0, id_bytes=b"", dtbo_offset=None,
              hdr_size=None, dtb_addr=0, dirty_padding=False, hdr_garbage=b"", split=512,
              name_tail=b"", cmd_tail=b"", extra_tail=b""):
    """boot.img header v0/v1/v2. A non-empty `dt` on a v0 header is the
    Qualcomm/CAF layout: word 10 holds the dt size instead of the version."""
    word10 = len(dt) if (version == 0 and dt) else version
    cmd = cmdline.encode()
    hdr = b"ANDROID!"
    hdr += struct.pack("<10I", len(kernel), 0x8000, len(ramdisk), 0x1000000, len(second),
                       0xF00000, 0x100, page, word10, os_version)
    hdr += with_tail(name.encode().ljust(16, b"\0"), name_tail)
    first, extra = split_cmdline(cmdline, split)
    hdr += with_tail(first, cmd_tail)
    hdr += id_bytes.ljust(32, b"\0")
    hdr += with_tail(extra, extra_tail)
    if version >= 1:
        pages = lambda n: -(-n // page)
        off = dtbo_offset
        if off is None:
            off = page * (1 + pages(len(kernel)) + pages(len(ramdisk)) + pages(len(second))) if dtbo else 0
        hdr += struct.pack("<IQI", len(dtbo), off, hdr_size or (1648 if version == 1 else 1660))
    if version >= 2:
        hdr += struct.pack("<IQ", len(dtb), dtb_addr)
    hdr += hdr_garbage  # something a vendor stashed after the header struct
    out = page_pad(hdr, page)
    parts = [kernel, ramdisk, second]
    if version == 0 and dt:
        parts.append(dt)
    if version >= 1:
        parts.append(dtbo)
    if version >= 2:
        parts.append(dtb)
    for p in parts:
        padded = page_pad(p, page)
        if dirty_padding and len(padded) > len(p):
            padded = p + b"\xa5" * (len(padded) - len(p))  # vendor garbage in the page padding
        out += padded
    return out


def split_cmdline(cmdline, split):
    """How mkbootimg divides a long command line between the two header fields:
    AOSP's mkbootimg.py fills the whole 512-byte field (split=512), the old C
    mkbootimg keeps a NUL at its end (split=511)."""
    cmd = cmdline.encode()
    return cmd[:split].ljust(512, b"\0"), cmd[split:].ljust(1024, b"\0")


def boot_pxa(kernel, ramdisk, second=b"", dt=b"", *, page=2048, unknown=0x03000000, cmdline="",
             name="", id_bytes=b"", split=511, hdr_garbage=b"", signature=b"",
             name_tail=b"", cmd_tail=b"", extra_tail=b""):
    """Marvell PXA1088/PXA1908 boot image (osm0sis/pxa-mkbootimg's bootimg.h): a v0 header
    with `unknown` after dt_size, so tags_addr/page_size sit at 40/44, the board name has
    24 bytes and the id is at 584. Pages: kernel, ramdisk, second, dt, then an optional
    256-byte (or 272 with a SEANDROIDENFORCE marker) vendor signature."""
    first, extra = split_cmdline(cmdline, split)
    hdr = b"ANDROID!"
    hdr += struct.pack("<10I", len(kernel), 0x10008000, len(ramdisk), 0x11000000, len(second),
                       0x10F00000, len(dt), unknown, 0x10000100, page)
    hdr += with_tail(name.encode().ljust(24, b"\0"), name_tail)
    hdr += with_tail(first, cmd_tail)
    hdr += id_bytes.ljust(32, b"\0")
    hdr += with_tail(extra, extra_tail)
    assert len(hdr) == 1640
    hdr += hdr_garbage
    out = page_pad(hdr, page)
    for part in (kernel, ramdisk, second):
        out += page_pad(part, page)
    if dt:
        out += page_pad(dt, page)
    return out + signature


def boot_v34(version, kernel, ramdisk, *, cmdline="", os_version=0, reserved=(0, 0, 0, 0),
             hdr_size=None, signature=b"", cmd_tail=b""):
    hdr = b"ANDROID!"
    hdr += struct.pack("<4I", len(kernel), len(ramdisk), os_version,
                       hdr_size or (1580 if version == 3 else 1584))
    hdr += struct.pack("<4I", *reserved) + le32(version)
    hdr += with_tail(cmdline.encode().ljust(1536, b"\0"), cmd_tail)
    if version == 4:
        hdr += le32(len(signature))
    out = page_pad(hdr, 4096) + page_pad(kernel, 4096) + page_pad(ramdisk, 4096)
    if signature:
        out += page_pad(signature, 4096)
    return out


# -------------------------------------------------------- vendor_boot ----

def vendor_boot_v4_empty_table(ramdisk, dtb, *, page=2048, hdr_size=2112, dtb_addr=0x102077FFF):
    """A v4 header that declares no ramdisk table (Magisk/Amlogic-style
    images): one anonymous ramdisk blob, a v3-sized header_size, page 2048."""
    hdr = b"VNDRBOOT" + struct.pack("<5I", 4, page, 0x8000, 0x1000000, len(ramdisk))
    hdr += b"console=ttyS0".ljust(2048, b"\0")
    hdr += le32(0x100) + b"vendtest".ljust(16, b"\0")
    hdr += struct.pack("<IIQ", hdr_size, len(dtb), dtb_addr)
    hdr += struct.pack("<4I", 0, 0, 0, 0)  # table size, entries, entry size, bootconfig
    return page_pad(hdr, page) + page_pad(ramdisk, page) + page_pad(dtb, page)


def vendor_boot(version, fragments, *, dtb=b"", bootconfig=b"", page=4096, cmdline="", name="",
                cmd_tail=b"", name_tail=b"", kernel_addr=0x8000, ramdisk_addr=0x1000000,
                tags_addr=0x100, dtb_addr=0x1F00000):
    """vendor_boot v3 (the ramdisk is `fragments[0][3]`) or v4 (`fragments` is the vendor ramdisk table:
    (type, name, name_tail, data) each). Header, ramdisk section, dtb, table, bootconfig, each from a page boundary
    (AOSP vendor_boot.h)."""
    section = b"".join(f[3] for f in fragments) if version == 4 else fragments[0][3]
    hdr = b"VNDRBOOT" + struct.pack("<5I", version, page, kernel_addr, ramdisk_addr, len(section))
    hdr += with_tail(cmdline.encode().ljust(2048, b"\0"), cmd_tail)
    hdr += le32(tags_addr) + with_tail(name.encode().ljust(16, b"\0"), name_tail)
    hdr += struct.pack("<IIQ", 2112 if version == 3 else 2128, len(dtb), dtb_addr)
    table = b""
    if version == 4:
        off = 0
        for typ, nm, nt, data in fragments:
            table += struct.pack("<III", len(data), off, typ)
            table += with_tail(nm.encode().ljust(32, b"\0"), nt) + b"\0" * 64  # (board_id: 16 words)
            off += len(data)
        hdr += struct.pack("<4I", len(table), len(fragments), 108, len(bootconfig))
    out = page_pad(hdr, page) + page_pad(section, page) + page_pad(dtb, page)
    if version == 4:
        out += page_pad(table, page) + page_pad(bootconfig, page)
    return out


# ------------------------------------------------------------- uImage ----

def uimage(data, name, name_tail=b"", *, os_=5, arch=2, typ=2, comp=0, load=0x8000, entry=0x8000, stamp=0x5F000000):
    """U-Boot legacy image (image.h): 64-byte header, big-endian, two CRC-32s."""
    import zlib
    hdr = struct.pack(">7I4B", 0x27051956, 0, stamp, len(data), load, entry, zlib.crc32(data), os_, arch, typ, comp)
    hdr += with_tail(name.encode().ljust(32, b"\0"), name_tail)
    return hdr[:4] + struct.pack(">I", zlib.crc32(hdr)) + hdr[8:] + data


# ---------------------------------------------------------------- AVB ----

def avb_hash_descriptor(partition, salt, digest, image_size, algo=b"sha256"):
    payload = struct.pack(">Q", image_size) + algo.ljust(32, b"\0")
    payload += struct.pack(">IIII", len(partition), len(salt), len(digest), 0) + b"\0" * 60
    payload += partition + salt + digest
    payload += b"\0" * ((-len(payload)) % 8)
    return struct.pack(">QQ", 2, len(payload)) + payload


def avb_property_descriptor(key, val):
    d = struct.pack(">QQ", len(key), len(val)) + key + b"\0" + val + b"\0"
    d += b"\0" * ((-len(d)) % 8)
    return struct.pack(">QQ", 0, len(d)) + d


def avb_footer_image(host, partition, partition_size, salt=b"", fingerprint=b"test/fingerprint/0"):
    """`host` + unsigned vbmeta + 64-byte footer at the end of a
    `partition_size` partition, laid out the way avbtool does: the vbmeta
    blob starts at the next 4096 boundary after `host`, the footer records
    the *unpadded* original size, and the digest covers salt || host."""
    digest = hashlib.sha256(salt + host).digest()
    descs = avb_hash_descriptor(partition, salt, digest, len(host))
    descs += avb_property_descriptor(b"com.android.build." + partition + b".fingerprint", fingerprint)
    desc_size = len(descs)
    aux = descs + b"\0" * ((-desc_size) % 64)
    pubkey_off = desc_size + ((-desc_size) % 8)
    hdr = b"AVB0" + struct.pack(">II", 1, 0) + struct.pack(">QQ", 0, len(aux))
    hdr += struct.pack(">I", 0)  # algorithm NONE
    hdr += struct.pack(">QQQQQQQQQQ", 0, 0, 0, 0, pubkey_off, 0, pubkey_off, 0, 0, desc_size)
    hdr += struct.pack(">Q", 0) + struct.pack(">II", 0, 0)
    hdr += b"avbtool 1.3.0".ljust(48, b"\0") + b"\0" * 80
    assert len(hdr) == 256
    vbmeta = hdr + aux
    vbmeta_off = len(host) + ((-len(host)) % 4096)
    out = bytearray(partition_size)
    assert vbmeta_off + len(vbmeta) <= partition_size - 64
    out[0:len(host)] = host
    out[vbmeta_off:vbmeta_off + len(vbmeta)] = vbmeta
    out[partition_size - 64:] = struct.pack(">4sIIQQQ28x", b"AVBf", 1, 0, len(host), vbmeta_off,
                                            len(vbmeta))
    return bytes(out)


# -------------------------------------------------------------- main ----

def build_all(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)

    def put(name, data):
        (out / name).write_bytes(data)

    kernel = blob(30000)
    ramdisk = gz(blob(60000))
    second = b""

    # --- boot id schemes -------------------------------------------------
    dt = blob(5000)
    put("boot_v0_qcdt_sha1_dt.img", boot_v012(
        0, kernel, ramdisk, dt=dt, cmdline="console=ttyHSL0",
        id_bytes=boot_id(hashlib.sha1, 0, kernel, ramdisk, second, dt=dt)))
    put("boot_v0_nodt_sha1_dt.img", boot_v012(
        0, kernel, ramdisk, cmdline="console=ttyHSL0",
        id_bytes=boot_id(hashlib.sha1, 0, kernel, ramdisk, second, dt=b"")))
    put("boot_v0_sha256.img", boot_v012(
        0, kernel, ramdisk, cmdline="console=ttyHSL0",
        id_bytes=boot_id(hashlib.sha256, 0, kernel, ramdisk, second)))
    put("boot_v0_rawid.img", boot_v012(
        0, kernel, ramdisk, cmdline="console=ttyHSL0", id_bytes=blob(20)))

    # --- header oddities -------------------------------------------------
    put("boot_v3_reserved_hdrsize.img", boot_v34(
        3, kernel, ramdisk, cmdline="bootconfig", reserved=(1, 2, 3, 0xDEADBEEF), hdr_size=1600))
    dtb = blob(1200)
    dtbo = blob(3000)
    put("boot_v1_dtbo_offset.img", boot_v012(
        1, kernel, ramdisk, dtbo=dtbo, dtbo_offset=0x12345000, hdr_size=1650,
        id_bytes=boot_id(hashlib.sha1, 1, kernel, ramdisk, second, dtbo=dtbo)))
    put("boot_v2_header_garbage.img", boot_v012(
        2, kernel, ramdisk, dtb=dtb, hdr_garbage=b"VENDOR-DATA-IN-HEADER-PAGE"))

    # --- a command line longer than the first field: where it is cut -------
    long_cmd = "androidboot.hardware=qcom " + "x" * 700
    put("boot_v0_cmdline512.img", boot_v012(
        0, kernel, ramdisk, cmdline=long_cmd, split=512,
        id_bytes=boot_id(hashlib.sha1, 0, kernel, ramdisk, second)))
    put("boot_v0_cmdline511.img", boot_v012(
        0, kernel, ramdisk, cmdline=long_cmd, split=511,
        id_bytes=boot_id(hashlib.sha1, 0, kernel, ramdisk, second)))

    # --- Marvell PXA headers (Samsung J1, Core Prime, Tab 4 ...) ------------
    pdt, psecond = blob(7000), blob(5000)
    put("boot_pxa_030_dt.img", boot_pxa(
        kernel, ramdisk, dt=pdt, unknown=0x03000000, cmdline="console=ttyS0,115200n8", name="SM-G531F",
        id_bytes=boot_id(hashlib.sha1, 0, kernel, ramdisk, b"", dt=pdt)))
    put("boot_pxa_020_p4096_second.img", boot_pxa(
        kernel, ramdisk, second=psecond, unknown=0x02000000, page=4096, cmdline="androidboot.selinux=permissive",
        name="SM-T230", id_bytes=boot_id(hashlib.sha1, 0, kernel, ramdisk, psecond)))
    put("boot_pxa_028_longcmd.img", boot_pxa(
        kernel, ramdisk, unknown=0x02800000, cmdline=long_cmd, split=511, name="SM-J110F",
        id_bytes=boot_id(hashlib.sha1, 0, kernel, ramdisk, b"")))
    put("boot_pxa_signed.img", boot_pxa(
        kernel, ramdisk, unknown=0x03000000, cmdline="x", name="SM-G388F",
        id_bytes=boot_id(hashlib.sha1, 0, kernel, ramdisk, b""),
        signature=b"SEANDROIDENFORCE" + blob(256)))

    # --- trimmed final padding ------------------------------------------
    full = boot_v012(2, kernel, ramdisk, dtb=dtb, page=2048)
    assert len(full) % 2048 == 0
    # the last component (dtb) ends mid-page; drop the padding a dumper trimmed
    put("boot_v2_trimmed_tail.img", full[:len(full) - ((-len(dtb)) % 2048)])

    # Non-zero bytes in the page padding between components: abr zero-fills
    # padding, so this one must be *reported* by the unpack self-check.
    put("boot_v2_dirty_padding.img", boot_v012(2, kernel, ramdisk, dtb=dtb, dirty_padding=True))

    # --- vendor_boot -----------------------------------------------------
    put("vendor_boot_v4_emptytable_p2048.img",
        vendor_boot_v4_empty_table(gz(blob(40000)), blob(900)))

    # --- tail + partition-size padding ----------------------------------
    host = boot_v012(2, kernel, ramdisk, dtb=dtb, page=2048)
    put("boot_v2_tail_padded.img",
        (host + b"SEANDROIDENFORCE").ljust(1 << 20, b"\0"))

    # --- BFBF/SSSS-like vendor wrapper ----------------------------------
    prefix = bytearray(b"BFBF" + blob(0x4040 - 4))
    prefix[0x4000:0x4004] = b"SSSS"
    inner = boot_v34(4, kernel, ramdisk, cmdline="bootconfig")
    trailer = blob(148) + b"\0" * 8 + b"EEEE" + blob(76)
    put("boot_v4_prefixed_signed.img", bytes(prefix) + inner + b"\0" * 4096 + trailer)

    # --- Barnes & Noble signing headers: a fixed-size block in front ----------
    # (AIK keeps the first 1 MiB -- 256 KiB on the tablets -- as master_boot.key.)
    nook_host = boot_v012(0, kernel, ramdisk, cmdline="console=ttyO2,115200n8 init=/init",
                          id_bytes=boot_id(hashlib.sha1, 0, kernel, ramdisk, b""))
    put("boot_v0_nook.img",
        (b"\0" * 64 + b"Green Loader" + blob((1 << 20) - 64 - 12)) + nook_host)
    put("boot_v0_nooktab.img",
        (b"\0" * 48 + b"BauwksBoot" + blob((256 << 10) - 48 - 10)) + nook_host)

    # --- LG Bump: sixteen constant bytes after the image ----------------------
    bump = bytes([0x41, 0xA9, 0xE4, 0x67, 0x74, 0x4D, 0x1D, 0x1B,
                  0xA4, 0x29, 0xF2, 0xEC, 0xEA, 0x65, 0x52, 0x79])
    put("boot_v0_bump.img", nook_host + bump)
    put("boot_v0_bump_filled.img", (nook_host + bump).ljust(1 << 20, b"\0"))
    put("boot_v0_bump_seandroid.img", nook_host + b"SEANDROIDENFORCE" + bump)

    # --- AVB footer: unaligned host (page 2048, odd page count) ---------
    k = kernel
    host = boot_v012(2, k, ramdisk, dtb=dtb, page=2048, cmdline="avb")
    if len(host) % 4096 == 0:
        k = kernel + blob(2048)  # one more page: a 2048-multiple that is not a 4096-multiple
        host = boot_v012(2, k, ramdisk, dtb=dtb, page=2048, cmdline="avb")
    assert len(host) % 4096 == 2048
    put("boot_v2_avbfooter_unaligned.img",
        avb_footer_image(host, b"boot", 2 << 20, salt=blob(32)))

    # --- AVBv1 (boot_signer): unsigned bases the tests sign ---------------
    # One per way the signed length is computed: plain v0, v0 with a QCDT
    # blob (word 10 = its size), v1 (+ recovery dtbo) and v2 (+ dtb).
    kernel_s, ramdisk_s = blob(24000), gz(blob(40000))
    dtbo_s, dtb_s, dt_s = blob(2500), blob(1700), blob(3100)
    put("avb1_v0.img", boot_v012(
        0, kernel_s, ramdisk_s, cmdline="androidboot.hardware=avb1",
        id_bytes=boot_id(hashlib.sha1, 0, kernel_s, ramdisk_s, b"")))
    put("avb1_v0_qcdt.img", boot_v012(
        0, kernel_s, ramdisk_s, dt=dt_s, cmdline="androidboot.hardware=avb1",
        id_bytes=boot_id(hashlib.sha1, 0, kernel_s, ramdisk_s, b"", dt=dt_s)))
    put("avb1_v1.img", boot_v012(
        1, kernel_s, ramdisk_s, dtbo=dtbo_s, cmdline="androidboot.hardware=avb1",
        id_bytes=boot_id(hashlib.sha1, 1, kernel_s, ramdisk_s, b"", dtbo=dtbo_s)))
    put("avb1_v2.img", boot_v012(
        2, kernel_s, ramdisk_s, dtbo=dtbo_s, dtb=dtb_s, cmdline="androidboot.hardware=avb1",
        id_bytes=boot_id(hashlib.sha1, 2, kernel_s, ramdisk_s, b"", dtbo=dtbo_s, dtb=dtb_s)))

    # --- a filesystem, not a boot image ---------------------------------
    ext4 = bytearray(2 << 20)
    ext4[0x438:0x43A] = b"\x53\xef"
    put("ext4_like.img", bytes(ext4))

    # --- trimmed final padding, the last component then edited -----------------
    # (the RNG is used last, so the images above stay what they were)
    dt_t = blob(5000)
    full0 = boot_v012(0, kernel, ramdisk, dt=dt_t, page=2048, cmdline="console=ttyHSL0")
    put("boot_v0_dt_trimmed.img", full0[:len(full0) - ((-len(dt_t)) % 2048)])  # CAF dt is the last component
    vb_dtb = blob(900)
    vb_full = vendor_boot_v4_empty_table(gz(blob(40000)), vb_dtb)
    put("vendor_boot_v4_trimmed_tail.img", vb_full[:len(vb_full) - ((-len(vb_dtb)) % 2048)])
    # a dump that ends in the middle of the final padding: 300 of its bytes are there, the other 548 are not
    put("boot_v2_partial_padding.img", full[:len(full) - ((-len(dtb)) % 2048) + 300])

    # --- bytes behind the NUL that ends the text of a field ---------------------------------------------------------------
    # A command line cut short in place leaves the rest of the old one behind its NUL ("console=ttyS0" over
    # "console=ttyS0,115200 androidboot.selinux=permissive" -> NUL where the comma was), a tool that never clears
    # the field leaves whatever was there. None of it is text, all of it is part of the image.
    tk, tr, td = blob(20000), gz(blob(30000)), blob(800)
    tid = boot_id(hashlib.sha1, 2, tk, tr, b"", dtb=td)
    old_text = "115200 androidboot.selinux=permissive"
    tails = dict(name_tail=b"OLDNAME", cmd_tail=old_text.encode(), extra_tail=b"\xff" * 30)
    put("boot_v2_tails.img", boot_v012(2, tk, tr, dtb=td, cmdline="console=ttyS0", name="tailtest", id_bytes=tid, **tails))
    put("boot_v2_tails_plain.img", boot_v012(2, tk, tr, dtb=td, cmdline="console=ttyS0", name="tailtest", id_bytes=tid))
    # the same image after the command line was edited: the tail stays behind the NUL of the new text, as far as it fits
    put("boot_v2_tails_short.img", boot_v012(2, tk, tr, dtb=td, cmdline="con", name="tailtest", id_bytes=tid, **tails))
    put("boot_v2_tails_long.img", boot_v012(2, tk, tr, dtb=td, cmdline="x" * 500, name="tailtest", id_bytes=tid, **tails))
    put("boot_v2_tails_full.img", boot_v012(2, tk, tr, dtb=td, cmdline="y" * 511, name="tailtest", id_bytes=tid, **tails))
    # a command line that continues in the second field (cut at 511 by the old C mkbootimg): a tail behind each text
    long_cmd2 = "androidboot.hardware=qcom " + "x" * 700
    put("boot_v0_longcmd_tails.img", boot_v012(
        0, tk, tr, cmdline=long_cmd2, split=511, name="tailtest", extra_tail=b"LEFTOVER", name_tail=b"\x01\x02",
        id_bytes=boot_id(hashlib.sha1, 0, tk, tr, b"")))
    put("boot_v3_tails.img", boot_v34(3, tk, tr, cmdline="bootconfig", cmd_tail=old_text.encode()))
    put("boot_v4_tails.img", boot_v34(4, tk, tr, cmdline="bootconfig", cmd_tail=b"\x00\x00old\x00text"))
    put("boot_pxa_tails.img", boot_pxa(
        tk, tr, cmdline="console=ttyS0", name="SM-G531F", unknown=0x03000000, name_tail=b"\xaa" * 10, cmd_tail=old_text.encode(),
        extra_tail=b"EXTRA", id_bytes=boot_id(hashlib.sha1, 0, tk, tr, b"")))
    vr0, vr1 = gz(blob(9000)), gz(blob(7000))
    put("vendor_boot_v3_tails.img", vendor_boot(
        3, [(0, "", b"", vr0)], dtb=td, cmdline="console=ttyMSM0", name="vendtail", cmd_tail=old_text.encode(),
        name_tail=b"\x07"))
    put("vendor_boot_v4_tails.img", vendor_boot(
        4, [(1, "platform_rd", b"old", vr0), (3, "dlkm_rd", b"\xde\xad\xbe\xef", vr1)], dtb=td,
        cmdline="console=ttyMSM0", name="vendtail", cmd_tail=old_text.encode(), name_tail=b"zz", bootconfig=b"androidboot.x=1\n"))
    put("vendor_boot_v4_tails_plain.img", vendor_boot(
        4, [(1, "platform_rd", b"", vr0), (3, "dlkm_rd", b"", vr1)], dtb=td,
        cmdline="console=ttyMSM0", name="vendtail", bootconfig=b"androidboot.x=1\n"))
    put("uimage_tails.img", uimage(tk, "kernel-tail", name_tail=b"old-name"))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    build_all(sys.argv[1])
