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
              hdr_size=None, dtb_addr=0, dirty_padding=False, hdr_garbage=b""):
    """boot.img header v0/v1/v2. A non-empty `dt` on a v0 header is the
    Qualcomm/CAF layout: word 10 holds the dt size instead of the version."""
    word10 = len(dt) if (version == 0 and dt) else version
    cmd = cmdline.encode()
    hdr = b"ANDROID!"
    hdr += struct.pack("<10I", len(kernel), 0x8000, len(ramdisk), 0x1000000, len(second),
                       0xF00000, 0x100, page, word10, os_version)
    hdr += name.encode().ljust(16, b"\0")
    hdr += cmd[:512].ljust(512, b"\0")
    hdr += id_bytes.ljust(32, b"\0")
    hdr += cmd[512:].ljust(1024, b"\0")
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


def boot_v34(version, kernel, ramdisk, *, cmdline="", os_version=0, reserved=(0, 0, 0, 0),
             hdr_size=None, signature=b""):
    hdr = b"ANDROID!"
    hdr += struct.pack("<4I", len(kernel), len(ramdisk), os_version,
                       hdr_size or (1580 if version == 3 else 1584))
    hdr += struct.pack("<4I", *reserved) + le32(version)
    hdr += cmdline.encode().ljust(1536, b"\0")
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

    # --- AVB footer: unaligned host (page 2048, odd page count) ---------
    k = kernel
    host = boot_v012(2, k, ramdisk, dtb=dtb, page=2048, cmdline="avb")
    if len(host) % 4096 == 0:
        k = kernel + blob(2048)  # one more page: a 2048-multiple that is not a 4096-multiple
        host = boot_v012(2, k, ramdisk, dtb=dtb, page=2048, cmdline="avb")
    assert len(host) % 4096 == 2048
    put("boot_v2_avbfooter_unaligned.img",
        avb_footer_image(host, b"boot", 2 << 20, salt=blob(32)))

    # --- a filesystem, not a boot image ---------------------------------
    ext4 = bytearray(2 << 20)
    ext4[0x438:0x43A] = b"\x53\xef"
    put("ext4_like.img", bytes(ext4))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    build_all(sys.argv[1])
