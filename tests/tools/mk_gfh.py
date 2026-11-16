#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic MediaTek preloader images (GFH chain), built from the layout of U-Boot's tools/mtk_image.h.
usage: mk_gfh.py OUTDIR   -- writes raw_sha256.bin, emmc_sha256.img, raw_sig5.bin, emmc_none.img, raw_gzip_loader.bin, sf_boot.img
"""
import gzip, hashlib, os, struct, sys, zlib


def gfh(version, typ, body):
    return struct.pack('<I', 0x4D4D4D | (version << 24)) + struct.pack('<HH', 8 + len(body), typ) + body


def pattern(n, seed):
    return bytes((seed + i * 13 + (i >> 7)) & 0xFF for i in range(n))


def chain(sig_type, load, max_size, sec_key, payload_len, sig_len, jump=None):
    bl_info = struct.pack('<I', 1)
    brom_cfg = bytearray(92)
    struct.pack_into('<I', brom_cfg, 0, 0x90)
    struct.pack_into('<I', brom_cfg, 80, 5000)
    anti = bytearray(12)
    struct.pack_into('<II', anti, 4, 0x10, 0x80)
    sec = bytearray(40)
    struct.pack_into('<I', sec, 0, 3)
    rest = gfh(1, 1, bl_info) + gfh(1, 7, bytes(brom_cfg)) + gfh(1, 2, bytes(anti)) + gfh(1, 8, bytes(sec))
    rest += gfh(1, 3, pattern(0x20c, 77)) if sec_key else b'\0' * 4
    hdr = 56 + len(rest)
    total = hdr + payload_len + sig_len
    fi = bytearray(48)
    fi[0:9] = b'FILE_INFO'
    struct.pack_into('<I', fi, 12, 1)
    struct.pack_into('<H', fi, 16, 1)
    fi[18] = 5
    fi[19] = sig_type
    struct.pack_into('<IIIIII', fi, 20, load, total, max_size, hdr, sig_len, hdr if jump is None else jump)
    struct.pack_into('<I', fi, 44, 0xC2600001)
    return gfh(1, 0, bytes(fi)) + rest


def raw(sig_type, payload, sig=None, sec_key=False, load=0x200f10, max_size=0x80000):
    sig_len = 32 if sig_type == 1 else (len(sig) if sig is not None else 0)
    c = chain(sig_type, load, max_size, sec_key, len(payload), sig_len)
    body = c + payload
    if sig_type == 1:
        body += hashlib.sha256(body).digest()
    elif sig:
        body += sig
    return body


def partition(inner, boot_name=b'EMMC_BOOT', brlyt_type=0x10005, at=0x800, align=0x200):
    n = (at + len(inner) + align - 1) // align * align
    d = bytearray(b'\xff' * n)
    d[at:at + len(inner)] = inner
    d[0:12] = boot_name.ljust(12, b'\0')
    struct.pack_into('<II', d, 12, 1, 0x200)
    d[0x200:0x208] = b'BRLYT\0\0\0'
    struct.pack_into('<IIIIIIII', d, 0x208, 1, at, n, 0x42424242, brlyt_type, at, n, 1)
    d[0x228:0x400] = b'\0' * (0x400 - 0x228)
    return bytes(d)


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    code = pattern(20000, 5)
    open(f'{out}/raw_sha256.bin', 'wb').write(raw(1, code))
    open(f'{out}/emmc_sha256.img', 'wb').write(partition(raw(1, code)))
    open(f'{out}/raw_sig5.bin', 'wb').write(raw(5, code, sig=pattern(0x66c, 201)))
    open(f'{out}/emmc_none.img', 'wb').write(partition(raw(0, code, sig=b'', sec_key=True, load=0x200d00, max_size=0x40000)))
    zcode = gzip.compress(bytes((i * 7 + (i >> 5)) & 0xFF for i in range(30000)) + b'preloader ' * 200, 9, mtime=0)
    open(f'{out}/raw_gzip_loader.bin', 'wb').write(raw(1, zcode))
    open(f'{out}/sf_boot.img', 'wb').write(partition(raw(1, code), boot_name=b'SF_BOOT', brlyt_type=0x10007))
    print('ok')
