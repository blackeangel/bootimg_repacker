#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Boot sectors of FAT volumes written from the specification (not from abr), and bytes that are not: FAT12/16/32 volumes (the partitions of Qualcomm
phones that hold firmware, NON-HLOS.bin and the like, are FAT), a boot loader's jump without a BPB, BPBs with numbers that cannot be, GPT headers.

  mk_fatboot.py OUTDIR
"""
import os, struct, sys
out = sys.argv[1]
os.makedirs(out, exist_ok=True)

def bpb(sector, per_cluster, reserved, fats, root_entries, total, media, fat_sectors, fat32=False):
    b = bytearray(512)
    b[0:3] = b"\xEB\x3C\x90"
    b[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBH", b, 11, sector, per_cluster, reserved, fats, root_entries)
    if total < 65536:
        struct.pack_into("<H", b, 19, total)
    else:
        struct.pack_into("<I", b, 32, total)
    b[21] = media
    if fat32:
        struct.pack_into("<I", b, 36, fat_sectors)
        b[82:90] = b"FAT32   "
    else:
        struct.pack_into("<H", b, 22, fat_sectors)
        b[54:62] = b"FAT16   "          # (the text is only informative: abr must not trust it)
    b[510], b[511] = 0x55, 0xAA
    return bytes(b)

def write(name, data, pad=4096):
    open(os.path.join(out, name), "wb").write(data + bytes(max(0, pad - len(data))))

write("fat12.img", bpb(512, 1, 1, 2, 224, 2880, 0xF0, 9))               # a 1.44 MB floppy
write("fat16.img", bpb(512, 4, 4, 2, 512, 131072, 0xF8, 128))            # 64 MiB, 2 KiB clusters
write("fat32.img", bpb(512, 8, 32, 2, 0, 1048576, 0xF8, 1025, True))     # 512 MiB, 4 KiB clusters
write("fat16_4k.img", bpb(4096, 1, 1, 1, 512, 20000, 0xF8, 10))          # 4096-byte sectors (a text that says FAT32 where the numbers say FAT16 is not believed)
# not FAT
mbr = bytearray(512); mbr[0:3] = b"\xEB\x63\x90"; mbr[510], mbr[511] = 0x55, 0xAA   # a boot loader's jump, no BPB
write("not_fat_mbr.img", bytes(mbr))
bad = bytearray(bpb(512, 3, 1, 2, 224, 2880, 0xF0, 9)); write("not_fat_cluster3.img", bytes(bad))   # 3 sectors a cluster
bad = bytearray(bpb(512, 1, 0, 2, 224, 2880, 0xF0, 9)); write("not_fat_no_reserved.img", bytes(bad))
bad = bytearray(bpb(512, 1, 1, 2, 224, 2880, 0x10, 9)); write("not_fat_media.img", bytes(bad))
bad = bytearray(bpb(512, 1, 1, 2, 224, 20, 0xF0, 9)); write("not_fat_total.img", bytes(bad))      # the FATs alone are bigger than the volume
write("zeros.img", bytes(4096))
# GPT: a protective MBR and the header at LBA 1 (512-byte sectors), or at LBA 1 of 4096-byte sectors
g = bytearray(8192); g[510], g[511] = 0x55, 0xAA; g[512:520] = b"EFI PART"; write("gpt512.img", bytes(g))
g = bytearray(8192); g[510], g[511] = 0x55, 0xAA; g[4096:4104] = b"EFI PART"; write("gpt4k.img", bytes(g))
