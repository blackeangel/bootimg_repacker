#!/usr/bin/env python3
"""An independent writer and reader of Sony ELF boot images, for the tests of abr.

The layout is that of elftool (github.com/osm0sis/elftool, srl3gx's elfboot.h), the program Android Image Kitchen
packs Xperia kernel.elf images with: a 52-byte ELF32 header (little endian, e_machine 40, e_ident
7f 45 4c 46 01 01 01 61, e_entry the address of the first part, e_phoff 52, e_phentsize 32), one 32-byte program
header per part, zeros up to byte 4096, and then the parts one behind the other without padding. A part is the
kernel (p_flags 0), the ramdisk (0x80000000), the ipl (0x40000000), the rpm (0x01000000) or the command line
(0x20000000, p_type 4 and the address 0); every other part is PT_LOAD with p_vaddr = p_paddr, p_filesz = p_memsz
and p_align 0.

This shares no code with abr (src/legacy/elf_boot.cpp); where the real elftool is at hand the test suite makes it
write the same images (ABR_ELFTOOL).

  elf_tool.py make OUT part [part ...]     part = role=FILE@ADDRESS  (role: kernel ramdisk ipl rpm cmdline;
                                           ADDRESS in hex, omitted for the cmdline)
  elf_tool.py parts IMAGE DIR              write every part of IMAGE to DIR/<role>[.N], and DIR/header (the first 4096 bytes)
  elf_tool.py list IMAGE                   one line per part: role flags offset address size
"""
import os
import struct
import sys

IDENT = bytes([0x7F, 0x45, 0x4C, 0x46, 1, 1, 1, 0x61]) + bytes(8)
FLAGS = {"kernel": 0, "ramdisk": 0x80000000, "ipl": 0x40000000, "cmdline": 0x20000000, "rpm": 0x01000000}
ROLE_OF = {v: k for k, v in FLAGS.items()}
DATA_START = 4096


def make(parts, machine=40):
    """parts: [(role, address, data)] in file order; the first one is the one whose address is e_entry."""
    out = bytearray(IDENT)
    out += struct.pack("<HHIIIIIHHHHHH", 2, machine, 1, parts[0][1], 52, 0, 0, 52, 32, len(parts), 0, 0, 0)
    offset = DATA_START
    placed = []
    for role, address, data in parts:
        placed.append(offset)
        ptype = 4 if role == "cmdline" else 1
        out += struct.pack("<IIIIIIII", ptype, offset, address, address, len(data), len(data), FLAGS[role], 0)
        offset += len(data)
    out += bytes(DATA_START - len(out))
    for role, address, data in parts:
        out += data
    return bytes(out)


def read(image):
    """[(role, flags, offset, address, data)] of an image written the way make() writes one."""
    assert image[:8] == IDENT[:8], "not an elftool image"
    phoff, phentsize, phnum = struct.unpack_from("<IHH", image, 28)[0], *struct.unpack_from("<HH", image, 42)
    parts = []
    for i in range(phnum):
        ptype, off, vaddr, paddr, filesz, memsz, flags, align = struct.unpack_from("<8I", image, phoff + i * phentsize)
        parts.append((ROLE_OF.get(flags, "extra"), flags, off, paddr, image[off:off + filesz]))
    return parts


def main(argv):
    if len(argv) >= 3 and argv[1] == "make":
        parts = []
        for spec in argv[3:]:
            role, rest = spec.split("=", 1)
            path, _, addr = rest.partition("@")
            with open(path, "rb") as f:
                data = f.read()
            parts.append((role, int(addr, 16) if addr else 0, data))
        with open(argv[2], "wb") as f:
            f.write(make(parts))
        return 0
    if len(argv) == 4 and argv[1] == "parts":
        with open(argv[2], "rb") as f:
            image = f.read()
        os.makedirs(argv[3], exist_ok=True)
        with open(os.path.join(argv[3], "header"), "wb") as f:
            f.write(image[:DATA_START])
        seen = {}
        for role, flags, off, addr, data in read(image):
            n = seen.get(role, 0)
            seen[role] = n + 1
            with open(os.path.join(argv[3], role + ("" if n == 0 else ".%d" % n)), "wb") as f:
                f.write(data)
        return 0
    if len(argv) == 3 and argv[1] == "list":
        with open(argv[2], "rb") as f:
            image = f.read()
        for role, flags, off, addr, data in read(image):
            print("%s flags=0x%08x offset=%d address=0x%x size=%d" % (role, flags, off, addr, len(data)))
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
