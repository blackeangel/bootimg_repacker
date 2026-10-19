#!/usr/bin/env python3
"""An independent writer and reader of Sony ELF boot images, for the tests of abr.

The layout of what elftool writes (github.com/osm0sis/elftool, srl3gx's elfboot.h -- the program Android Image Kitchen
packs Xperia kernel.elf images with) is the default: a 52-byte ELF32 header (little endian, e_machine 40, e_ident
7f 45 4c 46 01 01 01 61, e_entry the address of the first part, e_phoff 52, e_phentsize 32), one 32-byte program
header per part, zeros up to byte 4096, and then the parts one behind the other without padding. A part is the
kernel (p_flags 0), the ramdisk (0x80000000), the ipl (0x40000000), the rpm (0x01000000) or the command line
(0x20000000, p_type 4 and the address 0); every other part is PT_LOAD with p_vaddr = p_paddr, p_filesz = p_memsz
and p_align 0.

build() writes other layouts as well, for the images that are not elftool's: another size of the block in front of
the data, padding between the parts and something behind them, an e_entry of its own, p_align, p_memsz beyond
p_filesz, another OS/ABI byte, data in another order than the program headers, an ELF64 header.

This shares no code with abr (src/legacy/elf_boot.cpp); where the real elftool is at hand the test suite makes it
write the same images (ABR_ELFTOOL).

  elf_tool.py make OUT part [part ...]     part = role=FILE@ADDRESS  (role: kernel ramdisk ipl rpm cmdline;
                                           ADDRESS in hex, omitted for the cmdline)
  elf_tool.py parts IMAGE DIR              write every part of IMAGE to DIR/seg<N> (N = the number of its program header),
                                           DIR/header (the block in front of the data) and DIR/index.txt
  elf_tool.py list IMAGE                   one line per part: role flags offset address size
  elf_tool.py catalog DIR CPIO             write the images the tests use to DIR: <name>.img and <name>.json for every
                                           layout in CASES (the ramdisk of all of them is the gzip of the cpio archive
                                           CPIO), and DIR/index.txt: name, layout (elftool or kept),
                                           whether the real elftool takes it (yes or no), description (tab separated)
  elf_tool.py oracle ELFTOOL IMAGE WORKDIR the real elftool (built from its source) packs the parts of IMAGE (an image
                                           in elftool's layout), with the block in front of the data as its header: the
                                           result is IMAGE; and what it unpacks of IMAGE is those parts
  elf_tool.py rebuild SPEC IMAGE OUT [--kernel FILE] [--addr0 HEX] [--canonical]
                                           what the writer makes of the layout in SPEC (a <name>.json of catalog) when
                                           the data of its parts is the data of IMAGE's segments (and, with --kernel, the
                                           first part is FILE; with --addr0 it has that address): the image the same
                                           layout would come out as after an edit. --canonical: elftool's layout instead
"""
import os
import struct
import sys

FLAGS = {"kernel": 0, "ramdisk": 0x80000000, "ipl": 0x40000000, "cmdline": 0x20000000, "rpm": 0x01000000}
ROLE_OF = {v: k for k, v in FLAGS.items()}
DATA_START = 4096


def build(parts, machine=40, is64=False, start=DATA_START, pads=None, pad_fill=0, tail=b"", entry=None, osabi=0x61,
          e_flags=0, e_type=2, align=0, memsz_extra=None, file_order=None, phoff=None, hdr_fill=0, ptypes=None,
          paddr_delta=None, shnum=0, memsz=None):
    """parts: [(role, address, data)] in program header order (role: a name of FLAGS, or the p_flags themselves).
    start: where the first data goes (the size of the block in front of it); pads: the bytes between the data of the
    parts, in file order (n - 1 numbers); tail: what follows the last part; entry: e_entry (default: the address of the
    first part); align: p_align of every part; memsz_extra: {index: bytes} added to p_memsz; file_order: the order
    of the data in the file (default: that of the program headers); phoff: where the program headers are (default:
    behind the ELF header); hdr_fill: the byte that fills the block in front of the data where nothing else is;
    ptypes: {index: p_type}; paddr_delta: {index: p_paddr - p_vaddr}; memsz: {index: p_memsz} (instead of the size
    of the data plus memsz_extra)."""
    n = len(parts)
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    phoff = ehsize if phoff is None else phoff
    order = list(range(n)) if file_order is None else list(file_order)
    pads = list(pads) if pads is not None else [0] * max(n - 1, 0)
    memsz_extra = memsz_extra or {}
    memsz = memsz or {}
    ptypes = ptypes or {}
    paddr_delta = paddr_delta or {}
    assert phoff + n * phentsize <= start, "the program headers do not fit in front of the data"
    offsets = [0] * n
    cursor = start
    for k, idx in enumerate(order):
        offsets[idx] = cursor
        cursor += len(parts[idx][2]) + (pads[k] if k < len(pads) else 0)
    entry = parts[0][1] if entry is None else entry

    ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2 if is64 else 1, 1, 1, osabi]) + bytes(8)
    if is64:
        head = ident + struct.pack("<HHIQQQIHHHHHH", e_type, machine, 1, entry, phoff, 0, e_flags, ehsize, phentsize, n,
                                   0, shnum, 0)
    else:
        head = ident + struct.pack("<HHIIIIIHHHHHH", e_type, machine, 1, entry, phoff, 0, e_flags, ehsize, phentsize, n,
                                   0, shnum, 0)
    assert len(head) == ehsize
    block = bytearray(bytes([hdr_fill]) * start)
    block[:ehsize] = head
    for i, (role, address, data) in enumerate(parts):
        flags = role if isinstance(role, int) else FLAGS[role]
        ptype = ptypes.get(i, 4 if role == "cmdline" else 1)
        paddr = address + paddr_delta.get(i, 0)
        msz = memsz.get(i, len(data) + memsz_extra.get(i, 0))
        if is64:
            ph = struct.pack("<IIQQQQQQ", ptype, flags, offsets[i], address, paddr, len(data), msz, align)
        else:
            ph = struct.pack("<IIIIIIII", ptype, offsets[i], address, paddr, len(data), msz, flags, align)
        block[phoff + i * phentsize:phoff + (i + 1) * phentsize] = ph
    out = bytearray(block)
    for k, idx in enumerate(order):
        out += parts[idx][2]
        if k < len(pads) and k + 1 < len(order):
            out += bytes([pad_fill]) * pads[k]
    out += tail
    return bytes(out)


def make(parts, machine=40):
    """elftool's layout: parts is [(role, address, data)]; the first one is the one whose address is e_entry."""
    return build(parts, machine=machine)


def read(image):
    """(header, segments) of any ELF image: the header as a dict, the segments as dicts that have the program header's
    fields and `data` (what p_offset and p_filesz point at)."""
    assert image[:4] == b"\x7fELF", "not an ELF"
    is64 = image[4] == 2
    if is64:
        (e_type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", image, 16)
    else:
        (e_type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum,
         shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", image, 16)
    hdr = dict(is64=is64, osabi=image[7], type=e_type, machine=machine, entry=entry, phoff=phoff, flags=flags,
               ehsize=ehsize, phentsize=phentsize, phnum=phnum, shnum=shnum)
    segs = []
    for i in range(phnum):
        at = phoff + i * phentsize
        if is64:
            ptype, pflags, off, vaddr, paddr, filesz, memsz, palign = struct.unpack_from("<IIQQQQQQ", image, at)
        else:
            ptype, off, vaddr, paddr, filesz, memsz, pflags, palign = struct.unpack_from("<8I", image, at)
        segs.append(dict(type=ptype, flags=pflags, offset=off, vaddr=vaddr, paddr=paddr, filesz=filesz, memsz=memsz,
                         align=palign, data=image[off:off + filesz]))
    return hdr, segs


def role_of(seg):
    return ROLE_OF.get(seg["flags"], "extra")


def _scrub(b):
    """No 53 EF in the data: at byte 1080 it would make an ext2/3/4 image of the file (identify looks there)."""
    return b.replace(b"\x53\xef", b"\x53\xee")


def _gzip(data):
    import zlib

    c = zlib.compressobj(9, zlib.DEFLATED, 31)
    return c.compress(data) + c.flush()


KERNEL_ADDR, RAMDISK_ADDR, IPL_ADDR, RPM_ADDR = 0x80208000, 0x81800000, 0x20000000, 0x30000000
KERNEL64_ADDR = 0xFFFFFFC000080000

# (name, description, layout the way elftool writes it?, the parts that are there, build() options). The data of the
# parts is the same in all of them (the cases below only say which part is there): kernel 40000 bytes, ramdisk the
# gzip of the archive, cmdline, ipl 3000 bytes, rpm 2000 bytes, dtb 3000 bytes.
CASES = [
    ("elftool3", "kernel, ramdisk and command line in elftool's layout", True, ["kernel", "ramdisk", "cmdline"], {}),
    ("elftool5", "kernel, ramdisk, ipl, rpm and command line in elftool's layout", True,
     ["kernel", "ramdisk", "ipl", "rpm", "cmdline"], {}),
    ("kernel_only", "a kernel and nothing else", True, ["kernel"], {}),
    ("ramdisk_empty", "an empty ramdisk segment (elftool's layout)", True, ["kernel", "ramdisk0", "cmdline"], {}),
    ("unflagged3", "three segments without flags: kernel, ramdisk and an extra one by position", True,
     ["kernel:0", "ramdisk:0", "dtb:0"], {}),
    ("elf64", "elftool's layout with an ELF64 header", True, ["kernel64", "ramdisk", "cmdline"], dict(is64=True)),
    ("start8k", "the data starts at byte 8192", False, ["kernel", "ramdisk", "cmdline"], dict(start=8192)),
    ("tight", "the data right behind the program headers", False, ["kernel", "ramdisk", "cmdline"], dict(start=148)),
    ("pads_tail", "padding between the segments and bytes behind the last", False, ["kernel", "ramdisk", "cmdline"],
     dict(pads=[100, 7], pad_fill=0xA5, tail="9f" * 35)),
    ("entry_abi", "an e_entry of its own, OS/ABI 0, p_align, p_memsz beyond p_filesz", False,
     ["kernel", "ramdisk", "cmdline"], dict(entry=0x1234, osabi=0, align=0x1000, memsz_extra={"0": 50})),
    ("order", "the data in another order than the program headers", False, ["kernel", "ramdisk", "cmdline"],
     dict(file_order=[1, 0, 2], pads=[3, 4])),
    ("hdr_fill", "the block in front of the data is not zeros", False, ["kernel", "ramdisk", "cmdline"], dict(hdr_fill=0x5A)),
    ("paddr", "a p_paddr that is not the p_vaddr of the kernel", False, ["kernel", "ramdisk", "cmdline"],
     dict(paddr_delta={"0": -0x4000})),
    ("phoff", "the program headers are not right behind the ELF header", False, ["kernel", "ramdisk", "cmdline"],
     dict(phoff=256)),
    ("empty_kept", "an empty ramdisk segment in a layout that is not elftool's", False, ["kernel", "ramdisk0", "cmdline"],
     dict(pads=[10, 0], tail="7e" * 5)),
    ("elf64_all", "ELF64 with an e_entry, padding, a tail, p_align and another machine", False,
     ["kernel64", "ramdisk", "cmdline"], dict(is64=True, start=0x2000, pads=[16, 0], tail="7878", align=0x1000,
                                              entry=KERNEL64_ADDR + 0x40, machine=183)),
]


def _case_parts(kinds, data):
    out = []
    for kind in kinds:
        name, _, flags = kind.partition(":")
        if name == "kernel":
            out.append((int(flags) if flags else "kernel", KERNEL_ADDR, data["kernel"]))
        elif name == "kernel64":
            out.append(("kernel", KERNEL64_ADDR, data["kernel"]))
        elif name == "ramdisk":
            out.append((int(flags) if flags else "ramdisk", RAMDISK_ADDR, data["ramdisk"]))
        elif name == "ramdisk0":
            out.append(("ramdisk", RAMDISK_ADDR, b""))
        elif name == "ipl":
            out.append(("ipl", IPL_ADDR, data["ipl"]))
        elif name == "rpm":
            out.append(("rpm", RPM_ADDR, data["rpm"]))
        elif name == "dtb":
            out.append((int(flags), 0x82000000, data["dtb"]))
        elif name == "cmdline":
            out.append(("cmdline", 0, data["cmdline"]))
        else:
            raise SystemExit("unknown part " + kind)
    return out


def _options(opts):
    """build() keyword arguments from the JSON form of a case's options (keys of dicts are strings there)."""
    o = dict(opts)
    for key in ("memsz_extra", "paddr_delta", "memsz", "ptypes"):
        if key in o:
            o[key] = {int(k): v for k, v in o[key].items()}
    if "tail" in o:
        o["tail"] = bytes.fromhex(o["tail"])
    return o


def catalog(outdir, cpio_path, seed=20261018):
    import json
    import random

    rnd = random.Random(seed)
    with open(cpio_path, "rb") as f:
        cpio = f.read()
    data = {"kernel": _scrub(rnd.randbytes(40000)), "ramdisk": _gzip(cpio),
            "cmdline": b"console=ttyS0,115200 androidboot.hardware=elftest\0", "ipl": _scrub(rnd.randbytes(3000)),
            "rpm": _scrub(rnd.randbytes(2000)), "dtb": _scrub(rnd.randbytes(3000))}
    os.makedirs(outdir, exist_ok=True)
    index = []
    for name, desc, canonical, kinds, opts in CASES:
        parts = _case_parts(kinds, data)
        image = build(parts, **_options(opts))
        assert image[1080:1082] != b"\x53\xef" and image[:4] == b"\x7fELF", name  # (at 1080 it would be an ext4 image)
        spec = dict(name=name, description=desc, canonical=canonical, options=opts,
                    parts=[dict(role=r, addr=a, size=len(d)) for r, a, d in parts])
        with open(os.path.join(outdir, name + ".img"), "wb") as f:
            f.write(image)
        with open(os.path.join(outdir, name + ".json"), "w") as f:
            json.dump(spec, f)
        # (the real elftool packs and unpacks images of two parts or more in elftool's layout, ELF32, with the flags it knows)
        real = canonical and not opts.get("is64") and len(parts) >= 2 and all(isinstance(r, str) for r, _, _ in parts)
        index.append("%s\t%s\t%s\t%s" % (name, "elftool" if canonical else "kept", "yes" if real else "no", desc))
    with open(os.path.join(outdir, "index.txt"), "w") as f:
        f.write("\n".join(index) + "\n")


def rebuild(spec_path, image_path, out_path, kernel=None, addr0=None, canonical=False):
    """The image the layout of the case `spec_path` comes out as when its parts are the segments of `image_path`: the
    block in front of the data, the padding, the tail, e_entry, p_align, the OS/ABI byte and every other field the
    case sets are what they were; the sizes and offsets are those of the data; a p_memsz that was beyond p_filesz stays
    where it was unless the data outgrows it; a p_paddr that was not the p_vaddr stays where it was."""
    import json

    with open(spec_path) as f:
        spec = json.load(f)
    with open(image_path, "rb") as f:
        _, segs = read(f.read())
    opts = _options(spec["options"])
    parts = []
    for i, p in enumerate(spec["parts"]):
        data = segs[i]["data"]
        addr = p["addr"]
        if i == 0 and kernel:
            with open(kernel, "rb") as f:
                data = f.read()
        if i == 0 and addr0 is not None:
            if opts.get("paddr_delta", {}).get(0):  # a p_paddr of its own stays where it was
                opts["paddr_delta"][0] += addr - addr0
            addr = addr0
        parts.append((p["role"], addr, data))
    # p_memsz: what it was beyond the data, unless the data is longer than that now
    memsz = {}
    for i, extra in opts.pop("memsz_extra", {}).items():
        if extra:
            memsz[i] = max(spec["parts"][i]["size"] + extra, len(parts[i][2]))
    if memsz:
        opts["memsz"] = memsz
    if canonical:
        opts = {k: v for k, v in opts.items() if k in ("is64", "machine")}
    with open(out_path, "wb") as f:
        f.write(build(parts, **opts))


def oracle(elftool, image, work):
    """0 when the real elftool agrees with this reader and writer on `image` (which has to be in elftool's layout), else
    1 (and says what differs): it packs the parts this reader finds, with the 4096 bytes in front of the data as its
    header, into the image; and what it unpacks is those parts. (Not the unpack of an image with an rpm segment: elftool's
    source has no `break` behind `case p_flags_rpm`, so it writes the rpm over the ramdisk.)"""
    import shutil
    import subprocess

    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.join(work, "p"))
    os.makedirs(os.path.join(work, "u"))

    def run(*args):
        r = subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        return r.returncode, r.stdout.decode("latin-1")

    with open(image, "rb") as f:
        data = f.read()
    _, segs = read(data)
    roles = [role_of(s) for s in segs]
    if len(set(roles)) != len(roles) or "extra" in roles:
        print("elftool knows a kernel, a ramdisk, an ipl, an rpm and a command line, once each: %s" % roles)
        return 1
    header = os.path.join(work, "header")
    with open(header, "wb") as f:
        f.write(data[:DATA_START])
    args = [elftool, "pack", "-o", os.path.join(work, "packed.img"), "header=" + header]
    for s, role in zip(segs, roles):
        path = os.path.join(work, "p", role)
        with open(path, "wb") as f:
            f.write(s["data"])
        args.append(path if role == "kernel" else path + "@cmdline" if role == "cmdline" else "%s,%s" % (path, role))
    rc, out = run(*args)
    if rc != 0:
        print("elftool pack failed (%d): %s" % (rc, out[-300:]))
        return 1
    with open(os.path.join(work, "packed.img"), "rb") as f:
        if f.read() != data:
            print("what elftool packs from the parts of %s is not %s" % (image, image))
            return 1
    if "rpm" in roles:
        return 0
    rc, out = run(elftool, "unpack", "-i", image, "-o", os.path.join(work, "u"))
    if rc != 0:
        print("elftool unpack failed (%d): %s" % (rc, out[-300:]))
        return 1
    for s, role in zip(segs, roles):
        path = os.path.join(work, "u", role)
        if not os.path.exists(path):
            print("elftool wrote no file for the %s" % role)
            return 1
        with open(path, "rb") as f:
            if f.read() != s["data"]:
                print("the %s that elftool unpacks is not the one this reader finds" % role)
                return 1
    return 0


def main(argv):
    if len(argv) == 5 and argv[1] == "oracle":
        return oracle(argv[2], argv[3], argv[4])
    if len(argv) == 4 and argv[1] == "catalog":
        catalog(argv[2], argv[3])
        return 0
    if len(argv) >= 5 and argv[1] == "rebuild":
        opts = argv[5:]
        rebuild(argv[2], argv[3], argv[4],
                kernel=opts[opts.index("--kernel") + 1] if "--kernel" in opts else None,
                addr0=int(opts[opts.index("--addr0") + 1], 16) if "--addr0" in opts else None,
                canonical="--canonical" in opts)
        return 0
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
        hdr, segs = read(image)
        first = min((s["offset"] for s in segs if s["filesz"]), default=len(image))
        with open(os.path.join(argv[3], "header"), "wb") as f:
            f.write(image[:first])
        lines = []
        for i, s in enumerate(segs):
            with open(os.path.join(argv[3], "seg%d" % i), "wb") as f:
                f.write(s["data"])
            lines.append("%d %s flags=0x%08x offset=%d address=0x%x size=%d" % (i, role_of(s), s["flags"], s["offset"], s["vaddr"], s["filesz"]))
        with open(os.path.join(argv[3], "index.txt"), "w") as f:
            f.write("\n".join(lines) + "\n")
        return 0
    if len(argv) == 3 and argv[1] == "list":
        with open(argv[2], "rb") as f:
            image = f.read()
        hdr, segs = read(image)
        print("class=%d entry=0x%x machine=%d osabi=0x%02x" % (64 if hdr["is64"] else 32, hdr["entry"], hdr["machine"], hdr["osabi"]))
        for s in segs:
            print("%s flags=0x%08x offset=%d address=0x%x size=%d" % (role_of(s), s["flags"], s["offset"], s["vaddr"], s["filesz"]))
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
