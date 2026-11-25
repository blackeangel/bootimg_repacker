#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""kernel_info/ -- what `abr unpack` writes about the kernel of an image -- judged by programs that are not abr.

The driver builds kernels that carry what kernel_info/ is made of, the way a kernel carries it: the banner, the strings that a module's vermagic and
the command line parser leave, IKCONFIG, the kallsyms tables (written here from the description in scripts/kallsyms.c, in every layout), initramfs
archives (made by `cpio`, plain and gzip), certificates and keys (made by `openssl`), device trees (made by `dtc`), an ELF file (made by `gcc`) and a
compressed device tree. It puts them in the containers that hold kernels -- a boot image of header version 0 (the kernel plain and gzip) and 4, a U-Boot
uImage and a FIT with two kernels (made by `mkimage`), a Sony ELF, a Rockchip KRNL, an Intel OSIP image -- and checks what abr writes:

  * every piece is where it is (the offsets in summary.txt) and is what it is: the config is the text that went in, kallsyms.txt is the table that was
    written, a certificate says what `openssl x509` says of it, an archive is listed by `cpio -t` and its folder holds the files that were archived, a
    tree is compiled back by `dtc` to the blob that was in the kernel, an ELF file is read by `readelf`
  * `pack` never reads kernel_info/: the image comes back byte for byte with the folder there, gone, changed, replaced by a file or by a FIFO
  * unpacking again replaces what abr wrote before (and only that), `--no-kernel-info` writes nothing and removes what an earlier unpack wrote, a folder
    that is somebody's is not touched, the second kernel of an image is kernel_info_2
  * the number of threads changes nothing of what is written
  * damaged kernels (bytes changed inside every piece, cut short) never make an unpack fail, and what was unpacked packs again
  * with the real images of a directory (ABR_REAL_IMAGES): the symbols are checked against the kernel itself -- the address of `linux_proc_banner` minus
    the address of the banner that abr found is where "%s version %s (" has to be, `__initramfs_start` is where the initramfs is, the config is what
    zlib makes of the stream, the certificates are what openssl says they are

  kinfo_live.py ABR WORKDIR [REAL_IMAGE_DIRECTORY]

One FAIL line for each check that does not hold; exit status 1 when there is one. `cpio`, `dtc`, `openssl`, `mkimage`, `readelf` and `gcc` are the judges
and the makers; a piece whose program is not installed is a SKIP line and the rest runs.
"""
import datetime
import gzip
import hashlib
import importlib.util
import lzma
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import zlib

TOOLS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOLS)
from livelib import Live, manifest_get, read, same_bytes, write  # noqa: E402

ABR, WORK = sys.argv[1:3]
REAL = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" and os.path.isdir(sys.argv[3]) else None
live = Live(ABR, WORK)
spec = importlib.util.spec_from_file_location("fixtures", os.path.join(TOOLS, "fixtures.py"))
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)

HAVE = {name: shutil.which(name) is not None for name in ("openssl", "cpio", "dtc", "mkimage", "readelf", "gcc")}
WINE = "/winebin/" in ABR.replace("\\", "/")  # abr.exe under wine (tests/run_tests.sh): every run starts a process of its own, and a link or a FIFO is not what Windows has


def skip(what, tool):
    print("SKIP: %s (%s is not installed)" % (what, tool))


def tool(*args, cwd=None, data=None, timeout=60):
    """-> (status, stdout bytes, stderr text) of a program that judges or makes something."""
    r = subprocess.run(list(args), cwd=cwd, input=data, capture_output=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace")


# ================================================================================================================ what a kernel carries ==
RELEASE = "5.10.43-abr-kinfo"
BUILDER = "builder@abr-host"
COMPILER = "gcc (GCC) 11.2.0, GNU ld (GNU Binutils) 2.37"
BUILD = "#7 SMP PREEMPT Thu Jun 3 12:00:00 UTC 2021"
BANNER = "Linux version %s (%s) (%s) %s\n" % (RELEASE, BUILDER, COMPILER, BUILD)
PROC_BANNER = "%s version %s (%s) (%s) %s\n"
VERMAGIC = RELEASE + " SMP preempt mod_unload aarch64 "
ANDROIDBOOT = ["androidboot.hardware=%s", "androidboot.serialno=", "androidboot.verifiedbootstate=", "androidboot.slot_suffix="]

CONFIG_LINES = (
    ["#", "# Automatically generated file; DO NOT EDIT.", "# Linux/arm64 5.10.43 Kernel Configuration", "#"]
    + ["CONFIG_%s=y" % n for n in ("ARM64", "MMU", "SMP", "PREEMPT", "MODULES", "KALLSYMS", "KALLSYMS_ALL", "IKCONFIG", "IKCONFIG_PROC", "BLK_DEV_INITRD",
                                    "ANDROID", "SECURITY_SELINUX", "DM_VERITY", "EFI")]
    + ["CONFIG_%s=m" % n for n in ("USB_ACM", "NLS_UTF8", "ZRAM")]
    + ["# CONFIG_%s is not set" % n for n in ("DEBUG_INFO", "KASAN", "MODULE_SIG", "PROFILING")]
    + ['CONFIG_LOCALVERSION="-abr-kinfo"', "CONFIG_LOG_BUF_SHIFT=17", 'CONFIG_CMDLINE=""', "CONFIG_ARM64_VA_BITS=39"]
)
CONFIG_YES = sum(1 for l in CONFIG_LINES if l.endswith("=y"))
CONFIG_MODULES = sum(1 for l in CONFIG_LINES if l.endswith("=m"))
CONFIG_NOT_SET = sum(1 for l in CONFIG_LINES if l.endswith("is not set"))
CONFIG_VALUES = sum(1 for l in CONFIG_LINES if l.startswith("CONFIG_") and not l.endswith(("=y", "=m")))
CONFIG_TEXT = "\n".join(CONFIG_LINES) + "\n"


# --------------------------------------------------------------------------------------------------------------------------- kallsyms --
# scripts/kallsyms.c: addresses (or offsets and a base), the number of symbols, the names (a length and the tokens of the name; the first character of a
# name is its type), a marker for every 256th name, the token table (256 NUL-terminated strings, the digits at their own places) and the index of it.
def ks_compress(names):
    """names: bytes (type and name). -> (the 256 tokens, the names written with them)"""
    used = {b for n in names for b in n}
    table = [bytes([i]) if i in used else b"" for i in range(256)]
    seqs = [list(n) for n in names]
    for token in [i for i in range(256) if i not in used]:
        counts = {}
        for s in seqs:
            for a, b in zip(s, s[1:]):
                counts[(a, b)] = counts.get((a, b), 0) + 1
        if not counts:
            break
        pair, n = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
        if n < 3:
            break
        table[token] = table[pair[0]] + table[pair[1]]
        out = []
        for s in seqs:
            o, k = [], 0
            while k < len(s):
                if k + 1 < len(s) and (s[k], s[k + 1]) == pair:
                    o.append(token)
                    k += 2
                else:
                    o.append(s[k])
                    k += 1
            out.append(o)
        seqs = out
    return table, [bytes(s) for s in seqs]


def ks_table(symbols, at, *, big=False, address_size=8, relative=False, count_size=4, marker_size=4, align=8, base=None):
    """The kallsyms arrays for `symbols` ((address, type, name), ascending), as they lie from the offset `at` on (each array aligned to `align` from
    the start of the kernel). -> (bytes, where) with where: names, markers, token_table, addresses, count, relative_base."""
    e = ">" if big else "<"
    ucode = {1: "B", 2: "H", 4: "I", 8: "Q"}
    out = bytearray()
    where = {}

    def aligned():
        out.extend(b"\0" * ((-(at + len(out))) % align))
        return at + len(out)

    where["addresses"] = aligned()
    if relative:
        base = symbols[0][0] if base is None else base
        for a, _, _ in symbols:
            out += struct.pack(e + "i", a - base)
        where["relative_base"] = aligned()
        out += struct.pack(e + ucode[address_size], base)
    else:
        for a, _, _ in symbols:
            out += struct.pack(e + ucode[address_size], a)
    where["count"] = aligned()
    out += struct.pack(e + ucode[count_size], len(symbols))
    table, coded = ks_compress([t.encode() + n.encode() for _, t, n in symbols])
    where["names"] = aligned()
    markers, names = [], bytearray()
    for i, c in enumerate(coded):
        if i % 256 == 0:
            markers.append(len(names))
        assert len(c) < 128
        names += bytes([len(c)]) + c
    out += names
    where["names_end"] = at + len(out)
    where["markers"] = aligned()
    for m in markers:
        out += struct.pack(e + ucode[marker_size], m)
    where["token_table"] = aligned()
    index = []
    for t in table:
        index.append(len(out) - (where["token_table"] - at))
        out += t + b"\0"
    where["token_index"] = aligned()
    for i in index:
        out += struct.pack(e + "H", i)
    return bytes(out), where


def ks_text(symbols, address_size=8):
    """kallsyms.txt: the way /proc/kallsyms prints a table."""
    return "".join("%0*x %s %s\n" % (2 * address_size, a, t, n) for a, t, n in symbols)


def make_symbols(count, base, specials):
    """`count` symbols with addresses from `base` on, and the `specials` ({name: (offset from base, type)}); sorted, as a kernel's table is."""
    rnd = random.Random(count * 7919 + base % 9973)
    syms = {}
    for name, (offset, kind) in specials.items():
        syms[name] = (base + offset, kind, name)
    kinds = "TtTtDdRrBbAWw"
    for i in range(count - len(specials)):
        name = "%s_%04d_%s" % (rnd.choice(["sys", "do", "vfs", "kmem", "arm64", "ext4", "tcp", "pm", "blk", "dev"]), i,
                               rnd.choice(["open", "read", "write", "init", "exit", "alloc", "free", "0123456789", "handler", "mmap"]))
        syms[name] = (base + 0x4000 + i * 0x10 + rnd.randrange(8), rnd.choice(kinds), name)
    return sorted(syms.values(), key=lambda s: (s[0], s[2]))


# ----------------------------------------------------------------------------------------------------------------------- the pieces --
def make_certs():
    """-> a dict of what openssl makes: der (EC, DER), pem (RSA, the PEM text), key (the PEM text of a private key); None when openssl is missing."""
    if not HAVE["openssl"]:
        return None
    d = live.fresh("certs")
    os.makedirs(d)
    out = {}
    for name, newkey, subj in (("ec", ["ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"], "/CN=abr kinfo live EC/O=abr tests"),
                               ("rsa", ["rsa:2048"], "/CN=abr kinfo live RSA")):
        rc, _, err = tool("openssl", "req", "-x509", "-newkey", *newkey, "-nodes", "-keyout", os.path.join(d, name + ".key"), "-out",
                          os.path.join(d, name + ".crt"), "-days", "3650", "-subj", subj, "-sha256")
        if rc != 0:
            live.check(False, "openssl makes the %s certificate" % name, err)
            return None
    rc, der, err = tool("openssl", "x509", "-in", os.path.join(d, "ec.crt"), "-outform", "DER")
    live.check(rc == 0 and der[:1] == b"\x30", "openssl writes the EC certificate as DER", err)
    out["der"] = der
    out["pem"] = read(os.path.join(d, "rsa.crt")).decode()
    rc, key, err = tool("openssl", "pkey", "-in", os.path.join(d, "ec.key"))
    live.check(rc == 0 and key.startswith(b"-----BEGIN PRIVATE KEY-----"), "openssl writes the private key as PEM", err)
    out["key"] = key.decode()
    return out


def make_initramfs():
    """-> (the newc archive that cpio makes of a small tree, the folder it was made of); None when cpio is missing."""
    if not HAVE["cpio"]:
        return None
    root = live.fresh("initramfs_src")
    for rel, content in (("init", b"#!/system/bin/sh\nexec /system/bin/init\n"), ("etc/hosts", b"127.0.0.1 localhost\n"), ("etc/fstab", b"/dev/block/vda / ext4 ro 0 0\n" * 20),
                         ("system/bin/sh", b"\x7fELF-not-really"), ("res/images/logo.bin", bytes(range(256)) * 9)):
        write_path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(write_path), exist_ok=True)
        write(write_path, content)
    os.makedirs(os.path.join(root, "dev"))
    os.makedirs(os.path.join(root, "proc"))
    if os.name != "nt" and not WINE:
        os.symlink("/system/bin/sh", os.path.join(root, "sbin_sh"))
        os.chmod(os.path.join(root, "init"), 0o750)
    names = sorted(os.path.relpath(os.path.join(a, n), root) for a, ds, fs in os.walk(root) for n in ds + fs)
    rc, archive, err = tool("cpio", "-o", "-H", "newc", "--quiet", cwd=root, data="\n".join(names).encode() + b"\n")
    live.check(rc == 0 and archive[:6] == b"070701", "cpio makes the initramfs archive", err)
    return archive, root, names


def make_dtb(name, model):
    """-> the blob that dtc makes of a source with strings, cells, bytes, a label that is a phandle and a node with an address; None without dtc."""
    if not HAVE["dtc"]:
        return None
    src = live.path(name + ".dts")
    write(src, ("/dts-v1/;\n/ {\n  model = \"%s\";\n  compatible = \"abr,kinfo\", \"abr,test\";\n  #address-cells = <1>;\n  #size-cells = <1>;\n"
                "  interrupt-parent = <&gic>;\n  chosen { bootargs = \"console=ttyS0,115200 androidboot.hardware=abr\"; stdout-path = \"serial0:115200n8\"; };\n"
                "  memory@80000000 { device_type = \"memory\"; reg = <0x80000000 0x10000000>; };\n"
                "  gic: interrupt-controller@1000 { compatible = \"arm,gic-400\"; interrupt-controller; #interrupt-cells = <3>; reg = <0x1000 0x1000>; };\n"
                "  serial0: serial@2000 { reg = <0x2000 0x100>; interrupts = <0 5 4>; status = \"okay\"; mac = [00 11 22 33 44 55]; };\n};\n" % model).encode())
    dtb = live.path(name + ".dtb")
    rc, _, err = tool("dtc", "-q", "-I", "dts", "-O", "dtb", "-o", dtb, src)
    if not live.check(rc == 0, "dtc compiles the device tree %s" % name, err):
        return None
    return read(dtb)


def make_elf():
    """-> a small ELF file that gcc links; None without gcc."""
    if not HAVE["gcc"]:
        return None
    src, exe = live.path("elf_piece.c"), live.path("elf_piece.elf")
    write(src, b"void _start(void) { for (;;) { } }\nint kinfo_live_value = 7;\n")
    rc, _, err = tool("gcc", "-nostdlib", "-static", "-Os", "-s", "-Wl,--build-id=none,-z,noseparate-code", "-o", exe, src)
    if rc != 0:
        rc, _, err = tool("gcc", "-nostdlib", "-static", "-Os", "-s", "-o", exe, src)
    if not live.check(rc == 0, "gcc links an ELF file", err):
        return None
    return read(exe)


def arm64_header(image_size, text_offset=0x80000, flags=0xA):
    """The 64-byte header of an arm64 Image (Documentation/arm64/booting.rst)."""
    h = struct.pack("<II", 0x14000010, 0) + struct.pack("<QQQ", text_offset, image_size, flags) + b"\0" * 24 + b"ARM\x64" + b"\0" * 4
    assert len(h) == 64
    return h


def zimage_of(inner):
    """An ARM zImage: the magic 0x016f2818 and the end of the image in the stub, the gzip stream of `inner` behind 4 KiB of stub, a little code after it.
    -> (the image, where the stream is)"""
    stub = bytearray(0x1000)
    struct.pack_into("<III", stub, 0x24, 0x016f2818, 0, 0)
    image = bytearray(bytes(stub) + fx.gz(inner) + b"\x00\x00\xa0\xe1" * 200)
    struct.pack_into("<I", image, 0x2c, len(image))
    return bytes(image), 0x1000


def bzimage_of(inner, setup_sects=4):
    """An x86 bzImage of boot protocol 2.15: the setup code with "HdrS", the offset and the length of the payload, and the payload (the gzip stream of
    `inner`) behind 512 bytes of protected-mode code. -> (the image, where the stream is)"""
    setup = bytearray((setup_sects + 1) * 512)
    setup[0x1f1] = setup_sects
    setup[0x202:0x206] = b"HdrS"
    struct.pack_into("<H", setup, 0x206, 0x020f)
    gz = fx.gz(inner)
    struct.pack_into("<II", setup, 0x248, 0x200, len(gz))
    return bytes(setup) + bytes(0x200) + gz + bytes(64), (setup_sects + 1) * 512 + 0x200


class Built:
    """A kernel and what is known of every piece in it: the offsets that abr has to report and the bytes that have to come out."""

    def __init__(self, size):
        self.data = bytearray(size)
        self.at = {}
        self.size = {}
        self.what = {}

    def put(self, name, at, blob):
        assert at + len(blob) <= len(self.data), name
        assert not any(self.data[at:at + len(blob)]), name + ": the room is not free"
        self.data[at:at + len(blob)] = blob
        self.at[name] = at
        self.size[name] = len(blob)
        return at

    def bytes(self):
        return bytes(self.data)


KERNEL_SIZE = 0x22000
BASE = 0xffffffc010080000


def build_kernel(*, variant=None, release=RELEASE, parts=("banner", "config", "kallsyms", "initramfs", "certs", "dtb", "elf", "gzdtb"), extras=None):
    """The synthetic kernel. `variant`: the keyword arguments of ks_table() for its table."""
    k = Built(KERNEL_SIZE)
    k.what["release"] = release
    banner = BANNER.replace(RELEASE, release)
    proc = PROC_BANNER
    k.put("header", 0, arm64_header(KERNEL_SIZE))
    if "banner" in parts:
        k.put("proc_banner", 0x1000, proc.encode())
        k.put("banner", 0x1040, banner.encode())
        k.put("vermagic", 0x2000, (VERMAGIC.replace(RELEASE, release)).encode() + b"\0")
        at = 0x3000
        for s in ANDROIDBOOT:
            k.put("androidboot " + s, at, s.encode() + b"\0")
            at += 64
    if "config" in parts:
        k.put("config", 0x4000, b"IKCFG_ST" + gzip.compress(CONFIG_TEXT.encode(), 9, mtime=0) + b"IKCFG_ED")
        k.what["config_gz_at"] = 0x4000 + 8
        k.what["config_gz_len"] = len(gzip.compress(CONFIG_TEXT.encode(), 9, mtime=0))
    if "kallsyms" in parts:
        v = dict(variant or dict(relative=True))
        asz = v.get("address_size", 8)
        base = BASE if asz == 8 else 0xc0008000
        specials = {"_text": (0, "T"), "_stext": (0x800, "T"), "linux_proc_banner": (0x1000, "D"), "linux_banner": (0x1040, "D"),
                    "__initramfs_start": (0x14000, "T"), "kinfo_digits_0123456789": (0x4100, "d")}
        symbols = make_symbols(v.pop("count", 700), base, specials)
        blob, where = ks_table(symbols, 0x8000, base=base, **v)
        assert 0x8000 + len(blob) <= 0x10000
        k.put("kallsyms", 0x8000, blob)
        k.what["symbols"] = symbols
        k.what["ks_where"] = where
        k.what["ks_base"] = base
        k.what["ks_variant"] = dict(v, address_size=asz)
    certs = make_certs() if "certs" in parts else None
    if certs:
        k.put("cert_der", 0x1000d, certs["der"])
        k.put("cert_pem", 0x10800, certs["pem"].encode())
        k.put("key_pem", 0x11800, certs["key"].encode())
        k.what["certs"] = certs
    if "initramfs" in parts:
        made = make_initramfs()
        if made:
            archive, root, names = made
            k.put("cpio_plain", 0x14000, archive)
            k.put("cpio_gz", 0x18000, fx.gz(archive))
            k.what["cpio"] = (archive, root, names)
    if "dtb" in parts:
        dtb = make_dtb("kernel_tree", "abr kinfo live")
        if dtb:
            k.put("dtb", 0x5000, dtb)  # early: a tree with less than 64 KiB behind it is taken for a glued one (Image-dtb), and cut off the kernel
            k.what["dtb"] = dtb
    if "elf" in parts:
        elf = make_elf()
        if elf:
            assert len(elf) < 0x2000, len(elf)
            k.put("elf", 0x1d000, elf)
            k.what["elf"] = elf
    if "gzdtb" in parts:
        dtb2 = make_dtb("kernel_tree_gz", "abr kinfo live, the compressed one")
        if dtb2:
            k.put("gzdtb", 0x1f001, fx.gz(dtb2))
            k.what["gzdtb"] = dtb2
    for name, (at, blob) in (extras or {}).items():
        k.put(name, at, blob)
    return k


# =============================================================================================================================== judges ==
def unpack(image, out, *flags, env=None, expect=0):
    rc, text = live.run("unpack", "-i", image, "-o", out, *flags, env=env)
    live.check(rc == expect, "unpack %s %s ends with status %d" % (os.path.basename(image), " ".join(flags), expect), "status %d: %s" % (rc, text[-400:]))
    return text


def pack_same(folder, original, what):
    """`pack` of the folder is the image it came from, byte for byte."""
    out = live.fresh("packed.img")
    rc, text = live.run("pack", "-i", folder, "-o", out, timeout=60)
    ok = live.check(rc == 0, "%s: pack succeeds" % what, text[-300:])
    if ok:
        ok = live.check(same_bytes(out, original), "%s: pack gives back the image, byte for byte" % what)
    return ok


def summary_of(folder):
    return read(os.path.join(folder, "summary.txt")).decode("utf-8", "replace")


def field(text, label):
    """The text of a line of summary.txt: two blanks, the label, blanks, the text."""
    m = re.search(r"^  %s\s+(.*)$" % re.escape(label), text, re.M)
    return m.group(1) if m else None


def section(text, name):
    """The lines of summary.txt under the heading `name` (up to the blank line)."""
    m = re.search(r"^%s[^\n]*\n((?:.+\n)*)" % re.escape(name), text, re.M)
    return m.group(1) if m else ""


def first_difference(a, b):
    n = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    return "first difference at %d (abr %r, expected %r)" % (n, a[n:n + 24], b[n:n + 24])


def tree_of(folder):
    """{relative path: bytes (a file), "->target" (a link), None (a folder)} of a folder; what a comparison of two unpacks needs."""
    out = {}
    for a, ds, fs in os.walk(folder):
        for n in ds:
            out[os.path.relpath(os.path.join(a, n), folder)] = None
        for n in fs:
            p = os.path.join(a, n)
            out[os.path.relpath(p, folder)] = ("->" + os.readlink(p)) if os.path.islink(p) else read(p)
    return out


def write_and_return(path, data):
    write(path, data)
    return path


def hex_(n):
    return "0x%x" % n


def size_text(n):
    """The way summary.txt writes a size: 746 bytes, 4656 bytes (4.5 KiB), 3145728 bytes (3.0 MiB)."""
    if n >= 1 << 20:
        return "%d bytes (%.1f MiB)" % (n, n / (1 << 20))
    if n >= 4096:
        return "%d bytes (%.1f KiB)" % (n, n / 1024)
    return "%d bytes" % n


def check_symbol_lines(label, sy, k):
    """The lines of SYMBOLS in summary.txt that are not the places of the tables: what the table is (the number of symbols, the byte order, the size of an
    address, the layout and its base), how the symbols divide into text and data, and the addresses of the symbols a person looks for first."""
    syms, v = k.what["symbols"], k.what["ks_variant"]
    asz = v["address_size"]
    layout = ("offsets from the base %s (kallsyms_offsets)" % hex_(k.what["ks_base"])) if v.get("relative") else "the address of every symbol (kallsyms_addresses)"
    head = "  %d symbols; %s endian, %d-bit addresses; %s\n" % (len(syms), "big" if v.get("big") else "little", 8 * asz, layout)
    live.check(sy.startswith(head), "%s: the first line of SYMBOLS (the number, the byte order, the size of an address, the layout)" % label, sy[:200])
    text = sum(1 for _, t, _ in syms if t in "Tt")
    data = sum(1 for _, t, _ in syms if t in "DdRrBbAaGgSsVvWw")
    live.check(("  %d of text (T t), %d of data and other kinds, %d not told\n" % (text, data, len(syms) - text - data)) in sy, "%s: the division of the symbols" % label, sy[:400])
    for name in ("_text", "_stext", "_etext", "_end", "linux_banner"):
        found = [a for a, _, n in syms if n == name]
        line = "  %-14s%s\n" % (name, hex_(found[0])) if found else None
        live.check((line in sy) if line else (("  %-14s0x" % name) not in sy), "%s: the address of %s" % (label, name), sy[-300:])


# --------------------------------------------------------------------------------------------------------------------------------------
def check_kernel_info(label, info, k, *, header=True, payload=None):
    """Everything that kernel_info/ of the kernel `k` (a Built) has to say, piece by piece. `info`: the folder. `header`: the kernel is an arm64 Image and
    its header is described; `payload`: the bytes of payload.bin (a zImage or bzImage: the offsets are those of the kernel inside it), None when there is none."""
    s = summary_of(info)
    readme = read(os.path.join(info, "README.txt")).decode("utf-8", "replace")
    live.check(readme.startswith("abr kernel_info"), "%s: README.txt is abr's" % label, readme[:60])
    if payload is None:
        live.check(not os.path.exists(os.path.join(info, "payload.bin")), "%s: no payload.bin for a kernel that is not a zImage" % label)
    else:
        path = os.path.join(info, "payload.bin")
        live.check(os.path.isfile(path) and read(path) == payload, "%s: payload.bin is the kernel that the compressed stream holds" % label)
        live.check(s.startswith("abr kernel_info") and "offsets are those of payload.bin" in s.split("\n")[1], "%s: summary.txt says that its offsets are those of payload.bin" % label, s[:200])

    # --- the image
    if header:
        kind = field(s, "kind") or ""
        live.check(kind.startswith("arm64 Image, %d bytes" % KERNEL_SIZE), "%s: the kind of kernel and its size" % label, kind)
        live.check((field(s, "text_offset") or "").startswith("0x80000"), "%s: text_offset of the header" % label, field(s, "text_offset"))
        live.check((field(s, "image_size") or "").startswith("0x%x (%d bytes)" % (KERNEL_SIZE, KERNEL_SIZE)), "%s: image_size of the header" % label, field(s, "image_size"))
        live.check(field(s, "flags") == "0xa: little endian, 4 KiB pages, placed anywhere in memory", "%s: the flags of the header (0xa)" % label, field(s, "flags"))

    # --- the version
    release = k.what["release"]
    live.check(field(s, "release") == release, "%s: release" % label, field(s, "release"))
    live.check(field(s, "built by") == BUILDER, "%s: built by" % label, field(s, "built by"))
    live.check(field(s, "compiler") == COMPILER, "%s: compiler" % label, field(s, "compiler"))
    live.check(field(s, "build") == BUILD, "%s: build" % label, field(s, "build"))
    live.check((field(s, "vermagic") or "").startswith(release + " SMP preempt mod_unload aarch64"), "%s: vermagic" % label, field(s, "vermagic"))
    m = re.search(r"^  banner\s+at (0x[0-9a-f]+): (.*)$", s, re.M)
    live.check(bool(m) and int(m.group(1), 16) == k.at["banner"], "%s: the banner is at %s" % (label, hex_(k.at["banner"])), m.group(1) if m else s[:300])
    live.check(bool(m) and m.group(2).startswith("Linux version " + release), "%s: the banner text" % label, m.group(2)[:80] if m else "")
    for p in ANDROIDBOOT:
        live.check(p in s, "%s: the androidboot parameter %s is listed" % (label, p), s[:200])

    # --- the config
    if "config" in k.at:
        cfg = os.path.join(info, "config")
        live.check(os.path.isfile(cfg) and read(cfg) == CONFIG_TEXT.encode(), "%s: config is the text that went into IKCONFIG" % label,
                   first_difference(read(cfg), CONFIG_TEXT.encode()) if os.path.isfile(cfg) else "no file")
        c = section(s, "CONFIGURATION")
        want = "gzip stream at %s, %d bytes" % (hex_(k.what["config_gz_at"]), k.what["config_gz_len"])
        live.check(want in c, "%s: the config stream is at %s" % (label, hex_(k.what["config_gz_at"])), c[:200])
        live.check("%d options: %d =y, %d =m, %d with a value, %d not set" % (CONFIG_YES + CONFIG_MODULES + CONFIG_VALUES + CONFIG_NOT_SET, CONFIG_YES, CONFIG_MODULES,
                                                                              CONFIG_VALUES, CONFIG_NOT_SET) in c, "%s: the numbers of options" % label, c[:300])
    else:
        live.check(not os.path.exists(os.path.join(info, "config")), "%s: no config file when the kernel has none" % label)

    # --- the symbols
    if "symbols" in k.what:
        asz = k.what["ks_variant"]["address_size"]
        want = ks_text(k.what["symbols"], asz)
        got = read(os.path.join(info, "kallsyms.txt")).decode("utf-8", "replace") if os.path.isfile(os.path.join(info, "kallsyms.txt")) else ""
        live.check(got == want, "%s: kallsyms.txt is the table that was written (%d symbols)" % (label, len(k.what["symbols"])), first_difference(got.encode(), want.encode()))
        sy = section(s, "SYMBOLS")
        w = k.what["ks_where"]
        live.check(("names at %s..%s, markers at %s, token table at %s, addresses at %s" % (hex_(w["names"]), hex_(w["names_end"]), hex_(w["markers"]),
                                                                                         hex_(w["token_table"]), hex_(w["addresses"]))) in sy, "%s: where the tables are" % label, sy[:400])
        live.check(("%d symbols" % len(k.what["symbols"])) in sy, "%s: the number of symbols" % label, sy[:200])
        check_symbol_lines(label, sy, k)
    else:
        live.check(not os.path.exists(os.path.join(info, "kallsyms.txt")), "%s: no kallsyms.txt for a kernel without the table" % label)

    # --- the initramfs archives
    if "cpio" in k.what:
        archive, root, names = k.what["cpio"]
        ini = section(s, "INITRAMFS")
        for n, (piece, stored, how) in enumerate((("cpio_plain", len(archive), "cpio archive"), ("cpio_gz", len(fx.gz(archive)), "gzip stream that holds a cpio archive"))):
            stem = "initramfs" if n == 0 else "initramfs%d" % (n + 1)
            live.check(("at %s: %s" % (hex_(k.at[piece]), how)) in ini, "%s: the archive %d is at %s (%s)" % (label, n + 1, hex_(k.at[piece]), how), ini[:400])
            cpio_file = os.path.join(info, stem + ".cpio")
            if not live.check(os.path.isfile(cpio_file), "%s: %s.cpio is written" % (label, stem)):
                continue
            body = read(cpio_file)
            live.check(body.startswith(b"070701") and b"TRAILER!!!" in body, "%s: %s.cpio is an archive" % (label, stem), body[:20])
            if n == 0:  # plain: up to the end of the entry of the trailer (a name makes the entry a multiple of 4); what cpio pads the archive with is not in it
                end = (archive.rfind(b"TRAILER!!!") + len(b"TRAILER!!!\0") + 3) & ~3
                live.check(body == archive[:end] and not any(archive[end:]), "%s: %s.cpio is the archive that was in the kernel, up to the end of the trailer" % (label, stem),
                           "%d bytes, expected %d" % (len(body), end))
            else:  # gzip: what the stream holds, all of it
                live.check(body == archive, "%s: %s.cpio is what the gzip stream held" % (label, stem), "%d bytes, expected %d" % (len(body), len(archive)))
            if HAVE["cpio"]:
                rc, listing, err = tool("cpio", "-it", "--quiet", data=body)
                got = sorted(l for l in listing.decode("utf-8", "replace").split("\n") if l and l != ".")
                live.check(rc == 0 and got == sorted(names), "%s: cpio -t lists the archive %d the way it was made" % (label, n + 1), "%s %s" % (got[:8], err))
            tree = os.path.join(info, stem)
            live.check(os.path.isdir(tree) and os.path.isfile(os.path.join(info, stem + ".meta")), "%s: %s/ and %s.meta are written" % (label, stem, stem))
            for name in names:
                src, dst = os.path.join(root, name), os.path.join(tree, name)
                if os.path.islink(src):
                    live.check(os.path.islink(dst) and os.readlink(dst) == os.readlink(src), "%s: %s/%s is the link that was archived" % (label, stem, name))
                elif os.path.isdir(src):
                    live.check(os.path.isdir(dst), "%s: %s/%s is a folder" % (label, stem, name))
                else:
                    live.check(same_bytes(src, dst), "%s: %s/%s has the bytes that were archived" % (label, stem, name))
    else:
        live.check(not os.path.exists(os.path.join(info, "initramfs.cpio")), "%s: no initramfs.cpio for a kernel without an archive" % label)

    # --- the certificates and keys
    if "certs" in k.what:
        check_certificates(label, info, s, k)
    else:
        live.check(not os.path.exists(os.path.join(info, "certs")), "%s: no certs/ for a kernel without a certificate" % label)

    # --- device trees and ELF files
    check_binaries(label, info, s, k)


def check_certificates(label, info, s, k):
    certs = k.what["certs"]
    folder = os.path.join(info, "certs")
    files = sorted(os.listdir(folder)) if os.path.isdir(folder) else []
    ders = [f for f in files if f.endswith(".der")]
    pems = [f for f in files if f.endswith(".pem")]
    live.check(len(ders) == 1 and len(pems) == 2 and len(files) == 6, "%s: certs/ holds the DER certificate, the PEM certificate and the PEM key, each with its text" % label, files)
    # the names: the place of the object in the kernel, then the CN of the subject (or what the PEM block says it is) with what a file name cannot hold turned into _
    live.check(files == ["00-abr_kinfo_live_EC.der", "00-abr_kinfo_live_EC.txt", "01-abr_kinfo_live_RSA.pem", "01-abr_kinfo_live_RSA.txt", "02-PRIVATE_KEY.pem", "02-PRIVATE_KEY.txt"],
               "%s: the names of the files in certs/ are the number and the CN" % label, files)
    cs = section(s, "CERTIFICATES AND KEYS")
    live.check(("at %s: DER CERTIFICATE, %d bytes" % (hex_(k.at["cert_der"]), len(certs["der"]))) in cs, "%s: the DER certificate is at %s" % (label, hex_(k.at["cert_der"])), cs[:300])
    live.check(("at %s: PEM CERTIFICATE" % hex_(k.at["cert_pem"])) in cs, "%s: the PEM certificate is at %s" % (label, hex_(k.at["cert_pem"])), cs[:300])
    live.check(("at %s: PEM PRIVATE KEY" % hex_(k.at["key_pem"])) in cs, "%s: the PEM key is at %s" % (label, hex_(k.at["key_pem"])), cs[:300])
    for f in ders:
        live.check(read(os.path.join(folder, f)) == certs["der"], "%s: %s is the DER that was in the kernel" % (label, f))
        judge_certificate(label, os.path.join(folder, f), "DER", os.path.join(folder, f[:-4] + ".txt"), "CN=abr kinfo live EC")
    for f in pems:
        body = read(os.path.join(folder, f)).decode("utf-8", "replace")
        if "PRIVATE KEY" in body:
            live.check(body == certs["key"], "%s: %s is the PEM key that was in the kernel" % (label, f), body[:60])
            txt = read(os.path.join(folder, f[:-4] + ".txt")).decode("utf-8", "replace")
            live.check("private key" in txt and ("offset %s," % hex_(k.at["key_pem"])) in txt, "%s: the text of the key says what it is and where" % label, txt[:200])
            if HAVE["openssl"]:
                rc, _, err = tool("openssl", "pkey", "-in", os.path.join(folder, f), "-noout")
                live.check(rc == 0, "%s: openssl reads the key that abr wrote" % label, err)
        else:
            live.check(body == certs["pem"], "%s: %s is the PEM certificate that was in the kernel" % (label, f), body[:60])
            judge_certificate(label, os.path.join(folder, f), "PEM", os.path.join(folder, f[:-4] + ".txt"), "CN=abr kinfo live RSA")


def judge_certificate(label, path, form, txt_path, subject):
    """What abr's text of a certificate says is what `openssl x509` says: the subject, the serial, the dates, the signature, the key and the sha256."""
    if not HAVE["openssl"]:
        return
    txt = read(txt_path).decode("utf-8", "replace")
    rc, out, err = tool("openssl", "x509", "-inform", form, "-in", path, "-noout", "-serial", "-dates", "-fingerprint", "-sha256", "-text")
    if not live.check(rc == 0, "%s: openssl reads %s" % (label, os.path.basename(path)), err):
        return
    o = out.decode("utf-8", "replace")
    serial = re.search(r"^serial=([0-9A-Fa-f]+)", o, re.M)
    mine = re.search(r"^serial:\s+([0-9a-f]+)$", txt, re.M)
    live.check(bool(serial) and bool(mine) and int(mine.group(1), 16) == int(serial.group(1), 16), "%s: the serial of %s" % (label, os.path.basename(path)), txt[:300])
    fp = re.search(r"Fingerprint=([0-9A-F:]+)", o)
    live.check(bool(fp) and ("sha256:     " + fp.group(1).replace(":", "").lower()) in txt, "%s: the sha256 of %s is openssl's fingerprint" % (label, os.path.basename(path)), txt[:300])
    live.check(("subject:    " + subject) in txt or ("subject:    " + subject + ",") in txt, "%s: the subject of %s" % (label, os.path.basename(path)), txt[:200])
    dates = {m.group(1): m.group(2) for m in re.finditer(r"^(notBefore|notAfter)=(.*)$", o, re.M)}
    fmt = lambda s: datetime.datetime.strptime(" ".join(s.split()), "%b %d %H:%M:%S %Y GMT").strftime("%Y-%m-%d %H:%M:%S UTC")
    if len(dates) == 2:
        live.check(("valid:      %s to %s" % (fmt(dates["notBefore"]), fmt(dates["notAfter"]))) in txt, "%s: the dates of %s" % (label, os.path.basename(path)), txt[:300])
    sig = re.search(r"Signature Algorithm:\s*(\S+)", o)
    live.check(bool(sig) and ("signature:  " + sig.group(1)).lower() in txt.lower(), "%s: the signature algorithm of %s" % (label, os.path.basename(path)), txt[:300])
    name = os.path.basename(path)
    if "Public Key Algorithm: rsaEncryption" in o:
        bits, exponent = re.search(r"Public-Key: \((\d+) bit\)", o), re.search(r"Exponent: (\d+)", o)
        live.check(bool(bits) and bool(exponent) and ("key:        RSA %s bits, exponent %s" % (bits.group(1), exponent.group(1))) in txt, "%s: the RSA key of %s" % (label, name), txt[:300])
    elif "id-ecPublicKey" in o:
        curve = re.search(r"ASN1 OID: (\S+)", o)
        live.check(bool(curve) and re.search(r"^key:\s+EC\b.*\b%s\b" % re.escape(curve.group(1)), txt, re.M) is not None, "%s: the EC key of %s" % (label, name), txt[:300])
    else:
        live.check(False, "%s: a kind of key that the driver does not know (%s)" % (label, name), o[:300])


def check_binaries(label, info, s, k):
    files = sorted(os.listdir(os.path.join(info, "binaries"))) if os.path.isdir(os.path.join(info, "binaries")) else []
    fs = section(s, "FILES INSIDE THE KERNEL")
    expect = []
    if "dtb" in k.what:
        expect.append(("dtb", k.at["dtb"], k.what["dtb"], "", "dtb"))
    if "elf" in k.what:
        expect.append(("elf", k.at["elf"], k.what["elf"], "", "elf"))
    if "gzdtb" in k.what:
        expect.append(("dtb", k.at["gzdtb"], k.what["gzdtb"], "_from_gzip", "gzdtb"))
    expect.sort(key=lambda e: e[1])
    live.check(len(re.findall(r"^  at 0x", fs, re.M)) == len(expect), "%s: the files inside the kernel are %d" % (label, len(expect)), fs[:600])
    for n, (kind, at, blob, how, piece) in enumerate(expect):
        base = "%02d_%s_%x%s" % (n, kind, at, how)
        ext = "elf" if kind == "elf" else "dtb"
        # the line of summary.txt for this file, whole: where, how big, what it is, and where it was written to
        stored = k.size[piece]
        if how:
            line = "  at %s, %s: gzip stream of %d bytes that holds a device tree (%d bytes) -> binaries/%s.dtb" % (hex_(at), size_text(stored), stored, len(blob), base)
            live.check(line in fs.split("\n"), "%s: summary.txt describes the tree that lies in a gzip stream" % label, fs[:600])
        elif kind == "dtb":
            line = '  at %s, %s: device tree, model "abr kinfo live" -> binaries/%s.dtb' % (hex_(at), size_text(stored), base)
            live.check(line in fs.split("\n"), "%s: summary.txt describes the device tree" % label, fs[:600])
        else:
            m = re.search(r"^  at %s, %s: (ELF 64-bit little endian [a-z ]+, [\w-]+) -> binaries/%s\.elf$" % (hex_(at), re.escape(size_text(stored)), re.escape(base)), fs, re.M)
            live.check(m is not None, "%s: summary.txt describes the ELF file" % label, fs[:600])
        path = os.path.join(info, "binaries", base + "." + ext)
        if not live.check(os.path.isfile(path), "%s: binaries/%s.%s is written" % (label, base, ext), files):
            continue
        live.check(read(path) == blob, "%s: %s is the file that was in the kernel" % (label, base + "." + ext))
        live.check(("at %s," % hex_(at)) in fs, "%s: the file at %s is listed" % (label, hex_(at)), fs[:500])
        if kind == "dtb":
            dts = os.path.join(info, "binaries", base + ".dts")
            live.check(os.path.isfile(dts), "%s: %s.dts is written" % (label, base))
            if HAVE["dtc"] and os.path.isfile(dts):
                back = live.path("kinfo_back.dtb")
                rc, _, err = tool("dtc", "-q", "-I", "dts", "-O", "dtb", "-o", back, dts)
                live.check(rc == 0 and read(back) == blob, "%s: dtc compiles %s.dts to the blob that was in the kernel" % (label, base), err)
        else:
            if HAVE["readelf"]:
                rc, out, err = tool("readelf", "-h", "-l", "-S", path)
                o = out.decode("utf-8", "replace")
                live.check(rc == 0 and "Class:                             ELF64" in o and "little endian" in o and not err.strip(), "%s: readelf reads the ELF file abr wrote" % label, err)
                machine = {"Advanced Micro Devices X86-64": "x86-64", "AArch64": "AArch64", "ARM": "ARM"}.get((re.search(r"Machine:\s+(.*)", o) or [0, ""])[1].strip(), "?")
                kind_word = {"EXEC": "executable", "DYN": "shared object", "REL": "relocatable file"}.get((re.search(r"Type:\s+(\w+)", o) or [0, ""])[1], "?")
                live.check(("ELF 64-bit little endian %s, %s" % (kind_word, machine)) in fs, "%s: what the summary says of the ELF file is what readelf says" % label, fs[:400])


# =============================================================================================================================== the runs ==
def main():
    kernel = build_kernel()
    plain = kernel.bytes()
    cpio = kernel.what.get("cpio", (b"", None, []))[0]
    ramdisk = fx.gz(cpio) if cpio else fx.gz(fx.blob(2000))
    write(live.path("kernel.bin"), plain)

    # ----------------------------------------------------------------------------------------------- a boot image of header version 0, the kernel plain
    with live.section("boot image, plain kernel"):
        image = live.path("plain.img")
        write(image, fx.boot_v012(0, plain, ramdisk, cmdline="console=ttyS0"))
        out = live.fresh("plain_out")
        text = unpack(image, out)
        info = os.path.join(out, "kernel_info")
        live.check(os.path.isdir(info), "boot image: kernel_info/ is beside kernel")
        live.check(same_bytes(os.path.join(out, "kernel"), live.path("kernel.bin")), "boot image: kernel is the kernel that went in")
        line = [l for l in text.split("\n") if l.startswith("kernel_info: ")]
        live.check(len(line) == 1 and ("Linux %s (arm64 Image)" % RELEASE) in line[0] and ("%d symbols" % len(kernel.what["symbols"])) in line[0]
                   and ("config of %d options" % (CONFIG_YES + CONFIG_MODULES + CONFIG_VALUES + CONFIG_NOT_SET)) in line[0]
                   and ("3 certificates" in line[0] or "certs" not in kernel.what), "boot image: unpack says in one line what it found", line)
        live.check("kernel_info" not in read(os.path.join(out, "manifest.txt")).decode("utf-8", "replace"), "boot image: the manifest does not mention kernel_info")
        check_kernel_info("boot image", info, kernel)
        pack_same(out, image, "boot image with kernel_info/")

        # --- pack never reads kernel_info/
        saved = live.fresh("plain_saved_info")
        shutil.copytree(info, saved, symlinks=True)
        shutil.rmtree(info)
        pack_same(out, image, "boot image without kernel_info/")
        os.makedirs(info)
        write(os.path.join(info, "README.txt"), b"abr kernel_info -- what abr learned from the kernel of this image\nbut changed\n")
        write(os.path.join(info, "config"), b"CONFIG_NOT_THE_KERNEL=y\n")
        write(os.path.join(info, "kallsyms.txt"), b"nonsense\n")
        write(os.path.join(info, "initramfs.cpio"), b"not an archive")
        os.makedirs(os.path.join(info, "initramfs", "evil"))
        write(os.path.join(info, "payload.bin"), b"\xff" * 100)
        write(os.path.join(info, "kernel"), b"not the kernel")
        write(os.path.join(info, "kernel_dtb"), b"not a folder")
        pack_same(out, image, "boot image with a kernel_info/ that was edited")
        shutil.rmtree(info)
        write(info, b"a file named kernel_info")
        pack_same(out, image, "boot image with a file named kernel_info")
        os.unlink(info)
        if hasattr(os, "mkfifo") and not WINE:
            os.mkfifo(info)  # a read of it would never end
            pack_same(out, image, "boot image with a FIFO named kernel_info")
            os.unlink(info)
        shutil.copytree(saved, info, symlinks=True)

        # --- unpack again over the folder: what abr wrote is replaced
        write(os.path.join(info, "junk.txt"), b"left from the last time")
        os.makedirs(os.path.join(info, "initramfs", "stale"))
        write(os.path.join(info, "config"), b"CONFIG_STALE=y\n")
        unpack(image, out)
        live.check(not os.path.exists(os.path.join(info, "junk.txt")) and not os.path.exists(os.path.join(info, "initramfs", "stale")), "unpack again: what was there is replaced, not added to")
        check_kernel_info("boot image, unpacked again", info, kernel)
        a, b = tree_of(info), tree_of(saved)
        live.check(a == b, "unpack again: kernel_info/ is what the first unpack wrote, file for file", sorted(set(a) ^ set(b))[:6])

        # --- --no-kernel-info: nothing is written, and what an earlier unpack wrote is gone
        text = unpack(image, out, "--no-kernel-info")
        live.check(not os.path.exists(info), "--no-kernel-info: an earlier kernel_info/ is removed")
        live.check("kernel_info:" not in text, "--no-kernel-info: nothing is said about kernel_info", text[:200])
        live.check(os.path.isfile(os.path.join(out, "kernel")) and os.path.isdir(os.path.join(out, "ramdisk")), "--no-kernel-info: the rest is unpacked")
        pack_same(out, image, "boot image unpacked with --no-kernel-info")
        out2 = live.fresh("plain_out2")
        unpack(image, out2, "--no-kernel-info")
        live.check(not any(n.startswith("kernel_info") for n in os.listdir(out2)), "--no-kernel-info: a new folder has no kernel_info")

        # --- a folder that is somebody's
        theirs = os.path.join(out, "kernel_info")
        os.makedirs(theirs)
        write(os.path.join(theirs, "notes.txt"), b"my notes about this kernel\n")
        text = unpack(image, out)
        live.check(os.listdir(theirs) == ["notes.txt"] and read(os.path.join(theirs, "notes.txt")) == b"my notes about this kernel\n", "a foreign kernel_info/ is not touched")
        live.check("kernel_info is there already and was not made by abr" in text, "a foreign kernel_info/ is said to be there", text[:300])
        pack_same(out, image, "boot image next to a foreign kernel_info/")
        unpack(image, out, "--no-kernel-info")
        live.check(os.listdir(theirs) == ["notes.txt"], "--no-kernel-info does not remove a foreign kernel_info/")

        # --- the threads change nothing
        outs = {}
        for n in ("1", "2", "8"):
            outs[n] = live.fresh("plain_threads_" + n)
            unpack(image, outs[n], env={"ABR_THREADS": n})
        base = tree_of(os.path.join(outs["1"], "kernel_info"))
        for n in ("2", "8"):
            other = tree_of(os.path.join(outs[n], "kernel_info"))
            live.check(base == other, "ABR_THREADS=%s writes the same kernel_info/ as ABR_THREADS=1" % n, sorted(k2 for k2 in set(base) | set(other) if base.get(k2) != other.get(k2))[:6])

    # ---------------------------------------------------------------------------------------------------------- the kernel gzip, header version 4
    with live.section("boot image, gzip kernel"):
        image = live.path("gz.img")
        write(image, fx.boot_v012(0, fx.gz(plain), ramdisk, cmdline="console=ttyS0"))
        out = live.fresh("gz_out")
        text = unpack(image, out)
        live.check(same_bytes(os.path.join(out, "kernel"), live.path("kernel.bin")), "gzip kernel: kernel is the decompressed kernel")
        check_kernel_info("gzip kernel", os.path.join(out, "kernel_info"), kernel)
        s = summary_of(os.path.join(out, "kernel_info"))
        live.check("gzip stream of %d bytes that holds %d bytes" % (len(fx.gz(plain)), len(plain)) in s, "gzip kernel: summary.txt says what the field of the image held", s[:400])
        pack_same(out, image, "boot image with a gzip kernel and kernel_info/")
    with live.section("boot image, header version 4"):
        image = live.path("v4.img")
        write(image, fx.boot_v34(4, plain, ramdisk, cmdline="console=ttyS0"))
        out = live.fresh("v4_out")
        unpack(image, out)
        check_kernel_info("boot v4", os.path.join(out, "kernel_info"), kernel)
        pack_same(out, image, "boot image of header version 4 with kernel_info/")

    # ------------------------------------------------------------------------------------------------ the kernel inside a zImage or a bzImage
    with live.section("zImage and bzImage"):
        z, z_at = zimage_of(plain)
        image = live.path("zimage.img")
        write(image, fx.boot_v012(0, z, ramdisk))
        out = live.fresh("zimage_out")
        unpack(image, out)
        live.check(same_bytes(os.path.join(out, "kernel"), write_and_return(live.path("zimage.bin"), z)), "zImage: kernel is the zImage")
        info = os.path.join(out, "kernel_info")
        check_kernel_info("zImage", info, kernel, header=False, payload=plain)
        s = summary_of(info)
        live.check((field(s, "kind") or "").startswith("arm zImage, %d bytes" % len(z)), "zImage: the kind of kernel and its size", field(s, "kind"))
        live.check(("gzip stream at %s, %d bytes" % (hex_(z_at), len(fx.gz(plain)))) in (field(s, "kernel inside") or "") and ("it is payload.bin, %d bytes" % len(plain)) in (field(s, "kernel inside") or ""),
                   "zImage: the stream that holds the kernel is at %s" % hex_(z_at), field(s, "kernel inside"))
        live.check((field(s, "end") or "").startswith("0x%x (the zImage is %d bytes)" % (len(z), len(z))), "zImage: the end that its header says", field(s, "end"))
        live.check("arm64 Image" in s and "payload_kind" in s, "zImage: summary.txt says what kind of kernel is inside", s[:400])
        pack_same(out, image, "zImage with kernel_info/")

        b, b_at = bzimage_of(plain)
        image = live.path("bzimage.img")
        write(image, fx.boot_v012(0, b, ramdisk))
        out = live.fresh("bzimage_out")
        unpack(image, out)
        info = os.path.join(out, "kernel_info")
        check_kernel_info("bzImage", info, kernel, header=False, payload=plain)
        s = summary_of(info)
        live.check((field(s, "kind") or "").startswith("x86 bzImage, %d bytes" % len(b)), "bzImage: the kind of kernel and its size", field(s, "kind"))
        live.check(("gzip stream at %s, %d bytes" % (hex_(b_at), len(fx.gz(plain)))) in (field(s, "kernel inside") or ""), "bzImage: the stream that holds the kernel is at %s" % hex_(b_at), field(s, "kernel inside"))
        live.check((field(s, "payload_offset") or "").startswith("0x200") and (field(s, "payload_length") or "").startswith("0x%x" % len(fx.gz(plain))) and field(s, "setup_sects") == "4",
                   "bzImage: the header's offset, length of the payload and setup_sects", s[:600])
        pack_same(out, image, "bzImage with kernel_info/")

    # ------------------------------------------------------------------------------------- device trees glued behind the kernel (Image-dtb)
    with live.section("kernel with glued trees"):
        a, b = make_dtb("glue_a", "board a"), make_dtb("glue_b", "board b")
        if a and b:
            for how, field_bytes in (("Image-dtb", plain + a + b), ("Image.gz-dtb", fx.gz(plain) + a + b)):
                image = live.path("glued.img")
                write(image, fx.boot_v012(0, field_bytes, ramdisk))
                out = live.fresh("glued_out")
                unpack(image, out)
                live.check(same_bytes(os.path.join(out, "kernel"), live.path("kernel.bin")), "%s: kernel is the kernel without the trees" % how)
                live.check(os.path.isfile(os.path.join(out, "kernel_dtb", "entry0.dts")) and os.path.isfile(os.path.join(out, "kernel_dtb", "entry1.dts")),
                           "%s: the trees behind it are kernel_dtb/entry0.dts and entry1.dts" % how, os.listdir(out))
                check_kernel_info(how, os.path.join(out, "kernel_info"), kernel)
                s = summary_of(os.path.join(out, "kernel_info"))
                live.check(("device trees glued behind it, %d bytes: kernel_dtb/" % (len(a) + len(b))) in s, "%s: summary.txt says that trees are glued behind the kernel" % how, s[:500])
                live.check(not any(f.startswith("kernel_info") and "glue" in f for f in os.listdir(out)), "%s: nothing else is made of the trees" % how)
                pack_same(out, image, "%s with kernel_info/" % how)

    # ------------------------------------------------------------------------------------------ the other containers that hold a kernel
    with live.section("uImage"):
        for comp, data, name in ((0, plain, "plain"), (1, fx.gz(plain), "gzip")):
            image = live.path("uimage_%s.img" % name)
            write(image, fx.uimage(data, "abr kinfo", comp=comp))
            out = live.fresh("uimage_%s_out" % name)
            unpack(image, out)
            check_kernel_info("uImage (%s)" % name, os.path.join(out, "kernel_info"), kernel)
            pack_same(out, image, "uImage (%s) with kernel_info/" % name)
        other = fx.uimage(cpio or fx.blob(2000), "abr ramdisk", typ=3)
        write(live.path("uimage_rd.img"), other)
        out = live.fresh("uimage_rd_out")
        unpack(live.path("uimage_rd.img"), out)
        live.check(not os.path.exists(os.path.join(out, "kernel_info")), "uImage of a ramdisk: no kernel_info/ (it is not a kernel)")
    with live.section("Sony ELF"):
        kf, rf = live.path("sony_kernel.bin"), live.path("sony_ramdisk.bin")
        write(kf, plain)
        write(rf, ramdisk)
        image = live.path("sony.elf")
        rc, _, err = tool(sys.executable, "-I", os.path.join(TOOLS, "elf_tool.py"), "make", image, "kernel=%s@0x80008000" % kf, "ramdisk=%s@0x81000000" % rf)
        if live.check(rc == 0, "elf_tool makes a Sony ELF image", err):
            out = live.fresh("sony_out")
            unpack(image, out)
            check_kernel_info("Sony ELF", os.path.join(out, "kernel_info"), kernel)
            pack_same(out, image, "Sony ELF with kernel_info/")
    with live.section("KRNL"):
        kf = live.path("krnl_payload.bin")
        write(kf, plain)
        image = live.path("krnl.img")
        rc, _, err = tool(sys.executable, "-I", os.path.join(TOOLS, "krnl_tool.py"), "make", kf, image)
        if live.check(rc == 0, "krnl_tool makes a Rockchip KRNL image", err):
            out = live.fresh("krnl_out")
            unpack(image, out)
            check_kernel_info("KRNL", os.path.join(out, "kernel_info"), kernel)
            pack_same(out, image, "KRNL with kernel_info/")
    with live.section("OSIP"):
        hdr, stub, kf, rf = live.path("osip_hdr.bin"), live.path("osip_stub.bin"), live.path("osip_kernel.bin"), live.path("osip_ramdisk.bin")
        write(stub, b"\xeb\xfe" * 2048)
        write(kf, plain)
        write(rf, ramdisk)
        image = live.path("osip.img")
        osip = os.path.join(TOOLS, "osip_tool.py")
        rc, _, err = tool(sys.executable, "-I", osip, "header", hdr)
        if rc == 0:
            rc, _, err = tool(sys.executable, "-I", osip, "make", image, "--hdr", hdr, "--cmdline", "console=ttyS0", "--bootstub", stub, "--kernel", kf, "--ramdisk", rf)
        if live.check(rc == 0, "osip_tool makes an OSIP image", err):
            out = live.fresh("osip_out")
            unpack(image, out)
            check_kernel_info("OSIP", os.path.join(out, "kernel_info"), kernel)
            pack_same(out, image, "OSIP with kernel_info/")
    with live.section("FIT"):
        if not HAVE["mkimage"]:
            skip("FIT with two kernels", "mkimage")
        else:
            fit_two_kernels(plain, kernel, ramdisk)

    # ------------------------------------------------------------------------------------------------------------------ every kallsyms layout
    with live.section("kallsyms layouts"):
        kallsyms_layouts()

    # -------------------------------------------------------------------------------------------------------------------------- damaged kernels
    with live.section("damaged kernels"):
        damaged_kernels(kernel, plain, ramdisk)

    # ---------------------------------------------------------------------------------------------------------------------------- real kernels
    with live.section("real kernels"):
        if REAL is None:
            print("note: no real kernel was tried (no ABR_REAL_IMAGES)")
        else:
            real_kernels()
    return live.finish("kinfo_live")


def fit_two_kernels(plain, kernel, ramdisk):
    """A FIT with two kernels is kernel_info/ and kernel_info_2/, each with the banner of its own kernel."""
    second = build_kernel(release="6.1.99-abr-second", variant=dict(relative=False, big=False, address_size=8, count_size=8, marker_size=8),
                          parts=("banner", "config", "kallsyms"))
    k1, k2 = os.path.abspath(live.path("fit_kernel1.bin")), os.path.abspath(live.path("fit_kernel2.bin"))
    write(k1, plain)
    write(k2, second.bytes())
    write(live.path("fit_fdt.dtb"), kernel.what.get("dtb") or make_dtb("fit_tree", "fit tree") or b"")
    its = live.path("fit.its")
    write(its, ("/dts-v1/;\n/ {\n  description = \"abr kinfo live\";\n  #address-cells = <1>;\n  images {\n"
                "    kernel-1 { description = \"first\"; data = /incbin/(\"%s\"); type = \"kernel\"; arch = \"arm64\"; os = \"linux\"; compression = \"none\"; load = <0x80080000>; entry = <0x80080000>; hash-1 { algo = \"sha256\"; }; };\n"
                "    kernel-2 { description = \"second\"; data = /incbin/(\"%s\"); type = \"kernel\"; arch = \"arm64\"; os = \"linux\"; compression = \"none\"; load = <0x90080000>; entry = <0x90080000>; hash-1 { algo = \"crc32\"; }; };\n"
                "    fdt-1 { description = \"tree\"; data = /incbin/(\"%s\"); type = \"flat_dt\"; arch = \"arm64\"; compression = \"none\"; hash-1 { algo = \"sha1\"; }; };\n"
                "  };\n  configurations { default = \"conf-1\"; conf-1 { description = \"both\"; kernel = \"kernel-1\"; fdt = \"fdt-1\"; }; };\n};\n"
                % (k1, k2, os.path.abspath(live.path("fit_fdt.dtb")))).encode())
    image = live.path("two.itb")
    rc, _, err = tool("mkimage", "-f", its, image)
    if not live.check(rc == 0, "mkimage makes the FIT of two kernels", err):
        return
    out = live.fresh("fit_out")
    unpack(image, out)
    check_kernel_info("FIT, first kernel", os.path.join(out, "kernel_info"), kernel)
    two = os.path.join(out, "kernel_info_2")
    live.check(os.path.isdir(two), "FIT: the second kernel has kernel_info_2/")
    if os.path.isdir(two):
        s = summary_of(two)
        live.check(field(s, "release") == "6.1.99-abr-second", "FIT: kernel_info_2/ is about the second kernel", field(s, "release"))
        w = second.what["ks_where"]
        live.check(("addresses at %s" % hex_(w["addresses"])) in s and "the address of every symbol (kallsyms_addresses)" in s, "FIT: the second kernel's table is the absolute one", section(s, "SYMBOLS")[:300])
        live.check(read(os.path.join(two, "kallsyms.txt")).decode() == ks_text(second.what["symbols"]), "FIT: kernel_info_2/kallsyms.txt is the table of the second kernel")
    pack_same(out, image, "FIT with two kernels and their kernel_info/")
    # a number that is somebody's: the second kernel's information is not written there, and the first is replaced
    shutil.rmtree(two)
    os.makedirs(two)
    write(os.path.join(two, "mine.txt"), b"mine\n")
    shutil.rmtree(os.path.join(out, "kernel_info"))
    text = unpack(image, out)
    live.check(os.listdir(two) == ["mine.txt"] and "kernel_info_2 is there already and was not made by abr" in text, "FIT: a foreign kernel_info_2/ is left alone and said to be there", text[:300])
    live.check(os.path.isfile(os.path.join(out, "kernel_info", "summary.txt")), "FIT: kernel_info/ is written next to the foreign kernel_info_2/")
    pack_same(out, image, "FIT with a foreign kernel_info_2/")
    shutil.rmtree(two)
    # what is left of an unpack of two kernels is replaced when the image has one: `kernel_info_2` that abr made is gone
    unpack(image, out)
    live.check(os.path.isdir(two), "FIT: kernel_info_2/ is back after the foreign folder is gone")
    one = live.path("one.itb")
    write(live.path("fit1.its"), read(its).replace(b"kernel-2 {", b"xkernel-2 {").replace(b"type = \"kernel\"; arch = \"arm64\"; os = \"linux\"; compression = \"none\"; load = <0x90080000>", b"type = \"script\"; arch = \"arm64\"; os = \"linux\"; compression = \"none\"; load = <0x90080000>"))
    rc, _, err = tool("mkimage", "-f", live.path("fit1.its"), one)
    if rc == 0:
        unpack(one, out)
        live.check(not os.path.exists(two), "FIT: kernel_info_2/ that abr wrote last time is removed when the image has one kernel", os.listdir(out))
        live.check(os.path.isfile(os.path.join(out, "kernel_info", "summary.txt")), "FIT: kernel_info/ is there for the one kernel")


def kallsyms_layouts():
    """kallsyms tables of every layout, in kernels that have nothing else: what abr writes is the table that was written."""
    layouts = [
        ("absolute 64 LE", dict(relative=False)),
        ("absolute 64 LE, counts of 8 bytes", dict(relative=False, count_size=8, marker_size=8)),
        ("relative 64 LE", dict(relative=True)),
        ("relative 64 LE, counts of 8 bytes", dict(relative=True, count_size=8, marker_size=8)),
        ("absolute 32 LE", dict(relative=False, address_size=4)),
        ("relative 32 LE", dict(relative=True, address_size=4)),
        ("absolute 64 BE", dict(relative=False, big=True)),
        ("relative 64 BE", dict(relative=True, big=True)),
        ("absolute 32 BE", dict(relative=False, big=True, address_size=4)),
        ("absolute 64 LE, 256-byte alignment", dict(relative=False, align=256)),
        ("absolute 64 LE, 1000 symbols", dict(relative=False, count=1000)),
        ("relative 64 LE, 300 symbols", dict(relative=True, count=300)),
    ]
    for name, variant in layouts:
        k = build_kernel(variant=dict(variant), parts=("banner", "kallsyms"))
        image = live.path("ks.img")
        write(image, fx.boot_v012(0, k.bytes(), fx.gz(fx.blob(500))))
        out = live.fresh("ks_out")
        unpack(image, out)
        info = os.path.join(out, "kernel_info")
        got = os.path.join(info, "kallsyms.txt")
        asz = k.what["ks_variant"]["address_size"]
        want = ks_text(k.what["symbols"], asz)
        live.check(os.path.isfile(got) and read(got).decode("utf-8", "replace") == want, "kallsyms %s: kallsyms.txt is the table that was written" % name,
                   first_difference(read(got), want.encode()) if os.path.isfile(got) else "no kallsyms.txt")
        if os.path.isfile(got):
            s = summary_of(info)
            w = k.what["ks_where"]
            live.check(("addresses at %s" % hex_(w["addresses"])) in s and ("names at %s..%s" % (hex_(w["names"]), hex_(w["names_end"]))) in s,
                       "kallsyms %s: where the tables are" % name, section(s, "SYMBOLS")[:300])
            check_symbol_lines("kallsyms %s" % name, section(s, "SYMBOLS"), k)
        pack_same(out, image, "kallsyms %s" % name)


def damaged_kernels(kernel, plain, ramdisk):
    """Bytes changed inside every piece of the kernel, and the kernel cut short: unpack always works (what kernel_info/ finds is information, never
    a reason to refuse an image), and what it unpacks packs again to the image that was damaged."""
    rnd = random.Random(2026)
    pieces = [(name, at, kernel.size[name]) for name, at in kernel.at.items() if not name.startswith("androidboot")]
    runs = bad = 0
    mutants = int(os.environ.get("ABR_LIVE_MUTANTS") or (2 if WINE else 6))  # sabotage_check.sh asks for 2: it looks at the folder, not at damage
    for name, at, size in pieces:
        for n in range(mutants):
            b = bytearray(plain)
            for _ in range(rnd.randrange(1, 5)):
                b[at + rnd.randrange(size)] = rnd.randrange(256)
            image = live.path("dmg.img")
            write(image, fx.boot_v012(0, bytes(b), ramdisk))
            out = live.fresh("dmg_out")
            rc, text = live.run("unpack", "-i", image, "-o", out, timeout=60)
            runs += 1
            ok = live.check(rc == 0 and "terminate called" not in text, "damaged %s (%d): unpack works" % (name, n), "status %d: %s" % (rc, text[-300:]))
            if ok:
                ok = pack_same(out, image, "damaged %s (%d)" % (name, n))
            bad += 0 if ok else 1
    # the kernel cut short, and the file zeroed from a place on
    cuts = (1, 100, 0x1500, 0x4010, 0x8100, 0xa000, 0x10100, 0x14100, 0x18040, 0x5010, 0x1d010, 0x1f010, 0x21fff)
    for cut in cuts if mutants >= 6 else cuts[::3]:
        for how in ("cut", "zero"):
            b = plain[:cut] if how == "cut" else plain[:cut] + b"\0" * (len(plain) - cut)
            image = live.path("dmg.img")
            write(image, fx.boot_v012(0, b, ramdisk))
            out = live.fresh("dmg_out")
            rc, text = live.run("unpack", "-i", image, "-o", out, timeout=60)
            runs += 1
            ok = live.check(rc == 0 and "terminate called" not in text, "kernel %s at 0x%x: unpack works" % (how, cut), "status %d: %s" % (rc, text[-300:]))
            if ok:
                pack_same(out, image, "kernel %s at 0x%x" % (how, cut))
    live.damaged("boot image with a kernel carrying everything", fx.boot_v012(0, plain, ramdisk), 20261124, head=2048 + 0x300)
    print("note: %d runs of damaged kernels" % runs)


# ======================================================================================================================== real kernels ==
def parse_symbols(path):
    syms = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            a, t, n = line.rstrip("\n").split(" ", 2)
            syms.setdefault(n, int(a, 16))
    return syms


def real_kernels():
    """The kernels of the real images are judged by themselves: the symbol table and the strings are two views of one file. For a kernel whose table has
    `linux_banner`, the address of that symbol minus the offset at which abr found the banner is the address of the file's first byte; at the address of
    `linux_proc_banner` the file has to say "%s version %s (", and `__initramfs_start` is where abr says the initramfs is."""
    names = sorted(n for n in os.listdir(REAL) if os.path.isfile(os.path.join(REAL, n)))
    tried = checked = 0
    for n, name in enumerate(names):
        image = os.path.join(REAL, name)
        out = live.fresh("real_%d" % n)
        rc, text = live.run("unpack", "-i", image, "-o", out, timeout=240)
        info = os.path.join(out, "kernel_info")
        if rc != 0 or not os.path.isdir(info):
            live.check(rc == 0 or "not a boot-family container" in text or "out of scope" in text, "real %s: unpack works or says why not" % name, text[-200:])
            shutil.rmtree(out, ignore_errors=True)
            continue
        tried += 1
        pack_same(out, image, "real %s with kernel_info/" % name)
        s = summary_of(info)
        live.check(re.search(r"^kernel_info: ", text, re.M) is not None, "real %s: unpack says what it found" % name, text[:200])
        kernel_file = os.path.join(info, "payload.bin") if os.path.isfile(os.path.join(info, "payload.bin")) else os.path.join(out, "kernel")
        data = read(kernel_file)
        # the payload of a zImage: the stream that summary.txt names, decompressed by zlib or lzma here, is payload.bin
        inside = re.search(r"^  kernel inside\s+(gzip|xz|lzma) stream at (0x[0-9a-f]+), (\d+) bytes", s, re.M)
        if os.path.isfile(os.path.join(info, "payload.bin")) and inside:
            at, size = int(inside.group(2), 16), int(inside.group(3))
            stream = read(os.path.join(out, "kernel"))[at:at + size]
            if inside.group(1) == "gzip":
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                inflated = d.decompress(stream)
            else:
                inflated = lzma.LZMADecompressor().decompress(stream)
            live.check(inflated == data, "real %s: payload.bin is what %s makes of the stream at %s" % (name, "zlib" if inside.group(1) == "gzip" else "lzma", inside.group(2)))
        banner = re.search(r"^  banner\s+at (0x[0-9a-f]+): (Linux version .*)$", s, re.M)
        if banner:
            at = int(banner.group(1), 16)
            live.check(data[at:at + 14] == b"Linux version ", "real %s: the banner is at %s" % (name, banner.group(1)))
            release = field(s, "release")
            live.check(release is not None and ("Linux version " + release) in data[at:at + 200].decode("latin-1"), "real %s: the release is the one in the banner" % name)
        if os.path.isfile(os.path.join(info, "kallsyms.txt")):
            syms = parse_symbols(os.path.join(info, "kallsyms.txt"))
            lines = read(os.path.join(info, "kallsyms.txt")).decode("utf-8", "replace").split("\n")[:-1]
            live.check(len(lines) == int(re.search(r"(\d+) symbols", section(s, "SYMBOLS")).group(1)), "real %s: kallsyms.txt has the symbols that summary.txt counts" % name)
            addrs = [int(l.split(" ", 1)[0], 16) for l in lines]
            live.check(addrs == sorted(addrs), "real %s: kallsyms.txt is in the order of the addresses" % name)
            live.check(all(re.fullmatch(r"[0-9a-f]{8,16} [A-Za-z] \S+", l) for l in lines), "real %s: every line of kallsyms.txt is /proc/kallsyms' form" % name)
            if banner and "linux_banner" in syms:
                delta = syms["linux_banner"] - int(banner.group(1), 16)
                if "linux_proc_banner" in syms:
                    got = data[syms["linux_proc_banner"] - delta:][:15]
                    checked += live.check(got == b"%s version %s (", "real %s: the kernel has \"%%s version %%s (\" at linux_proc_banner (the table and the banner agree)" % name, got)
                if "__initramfs_start" in syms:
                    ini = re.search(r"INITRAMFS\n\s+at (0x[0-9a-f]+)", s)
                    live.check(ini is not None and int(ini.group(1), 16) == syms["__initramfs_start"] - delta, "real %s: the initramfs is at __initramfs_start" % name,
                               ini.group(1) if ini else s[-300:])
        # the config: zlib reads the stream where abr says it is
        cfg = re.search(r"gzip stream at (0x[0-9a-f]+), (\d+) bytes", section(s, "CONFIGURATION"))
        if cfg:
            at, size = int(cfg.group(1), 16), int(cfg.group(2))
            live.check(data[at - 8:at] == b"IKCFG_ST" and data[at + size:at + size + 8] == b"IKCFG_ED", "real %s: IKCFG_ST and IKCFG_ED are around the config stream" % name)
            plain = zlib.decompress(data[at:at + size], 16 + zlib.MAX_WBITS)
            live.check(read(os.path.join(info, "config")) == plain, "real %s: config is what zlib makes of the stream" % name)
            options = [l for l in plain.decode("utf-8", "replace").split("\n") if l.startswith("CONFIG_") or l.startswith("# CONFIG_")]
            yes = sum(1 for l in options if l.endswith("=y"))
            live.check(("%d =y" % yes) in section(s, "CONFIGURATION"), "real %s: the number of options that are =y" % name, section(s, "CONFIGURATION")[:200])
        else:
            live.check(not os.path.exists(os.path.join(info, "config")), "real %s: no config file when the kernel has none" % name)
        # initramfs archives: cpio lists what the folder holds
        for f in sorted(os.listdir(info)):
            if f.startswith("initramfs") and f.endswith(".cpio") and HAVE["cpio"]:
                rc, listing, err = tool("cpio", "-it", "--quiet", data=read(os.path.join(info, f)))
                listed = sorted(l for l in listing.decode("utf-8", "replace").split("\n") if l and l != ".")
                tree = os.path.join(info, f[:-5])
                walked = sorted(os.path.relpath(os.path.join(a, x), tree) for a, ds, fs in os.walk(tree) for x in ds + fs) if os.path.isdir(tree) else None
                live.check(rc == 0 and (walked is None or walked == listed), "real %s: cpio lists %s the way its folder is" % (name, f), "%s %s" % (listed[:6], walked and walked[:6]))
        # certificates: openssl judges them
        certs = os.path.join(info, "certs")
        if os.path.isdir(certs) and HAVE["openssl"]:
            for f in sorted(os.listdir(certs)):
                if f.endswith((".der", ".pem")) and "private" not in f:
                    form = "DER" if f.endswith(".der") else "PEM"
                    rc, _, err = tool("openssl", "x509", "-inform", form, "-in", os.path.join(certs, f), "-noout")
                    live.check(rc == 0, "real %s: openssl reads certs/%s" % (name, f), err)
                    if rc == 0:
                        cn = re.search(r"^subject:\s+(.*)$", read(os.path.join(certs, f[:-4] + ".txt")).decode("utf-8", "replace"), re.M)
                        judge_certificate("real %s" % name, os.path.join(certs, f), form, os.path.join(certs, f[:-4] + ".txt"), cn.group(1).split(",")[0] if cn else "?")
        # embedded files: readelf and dtc judge them
        bins = os.path.join(info, "binaries")
        if os.path.isdir(bins):
            for f in sorted(os.listdir(bins)):
                p = os.path.join(bins, f)
                if f.endswith(".elf") and HAVE["readelf"]:
                    rc, _, err = tool("readelf", "-h", p)
                    live.check(rc == 0, "real %s: readelf reads binaries/%s" % (name, f), err)
                if f.endswith(".dts") and HAVE["dtc"]:
                    back = live.path("real_back.dtb")
                    rc, _, err = tool("dtc", "-q", "-I", "dts", "-O", "dtb", "-o", back, p)
                    live.check(rc == 0 and read(back) == read(p[:-4] + ".dtb"), "real %s: dtc compiles binaries/%s to the blob that was in the kernel" % (name, f), err)
        shutil.rmtree(out, ignore_errors=True)
    live.check(tried > 0, "real kernels: at least one image with a kernel was tried", names)
    print("note: %d real images with a kernel, %d symbol tables confirmed by the kernel itself" % (tried, checked))


if __name__ == "__main__":
    sys.exit(main())
