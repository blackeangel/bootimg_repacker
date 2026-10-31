#!/usr/bin/env python3
"""Mutation fuzzing of `abr repack`: the directory that `unpack` wrote, damaged the ways a hand, a script or a hostile
archive damages it.

tests/tools/fuzz_images.py damages images and looks at `unpack`. This damages what `unpack` made and looks at `repack`:

  manifest   `manifest.txt`: a value that is too big or not a number, a key twice, not at all or from another format, a
             line that is no line, a path that leaves the directory, a manifest that belongs to another image
  files      the files of the components (cut, grown, flipped, swapped, taken out, a directory or a symbolic link in
             their place, a stranger next to them), the raw copies in `.abr_raw`, a stream of one of the eight codecs
             (whole, damaged, a bomb) in the place of a component with the name of its compression left, changed, or
             not one that abr knows
  tree       the ramdisk directory (a name that is a control character, a file that is a fifo, a link to `/`, a file of
             4 GiB, a tree 1500 levels deep)
  meta       `ramdisk.meta` (a mode that is no mode, a hard link without its partner, a type that is none, a path twice)
  keys       the keys that sign (`--avb-key`, `--avb1-key`, `--avb1-cert`, `--chromeos-key`, `--chromeos-keyblock`): a PEM
             cut in the middle, a length in the DER that is a lie
  output     where `-o` points (a directory, a path whose parent is not there, one of the files that are read)

What is judged is how abr behaves, not what it says. A directory that is wrong may be refused (exit status 1 and a message)
or taken; `repack` must never crash, hang, run out of memory, stop for a reason that is not the directory's (an exception
of the standard library that nobody meant to reach), print a control character (the manifest and the names in a ramdisk
are the sender's: a terminal would obey an escape sequence in them), say nothing when it refuses, leave something behind
when it refuses, change the directory it reads, or write an image that abr itself does not know again. An image that it
writes must be the same with another number of threads, and must come back byte for byte from `unpack` and `repack`
unless `unpack` said it could not. With -DABR_SANITIZE=address,undefined the sanitizers must have nothing to say:

    cmake -S . -B build-asan -G Ninja -DABR_SANITIZE=address,undefined && cmake --build build-asan
    ABR_KEEP_WORK=1 tests/run_tests.sh build-asan/abr          # (makes the images and the keys of the suite; its last note names the directory)
    tests/tools/fuzz_repack.py --abr build-asan/abr --seeds <that directory> --iterations 20

Every run is determined by --rng-seed, the seed file and the iteration number, so a finding is rebuilt by the same
command. The damaged directory that did it is also kept in --findings as a tar file with the command line (REPRO_ARGV in
it), and `--repro FILE.tar` runs it again. Exit status: 0 = nothing found, 1 = findings, 2 = usage.
"""

import argparse
import base64
import bz2
import collections
import concurrent.futures
import errno
import gzip
import hashlib
import io
import json
import lzma
import os
import random
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import traceback
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz_images as fz  # noqa: E402  (the runner, the judge of a run, the seeds)

# ---------------------------------------------------------------------------------------------------------------------
# what the values are made of

NUMBERS = [
    b"0", b"1", b"-1", b"2", b"3", b"4", b"7", b"8", b"9", b"10", b"15", b"16", b"17", b"31", b"32", b"63", b"64", b"127",
    b"128", b"255", b"256", b"511", b"512", b"1023", b"1024", b"2047", b"2048", b"4095", b"4096", b"4097", b"8192", b"16384",
    b"32767", b"32768", b"65535", b"65536", b"1048576", b"16777215", b"16777216", b"2147483647", b"2147483648", b"2147483649",
    b"4294967295", b"4294967296", b"4294967297", b"9223372036854775807", b"9223372036854775808", b"18446744073709551615",
    b"18446744073709551616", b"36893488147419103232", b"-2", b"-128", b"-2147483648", b"-2147483649", b"-4294967296",
    b"-9223372036854775808", b"-9223372036854775809", b"0x0", b"0x1", b"0x7f", b"0x80", b"0xff", b"0x100", b"0x1000", b"0x7fff",
    b"0x8000", b"0xffff", b"0x10000", b"0x7fffffff", b"0x80000000", b"0x80000001", b"0xfffffffe", b"0xffffffff", b"0x100000000",
    b"0x7fffffffffffffff", b"0x8000000000000000", b"0xffffffffffffffff", b"0x10000000000000000", b"0xFFFFFFFF", b"0XFF",
    b"0x" + b"f" * 17, b"0x" + b"f" * 40, b"0x" + b"0" * 40 + b"1", b"00", b"01", b"010", b"0777", b"09", b"+1", b"+0", b"-0",
    b" 1", b"1 ", b"\t1", b"1\t", b"1.0", b"1e3", b"0x", b"0x ", b"0b11", b"0o7", b"1_0", b"1,0", b"1k", b"1K", b"0xg",
    "\u0663".encode(), "\uff11".encode(), b"9" * 20, b"9" * 100, b"9" * 1000, b"-" + b"9" * 100, b"",
]
BOOLS = [b"true", b"false", b"TRUE", b"False", b"1", b"0", b"yes", b"no", b"on", b"off", b"", b"2", b"-1", b"t", b"f",
         b"true ", b" true", b"truee", b"tru"]
HEXES = [b"", b"0", b"00", b"0" * 63, b"0" * 64, b"0" * 65, b"f" * 64, b"F" * 64, b"g" * 64, b"0x" + b"0" * 64, b"00" * 20,
         b"00" * 32, b"00" * 100000, b"zz", b"0 0", b"00\\n00", b"-" + b"0" * 63]
TEXTS = [
    b"", b" ", b"  x  ", b"\t", b"x" * 15, b"x" * 16, b"x" * 17, b"x" * 511, b"x" * 512, b"x" * 513, b"x" * 1023, b"x" * 1024,
    b"x" * 1025, b"x" * 4096, b"x" * 65536, b"x" * 1000000, b'"', b'""', b'"x', b'x"', b'"x"', b'"\\"', b'"\\', b"\\", b"\\\\",
    b'"\\n"', b'"\\x"', b'"\\x1"', b'"\\xg1"', b'"\\x00"', b'"a\\x00b"', b'"\\x1b[2J"', b'"\\u1234"', b'"\\777"', b'"\\0"',
    b'"\\"x"', b"\x1b[2J", b"\x1b]0;x\x07", b"\x07", b"\r", b"x\ry", b"\x08", b"\x7f", b"\x9b", b"\xc2\x9b", b"\xff",
    b"\xc0\xaf", b"\xed\xa0\x80", b"\xe2\x82", b"\xf4\x90\x80\x80", b"\xef\xbb\xbfx", "é".encode(), "日本語".encode(), b"x\x00y",
    b"%s%s%s%n", b"%x", b"{}", b"$(id)", b"`id`", b"; id", b"--", b"-x", b"=", b"==", b"a=b", b"#", b"# x", b"a#b", b"a\\\nb",
]
PATHS = [
    b"", b".", b"..", b"./", b"../x", b"../../x", b"/", b"/etc/hostname", b"/dev/zero", b"/dev/urandom", b"/proc/self/status",
    b"a/../kernel", b"kernel/", b"kernel/x", b"./kernel", b"manifest.txt", b".abr_raw/kernel.raw", b".abr_raw", b"ramdisk",
    b"ramdisk/..", b"x" * 255, b"x" * 256, b"x" * 4096, b"x/" * 2100, b'"a\\nb"', b'"\\x1b[2J"', b"a\\b", b"C:\\x", b"\\\\h\\s\\x",
    b"NUL", b"CON", b"kernel.", b"kernel ", b" kernel", b"~", b"-", b"--help", b"*", b"kernel\\x00x", b"\xff", b"\x1b[2J",
    "é".encode(), b"kernel:stream", b"/tmp", b"//", b"a//b", b"a/./b",
]
NAMES = [
    "a", "A", "a b", " a", "a ", "...", ".hidden", "-rf", "--help", "-", "a\nb", "a\tb", "a\x1bb", "a\x1b[2Jb", "a\rb", "a\\b",
    'a"b', "a'b", "a=b", "a#b", "a%sb", "ü", "日本語", "x" * 255, "x" * 200, "CON", "NUL", "aux", "a:b", "a*b", "a?b", "a<b", "a|b",
    "ramdisk.meta", "manifest.txt", "kernel", "init", "..hidden", "~", "$HOME", "\x7f", "\x01", "\udcff", "\udcc0\udcaf", "x\u0085y",
    "\u202e", "a\u200bb", "e\u0301", "init.rc", "etc", "system", "ramdisk.cpio", "dev", "proc", "sys", "lib", "bin",
]
LINK_TARGETS = [".", "..", "/", "x", "../x", "../../../..", "/dev/zero", "/dev/urandom", "/proc/self/status", "a\nb", "\x1b[2J",
                "x" * 4000, "-", "ü", "\udcff", "kernel", "../kernel", ".abr_raw/kernel.raw", "manifest.txt"]
META_TYPES = [b"d", b"f", b"l", b"c", b"b", b"p", b"s", b"T", b"x", b"?", b"dd", b"F", b"", b"0"]
META_MODES = [b"0", b"0000", b"7777", b"07777", b"10000", b"0100644", b"17777777777", b"-1", b"abc", b"0x1ff", b"8", b"9", b"1" * 30,
              b"0644 ", b"644", b"777", b"4755", b"2755", b"1777", b"000", b"0111"]
META_EXTRAS = [b"-", b"ino=0", b"ino=1", b"ino=4294967295", b"ino=4294967296", b"ino=18446744073709551616", b"nlink=0", b"nlink=1",
               b"nlink=2", b"nlink=65536", b"nlink=4294967295", b"dev=0:0", b"dev=1:1", b"dev=4294967295:4294967295", b"dev=1",
               b"dev=:", b"rdev=1:3", b"rdev=4294967296:0", b"ino=1,nlink=2", b",", b",,", b"ino=1,", b"unknown=3", b"ino=-1",
               b"ino=0x10", b"ino=", b"=", b"ino=1,ino=2", b"nlink=2,nlink=3", b"dev=1:1,rdev=1:1,ino=5,nlink=3", b"x"]
META_DIRECTIVES = {
    b"format": [b"newc", b"crc", b"odc", b"bin", b"x", b""],
    b"hex": [b"lower", b"upper", b"x", b""],
    b"names": [b"plain", b"dotslash", b"x", b""],
    b"order": [b"sorted", b"archive", b"x", b""],
    b"inode": [b"sequential 300000", b"sequential", b"sequential 4294967295", b"sequential 4294967296", b"sequential 0", b"explicit",
               b"x", b"", b"sequential -1", b"sequential 4294967290"],
    b"nlink": [b"1", b"posix", b"explicit", b"0", b"2", b"x", b""],
    b"tail": [b"align 256", b"align 0", b"align 1", b"align 4", b"align 4294967295", b"size 0", b"size 100", b"size 4294967295",
              b"size 4294967296", b"x 1", b"align", b""],
    b"default": [b"uid=0 gid=0 mtime=0 dev=0:0", b"uid=4294967295 gid=4294967295 mtime=4294967295 dev=4294967295:4294967295",
                 b"uid=4294967296", b"uid=-1", b"x=1", b"uid", b"dev=1", b"mtime=1e9", b""],
    b"newmode": [b"file=0644 exec=0755 dir=0755 link=0777", b"file=07777 exec=07777 dir=07777 link=07777", b"file=010000",
                 b"file=8", b"file=", b"x=1", b"file", b""],
}
FORMAT_WEIGHTS = {"manifest": 40, "files": 20, "tree": 14, "meta": 12, "keys": 8, "output": 6}


def show(b, n=60):
    if isinstance(b, str):
        b = os.fsencode(b)
    s = repr(b[:n])
    return s + ("...(%d bytes)" % len(b) if len(b) > n else "")


def rm_rf(path):
    """rm -rf, as a program of its own: it walks a tree that is deeper than a Python function can recurse."""
    subprocess.run(["rm", "-rf", "--", path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def snapshot(root):
    """{relative path: (type, size, mtime ns, inode, permission bits)} of a tree, without following links."""
    snap = {}
    stack = [""]
    while stack:
        rel = stack.pop()
        full = os.path.join(root, rel) if rel else root
        try:
            with os.scandir(full) as it:
                for e in it:
                    r = os.path.join(rel, e.name) if rel else e.name
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        snap[r] = ("?",)
                        continue
                    snap[r] = (stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ino, st.st_mode & 0o7777)
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(r)
        except OSError:
            snap[rel + "/"] = ("unreadable",)
    return snap


def walk(root, limit=6000):
    """[(relative path, kind)] under root (kind: d f l o), in a fixed order, at most `limit` of them (iterative: a tree can be deep)."""
    out = []
    stack = [""]
    while stack and len(out) < limit:
        rel = stack.pop()
        full = os.path.join(root, rel) if rel else root
        try:
            with os.scandir(full) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            r = os.path.join(rel, e.name) if rel else e.name
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            m = stat.S_IFMT(st.st_mode)
            kind = "d" if m == stat.S_IFDIR else "f" if m == stat.S_IFREG else "l" if m == stat.S_IFLNK else "o"
            out.append((r, kind))
            if kind == "d":
                stack.append(r)
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------------------------------------------------------------
# the mutators

MUTATORS = []  # (name, family, weight, function)


def mutator(family, weight=10):
    def deco(fn):
        MUTATORS.append((fn.__name__[2:], family, weight, fn))
        return fn

    return deco


class Ctx:
    """One damaged directory in the making."""

    def __init__(self, campaign, tpl, rng, work):
        self.campaign = campaign
        self.tpl = tpl
        self.rng = rng
        self.work = work
        self.d = os.path.join(work, "d")
        self.extra = []  # more command line for `repack`
        self.out = None  # another place for -o than work/re.img
        self.aux = os.path.join(work, "aux")
        self.counter = 0

    def aux_file(self, name, data):
        os.makedirs(self.aux, exist_ok=True)
        path = os.path.join(self.aux, name)
        write_file(path, data)
        return path

    def manifest_path(self):
        return os.path.join(self.d, "manifest.txt")

    def manifest_values(self, suffix):
        """The values of the manifest's keys that end in `suffix` (`_file`, `_tree`)."""
        out = []
        for line in self.read_manifest_lines() or []:
            k, eq, v = line.partition(b"=")
            if eq and k.strip().endswith(suffix.encode()) and not k.lstrip().startswith(b"#"):
                out.append(v.strip().decode("utf-8", "replace"))
        return out

    def read_manifest_lines(self):
        try:
            return read_file(self.manifest_path()).split(b"\n")
        except OSError:
            return None

    def save_manifest_lines(self, lines):
        write_file(self.manifest_path(), b"\n".join(lines))

    def tree_dirs(self):
        out = []
        for name in self.manifest_values("_tree"):
            p = os.path.join(self.d, name)
            if name and os.path.isdir(p) and not os.path.islink(p) and os.sep not in name:
                out.append(name)
        return out

    def top_files(self):
        """Regular files of the directory that are not in a ramdisk tree: the components, the sides, the raw copies."""
        trees = set(self.tree_dirs())
        out = []
        try:
            names = sorted(os.listdir(self.d))
        except OSError:
            return out
        for name in names:
            p = os.path.join(self.d, name)
            if name in trees:
                continue
            if os.path.isdir(p) and not os.path.islink(p):
                try:
                    for sub in sorted(os.listdir(p)):
                        sp = os.path.join(p, sub)
                        if os.path.isfile(sp) and not os.path.islink(sp):
                            out.append(os.path.join(name, sub))
                except OSError:
                    pass
            elif os.path.isfile(p) or os.path.islink(p):
                out.append(name)
        return out

    def meta_files(self):
        out = []
        for name in self.tree_dirs():
            m = os.path.join(self.d, name + ".meta")
            if os.path.isfile(m):
                out.append(name + ".meta")
        return out


def parse_int(value):
    try:
        v = value.strip()
        if re.fullmatch(rb"-?[0-9]+", v):
            return int(v)
        if re.fullmatch(rb"0[xX][0-9a-fA-F]+", v):
            return int(v, 16)
    except ValueError:
        pass
    return None


def format_int(rng, n, like):
    if like.strip()[:2] in (b"0x", b"0X"):
        text = ("%#x" % n) if n >= 0 else "-%#x" % -n
        if like.strip()[:2] == b"0X":
            text = text.upper()
        return text.encode()
    text = str(n).encode()
    if rng.random() < 0.15:
        text = (b" " if rng.random() < 0.5 else b"") + text + (b" " if rng.random() < 0.5 else b"")
    return text


def value_kind(key, value):
    if key.endswith(b"_file") or key.endswith(b"_tree"):
        return "path"
    if value in (b"true", b"false"):
        return "bool"
    if parse_int(value) is not None:
        return "num"
    if re.fullmatch(rb"[0-9a-fA-F]{16,}", value):
        return "hex"
    return "text"


def pick_value(ctx, key, value):
    rng = ctx.rng
    kind = value_kind(key, value)
    if rng.random() < 0.2:
        kind = rng.choice(("num", "bool", "hex", "path", "text"))
    if kind == "num":
        n = parse_int(value)
        if n is None or rng.random() < 0.4:
            return rng.choice(NUMBERS)
        c = rng.choice([n + 1, n - 1, n + rng.randint(2, 4096), n - rng.randint(2, 4096), n * 2, n << rng.randint(1, 16), n >> 1,
                        n ^ (1 << rng.randrange(0, 64)), -n, n | 0x80000000, n & 0xFFFFFFFF, n + (1 << 32), n + (1 << 63)])
        return format_int(rng, c, value)
    if kind == "bool":
        return rng.choice(BOOLS)
    if kind == "hex":
        c = rng.random()
        if c < 0.5 or not value:
            return rng.choice(HEXES)
        i = rng.randrange(len(value))
        if c < 0.7:
            return value[:i] + bytes([rng.choice(b"0123456789abcdefg-x ")]) + value[i + 1:]
        if c < 0.85:
            return value[:i] + value[i + 1:]
        return value + rng.choice((b"0", b"00", b"f"))
    if kind == "path":
        pool = list(PATHS) + [os.fsencode(n) for n in ctx.top_files()[:8]] + [os.fsencode(n) for n in ctx.tree_dirs()[:3]]
        if rng.random() < 0.3 and value:
            return value + rng.choice((b"/", b"/x", b"x", b"/..", b".", b" ", b"\\"))
        return rng.choice(pool)
    if rng.random() < 0.3 and value:
        i = rng.randrange(len(value) + 1)
        return value[:i] + rng.choice(TEXTS[:60]) + value[i:]
    return rng.choice(TEXTS)


def kv_indices(lines):
    out = []
    for i, l in enumerate(lines):
        s = l.lstrip()
        if s and not s.startswith(b"#") and b"=" in s:
            out.append(i)
    return out


@mutator("manifest", 30)
def m_manifest_value(ctx):
    lines = ctx.read_manifest_lines()
    idx = kv_indices(lines or [])
    if not idx:
        return None
    i = ctx.rng.choice(idx)
    key, _, value = lines[i].partition(b"=")
    new = pick_value(ctx, key.strip(), value.strip())
    lines[i] = key + b"=" + new
    ctx.save_manifest_lines(lines)
    return f"manifest {key.strip().decode('latin1')}={show(new)}"


@mutator("manifest", 8)
def m_manifest_delete(ctx):
    lines = ctx.read_manifest_lines()
    idx = kv_indices(lines or [])
    if not idx:
        return None
    i = ctx.rng.choice(idx)
    gone = lines.pop(i)
    ctx.save_manifest_lines(lines)
    return f"manifest: delete {show(gone.split(b'=')[0])}"


@mutator("manifest", 8)
def m_manifest_duplicate(ctx):
    lines = ctx.read_manifest_lines()
    idx = kv_indices(lines or [])
    if not idx:
        return None
    i = ctx.rng.choice(idx)
    key, _, value = lines[i].partition(b"=")
    other = key + b"=" + (value if ctx.rng.random() < 0.3 else pick_value(ctx, key.strip(), value.strip()))
    lines.insert(ctx.rng.randrange(len(lines) + 1), other)
    ctx.save_manifest_lines(lines)
    return f"manifest: {show(key.strip())} twice, the second {show(other.partition(b'=')[2])}"


@mutator("manifest", 8)
def m_manifest_pool(ctx):
    pool = ctx.campaign.pool
    if not pool:
        return None
    lines = ctx.read_manifest_lines()
    if lines is None:
        return None
    fmt, key, value = ctx.rng.choice(pool)
    line = key + b"=" + value
    idx = [i for i in kv_indices(lines) if lines[i].partition(b"=")[0].strip() == key]
    if idx and ctx.rng.random() < 0.5:
        lines[ctx.rng.choice(idx)] = line
    else:
        lines.insert(ctx.rng.randrange(len(lines) + 1), line)
    ctx.save_manifest_lines(lines)
    return f"manifest: a line of a {fmt} manifest: {show(line)}"


JUNK_LINES = [b"zzz=1", b"=", b"==", b"=x", b"key", b"   ", b"\t", b"#", b"# x=y", b" kernel_file = kernel ", b"page_size ==4096", b"Page_Size=4096",
              b"PAGE_SIZE=4096", b"page_size =4096", b"page_size= 4096", b"page size=4096", b"page_size=4096 # c", b"[boot]", b"{}", b"x" * 70000,
              b"kernel_file=kernel\rkernel_file=x", b"\xef\xbb\xbftype=boot", b"type=boot\x00", b"\x00", b"a=\x00", b"type\x00=boot"]


@mutator("manifest", 4)
def m_manifest_junk(ctx):
    lines = ctx.read_manifest_lines()
    if lines is None:
        return None
    junk = ctx.rng.choice(JUNK_LINES)
    lines.insert(ctx.rng.randrange(len(lines) + 1), junk)
    ctx.save_manifest_lines(lines)
    return f"manifest: a line {show(junk)}"


@mutator("manifest", 3)
def m_manifest_reorder(ctx):
    lines = ctx.read_manifest_lines()
    if not lines or len(lines) < 3:
        return None
    r = ctx.rng
    c = r.random()
    if c < 0.4:
        i, j = r.randrange(len(lines)), r.randrange(len(lines))
        lines[i], lines[j] = lines[j], lines[i]
        note = f"two lines swapped ({i}, {j})"
    elif c < 0.7:
        lines.reverse()
        note = "reversed"
    else:
        r.shuffle(lines)
        note = "shuffled"
    ctx.save_manifest_lines(lines)
    return "manifest: " + note


@mutator("manifest", 8)
def m_manifest_bytes(ctx):
    try:
        data = read_file(ctx.manifest_path())
    except OSError:
        return None
    r = ctx.rng
    c = r.random()
    if c < 0.25 and data:
        i = r.randrange(len(data))
        data = data[:i]
        note = f"cut at {i}"
    elif c < 0.5:
        i = r.randrange(len(data) + 1)
        piece = r.choice([b"\x00", b"\r", b"\n", b'"', b"\\", b"=", b"\xff", b"\x1b", b"\xef\xbb\xbf", b"\r\n", b"#", b"\\n", b"\\x"])
        data = data[:i] + piece + data[i:]
        note = f"{show(piece)} put in at {i}"
    elif c < 0.65 and data:
        i = r.randrange(len(data))
        j = min(len(data), i + r.randrange(1, 64))
        data = data[:i] + data[j:]
        note = f"bytes {i}..{j} taken out"
    elif c < 0.75 and data:
        i = r.randrange(len(data))
        j = min(len(data), i + r.randrange(1, 200))
        data = data[:j] + data[i:j] + data[j:]
        note = f"bytes {i}..{j} doubled"
    elif c < 0.85:
        data = data.replace(b"\n", b"\r\n")
        note = "CRLF"
    elif c < 0.9:
        data = data.replace(b"\n", b"")
        note = "one line"
    elif c < 0.95:
        n = r.choice((1000, 20000, 100000))
        data += b"".join(b"k%d=v%d\n" % (i, i) for i in range(n))
        note = f"{n} lines more"
    else:
        data = bytes(r.getrandbits(8) for _ in range(r.choice((0, 1, 40, 2000))))
        note = "random bytes"
    write_file(ctx.manifest_path(), data)
    return "manifest as bytes: " + note


@mutator("manifest", 5)
def m_manifest_foreign(ctx):
    others = ctx.campaign.templates
    if len(others) < 2:
        return None
    t = ctx.rng.choice(others)
    try:
        data = read_file(os.path.join(t.dir, "manifest.txt"))
    except OSError:
        return None
    write_file(ctx.manifest_path(), data)
    return f"manifest: the manifest of another image ({t.fmt}, {t.sha})"


@mutator("manifest", 4)
def m_manifest_type(ctx):
    lines = ctx.read_manifest_lines()
    if lines is None:
        return None
    types = sorted({t.fmt for t in ctx.campaign.templates}) + ["", "x", "BOOT", "boot ", "boot\\n", "vbmeta", "dtbo", "uimage", "raw_dtb"]
    new = ctx.rng.choice(types).encode()
    for i in kv_indices(lines):
        if lines[i].partition(b"=")[0].strip() == b"type":
            lines[i] = b"type=" + new
            break
    else:
        lines.insert(0, b"type=" + new)
    ctx.save_manifest_lines(lines)
    return f"manifest: type={show(new)}"


# ---- files

def open_regular(path, write=False):
    """A file object for a regular file and for nothing else. The damage this program makes includes a fifo in the place of
    a file, a link, a device: an open of a fifo waits for a partner that never comes (the run hangs for ever), a write
    through a link goes to where the link points, out of the work directory. Both are refused with an OSError, which the
    mutators take as 'the damage is not made' (a read follows a link, a write does not)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW if write else os.O_RDONLY
    fd = os.open(path, flags | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), 0o644)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
        return os.fdopen(fd, "wb" if write else "rb")
    except BaseException:
        os.close(fd)
        raise


def read_file(path):
    with open_regular(path) as f:
        return f.read()


def write_file(path, data):
    with open_regular(path, write=True) as f:
        f.write(data)


def random_bytes(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n)) if n <= 4096 else rng.randbytes(n)


def size_class(rng):
    return rng.choice((0, 1, 2, 15, 16, 17, 255, 256, 4095, 4096, 4097, 65535, 70000, 1 << 20))


def pick_top(ctx, regular=True):
    files = ctx.top_files()
    if regular:
        files = [f for f in files if os.path.isfile(os.path.join(ctx.d, f)) and not os.path.islink(os.path.join(ctx.d, f))]
    if not files:
        return None
    named = {n for n in ctx.manifest_values("_file")}
    preferred = [f for f in files if f in named]
    if preferred and ctx.rng.random() < 0.7:
        return ctx.rng.choice(preferred)
    return ctx.rng.choice(files)


@mutator("files", 30)
def m_file_bytes(ctx):
    name = pick_top(ctx)
    if name is None:
        return None
    path = os.path.join(ctx.d, name)
    data = read_file(path)
    r = ctx.rng
    c = r.random()
    n = len(data)
    if c < 0.2:
        cut = r.choice([0, 1, n // 2, max(0, n - 1), max(0, n - 4096), r.randrange(n + 1)])
        data = data[:cut]
        note = f"cut to {cut}"
    elif c < 0.35:
        extra = r.choice((1, 2, 3, 16, 100, 4096, 70000))
        data = data + (b"\0" * extra if r.random() < 0.5 else random_bytes(r, extra))
        note = f"{extra} bytes more"
    elif c < 0.6 and n:
        buf = bytearray(data)
        for _ in range(r.randint(1, 8)):
            buf[r.randrange(n) if r.random() < 0.5 else r.randrange(min(n, 512))] ^= 1 << r.randrange(8)
        data = bytes(buf)
        note = "bits flipped"
    elif c < 0.7 and n:
        i = r.randrange(n)
        j = min(n, i + r.choice((1, 4, 16, 512, 4096)))
        data = data[:i] + (b"\xff" if r.random() < 0.5 else b"\0") * (j - i) + data[j:]
        note = f"bytes {i}..{j} filled"
    elif c < 0.8:
        head = random_bytes(r, r.choice((1, 2, 7, 64, 512, 4096)))
        data = head + data
        note = f"{len(head)} bytes in front"
    elif c < 0.9 and n:
        i = r.randrange(n)
        j = min(n, i + r.choice((1, 16, 4096)))
        data = data[:j] + data[i:j] + data[j:]
        note = f"bytes {i}..{j} doubled"
    else:
        data = random_bytes(r, min(n, 1 << 16)) + data[1 << 16:]
        note = "garbage over the first 64 KiB"
    write_file(path, data)
    return f"file {name}: {note}"


@mutator("files", 6)
def m_file_swap(ctx):
    files = [f for f in ctx.top_files() if os.path.isfile(os.path.join(ctx.d, f)) and not os.path.islink(os.path.join(ctx.d, f))]
    if len(files) < 2:
        return None
    a, b = ctx.rng.sample(files, 2)
    pa, pb = os.path.join(ctx.d, a), os.path.join(ctx.d, b)
    da, db = read_file(pa), read_file(pb)
    write_file(pa, db)
    write_file(pb, da)
    return f"files {a} and {b} swapped"


@mutator("files", 6)
def m_file_delete(ctx):
    name = pick_top(ctx, regular=False)
    if name is None:
        return None
    path = os.path.join(ctx.d, name)
    rm_rf(path)
    return f"file {name} taken out"


@mutator("files", 4)
def m_file_rename(ctx):
    name = pick_top(ctx, regular=False)
    if name is None:
        return None
    path = os.path.join(ctx.d, name)
    new = ctx.rng.choice([name.upper(), name + ".bak", name + " ", " " + name, "x" + name, name + "\n"]) if os.sep not in name else name + ".bak"
    try:
        os.rename(path, os.path.join(ctx.d, new))
    except OSError:
        return None
    return f"file {name} renamed to {show(new)}"


@mutator("files", 10)
def m_file_kind(ctx):
    name = pick_top(ctx, regular=False)
    if name is None:
        return None
    path = os.path.join(ctx.d, name)
    r = ctx.rng
    c = r.random()
    others = [f for f in ctx.top_files() if f != name]  # (before it is taken out: the directory may have nothing else)
    rm_rf(path)
    if c < 0.25:
        os.mkdir(path)
        if r.random() < 0.5:
            write_file(os.path.join(path, "x"), random_bytes(r, 100))
        note = "a directory"
    elif c < 0.7:
        target = r.choice(LINK_TARGETS + [os.path.join(ctx.work, "t.bin")])
        if target.endswith("t.bin"):
            write_file(target, random_bytes(r, 5000))
        os.symlink(target, path)
        note = f"a symbolic link to {show(target)}"
    elif c < 0.8:
        other = r.choice(others) if others else name
        os.symlink(os.path.basename(path) if r.random() < 0.3 else other, path)
        note = "a symbolic link to a file or itself"
    elif c < 0.9:
        os.mkfifo(path)
        note = "a fifo"
    else:
        other = r.choice([f for f in ctx.top_files() if os.path.isfile(os.path.join(ctx.d, f)) and f != name] or [None])
        if other is None:
            return None
        try:
            os.link(os.path.join(ctx.d, other), path)
        except OSError:
            return None
        note = f"a hard link to {other}"
    return f"file {name} replaced by {note}"


@mutator("files", 4)
def m_file_stray(ctx):
    r = ctx.rng
    name = r.choice(NAMES)
    path = os.path.join(ctx.d, name) if r.random() < 0.8 else os.path.join(ctx.d, ".abr_raw", name)
    try:
        write_file(path, random_bytes(r, size_class(r)))
    except OSError:
        return None
    return f"a file {show(name)} next to the others"


@mutator("files", 3)
def m_file_raw_sizes(ctx):
    """.abr_raw: the raw copies that an unchanged component is written back from."""
    raw = os.path.join(ctx.d, ".abr_raw")
    if not os.path.isdir(raw):
        return None
    names = sorted(os.listdir(raw))
    if not names:
        return None
    r = ctx.rng
    name = r.choice(names)
    path = os.path.join(raw, name)
    if not os.path.isfile(path) or os.path.islink(path):
        return None
    data = read_file(path)
    n = len(data)
    if r.random() < 0.5 or not n:
        data = data[: r.randrange(n + 1)]
        note = f"cut to {len(data)}"
    else:
        buf = bytearray(data)
        buf[r.randrange(n)] ^= 1 << r.randrange(8)
        data = bytes(buf)
        note = "a bit flipped"
    write_file(path, data)
    return f".abr_raw/{name}: {note}"


# ---- streams in the place of a component: what goes into the image as it is must be one that unpack takes

STREAM_CODECS = ("gzip", "lz4", "lz4_legacy", "zstd", "xz", "lzma", "bzip2", "lzo")
WRONG_COMPRESSIONS = [b"gzp", b"GZIP", b"", b"gz", b"zst", b"none ", b"lz4_frame", b"\x1b[2J", b'"\\x1b[2J"', b'"\\xff"', b"xz2", b"0",
                      b"lzma_alone", b"bzip", b"zstd,xz", b'"gzip\\x00"']
STREAM_TOOLS = {"zstd": ["zstd", "-q", "-c"], "lz4": ["lz4", "-q", "-c"], "lz4_legacy": ["lz4", "-q", "-l", "-c"], "lzo": ["lzop", "-c"]}


def zstd_rle_frame(n, declared=None):
    """A zstd frame of `n` zeros as run-length blocks (4 bytes for up to 128 KiB), with the size `declared` in its header or none."""
    f = bytes([0x28, 0xB5, 0x2F, 0xFD])
    f += bytes([0xE0]) + struct.pack("<Q", declared) if declared is not None else bytes([0x00, 0x38])
    left = n
    if n == 0:
        return f + bytes([0x01, 0x00, 0x00])
    while left > 0:
        take = min(left, 131072)
        left -= take
        f += struct.pack("<I", (1 if left == 0 else 0) | (1 << 1) | (take << 3))[:3] + b"\x00"
    return f


def make_stream(rng, codec, plain):
    """A whole stream of `codec` of `plain`, or None when this machine has nothing that makes one."""
    try:
        if codec == "gzip":
            return gzip.compress(plain, rng.choice((1, 6, 9)))
        if codec == "bzip2":
            return bz2.compress(plain)
        if codec == "xz":
            return lzma.compress(plain, format=lzma.FORMAT_XZ)
        if codec == "lzma":
            return lzma.compress(plain, format=lzma.FORMAT_ALONE)
        exe = shutil.which(STREAM_TOOLS[codec][0])
        if exe is None:
            return None
        return subprocess.run([exe] + STREAM_TOOLS[codec][1:], input=plain, capture_output=True, timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError, lzma.LZMAError):
        return None


def damage_stream(rng, data):
    """What a bad download, a bad flash or a bad hand does to a stream: nothing, or one of these."""
    n = len(data)
    c = rng.random()
    if c < 0.25 or not n:
        return data, "whole"
    if c < 0.4:
        cut = rng.choice([1, 2, 5, 12, n // 2, n - 1, n - 8, rng.randrange(n)])
        return data[: max(0, cut)], f"cut to {max(0, cut)}"
    if c < 0.65:
        buf = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            buf[rng.randrange(n)] ^= 1 << rng.randrange(8)
        return bytes(buf), "bits flipped"
    if c < 0.75:
        i = rng.randrange(n)
        j = min(n, i + rng.choice((1, 4, 16, 512)))
        return data[:i] + (b"\xff" if rng.random() < 0.5 else b"\x00") * (j - i) + data[j:], f"bytes {i}..{j} filled"
    if c < 0.85:
        return data + random_bytes(rng, rng.choice((1, 4, 64, 4096))), "bytes behind it"
    if c < 0.93:
        return data[: rng.choice((4, 8, 16, 32))] + random_bytes(rng, rng.choice((8, 64, 1024))), "the head and garbage"
    return data[rng.randrange(1, min(n, 16) + 1):], "the head cut off"


_bombs = {}
_bombs_lock = threading.Lock()


def bomb_stream(rng):
    """A stream that is a thousand times its own size or more (and how it is called): a zstd frame of run-length blocks of
    1.1 GiB of zeros (33 KB), one that declares a terabyte, one that declares a gibibyte and holds a thousand bytes."""
    kind = rng.choice(("rle", "terabyte", "gibibyte"))
    with _bombs_lock:
        if kind not in _bombs:
            _bombs[kind] = {"rle": lambda: zstd_rle_frame(1100 << 20), "terabyte": lambda: zstd_rle_frame(1000, declared=1 << 40),
                            "gibibyte": lambda: zstd_rle_frame(1000, declared=1 << 30)}[kind]()
        return _bombs[kind], "a zstd bomb (" + kind + ")"


@mutator("files", 9)
def m_file_stream(ctx):
    """A stream in the place of a component, and the name of its compression kept, changed (to another codec, to `none`: the
    stream then goes into the image as it is, which unpack must take) or made one that abr does not know. Found by it: an
    image that `repack` wrote with a damaged stream in it and `unpack` refused (a35)."""
    lines = ctx.read_manifest_lines()
    if lines is None:
        return None
    components = []  # (prefix, file name)
    for line in lines:
        k, eq, v = line.partition(b"=")
        k = k.strip()
        if eq and k.endswith(b"_file") and not k.startswith(b"#"):
            name = v.strip().decode("utf-8", "replace")
            if name and os.sep not in name and os.path.isfile(os.path.join(ctx.d, name)) and not os.path.islink(os.path.join(ctx.d, name)):
                components.append((k[: -len(b"_file")].decode("utf-8", "replace"), name))
    if not components:
        return None
    r = ctx.rng
    prefix, name = r.choice(components)
    path = os.path.join(ctx.d, name)
    if r.random() < 0.06:
        data, what = bomb_stream(r)
        codec = "zstd"
    else:
        codec = r.choice(STREAM_CODECS)
        try:
            original = read_file(path)
        except OSError:
            return None
        kind = r.random()
        n = min(r.choice((0, 1, 100, 4096, 70000, 300000)), 1 << 20)
        if kind < 0.4 and original:
            plain = original[: 1 << 20]
        elif kind < 0.7:
            plain = bytes(n)
        else:
            plain = random_bytes(r, n)
        data = make_stream(r, codec, plain)
        if data is None:
            return None
        data, what = damage_stream(r, data)
        what = f"{codec} stream of {len(plain)} bytes, {what}"
    try:
        write_file(path, data)
    except OSError:
        return None
    # the name of the compression the manifest has for it
    c = r.random()
    key = (prefix + "_compression").encode()
    if c < 0.55:
        value, said = b"none", "none"
    elif c < 0.7:
        return f"{name}: {what} (the compression kept)"
    elif c < 0.85:
        value = r.choice(STREAM_CODECS).encode()
        said = value.decode()
    else:
        value = r.choice(WRONG_COMPRESSIONS)
        said = show(value)
    for i, line in enumerate(lines):
        k, eq, _ = line.partition(b"=")
        if eq and k.strip() == key and not k.lstrip().startswith(b"#"):
            lines[i] = key + b"=" + value
            break
    else:
        lines.insert(len(lines) - 1 if lines and lines[-1] == b"" else len(lines), key + b"=" + value)
    ctx.save_manifest_lines(lines)
    return f"{name}: {what}, {prefix}_compression={said}"


# ---- the ramdisk tree

def tree_root(ctx):
    dirs = ctx.tree_dirs()
    if not dirs:
        return None
    return ctx.rng.choice(dirs)


def tree_pick(ctx, root, kinds="dfl"):
    entries = [(p, k) for p, k in walk(os.path.join(ctx.d, root)) if k in kinds]
    if not entries:
        return None
    return ctx.rng.choice(entries)


def tree_parent(ctx, root):
    dirs = [""] + [p for p, k in walk(os.path.join(ctx.d, root), limit=2000) if k == "d"]
    return ctx.rng.choice(dirs)


@mutator("tree", 14)
def m_tree_add_file(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    r = ctx.rng
    parent = tree_parent(ctx, root)
    name = r.choice(NAMES) if r.random() < 0.6 else "new_%d" % r.randrange(1000)
    path = os.path.join(ctx.d, root, parent, name)
    try:
        write_file(path, random_bytes(r, size_class(r)))
        if r.random() < 0.3:
            os.chmod(path, r.choice((0o000, 0o755, 0o4755, 0o7777, 0o111, 0o200)))
    except OSError:
        return None
    return f"tree {root}: a file {show(os.path.join(parent, name))}"


@mutator("tree", 6)
def m_tree_add_dir(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    r = ctx.rng
    parent = tree_parent(ctx, root)
    name = r.choice(NAMES) if r.random() < 0.5 else "dir_%d" % r.randrange(1000)
    path = os.path.join(ctx.d, root, parent, name)
    try:
        os.mkdir(path)
        if r.random() < 0.5:
            os.chmod(path, r.choice((0o000, 0o755, 0o1777, 0o7777)))
    except OSError:
        return None
    return f"tree {root}: a directory {show(os.path.join(parent, name))}"


@mutator("tree", 8)
def m_tree_add_link(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    r = ctx.rng
    parent = tree_parent(ctx, root)
    name = r.choice(NAMES) if r.random() < 0.5 else "link_%d" % r.randrange(1000)
    target = r.choice(LINK_TARGETS + [name, "../" + root, "/" + root])
    path = os.path.join(ctx.d, root, parent, name)
    try:
        os.symlink(target, path)
    except OSError:
        return None
    return f"tree {root}: a symbolic link {show(os.path.join(parent, name))} -> {show(target)}"


@mutator("tree", 5)
def m_tree_add_special(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    r = ctx.rng
    parent = tree_parent(ctx, root)
    name = "special_%d" % r.randrange(1000)
    path = os.path.join(ctx.d, root, parent, name)
    kind = r.choice(("fifo", "socket", "chardev", "blockdev"))
    try:
        if kind == "fifo":
            os.mkfifo(path)
        elif kind == "socket":
            s = socket.socket(socket.AF_UNIX)
            try:
                s.bind(path)
            finally:
                s.close()
        elif kind == "chardev":
            os.mknod(path, 0o600 | stat.S_IFCHR, os.makedev(1, 3))
        else:
            os.mknod(path, 0o600 | stat.S_IFBLK, os.makedev(7, 0))
    except OSError:
        return None
    return f"tree {root}: a {kind} {show(os.path.join(parent, name))}"


@mutator("tree", 10)
def m_tree_delete(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    pick = tree_pick(ctx, root)
    if pick is None:
        return None
    rm_rf(os.path.join(ctx.d, root, pick[0]))
    return f"tree {root}: {show(pick[0])} taken out"


@mutator("tree", 8)
def m_tree_rewrite(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    pick = tree_pick(ctx, root, "f")
    if pick is None:
        return None
    path = os.path.join(ctx.d, root, pick[0])
    r = ctx.rng
    data = read_file(path)
    c = r.random()
    if c < 0.3:
        data = b""
        note = "emptied"
    elif c < 0.6 and data:
        buf = bytearray(data)
        buf[r.randrange(len(data))] ^= 1 << r.randrange(8)
        data = bytes(buf)
        note = "a bit flipped"
    elif c < 0.8:
        data = data + random_bytes(r, r.choice((1, 100, 5000)))
        note = "grown"
    else:
        data = random_bytes(r, r.choice((1 << 16, 1 << 20)))
        note = "garbage"
    write_file(path, data)
    return f"tree {root}: {show(pick[0])} {note}"


@mutator("tree", 8)
def m_tree_kind(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    pick = tree_pick(ctx, root, "dfl")
    if pick is None:
        return None
    path = os.path.join(ctx.d, root, pick[0])
    r = ctx.rng
    rm_rf(path)
    c = r.random()
    if c < 0.35:
        os.mkdir(path)
        write_file(os.path.join(path, "inner"), b"x")
        note = "a directory"
    elif c < 0.7:
        os.symlink(r.choice(LINK_TARGETS), path)
        note = "a symbolic link"
    else:
        write_file(path, random_bytes(r, size_class(r)))
        note = "a file"
    return f"tree {root}: {show(pick[0])} made {note}"


@mutator("tree", 5)
def m_tree_attrs(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    pick = tree_pick(ctx, root, "df")
    if pick is None:
        return None
    path = os.path.join(ctx.d, root, pick[0])
    r = ctx.rng
    try:
        if r.random() < 0.5:
            mode = r.choice((0o000, 0o7777, 0o4755, 0o2755, 0o1777, 0o111, 0o222, 0o444))
            os.chmod(path, mode)
            return f"tree {root}: {show(pick[0])} chmod {mode:o}"
        t = r.choice((0, -1, 1, 2**31, 2**32, 2**32 + 1, 2**33, -(2**31)))
        os.utime(path, ns=(t * 10**9, t * 10**9))
        return f"tree {root}: {show(pick[0])} time {t}"
    except (OSError, OverflowError, ValueError):
        return None


@mutator("tree", 4)
def m_tree_hardlink(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    a = tree_pick(ctx, root, "f")
    parent = tree_parent(ctx, root)
    if a is None:
        return None
    name = "hl_%d" % ctx.rng.randrange(1000)
    try:
        os.link(os.path.join(ctx.d, root, a[0]), os.path.join(ctx.d, root, parent, name))
    except OSError:
        return None
    return f"tree {root}: {show(name)} a hard link to {show(a[0])}"


@mutator("tree", 3)
def m_tree_big(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    r = ctx.rng
    size = r.choice((2**32, 2**32 + 1, 2**33, 2**40, 2**32 - 1))
    parent = tree_parent(ctx, root)
    path = os.path.join(ctx.d, root, parent, "big_%d" % r.randrange(1000))
    try:
        with open_regular(path, write=True) as f:
            f.truncate(size)
    except OSError:
        return None
    return f"tree {root}: a sparse file of {size} bytes"


@mutator("tree", 3)
def m_tree_many(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    r = ctx.rng
    n = r.choice((1000, 5000, 20000))
    base = os.path.join(ctx.d, root, "many")
    try:
        os.mkdir(base)
        for i in range(n):
            with open_regular(os.path.join(base, "f%d" % i), write=True) as f:
                if i % 7 == 0:
                    f.write(b"x")
    except OSError:
        return None
    return f"tree {root}: {n} files more"


@mutator("tree", 2)
def m_tree_deep(ctx):
    root = tree_root(ctx)
    if root is None:
        return None
    r = ctx.rng
    depth = r.choice((50, 300, 1500))
    path = os.path.join(ctx.d, root, "deep")
    try:
        os.mkdir(path)
        for _ in range(depth):
            path = os.path.join(path, "d")
            os.mkdir(path)
        write_file(os.path.join(path, "leaf"), b"x")
    except OSError:
        return None
    return f"tree {root}: {depth} directories one in the other"


# ---- ramdisk.meta

def meta_lines(ctx):
    names = ctx.meta_files()
    if not names:
        return None, None
    name = ctx.rng.choice(names)
    try:
        return name, read_file(os.path.join(ctx.d, name)).split(b"\n")
    except OSError:
        return None, None


def save_meta(ctx, name, lines):
    write_file(os.path.join(ctx.d, name), b"\n".join(lines))


def meta_split(lines):
    """(index of the line after `entries`, or len(lines)): where the entries begin."""
    for i, l in enumerate(lines):
        if l.strip() == b"entries":
            return i + 1
    return len(lines)


def entry_indices(lines):
    start = meta_split(lines)
    return [i for i in range(start, len(lines)) if lines[i].strip() and not lines[i].lstrip().startswith(b"#")]


@mutator("meta", 20)
def m_meta_field(ctx):
    name, lines = meta_lines(ctx)
    if lines is None:
        return None
    idx = entry_indices(lines)
    if not idx:
        return None
    r = ctx.rng
    i = r.choice(idx)
    parts = lines[i].split(b" ", 6)
    if len(parts) < 7:
        return None
    field = r.choice((0, 1, 1, 2, 3, 4, 5, 5, 6, 6))
    old = parts[field]
    if field == 0:
        new = r.choice(META_TYPES)
    elif field == 1:
        new = r.choice(META_MODES)
    elif field in (2, 3, 4):
        new = r.choice(NUMBERS)
    elif field == 5:
        new = r.choice(META_EXTRAS)
    else:
        entries = [lines[j].split(b" ", 6)[6] for j in idx if len(lines[j].split(b" ", 6)) == 7]
        c = r.random()
        if c < 0.3 and entries:
            new = r.choice(entries)
        elif c < 0.5:
            new = old + r.choice((b"/", b"/x", b"x", b"/..", b" ", b"\\"))
        else:
            new = r.choice(PATHS)
    parts[field] = new
    lines[i] = b" ".join(parts)
    save_meta(ctx, name, lines)
    return f"{name} line {i + 1}: field {field} {show(old, 30)} -> {show(new, 40)}"


@mutator("meta", 8)
def m_meta_directive(ctx):
    name, lines = meta_lines(ctx)
    if lines is None:
        return None
    r = ctx.rng
    start = meta_split(lines)
    idx = [i for i in range(start) if lines[i].split(b" ", 1)[0] in META_DIRECTIVES]
    if not idx:
        return None
    i = r.choice(idx)
    key = lines[i].split(b" ", 1)[0]
    new = r.choice(META_DIRECTIVES[key]) if r.random() < 0.85 else r.choice(NUMBERS)
    lines[i] = key + b" " + new
    save_meta(ctx, name, lines)
    return f"{name}: {show(lines[i], 70)}"


@mutator("meta", 12)
def m_meta_lines(ctx):
    name, lines = meta_lines(ctx)
    if lines is None:
        return None
    idx = entry_indices(lines)
    if not idx:
        return None
    r = ctx.rng
    i = r.choice(idx)
    c = r.random()
    if c < 0.2:
        gone = lines.pop(i)
        note = f"line {i + 1} taken out ({show(gone, 40)})"
    elif c < 0.35:
        lines.insert(r.randrange(meta_split(lines), len(lines) + 1), lines[i])
        note = f"line {i + 1} twice"
    elif c < 0.5:
        j = r.choice(idx)
        lines[i], lines[j] = lines[j], lines[i]
        note = f"lines {i + 1} and {j + 1} swapped"
    elif c < 0.7:
        kind = r.choice(b"dflcbpsT")
        path = r.choice([b"nonexistent", b"a/b/c/d", b"x" * 300, b"deep/er/than/the/tree", b"..", b"/abs", b"a//b", b"\xff"])
        lines.insert(r.randrange(meta_split(lines), len(lines) + 1),
                     bytes([kind]) + b" " + r.choice(META_MODES) + b" 0 0 0 " + r.choice(META_EXTRAS) + b" " + path)
        note = f"an entry for {show(path, 30)} of type {chr(kind)}"
    elif c < 0.85:
        lines = lines[: r.randrange(len(lines))]
        note = f"cut at a line"
    else:
        lines.insert(r.randrange(meta_split(lines), len(lines) + 1), r.choice([b"T 0000 0 0 0 - TRAILER!!!", b"entries", b"# x", b"f", b"f 0644", b"\t", b"x y z"]))
        note = "a stray line"
    save_meta(ctx, name, lines)
    return f"{name}: {note}"


@mutator("meta", 4)
def m_meta_bytes(ctx):
    names = ctx.meta_files()
    if not names:
        return None
    r = ctx.rng
    name = r.choice(names)
    path = os.path.join(ctx.d, name)
    data = read_file(path)
    c = r.random()
    if c < 0.2:
        data = b""
        note = "empty"
    elif c < 0.4 and data:
        data = data[: r.randrange(len(data))]
        note = "cut"
    elif c < 0.55:
        data = data.replace(b"\n", b"\r\n")
        note = "CRLF"
    elif c < 0.7:
        n = r.choice((1000, 50000, 200000))
        data += b"".join(b"d 0755 0 0 0 - e%d\n" % i for i in range(n))
        note = f"{n} entries more"
    elif c < 0.85 and data:
        i = r.randrange(len(data))
        data = data[:i] + r.choice([b"\x00", b'"', b"\\", b"\x1b", b"\xff", b" ", b"\t"]) + data[i:]
        note = f"a byte put in at {i}"
    else:
        data = random_bytes(r, r.choice((1, 100, 3000)))
        note = "random"
    write_file(path, data)
    return f"{name}: {note}"


# ---- keys

PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)-----END \1-----", re.S)


def der_nodes(data, pos=0, end=None, depth=0):
    """[(tag, start, header length, content start, content end)] of the TLVs of data[pos:end], the constructed ones' too."""
    out = []
    end = len(data) if end is None else end
    while pos + 2 <= end:
        tag = data[pos]
        ln = data[pos + 1]
        hdr = 2
        if ln & 0x80:
            n = ln & 0x7F
            if n == 0 or n > 4 or pos + 2 + n > end:
                break
            ln = int.from_bytes(data[pos + 2 : pos + 2 + n], "big")
            hdr = 2 + n
        cs, ce = pos + hdr, pos + hdr + ln
        if ce > end:
            break
        out.append((tag, pos, hdr, cs, ce))
        if tag & 0x20 and depth < 6:
            out.extend(der_nodes(data, cs, ce, depth + 1))
        pos = ce
    return out


def der_length_bytes(n, form):
    """The length n of a DER node: form 0 the shortest way, 1 on two bytes when it fits (else four), 2 always on four."""
    if form == 0:
        if n < 128:
            return bytes([n])
        size = max(1, (n.bit_length() + 7) // 8)
        return bytes([0x80 | size]) + n.to_bytes(size, "big")
    if form == 1:
        return b"\x82" + n.to_bytes(2, "big") if n < 65536 else b"\x84" + (n & 0xFFFFFFFF).to_bytes(4, "big")
    return b"\x84" + (n & 0xFFFFFFFF).to_bytes(4, "big")


def mutate_der(rng, data):
    nodes = der_nodes(data)
    if not nodes:
        return None
    tag, start, hdr, cs, ce = rng.choice(nodes)
    ln = ce - cs
    c = rng.random()
    if c < 0.35:
        new = rng.choice([0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0x7FFFFFFF, 0xFFFFFFFF, ln + 1, max(0, ln - 1), ln * 2, ln + 4096])
        if rng.random() < 0.2:
            lb = rng.choice([b"\x80", b"\x81\xff", b"\x82\xff\xff", b"\x84\xff\xff\xff\xff", b"\x88" + b"\xff" * 8, b"\x85\x00\x00\x00\x00\x05", b"\xff"])
        else:
            lb = der_length_bytes(new & 0xFFFFFFFF, rng.randrange(3))
        return data[:start + 1] + lb + data[cs:], f"DER: the length of the node at {start} (tag {tag:#x}, {ln}) is {show(lb, 12)}"
    if c < 0.5:
        new = rng.choice([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0C, 0x13, 0x30, 0x31, 0xA0, 0xA1, 0x80, 0xFF, rng.randrange(256)])
        return data[:start] + bytes([new]) + data[start + 1:], f"DER: the tag of the node at {start} {tag:#x} -> {new:#x}"
    if c < 0.65 and ln:
        buf = bytearray(data)
        buf[cs + rng.randrange(ln)] ^= 1 << rng.randrange(8)
        return bytes(buf), f"DER: a bit in the node at {start}"
    if c < 0.8:
        newlen = rng.choice((0, 1, 2, 129, 257, 513, 1025, 2049, 4097, 8193, 16385))
        fill = rng.choice((b"\xff", b"\x00", b"\x01", b"\x80"))
        content = (b"\x00" if rng.random() < 0.3 else b"") + fill * newlen
        lb = der_length_bytes(len(content), 0)
        return data[:start + 1] + lb + content + data[ce:], f"DER: the node at {start} holds {newlen} bytes of {show(fill)}"
    if c < 0.9:
        return data[:start] + data[ce:], f"DER: the node at {start} taken out"
    return data[:ce] + data[start:ce] + data[ce:], f"DER: the node at {start} twice"


def mutate_key(rng, data):
    """-> (bytes, note) a key file damaged the way keys are: in the text of a PEM, in the DER under it, in the bytes."""
    m = PEM_RE.search(data)
    c = rng.random()
    if c < 0.05:
        return b"", "empty"
    if c < 0.10:
        return random_bytes(rng, rng.choice((1, 16, 100, 2000))), "random bytes"
    if c < 0.13:
        return b"A" * (10 << 20), "10 MiB of A"
    if c < 0.20 and data:
        i = rng.randrange(len(data))
        return data[:i], f"cut at {i}"
    if c < 0.28 and data:
        buf = bytearray(data)
        for _ in range(rng.randint(1, 5)):
            buf[rng.randrange(len(buf))] = rng.getrandbits(8)
        return bytes(buf), "bytes changed"
    if c < 0.55 and m:
        try:
            der = base64.b64decode(m.group(2), validate=False) if m.group(2).strip() else b""
        except ValueError:
            return data[: len(data) // 2], "PEM body not base64, cut"
        res = mutate_der(rng, der)
        if res is None:
            return data, "DER not parsed, unchanged"
        new, note = res
        body = base64.encodebytes(new)
        return data[: m.start(2)] + body + data[m.end(2):], "PEM " + note
    if c < 0.65 and not m:
        res = mutate_der(rng, data)
        if res is None:
            return data[: len(data) // 2], "DER not parsed, cut"
        return res
    if c < 0.75 and m:
        label = rng.choice([b"RSA PRIVATE KEY", b"PRIVATE KEY", b"EC PRIVATE KEY", b"CERTIFICATE", b"PUBLIC KEY", b"ENCRYPTED PRIVATE KEY", b"X", b""])
        return data.replace(m.group(1), label), f"PEM label {show(label)}"
    if c < 0.85 and m:
        lines = data.split(b"\n")
        i = rng.randrange(len(lines))
        op = rng.choice(("drop", "twice", "blank", "garble"))
        if op == "drop":
            lines.pop(i)
        elif op == "twice":
            lines.insert(i, lines[i])
        elif op == "blank":
            lines[i] = b""
        else:
            lines[i] = lines[i][: len(lines[i]) // 2] + b"!" + lines[i][len(lines[i]) // 2 + 1:]
        return b"\n".join(lines), f"PEM line {i} {op}"
    if c < 0.92:
        return data + random_bytes(rng, rng.choice((1, 100, 4096))), "bytes behind it"
    return data + data, "twice"


def key_candidates(ctx):
    return ctx.campaign.keys


@mutator("keys", 10)
def m_keys(ctx):
    """Options for the keys, whatever the image is: a key (damaged or whole) where one is asked for."""
    text = b"\n".join(ctx.read_manifest_lines() or [])
    r = ctx.rng
    wants = []
    if b"has_avb_footer=true" in text or b"type=vbmeta" in text or b"avb_algorithm" in text:
        wants.append("avb")
    if b"avb1_signature=true" in text:
        wants.append("avb1")
    if b"type=chromeos" in text or b"chromeos" in text:
        wants.append("chromeos")
    if not wants or r.random() < 0.15:
        wants = [r.choice(("avb", "avb1", "chromeos"))]
    want = r.choice(wants)
    # the payload changes, so a signature has to be made: without that the key is not looked at
    edited = edit_payload(ctx)
    corpus = key_candidates(ctx)
    notes = []

    def key_file(label):
        if corpus and r.random() < 0.9:
            src = r.choice(corpus)
            data = read_file(src)
            name = os.path.basename(src)
        else:
            data, name = random_bytes(r, r.choice((0, 30, 1200))), "random"
        note = "whole"
        if r.random() < 0.8:
            data, note = mutate_key(r, data)
        path = ctx.aux_file(f"{label}_{ctx.counter}_{name[:40]}", data)
        ctx.counter += 1
        notes.append(f"{label}: {name} {note}")
        return path

    if want == "avb":
        ctx.extra += ["--avb-key", key_file("avb")]
    elif want == "avb1":
        ctx.extra += ["--avb1-key", key_file("avb1key")]
        if r.random() < 0.6:
            ctx.extra += ["--avb1-cert", key_file("avb1cert")]
    else:
        ctx.extra += ["--chromeos-key", key_file("croskey")]
        if r.random() < 0.7:
            ctx.extra += ["--chromeos-keyblock", key_file("croskb")]
    return "keys (" + want + "): " + "; ".join(notes) + (f"; {edited}" if edited else "")


def edit_payload(ctx):
    """A change that makes an image need a new signature: a byte of a component, or a value of the header."""
    r = ctx.rng
    named = [f for f in ctx.manifest_values("_file") if os.path.isfile(os.path.join(ctx.d, f)) and os.path.getsize(os.path.join(ctx.d, f))]
    if named:
        name = r.choice(named)
        path = os.path.join(ctx.d, name)
        data = bytearray(read_file(path))
        data[r.randrange(len(data))] ^= 0x01
        write_file(path, bytes(data))
        return f"a bit of {name} flipped"
    lines = ctx.read_manifest_lines() or []
    for i in kv_indices(lines):
        k, _, v = lines[i].partition(b"=")
        if k.strip() == b"avb_rollback_index":
            n = parse_int(v)
            lines[i] = k + b"=" + str((n or 0) + 1).encode()
            ctx.save_manifest_lines(lines)
            return "avb_rollback_index + 1"
    return None


@mutator("edit", 0)
def m_edit(ctx):
    return edit_payload(ctx)


# ---- where the output goes

@mutator("output", 10)
def m_output(ctx):
    r = ctx.rng
    c = r.random()
    inputs = [f for f in ctx.top_files() if os.path.isfile(os.path.join(ctx.d, f)) and not os.path.islink(os.path.join(ctx.d, f))]
    if c < 0.35 and inputs:
        name = r.choice(inputs + ["manifest.txt"])
        ctx.out = os.path.join(ctx.d, name)
        return f"output: -o is the input {name}"
    if c < 0.45:
        ctx.out = os.path.join(ctx.d, "new.img")
        return "output: -o a new file inside the directory"
    if c < 0.55:
        os.mkdir(os.path.join(ctx.work, "o.d"))
        ctx.out = os.path.join(ctx.work, "o.d")
        return "output: -o a directory"
    if c < 0.65:
        ctx.out = os.path.join(ctx.work, "missing", "sub", "re.img")
        return "output: -o in a directory that is not there"
    if c < 0.72:
        ctx.out = ctx.d
        return "output: -o the directory that is read"
    if c < 0.77:
        ctx.out = ""
        return "output: -o empty"
    if c < 0.82:
        ctx.out = os.path.join(ctx.work, "x" * 300)
        return "output: -o a name of 300 characters"
    if c < 0.87:
        ctx.out = os.path.join(ctx.work, "re.img") + "/"
        return "output: -o with a slash at the end"
    if c < 0.92:
        os.symlink(os.path.join(ctx.work, "target.img"), os.path.join(ctx.work, "lnk.img"))
        ctx.out = os.path.join(ctx.work, "lnk.img")
        return "output: -o a symbolic link to a file that is not there"
    if c < 0.96:
        write_file(os.path.join(ctx.work, "exists.img"), b"old")
        ctx.out = os.path.join(ctx.work, "exists.img")
        return "output: -o a file that exists"
    ctx.out = "re.img"
    return "output: -o a relative path"


# ---------------------------------------------------------------------------------------------------------------------
# the campaign


class Template:
    def __init__(self, sha, path, dir_, fmt):
        self.sha, self.path, self.dir, self.fmt = sha, path, dir_, fmt


class Findings:
    def __init__(self, directory, per_signature):
        self.dir = directory
        self.per_signature = per_signature
        self.lock = threading.Lock()
        self.seen = {}
        os.makedirs(directory, exist_ok=True)

    def add(self, cls, sig, command, status, report, ctx, origin, argv):
        key = (cls, sig)
        with self.lock:
            entry = self.seen.setdefault(key, [0, []])
            entry[0] += 1
            if entry[0] > self.per_signature:
                return False
            digest = hashlib.sha1(origin.encode("utf-8", "replace")).hexdigest()[:10]
            stem = f"{cls}_{digest}"
            rel = [a.replace(ctx.work + os.sep, "") if isinstance(a, str) else a for a in argv]
            try:
                self.write_tar(os.path.join(self.dir, stem + ".tar"), ctx, rel)
            except OSError as e:
                report += f"\n(the damaged directory could not be saved: {e})\n".encode()
            with open(os.path.join(self.dir, stem + ".txt"), "w") as f:
                f.write(f"class:     {cls}\nsignature: {sig}\ncommand:   {command}   (abr {' '.join(rel)})\nstatus:    {status}\n")
                f.write(f"origin:    {origin}\n\n--- what abr said (first 8000 bytes) ---\n")
                f.write(report[:8000].decode(errors="replace"))
            entry[1].append(stem)
            return True

    @staticmethod
    def write_tar(path, ctx, argv):
        skipped = []
        with tarfile.open(path, "w") as tar:
            info = tarfile.TarInfo("REPRO_ARGV")
            payload = json.dumps(argv).encode()
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
            for sub in ("d", "aux"):
                root = os.path.join(ctx.work, sub)
                if not os.path.exists(root):
                    continue
                tar.add(root, arcname=sub, recursive=False)
                for rel, kind in walk(root, limit=20000):
                    full = os.path.join(root, rel)
                    try:
                        st = os.lstat(full)
                        if stat.S_ISREG(st.st_mode) and st.st_size > (48 << 20):
                            skipped.append(f"{sub}/{rel} ({st.st_size} bytes)")
                            continue
                        if stat.S_ISSOCK(st.st_mode):
                            skipped.append(f"{sub}/{rel} (a socket)")
                            continue
                        tar.add(full, arcname=os.path.join(sub, rel), recursive=False)
                    except (OSError, tarfile.TarError):
                        skipped.append(f"{sub}/{rel} (not saved)")
            if skipped:
                info = tarfile.TarInfo("NOT_SAVED")
                payload = ("\n".join(skipped[:200])).encode()
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))


def refusal_line(err, work):
    """The first line of a refusal, with the working directory and the numbers taken out: what kind of refusal it is."""
    text = err.decode("utf-8", "replace").replace(work, "<work>").strip().splitlines()
    first = text[0] if text else ""
    return re.sub(r"0x[0-9a-fA-F]+|[0-9]+", "N", first)[:130]


class Campaign:
    def __init__(self, args, seeds):
        self.args = args
        self.seeds = seeds
        self.runner = fz.Runner(args)
        self.findings = Findings(args.findings, args.per_signature)
        self.lock = threading.Lock()
        self.templates = []
        self.pool = []
        self.keys = []
        self.mutants = 0
        self.runs = 0
        self.accepted = 0
        self.refused = 0
        self.unchanged = 0
        self.refusal_lines = collections.Counter()
        self.by_mutator = collections.defaultdict(lambda: [0, 0, 0])  # tried, taken, refused
        self.slowest = (0.0, "")
        self.stop_at = time.time() + args.time_limit if args.time_limit else None
        self.root = tempfile.mkdtemp(prefix="fuzz_repack_templates_", dir=args.tmp)
        self.stable_checked = 0
        self.mutator_faults = collections.Counter()

    # -- preparation: one unpack of every seed, the lines of their manifests, the keys

    def prepare(self):
        def one(seed):
            path, _, sha = seed
            tdir = os.path.join(self.root, sha)
            mode = int(sha[:2], 16) % 5
            argv = ["unpack", path, "-o", tdir] + (["--no-tree"] if mode == 0 else ["--tree-only"] if mode == 1 else [])
            status, err, secs, out = self.runner.run(argv, self.root)
            if status != 0 or not os.path.isfile(os.path.join(tdir, "manifest.txt")):
                rm_rf(tdir)
                return None
            size = sum(s[1] for s in snapshot(tdir).values() if len(s) > 1 and s[0] == stat.S_IFREG)
            if size > self.args.max_template_mb << 20:
                rm_rf(tdir)
                return None
            lines = fz_read_lines(os.path.join(tdir, "manifest.txt"))
            fmt = next((l.partition(b"=")[2].strip().decode("latin1") for l in lines if l.startswith(b"type=")), "?")
            return Template(sha, path, tdir, fmt), lines

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.jobs) as pool:
            results = list(pool.map(one, self.seeds))
        for r in results:
            if r is None:
                continue
            tpl, lines = r
            self.templates.append(tpl)
            for l in lines[:60]:
                if l.startswith(b"#") or b"=" not in l:
                    continue
                k, _, v = l.partition(b"=")
                if len(v) < 200:
                    self.pool.append((tpl.fmt, k, v))
        self.templates.sort(key=lambda t: t.sha)
        self.find_keys()

    def find_keys(self):
        roots = list(self.args.keys or []) + [s for s in (self.args.seeds or []) if os.path.isdir(s)]
        found = []
        for root in roots:
            for dirpath, dirs, files in os.walk(root):
                dirs.sort()
                for name in sorted(files):
                    if re.search(r"\.(pem|pk8|der|vbprivk|vbpubk|keyblock|x509|key|crt|cer)$|^(key|cert)", name):
                        p = os.path.join(dirpath, name)
                        try:
                            if os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) <= 200_000:
                                found.append(p)
                        except OSError:
                            pass
        # the same bytes once
        seen = set()
        for p in found:
            try:
                h = hashlib.sha1(read_file(p)).hexdigest()
            except OSError:
                continue
            if h not in seen:
                seen.add(h)
                self.keys.append(p)
        self.keys = self.keys[:400]

    def cleanup(self):
        rm_rf(self.root)

    # -- one damaged directory

    def pick_mutators(self, rng, families):
        weights = {f: w for f, w in FORMAT_WEIGHTS.items() if f in families}
        names = sorted(weights)
        fam = rng.choices(names, [weights[n] for n in names])[0]
        pool = [(n, w, fn) for n, f, w, fn in MUTATORS if f == fam and w > 0 and (not self.args.mutators or n in self.args.mutators)]
        if not pool:
            return None
        n, _, fn = rng.choices(pool, [w for _, w, _ in pool])[0]
        return n, fn

    def one(self, index, iteration):
        if self.stop_at and time.time() > self.stop_at:
            return
        tpl = self.templates[index]
        rng = random.Random(f"{self.args.rng_seed}:{tpl.sha}:{iteration}")
        work = tempfile.mkdtemp(prefix="fuzzr_", dir=self.args.tmp)
        try:
            ctx = Ctx(self, tpl, rng, work)
            try:
                shutil.copytree(tpl.dir, ctx.d, symlinks=True)
            except (OSError, shutil.Error):
                return
            notes = []
            wanted = rng.choices((1, 2, 3, 4), (50, 30, 15, 5))[0]
            families = set(self.args.families)
            if rng.random() < self.args.pre_edit:
                try:
                    note = edit_payload(ctx)  # an edit that is none of the damage: the image is built, not replayed
                except (OSError, ValueError):
                    note = None
                if note:
                    notes.append(f"edit: {note}")
            tried = []
            for _ in range(wanted * 4):
                if len([n for n in notes if not n.startswith("edit:")]) >= wanted:
                    break
                pick = self.pick_mutators(rng, families)
                if pick is None:
                    break
                name, fn = pick
                try:
                    note = fn(ctx)
                except OSError:
                    note = None  # (a name too long, a full disk, a kind of file the file system has not: the damage is not made)
                except Exception:  # a fault of this program: said once for each mutator, the damage is not made
                    note = None
                    with self.lock:
                        first = name not in self.mutator_faults
                        self.mutator_faults[name] += 1
                    if first:
                        print(f"fuzz_repack: the mutator {name} failed:\n{traceback.format_exc()}", file=sys.stderr, flush=True)
                with self.lock:
                    self.by_mutator[name][0] += 1
                if note:
                    notes.append(note)
                    tried.append(name)
            if not tried:
                with self.lock:
                    self.unchanged += 1
                return
            origin = f"{tpl.path} ({tpl.fmt}) iteration {iteration} rng-seed {self.args.rng_seed}: " + "; ".join(notes)
            self.judge(ctx, origin, tried)
        except OSError as e:
            if e.errno == 28:  # no space
                print(f"fuzz_repack: {e}", file=sys.stderr)
        finally:
            rm_rf(work)

    def run(self, ctx, label, argv, origin):
        status, err, secs, out = self.runner.run(argv, ctx.work)
        with self.lock:
            self.runs += 1
            if secs > self.slowest[0]:
                self.slowest = (secs, f"{label} {origin[:120]}")
        return status, err, secs, out

    def report(self, ctx, cls, sig, command, status, report, origin, argv):
        self.findings.add(cls, sig, command, status, report, ctx, origin, argv)

    def judge(self, ctx, origin, tried):
        rng = ctx.rng
        d = ctx.d
        threads = rng.choice(("1", "1", "2", "3"))
        out = ctx.out if ctx.out is not None else os.path.join(ctx.work, "re.img")  # what abr is told
        out_path = os.path.normpath(os.path.join(ctx.work, out)) if out else ""  # where that is (abr runs in the work directory)
        inside = bool(out_path) and (out_path.startswith(d + os.sep) or out_path == d)
        base = ["repack", d]
        tail = []
        if rng.random() < 0.2:
            tail += ["--ramdisk-from", rng.choice(("cpio", "tree"))]
        tail += ctx.extra
        with self.lock:
            self.mutants += 1
        reference = None
        if ctx.out is not None:
            ref = os.path.join(ctx.work, "ref.img")
            st, er, _, ou = self.run(ctx, "reference", ["-j", threads] + base + ["-o", ref] + tail, origin)
            if st == 0 and os.path.isfile(ref):
                reference = read_file(ref)
            if os.path.lexists(ref):
                os.unlink(ref)
        existed = bool(out_path) and os.path.lexists(out_path)
        before = snapshot(d)
        argv = ["-j", threads] + base + ["-o", out] + tail
        status, err, secs, stdout = self.run(ctx, "repack", argv, origin)
        verdict = fz.classify("repack", status, err, stdout)
        if verdict:
            self.report(ctx, verdict[0], verdict[1], "repack", status, fz.report_of(verdict, err, stdout), origin, argv)
            return
        after = snapshot(d)
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        if inside and out_path != d:
            changed = [k for k in changed if k != os.path.relpath(out_path, d)]
        if changed and out_path != d:
            self.report(ctx, "input-changed", "repack changed the directory it reads", "repack", status,
                        ("changed: " + ", ".join(changed[:20])).encode() + b"\n" + err, origin, argv)
            return
        with self.lock:
            for name in tried:
                self.by_mutator[name][1 if status == 0 else 2] += 1
        if status == 1:
            with self.lock:
                self.refused += 1
                self.refusal_lines[refusal_line(err, ctx.work)] += 1
            if not (err.strip() or stdout.strip()):
                self.report(ctx, "silent-refusal", "repack exits 1 and says nothing", "repack", status, b"", origin, argv)
                return
            leftovers = []
            if out_path and not existed and os.path.lexists(out_path):
                leftovers.append(out_path)
            if ctx.out is None:
                leftovers += [os.path.join(ctx.work, n) for n in sorted(os.listdir(ctx.work)) if n not in ("d", "aux", "re.img", "t.bin")]
            if leftovers:
                self.report(ctx, "left-behind", "repack refused and left a file behind", "repack", status,
                            ("left: " + ", ".join(os.path.relpath(x, ctx.work) for x in leftovers)).encode() + b"\n" + err, origin, argv)
            return
        # taken
        with self.lock:
            self.accepted += 1
        if not os.path.isfile(out_path):
            self.report(ctx, "no-output", "repack succeeded and there is no image", "repack", status, err, origin, argv)
            return
        image = read_file(out_path)
        if reference is not None and image != reference:
            self.report(ctx, "output-differs", "the image depends on where -o points", "repack", status,
                        b"sizes %d / %d" % (len(image), len(reference)), origin, argv)
            return
        if not image:
            self.report(ctx, "empty-output", "repack succeeded and wrote no byte", "repack", status, err, origin, argv)
            return
        if inside:
            return  # (the directory has changed by what was written into it: nothing more to compare)
        if ctx.out is None:
            stray = [n for n in sorted(os.listdir(ctx.work)) if n not in ("d", "aux", "re.img", "t.bin")]
            if stray:
                self.report(ctx, "left-behind", "repack succeeded and left a file behind", "repack", status, ("left: " + ", ".join(stray)).encode(), origin, argv)
                return
        if len(image) > (24 << 20) and rng.random() > 0.3:
            return
        # the image is known again, with another number of threads it is the same, and it comes back as it is
        label = self.run(ctx, "identify", ["identify", "-b", out_path], origin)
        if label[0] != 0 or label[3].strip() == b"data":
            self.report(ctx, "unknown-output", "abr does not know the image it wrote", "identify", label[0], label[1] + label[3], origin, argv)
            return
        other = "1" if threads != "1" else "3"
        out2 = os.path.join(ctx.work, "re2.img")
        argv2 = ["-j", other] + base + ["-o", out2] + tail
        st2, er2, _, ou2 = self.run(ctx, "repack-again", argv2, origin)
        if st2 != 0 or not os.path.isfile(out2) or read_file(out2) != image:
            cls = fz.classify("repack", st2, er2, ou2)
            self.report(ctx, cls[0] if cls else "threads", cls[1] if cls else f"-j {threads} and -j {other} do not give the same image",
                        "repack", st2, er2, origin, argv2)
            return
        os.unlink(out2)
        if rng.random() > self.args.deep:
            return
        un = os.path.join(ctx.work, "again")
        argv3 = ["unpack", out_path, "-o", un] + (["--no-tree"] if rng.random() < 0.2 else [])
        st3, er3, _, ou3 = self.run(ctx, "unpack-result", argv3, origin)
        verdict = fz.classify("unpack", st3, er3, ou3)
        if verdict:
            self.report(ctx, verdict[0], verdict[1], "unpack", st3, fz.report_of(verdict, er3, ou3), origin, argv3)
            return
        if st3 != 0:
            self.report(ctx, "unreadable-output", "repack wrote an image that unpack refuses", "unpack", st3, er3, origin, argv3)
            return
        said = b"warning" in (er3 + ou3).lower() or b"is not kept" in (er3 + ou3)
        argv4 = ["repack", un, "-o", os.path.join(ctx.work, "re3.img")]
        st4, er4, _, ou4 = self.run(ctx, "repack-result", argv4, origin)
        verdict = fz.classify("repack", st4, er4, ou4)
        if verdict:
            self.report(ctx, verdict[0], verdict[1], "repack", st4, fz.report_of(verdict, er4, ou4), origin, argv4)
            return
        with self.lock:
            self.stable_checked += 1
        if st4 != 0:
            self.report(ctx, "result-not-repackable", "unpack of what repack wrote cannot be repacked", "repack", st4, er4, origin, argv4)
            return
        again = read_file(os.path.join(ctx.work, "re3.img"))
        if again != image and not said:
            first = next((i for i in range(min(len(again), len(image))) if again[i] != image[i]), min(len(again), len(image)))
            self.report(ctx, "unstable", "unpack and repack of what repack wrote is another image, unpack said nothing", "repack", st4,
                        b"sizes %d / %d, first difference at %d\n" % (len(image), len(again), first), origin, argv4)


def fz_read_lines(path):
    try:
        return read_file(path).split(b"\n")
    except OSError:
        return []


def repro(args):
    runner = fz.Runner(args)
    work = tempfile.mkdtemp(prefix="fuzz_repack_repro_", dir=args.tmp)
    try:
        with tarfile.open(args.repro) as tar:
            tar.extractall(work)
        with open(os.path.join(work, "REPRO_ARGV")) as f:
            argv = json.load(f)
        status, err, secs, out = runner.run(argv, work)
        verdict = fz.classify("repack", status, err, out)
        print(f"== abr {' '.join(argv)}: status {status}, {secs:.1f} s, verdict {verdict}")
        sys.stdout.write((fz.report_of(verdict, err, out) if verdict else err)[:6000].decode(errors="replace"))
    finally:
        rm_rf(work)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--abr", required=True, help="the abr binary (built with -DABR_SANITIZE=address,undefined to see more)")
    ap.add_argument("--seeds", nargs="+", default=[], help="image files, or directories searched for them (and for keys)")
    ap.add_argument("--keys", nargs="+", default=[], help="more directories searched for key files")
    ap.add_argument("--iterations", type=int, default=10, help="damaged directories per seed (default 10)")
    ap.add_argument("--rng-seed", default="1", help="the seed of the random numbers (default 1)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="abr processes at a time")
    ap.add_argument("--timeout", type=float, default=60, help="seconds before a run counts as a hang (default 60)")
    ap.add_argument("--time-limit", type=float, default=0, help="stop starting new work after this many seconds (default: no limit)")
    ap.add_argument("--max-seed-size", type=int, default=16 << 20, help="seeds above this many bytes are skipped (default 16 MiB)")
    ap.add_argument("--min-seed-size", type=int, default=32, help="seeds below this many bytes are skipped")
    ap.add_argument("--max-template-mb", type=int, default=64, help="a seed whose unpacked directory is bigger than this is skipped (default 64)")
    ap.add_argument("--include-unknown", action="store_true", help="also take files abr does not take for an image")
    ap.add_argument("--findings", default="fuzz_repack_findings", help="where the damaged directories and reports go")
    ap.add_argument("--per-signature", type=int, default=2, help="damaged directories kept for one and the same finding (default 2)")
    ap.add_argument("--tmp", default=None, help="where the working directories go (default: the system's)")
    ap.add_argument("--max-alloc-mb", type=int, default=2048, help="AddressSanitizer: one allocation above this is a finding")
    ap.add_argument("--max-rss-mb", type=int, default=4096, help="AddressSanitizer: a process above this is a finding")
    ap.add_argument("--max-output-mb", type=int, default=1024, help="one output file above this many MiB is a finding")
    ap.add_argument("--filtered", action="store_true", help="leave abr's output filter on (what a user gets); by default it is off, to find the messages that do not escape what they print")
    ap.add_argument("--families", default=",".join(sorted(FORMAT_WEIGHTS)), help="only these kinds of damage, comma separated (" + ", ".join(sorted(FORMAT_WEIGHTS)) + ")")
    ap.add_argument("--mutators", default="", help="only these mutators, comma separated (" + ", ".join(sorted(n for n, f, w, _ in MUTATORS if w > 0)) + ")")
    ap.add_argument("--deep", type=float, default=0.5, help="the share of accepted directories whose image is unpacked and repacked again (default 0.5)")
    ap.add_argument("--pre-edit", type=float, default=0.3, help="the share of damaged directories that were also edited the way a person edits (a byte of a component), so the image is built and not replayed (default 0.3)")
    ap.add_argument("--repro", metavar="TAR", help="run the command of a finding again")
    ap.add_argument("--seed-list", metavar="FILE", help="the seeds as `fuzz_images.py --list-seeds` printed them, instead of searching --seeds")
    args = ap.parse_args()
    args.families = [f.strip() for f in args.families.split(",") if f.strip()]
    unknown = set(args.families) - set(FORMAT_WEIGHTS)
    if unknown:
        ap.error("unknown kinds of damage: " + ", ".join(sorted(unknown)))
    args.mutators = {m.strip() for m in args.mutators.split(",") if m.strip()}
    known = {n for n, f, w, _ in MUTATORS}
    if args.mutators - known:
        ap.error("unknown mutators: " + ", ".join(sorted(args.mutators - known)))
    if args.tmp:
        args.tmp = os.path.abspath(args.tmp)
        os.makedirs(args.tmp, exist_ok=True)
    args.abr = os.path.abspath(args.abr)
    if not os.access(args.abr, os.X_OK):
        print(f"fuzz_repack: {args.abr} is not an executable", file=sys.stderr)
        return 2
    if args.repro:
        return repro(args)
    if args.seed_list:
        with open(args.seed_list) as f:
            seeds = [(line.split(" ", 2)[2].rstrip("\n"), None, line.split(" ", 2)[0]) for line in f if line.strip()]
        skipped_big = 0
    else:
        seeds, skipped_big = fz.find_seeds(args.seeds, args.abr, args.max_seed_size, args.min_seed_size, args.include_unknown)
    if not seeds:
        print("fuzz_repack: no seed images (give --seeds a directory of images)", file=sys.stderr)
        return 2
    campaign = Campaign(args, seeds)
    t0 = time.time()
    try:
        campaign.prepare()
        if not campaign.templates:
            print("fuzz_repack: not one seed unpacks", file=sys.stderr)
            return 2
        print(f"fuzz_repack: {len(seeds)} seeds ({skipped_big} larger than {args.max_seed_size >> 20} MiB skipped), {len(campaign.templates)} unpacked "
              f"in {time.time() - t0:.0f} s, {len(campaign.keys)} key files, {args.iterations} damaged directories of each, "
              f"{args.jobs} at a time, rng seed {args.rng_seed}", flush=True)
        t1 = time.time()
        total = len(campaign.templates) * args.iterations
        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = []
            for iteration in range(args.iterations):  # all seeds once before any is done twice
                for index in range(len(campaign.templates)):
                    futures.append(pool.submit(campaign.one, index, iteration))
            for fut in concurrent.futures.as_completed(futures):
                fut.result()
                done += 1
                if done % 200 == 0 or done == total:
                    with campaign.lock:
                        print(f"  {done}/{total} damaged directories, {campaign.runs} runs, {time.time() - t1:.0f} s, "
                              f"{len(campaign.findings.seen)} distinct findings", flush=True)
        elapsed = time.time() - t1
        print(f"\nfuzz_repack: {campaign.mutants} damaged directories ({campaign.unchanged} not damaged: no mutator applied), "
              f"{campaign.runs} runs of abr in {elapsed:.0f} s; `repack` took {campaign.accepted} of them and refused {campaign.refused}; "
              f"{campaign.stable_checked} images were unpacked and repacked again")
        print(f"             slowest run: {campaign.slowest[0]:.1f} s ({campaign.slowest[1]})")
        print("             by mutator (applied / image written / refused):")
        for name, (tried, taken, refused) in sorted(campaign.by_mutator.items()):
            print(f"               {name:22} {tried:6} / {taken:6} / {refused:6}")
        print("             the refusals that were said most often:")
        for line, n in campaign.refusal_lines.most_common(25):
            print(f"               {n:6}  {line}")
        if campaign.findings.seen:
            print(f"\n{len(campaign.findings.seen)} distinct findings (files in {args.findings}):")
            for (cls, sig), (count, stems) in sorted(campaign.findings.seen.items()):
                print(f"  [{cls}] x{count}: {sig}   {' '.join(stems)}")
            return 1
        print("nothing found")
        return 0
    finally:
        campaign.cleanup()


if __name__ == "__main__":
    sys.exit(main())
