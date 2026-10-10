#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""cpio archives for the ramdisk-directory tests of tests/run_tests.sh.

usage: cpio_gen.py <style> <out-file>
       cpio_gen.py list <archive>     one line per record: type mode uid gid size ino nlink name
                                      (of every archive, when there are several one after the other)
       cpio_gen.py split <archive> <prefix>
                                      writes <prefix>.0.cpio, <prefix>.1.cpio ...: each archive of a
                                      stream of several, with the zero fill that follows it

Every archive is written by this script's own writer, independently of abr's, so that what abr reads
and rebuilds is judged against something it did not produce. The styles:

  mkbootfs     what Android's mkbootfs writes: records depth first, the names of a directory sorted by
               their bytes, inodes counted up from 300000, every link count 1, owner root, time 0,
               the end record with mode 0755, zero fill up to a multiple of 256 bytes.
  crc          the same with the "070702" magic (a byte sum in every header)
  owners       mkbootfs, with owners other than root, setuid, setgid and sticky bits
  aik          what `find . | cpio -R 0:0 -H newc -o` writes (as Android Image Kitchen does): names "."
               and "./x", the inodes and times of a real file system, link counts as a file system has
               them, the records in the order of readdir, fill up to 512 bytes
  dotroot      the same as GNU cpio 2.15 writes it: the root is ".", every other name is plain ("x")
  upper        mkbootfs, with the header digits in upper case, as GNU cpio and gen_init_cpio write them
               (aik and dotroot are upper case too: they imitate GNU cpio)
  uppercrc     the same with the "070702" magic
  explicit     mkbootfs content with inode numbers and link counts that follow no rule
  tail         mkbootfs, but the fill after the end record is 100 bytes, not a block multiple
  weird        file names a text file cannot hold unquoted: spaces, quotes, a backslash, a tab, UTF-8
  big          many files, some larger than 64 KiB

  several archives one after the other (each becomes a directory of its own):
  volumes2     an mkbootfs ramdisk, then what Magisk adds: a small archive of its own
  volumes3     three archives of three kinds: crc, `find . | cpio` style, mkbootfs
  volumes_tail two archives with no fill of their own, the whole padded to 512 bytes

  and the ones that cannot become a directory (abr must say so and keep the file):
  hardlink dup dotdot absolute nodir junk junk2 offbound odc trunc linkbreak mixed mixcase
"""
import random
import sys

S_DIR, S_REG, S_LNK = 0o040000, 0o100000, 0o120000
S_CHR, S_BLK, S_FIFO, S_SOCK = 0o020000, 0o060000, 0o010000, 0o140000


class Rec:
    def __init__(self, name, mode, data=b"", uid=0, gid=0, mtime=0, nlink=1, ino=0, dev=(0, 0), rdev=(0, 0)):
        self.name, self.mode, self.data = name, mode, data
        self.uid, self.gid, self.mtime, self.nlink, self.ino = uid, gid, mtime, nlink, ino
        self.dev, self.rdev = dev, rdev


def record(e, magic=b"070701", upper=False):
    name = e.name.encode("utf-8") + b"\0"
    check = 0
    if magic == b"070702" and (e.mode & 0o170000) == S_REG:
        check = sum(e.data) & 0xFFFFFFFF
    fields = (e.ino, e.mode, e.uid, e.gid, e.nlink, e.mtime, len(e.data), e.dev[0], e.dev[1],
              e.rdev[0], e.rdev[1], len(name), check)
    out = magic + b"".join((b"%08X" if upper else b"%08x") % v for v in fields) + name
    out += b"\0" * (-len(out) % 4)
    out += e.data
    out += b"\0" * (-len(e.data) % 4)
    return out


def archive(recs, magic=b"070701", trailer=None, tail=256, tail_exact=None, upper=False):
    out = b"".join(record(r, magic, upper) for r in recs)
    out += record(trailer or Rec("TRAILER!!!", 0o755), magic, upper)
    if tail_exact is not None:
        out += b"\0" * tail_exact
    else:
        out += b"\0" * (-len(out) % tail)
    return out


def blob(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def text(s):
    return s.encode("utf-8")


def tree(extra=()):
    """(path, mode, data, rdev) in mkbootfs order."""
    rng = random.Random(20260621)
    items = [
        ("acct", S_DIR | 0o755, b""),
        ("config", S_DIR | 0o500, b""),
        ("data", S_DIR | 0o771, b""),
        ("dev", S_DIR | 0o755, b""),
        ("dev/console", S_CHR | 0o600, b"", (5, 1)),
        ("dev/null", S_CHR | 0o666, b"", (1, 3)),
        ("dev/pipe", S_FIFO | 0o600, b""),
        ("etc", S_LNK | 0o777, b"/system/etc"),
        ("init", S_REG | 0o750, b"\x7fELF" + blob(rng, 3000)),
        ("init.rc", S_REG | 0o750, text("on early-init\n    start ueventd\non init\n    mkdir /dev/cpuset 0750 root system\n")),
        ("lib", S_DIR | 0o755, b""),
        ("lib/modules", S_DIR | 0o755, b""),
        ("lib/modules/a.ko", S_REG | 0o644, blob(rng, 70000)),
        ("lib/modules/empty", S_REG | 0o644, b""),
        ("lib/modules/odd", S_REG | 0o644, blob(rng, 5)),
        ("proc", S_DIR | 0o755, b""),
        ("sbin", S_DIR | 0o755, b""),
        ("sbin/adbd", S_REG | 0o755, b"\x7fELF" + blob(rng, 1001)),
        ("sbin/ueventd", S_LNK | 0o777, b"../init"),
        ("sepolicy", S_REG | 0o644, blob(rng, 4096)),
        ("sys", S_DIR | 0o755, b""),
        ("system", S_DIR | 0o755, b""),
    ]
    items += list(extra)
    out = []
    for it in items:
        path, mode, data = it[0], it[1], it[2]
        rdev = it[3] if len(it) > 3 else (0, 0)
        out.append((path, mode, data, rdev))
    out.sort(key=lambda t: tuple(p.encode("utf-8") for p in t[0].split("/")))
    return out


def mkbootfs(items, magic=b"070701", owners=None, tail=256, tail_exact=None, upper=False):
    recs = []
    for i, (path, mode, data, rdev) in enumerate(items):
        uid, gid = (owners or {}).get(path, (0, 0))
        recs.append(Rec(path, mode, data, uid=uid, gid=gid, ino=300000 + i, rdev=rdev))
    trailer = Rec("TRAILER!!!", 0o755, ino=300000 + len(items))
    return archive(recs, magic, trailer, tail, tail_exact, upper)


def make_aik(prefix="./"):
    items = tree()
    rng = random.Random(7)
    # `find` lists a directory's entries in the order the file system gives them: shuffle the siblings,
    # keeping every directory in front of what it holds.
    kids = {}
    for it in items:
        kids.setdefault(it[0].rpartition("/")[0], []).append(it)
    order = []

    def walk(parent):
        entries = kids.get(parent, [])
        rng.shuffle(entries)
        for it in entries:
            order.append(it)
            if (it[1] & 0o170000) == S_DIR:
                walk(it[0])

    walk("")
    subdirs = {}
    for it in items:
        if (it[1] & 0o170000) == S_DIR:
            subdirs[it[0].rpartition("/")[0]] = subdirs.get(it[0].rpartition("/")[0], 0) + 1
    recs = [Rec(".", S_DIR | 0o755, nlink=2 + subdirs.get("", 0), mtime=1760000000, ino=131073, dev=(8, 1))]
    for i, (path, mode, data, rdev) in enumerate(order):
        is_dir = (mode & 0o170000) == S_DIR
        recs.append(Rec(prefix + path, mode, data, mtime=1760000000 + 37 * i, ino=131080 + 7 * i, dev=(8, 1),
                        nlink=2 + subdirs.get(path, 0) if is_dir else 1, rdev=rdev))
    return archive(recs, trailer=Rec("TRAILER!!!", 0, nlink=1), tail=512, upper=True)  # GNU cpio: upper case digits


def make_explicit():
    items = tree()
    rng = random.Random(3)
    inos = rng.sample(range(1000, 90000), len(items) + 1)
    recs = [Rec(p, m, d, ino=inos[i], nlink=rng.choice([1, 1, 1, 3, 5]) if (m & 0o170000) != S_DIR else 2 + i % 3,
                rdev=r) for i, (p, m, d, r) in enumerate(items)]
    return archive(recs, trailer=Rec("TRAILER!!!", 0o755, ino=inos[-1]), tail=256)


def overlay(tail=256):
    """What Magisk puts behind a ramdisk: an archive of its own."""
    rng = random.Random(5)
    items = [
        (".backup", S_DIR | 0o755, b"", (0, 0)),
        (".backup/.magisk", S_REG | 0o644, b"KEEPVERITY=true\nKEEPFORCEENCRYPT=true\n", (0, 0)),
        ("overlay.d", S_DIR | 0o755, b"", (0, 0)),
        ("overlay.d/sbin", S_DIR | 0o755, b"", (0, 0)),
        ("overlay.d/sbin/magisk", S_REG | 0o755, b"\x7fELF" + blob(rng, 500), (0, 0)),
        ("overlay.d/sbin/magisk.xz", S_REG | 0o644, blob(rng, 777), (0, 0)),
    ]
    return mkbootfs(items, tail=tail)


def good(style):
    items = tree()
    if style == "volumes2":
        return mkbootfs(items) + overlay()
    if style == "volumes3":
        return mkbootfs(items, magic=b"070702", tail=4) + make_aik() + overlay()
    if style == "volumes_tail":
        data = mkbootfs(items, tail=4) + overlay(tail=4)
        return data + b"\0" * (-len(data) % 512)
    if style == "dotroot":
        return make_aik(prefix="")
    if style == "mkbootfs":
        return mkbootfs(items)
    if style == "crc":
        return mkbootfs(items, magic=b"070702")
    if style == "upper":
        return mkbootfs(items, upper=True)
    if style == "uppercrc":
        return mkbootfs(items, magic=b"070702", upper=True, tail=512)
    if style == "owners":
        return mkbootfs(
            tree([("sbin/su", S_REG | 0o4755, b"su"), ("tmp", S_DIR | 0o1777, b""), ("wall", S_REG | 0o2755, b"w")]),
            owners={"init.rc": (0, 2000), "sbin/adbd": (2000, 2000), "data": (1000, 1000), "sepolicy": (0, 1000)})
    if style == "aik":
        return make_aik()
    if style == "explicit":
        return make_explicit()
    if style == "tail":
        return mkbootfs(items, tail_exact=100)
    if style == "weird":
        return mkbootfs(tree([
            ("res", S_DIR | 0o755, b""),
            ("res/with space.txt", S_REG | 0o644, b"1"),
            ("res/\"quoted\".txt", S_REG | 0o644, b"2"),
            ("res/back\\slash", S_REG | 0o644, b"3"),
            ("res/tab\there", S_REG | 0o644, b"4"),
            ("res/ünï cödé.txt", S_REG | 0o644, text("5ü")),
            ("res/ leading", S_REG | 0o644, b"6"),
            ("res/#hash", S_REG | 0o644, b"7"),
            ("res/- dash", S_REG | 0o644, b"8"),
            ("res/very long " + "n" * 150, S_REG | 0o644, b"9"),
        ]))
    if style == "big":
        rng = random.Random(11)
        extra = [("d%02d" % d, S_DIR | 0o755, b"") for d in range(12)]
        for d in range(12):
            for f in range(40):
                size = rng.choice([0, 1, 3, 4, 5, 100, 4095, 4096, 4097, 66000, 131072])
                extra.append(("d%02d/f%03d" % (d, f), S_REG | rng.choice([0o644, 0o755, 0o600]), blob(rng, size)))
        return mkbootfs(tree(extra))
    return None


def bad(style):
    items = tree()
    if style == "hardlink":
        recs = [Rec(p, m, d, ino=300000 + i, rdev=r) for i, (p, m, d, r) in enumerate(items)]
        a = next(r for r in recs if r.name == "init")
        b = next(r for r in recs if r.name == "sepolicy")
        a.nlink = b.nlink = 2
        b.ino = a.ino
        b.data = a.data
        return archive(recs, trailer=Rec("TRAILER!!!", 0o755, ino=300000 + len(recs)))
    if style == "dup":
        recs = [Rec(p, m, d, ino=300000 + i, rdev=r) for i, (p, m, d, r) in enumerate(items)]
        recs.append(Rec("init.rc", S_REG | 0o644, b"second one", ino=300999))
        return archive(recs, trailer=Rec("TRAILER!!!", 0o755, ino=301000))
    if style == "dotdot":
        recs = [Rec(p, m, d, ino=300000 + i, rdev=r) for i, (p, m, d, r) in enumerate(items)]
        recs.append(Rec("lib/../../evil", S_REG | 0o644, b"x", ino=300999))
        return archive(recs, trailer=Rec("TRAILER!!!", 0o755, ino=301000))
    if style == "absolute":
        recs = [Rec(p, m, d, ino=300000 + i, rdev=r) for i, (p, m, d, r) in enumerate(items)]
        recs.append(Rec("/etc/evil", S_REG | 0o644, b"x", ino=300999))
        return archive(recs, trailer=Rec("TRAILER!!!", 0o755, ino=301000))
    if style == "nodir":
        recs = [Rec(p, m, d, ino=300000 + i, rdev=r) for i, (p, m, d, r) in enumerate(items)]
        recs.append(Rec("nowhere/file", S_REG | 0o644, b"x", ino=300999))
        return archive(recs, trailer=Rec("TRAILER!!!", 0o755, ino=301000))
    if style == "junk":
        return mkbootfs(items, tail=4) + b"this is not zero fill\n"
    if style == "junk2":
        return mkbootfs(items, tail=4) + b"this is not an archive!" + overlay()
    if style == "offbound":
        return mkbootfs(items, tail=4) + b"\0\0\0" + overlay()
    if style == "odc":
        return b"070707" + b"0" * 70 + b"init\0" + b"TRAILER!!!\0" + b"\0" * 100
    if style == "trunc":
        whole = mkbootfs(items)
        return whole[: len(whole) // 2]
    if style == "linkbreak":
        return mkbootfs(tree([("lnk", S_LNK | 0o777, b"target\n")]))
    if style == "mixed":
        recs = [Rec(p, m, d, ino=300000 + i, rdev=r) for i, (p, m, d, r) in enumerate(items)]
        out = b"".join(record(r, b"070701") for r in recs[:3])
        out += b"".join(record(r, b"070702") for r in recs[3:])
        return out + record(Rec("TRAILER!!!", 0o755), b"070701") + b"\0" * 256
    if style == "mixcase":
        recs = [Rec(p, m, d, ino=300000 + i, rdev=r) for i, (p, m, d, r) in enumerate(items)]
        out = b"".join(record(r, b"070701", upper=False) for r in recs[:10])
        out += b"".join(record(r, b"070701", upper=True) for r in recs[10:])
        return out + record(Rec("TRAILER!!!", 0o755, ino=300000 + len(recs)), b"070701", upper=True) + b"\0" * 256
    return None


def parse_at(data, pos=0):
    """Reads the archive that starts at `pos` with a parser of its own: ([Rec], the end record, the
    offset behind the end record)."""
    recs = []
    while True:
        magic = data[pos:pos + 6]
        if magic not in (b"070701", b"070702"):
            sys.exit("no cpio record at %d" % pos)
        f = [int(data[pos + 6 + 8 * i:pos + 14 + 8 * i], 16) for i in range(13)]
        namesize = f[11]
        name = data[pos + 110:pos + 110 + namesize - 1].decode("utf-8", "surrogateescape")
        start = (pos + 110 + namesize + 3) & ~3
        body = data[start:start + f[6]]
        pos = (start + f[6] + 3) & ~3
        rec = Rec(name, f[1], body, uid=f[2], gid=f[3], mtime=f[5], nlink=f[4], ino=f[0], dev=(f[7], f[8]), rdev=(f[9], f[10]))
        if name == "TRAILER!!!":
            return recs, rec, pos
        recs.append(rec)


def parse(path):
    """The first archive of a file: ([Rec], the end record, what follows it)."""
    data = open(path, "rb").read()
    recs, trailer, pos = parse_at(data)
    return recs, trailer, data[pos:]


def volumes(path):
    """Every archive of a file of several one after the other: [(start, end)], where `end` is the start
    of the next one (or the end of the file), so the zero fill belongs to the archive before it."""
    data = open(path, "rb").read()
    out, pos = [], 0
    while True:
        recs, trailer, end = parse_at(data, pos)
        nxt = end
        while nxt < len(data) and data[nxt] == 0:
            nxt += 1
        if nxt >= len(data):
            out.append((pos, len(data)))
            return out
        out.append((pos, nxt))
        pos = nxt


KINDS = {S_DIR: "d", S_REG: "f", S_LNK: "l", S_CHR: "c", S_BLK: "b", S_FIFO: "p", S_SOCK: "s"}


def listing(path):
    data = open(path, "rb").read()
    for start, end in volumes(path):
        recs, trailer, pos = parse_at(data, start)
        for r in recs:
            print(KINDS.get(r.mode & 0o170000, "?"), "%04o" % (r.mode & 0o7777), r.uid, r.gid, len(r.data), r.ino, r.nlink, r.name)


def split(path, prefix):
    data = open(path, "rb").read()
    for i, (start, end) in enumerate(volumes(path)):
        with open("%s.%d.cpio" % (prefix, i), "wb") as f:
            f.write(data[start:end])


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "list":
        try:
            listing(sys.argv[2])
        except BrokenPipeError:  # `| head`, `| grep -q`: the reader has what it wanted
            pass
        return
    if len(sys.argv) == 4 and sys.argv[1] == "split":
        split(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    style, out = sys.argv[1], sys.argv[2]
    data = good(style)
    if data is None:
        data = bad(style)
    if data is None:
        sys.exit("unknown style " + style)
    with open(out, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main()
