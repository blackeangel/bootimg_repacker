#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare an abr ramdisk directory (the tree and its .meta file) with what GNU cpio says about the
same archive: the listing (types, modes, owners, sizes, link targets, order) and the files GNU cpio
extracts (contents, nothing missing, nothing extra). abr's own code is not involved.

usage: ramdisk_oracle.py <archive.cpio> <tree_dir> <meta_file>
       ramdisk_oracle.py --prefix <archive.cpio> <unpack_dir> <prefix>
       ramdisk_oracle.py --link <path>

The second form is for a ramdisk that may be several cpio archives one after the other: GNU cpio reads
only the first archive of a stream, so the stream is cut into its archives here (with a reader of this
script's own) and each is compared with its directory: <prefix>/ and <prefix>.meta for the first,
<prefix>.vol2/ and <prefix>.vol2.meta for the second, and so on.

A symbolic link in the tree may be a real one, a Cygwin link file ("!<symlink>", FF FE, UTF-16LE, two
zero bytes: what abr writes where links cannot be made) or a text file holding the target. The third form
prints what such a link points at (exit status 1 when the path is not a link or a file).

Exit status 0 when every entry agrees, 1 when not, 77 when GNU cpio is not installed.
"""
import os, re, shutil, stat, subprocess, sys, tempfile

TYPEMAP = {"-": "f", "d": "d", "l": "l", "c": "c", "b": "b", "p": "p", "s": "s"}
RX = re.compile(r"^(\S{10})\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+(?:,\s*\d+)?)\s+(\w{3}\s+\d+\s+[\d:]+)\s+(.*)$")


def gnu_unescape(s):
    """GNU cpio prints a name with C escapes: \\ \t \n and \ooo for other bytes."""
    out = bytearray()
    i = 0
    raw = s.encode("utf-8", "surrogateescape")
    while i < len(raw):
        c = raw[i]
        if c == 0x5C and i + 1 < len(raw):
            n = raw[i + 1]
            simple = {0x5C: 0x5C, ord("t"): 9, ord("n"): 10, ord("r"): 13, ord("a"): 7, ord("b"): 8, ord("f"): 12, ord("v"): 11}
            if n in simple:
                out.append(simple[n]); i += 2; continue
            if 0x30 <= n <= 0x37:
                j = i + 1; v = 0; k = 0
                while j < len(raw) and k < 3 and 0x30 <= raw[j] <= 0x37:
                    v = v * 8 + raw[j] - 0x30; j += 1; k += 1
                out.append(v & 255); i = j; continue
        out.append(c); i += 1
    return bytes(out).decode("utf-8", "surrogateescape")


def perm_to_mode(p):
    m = 0
    for i, ch in enumerate(p[1:10]):
        bit = 0o400 >> i
        if ch in "rwx":
            m |= bit
        elif ch in "sS" and i == 2: m |= 0o4000 | (bit if ch == "s" else 0)
        elif ch in "sS" and i == 5: m |= 0o2000 | (bit if ch == "s" else 0)
        elif ch in "tT" and i == 8: m |= 0o1000 | (bit if ch == "t" else 0)
    return m


def unq(s):
    if s.startswith('"'):
        return s[1:-1].encode().decode("unicode_escape") if "\\" in s else s[1:-1]
    return s


def link_target(path):
    """What a link in the tree points at: a real link, a Cygwin link file, or a text file with the target."""
    if os.path.islink(path):
        return os.readlink(path)
    if not os.path.isfile(path):
        return None
    data = open(path, "rb").read()
    if data.startswith(b"!<symlink>"):
        body = data[10:]
        if body[:2] == b"\xff\xfe":
            body = body[2:]
            if len(body) % 2:
                body = body[:-1]
            return body.decode("utf-16-le", "surrogatepass").split("\0")[0]
        return body.split(b"\0")[0].decode("utf-8", "surrogateescape")
    return data.decode("utf-8", "surrogateescape").rstrip("\r\n")


def check(arch, tree, meta):
    """Compares one archive (a file) with its directory and metadata; returns (entries, problems)."""
    problems = []

    def bad(msg):
        problems.append(msg)

    # --- GNU cpio's listing -------------------------------------------------
    lst = subprocess.run(["cpio", "--list", "--verbose", "--numeric-uid-gid", "--quiet"],
                         stdin=open(arch, "rb"), capture_output=True, check=True).stdout.decode("utf-8", "surrogateescape")
    gnu = []
    for line in lst.splitlines():
        mt = RX.match(line)
        if not mt:
            bad("unparsable cpio line: " + line)
            continue
        perm, nlink, uid, gid, size, date, name = mt.groups()
        target = None
        if perm[0] == "l":
            name, _, target = name.partition(" -> ")
            target = gnu_unescape(target)
        name = gnu_unescape(name)
        size = 0 if "," in size else int(size)
        gnu.append((perm, int(uid), int(gid), size, name, target))

    # --- the meta file ---------------------------------------------------------
    entries = []
    inhead = True
    for line in open(meta, encoding="utf-8"):
        line = line.rstrip("\n")
        if inhead:
            if line == "entries":
                inhead = False
            continue
        if not line or line.startswith("#"):
            continue
        parts = line.split(" ", 6)
        typ, mode, uid, gid, mtime, extras, path = parts
        if typ == "T":
            continue
        entries.append((typ, int(mode, 8), int(uid), int(gid), unq(path)))

    if len(entries) != len(gnu):
        bad(f"entry count: meta {len(entries)}, cpio {len(gnu)}")

    for (typ, mode, uid, gid, path), (perm, guid, ggid, size, gname, target) in zip(entries, gnu):
        gp = gname[2:] if gname.startswith("./") else gname
        gp = "." if gname == "." else gp
        if path != gp:
            bad(f"name: meta {path!r}, cpio {gname!r}")
            continue
        if TYPEMAP.get(perm[0]) != typ:
            bad(f"{path}: type meta {typ}, cpio {perm[0]}")
        if (perm_to_mode(perm) & 0o7777) != mode:
            bad(f"{path}: mode meta {mode:o}, cpio {perm_to_mode(perm):o} ({perm})")
        if guid != uid or ggid != gid:
            bad(f"{path}: owner meta {uid}:{gid}, cpio {guid}:{ggid}")
        full = os.path.join(tree, path) if path != "." else tree
        if typ == "f":
            if not os.path.isfile(full):
                bad(f"{path}: missing in the tree")
            elif os.path.getsize(full) != size:
                bad(f"{path}: size tree {os.path.getsize(full)}, cpio {size}")
        elif typ == "l":
            t = link_target(full)
            if t is None:
                bad(f"{path}: symlink missing in the tree")
            elif t != target:
                bad(f"{path}: link target tree {t!r}, cpio {target!r}")
        elif typ == "d":
            if not os.path.isdir(full):
                bad(f"{path}: directory missing in the tree")

    # --- extract with GNU cpio and compare contents ------------------------------
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["cpio", "-idm", "--quiet", "--no-absolute-filenames"], cwd=td,
                       stdin=open(arch, "rb"), capture_output=True)
        for root, dirs, files in os.walk(td):
            for f in files + dirs:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, td)
                theirs = os.path.join(tree, rel)
                st = os.lstat(full)
                if stat.S_ISREG(st.st_mode):
                    if not os.path.isfile(theirs) or open(full, "rb").read() != open(theirs, "rb").read():
                        bad(f"{rel}: content differs from GNU cpio's extraction")
                elif stat.S_ISLNK(st.st_mode):
                    want = os.readlink(full)
                    have = link_target(theirs)
                    if have != want:
                        bad(f"{rel}: symlink target differs ({have!r} vs {want!r})")
                elif stat.S_ISDIR(st.st_mode):
                    if not os.path.isdir(theirs):
                        bad(f"{rel}: directory not in the tree")
        # and nothing extra in the tree (device nodes may not be creatable here: those are placeholders)
        kinds = {path: typ for typ, _, _, _, path in entries}
        for root, dirs, files in os.walk(tree):
            for f in files + dirs:
                rel = os.path.relpath(os.path.join(root, f), tree)
                if kinds.get(rel) in ("c", "b", "p", "s"):
                    continue
                if not os.path.lexists(os.path.join(td, rel)):
                    bad(f"{rel}: in the tree but GNU cpio did not extract it")
    return len(gnu), problems


def split_stream(data):
    """The archives of a stream of several one after the other: [bytes], each with the zeros behind it."""
    out, pos = [], 0
    while True:
        start = pos
        while True:
            magic = data[pos:pos + 6]
            if magic not in (b"070701", b"070702"):
                sys.exit("no cpio record at %d" % pos)
            fields = [int(data[pos + 6 + 8 * i:pos + 14 + 8 * i], 16) for i in range(13)]
            namesize, filesize = fields[11], fields[6]
            name = data[pos + 110:pos + 110 + namesize - 1]
            body = (pos + 110 + namesize + 3) & ~3
            pos = (body + filesize + 3) & ~3
            if name == b"TRAILER!!!":
                break
        nxt = pos
        while nxt < len(data) and data[nxt] == 0:
            nxt += 1
        if nxt >= len(data):
            out.append(data[start:])
            return out
        out.append(data[start:nxt])
        pos = nxt


def volume_names(prefix, i):
    name = prefix if i == 0 else "%s.vol%d" % (prefix, i + 1)
    return name, name + ".meta"


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--link":
        target = link_target(args[1])
        if target is None:
            sys.exit(1)
        sys.stdout.buffer.write(target.encode("utf-8", "surrogateescape"))
        return
    if shutil.which("cpio") is None:
        print("GNU cpio is not installed")
        sys.exit(77)
    if len(args) == 4 and args[0] == "--prefix":
        arch, unpack_dir, prefix = args[1:]
        parts = split_stream(open(arch, "rb").read())
        total, problems = 0, []
        for i, part in enumerate(parts):
            name, meta = volume_names(prefix, i)
            with tempfile.TemporaryDirectory() as td:
                piece = os.path.join(td, "volume.cpio")
                open(piece, "wb").write(part)
                n, probs = check(piece, os.path.join(unpack_dir, name), os.path.join(unpack_dir, meta))
            total += n
            problems += [f"[{name}] {p}" for p in probs]
        label = "%s: %d entries in %d archive%s" % (arch, total, len(parts), "" if len(parts) == 1 else "s")
    elif len(args) == 3:
        arch, tree, meta = args
        total, problems = check(arch, tree, meta)
        label = f"{arch}: {total} entries"
    else:
        sys.exit(__doc__)
    print(f"{label}, {len(problems)} problem(s)")
    for p in problems[:20]:
        print("   ", p)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
