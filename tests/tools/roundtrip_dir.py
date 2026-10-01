#!/usr/bin/env python3
"""Round-trip every image in a directory through `abr unpack` + `abr repack`.

usage: roundtrip_dir.py <abr-binary> <image-dir> [<work-dir>] [-k pattern]

Prints one line per file: IDENTICAL, or DIFF (first differing offset and
sizes), or UNPACK-FAIL / REPACK-FAIL with abr's error text.  Exit status is
0 only when every file is byte-identical.  Real device images are not part
of the repository; this is the tool used to validate against them.
"""
import fnmatch
import hashlib
import os
import shutil
import subprocess
import sys


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def first_diff(a, b):
    with open(a, "rb") as fa, open(b, "rb") as fb:
        off = 0
        while True:
            ca, cb = fa.read(1 << 20), fb.read(1 << 20)
            if not ca and not cb:
                return None
            if ca != cb:
                for i in range(min(len(ca), len(cb))):
                    if ca[i] != cb[i]:
                        return off + i
                return off + min(len(ca), len(cb))
            off += len(ca)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def main():
    args = [a for a in sys.argv[1:]]
    pattern = None
    if "-k" in args:
        i = args.index("-k")
        pattern = args[i + 1]
        del args[i:i + 2]
    if len(args) < 2:
        print(__doc__)
        return 2
    abr, src = args[0], args[1]
    work = args[2] if len(args) > 2 else "rt_work"
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    bad = 0
    for name in sorted(os.listdir(src)):
        path = os.path.join(src, name)
        if not os.path.isfile(path):
            continue
        if pattern and not fnmatch.fnmatch(name, pattern):
            continue
        safe = name.replace(" ", "_").replace("(", "").replace(")", "")
        d = os.path.join(work, safe + ".unpacked")
        out = os.path.join(work, safe + ".repacked")
        rc, msg = run([abr, "unpack", path, "-o", d])
        if rc != 0:
            print(f"UNPACK-FAIL  {name}: {msg.splitlines()[-1] if msg else rc}")
            bad += 1
            continue
        warn = [l for l in msg.splitlines() if l.lower().startswith("warning")]
        rc, msg2 = run([abr, "repack", d, "-o", out])
        if rc != 0:
            print(f"REPACK-FAIL  {name}: {msg2.splitlines()[-1] if msg2 else rc}")
            bad += 1
            continue
        if sha(path) == sha(out):
            print(f"IDENTICAL    {name} ({os.path.getsize(path)} bytes)")
        else:
            off = first_diff(path, out)
            print(f"DIFF         {name}: {os.path.getsize(path)} -> {os.path.getsize(out)} bytes, "
                  f"first difference at 0x{off:x}")
            bad += 1
        for w in warn:
            print(f"             {w}")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
