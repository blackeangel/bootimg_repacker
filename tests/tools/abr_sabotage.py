#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""A sabotaged abr, to see that the judges of the suite notice: it runs the real abr (ABR_REAL) with the arguments it is given and then changes ONE byte of
what the real one wrote. Its output and its exit status are the real abr's, so a driver cannot tell from them.

  SAB=pack     the byte in the middle of the image that `pack` wrote
  SAB=unpack   the byte in the middle of the biggest file (not manifest.txt) that `unpack` wrote
  SAB=kinfo    one byte of one file of the kernel_info/ folders that `unpack` wrote: SAB_FILE is the file (a pattern, as fnmatch reads it, for the path
               below the folder: "config", "certs/*.der", "binaries/*.dts"; the first file that matches, in every folder), SAB_FIND a regular expression
               whose first group is the byte to change (the middle of the file when it is not set: "release\\s+(\\S)" is the first character of the release in
               summary.txt); every byte that is changed is a line of the file SAB_LOG (when it is set), so that a run that changed nothing is seen

It is used through tests/tools/sabotage_check.sh; a driver is run with this file where it expects abr:

  ABR_REAL=build/abr SAB=pack python3 -I tests/tools/mbn_live.py tests/tools/abr_sabotage.py <the arguments of the driver>

A driver that passes against it judges nothing. (The one byte is found from what abr says it wrote: "packed ... -> FILE (N bytes)" and
"unpacked ... -> DIRECTORY/"; if abr's words change and the byte is not found, this script ends with status 99 and says so, which fails the driver as well.)"""
import fnmatch
import os
import re
import subprocess
import sys

REAL = os.environ.get("ABR_REAL")
MODE = os.environ.get("SAB", "pack")
if not REAL or MODE not in ("pack", "unpack", "kinfo"):
    sys.exit("abr_sabotage.py: ABR_REAL names the real abr and SAB is pack, unpack or kinfo")


def flip_at(path, at):
    with open(path, "r+b") as f:
        f.seek(at)
        b = f.read(1)
        f.seek(at)
        f.write(bytes([b[0] ^ 0x55]))


def flip_middle(path, size):
    flip_at(path, size // 2)


def flip_kinfo(out):
    """One byte of the first file (in the order of the names) of every kernel_info folder in `out` that SAB_FILE names; -> how many were changed."""
    pattern, find, log, changed = os.environ.get("SAB_FILE", "*"), os.environ.get("SAB_FIND") or None, os.environ.get("SAB_LOG"), 0
    for name in sorted(os.listdir(out)):
        folder = os.path.join(out, name)
        if not (name.startswith("kernel_info") and os.path.isdir(folder) and os.path.isfile(os.path.join(folder, "README.txt"))):
            continue
        rels = sorted(os.path.relpath(os.path.join(a, f), folder).replace(os.sep, "/") for a, _, fs in os.walk(folder) for f in fs)
        for rel in rels:
            path = os.path.join(folder, rel)
            if not fnmatch.fnmatchcase(rel, pattern) or os.path.islink(path) or os.path.getsize(path) == 0:
                continue
            at = os.path.getsize(path) // 2
            if find:
                with open(path, "rb") as f:
                    m = re.search(find.encode(), f.read(), re.M)
                if not m:
                    continue
                at = m.start(1) if m.groups() else m.start()
            flip_at(path, at)
            changed += 1
            if log:
                with open(log, "a") as f:
                    f.write("%s byte %d\n" % (path, at))
            break
    return changed


def main():
    args = sys.argv[1:]
    p = subprocess.run([REAL] + args, capture_output=True)
    sys.stdout.buffer.write(p.stdout)
    sys.stderr.buffer.write(p.stderr)
    if p.returncode != 0 or not args or args[0] != ("unpack" if MODE == "kinfo" else MODE):
        return p.returncode
    said = p.stdout.decode("utf-8", "replace")
    if MODE == "kinfo":
        m = re.search(r"unpacked .*? -> (.+?)/?\n", said)
        if m and os.path.isdir(m.group(1)):
            flip_kinfo(m.group(1))
        return p.returncode
    if MODE == "pack":
        m = re.search(r"packed .*? -> (.+?) \(\d+ bytes\)", said)
        if not m or not os.path.isfile(m.group(1)) or os.path.getsize(m.group(1)) <= 8:
            sys.stderr.write("abr_sabotage: no image to change in what pack said\n")
            return 99
        flip_middle(m.group(1), os.path.getsize(m.group(1)))
    else:
        m = re.search(r"unpacked .*? -> (.+?)/?\n", said)
        if not m or not os.path.isdir(m.group(1)):
            sys.stderr.write("abr_sabotage: no directory to change in what unpack said\n")
            return 99
        biggest = None
        for root, _, files in os.walk(m.group(1)):
            for name in files:
                path = os.path.join(root, name)
                size = os.path.getsize(path)
                if name != "manifest.txt" and size > 8 and (biggest is None or size > biggest[0]):
                    biggest = (size, path)
        if biggest is None:
            sys.stderr.write("abr_sabotage: no file to change in what unpack wrote\n")
            return 99
        flip_middle(biggest[1], biggest[0])
    return p.returncode


sys.exit(main())
