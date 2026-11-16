#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""A sabotaged abr, to see that the judges of the suite notice: it runs the real abr (ABR_REAL) with the arguments it is given and then changes ONE byte of
what the real one wrote. Its output and its exit status are the real abr's, so a driver cannot tell from them.

  SAB=pack     the byte in the middle of the image that `pack` wrote
  SAB=unpack   the byte in the middle of the biggest file (not manifest.txt) that `unpack` wrote

It is used through tests/tools/sabotage_check.sh; a driver is run with this file where it expects abr:

  ABR_REAL=build/abr SAB=pack python3 -I tests/tools/mbn_live.py tests/tools/abr_sabotage.py <the arguments of the driver>

A driver that passes against it judges nothing. (The one byte is found from what abr says it wrote: "packed ... -> FILE (N bytes)" and
"unpacked ... -> DIRECTORY/"; if abr's words change and the byte is not found, this script ends with status 99 and says so, which fails the driver as well.)"""
import os
import re
import subprocess
import sys

REAL = os.environ.get("ABR_REAL")
MODE = os.environ.get("SAB", "pack")
if not REAL or MODE not in ("pack", "unpack"):
    sys.exit("abr_sabotage.py: ABR_REAL names the real abr and SAB is pack or unpack")


def flip_middle(path, size):
    with open(path, "r+b") as f:
        f.seek(size // 2)
        b = f.read(1)
        f.seek(size // 2)
        f.write(bytes([b[0] ^ 0x55]))


def main():
    args = sys.argv[1:]
    p = subprocess.run([REAL] + args, capture_output=True)
    sys.stdout.buffer.write(p.stdout)
    sys.stderr.buffer.write(p.stderr)
    if p.returncode != 0 or not args or args[0] != MODE:
        return p.returncode
    said = p.stdout.decode("utf-8", "replace")
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
