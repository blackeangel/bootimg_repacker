#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Judge of what `abr unpack` keeps of the padding behind the components of an image.

    padding_check.py <unpacked directory> <name.gaps.json>

The JSON (made by tests/tools/fixtures.py, from the format and not from abr) maps a component's name to the bytes that
the image holds from the end of that component to the last byte that is not zero (hex). The directory must have a
`<component>_padding.bin` with exactly those bytes for every one of them, and no such file for any other component (the
padding of the header page, `header_padding.bin`, is another thing and is not looked at), and manifest.txt must name
each of the files by a `<component>_padding_file=` line and no other. Prints what is wrong and exits 1, or prints
`ok <n>` and exits 0.
"""
import json
import re
import sys
from pathlib import Path


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    d, want = Path(argv[1]), json.loads(Path(argv[2]).read_text())
    problems = []
    for comp, hexa in sorted(want.items()):
        f = d / f"{comp}_padding.bin"
        if not f.is_file():
            problems.append(f"{f.name}: missing")
        elif f.read_bytes() != bytes.fromhex(hexa):
            problems.append(f"{f.name}: {f.stat().st_size} bytes, other than the {len(hexa) // 2} expected")
    have = {m.group(1) for p in d.glob("*_padding.bin") if (m := re.fullmatch(r"(.+)_padding\.bin", p.name))}
    have.discard("header")
    for comp in sorted(have - set(want)):
        problems.append(f"{comp}_padding.bin: not expected (that padding is zeros)")
    keys = set()
    manifest = d / "manifest.txt"
    if manifest.is_file():
        for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.fullmatch(r"([a-z_]+)_padding_file=(.*)", line.strip())
            if m and m.group(1) != "header":
                keys.add(m.group(1))
                if m.group(2).strip() != f"{m.group(1)}_padding.bin":
                    problems.append(f"manifest.txt: {m.group(1)}_padding_file names {m.group(2).strip()!r}")
    if keys != set(want):
        problems.append(f"manifest.txt names the padding of {sorted(keys)}, expected {sorted(want)}")
    if problems:
        print("; ".join(problems))
        return 1
    print(f"ok {len(want)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
