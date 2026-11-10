#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Is a library that abr is built with behind its newest release?

abr builds zlib, LZ4, zstd, xz and bzip2 from source at the versions that cmake/dependency_versions.cmake names, and LZO from
third_party/lzo. This asks the repository of each library which release is the newest (`git ls-remote`; for LZO, which has no repository, the
download page of its author) and says which of them are behind.

    tools/check_deps.py             a table of the libraries
    tools/check_deps.py --markdown  the same as a Markdown table (what .github/workflows/deps.yml puts into the summary of its run)
    tools/check_deps.py --strict    a library that cannot be asked is a failure too

Exit status: 0 nothing is behind (a library that could not be asked is said, and no more); 1 something is behind (with --strict: or could not
be asked); 2 the versions cannot be read.

What a release is, is the rule of `cmake -DABR_DEPS_LATEST=ON` (cmake/vendor_deps.cmake): a tag of the library's prefix and a version of two or three
numbers (v1.4, v1.11.0, bzip2-1.0.8). What has anything else in it -- v1.5.7-kernel, v5.7.2beta, v1.3.1.2, a snapshot -- is not one.
"""
import argparse
import os
import re
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# name, the key in cmake/dependency_versions.cmake, the repository, the prefix of a release's tag
LIBRARIES = [
    ("zlib", "ZLIB", "https://github.com/madler/zlib.git", "v"),
    ("LZ4", "LZ4", "https://github.com/lz4/lz4.git", "v"),
    ("zstd", "ZSTD", "https://github.com/facebook/zstd.git", "v"),
    ("xz", "XZ", "https://github.com/tukaani-project/xz.git", "v"),
    ("bzip2", "BZIP2", "https://github.com/libarchive/bzip2.git", "bzip2-"),
]

LZO_PAGE = "https://www.oberhumer.com/opensource/lzo/download/"


def as_tuple(version):
    return tuple(int(part) for part in version.split("."))


def pins(path):
    """{"ZLIB": "1.4", ...} from the abr_pin(ABR_<NAME>_VERSION "<version>") lines of the file."""
    found = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r'\s*abr_pin\(\s*ABR_([A-Z0-9]+)_VERSION\s+"([0-9][0-9.]*)"\s*\)', line)
            if m:
                found[m.group(1)] = m.group(2)
    return found


def lzo_pin():
    """The version of the copy in third_party/lzo (LZO_VERSION_STRING of lzoconf.h)."""
    path = os.path.join(ROOT, "third_party", "lzo", "include", "lzo", "lzoconf.h")
    with open(path, encoding="utf-8", errors="replace") as f:
        m = re.search(r'#\s*define\s+LZO_VERSION_STRING\s+"([0-9][0-9.]*)"', f.read())
    return m.group(1) if m else None


def newest_tag(repository, prefix):
    """The newest release the repository tags, or None when it cannot be asked."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        out = subprocess.run(["git", "ls-remote", "--tags", "--refs", repository], capture_output=True, text=True, timeout=120, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    rule = re.compile(r"refs/tags/" + re.escape(prefix) + r"([0-9]+(?:\.[0-9]+){1,2})$")
    versions = [m.group(1) for m in (rule.search(line) for line in out.stdout.splitlines()) if m]
    return max(versions, key=as_tuple) if versions else None


def newest_lzo():
    """The newest lzo-<version>.tar.gz on the page of its author, or None when the page cannot be read."""
    try:
        with urllib.request.urlopen(LZO_PAGE, timeout=60) as page:
            text = page.read().decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    versions = re.findall(r"lzo-([0-9]+(?:\.[0-9]+){1,2})\.tar\.gz", text)
    return max(versions, key=as_tuple) if versions else None


def status(pinned, newest):
    if newest is None:
        return "cannot be asked"
    if as_tuple(pinned) < as_tuple(newest):
        return "BEHIND"
    if as_tuple(pinned) > as_tuple(newest):
        return "ahead of the newest release that is tagged"
    return "up to date"


def main():
    ap = argparse.ArgumentParser(description="Is a library that abr is built with behind its newest release?")
    ap.add_argument("--markdown", action="store_true", help="print a Markdown table")
    ap.add_argument("--strict", action="store_true", help="a library that cannot be asked is a failure too")
    ap.add_argument("--pins", default=os.path.join(ROOT, "cmake", "dependency_versions.cmake"), help="the file of the versions")
    args = ap.parse_args()

    try:
        pinned = pins(args.pins)
    except OSError as e:
        print(f"check_deps: cannot read {args.pins}: {e}", file=sys.stderr)
        return 2

    rows = []  # name, pinned, newest, status
    for name, key, repository, prefix in LIBRARIES:
        if key not in pinned:
            print(f"check_deps: {args.pins} has no abr_pin for ABR_{key}_VERSION", file=sys.stderr)
            return 2
        newest = newest_tag(repository, prefix)
        rows.append((name, pinned[key], newest, status(pinned[key], newest)))
    try:
        lzo = lzo_pin()
    except OSError as e:
        print(f"check_deps: cannot read third_party/lzo: {e}", file=sys.stderr)
        return 2
    if lzo is None:
        print("check_deps: third_party/lzo/include/lzo/lzoconf.h has no LZO_VERSION_STRING", file=sys.stderr)
        return 2
    newest = newest_lzo()
    rows.append(("LZO (third_party/lzo)", lzo, newest, status(lzo, newest)))

    if args.markdown:
        print("| library | in abr | newest release | |")
        print("|---|---|---|---|")
        for name, have, newest, state in rows:
            print(f"| {name} | {have} | {newest or '?'} | {state} |")
    else:
        width = max(len(r[0]) for r in rows)
        for name, have, newest, state in rows:
            print(f"{name:<{width}}  {have:<8} {newest or '?':<8} {state}")

    behind = [r for r in rows if r[3] == "BEHIND"]
    unknown = [r for r in rows if r[3] == "cannot be asked"]
    if behind:
        print("\nbehind: " + ", ".join(f"{r[0]} {r[1]} -> {r[2]}" for r in behind) + "\n"
              "(bump cmake/dependency_versions.cmake, or for LZO replace third_party/lzo; then build and run the unit tests)", file=sys.stderr)
    if unknown:
        print("\ncould not be asked: " + ", ".join(r[0] for r in unknown), file=sys.stderr)
    return 1 if behind or (args.strict and unknown) else 0


if __name__ == "__main__":
    sys.exit(main())
