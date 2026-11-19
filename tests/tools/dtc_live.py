#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""abr's device tree compiler (src/dts.cpp) judged by the real dtc. abr is the unit-test binary here: `abr_unit_tests dts-compile` and `dts-decompile`
run the same code that `abr pack` and `abr unpack` run on a tree; nothing of dtc is in abr, and nothing of abr is in the judge.

  golden      every source of tests/golden/dts is compiled by dtc, and what dtc writes is the .dtb that is kept there (a source dtc refuses has
              a .fail): the golden files are what dtc writes. --update-golden writes them again.
  dtc-tests   the sources of dtc's own test suite (a checkout of dtc: --dtc-tests DIR, or $ABR_DTC_TESTS), plain and with -@: dtc and abr write
              the same bytes, or both refuse. Left out when there is no checkout.
  mutation    N sources made by changing the golden ones (a line gone, doubled or swapped, a token gone, doubled or put in place of another one,
              a snippet that deletes, merges, labels or refers): the same. --fuzz N (default 400), --seed S (default 1)
  text        the blobs that dtc wrote (the golden ones, and the ones the mutations made): dtc's own text of a blob, which abr compiles to the
              bytes that dtc compiles it to; abr's text of the blob, which dtc compiles to the same bytes as it compiles its own text to.

One thing abr does not do as dtc does, on purpose: a source that deletes the root node (`/delete-node/ &{/};`) makes dtc write a blob that dtc itself
cannot read ("doesn't begin with FDT_BEGIN_NODE"); abr refuses it. The judge accepts that, and only that.

  dtc_live.py ABR_UNIT_TESTS WORKDIR [--update-golden] [--fuzz N] [--seed S] [--dtc-tests DIR]      exit status 1 when a check fails
"""
import argparse
import glob
import os
import random
import shutil
import subprocess
import sys

TOOLS = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.normpath(os.path.join(TOOLS, "..", "golden", "dts"))

ap = argparse.ArgumentParser()
ap.add_argument("unit")
ap.add_argument("work")
ap.add_argument("--update-golden", action="store_true")
ap.add_argument("--fuzz", type=int, default=400)
ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--dtc-tests", default=os.environ.get("ABR_DTC_TESTS", ""))
ARGS = ap.parse_args()
UNIT = os.path.abspath(ARGS.unit)
WORK = os.path.abspath(ARGS.work)
os.makedirs(WORK, exist_ok=True)

failures = []
checks = 0

version = subprocess.run(["dtc", "--version"], capture_output=True, text=True).stdout.strip()
if "1.7." not in version:
    # the golden blobs, and the language that abr reads, are those of dtc 1.7 (1.6 makes other blobs: it checks and names things differently)
    print("SKIP: dtc 1.7 is the judge, and `dtc --version` says %r" % version)
    sys.exit(0)


def fail(what, detail=""):
    failures.append(what)
    print("  FAIL %s %s" % (what, detail))


def run(cmd, cwd=None):
    return subprocess.run(cmd, capture_output=True, cwd=cwd, timeout=60)


def dtc_compile(src, out, symbols=False):
    return run(["dtc"] + (["-@"] if symbols else []) + ["-I", "dts", "-O", "dtb", "-o", out, src])


def abr_compile(src, out, symbols=False):
    return run([UNIT, "dts-compile", src, out] + (["-@"] if symbols else []))


def slurp(path):
    with open(path, "rb") as f:
        return f.read()


def dtc_reads(blob):
    """What dtc says to its own blob: its text, or None when dtc cannot read the blob."""
    r = run(["dtc", "-I", "dtb", "-O", "dts", blob])
    return r.stdout if r.returncode == 0 else None


def compare(label, src, symbols, expect_root_gone_ok=True):
    """dtc and abr on one source: the same bytes, or both refuse. -> the blob of dtc (or None)."""
    global checks
    checks += 1
    ref = os.path.join(WORK, "ref.dtb")
    mine = os.path.join(WORK, "abr.dtb")
    for p in (ref, mine):
        if os.path.exists(p):
            os.remove(p)
    r = dtc_compile(src, ref, symbols)
    a = abr_compile(src, mine, symbols)
    if r.returncode != 0 and a.returncode != 0:
        return None
    if r.returncode != 0 or a.returncode != 0:
        if r.returncode == 0 and expect_root_gone_ok and b"the root node is deleted" in a.stderr and dtc_reads(ref) is None:
            return None  # the one thing abr does differently
        keep = os.path.join(WORK, "fail_%d.dts" % len(failures))
        shutil.copy(src, keep)
        fail(label, "dtc %s, abr %s (%s): dtc says %r, abr says %r" % (
            "writes" if r.returncode == 0 else "refuses", "writes" if a.returncode == 0 else "refuses", keep,
            r.stderr.decode("utf-8", "replace")[:150], a.stderr.decode("utf-8", "replace")[:150]))
        return None
    if slurp(ref) != slurp(mine):
        keep = os.path.join(WORK, "fail_%d.dts" % len(failures))
        shutil.copy(src, keep)
        fail(label, "the blobs differ (%s)" % keep)
        return None
    return slurp(ref)


# --------------------------------------------------------------------------------------------------------------------------------- golden
names = sorted(os.path.basename(p)[:-4] for p in glob.glob(os.path.join(GOLDEN, "*.dts")))
for name in names:
    src = os.path.join(GOLDEN, name + ".dts")
    symbols = os.path.exists(os.path.join(GOLDEN, name + ".flags")) and b"-@" in slurp(os.path.join(GOLDEN, name + ".flags"))
    golden = os.path.join(GOLDEN, name + ".dtb")
    out = os.path.join(WORK, "golden_" + name + ".dtb")
    r = dtc_compile(src, out, symbols)
    checks += 1
    if r.returncode != 0:
        if os.path.exists(golden):
            if ARGS.update_golden:
                os.remove(golden)
            else:
                fail("golden " + name, "dtc refuses the source, and there is a .dtb")
        if not os.path.exists(os.path.join(GOLDEN, name + ".fail")):
            fail("golden " + name, "dtc refuses the source, and there is no .fail")
        continue
    if os.path.exists(os.path.join(GOLDEN, name + ".fail")):
        fail("golden " + name, "dtc compiles the source, and there is a .fail")
    if ARGS.update_golden:
        shutil.copy(out, golden)
    elif not os.path.exists(golden) or slurp(golden) != slurp(out):
        fail("golden " + name, "the .dtb is not what dtc writes")
print("golden: %d sources, %d failures so far" % (len(names), len(failures)))

# the folder the sources are read in (an /include/ and an /incbin/ are relative to the source)
SCRATCH = os.path.join(WORK, "src")
shutil.rmtree(SCRATCH, ignore_errors=True)
shutil.copytree(GOLDEN, SCRATCH)

blobs = []  # the blobs of dtc for the text checks: (label, path)
for name in names:
    p = os.path.join(GOLDEN, name + ".dtb")
    if os.path.exists(p):
        blobs.append(("golden " + name, p))

# ----------------------------------------------------------------------------------------------------------------------------- dtc-tests
tests_dir = ARGS.dtc_tests
if tests_dir and os.path.isdir(os.path.join(tests_dir, "tests")):
    tests_dir = os.path.join(tests_dir, "tests")
if tests_dir and os.path.isdir(tests_dir):
    n = 0
    for src in sorted(glob.glob(os.path.join(tests_dir, "*.dts"))):
        for symbols in (False, True):
            blob = compare("dtc-tests %s%s" % (os.path.basename(src), " -@" if symbols else ""), src, symbols)
            n += 1
            if blob is not None:
                keep = os.path.join(WORK, "dtc_test_%d.dtb" % len(blobs))
                with open(keep, "wb") as f:
                    f.write(blob)
                blobs.append(("dtc-tests " + os.path.basename(src), keep))
    print("dtc-tests: %d runs, %d failures so far" % (n, len(failures)))
else:
    print("dtc-tests: left out (no checkout of dtc: --dtc-tests DIR or $ABR_DTC_TESTS)")

# ----------------------------------------------------------------------------------------------------------------------------- mutation
rng = random.Random(ARGS.seed)
texts = [slurp(os.path.join(GOLDEN, n + ".dts")).decode("latin-1") for n in names]
vocab = ['{', '}', ';', '=', ',', '<', '>', '[', ']', '(', ')', ':', '&', '/', '"', "'", '0', '1', '0x10', '-1', '(1+2)', '&a', '&{/n}', '&{l/c}',
         '/delete-node/', '/delete-property/', '/omit-if-no-ref/', '/bits/', '8', '16', '32', '64', '/incbin/', '/memreserve/', '/plugin/', '/dts-v1/',
         'x:', 'l:', 'a', 'n', 'phandle', 'name', 'linux,phandle', '<&a>', '<&l>', '"s"', '\n', ' ', '\t', '/* c */', '// c\n', '\\', '@', '#', '?', '*',
         '.', '+', '-', '~', '!', '<<', '>>', '==', '&&', '||', '1 ? 2 : 3', '\x00', '\xc3\xa9']
snippets = ['&l { added; };', '/delete-node/ &l;', '/delete-node/ &a;', 'x9: extra { y = <&l &a>; };', '/ { n { q = <1>; }; };', '&n { z = "z"; };',
            '/ { /delete-property/ a; };', '/ { n { /delete-node/ c; }; };', '/ { p = &l; };', '/ { r = <&x9>; };', '/ { phandle = <9>; };',
            '/omit-if-no-ref/ &l;', '/ { omitted: /omit-if-no-ref/ o { }; };', '&{/n} { w; };', '&{l} { v; };', 'l: &n { u; };']


def tokens(t):
    out, cur = [], ''
    for ch in t:
        if ch in ' \n\t;{}<>[]()=,:&/"\'':
            if cur:
                out.append(cur)
                cur = ''
            out.append(ch)
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def mutate_lines(t):
    ls = t.split('\n')
    for _ in range(rng.choice([1, 2, 3])):
        k = rng.randrange(5)
        i = rng.randrange(len(ls)) if ls else 0
        if k == 0 and len(ls) > 1:
            del ls[i]
        elif k == 1:
            ls.insert(i, ls[rng.randrange(len(ls))])
        elif k == 2 and len(ls) > 1:
            j = rng.randrange(len(ls))
            ls[i], ls[j] = ls[j], ls[i]
        else:
            ls.insert(rng.randrange(len(ls) + 1), rng.choice(snippets))
    return '\n'.join(ls)


def mutate(t):
    if rng.random() < 0.3:  # snippets behind the source: they merge into, delete from or refer to what is there, and mostly stay a source
        return t + '\n' + '\n'.join(rng.choice(snippets) for _ in range(rng.choice([1, 2, 3]))) + '\n'
    if rng.random() < 0.6:
        return mutate_lines(t)
    tk = tokens(t)
    for _ in range(rng.choice([1, 1, 2, 3])):
        k = rng.randrange(5)
        i = rng.randrange(len(tk)) if tk else 0
        if k == 0 and tk:
            del tk[i]
        elif k == 1:
            tk.insert(i, rng.choice(vocab))
        elif k == 2 and tk:
            tk[i] = rng.choice(vocab)
        elif k == 3 and tk:
            j = rng.randrange(len(tk))
            tk[i], tk[j] = tk[j], tk[i]
        elif k == 4 and tk:
            tk.insert(i, tk[rng.randrange(len(tk))])
    return ''.join(tk)


mutated = os.path.join(SCRATCH, "fz.dts")
made = 0
for it in range(ARGS.fuzz):
    text = mutate(rng.choice(texts))
    with open(mutated, "w", encoding="latin-1", errors="replace") as f:
        f.write(text)
    symbols = rng.random() < 0.2
    blob = compare("mutation %d (seed %d)" % (it, ARGS.seed), mutated, symbols)
    if blob is not None:
        made += 1
        if len(blobs) < 400:
            keep = os.path.join(WORK, "mutant_%d.dtb" % it)
            with open(keep, "wb") as f:
                f.write(blob)
            blobs.append(("mutation %d" % it, keep))
print("mutation: %d sources (seed %d), %d compiled, %d failures so far" % (ARGS.fuzz, ARGS.seed, made, len(failures)))

# -------------------------------------------------------------------------------------------------------------------------------- text
texted = 0
for label, blob in blobs:
    checks += 1
    theirs = dtc_reads(blob)
    if theirs is None:
        continue  # a blob that dtc does not read
    text_dtc = os.path.join(SCRATCH, "text_dtc.dts")
    with open(text_dtc, "wb") as f:
        f.write(theirs)
    # (1) the text that dtc writes: abr compiles it to what dtc compiles it to
    compare("text of dtc: " + label, text_dtc, False, False)
    # (2) the text that abr writes: dtc compiles it to what it compiles its own text to
    text_abr = os.path.join(SCRATCH, "text_abr.dts")
    r = run([UNIT, "dts-decompile", blob, text_abr])
    if r.returncode != 0:
        # abr says it cannot write the text of this blob: only a blob that is not a tree of a source qualifies
        fail("text of abr: " + label, "abr cannot write the text: " + r.stderr.decode("utf-8", "replace")[:150])
        continue
    out_abr = os.path.join(WORK, "t_abr.dtb")
    out_dtc = os.path.join(WORK, "t_dtc.dtb")
    ra = dtc_compile(text_abr, out_abr)
    rd = dtc_compile(text_dtc, out_dtc)
    if ra.returncode != 0:
        if rd.returncode != 0:
            continue  # dtc refuses its own text too (a blob that no source says)
        fail("text of abr: " + label, "dtc refuses it: " + ra.stderr.decode("utf-8", "replace")[:200])
        continue
    if rd.returncode == 0 and slurp(out_abr) != slurp(out_dtc):
        fail("text of abr: " + label, "dtc compiles it to another blob than its own text")
        continue
    texted += 1
    if rd.returncode == 0 and slurp(out_dtc) == slurp(blob) and slurp(out_abr) != slurp(blob):
        fail("text of abr: " + label, "the blob is a fixed point of dtc, and abr's text is not")
print("text: %d blobs, %d texts of abr compile with dtc" % (len(blobs), texted))

print("dtc_live: %d checks, %d failure(s)" % (checks, len(failures)))
sys.exit(1 if failures else 0)
