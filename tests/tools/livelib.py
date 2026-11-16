# SPDX-License-Identifier: GPL-3.0-or-later
"""What the live drivers (mbn_live.py, mtk_live.py, qcdt_live.py, ...) have in common: running abr, counting checks, working in directories that are
made new, reading and setting the keys of a manifest, and the damaged-image runs (cut short, bytes changed): abr must refuse or take every one,
say something when it refuses, and pack again what it took."""
import os
import random
import shutil
import subprocess
import sys
import traceback


class _Section:
    """`with live.section("label"):` -- a check that itself falls over (a file that is not there, a table that cannot be read because abr wrote it wrong) is a
    FAIL line, and the next section runs; without it the first image abr writes wrong would end the run with a traceback and hide the rest."""

    def __init__(self, live, label):
        self.live, self.label = live, label

    def __enter__(self):
        return self

    def __exit__(self, kind, value, tb):
        if kind is None or issubclass(kind, (SystemExit, KeyboardInterrupt)):
            return False
        line = traceback.extract_tb(tb)[-1].lineno
        self.live.check(False, "%s: the check itself stopped (%s: %s, line %d); the rest of this section was not run" % (self.label, kind.__name__, value, line))
        return True


class Live:
    def section(self, label):
        return _Section(self, label)

    def __init__(self, abr, work):
        self.abr = abr
        self.work = work
        self.env = dict(os.environ, NO_COLOR="1", ABR_PROGRESS="0")
        self.passed = 0
        self.failed = []
        os.makedirs(work, exist_ok=True)

    def check(self, ok, what, detail=""):
        if ok:
            self.passed += 1
        else:
            self.failed.append(what)
            print("FAIL:", what, ("-- " + str(detail)[-500:].replace("\n", " | ")) if detail else "")
        return bool(ok)

    def run(self, *args, env=None, timeout=120):
        """-> (exit status, stdout + stderr); 124 for a run that took more than `timeout` seconds."""
        e = dict(self.env, **(env or {}))
        try:
            r = subprocess.run([self.abr, *args], capture_output=True, text=True, errors="replace", env=e, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, "timeout"
        return r.returncode, r.stdout + r.stderr

    def path(self, *parts):
        return os.path.join(self.work, *parts)

    def fresh(self, *parts):
        """A path in the work directory that is free: what was there is gone."""
        p = self.path(*parts)
        if os.path.lexists(p):
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.unlink(p)
        return p

    def finish(self, what):
        print("%s: %d checks passed, %d failed" % (what, self.passed, len(self.failed)))
        for f in self.failed:
            print("  -", f)
        return 1 if self.failed else 0

    def damaged(self, name, data, seed, head=None, mutants=24):
        """Cut-offs and changed bytes of `data` (the changes within the first `head` bytes, headers and tables, when that is given): `info` and `unpack`
        of each must not crash, hang or fail without a word, and an unpack that worked must pack again. -> the number of runs."""
        rnd = random.Random(seed)
        cases = [("cut%d" % c, data[:-c]) for c in (1, 7, 100, 513, len(data) // 2) if 0 < c < len(data)]
        limit = min(len(data), head or len(data))
        for _ in range(int(os.environ.get("ABR_LIVE_MUTANTS", mutants))):  # (fewer under wine, where every run of abr starts a process of its own)
            b = bytearray(data)
            for _ in range(rnd.randrange(1, 4)):
                b[rnd.randrange(0, limit)] = rnd.randrange(256)
            cases.append(("mut", bytes(b)))
        runs = 0
        for tag, blob in cases:
            p = self.path("damaged.bin")
            with open(p, "wb") as f:
                f.write(blob)
            for verb in ("info", "unpack"):
                runs += 1
                out = self.fresh("damaged_out")
                rc, text = self.run(verb, "-i", p, *(["-o", out] if verb == "unpack" else []), timeout=60)
                if rc == 124:
                    self.check(False, "%s %s %s: hangs" % (name, tag, verb))
                elif rc < 0 or rc >= 124 or "terminate called" in text or "Assertion" in text or "Segmentation" in text:
                    self.check(False, "%s %s %s: died (status %d)" % (name, tag, verb, rc), text)
                elif rc != 0 and not text.strip():
                    self.check(False, "%s %s %s: failed without a word" % (name, tag, verb))
                elif verb == "unpack" and rc == 0:
                    rc2, t2 = self.run("pack", "-i", out, "-o", self.fresh("damaged_back.bin"))
                    self.check(rc2 == 0, "%s %s: an image that unpack took packs again" % (name, tag), t2)
                else:
                    self.passed += 1
        return runs


def read(path):
    with open(path, "rb") as f:
        return f.read()


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def same_bytes(a, b):
    return os.path.isfile(a) and os.path.isfile(b) and read(a) == read(b)


def manifest_get(folder, key):
    with open(os.path.join(folder, "manifest.txt"), encoding="utf-8", errors="replace") as f:
        for line in f.read().split("\n"):
            if line.startswith(key + "="):
                return line.split("=", 1)[1]
    return None


def manifest_set(folder, key, value):
    """Sets key=value in manifest.txt (a key that is not there is added at the end); value None deletes the key."""
    p = os.path.join(folder, "manifest.txt")
    with open(p, encoding="utf-8", errors="replace") as f:
        lines = f.read().split("\n")
    out, done = [], False
    for line in lines:
        if line.startswith(key + "="):
            done = True
            if value is not None:
                out.append("%s=%s" % (key, value))
        else:
            out.append(line)
    if not done and value is not None:
        at = len(out) - 1 if out and out[-1] == "" else len(out)
        out.insert(at, "%s=%s" % (key, value))
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(out))


def script_dir():
    return os.path.dirname(os.path.abspath(__file__))
