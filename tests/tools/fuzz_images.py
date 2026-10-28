#!/usr/bin/env python3
"""Mutation fuzzing of the abr command line.

Takes images (the seeds), damages them the ways images are damaged -- a size field that is too big, a cut-off file, a
flipped bit, a block taken out or doubled, a piece of another image spliced in -- and runs abr on each damaged copy:
`identify`, `info`, `unpack`, and `repack` of what `unpack` wrote. What is judged is not what abr says but how it
behaves. A damaged image may be refused (exit status 1 and a message) or taken; it must never crash, hang, run out of
memory or stop for a reason that is not the image's (an exception of the standard library that nobody meant to
reach), never print a control character (an escape sequence in a name or a command line that an image holds would be
obeyed by a terminal: abr writes such text with escapes), and when abr was built with -DABR_SANITIZE=address,undefined,
AddressSanitizer and UndefinedBehaviorSanitizer must have nothing to say:

    cmake -S . -B build-asan -G Ninja -DABR_SANITIZE=address,undefined && cmake --build build-asan
    ABR_KEEP_WORK=1 tests/run_tests.sh build-asan/abr           # (makes the images of the suite; its last note names the directory)
    tests/tools/fuzz_images.py --abr build-asan/abr --seeds <that directory> --iterations 20

Every run is determined by --rng-seed, the seed file and the iteration number, so a finding is rebuilt by the same
command; the damaged file that did it is also kept in --findings, with the command and what abr printed, and
`--repro FILE` runs the commands on a file as it is. Exit status: 0 = nothing found, 1 = findings, 2 = usage.
"""

import argparse
import concurrent.futures
import hashlib
import os
import random
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

SANITIZER = re.compile(
    rb"AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|ThreadSanitizer|MemorySanitizer|runtime error:"
)
# What the standard library says when nothing in abr looked at the value first: abr's own refusals are worded for people.
STDLIB_EXCEPTION = re.compile(
    rb"std::bad_|cannot create std::|vector::|basic_string|map::at|_M_range_check|deque::|array::at|stoul|stoi|stoll"
)

# What a terminal would act on, or show as something else: control characters but the tab and the line break (ESC, BEL,
# backspace, carriage return, DEL ...), the C1 controls (a single byte, or U+0080-U+009F in UTF-8: U+009B is CSI), and
# anything that is not UTF-8 (a terminal of another encoding reads it as it likes). SUSPECT finds a place to look at: any
# byte of that kind, among them every byte from 0x80 on; UTF8_PIECE says whether the byte starts a well-formed character.
SUSPECT = re.compile(rb"[\x00-\x08\x0b-\x1f\x7f-\xff]")
UTF8_PIECE = re.compile(rb"[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]|"
                        rb"\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2}")
# what m_text puts into a piece of text of an image
CONTROL_TEXT = [b"\x1b", b"\x1b[2J", b"\x1b]0;x\x07", b"\x07", b"\r", b"\x08", b"\x7f", b"\x9b", b"\xc2\x9b", b"\xc2\x80", b"\xff", b"\xc0\xaf",
                b"\xed\xa0\x80", b"\xe2\x82", b"\x00"]
PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")

BASE32 = [
    0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 0x7F, 0x80, 0xFF, 0x100, 0x1FF, 0x200, 0x400, 0x800, 0x1000, 0x7FFF,
    0x8000, 0xFFFF, 0x10000, 0xFFFFFF, 0x1000000, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF,
]
BASE64 = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF]
HEX_VALUES = [b"00000000", b"00000001", b"7FFFFFFF", b"80000000", b"FFFFFFFF", b"FFFFFFF0", b"0000FFFF", b"00001000", b"ffffffff"]
CPIO_MAGICS = (b"070701", b"070702")


def to_word(value, size, big):
    return (value & ((1 << (8 * size)) - 1)).to_bytes(size, "big" if big else "little")


def from_word(chunk, big):
    return int.from_bytes(chunk, "big" if big else "little")


class Context:
    def __init__(self, data, splice_source):
        self.size = len(data)
        self.header = min(self.size, 4096)
        self.splice_source = splice_source  # a callable: () -> bytes of another seed


def pick_offset(rng, ctx, width, hot=0.75):
    """An offset for a field: mostly in the first 4096 bytes (where the headers are), aligned to its width."""
    limit = ctx.header if rng.random() < hot else ctx.size
    if limit < width:
        return None
    off = rng.randrange(0, limit - width + 1)
    if rng.random() < 0.85:
        off -= off % width
    return off


def interesting(rng, ctx, old, bits):
    mask = (1 << bits) - 1
    c = rng.random()
    if c < 0.35:
        return rng.choice(BASE32 if bits <= 32 else BASE64)
    if c < 0.55:
        return (ctx.size + rng.choice((-4096, -512, -16, -4, -2, -1, 0, 1, 2, 4, 16, 512, 4096))) & mask
    if c < 0.75:
        return (old + rng.choice((-4096, -3, -2, -1, 1, 2, 3, 4095, 4096))) & mask
    if c < 0.85:
        return (old << rng.randint(1, 8)) & mask
    if c < 0.92:
        return rng.randrange(0, ctx.size + 1)
    return rng.getrandbits(bits)


def m_field(rng, buf, ctx):
    width = rng.choice((1, 2, 4, 4, 4, 8))
    off = pick_offset(rng, ctx, width)
    if off is None:
        return None
    big = rng.random() < 0.3
    old = from_word(buf[off : off + width], big)
    new = interesting(rng, ctx, old, 8 * width)
    buf[off : off + width] = to_word(new, width, big)
    return f"field{8 * width}{'be' if big else 'le'}@{off}={new:#x}"


def m_bitflip(rng, buf, ctx):
    count = rng.randint(1, 8)
    places = []
    for _ in range(count):
        off = rng.randrange(0, ctx.header if rng.random() < 0.5 else ctx.size)
        buf[off] ^= 1 << rng.randrange(8)
        places.append(off)
    return "bitflip@" + ",".join(map(str, places))


def m_byteset(rng, buf, ctx):
    count = rng.randint(1, 8)
    places = []
    for _ in range(count):
        off = rng.randrange(0, ctx.header if rng.random() < 0.6 else ctx.size)
        buf[off] = rng.choice((0, 0xFF, 0x7F, 0x80, rng.randrange(256)))
        places.append(off)
    return "byteset@" + ",".join(map(str, places))


def m_truncate(rng, buf, ctx):
    c = rng.random()
    if c < 0.3:
        length = rng.randrange(0, len(buf))
    elif c < 0.5:
        length = max(0, len(buf) - rng.choice((1, 2, 3, 4, 8, 16, 64, 511, 512, 4095, 4096)))
    elif c < 0.7:
        step = rng.choice((512, 2048, 4096, 8192))
        length = max(0, (rng.randrange(0, len(buf)) // step) * step + rng.choice((-1, 0, 0, 1)))
    elif c < 0.85 and ctx.header >= 4:
        off = pick_offset(rng, ctx, 4, hot=1.0)
        length = int.from_bytes(buf[off : off + 4], "little") if off is not None else 0
        if length >= len(buf):
            length = len(buf) // 2
    else:
        length = rng.randrange(0, min(len(buf), 4096))
    del buf[length:]
    return f"truncate={length}"


def m_append(rng, buf, ctx):
    count = rng.choice((1, 3, 16, 100, 511, 4096, 4097, 65536))
    fill = rng.choice(("zero", "ff", "random"))
    buf += bytes(count) if fill == "zero" else (b"\xff" * count if fill == "ff" else rng.randbytes(count))
    return f"append={count}{fill}"


def m_cut(rng, buf, ctx):
    if len(buf) < 2:
        return None
    a = rng.randrange(0, len(buf) if rng.random() < 0.5 else min(len(buf), 4096))
    n = rng.choice((1, 2, 4, 16, 100, 512, 4096, rng.randint(1, 65536)))
    del buf[a : a + n]
    return f"cut@{a}+{n}"


def m_insert(rng, buf, ctx):
    a = rng.randrange(0, len(buf) + 1 if rng.random() < 0.5 else min(len(buf), 4096) + 1)
    n = rng.choice((1, 4, 16, 100, 512, 4096))
    buf[a:a] = rng.randbytes(n) if rng.random() < 0.5 else bytes(n)
    return f"insert@{a}+{n}"


def m_dup(rng, buf, ctx):
    if len(buf) < 2:
        return None
    a = rng.randrange(0, len(buf) - 1)
    n = min(rng.choice((4, 16, 64, 512, 4096, 65536)), len(buf) - a)
    b = rng.randrange(0, len(buf))
    buf[b:b] = buf[a : a + n]
    return f"dup {a}+{n} to {b}"


def m_zero(rng, buf, ctx):
    if len(buf) < 2:
        return None
    a = rng.randrange(0, len(buf) if rng.random() < 0.5 else min(len(buf), 4096))
    n = rng.choice((1, 2, 4, 8, 16, 64, 512, 4096))
    buf[a : a + n] = bytes(min(n, len(buf) - a))
    return f"zero@{a}+{n}"


def m_swap(rng, buf, ctx):
    if ctx.header < 16:
        return None
    a = pick_offset(rng, ctx, 4, hot=1.0)
    b = pick_offset(rng, ctx, 4, hot=1.0)
    buf[a : a + 4], buf[b : b + 4] = bytes(buf[b : b + 4]), bytes(buf[a : a + 4])
    return f"swap4 {a}<->{b}"


def m_splice(rng, buf, ctx):
    other = ctx.splice_source()
    if not other:
        return None
    n = min(rng.choice((16, 128, 1024, 4096, 65536)), len(other))
    src = rng.randrange(0, len(other) - n + 1)
    dst = rng.randrange(0, len(buf) if rng.random() < 0.5 else min(len(buf), 4096) + 1)
    buf[dst : dst + n] = other[src : src + n]
    return f"splice {n} from other@{src} to {dst}"


def m_cpio_field(rng, buf, ctx):
    """A field of a "newc" cpio header (13 fields of 8 hexadecimal digits after the magic)."""
    starts = []
    for magic in CPIO_MAGICS:
        at = bytes(buf).find(magic)
        while at != -1 and len(starts) < 64:
            starts.append(at)
            at = bytes(buf).find(magic, at + 1)
    if not starts:
        return None
    at = rng.choice(starts)
    field = rng.randrange(13)
    off = at + 6 + 8 * field
    if off + 8 > len(buf):
        return None
    value = rng.choice(HEX_VALUES)
    buf[off : off + 8] = value
    return f"cpio-field{field}@{off}={value.decode()}"


def m_text(rng, buf, ctx):
    """A control character, a C1 control or a byte that is not UTF-8 inside a piece of text (four or more printable characters) of the image:
    the command lines, names and strings an image holds, that abr prints and puts into manifest.txt."""
    if rng.random() < 0.7 or len(buf) <= 4096:
        window = (0, min(len(buf), 4096))
    else:
        start = rng.randrange(0, max(1, len(buf) - (1 << 18)))
        window = (start, min(len(buf), start + (1 << 18)))
    runs = [m for _, m in zip(range(300), PRINTABLE_RUN.finditer(bytes(buf[window[0] : window[1]])))]
    if not runs:
        return None
    run = rng.choice(runs)
    piece = rng.choice(CONTROL_TEXT)
    lo, hi = window[0] + run.start(), window[0] + run.end()
    if hi - lo < len(piece):
        return None
    at = rng.randrange(lo, hi - len(piece) + 1)
    buf[at : at + len(piece)] = piece
    return f"text@{at}={piece!r}"


MUTATORS = [
    (m_field, 30),
    (m_bitflip, 10),
    (m_byteset, 8),
    (m_truncate, 10),
    (m_append, 6),
    (m_cut, 7),
    (m_insert, 5),
    (m_dup, 5),
    (m_zero, 5),
    (m_swap, 4),
    (m_splice, 4),
    (m_cpio_field, 6),
    (m_text, 8),
]


def mutate(rng, data, splice_source):
    buf = bytearray(data)
    ctx = Context(data, splice_source)
    notes = []
    rounds = 1 + (rng.random() < 0.4) + (rng.random() < 0.15)
    for _ in range(rounds):
        if not buf:
            break
        ctx.size = len(buf)
        ctx.header = min(ctx.size, 4096)
        for _try in range(5):
            fn = rng.choices([m for m, _ in MUTATORS], [w for _, w in MUTATORS])[0]
            note = fn(rng, buf, ctx)
            if note:
                notes.append(note)
                break
    return bytes(buf), notes


ASAN_START_FAILED = re.compile(rb"==[0-9]+==ERROR: AddressSanitizer (?:setrlimit|getrlimit)\(\) failed [0-9]+")


class Runner:
    def __init__(self, args):
        self.abr = os.path.abspath(args.abr)
        self.timeout = args.timeout
        self.env = dict(os.environ)
        # exit codes of their own: abr's refusal is 1, and a sanitizer's report must not pass for one
        self.env["ASAN_OPTIONS"] = ":".join(
            [
                "detect_leaks=1",
                "exitcode=86",
                "abort_on_error=0",
                "strict_string_checks=1",
                "detect_stack_use_after_return=1",
                "allocator_may_return_null=0",
                f"max_allocation_size_mb={args.max_alloc_mb}",
                f"hard_rss_limit_mb={args.max_rss_mb}",
            ]
        )
        self.env["UBSAN_OPTIONS"] = "print_stacktrace=1:exitcode=87:halt_on_error=1"
        # abr's output passes a filter that writes control characters as escapes; without it a message that took text out of an image
        # and did not escape it shows (that is a finding too: the filter is the last line of defence, not the first)
        self.env["ABR_UNFILTERED_OUTPUT"] = "0" if args.filtered else "1"
        self.max_file = args.max_output_mb << 20

    def run(self, argv, cwd):
        """-> (status or None for a timeout, stderr bytes, seconds, stdout bytes)"""
        # AddressSanitizer's runtime sometimes fails to start ("setrlimit() failed 1", once in some thousand runs, and not again
        # when the same command is run again): none of abr has run, nothing is written, so the run is made again, and a start that
        # fails three times in a row is a finding.
        for _ in range(2):
            result = self.run_once(argv, cwd)
            if result[0] != 86 or not ASAN_START_FAILED.fullmatch(result[1].strip()):
                return result
        return self.run_once(argv, cwd)

    def run_once(self, argv, cwd):
        t0 = time.time()
        proc = subprocess.Popen(
            [self.abr] + argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
            cwd=cwd,
            start_new_session=True,
        )
        try:
            # (not preexec_fn: it is not safe in a program with threads; the child has hardly begun, and nothing is written yet)
            resource.prlimit(proc.pid, resource.RLIMIT_CORE, (0, 0))
            resource.prlimit(proc.pid, resource.RLIMIT_FSIZE, (self.max_file, self.max_file))
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            out, err = proc.communicate(timeout=self.timeout)
            return proc.returncode, err, time.time() - t0, out
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            out, err = proc.communicate()
            return None, err, time.time() - t0, out


def terminal_trouble(command, text):
    """-> (signature, report) when `text` (what abr printed) has something a terminal would act on, else None."""
    i = 0
    while True:
        m = SUSPECT.search(text, i)
        if not m:
            return None
        at = m.start()
        c = text[at]
        if c < 0x80:
            kind = f"control byte {c:#04x}"
            break
        piece = UTF8_PIECE.match(text, at)
        if not piece:
            kind = f"byte {c:#04x} that is not UTF-8"
            break
        if c == 0xC2 and text[at + 1] < 0xA0:
            kind = f"C1 control U+{text[at + 1]:04X}"
            break
        i = piece.end()  # (well-formed UTF-8: nothing for a terminal to take for something else)
    line_start = text.rfind(b"\n", 0, at) + 1
    line_end = text.find(b"\n", at)
    line = text[line_start : line_end if line_end != -1 else len(text)]
    before = re.sub(rb"[0-9]+", b"N", text[line_start:at])[:40].decode(errors="replace")
    return f"{command}: {kind} after {before!r}", f"a line of the output has a {kind} in it:\n".encode() + repr(line[:400]).encode() + b"\n"


def classify(command, status, err, out=b""):
    """-> (class, signature) or None when abr behaved: a refusal (1) or success (0) without a sanitizer's word."""
    if SANITIZER.search(err) or status in (86, 87):
        summary = re.search(rb"SUMMARY: ([^\n]*)", err)
        runtime = re.search(rb"([^\s:]+:\d+(?::\d+)?): runtime error: ([^\n]*)", err)
        if summary:
            sig = summary.group(1).decode(errors="replace")
        elif runtime:
            sig = (runtime.group(1) + b" " + runtime.group(2)).decode(errors="replace")
        else:
            sig = "sanitizer exit"
        return "sanitizer", re.sub(r"0x[0-9a-f]+", "0x?", sig)
    if status is None:
        return "timeout", command
    if status < 0:
        return f"signal{-status}", command
    if status not in (0, 1):
        return f"exit{status}", command
    if status == 1 and STDLIB_EXCEPTION.search(err):
        line = [l for l in err.splitlines() if STDLIB_EXCEPTION.search(l)][0]
        return "stdlib-exception", command + ": " + re.sub(r"\d+", "N", line.decode(errors="replace"))
    trouble = terminal_trouble(command, err + b"\n" + out)
    if trouble:
        return "terminal", trouble[0]
    return None


def report_of(verdict, err, out):
    """What the file of a finding says of what abr printed: stderr, and stdout too when the finding is about a terminal."""
    if verdict[0] == "terminal":
        trouble = terminal_trouble("", err + b"\n" + out)
        return (trouble[1] if trouble else b"") + b"\n--- stdout ---\n" + out[:4000] + b"\n--- stderr ---\n" + err
    return err


class Findings:
    def __init__(self, directory, per_signature):
        self.dir = directory
        self.per_signature = per_signature
        self.lock = threading.Lock()
        self.seen = {}
        os.makedirs(directory, exist_ok=True)

    def add(self, cls, sig, command, status, err, mutant, origin, argv):
        key = (cls, sig)
        with self.lock:
            entry = self.seen.setdefault(key, [0, []])
            entry[0] += 1
            if entry[0] > self.per_signature:
                return False
            digest = hashlib.sha1(mutant).hexdigest()[:10]
            stem = f"{cls}_{digest}"
            with open(os.path.join(self.dir, stem + ".bin"), "wb") as f:
                f.write(mutant)
            with open(os.path.join(self.dir, stem + ".txt"), "w") as f:
                f.write(f"class:     {cls}\nsignature: {sig}\ncommand:   {command}   (abr {' '.join(argv)})\nstatus:    {status}\n")
                f.write(f"origin:    {origin}\n\n--- stderr (first 8000 bytes) ---\n")
                f.write(err[:8000].decode(errors="replace"))
            entry[1].append(stem)
            return True


class Campaign:
    def __init__(self, args, seeds):
        self.args = args
        self.seeds = seeds  # list of (path, bytes loader, sha)
        self.runner = Runner(args)
        self.findings = Findings(args.findings, args.per_signature)
        self.stats_lock = threading.Lock()
        self.runs = 0
        self.mutants = 0
        self.refused = 0
        self.accepted = 0
        self.round_trip_differs = 0
        self.rt_said = {}
        self.rt_silent = {}
        self.slowest = (0.0, "")
        self.stop_at = time.time() + args.time_limit if args.time_limit else None
        self.cache = {}

    def load(self, index):
        path = self.seeds[index][0]
        with self.stats_lock:
            data = self.cache.get(path)
        if data is None:
            with open(path, "rb") as f:
                data = f.read()
            with self.stats_lock:
                if sum(len(d) for d in self.cache.values()) + len(data) <= (256 << 20):
                    self.cache[path] = data
        return data

    def commands_for(self, rng, workdir, mutant_path):
        """The command lines for one damaged image; `repack` follows an `unpack` that worked."""
        threads = rng.choice(("1", "1", "1", "2", "3"))
        unpack = ["-j", threads, "unpack", mutant_path, "-o", os.path.join(workdir, "out")]
        mode = rng.random()
        if mode < 0.2:
            unpack.append("--no-tree")
        elif mode < 0.4:
            unpack.append("--tree-only")
        return threads, unpack

    def one(self, index, iteration):
        if self.stop_at and time.time() > self.stop_at:
            return
        path, _, sha = self.seeds[index]
        rng = random.Random(f"{self.args.rng_seed}:{sha}:{iteration}")
        data = self.load(index)

        def splice_source():
            return self.load(rng.randrange(len(self.seeds)))

        mutant, notes = mutate(rng, data, splice_source)
        origin = f"{path} iteration {iteration} rng-seed {self.args.rng_seed}: " + "; ".join(notes)
        workdir = tempfile.mkdtemp(prefix="fuzz_", dir=self.args.tmp)
        try:
            mutant_path = os.path.join(workdir, "m.img")
            with open(mutant_path, "wb") as f:
                f.write(mutant)
            self.judge(workdir, mutant_path, mutant, rng, origin)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def judge(self, workdir, mutant_path, mutant, rng, origin):
        threads, unpack = self.commands_for(rng, workdir, mutant_path)
        plan = [("identify", ["identify", mutant_path]), ("info", ["-j", threads, "info", mutant_path]), ("unpack", unpack)]
        unpacked_ok = False
        unpack_said = b""
        fmt = "?"
        with self.stats_lock:
            self.mutants += 1
        for name, argv in plan:
            status, err, secs, out = self.runner.run(argv, workdir)
            if name == "info":
                m = re.search(rb"^format:\s+(\S+)", out, re.M)
                fmt = m.group(1).decode(errors="replace") if m else "?"
            with self.stats_lock:
                self.runs += 1
                if secs > self.slowest[0]:
                    self.slowest = (secs, f"{name} {origin[:120]}")
            verdict = classify(name, status, err, out)
            if verdict:
                self.findings.add(verdict[0], verdict[1], name, status, report_of(verdict, err, out), mutant, origin, argv)
                return
            if name == "unpack":
                unpacked_ok = status == 0
                unpack_said = err + b"\n" + out  # (a wrapper that is not kept is a note, on stdout)
                with self.stats_lock:
                    if unpacked_ok:
                        self.accepted += 1
                    else:
                        self.refused += 1
        if not unpacked_ok:
            return
        out_dir = os.path.join(workdir, "out")
        repacked = os.path.join(workdir, "re.img")
        argv = ["-j", threads, "repack", out_dir, "-o", repacked]
        if rng.random() < 0.2:
            argv += ["--ramdisk-from", "cpio"]
        status, err, secs, out = self.runner.run(argv, workdir)
        with self.stats_lock:
            self.runs += 1
            if secs > self.slowest[0]:
                self.slowest = (secs, f"repack {origin[:120]}")
        verdict = classify("repack", status, err, out)
        if verdict:
            self.findings.add(verdict[0], verdict[1], "repack", status, report_of(verdict, err, out), mutant, origin, argv)
            return
        if status == 0 and os.path.exists(repacked):
            with open(repacked, "rb") as f:
                again = f.read()
            if again != mutant:
                said_something = b"warning" in unpack_said.lower() or b"is not kept" in unpack_said
                with self.stats_lock:
                    self.round_trip_differs += 1
                    table = self.rt_said if said_something else self.rt_silent
                    table[fmt] = table.get(fmt, 0) + 1
                if not said_something and not self.args.no_silent:
                    first = next((i for i in range(min(len(again), len(mutant))) if again[i] != mutant[i]), min(len(again), len(mutant)))
                    self.findings.add("silent-roundtrip", f"{fmt}: unpack said nothing, and the repack is not the image",
                                      "repack", 0, b"sizes %d/%d, first difference at %d\n" % (len(mutant), len(again), first), mutant, origin, argv)
                if self.args.report_roundtrip:
                    first = next((i for i in range(min(len(again), len(mutant))) if again[i] != mutant[i]), min(len(again), len(mutant)))
                    said = unpack_said.decode(errors="replace").strip().replace("\n", " | ")[:300] or "(unpack said nothing)"
                    self.findings.add("roundtrip", f"sizes {len(mutant)}/{len(again)}, first difference at {first}; unpack said: {said}",
                                      "repack", 0, b"", mutant, origin, argv)


def find_seeds(paths, abr, max_size, min_size, include_unknown):
    """The files under `paths` that abr takes for an image (those it calls `data` are not), once each."""
    seen = set()
    seeds = []
    skipped_big = 0
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for name in sorted(names):
                    files.append(os.path.join(root, name))
        else:
            files.append(p)
    for path in sorted(files):
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
        except OSError:
            continue
        if size < min_size:
            continue
        if size > max_size:
            skipped_big += 1
            continue
        if not include_unknown:
            label = subprocess.run([abr, "identify", "-b", path], capture_output=True).stdout.strip()
            if label == b"data":
                continue
        with open(path, "rb") as f:
            sha = hashlib.sha1(f.read()).hexdigest()
        if sha in seen:
            continue
        seen.add(sha)
        seeds.append((path, None, sha[:16]))
    return seeds, skipped_big


def repro(args):
    runner = Runner(args)
    work = tempfile.mkdtemp(prefix="fuzz_repro_", dir=args.tmp)
    try:
        path = os.path.abspath(args.repro)
        for name, argv in (
            ("identify", ["identify", path]),
            ("info", ["info", path]),
            ("unpack", ["unpack", path, "-o", os.path.join(work, "out")]),
            ("repack", ["repack", os.path.join(work, "out"), "-o", os.path.join(work, "re.img")]),
        ):
            status, err, secs, out = runner.run(argv, work)
            verdict = classify(name, status, err, out)
            print(f"== abr {' '.join(argv[:1])}: status {status}, {secs:.1f} s, verdict {verdict}")
            sys.stdout.write((report_of(verdict, err, out) if verdict else err)[:6000].decode(errors="replace"))
            if status not in (0,):
                break
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


def main():
    global MUTATORS
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--abr", required=True, help="the abr binary (built with -DABR_SANITIZE=address,undefined to see more)")
    ap.add_argument("--seeds", nargs="+", default=[], help="image files, or directories searched for them")
    ap.add_argument("--iterations", type=int, default=10, help="damaged copies per seed (default 10)")
    ap.add_argument("--rng-seed", default="1", help="the seed of the random numbers (default 1)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="abr processes at a time")
    ap.add_argument("--timeout", type=float, default=120, help="seconds before a run counts as a hang (default 120)")
    ap.add_argument("--time-limit", type=float, default=0, help="stop starting new work after this many seconds (default: no limit)")
    ap.add_argument("--max-seed-size", type=int, default=16 << 20, help="seeds above this many bytes are skipped (default 16 MiB)")
    ap.add_argument("--min-seed-size", type=int, default=32, help="seeds below this many bytes are skipped")
    ap.add_argument("--include-unknown", action="store_true", help="also damage files abr does not take for an image")
    ap.add_argument("--findings", default="fuzz_findings", help="where the damaged files and reports go")
    ap.add_argument("--per-signature", type=int, default=2, help="damaged files kept for one and the same finding (default 2)")
    ap.add_argument("--tmp", default=None, help="where the working directories go (default: the system's)")
    ap.add_argument("--max-alloc-mb", type=int, default=2048, help="AddressSanitizer: one allocation above this is a finding")
    ap.add_argument("--max-rss-mb", type=int, default=4096, help="AddressSanitizer: a process above this is a finding")
    ap.add_argument("--max-output-mb", type=int, default=1024, help="one output file above this many MiB is a finding")
    ap.add_argument("--report-roundtrip", action="store_true", help="also keep the damaged images whose unpack and repack differ from them, though unpack said so")
    ap.add_argument("--filtered", action="store_true", help="leave abr's output filter on (what a user gets); by default it is off, to find the messages that do not escape what they print")
    ap.add_argument("--mutators", default="", help="only these, comma separated (" + ", ".join(m.__name__[2:] for m, _ in MUTATORS) + ")")
    ap.add_argument("--no-silent", action="store_true", help="do not count it as a finding when unpack took a damaged image without a word and the repack is not that image")
    ap.add_argument("--repro", metavar="FILE", help="run the commands on this file as it is, and print what abr says")
    ap.add_argument("--list-seeds", action="store_true", help="only list the seeds (hash, size, path)")
    ap.add_argument("--seed-list", metavar="FILE", help="the seeds as --list-seeds printed them, instead of searching --seeds again")
    args = ap.parse_args()
    if args.mutators:
        wanted = {w.strip() for w in args.mutators.split(",") if w.strip()}
        unknown = wanted - {m.__name__[2:] for m, _ in MUTATORS}
        if unknown:
            ap.error("unknown mutators: " + ", ".join(sorted(unknown)))
        MUTATORS = [(m, w) for m, w in MUTATORS if m.__name__[2:] in wanted]

    if args.tmp:
        args.tmp = os.path.abspath(args.tmp)
        os.makedirs(args.tmp, exist_ok=True)
    if not os.access(args.abr, os.X_OK):
        print(f"fuzz_images: {args.abr} is not an executable", file=sys.stderr)
        return 2
    if args.repro:
        return repro(args)
    if args.seed_list:
        with open(args.seed_list) as f:
            seeds = [(line.split(" ", 2)[2].rstrip("\n"), None, line.split(" ", 2)[0]) for line in f if line.strip()]
        skipped_big = 0
    else:
        seeds, skipped_big = find_seeds(args.seeds, args.abr, args.max_seed_size, args.min_seed_size, args.include_unknown)
    if not seeds:
        print("fuzz_images: no seed images (give --seeds a directory of images)", file=sys.stderr)
        return 2
    if args.list_seeds:
        for path, _, sha in seeds:
            print(sha, os.path.getsize(path), path)
        return 0
    print(f"fuzz_images: {len(seeds)} seeds ({skipped_big} larger than {args.max_seed_size >> 20} MiB skipped), "
          f"{args.iterations} damaged copies of each, {args.jobs} at a time, rng seed {args.rng_seed}")
    campaign = Campaign(args, seeds)
    t0 = time.time()
    total = len(seeds) * args.iterations
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = []
        for iteration in range(args.iterations):  # all seeds once before any is done twice
            for index in range(len(seeds)):
                futures.append(pool.submit(campaign.one, index, iteration))
        for fut in concurrent.futures.as_completed(futures):
            fut.result()
            done += 1
            if done % 200 == 0 or done == total:
                with campaign.stats_lock:
                    print(f"  {done}/{total} damaged images, {campaign.runs} runs, {time.time() - t0:.0f} s, "
                          f"{sum(1 for e in campaign.findings.seen.values())} distinct findings", flush=True)
    elapsed = time.time() - t0
    print(f"\nfuzz_images: {campaign.mutants} damaged images, {campaign.runs} runs of abr in {elapsed:.0f} s; "
          f"unpack took {campaign.accepted} of them and refused {campaign.refused}; "
          f"{campaign.round_trip_differs} unpacked ones came back from `repack` as something else")
    print(f"             slowest run: {campaign.slowest[0]:.1f} s ({campaign.slowest[1]})")
    if campaign.rt_said or campaign.rt_silent:
        print("             unpack and repack that are not the image, by format: said so / silent:")
        for fmt in sorted(set(campaign.rt_said) | set(campaign.rt_silent)):
            print(f"               {fmt:12} {campaign.rt_said.get(fmt, 0):6} / {campaign.rt_silent.get(fmt, 0)}")
    if campaign.findings.seen:
        print(f"\n{len(campaign.findings.seen)} distinct findings (files in {args.findings}):")
        for (cls, sig), (count, stems) in sorted(campaign.findings.seen.items()):
            print(f"  [{cls}] x{count}: {sig}   {' '.join(stems)}")
        return 1
    print("nothing found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
