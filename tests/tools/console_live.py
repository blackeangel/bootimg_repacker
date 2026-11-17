#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The console of abr, as a person sees it.

  console_live.py <abr> <work directory>

What it checks, with images that this program writes itself (a boot image whose ramdisk is a gzip stream of a cpio archive: no code of abr and no
other tool in it):

  * a screen that is narrower than the tables (ABR_COLUMNS=40, 56, 80, 120; a pipe, so that this runs under wine and an emulator too): no line of
    `info`, `unpack` or `help` is wider than the screen leaves room for, nothing is lost (the words of the text are the words of the text that a
    pipe gets, in the same order), the column of offsets and sizes is the same as the wide table's, the width is taken only where it is asked for
    (ABR_COLUMNS is a number; a pipe is not wrapped), and the images of ABR_REAL_IMAGES (when set) are told the same way;
  * a pseudo terminal of 56 columns (where there is one): the width is the terminal's, with no ABR_COLUMNS; while the progress bar is drawn nothing
    else is written (not one line break before the bar is taken away, once, and the lines come after it), what comes out is what a pipe gets,
    no line is wider than the terminal, nothing is drawn after the last line; ABR_PROGRESS=never draws no bar at all.
"""
import os
import re
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from livelib import Live, read, write  # noqa: E402

COLUMNS = (40, 56, 80, 120)


def newc(entries):
    """A cpio archive (SVR4 newc) of (name, mode, data)."""
    out = bytearray()
    for ino, (name, mode, data) in enumerate(entries + [("TRAILER!!!", 0, b"")], 1):
        nm = name.encode() + b"\0"
        out += b"070701" + b"".join(b"%08X" % v for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0))
        out += nm + b"\0" * (-(110 + len(nm)) % 4)
        out += data + b"\0" * (-len(data) % 4)
    return bytes(out)


def gzip_stream(data):
    c = zlib.compressobj(6, zlib.DEFLATED, 31)
    return c.compress(data) + c.flush()


def text_of(size):
    """Text that deflate has to work at (words of a vocabulary of 4000 in a fixed order of choice), so that a run takes long enough to see a bar."""
    import random

    rnd = random.Random(7)
    vocab = [bytes(rnd.choices(b"abcdefghijklmnopqrstuvwxyz", k=rnd.randrange(3, 9))) for _ in range(4000)]
    buf = bytearray()
    while len(buf) < size:
        buf += rnd.choice(vocab) + (b" " if rnd.random() < 0.9 else b"\n")
    return bytes(buf[:size])


def boot_v0(kernel, ramdisk, page=2048):
    def pad(b):
        return b + b"\0" * (-len(b) % page)

    head = b"ANDROID!" + struct.pack("<10I", len(kernel), 0x10008000, len(ramdisk), 0x11000000, 0, 0x10F00000, 0x10000100, page, 0, 0)
    head += b"console".ljust(16, b"\0") + b"console=ttyS0 androidboot.hardware=a-rather-long-name-of-a-device".ljust(512, b"\0")
    head += b"\0" * 32 + b"\0" * 1024
    return pad(head) + pad(kernel) + pad(ramdisk)


def squeeze(text):
    return re.sub(r"\s+", "", text)


def width_of(line):
    return len(line)  # (the text of these images is ASCII)


def numbers_of(text):
    """The offset and the size of every region of a table, in order."""
    return re.findall(r"(?m)^  (0x[0-9a-f]+)\s+(\d+)", text)


def narrow_checks(live, label, img, work):
    """`info` and `unpack` of one image at every width: nothing is wider, nothing is lost, the numbers are the same."""
    plain = {}
    out = live.fresh(work, "out")
    rc, text = live.run("info", "-i", img)
    if rc != 0:
        return False
    plain["info"] = text
    rc, text = live.run("unpack", "-i", img, "-o", out)
    if rc != 0:
        return False
    plain["unpack"] = text
    for columns in COLUMNS:
        for verb in ("info", "unpack"):
            args = [verb, "-i", img] + (["-o", live.fresh(work, "out")] if verb == "unpack" else [])
            rc, text = live.run(*args, env={"ABR_COLUMNS": str(columns)})
            live.check(rc == 0, "%s: %s at %d columns works" % (label, verb, columns), text)
            wide = [ln for ln in text.splitlines() if width_of(ln) > columns - 1]
            live.check(not wide, "%s: %s at %d columns: no line wider than %d (%d are)" % (label, verb, columns, columns - 1, len(wide)), "\n".join(wide[:3]))
            live.check(squeeze(text) == squeeze(plain[verb]), "%s: %s at %d columns: nothing lost, nothing added, the same order" % (label, verb, columns),
                       text[-400:])
            live.check(numbers_of(text) == numbers_of(plain[verb]) and numbers_of(text), "%s: %s at %d columns: the offsets and sizes are those of the wide table" % (label, verb, columns))
            # (a line that a pipe gets with a blank at its end, `os_version:     ` of an image that has none, is left as it is; a line that is broken has none)
            live.check(sum(ln.endswith(" ") for ln in text.splitlines()) == sum(ln.endswith(" ") for ln in plain[verb].splitlines()),
                       "%s: %s at %d columns: breaking a line leaves no blank at the end of it" % (label, verb, columns))
    return True


def pty_run(argv, columns, env, rows=50, timeout=120):
    """Run abr on a pseudo terminal of `columns` columns -> (exit status, the bytes it wrote)."""
    import fcntl
    import pty
    import select
    import subprocess
    import termios
    import time

    master, slave = pty.openpty()
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    e = dict(os.environ)
    for k in ("NO_COLOR", "ABR_PROGRESS", "ABR_COLUMNS", "COLUMNS", "ABR_THREADS"):
        e.pop(k, None)
    e.update(env)
    e["TERM"] = "xterm-256color"
    p = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, start_new_session=True, env=e, close_fds=True)
    os.close(slave)
    data = bytearray()
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
        elif p.poll() is not None:
            break
    else:
        p.kill()
    try:
        while select.select([master], [], [], 0.05)[0]:
            chunk = os.read(master, 65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    os.close(master)
    return p.wait(), bytes(data)


def main():
    abr, work = sys.argv[1], sys.argv[2]
    live = Live(abr, work)

    small = live.path("small.img")
    write(small, boot_v0(b"\x7fkernel" * 40000, gzip_stream(newc([("init", 0o100755, b"#!/bin/sh\n"), ("etc/fstab", 0o100644, b"x" * 100)]))))
    big = live.path("big.img")
    write(big, boot_v0(b"\x7fkernel" * 40000, gzip_stream(newc([("init", 0o100755, b"#!/bin/sh\n"), ("big.bin", 0o100644, text_of(32 << 20))]))))

    # ---- narrow screens through ABR_COLUMNS
    with live.section("narrow"):
        live.check(narrow_checks(live, "boot image", small, "narrow_small"), "boot image: the plain runs work")
        # the width is taken only where it is asked for
        rc, plain = live.run("info", "-i", small)
        for bad in ("abc", "0", "-3", "", "12345678"):
            rc2, text = live.run("info", "-i", small, env={"ABR_COLUMNS": bad})
            live.check(rc2 == 0 and text == plain, "ABR_COLUMNS=%r asks for nothing: the text is the text of a pipe" % bad, text[-300:])
        live.check(any(width_of(ln) > 56 for ln in plain.splitlines()), "(the plain table is wider than 56 columns: the checks above have something to do)")
        # a `key:   value` line that does not fit goes on under its value
        rc, text = live.run("info", "-i", small, env={"ABR_COLUMNS": "56"})
        live.check(any(ln.startswith(" " * 16 + "androidboot.hardware=") for ln in text.splitlines()),
                   "info at 56 columns: the rest of the cmdline is under its value, not at the margin", text[:600])
        # the table that does not fit is the stacked one: the numbers and the name of a region on a line, what is known of it under them
        for columns in (40, 56):
            rc, text = live.run("info", "-i", small, env={"ABR_COLUMNS": str(columns)})
            lines = text.splitlines()
            for name, note in (("header", "header version 0, 1632 bytes"), ("ramdisk", "gzip (472 bytes unpacked)")):
                at = [i for i, ln in enumerate(lines) if re.fullmatch(r"  0x[0-9a-f]{8}\s+\d+  " + name, ln)]
                live.check(len(at) == 1 and at[0] + 1 < len(lines) and lines[at[0] + 1].startswith("      " + note),
                           "info at %d columns: the numbers and the name of %r are on a line, what is known of it is under them, indented" % (columns, name), text[-500:])

    # ---- help
    with live.section("help"):
        rc, text = live.run("help")
        live.check(rc == 0 and all(width_of(ln) <= 100 for ln in text.splitlines()), "help of a pipe: lines of at most 100 characters", text[:200])
        for columns in (40, 56, 80, 120, 200):
            rc, text = live.run("help", env={"ABR_COLUMNS": str(columns)})
            limit = min(columns - 1, 100)
            live.check(rc == 0, "help at %d columns works" % columns, text[:200])
            wide = [ln for ln in text.splitlines() if width_of(ln) > limit]
            live.check(not wide, "help at %d columns: no line wider than %d (%d are)" % (columns, limit, len(wide)), "\n".join(wide[:3]))
            for cmd in ("abr unpack", "abr pack", "abr info", "abr help", "abr version"):
                live.check(cmd in text, "help at %d columns names %r" % (columns, cmd))
            live.check(squeeze(text).count("ABR_THREADS") == 1 and "-o" in text, "help at %d columns: the paragraphs are there once" % columns)
        rc, text = live.run()
        live.check(rc != 0 and "abr unpack" in text, "no arguments: the usage and a failure", text[:200])

    # ---- the images of the corpus, when there is one
    real = os.environ.get("ABR_REAL_IMAGES")
    if real and os.path.isdir(real):
        with live.section("corpus"):
            tried = 0
            for name in sorted(os.listdir(real)):
                path = os.path.join(real, name)
                if not os.path.isfile(path):
                    continue
                rc, plain = live.run("info", "-i", path)
                if rc != 0:
                    continue
                tried += 1
                for columns in (40, 56, 80):
                    rc, text = live.run("info", "-i", path, env={"ABR_COLUMNS": str(columns)})
                    wide = [ln for ln in text.splitlines() if width_of(ln) > columns - 1]
                    live.check(rc == 0 and not wide and squeeze(text) == squeeze(plain) and numbers_of(text) == numbers_of(plain),
                               "%s: info at %d columns (no line wider, nothing lost, the same numbers)" % (name, columns), "\n".join(wide[:3]))
            print("note: the console was tried on the info of %d images of %s" % (tried, real))

    # ---- a terminal
    emulated = bool(os.environ.get("ABR_RUNNER")) or abr.lower().endswith(".exe") or os.environ.get("ABR_LIVE_NO_PTY")
    try:
        import pty  # noqa: F401
        have_pty = True
    except ImportError:
        have_pty = False
    if emulated or not have_pty:
        print("SKIP: the pseudo terminal runs (%s)" % ("the build runs under an emulator or wine" if emulated else "no pty on this system"))
    else:
        with live.section("terminal"):
            rc, plain = live.run("info", "-i", small)
            status, raw = pty_run([abr, "info", "-i", small], 56, {})
            text = raw.decode("utf-8", "replace").replace("\r\n", "\n")
            wide = [ln for ln in text.splitlines() if width_of(ln) > 55]
            live.check(status == 0 and not wide, "terminal of 56 columns, no ABR_COLUMNS: info has no line wider than 55 (%d are)" % len(wide), "\n".join(wide[:3]))
            live.check(squeeze(text) == squeeze(plain) and numbers_of(text) == numbers_of(plain), "terminal of 56 columns: info says what a pipe is told", text[-300:])
            live.check("\x1b" not in text and "\r" not in text, "info draws no bar (it takes no time)")
            status, raw = pty_run([abr, "help"], 56, {})
            text = raw.decode("utf-8", "replace").replace("\r\n", "\n")
            live.check(status == 0 and not [ln for ln in text.splitlines() if width_of(ln) > 55], "terminal of 56 columns: help has no line wider than 55")

            # the bar and what is said meanwhile
            out = live.fresh("terminal_out")
            rc, plain = live.run("unpack", "-i", big, "-o", out)
            live.check(rc == 0, "the long unpack works without a terminal", plain)
            for no_color in (True, False):
                out = live.fresh("terminal_out")
                env = {"ABR_PROGRESS": "always"}
                if no_color:
                    env["NO_COLOR"] = "1"
                status, raw = pty_run([abr, "unpack", "-i", big, "-o", out], 56, env)
                text = raw.decode("utf-8", "replace")
                label = "bar on a terminal of 56 columns (%s)" % ("NO_COLOR" if no_color else "colours")
                live.check(status == 0, label + ": the unpack works", text[-300:])
                erase = "\r\x1b[2K"
                last = text.rfind(erase)
                frames = text.count("\x1b[K")  # (a frame of the bar ends with it; the erase is another sequence)
                if frames < 2:
                    print("SKIP: %s: the bar was drawn %d times (the run was too short to see it); the rules below were not checked" % (label, frames))
                    continue
                # (a bar that is drawn and never taken away is a failure, not a run that was too short)
                live.check(last >= 0, label + ": the bar that was drawn %d times is taken away when the command is over" % frames, repr(text[-200:]))
                if last < 0:
                    continue
                live.check(text.count(erase) == 1, label + ": the bar is taken away once, at the end (%d times)" % text.count(erase))
                live.check("\n" not in text[:last], label + ": not one line break while the bar is on the screen (it does not move)", repr(text[: min(last, 400)]))
                tail = text[last + len(erase):].replace("\r\n", "\n")
                live.check("\x1b" not in tail and "\r" not in tail, label + ": after the bar nothing but lines (no bar drawn again)", repr(tail[-200:]))
                live.check(text.endswith("\r\n"), label + ": the last thing written is a line")
                wide = [ln for ln in tail.splitlines() if width_of(ln) > 55]
                live.check(not wide, label + ": no line wider than 55 (%d are)" % len(wide), "\n".join(wide[:3]))
                live.check(squeeze(tail) == squeeze(plain), label + ": the lines are the lines a pipe gets, in the same order", tail[-300:])
                live.check(not no_color or "\x1b[0;" not in text and "\x1b[38" not in text, label + ": NO_COLOR draws the bar in plain characters")

            out = live.fresh("terminal_out")
            status, raw = pty_run([abr, "unpack", "-i", big, "-o", out], 56, {"ABR_PROGRESS": "never"})
            text = raw.decode("utf-8", "replace")
            live.check(status == 0 and "\x1b" not in text and text.replace("\r\n", "") .count("\r") == 0, "ABR_PROGRESS=never on a terminal: no bar", repr(text[:200]))

    sys.exit(live.finish("console"))


if __name__ == "__main__":
    main()
