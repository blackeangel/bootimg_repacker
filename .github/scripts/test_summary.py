#!/usr/bin/env python3
"""What a run of tests/run_tests.sh came to, as an annotation of the job (and an exit status).

    test_summary.py <name of the job> <log of the suite>

The suite ends with "===== N passed, M failed =====". Here that line, the FAIL and SKIP lines before it and, when the log ends
some other way (the suite did not get that far), its last lines become one annotation -- an error when anything failed
or the summary is missing, a notice otherwise -- and the exit status is 0 only for "M = 0". A step that pipes the suite
into `tee` must not be the only judge of it, and the Actions log of a job is not something the people who work on this
repository can always read; an annotation is (the API lists it: GET /repos/{owner}/{repo}/check-runs/{job id}/annotations).
"""
import re
import sys


def escape_data(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text):
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    name, path = sys.argv[1], sys.argv[2]
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as e:
        print(f"::error title={escape_property(name + ' tests')}::{escape_data('no log of the suite: ' + str(e))}")
        return 1

    summary = None
    for line in lines:
        m = re.match(r"^===== (\d+) passed, (\d+) failed =====", line)
        if m:
            summary = (int(m.group(1)), int(m.group(2)))
    fails = [l for l in lines if l.startswith("FAIL")]
    skips = [l for l in lines if l.startswith("SKIP")]

    def clip(items, n, width=300):
        out = [i[:width] + ("..." if len(i) > width else "") for i in items[:n]]
        if len(items) > n:
            out.append(f"... and {len(items) - n} more")
        return out

    if summary is None:
        body = ["the suite did not reach its summary line; the end of its log:"] + [l[:300] for l in lines[-25:]]
        level, status = "error", 1
    elif summary[1] or fails:
        body = [f"{summary[0]} passed, {summary[1]} failed"] + clip(fails, 12)
        level, status = "error", 1
    else:
        body = [f"{summary[0]} passed, 0 failed" + (f", {len(skips)} skipped" if skips else "")] + clip(skips, 8)
        level, status = "notice", 0
    print(f"::{level} title={escape_property(name + ' tests')}::{escape_data(chr(10).join(body))}")
    for l in body:
        print(l)
    return status


if __name__ == "__main__":
    sys.exit(main())
