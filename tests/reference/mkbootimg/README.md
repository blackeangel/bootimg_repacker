# Vendored: AOSP mkbootimg (test-only reference oracle)

`mkbootimg.py`, `unpack_bootimg.py` and `repack_bootimg.py` are copied
unmodified from AOSP's `system/tools/mkbootimg` (Apache License 2.0,
see `LICENSE` in this directory; original copyright headers are kept
intact in each file). `gki/generate_gki_certificate.py` is **not**
from AOSP -- it's a tiny stub Claude wrote so `mkbootimg.py` can be
imported without needing that submodule, since our tests never pass
`--gki_signing_key` (the only thing that would actually call it).

These are used **only** by `tests/run_tests.sh`, as an independent
reference implementation to build real boot/vendor_boot images against,
so the test suite checks `abr`'s output against Google's own tool
rather than only against itself. They are not part of the `abr`
binary, are not linked into it, and are not required to build or run
`abr` -- Python 3 is only needed to run this test suite.

Not actively kept in sync with upstream; if AOSP mkbootimg changes in
a way that breaks these tests, re-vendor from
https://android.googlesource.com/platform/system/tools/mkbootimg/.
