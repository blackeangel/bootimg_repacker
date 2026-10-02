# Vendored: AOSP avbtool (test-only reference oracle)

`avbtool.py` is copied unmodified from AOSP's `external/avb`
(commit `7cd928fb51baafc5117566744a57230a048bae04`, taken from the LineageOS
mirror `LineageOS/android_external_avb`, branch `lineage-22.0`, because
`android.googlesource.com` is not reachable from the development sandbox).
Its own header carries the MIT-style license; `LICENSE` is the repo-wide
license file of `external/avb`, kept for completeness.

It is used **only** by `tests/run_tests.sh`, as an independent reference:

- `add_hash_footer` / `make_vbmeta_image` build real signed AVB images that
  `abr` must reproduce byte-for-byte when nothing was edited;
- `verify_image` is the judge for images `abr` re-signs after an edit: it
  checks the vbmeta signature against the embedded public key, the public
  key against the one given, and every hash descriptor against the image;
- `extract_public_key` is the reference for the public-key blob `abr`
  generates from a signing key.

It is not part of the `abr` binary and is not needed to build or run `abr`;
the test suite needs Python 3 and the `openssl` command line (avbtool shells
out to it).

Not kept in sync with upstream; re-vendor from `external/avb` if a newer
avbtool is needed.
