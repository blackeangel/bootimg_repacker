# Progress log

Read this file first when resuming. Update it after every meaningful
step. Single source of truth for status -- not a changelog nobody reads.

## This project's place in the bigger picture

This repo (`blackeangel/bootimg_repacker`) is one tool in Павел's
wider suite of Android firmware C++ CLI tools (internally tracked on
the Claude side as the "UKA_tools" project): `f2fs_unpacker`,
`tar_repacker`, `md1img_repacker`, `utils`. Match that suite's
established conventions -- see "Conventions inherited from the sibling
tools" below.

## Status

| Piece | Status |
|---|---|
| boot (header v0-v4): boot.img, init_boot.img, boot-debug.img, boot-test-harness.img, recovery.img, recovery-two-step.img | **done + verified** |
| vendor_boot (header v3-v4): vendor_boot.img, vendor_boot-debug.img, vendor_kernel_boot.img | **done + verified** |
| dtbo.img (+ ACPIO variant) | **done + verified** |
| dtb (raw/concatenated FDT) | **done + verified** |
| vbmeta (AVB): vbmeta.img, vbmeta_system.img, footer-on-other-partitions | **done + verified**, incl. RSA signing (images made by the real `avbtool` round-trip exactly; images `abr` re-signed pass `avbtool verify_image`) |
| uboot: U-Boot legacy uImage | **done + verified** |
| ELF boot images (Sony/Xperia) | **done + verified** against real elftool (commit `67157cf`) |
| MTK sub-header, DHTB wrapper | **done + verified** against real mkmtkhdr/dhtbsign |
| Everything around the container: opaque prefix (BFBF/SSSS-style wrappers), verbatim tail, partition-size fill, boot `id` schemes (sha1 / sha1+dt / sha256 / raw), QCDT `dt_size`, reserved words, odd `header_size`, header-page data, trimmed dumps, vendor_boot v4 with an empty ramdisk table | **done + verified** -- 13 of 14 real device dumps round-trip byte-for-byte (the 14th is an ext4 filesystem, out of scope and rejected with a clear message); see "Round-tripping 14 real device images" at the end |
| AVB footer on boot / vendor_boot / dtbo: layout, digest check, digest refresh after an edit, `--avb-key` required for signed footers | **done + verified** against the real `avbtool` (`add_hash_footer` output round-trips byte-for-byte; edited + re-signed output passes `verify_image`) and the independent Python/openssl checks |
| AVBv1 `BootSignature` (pre-AVB `boot_signer`, DER blob after the image): detect, verify (`info`, unpack warning), re-create after an edit with the AOSP test key or `--avb1-key/--avb1-cert` (AIK `name.pk8`+`name.x509.pem` naming too), add to an unsigned image | **done + verified** against the real AOSP `boot_signer` (compiled from its Java sources) and an independent Python/openssl signer: same bytes from the same key and image; abr-re-signed images pass `boot_signer -verify`; real-device AVBv1 images read VALID |
| compression: gzip, lz4, lz4-legacy, zstd, xz, lzma(alone), bzip2, lzo | **done + verified, all algorithms** |
| bundled SHA-1/256/512 | **done**, self-test passes, catches its own transcription bug once already (see Verification below) |
| self-contained RSA: BigInt (Knuth D, Montgomery), DER/PEM/X.509, PKCS#1 v1.5 sign/verify, PKCS#8/PKCS#1 key parsing, AVB public-key blob -- **no OpenSSL anywhere in the build** | **done + verified** (Python integers, `openssl dgst -sign`, `avbtool extract_public_key`; see "Self-contained crypto" below) |
| manifest + CLI (`abr info/unpack/repack`) | **done** |
| CMake: FetchContent-vendored static zlib/lz4/zstd/xz/bzip2 | **done + build-verified natively on Linux**, both the dynamic and the `-DABR_STATIC_BINARY=ON` fully-static configurations |
| Test suite (`tests/run_tests.sh`) | **done, 98/98 passing** -- see Verification |
| CMake cross toolchains (mingw-w64, Android NDK) | **done + verified** (mingw reproduced locally; NDK only provable via CI, see below) |
| GitHub Actions static build matrix (linux-x86_64, windows-x86_64, android-arm64) | **done + verified**: run 35313499827, all 3 jobs green, all 3 static binaries produced as artifacts (abr-linux-x86_64, abr-windows-x86_64, abr-android-arm64) |

## Verification (this is the part to trust over any code comment)

`tests/run_tests.sh` builds real reference images and checks that
`abr unpack X && abr repack` reproduces each one **byte-for-byte**
(not just "same decompressed content" -- see how below), then runs it.
98/98 passing as of the last local run. What it actually checks:

- **boot v4**: built with AOSP's own `mkbootimg.py` (vendored in
  `tests/reference/mkbootimg/`, Apache-2.0, unmodified except a stub
  `gki/` module so it imports without that unrelated submodule),
  gzip kernel + lz4 ramdisk. Byte-identical round trip.
- **boot v2**: same, plus a dtb, board name, and `--id` (content-hash
  field) -- `abr` recomputes this hash on repack (see
  `BootImage::recompute_id`, called from `repack_boot` in
  `src/main.cpp`) and it matches mkbootimg.py's own SHA-1(payload‖size)
  scheme exactly.
- **vendor_boot v3** (single ramdisk) and **v4** (two fragments --
  zstd-compressed "platform" + lz4-compressed named "dlkm_frag" with a
  non-zero board_id word, plus dtb and bootconfig): both built with
  `mkbootimg.py`, both byte-identical.
- **dtb**: single blob and two concatenated blobs, both real device
  trees compiled with the system `dtc`.
- **uimage**: built with the real `mkimage` (u-boot-tools), plain and
  gzip-compressed.
- **dtbo**: self-built (no external oracle used here -- see note
  below) with one zlib-compressed (flags=0x02) entry; round-trips and
  the decompressed content matches the source dtb exactly.
- **vbmeta**: unsigned (algorithm=NONE) with a kernel_cmdline
  descriptor; RSA-2048-signed with a locally generated test key,
  where the embedded SHA-256 hash and signature are independently
  recomputed/reparsed in Python and the signature is verified with
  `openssl pkeyutl -verify` -- i.e. a completely independent
  implementation (OpenSSL's) confirms the RSA-PKCS1v1.5 signature
  `abr` produces is valid, not just that `abr` accepts its own output;
  and an AVB footer attached to a synthetic host partition, round-tripped
  whole.
- Along the way, `sha_selftest()`'s SHA-1 known-answer string turned out
  to be missing its last hex digit (a transcription typo when it was
  written, not a bug in the SHA-1 implementation -- the actual digest
  bytes matched the FIPS 180 example exactly before that conclusion was
  reached). Caught immediately because the binary refuses to run at all
  if the self-test fails. Fixed; see git log.

Why dtbo has no external-oracle test: `mkdtboimg.py` (AOSP
system/libufdt) couldn't be fetched from a GitHub mirror in the time
spent looking (googlesource.com isn't reachable from the sandbox's
egress allowlist, and no mirror with the file was found) -- but its
*source was read directly* via `web_fetch` on the googlesource gitiles
URL earlier in this session and matched this project's implementation
field-for-field (magic, struct layout, big-endian, the exact
`>8I` pack format, the wbits=47 auto-detect decompression trick). If
picking this up later and it'd be easy to get a working mirror or a
local AOSP checkout, wiring `mkdtboimg.py` into `run_tests.sh` the same
way as `mkbootimg.py` would upgrade this from "verified by reading the
source" to "verified against a real build," which is the stronger
standard the rest of the suite meets.

### Real-device quirk tests (added after the 14-image round trip)

`tests/tools/fixtures.py` builds one small synthetic image per quirk
that real devices exposed, **from the format specs, not from abr's
code** (AOSP `bootimg.h` / `vendor_boot.h`, avbtool's layout), so the
suite cross-checks abr instead of agreeing with it by construction.
`tests/tools/verify.py` then re-checks abr's *output* independently:
the boot `id` per hash scheme, every AVB HASH descriptor against the
host bytes, and the vbmeta RSA signature through `openssl`.
`tests/tools/roundtrip_dir.py <abr> <dir>` unpacks and repacks every
image in a directory and prints IDENTICAL / DIFF / UNPACK-FAIL per file
-- that is how the real device dumps were checked.

Covered: QCDT `dt_size`, `sha1_dt` / `sha256` / `raw` ids and their
recomputation after a ramdisk edit, reserved words + odd `header_size`,
a non-standard `recovery_dtbo_offset`, vendor data in the header page,
dumps with the last page's padding trimmed, vendor_boot v4 with an empty
ramdisk table at page 2048, SEAndroid tail + zero fill up to the
partition size (and that an edited image is padded back to it), a
BFBF/SSSS-style prefix + signature trailer, an AVB hash footer on a host
that is **not** 4096-aligned with a salted digest (digest refreshed after
an edit, partition size unchanged), a signed footer refusing to be
rebuilt without `--avb-key` and verifying with it, a stale digest being
reported but not silently "fixed", the unpack self-check (positive and
negative), `info`, and an ext4 image being rejected with an explanation.

### Self-contained crypto, judged by three implementations that share no code with abr

`abr` has no crypto library (see "Conventions"), so the arithmetic is
checked against independent implementations -- all of it in
`tests/run_tests.sh`, using `build/abr_unit_tests`:

- **BigInt vs Python integers**: `tests/tools/gen_bigint_vectors.py [seed]`
  emits add/sub/mul/divmod/modexp/shift/byte-round-trip vectors. Limbs are
  drawn from 0, 1, 0x7fffffff, 0x80000000, 0xffffffff so the rare
  "qhat one too large" and "add the divisor back" paths of Knuth's
  algorithm D and the carry chains of Montgomery multiplication really
  run; dividends are built as `q*d + r` with `r` at the edge of the divisor.
  190k+ vectors over several seeds, 0 mismatches (the suite runs the default
  seed, ~24k vectors).
- **RSA vs `openssl dgst -sign`**: 1024/2048/4096-bit keys x SHA-1/256/512
  x PEM PKCS#1 / PEM PKCS#8 / DER PKCS#8 (`.pk8`) / DER PKCS#1 = 36
  signatures compared byte-for-byte (PKCS#1 v1.5 is deterministic).
  Verification: accepts openssl's signature through a bare public key, a
  PEM certificate and a DER certificate; rejects a flipped byte and the
  wrong hash. A passphrase-protected key and an unreadable key file are
  refused with a message that says what to do / what was expected.
  8192-bit signing takes ~1.3 s.
- **AVB public-key blob vs `avbtool extract_public_key`**: identical for
  RSA-2048 and RSA-4096 (`key_num_bits`, `n0inv`, modulus, `R^2 mod n`).
- **Images from the real avbtool** (`tests/reference/avb/avbtool.py`):
  - `add_hash_footer` (SHA256_RSA2048, 4 MiB partition, salted, with a
    property): unpack+repack is byte-identical; `info` reports the footer;
    an edit without `--avb-key` is refused; with the key the result passes
    `avbtool verify_image` (signature, embedded key, hash descriptor); a key of
    the wrong size is refused; a different key replaces the embedded public
    key, `abr` says so, and the image then verifies only with the new key.
  - `make_vbmeta_image` (SHA256_RSA4096, rollback index, property, cmdline,
    `--include_descriptors_from_image`): unpack+repack is byte-identical;
    re-signing the unchanged vbmeta with the same key reproduces avbtool's
    bytes exactly; with edited `flags` it is refused without a key and, with
    the key, passes `verify_image` and shows the new flags in `info_image`.
  Signing also regenerates the vbmeta's embedded public key from the signing
  key (before this, the blob was passed through, so a re-signed image made
  with a different key could never have verified).

Not done: booting an `abr`-signed image on a device that enforces verified boot.

### AVBv1 boot signature, judged by two implementations that share no code with abr

The pre-AVB-2.0 signature of AOSP's `boot_signer` (what Android Image
Kitchen calls AVBv1; layout in `include/abr/legacy/avb1.hpp`). Oracles:

- **the real `boot_signer`**: `BootSignature.java` + `Utils.java` from AOSP
  `system/extras/verity` (LineageOS mirror, commit `51de782c`; vendored in
  `tests/reference/boot_signer/` with the public AOSP "verity" key pair),
  compiled by the suite with `javac` against BouncyCastle (skipped, with a
  message, when Java or `bcprov.jar` is missing);
- **`tests/tools/avb1.py`**: DER assembled in Python, RSA from `openssl dgst
  -sign`; also signs with ECDSA (`--ec`) to make images abr cannot judge.

What `tests/run_tests.sh` checks (all four layouts: header v0, v0 with a
Qualcomm dt blob where header word 10 is the dt size, v1 with a recovery
dtbo, v2 with a dtb -- the signed length differs per layout):

- the AOSP dev key embedded in abr is exactly the vendored `verity.pk8` +
  `verity.x509.pem` (the suite regenerates `src/legacy/avb1_aosp_key.cpp`
  with `tools/gen_aosp_verity_key.py` and compares);
- an image signed by the Python signer or by the real `boot_signer` is
  reported VALID by `info`, and unpack+repack is byte-identical; the two
  signers also give identical bytes;
- one flipped byte in the kernel: reported INVALID at unpack and in `info`,
  and the image still round-trips unchanged;
- after an edit: the image abr builds equals the one the independent signer
  builds from the same edited core, equals what the real `boot_signer`
  signs, passes `boot_signer -verify`, and no stale-signature warning is
  printed;
- a custom RSA-4096 key: `--avb1-key/--avb1-cert`, the AIK `name.pk8 +
  name.x509.pem` form and a single PEM holding key and certificate all give
  the same bytes, equal to the independent signer's and to `boot_signer`'s;
  a certificate that does not belong to the key, and a key without any
  certificate, are refused with an explanation;
- an original signed by another key (+ a vendor trailer after the signature,
  as on the BFBF devices): re-signed with the AOSP key **with a warning**,
  the trailer stays at its offset (the signature changed size), and the
  stale-trailer warning is shown;
- unsigned stays unsigned; `avb1_signature=true` or `--avb1-key` adds a
  signature; `--avb1-key` on a vendor_boot is ignored with a warning;
- ECDSA-signed original: "not checked", exact round trip, replaced by an RSA
  signature (with a warning) after an edit.

Facts established while building this (against the real tool, not assumed):

- The signed range starts at the `ANDROID!` magic, not at the file start
  (matters under a BFBF prefix), covers the page-aligned image, and the
  signed data is `image[0:length] || DER(attributes)`.
- `getSignableImageSize` rejects header v3/v4; v0-v2 only. Its size is the
  header page + page-aligned kernel/ramdisk/second [+ recovery dtbo, v1-v4
  field at 1632] [+ dtb, v2 field at 1648] [+ the Qualcomm dt blob when
  word 10 > 4], rounded up to a page.
- RSA keys are always signed as `sha256WithRSA` with no NULL parameters
  (`30 0b 06 09 2a864886f70d01010b`); the real tool also does ECDSA, which
  abr can neither verify nor create ("not checked", kept verbatim).
- Re-signing the unsigned part of a real vendor `boot.img` with the AOSP
  key reproduced the stored 2540-byte signature byte for byte; the other two
  real AVBv1 images (inside a BFBF wrapper) also read VALID.

### Design point this verification depends on: byte-identical passthrough

`abr` decompresses kernel/ramdisk/vendor-ramdisk-fragment components on
unpack (so there's an editable, plain file) and recompresses on
repack. Recompressing essentially never reproduces a compressor's
*exact original bytes* (different tool/version/level/header fields
even for byte-identical decompressed content) -- so naive
decompress-then-recompress would only give "content-equivalent," not
"byte-identical," round trips. Fixed by keeping the original
still-compressed bytes on the side (`.abr_raw/` under the unpack
directory) plus a SHA-256 of the decompressed content; repack replays
the original raw bytes verbatim when the extracted file's hash still
matches (nothing was touched), and only actually recompresses when it
doesn't (the file was edited). See `save_component`/`load_component`
in `src/main.cpp`. This is what makes the "byte-for-byte" claims above
true even though every compressed component gets decompressed for
editing.

### LZO specifically: why it needed a container format of its own

Raw LZO1X (what `lzo1x_1_compress`/`lzo1x_decompress_safe` produce/
consume) has **no magic bytes or header at all** -- unlike every other
codec here, there's nothing for `detect_codec()` to sniff, and nothing
telling a decoder where one compressed block ends. Checked what a real
LZO-compressed kernel/ramdisk/initramfs on an actual device would
therefore need to look like by reading the Linux kernel's own
`lib/decompress_unlzo.c` directly (not guessing): it expects the
**lzop file format**'s header and per-block framing (magic
`\x89LZO\x00\x0d\x0a\x1a\x0a`, then a fairly involved header, then
repeated `{dst_len BE32, src_len BE32, checksum BE32, block bytes}`
until a `dst_len == 0` terminator). That's what's implemented
(`lzo_compress`/`lzo_decompress` in `src/compression.cpp`), using
miniLZO (`third_party/minilzo/`, vendored directly rather than
FetchContent'd -- see its README for why) for the actual LZO1X
compress/decompress calls. The encoder always writes the minimal
header form; the decoder tolerates the newer/optional fields
(filter info, mtime_high, a filename) a real lzop file could have,
matching the kernel decompressor's own leniency.

Verified in both directions independently of `abr`'s own code, using
`python-lzo` (real liblzo2, not miniLZO) -- see the `lzo` section of
`tests/run_tests.sh`:
- **abr encode -> real liblzo2 decode**: `abr`'s lzop-framed output is
  parsed by hand in Python and the LZO1X blocks are decompressed with
  `lzo.decompress()`; matches the original content exactly.
- **real liblzo2 encode -> abr decode**: an lzop stream is hand-built
  in Python around a block compressed with `lzo.compress()` (real
  liblzo2), spliced into a manually-constructed boot.img header (to
  bypass `abr`'s own recompress-on-repack convenience, which would
  otherwise mask this check by re-encoding the payload with `abr`'s
  own encoder before it ever reached the decoder) -- `abr unpack`
  reads it correctly.
(First attempt at this test had a methodology bug -- the boot.img was
built via `abr repack` with the hand-made lzop bytes as the *input*
file, which `abr` correctly treated as plaintext-to-be-compressed and
re-encoded, so the "cross-check" was accidentally only testing abr
against itself. Caught by the ramdisk size in `abr info` output being
implausibly small for the supposedly-already-compressed input; fixed
by constructing the test boot.img's bytes directly instead of going
through `abr repack` for that part.)

## C++26 and the build toolchains (3 Oct 2026)

Decision (the user, 2 Oct): the language is C++26, not C++20; multithreading
where it makes sense. Facts established on the machine, not assumed:

- **GCC 13.3 (Ubuntu 24.04's default) rejects both `-std=c++26` and
  `-std=c++2c`.** GCC 14.2 accepts `c++26`, `c++2c`, `gnu++26`, `gnu++2c`;
  Clang 18.1 and 20.1 accept `-std=c++26`. (An earlier note here said GCC 13
  took `-std=c++2c`; that was wrong.)
- **CMake 3.28 cannot map `CXX_STANDARD 26` to GCC's flag** ("CMake does not
  know the flags" even for GCC 14) but does for Clang. So `CMakeLists.txt`
  probes the flag itself (`ABR_CXX_STANDARD`, default 26: `-std=gnu++26`, then
  `-std=gnu++2c`; MSVC `/std:c++latest`) and fails with an instruction when the
  compiler has none. `-DABR_CXX_STANDARD=23` is the escape hatch.
- Nothing in abr needs a C++26-only language or library feature, and saying so
  is the honest position: the sources compile warning-free and pass 98/98 as
  C++26 with g++-14 and clang-20 and as C++23 with g++-13. What C++26 buys us
  today is the baseline itself (and the freedom to use C++23/26 library
  facilities when a change is easier with them: `std::byteswap`, ...). Not
  usable yet, on purpose: reflection and contracts (GCC 16 only), `#embed`
  (GCC 15 / Clang 19), `std::execution` (no libstdc++ has it; and the C++17
  parallel algorithms need TBB, which a static binary should not).
- Portable library subset, because the NDK's libc++ and mingw's libstdc++ are
  older than the host's: nothing newer than libstdc++ 13 / libc++ 18 (no
  `std::print`, `std::ranges::to`, `std::move_only_function`).

**Windows**: Ubuntu's mingw-w64 is GCC 13, so there is no C++26 there. New
`cmake/toolchains/mingw-w64-clang.cmake`: Clang (20 tested) targeting
`x86_64-w64-mingw32`, over the apt mingw-w64 headers/CRT and the *posix-model*
libstdc++ 13 (`-nostdinc++` plus explicit include dirs, `ld.lld`, winpthread
pulled in whole because a statically linked winpthread otherwise loses its
thread-exit hook). Result: a static PE that imports only `KERNEL32.dll` and
`msvcrt.dll`. `cmake/toolchains/mingw-w64.cmake` (plain GCC, now the `-posix`
compilers: the default win32 thread model has no `std::thread`) is kept and
builds C++23.

**The Windows build had never been executed before.** It was only compiled in
CI. `tests/run_tests.sh` now accepts an `.exe` and runs it under wine 9.0
(wrapper scripts; the checks are unchanged). First run: 13 of 98 failed, all
one cause -- text mode: the manifest was written with CRLF and every line of
output ended in CRLF, so exact-match checks failed. Fixed in the program, not
the tests: the manifest is read and written in binary mode (LF everywhere; the
reader already trimmed CR), and `set_binary_stdio()` puts stdout/stderr in
binary mode on Windows (the console still shows it correctly). Then 98/98 for
both Windows builds (clang C++26 and GCC-posix C++23). wine is not Windows:
what is still unproven is a real Windows machine, and non-ASCII paths (the ANSI
code page applies to `argv`; a UTF-8 application manifest or `wmain` would fix
that -- noted, not done).

**A test-suite bug found on the way**: `cmd | grep -q` under `set -o pipefail`
failed intermittently (grep exits at its first match, the still-writing
`abr` gets SIGPIPE, the pipeline reports failure). It showed up only on some
builds (timing). All such checks now go through `said <pattern> <command...>`.

**Android**: the NDK's Clang (18 in r27d) takes `-std=c++26`; CI now uses NDK
r29. Downloading the NDK is blocked from the development sandbox, so the
Android build is proven only by CI, as before.

## Conventions inherited from the sibling tools (apply here too)

- **License: GPL v3**, not MIT (corrected early this session -- see
  git log). Chosen across the suite to allow LZO inclusion.
- **Dependencies are vendored via CMake FetchContent, built as static
  libraries from source** -- done for zlib/lz4/zstd/xz/bzip2 in
  `cmake/vendor_deps.cmake`. Real (not guessed) option names and
  target names, confirmed by an actual local build:
  - zlib: `ZLIB_BUILD_TESTING`/`ZLIB_BUILD_SHARED`/`ZLIB_INSTALL` ->
    `OFF`; target `zlibstatic`. Needed an explicit
    `target_include_directories(zlibstatic PUBLIC ...SOURCE_DIR...
    ...BINARY_DIR...)` because its own CMakeLists uses directory-scoped
    `include_directories()` for the generated `zconf.h`, which doesn't
    reliably propagate to outside consumers.
  - lz4: CMakeLists lives at `build/cmake` (`SOURCE_SUBDIR`); target
    `lz4_static`; `LZ4_BUILD_CLI`/`LZ4_BUILD_LEGACY_LZ4C` -> `OFF`.
  - zstd: CMakeLists at `build/cmake`; target `libzstd_static`;
    `ZSTD_BUILD_SHARED`/`_PROGRAMS`/`_TESTS`/`_CONTRIB` -> `OFF`.
  - xz (liblzma): top-level CMakeLists (5.4+ ships one); target
    `liblzma`; plain `BUILD_SHARED_LIBS`/`BUILD_TESTING` -> `OFF` work
    since it's a modern, well-behaved CMake build.
  - bzip2: **no CMakeLists.txt upstream at all** (classic Makefile
    project) -- populated source-only via `FetchContent_Populate`
    (not `_MakeAvailable`) and compiled its 7 library `.c` files
    (blocksort/huffman/crctable/randtable/compress/decompress/bzlib)
    directly with our own `add_library(bz2_static STATIC ...)`. This
    sidesteps the whole old-CMakeLists problem for this one entirely.
  - `CMAKE_POLICY_VERSION_MINIMUM 3.5` is set defensively for CMake
    >= 4.0 (the sandbox's CMake is 3.28, which didn't need it, but CI
    or a future local setup might have 4.x).
  - `ABR_VENDOR_DEPS=OFF` is kept as an escape hatch to use system dev
    packages instead, for fast local iteration -- not the shipping
    default.
- **No crypto library at all.** Hashing (boot `id`, AVB digests) uses the
  bundled SHA-1/256/512 (`src/sha.cpp`); AVB RSA signing/verification, the
  big-integer arithmetic under it and the DER/PEM/X.509 reading of key files
  are `src/bigint.cpp`, `src/rsa.cpp`, `src/asn1.cpp`. OpenSSL was used for
  the first AVB signing and removed once those were verified (it had made
  `--avb-key` unavailable in the Windows and Android builds, which cannot
  `find_package` it). OpenSSL, Python and `avbtool` remain in the *test
  suite* as independent oracles only.
- **Android: bionic cannot be statically linked, and that's correct,
  not a bug.** `file` reporting "dynamically linked" on the Android
  arm64 binary is expected. "Static" for that target means
  `ANDROID_STL=c++_static` plus our own vendored deps statically
  linked in, i.e. nothing beyond what bionic itself always provides.
  Don't chase a fully-static Android executable; it isn't a thing.
- Cross-compilation targets across the whole suite: Linux native,
  Windows (MinGW-w64 or MSVC), Android NDK arm64-v8a, all validated in
  CI.
- Push early, push often, commit every logical patch separately -- a
  *recovered* lesson from the sibling tools (a sandbox reset
  previously destroyed unpushed work there). Every commit in this
  repo's history so far is a self-contained, working step for exactly
  this reason.
- Reference/validation tools the user already relies on: Python
  `avbtool`, `img2sdat`/`sdat2img`, `adb`/`fastboot`. `mkbootimg.py` + `dtc` +
  `mkimage` + `openssl` were used first; real `avbtool.py` is now vendored
  in `tests/reference/avb/` (MIT; provenance in its README) and is the
  oracle for AVB footers, vbmeta images and public-key blobs.
- Repo naming across the suite: `f2fs_unpacker`, `tar_repacker`,
  `md1img_repacker`, `utils`. This repo was renamed mid-session from
  `android-boot-repack` to `bootimg_repacker` to match.

## Key format-level design decisions

- One parser per *container format*, not per file name: `BootImage`
  handles boot.img/init_boot.img/boot-debug.img/boot-test-harness.img/
  recovery.img/recovery-two-step.img identically (init_boot.img is a
  v4 image with kernel_size==0 -- confirmed `--kernel` is optional in
  mkbootimg.py's argparse setup).
- `vendor_kernel_boot.img` uses the *same* vendor_boot header v3/v4
  struct as `vendor_boot.img` (Pixel 7+ split one logical partition
  into two files of the same format) -- confirmed via
  cfig/Android_boot_image_editor's layout.md and AOSP partition docs.
- Endianness verified per format against primary sources, not assumed:
  boot/vendor_boot headers -> little-endian; AVB vbmeta
  header/footer/descriptors, dtbo dt_table_header/dt_table_entry, raw
  dtb (FDT) header, and U-Boot legacy uImage header -> all big-endian.
  Sources are in each file's header comment.
- zstd is this project's own contribution -- confirmed neither AOSP
  mkbootimg nor current Magisk (checked native/src/boot/
  {format,compress}.rs) support it.
- Boot header v4 remains the newest version in AOSP mkbootimg's `main`
  branch (hard-rejects `header_version > 4`); no evidence of a v5 tied
  to "Android 17" specifically. Interpreted the ask as "v4 needs to be
  solid" rather than "implement a format that doesn't exist yet."
- AVB descriptors are stored as opaque (tag, raw content) pairs so an
  unmodified descriptor round-trips byte-for-byte; `describe()` decodes
  well-known tag types (verified: property, hash, hashtree,
  kernel_cmdline, chain_partition) for `info` output only, read-only.
- "uboot" is interpreted as U-Boot's legacy `mkimage`/uImage container
  (magic 0x27051956). FIT (Flattened Image Tree), U-Boot's newer
  format, is **not** implemented -- possible follow-up.

## Repo / GitHub

- `blackeangel/bootimg_repacker` (private). The token pasted in chat
  to create/push to it was used only for that -- never committed,
  never written to Claude's memory. User should rotate it.
- No internet access to dl.google.com (Android NDK) or mingw prebuilt
  mirrors from inside the Claude sandbox -- Windows/Android builds are
  expected to happen in GitHub Actions (unrestricted runner network),
  driven/monitored from here via the GitHub API, not built locally.

## AIK format parity (requested, large scope, sequenced -- in progress: MTK, DHTB, ELF done)

User wants parity with what Android Image Kitchen (AIK) handles,
explicitly comparing the end goal to Magisk: **one static binary, no
shell-outs to other tools**. Reference implementations given (all
`osm0sis` on GitHub unless noted -- a long-time XDA maintainer of
exactly this ecosystem of tools):

| Format/tool | What it is | Reference |
|---|---|---|
| ELF boot images (Sony) | whole file is an ELF executable, kernel/ramdisk/etc as segments, instead of an "ANDROID!" header | `osm0sis/elftool`, `osm0sis/unpackelf`, `osm0sis/mkbootimg` (has ELF support built in), `osm0sis/pxa-mkbootimg` |
| OSIP / KRNL | old ASUS/Rockchip boot header format | not yet researched |
| MTK headers | MediaTek wraps kernel/ramdisk each in a small sub-header *inside* an otherwise-normal boot.img | `osm0sis/mkmtkhdr`; DHTB_MAGIC and an `mtk_hdr` struct were already seen once in Magisk's `native/src/boot/bootimg.hpp` this session (not recorded verbatim -- re-check that file) |
| PXA (Marvell) | another boot header variant, Magisk's bootimg.hpp has a `boot_img_hdr_pxa` (seen, not recorded verbatim) | `osm0sis/pxa-mkbootimg` |
| LOKI | a 2013-era boot.img patcher for specific locked Samsung/LG bootloaders (aboot exploit) -- a transform on an existing image, not a container format of its own | `djrbliss/loki` (`loki_tool`) |
| DHTB | a signature-wrapper header prepended to a boot.img; `DHTB_MAGIC` already seen in Magisk's `format.rs` this session (value not recorded -- re-check) | `osm0sis/dhtbsign` |
| Older AOSP "boot signature" / verity (pre-AVB, Android ~4.4-6) | a distinct, simpler signing scheme AVB superseded | `boot_signer` (AOSP `system/extras/verity`, Java) |
| ChromeOS vboot signature | yet another distinct signing scheme (not AVB); also used by some Google/Android devices historically | `osm0sis/futility` |
| blobpack/blobunpack | some OEMs' combined-image "blob" wrapper | `AndroidRoot/BlobTools` |
| Rockchip RKCRC | Rockchip-specific CRC-wrapped image format | `neo-technologies/rkflashtool` (`rkcrc.c`) |
| `androidbootimg.magic` | an XDA-posted `file`(1)/libmagic pattern file covering several of the above -- worth fetching as a cross-check for magic bytes once picking this up | `osm0sis @ xda-developers` (forum post, not a repo -- will need a web search, not a git clone) |

Done so far: MTK sub-header, DHTB, ELF (see the status table). The rest is
still open. Suggested order, roughly by
tractability and how well-defined/low-risk each format is (revisit if
new information changes this):

1. **MTK headers** -- integrates as an extension to the *existing*
   `BootImage`/`VendorBootImage` classes (a sub-header inside the
   kernel/ramdisk blob, not a new top-level container), so it's the
   smallest incremental change. Re-fetch Magisk's `bootimg.hpp` first
   (it was read once already this session but the exact struct wasn't
   saved anywhere durable).
2. **DHTB** -- same reasoning: it's a wrapper (header + hash) around
   an otherwise-normal boot.img, likely implementable as something
   closer to how the AVB footer is handled (an optional outer layer)
   than a whole new parser. Re-check Magisk's `format.rs` for
   `DHTB_MAGIC`'s actual byte value first.
3. **ELF (Sony)** -- a genuinely new top-level container, but ELF
   itself is a completely open, extremely well-documented standard
   (not Android-specific reverse-engineering) -- read `elftool`/
   `unpackelf` source to see exactly which segments map to which boot
   image components before writing anything.
4. **PXA, OSIP/KRNL, RKCRC, blobpack** -- each needs dedicated research
   (read the linked source for each) before implementing; no shortcuts
   from what's already known this session.
5. **ChromeOS vboot (futility) and the pre-AVB AOSP boot_signer verity
   scheme** -- both are full signing schemes similar in scope/care-
   needed to AVB (see how much research + independent verification
   went into `vbmeta.cpp` above) -- budget real time for these, don't
   rush them just because they're later in this list.
6. **LOKI** -- a patch/transform technique for old locked-bootloader
   devices, not a container format; scope this as its own CLI
   operation (e.g. `abr loki-patch`) once everything else here is
   solid, since it's conceptually different from unpack/repack.

Do **not** implement any of these by adding a runtime dependency on
the actual `elftool`/`mkmtkhdr`/`loki_tool`/etc. binaries or by
shelling out to them -- the whole point (explicitly stated) is one
self-contained static binary like Magisk, not a wrapper around a pile
of other people's tools. Their source is a reference for the format,
not something to link against or invoke.

## Next steps (in order)

Build/CI is done and green -- the remaining priority is the AIK
format-parity list above (MTK headers first; see the reasoning there
for the full ordering). Once that's further along:

1. Consider re-running the CI matrix periodically as format support
   grows, so a regression is caught the same session it's introduced
   rather than discovered later.
2. If a working `mkdtboimg.py` mirror turns up, wire it into
   `tests/run_tests.sh` the same way as `mkbootimg.py` (see
   Verification above for why that's worth doing). Low priority.
3. Consider testing the *produced* windows-x86_64/android-arm64
   binaries themselves (under Wine / an Android emulator respectively)
   rather than only their native-Linux-built counterpart -- currently
   only linux-x86_64 runs `tests/run_tests.sh` in CI; the other two are
   build-verified but not run-verified. Not urgent given the shared
   CMakeLists/source is what `tests/run_tests.sh` is actually
   exercising, but would close the loop completely.

### CI status: green as of commit `ea0206d` (run 35313499827)

The path here is worth recording since it involved real debugging, not
just "push and it worked":

1. First run (commit `43cb4cd`): all 3 jobs failed at the Build step,
   `logs` API 302-redirects to `productionresultssa1.blob.core.windows.net`,
   not in this sandbox's egress allowlist -- confirmed via the actual
   HTTP response, not assumed. `check-runs/{id}/annotations` (which
   doesn't redirect) only gave a generic "exit code 1". Added
   `.github/scripts/post_failure_log.py`, called from each job's
   `if: failure()` step, which posts the tail of a tee'd build.log as
   a plain commit comment via the API instead -- reachable from
   anywhere, no blob storage involved.
2. Second run (commit `38fd3d7`, diagnostics added): Build now
   *succeeded* on all 3 platforms (never confirmed why the first
   attempt failed there -- possibly transient), but Package failed on
   windows-x86_64/android-arm64 and Test failed on linux-x86_64.
3. Reproduced the mingw cross-build locally (installed mingw-w64 in
   the sandbox directly -- something the NDK build can't do here, no
   network access to dl.google.com) and got the real compiler error
   immediately: `fatal error: lzma.h: No such file or directory`.
   Root cause: `vendor_deps.cmake` never added an explicit
   `target_include_directories` for `liblzma`, unlike every other
   vendored dep. Native builds had been silently working all session
   because this sandbox had `liblzma-dev` installed system-wide from
   early pre-FetchContent experimentation, so `#include <lzma.h>` was
   quietly resolving to `/usr/include/lzma.h` while still *linking*
   the vendored static lib -- a header/library mismatch that happened
   to compile, masking the real gap. Confirmed the theory by removing
   `liblzma-dev` and rebuilding natively (still worked, using only the
   now-fixed vendored include path) and by rebuilding the mingw target
   (now produces a working `abr.exe`).
4. Third run (commit `ea0206d`, the fix): all 3 jobs green, all 3
   static binaries uploaded as artifacts.

Lesson worth keeping in mind for future work on this repo: a dev
package installed once for quick local iteration can silently mask a
real vendoring gap for the rest of a session. Prefer testing against a
cross-compilation target (even a locally-installable one like mingw)
over trusting a native build alone whenever "does this component
actually come from where I think it does" matters.


## Real device file validation + AIK format parity progress (this session)

The user sent a real vendor_boot.img from an OrangeFox recovery build
(`vendor_boot_ofox.img`, 64MiB) as the promised test case, plus links
to more (Yandex Disk `disk.yandex.ru/d/HbnFvaV-ihx0Tw` and Google Drive
`drive.google.com/drive/folders/1-kgXpos3bKC9NhoNBQls91pGXCT-sMOU` --
**neither is reachable from this sandbox** and the Google Drive
connector tool errored with "user didn't complete authentication", so
further test files need to come as direct chat uploads).

That one real file was extremely productive:
- Confirmed the core vendor_boot v4 multi-fragment/mixed-compression
  support (2 fragments, zstd + lz4_legacy) exactly as designed --
  content-level round trip was already perfect.
- Exposed a real gap: it has a trailing AVB hash-footer (unsigned,
  hash + property descriptor) after the vendor_boot content, which
  unpack correctly ignored (doesn't need it) but repack was silently
  dropping. Fixed generically for boot/vendor_boot/dtbo by reusing the
  existing VbmetaImage footer handling (`save_avb_footer`/
  `reattach_avb_footer` in main.cpp, named `*_avb_tail` at the time) rather than a vendor_boot-specific
  patch -- see git log for the full writeup. Whole 67108864-byte file
  now round-trips byte-for-byte. Added a synthetic permanent regression
  test mirroring this (18 tests total at that point).
- ~~Known limitation: an edited-and-repacked image keeps stale AVB
  hash-descriptor digests.~~ **Resolved later in this session**: the
  digests are now refreshed when the host changed (and a signed
  footer demands `--avb-key`); see "Round-tripping 14 real device
  images" below.

Followed up on the user's "Продолжай... тяни исходники, переделывай
под C++20" instruction to keep working through AIK format parity, per
the roadmap below. Studied AIK's actual `unpackimg.sh`/`repackimg.sh`
(osm0sis/Android-Image-Kitchen, AIK-Linux branch) for the real
detection cascade and orchestration, and its `bin/androidbootimg.magic`
for authoritative magic bytes/offsets for every format on the roadmap
list (BLOB, NOOK/NOOKTAB, CHROMEOS, DHTB, SIN, AOSP/AOSP_VNDR/AOSP-PXA,
ELF+MTK, KRNL, OSIP, LOKI, AMONET, QCDT, AVBv1/AVBv2 footers, Bump,
SEAndroid) -- this single file is the best reference for the whole
list and is worth re-reading rather than re-deriving; not vendored
into this repo (unclear/no stated license on that specific file).

Implemented and shipped, organized under `include/abr/legacy/` +
`src/legacy/` per the user's request to keep this separate from the
core AOSP-standard format code:
- **MTK sub-header** (`legacy/mtk.{hpp,cpp}`): wraps kernel and/or
  ramdisk independently inside an ordinary boot.img on MediaTek
  devices. 512-byte header, magic 0x58881688 LE, 0xFF-padded (not
  zero -- easy to miss), struct from osm0sis/mkmtkhdr's mtkimg.h.
  Wired transparently into `save_component`/`load_component` so it
  applies to any component (boot's kernel/ramdisk, vendor_boot's
  ramdisk fragments) uniformly.
- **DHTB wrapper** (`legacy/dhtb.{hpp,cpp}`): a 512-byte header (magic
  + SHA-256 integrity checksum, not a real signature) some
  Samsung/Qualcomm-based devices' bootloaders require around a whole
  boot.img, itself conventionally followed by a 16-byte
  "SEANDROIDENFORCE" footer and/or 4 bytes of 0xFF padding. Struct
  from osm0sis/dhtbsign's dhtbsign.c. Wired as a pre/post-processing
  step in `do_unpack`/`do_repack`, same pattern as the AVB tail.

Verification: compiled **real** `mkmtkhdr` and `dhtbsign` locally in
this sandbox (`gcc -o mkmtkhdr mkmtkhdr.c`, and dhtbsign + its bundled
libmincrypt sha256.c) and used them as independent oracles --
byte-identical round trips confirmed against both, including a
combined case (DHTB-wrapped + MTK-headered-kernel boot.img together).
This caught one real bug: `strip_mtk_header` never skipped the 4-byte
magic before reading size/name, misaligning every field by 4 bytes
(payload extraction was still correct, since that used a fixed offset
independent of the parse bug, but the recorded component type name
came out as garbage, e.g. "PM-C" instead of "KERNEL" -- a real
round-trip mismatch that a byte-identical check catches regardless of
whether the reference oracle is real or self-consistent). Fixed.
`dhtbsign` itself crashes on exit (double-free) but writes a complete,
correct file before crashing -- usable as an oracle regardless.

**Did not vendor mkmtkhdr.c/dhtbsign.c source into this repo** (unlike
mkbootimg.py): neither has a clear repo-level license, so the
permanent regression tests (`tests/run_tests.sh`) generate equivalent
fixtures directly in Python from this project's own documented struct
layout instead of redistributing that code. Real-tool verification
above was ad hoc (done once, this session, not repeatable via
`run_tests.sh`) -- 22/22 tests passing as of this update, all via
synthetic fixtures for MTK/DHTB specifically.

### Remaining AIK format-parity roadmap (updated, larger than first scoped)

Reading `androidbootimg.magic` directly revealed more distinct formats
than the original ask enumerated. Rough priority, revisit as needed:

1. **ELF (Sony)** -- **done** (commit `67157cf`, verified against the real
   elftool). Whole file is an ELF (32/64-bit,
   little-endian, EI_OSABI=0x61 as the Android-boot marker,
   e_machine identifies CPU arch), components stored as ELF segments.
   Sources fetched already: osm0sis/elftool (elfboot.h, elftool.cpp)
   and osm0sis/unpackelf (unpackelf.c) -- read the struct/segment
   layout from these, not yet done.
2. **PXA (Marvell)** -- osm0sis/pxa-mkbootimg fetched (bootimg.h,
   unpackbootimg.c), not yet read/implemented.
3. **OSIP/KRNL (ASUS/Rockchip)** -- magic bytes known from
   androidbootimg.magic (`$OS$\x00\x00\x01` for OSIP, plain "KRNL"
   for the Rockchip one), but AIK's own KRNL handling in unpackimg.sh
   looks minimal/incomplete (an 8-byte skip with no separate kernel
   extraction shown) -- needs osm0sis/mboot source or real sample
   files to do properly, not just the magic file.
4. **RKCRC, blobpack/blobunpack, QCDT** -- each needs its own source
   read (neo-technologies/rkflashtool's rkcrc.c,
   AndroidRoot/BlobTools, no source identified yet for QCDT).
5. **AVBv1 (old boot_signer verity) and ChromeOS futility signing** --
   both full signing schemes, comparable in scope/care to AVB itself;
   don't rush these. androidbootimg.magic gives the AVBv1 footer
   pattern (`\x02\x01\x01\x30\x82`, DER/ASN.1-looking) as a
   starting point.
6. **LOKI, AMONET** -- bootloader-exploit patch/reversal techniques for
   specific old locked devices, not container formats -- scope as
   their own explicit CLI operations later, not part of unpack/repack
   detection.
7. **BLOB, NOOK/NOOKTAB, SIN (Sony's outer container, separate from the
   ELF format itself)** -- lower priority, older/niche device
   ecosystems; magic bytes are in androidbootimg.magic when it's time.

## Round-tripping 14 real device images

The user supplied 14 real dumps (`boot.7z.001-007`, "the lost files")
and a ChatGPT-written behaviour spec with the caveat "but it's not
exact -- think". The images are the ground truth; the spec was treated
as a hint and cross-checked (below). `tests/tools/roundtrip_dir.py`
unpacks and repacks every file and compares bytes.

| File | What it is | Before | After |
|---|---|---|---|
| `TWRP Recovery Amlogic S9xx.img` | boot v0, page 2048, sha1 id | identical | identical |
| `twrps905x4.img` | boot v0 | identical | identical |
| `boot (2).img`, `boot-sign.img` | 0x4040-byte BFBF/SSSS vendor wrapper around a boot v0, AVBv1 signature inside the payload, 236-byte signature trailer | not recognised (magic is not at offset 0) | identical; the AVBv1 signature inside reads VALID |
| `boot (3).img` | boot v0, page 4096, `id` = SHA-1 that also covers an (empty) dt entry | DIFF at 0x240 (the id) | identical |
| `boot (4).img` | boot v0 + AVBv1 `BootSignature` (2540-byte DER after the image, signed with the public AOSP test key) | DIFF: the DER blob was dropped | identical; signature VALID, and re-signing reproduces it byte for byte |
| `boot.emmc.win` | TWRP backup: boot v0 zero-filled up to 16 MiB | DIFF: output 8 MB, fill dropped | identical |
| `boot_32bit.img` | boot v1 + AVB hash footer | DIFF at the footer | identical |
| `boot_lk2nd.img` | lk2nd bootloader with a boot v0 whose header word 10 is a CAF/QCDT `dt_size` (8192) | unpack failed: "unsupported boot header version: 8192" | identical |
| `vendor_boot (2).img` | vendor_boot v4, 2 ramdisks, AVB hash footer | DIFF at the footer | identical |
| `vendor_boot_b-magisk_patched-27000.img` | vendor_boot v4 with an *empty* ramdisk table, page 2048, v3-sized `header_size` (Magisk/Amlogic style) | DIFF at 0x830, +2048 bytes | identical |
| `vendor_boot_ofox.img` | vendor_boot v4 + AVB hash footer | identical | identical |
| `vendor_dlkm.img` | vbmeta-footer partition with hashtree + FEC data between host and vbmeta | identical | identical (kept so while fixing the footer layout) |
| `recovery (2).img` | an **ext4 filesystem**, not a boot container | "unrecognized image format" | rejected with an explanation (filesystems are out of scope) |

4 of 14 identical before, 13 of 14 after; the 14th is intentionally
refused. Every file is now covered by a synthetic regression fixture
(`tests/tools/fixtures.py`), so the quirks stay fixed without needing the
real dumps.

### What the real files taught us

The recurring lesson matches the spec's own key rule ("keep what you do
not understand and give it back") -- but it applied to far more than
unknown *blocks*: it applied to header *fields*, to the bytes *around* the
container and to how a hash was *computed*.

- **Envelope** (`include/abr/envelope.hpp`): `[opaque prefix][container]
  [opaque tail][fill]`. The prefix is found by scanning the first 64 KiB
  for `ANDROID!`/`VNDRBOOT`; the tail is kept verbatim; a trailing run of
  >= 64 identical bytes is recorded as `pad_byte`/`pad_to` and the file is
  padded back to its original size after an edit. Nothing is dropped.
  If the vendor wrapper/signature data is kept while the container was
  edited, repack warns that it now describes the original image.
- **Boot `id`**: the scheme is detected by trying candidates against the
  stored value -- `sha1` (AOSP), `sha1_dt` (adds the CAF dt entry, even an
  empty one), `sha256`, `sha256_dt`, else `raw` (kept verbatim, never
  "corrected"). After an edit the id is recomputed with the same scheme.
- **Header word 10** (offset 40): <= 4 is `header_version`; 5..8 is an
  unsupported version (error); > 8 is a CAF/QCDT `dt_size` of a v0 header
  (osm0sis' `hdr_ver_max = 8`). The dt blob follows `second`.
- **Header fields kept although nothing parses them**: reserved words
  (v3/v4), a non-standard `header_size`, a non-standard
  `recovery_dtbo_offset`, non-zero data in the header page, and dumps whose
  last page was trimmed (`missing_tail_padding`).
- **vendor_boot v4** can declare no ramdisk table at all (one anonymous
  blob), at page 2048, with a v3-sized `header_size`.
- **AVB footer** (avbtool layout): `[host of original_image_size][zero pad
  to 4096][vbmeta blob][zero fill][64-byte AVBf footer at the partition
  end]`. The footer records the *unpadded* size, so a 2048-page host is
  usually *not* 4096-aligned. Hashtree footers keep tree/FEC between host
  and vbmeta, so `host_prefix` is kept as it was. The HASH descriptor digest
  is `H(salt || host)`; all three real footers verified against their host.
  After an edit the digests are refreshed; a signed footer (algorithm !=
  NONE) refuses to be rebuilt without `--avb-key`; a stale digest in the
  *source* is reported at unpack and left alone on an untouched repack.
- **AVBv1 BootSignature** (AOSP `boot_signer`): DER `SEQUENCE { INTEGER 1,
  X.509 cert, AlgorithmIdentifier sha256WithRSA, AuthenticatedAttributes
  { PrintableString "/boot", INTEGER length }, OCTET STRING signature }` at
  the page-aligned end of the image. Signed data = `image[0:length] ||
  DER(AuthenticatedAttributes)`, SHA-256, RSA PKCS#1 v1.5. The one in
  `boot (4).img` verifies with openssl against the public AOSP test key, so
  re-signing is feasible -- and `abr` now does it (see "AVBv1 boot
  signature, judged by two implementations" above).
- **BFBF/SSSS wrapper**: 0x4040-byte prefix (BFBF blocks at 0 and 0x100,
  SSSS sub-header at 0x4000); payload = boot image + AVBv1 DER + zeros, then
  a 236-byte trailer (148-byte signature + 88-byte `EEEE` TLV list). The
  SHA-1 at 0x140 covers `file[0x4000:EOF]`; `payload_size` is at 0x30,
  0x130 and 0x403c. The vendor RSA signature cannot be reproduced, so the
  wrapper is kept verbatim (not regenerated) and `abr` says so on an edit.
  The vendor that defined it is unidentified -- web searches found nothing.
- **Unpack self-check**: `unpack` now rebuilds the image in memory and
  compares it with the input, so a non-identical round trip is reported
  when unpacking rather than discovered on a device. Known case it flags:
  non-zero bytes in the page padding between components (abr zero-fills
  padding).

### Layering at repack

Build the container -> `Envelope::assemble` (prefix + container + tail +
fill) -> `reattach_avb_footer` (digests refreshed, vbmeta rebuilt, footer at
the partition end) -> DHTB wrap (outermost, recomputes its own SHA-256).

### Cross-check of the ChatGPT "UKA" specification

Useful as a checklist; wrong in places, and much wider than `abr`:

- *"boot v3-v4: header, kernel, ramdisk, **bootconfig (v4)**"* -- no.
  boot v4 adds a `boot_signature` (GKI) block after the ramdisk; bootconfig
  belongs to **vendor_boot** v4. abr implements both correctly.
- *"ramdisk_name[**16**], board_id[16]"* -- the AOSP vendor ramdisk table
  entry has `name[32]` and `board_id` = 16 x u32 (64 bytes), 108 bytes in
  all; confirmed on `vendor_boot_ofox.img` and `vendor_boot (2).img`.
- *"preserve unknown fields and tails"*, *"refuse to repack a
  contradictory header / out-of-range offsets"*, *"mark a signature invalid
  after a payload change"* -- right, and now actually enforced (see above).
- Stage 1 also lists **CPIO** (newc/crc/odc/binary), **MBN**, **FIT/ITB**
  and Qualcomm **ELF** loaders -- not in abr yet (abr's ELF is the Sony
  boot-image ELF). Stage 2/3 (Rockchip, Amlogic upgrade packages, MediaTek
  logo/md1img, Tegra BLOB/BCT, Samsung tar.md5, sparse) is a different and
  much larger scope than "the boot-image family"; some of it already has a
  sibling tool in the suite (`tar_repacker`, `md1img_repacker`). Needs the
  user's decision before any of it is started here.

### Updated roadmap (next first)

1. ~~**AVBv1 BootSignature**~~ -- **done** (detect, verify, re-sign with the
   AOSP test key or `--avb1-key/--avb1-cert`; self-contained RSA).
2. **CPIO ramdisk as a directory tree** (newc, crc, odc, binary): AIK
   parity and spec stage 1. Keep an index of the original member order and
   header fields so an unedited ramdisk still round-trips byte-for-byte.
3. Remaining AIK parity: PXA, OSIP/KRNL, RKCRC, blobpack, QCDT, ChromeOS
   futility signing, LOKI/AMONET, BLOB/NOOK/SIN.
4. Spec stage 1 leftovers: MBN, FIT/ITB. Spec stages 2/3: scope decision.
5. Housekeeping: CI should run the quirk suite; `main.cpp` is ~1200 lines
   and should be split per format.
