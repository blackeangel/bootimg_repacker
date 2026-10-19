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
| ELF boot images (Sony/Xperia `kernel.elf`) | **done + verified** against the real `elftool` (compiled, not vendored) and an independent Python tool and C++ writer: kernel / ramdisk (a directory) / `ipl` / `rpm` / command line by `p_flags`, positional roles for unflagged segments, ELF32 and ELF64; an image in elftool's layout is built from the manifest alone, any other layout (padding, another start of the data, own `e_entry`/OS-ABI/`p_align`/`p_memsz`/`p_paddr`, data in another order, empty segments) is kept and written back; 16 layouts in the CLI suite, 60,000+ unit checks; no real `kernel.elf` has been tried, see "Sony ELF boot images" |
| Sony SIN containers v1-v3 (AIK: `sony_dump`) | **done + verified** against the real `sony_dump` (compiled from its source, not vendored: no licence file) and an independent Python tool: the container comes off and is never put back (AIK forgets it too), what is inside is unpacked as it is on its own; MMCF with `ADDR` / `LZ4A` parts (decoded on several threads when large), loader, data in front; damaged containers are refused with the reason; no real `.sin` has been tried, see "Sony SIN containers" |
| Rockchip KRNL images (`kernel.img`, SDK `boot.img`) | **done + verified** against the real `rkcrc -k` (compiled, not vendored) and an independent Python tool: the payload (kernel, or a compressed cpio ramdisk -> `ramdisk.cpio` + `ramdisk/`), Rockchip's own CRC (polynomial 0x04C10DB7), partition fill, wrong stored CRC kept |
| AMONET patch (Amazon Fire, MediaTek): microloader + boot header moved to 1024 | **done + verified** against AIK's own `dd`/`truncate`/`cat` commands (copied into the suite): `microloader.bin`, `has_amonet=true`, refuses what the patch would overwrite; layered under DHTB |
| ASUS blob (`"MSM-RADIO-UPDATE"`, with or without the `-SIGNED-BY-SIGNBLOB-` header): AIK's `blobunpack`/`blobpack` | **done + verified** against the real BlobTools `blobpack`/`blobunpack` (compiled, not vendored) and an independent Python tool: a blob that holds one image is a wrapper layer (`has_blob=true`; AIK's case), any other is `type=blob` with a file per partition; the signature is kept, `datalen` follows an edit; only blobpack's layout is read |
| Intel OSIP boot images (AIK's `mboot`): OSIP header (or none), signature of 0/480/728/1024 bytes, cmdline, image info, bootstub of 4096/8192 bytes, kernel, gzip ramdisk | **done + verified** against the real `mboot` (compiled, not vendored) and an independent Python tool: images with and without a header, unsigned and signed, are packed to the same bytes, `abr` unpacks them into the pieces `mboot -u` writes, an untouched repack is identical, and an edited image (ramdisk, signature taken away or put in) is a fixed point of `mboot`; the header's sector count, "unsigned" bit and checksum follow mboot's rules, but only when the size or the signature changed; the ramdisk is `ramdisk.cpio` + `ramdisk/` |
| LOKI patch of `loki_tool` (AIK: `loki_tool unlok` / `patch`) on boot and recovery images | **done + verified** against the real `loki_tool` (compiled, not vendored) and an independent Python tool, on synthetic bootloader images: a wrapper layer (`has_loki=true`) that needs no `aboot.img` -- the block of the bootloader's code behind the ramdisk is carried, so an untouched image comes back as it was and an edited one is what `loki_tool patch` makes of the plain repack; the patch code at offsets 0/4/8/12, a block of 512 bytes or of a page, boot and recovery, with and without a device tree, tails and partition fill; `loki patch` itself (the search in an `aboot.img`, loki's table of targets) is not done |
| ChromeOS (vboot) kernel blobs (AIK: `futility vbutil_kernel --get-vmlinuz` / `--pack`) | **done + verified** against the real `futility` (package `vboot-kernel-utils`, run as an oracle, not vendored) and an independent Python tool: the blob is a wrapper layer around the image in its kernel field (`has_chromeos=true`) or a container of its own (`type=chromeos`); preambles 2.0 / 2.1 / 2.2, RSA of 1024 to 4096 bits with the exponent 65537 or 3, SHA-1 / 256 / 512; an untouched blob comes back byte for byte whoever signed it, an edited one is signed again (with the public developer key of vboot_reference, which abr carries, or with `--chromeos-key` / `--chromeos-keyblock`) and is what `futility --pack` / `--repack` make; x86 blobs and layouts futility does not write are refused with the reason; no real Chromebook partition has been tried, see "ChromeOS kernel blobs" |
| Marvell PXA boot header (Samsung Galaxy J1 / Core Prime / Tab 4) | **done + verified** against the real `pxa-mkbootimg` / `pxa-unpackbootimg` (compiled, not vendored): 240 images byte-identical, 34 edits equal to the tool's output (commit `0652429`) |
| `abr identify`: AIK's `androidbootimg.magic` as code | **done + verified**: 98 samples, agree with `file(1)` + AIK's magic file on all (when both are at hand) and with the built-in table; unsupported-but-known formats are named in the refusal (commit `803b820`) |
| Nook / Nook-tablet signing header in front, LG Bump footer behind | **done** (synthetic fixtures; no real device dump of either yet): header kept as a constant prefix (`prefix_kind=`), footer kept as tail, neither triggers the stale-signature warning (commit `2a76f87`) |
| MTK sub-header, DHTB wrapper | **done + verified** against real mkmtkhdr/dhtbsign |
| Everything around the container: opaque prefix (BFBF/SSSS-style wrappers), verbatim tail, partition-size fill, boot `id` schemes (sha1 / sha1+dt / sha256 / raw), QCDT `dt_size`, reserved words, odd `header_size`, header-page data, trimmed dumps, vendor_boot v4 with an empty ramdisk table | **done + verified** -- 13 of 14 real device dumps round-trip byte-for-byte (the 14th is an ext4 filesystem, out of scope and rejected with a clear message); see "Round-tripping 14 real device images" at the end |
| AVB footer on boot / vendor_boot / dtbo: layout, digest check, digest refresh after an edit, `--avb-key` required for signed footers | **done + verified** against the real `avbtool` (`add_hash_footer` output round-trips byte-for-byte; edited + re-signed output passes `verify_image`) and the independent Python/openssl checks |
| AVBv1 `BootSignature` (pre-AVB `boot_signer`, DER blob after the image): detect, verify (`info`, unpack warning), re-create after an edit with the AOSP test key or `--avb1-key/--avb1-cert` (AIK `name.pk8`+`name.x509.pem` naming too), add to an unsigned image | **done + verified** against the real AOSP `boot_signer` (compiled from its Java sources) and an independent Python/openssl signer: same bytes from the same key and image; abr-re-signed images pass `boot_signer -verify`; real-device AVBv1 images read VALID |
| compression: gzip, lz4, lz4-legacy (HC 12, as Android builds it), zstd, xz, lzma(alone), bzip2, lzo (genuine lzop framing) | **done + verified, all algorithms**, each also read back by the real `gzip`/`lz4`/`zstd`/`xz`/`bzip2`/`lzop` |
| multithreading (`-j N`): components of an image, LZ4 legacy blocks, zstd workers | **done + verified**: bytes identical for any thread count (suite, every codec), `abr::par` unit-tested, TSan/ASan-clean; see "Threads, and what the codecs taught us" |
| bundled SHA-1/256/512 | **done**, self-test passes, catches its own transcription bug once already (see Verification below) |
| self-contained RSA: BigInt (Knuth D, Montgomery), DER/PEM/X.509, PKCS#1 v1.5 sign/verify, PKCS#8/PKCS#1 key parsing, AVB public-key blob -- **no OpenSSL anywhere in the build** | **done + verified** (Python integers, `openssl dgst -sign`, `avbtool extract_public_key`; see "Self-contained crypto" below) |
| manifest + CLI (`abr info/unpack/repack`) | **done** |
| CMake: FetchContent-vendored static zlib/lz4/zstd/xz/bzip2 | **done + build-verified natively on Linux**, both the dynamic and the `-DABR_STATIC_BINARY=ON` fully-static configurations |
| Test suite (`tests/run_tests.sh`) | **done, 312/312 passing** locally on g++-14 and on clang-20, 311/311 for `abr.exe` under wine (with the optional `pxa-*` / `rkcrc` / `blobpack`+`blobunpack` / `mboot` / `loki_tool` / `futility` oracles and AIK's magic file); CI runs the matrix (g++-14, clang-20, Windows under wine, arm64 under qemu-user) -- see Verification |
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
compress/decompress calls. Since 4 Oct the encoder writes what
`lzop -c < file` writes (version 1.04 layout, LZO1X-1, 256 KiB blocks, an
Adler-32 of each block's uncompressed data, incompressible blocks stored as
they are); its first version wrote a minimal header laid out the way the
kernel's parser reads it, which the real `lzop` rejects, and wrote
incompressible blocks longer than their data, which the kernel rejects (see
"Threads, and what the codecs taught us"). The decoder tolerates the
newer/optional fields (filter info, mtime_high, a filename, one or two checksum
words per block) a real lzop file could have, matching the kernel
decompressor's own leniency.

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

## Hashing speed: SHA-NI / ARMv8 (4 Oct 2026)

Why: the profile of an unpack (callgrind, `twrps905x4.img`, before any change)
was 77% `Sha256::process_block`, 12% SHA-1, under 10% decompression. Threads
would have parallelised a minority of the time; the hashing itself was the
lever. (Note for later profiling: valgrind does not emulate the SHA
instructions and hides them from CPUID, so a callgrind profile always shows
the portable code.)

What `src/sha.cpp` does now:

- SHA-1 and SHA-256 compress whole blocks straight from the caller's buffer
  (no per-block copy into an internal buffer) through a function chosen once:
  x86-64 **SHA-NI** (`sha1rnds4`, `sha256rnds2`, message schedule with
  `msg1/msg2`), ARMv8 **SHA1/SHA2** (`vsha1cq` ..., `vsha256hq` ...), else a
  fully unrolled portable version (literal round numbers, 16-word schedule
  window, variables rotated by renaming). The instructions are used through
  per-function `target` attributes, not global `-m` flags, so the binary still
  runs on a CPU without them. Detection: CPUID (SSSE3, SSE4.1, SHA) on x86;
  `getauxval(AT_HWCAP)` on Linux/Android and `IsProcessorFeaturePresent` on
  Windows for arm64. SHA-512 is unchanged (no mainstream CPU has it).
- `ABR_SHA_IMPL=portable` forces the portable code; `abr_unit_tests sha-impl`
  prints what runs; `sha-bench [MiB]` prints MB/s for every implementation.

Measured (this machine, one core, 128 MiB buffer; same on g++-14 and
clang-20, and under wine for the Windows builds):

| | before | portable now | SHA-NI |
|---|---|---|---|
| SHA-256 | 240 MB/s | 275-300 | 1400 |
| SHA-1 | 175 MB/s | 700 | 1560 |
| SHA-512 | 360 MB/s | 360-400 | (unchanged) |

Unpack of real images, warm cache, whole command including the self-check
(previous commit built beside it for an honest A/B): `twrps905x4.img` (33 MB,
gzip kernel + ramdisk) 1.70 s -> 0.85 s; `vendor_boot_ofox.img` (67 MB)
3.36 s -> 1.45 s; `vendor_boot (2).img` (25 MB) 0.92 s -> 0.37 s. What is left
is mostly zlib inflate and memory traffic -- which is where threads can still
help (next section).

How it is verified: 3024 known-answer vectors per implementation, computed
with Python's `hashlib` (`tests/tools/gen_sha_vectors.py`: every length
0..129, the 55/56 and 63/64/65 boundaries, 191..257, 4095..4097, 64 KiB +-1,
1 MiB + 7; each fed in 7 different `update()` chunkings), run for the
hardware-selected implementation **and** for `ABR_SHA_IMPL=portable`, so both
are judged on every machine. Run and passing: x86 SHA-NI and portable (g++-14,
clang-20, g++-13/C++23, both Windows builds under wine); the **ARMv8
implementation under qemu-user** (`-cpu max`), hardware and portable, 3024/3024
each. The whole suite on the arm64 build under qemu-user: 100/100 (5 minutes
emulated). qemu's speeds say nothing about real ARM cores (TCG emulates the
SHA instructions slowly), only that the results are right.

`cmake/toolchains/aarch64-linux-gnu.cmake` (GCC cross compiler, static glibc)
exists for exactly this, and `tests/run_tests.sh` takes `ABR_RUNNER="qemu-aarch64
-cpu max"` to run any non-native build through an emulator; CI has an arm64 job
that does it on every push.

## Threads, and what the codecs taught us (4 Oct 2026)

Decision (the user, 2 Oct): multithreading where it makes sense. So: find out
where the time goes, parallelise only that, and make the output independent of
the thread count.

### Where threads help, and where they cannot

| work | parallel? | notes |
|---|---|---|
| the components of one image (kernel, ramdisk, each vendor fragment, dtb, ...): decode + hash + write on unpack, load + recompress on repack | yes, one job per component, biggest first | `save_components` / `load_components` in `src/main.cpp` |
| LZ4 legacy compression | yes, per 8 MiB block | the format is a run of independent blocks. At HC level 12 a block compresses at 3-20 MB/s depending on the data, so this is the one place where editing a ramdisk takes seconds |
| zstd compression | yes, the library's own workers | `ZSTD_c_nbWorkers`, counted in the same thread budget (`par::Lease`); needs libzstd built with `ZSTD_MULTITHREAD_SUPPORT`, now on |
| gzip / xz / lzma / bzip2 compression | no | one stream each. A block-parallel gzip (pigz style: raw deflate blocks, dictionary priming, sync flush, `crc32_combine`) is possible but writes different bytes than a plain zlib would; not done |
| decompression | no, inside one stream (components overlap) | LZ4 is GB/s anyway; gzip inflate is a serial chain |
| SHA of one buffer | no | a serial chain; the hashes of different components overlap because components are jobs |

**The rule: the result never depends on the number of threads.** Work is split
by the data (fixed 8 MiB LZ4 blocks, one job per component), never by the
thread count; results are joined in index order; zstd is always asked for at
least one worker (`nbWorkers = 0` writes a different, equally valid frame than
`>= 1`, and `-j1` must not be the odd one out); an exception from the lowest
failing index is the one rethrown, as a serial run would meet it first. The
suite repacks every codec with `-j1`, `-j4` (and `-j2`/`-j8` for the two that
use threads) and demands identical bytes. Mutation-checked: making `-j1` ask zstd
for 0 workers makes the suite fail.

### `abr::par` (`include/abr/parallel.hpp`, `src/parallel.cpp`)

One pool for the process: at most `max_threads() - 1` workers, started when
there is something for them to do. `for_each(n, fn)` puts its jobs on a shared
list and works on them itself; **a thread that has to wait for its own jobs
runs jobs of any region that still has an unstarted one** ("help while
waiting"). That is what makes nesting work (the ramdisk job of an image
compressing its own LZ4 blocks borrows every idle thread, never holds one just
by waiting, and can never wait for work nobody is running); the running jobs
never outnumber `max_threads()`. `Lease` is for code that starts threads of its
own (libzstd): it takes places out of the same budget and gives them back.
`-j N` / `--threads N` / `ABR_THREADS`; default = hardware threads, at most 16;
`-j1` runs everything on the main thread.

How it got there (so nobody repeats it): the first design was fork/join with
helper threads per region and a global budget of extra threads. On the real
case that motivated all this -- OrangeFox's `vendor_boot` with two ramdisk
fragments, one of them edited -- `-j2` was *exactly as slow as `-j1`*, three
times over, each time for a different reason: (1) the outer job held its slot
while it waited for the inner region, so the inner one found the budget empty;
(2) the main thread sat idle in the join while the worker ran the heavy job;
(3) an inner region that started with an empty budget never asked again once a
slot was free. Patching those got 10.0 s -> 6.1 s; replacing the budget by one
pool with help-while-waiting got 10.0 s -> 5.4 s with much less machinery and
no special cases. Checked by `abr_unit_tests par` (every index once; the error of
the lowest failing index; nested regions; the cap on running threads; leases;
300 rounds of tiny nested regions; a 120 s watchdog turns a deadlock into a
failure), run for limits 1, 2, 3, 8 and 2 again: 25 repeats without a failure,
pinned to a single core, and clean under ThreadSanitizer and ASan+UBSan.

### Measured (2-core sandbox, warm cache, best of 5, previous commit built beside it)

`unpack` of real device images (the whole command, including the self-check):

| image | previous commit | now `-j1` | now `-j2` |
|---|---|---|---|
| `twrps905x4.img` (33 MB) | 0.85 s | 0.86 s | 0.73 s |
| `vendor_boot_ofox.img` (67 MB) | 1.64 s | 1.60 s | 1.18 s |
| `vendor_boot (2).img` (25 MB) | 0.32 s | 0.31 s | 0.26 s |
| `boot (3).img` (15 MB) | 0.32 s | 0.31 s | 0.30 s |

`-j1` costs nothing against the commit before threads; `-j2` gives 14-28% on
the big images, which is what the serial parts (reading, one stream's inflate)
allow. Recompressing an edited ramdisk is where threads matter:

| edit | `-j1` | `-j2` |
|---|---|---|
| OrangeFox `vendor_boot`, 63 MB LZ4 ramdisk edited | 10.0 s | 5.4 s |
| 63 MB ramdisk -> lz4_legacy (HC 12), 37.4 MB out | 9.2 s | 4.9 s |
| same -> zstd (level 3) | 0.58 s | 0.44 s |
| same -> gzip / bzip2 / lz4 frame / lzo | 2.5 / 5.3 / 0.4 / 0.5 s | no change |

(`-j3` and `-j8` on two cores: the same bytes, no faster.) More cores should
help the LZ4/zstd rows further; this machine has two, so that is not measured.

### What measuring and the real tools turned up

- **LZ4 legacy was written at the fast setting**, not at what Android uses
  (`lz4 -l -12`, the densest HC level). An edited OrangeFox ramdisk came out
  larger than the 64 MiB `vendor_boot` partition allows; at HC 12 it fits
  (67108864 bytes exactly as before). The default is now HC 12, parallel per
  block; `<component>_level=N` in the manifest overrides it for any codec.
- **LZO had two faults, found by feeding its output to the real `lzop`**: the
  header was not a valid lzop header (version fields laid out the way the
  kernel's parser reads them, and the checksum started from 0 instead of 1),
  and incompressible blocks were written *longer* than the data they held
  (`src_len > dst_len`), which the kernel's `unlzo` rejects as a corrupt file --
  2 of 7 blocks in a test ramdisk with a random stretch. The encoder now writes
  what `lzop -c < file` writes (version 1.04 layout, LZO1X-1, 256 KiB blocks, an
  Adler-32 of each block's uncompressed data) and stores incompressible blocks
  as they are; the decoder counts the per-block checksum words from the flags
  instead of assuming one. `lzop -d` and `lzop -t` accept the output, including
  the empty and one-byte inputs.
- `std::call_once` does not link with clang + mingw-w64 (undefined
  `std::__once_callable`); a function-local static does the same job.
- A statically linked glibc older than 2.34 needs libpthread pulled in whole for
  `std::thread` (added to `CMakeLists.txt` when `libpthread.a` exists).
- Not done, on purpose: gzip at its default level (6) where AIK uses 9;
  zlib-ng for deflate/inflate speed (measured, see the Rust section); the gzip
  header's OS byte is zlib's per-platform value (3 on Unix, 10 on Windows), so a
  *recompressed* gzip stream differs between a Linux and a Windows build while an
  untouched image is unaffected -- worth fixing with `deflateSetHeader` if byte
  equality across platforms ever matters.

### Rust 1.99.0 instead of C++26? (asked 2 Oct; answered 5 Oct)

Two readings of the question, both answered with measurements, not opinion.
The sandbox has Rust **1.95.0** (rustup's static.rust-lang.org is not reachable
from here, so 1.99.0 could not be installed; four releases later the
compiler, std and LLVM backend are not different in ways that matter below).
Same inputs (128 MiB buffer; the 63 MB ramdisk of `twrps905x4.img` as gzip),
same idle machine, back to back, best of 5 (2 for the deflate rows): the
real `abr_core` with zlib 1.3.2, the same C++ program linked against
**zlib-ng 2.3.3 in zlib-compatible mode** (a C library, built from the git tag),
and a small Rust program (`sha2` 0.10.9; `flate2` 1.1.10 with the pure-Rust
`zlib-rs`):

| | C++ + zlib 1.3.2 | C++ + zlib-ng 2.3.3 | Rust 1.95 + zlib-rs |
|---|---|---|---|
| SHA-256 (SHA-NI in all three) | 1454 MB/s | 1459 | 1433 |
| gunzip, 63 MB out | 224 MB/s | 358 | 354 |
| gzip -6 | 27 MB/s | 67 | 62 |
| gzip -9 | 6.2 MB/s | 20.8 | 21.7 |
| cold `cargo build --release` of the 2-crate program | | | 19 s wall, 2 cores |

1. **Would a rewrite make abr run faster?** Not by being Rust. Hashing is the
   same CPU instructions in either language (first row). The one real
   difference, deflate/inflate (1.6x to 3.4x), is a difference of
   *libraries*: zlib-ng, a C library, is exactly as fast as zlib-rs, the Rust
   one (second and third columns). C++ gets it by swapping zlib for zlib-ng.
   Everything else is codec libraries that are C either way -- zstd, xz, lz4
   (HC), bzip2, minilzo; I know of no pure-Rust LZ4 HC or LZO that I would
   trust to write what Android's tools write, so a Rust abr would link the
   same C libraries through `-sys` crates.
   Whether to swap zlib for zlib-ng was weighed and **not done**: the gain is
   real but small where a person feels it (inflating a 25 MB gzip ramdisk is
   ~0.1 s of a ~0.85 s unpack; gzip recompression after an edit would drop from
   ~2.3 s to ~1 s for a 63 MB ramdisk at the default level), while the costs
   are not zero: recompressed gzip streams would differ from zlib's (harmless,
   but a change), zlib-ng picks its code at run time by CPU feature, so
   "same bytes on every machine" would have to be shown for its deflate paths
   (not assumed), and it must build for the mingw-clang, NDK and aarch64
   targets (the NDK one provable only in CI). Option for later, if gzip
   speed ever matters.
2. **Would it speed up writing/rewriting code?** I do not expect so. The
   language-neutral test suite (shell + Python + the real tools) is what makes
   any rewrite verifiable at all, and it already exists; it would not get
   shorter. Rust's compile-fix loop (borrow checker) costs iterations for
   every new parser; C++ with sanitizers costs them at test time instead.
   Build time is not an argument either way (19 s for two crates).
3. **What Rust would genuinely give**: memory safety for parsers fed with
   untrusted images (a boot image is attacker-controlled input to anyone who
   unpacks images they did not build), `rayon` instead of `abr::par`
   (well-tested nested fork/join; our 250 lines are tested too, but they are
   ours), and cargo for cross builds. What it would cost: re-deriving ~7.9k
   lines of C++ together with every real-device quirk found so far; losing
   code sharing with the sibling C++ tools (`f2fs_unpacker`, `tar_repacker`,
   `md1img_repacker`, `utils`), or living with two languages in one build; and
   delaying the remaining AIK-parity work (cpio tree, PXA, ...).
4. **A cheaper way to most of the safety**: ASan/UBSan/TSan builds of the
   suite in CI and libFuzzer targets for the parsers. All of it works in C++
   today.

Recommendation: stay on C++26; do not rewrite now. Revisit after the AIK-parity
feature freeze, and then only as a measured port with the existing suite as the
acceptance test (differential runs of the C++ and Rust binaries on every image).
If speed is the goal, the next lever is the deflate library (zlib-ng), not the
language.

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

## AIK format parity: where things stand (6 Oct 2026)

The user wants parity with what Android Image Kitchen (AIK, osm0sis) handles,
explicitly comparing the end goal to Magisk: **one static binary, no
shell-outs to other tools**. AIK's own scripts are the specification
(`unpackimg.sh` / `repackimg.sh` of AIK-Linux v3.8 were read in full), and
its `androidbootimg.magic` -- two files the user supplied -- is the list of
formats; it is **not vendored** (no licence stated), the real tools
(`mkmtkhdr`, `dhtbsign`, `pxa-mkbootimg`, `elftool`, `boot_signer`) are
compiled from source and used only as oracles, never as a dependency.

| AIK does | abr |
|---|---|
| AOSP boot / recovery, header v0-v4; vendor_boot / vendor_kernel_boot | done |
| AOSP-PXA (`pxa-unpackbootimg`) | done, oracle-verified |
| ELF (`unpackelf` / `elftool`) | done, oracle-verified; layouts other than elftool's are kept (see "Sony ELF boot images" below) |
| U-Boot legacy uImage (`dumpimage` / `mkimage`) | done; FIT (flattened image tree) not |
| MTK 512-byte header on kernel/ramdisk (`mkmtkhdr`) | done, oracle-verified |
| DHTB wrapper (`dhtbsign`) | done, oracle-verified |
| NOOK (1 MiB) / NOOKTAB (256 KiB) header (`master_boot.key`) | done, as a constant prefix; synthetic fixtures only |
| tail footers AVBv1 / AVBv2 / Bump / SEAndroid | AVBv1 and AVBv2 verified and re-created after an edit (`boot_signer` / `avbtool` oracles); Bump and SEAndroid kept verbatim and inert |
| ramdisk codecs gzip / lzop / xz / lzma / bzip2 / lz4 / lz4-legacy | done, all judged by the real tools; plus zstd |
| **ramdisk as a directory tree** (`cpio -i` / `find . | cpio -H newc`) | **done** for newc/crc, including several archives one after the other; owners/modes live in `ramdisk.meta`, links work on Windows; odc/binary/hard links stay a `ramdisk.cpio` (see "The ramdisk as a directory" below) |
| AIK's compression defaults (`xz -1 -Ccrc32`, `lz4 -9`) and `--level` | abr uses each codec's usual setting; `<component>_level=N` overrides |
| `--original` (repack with the stored ramdisk, skip `ramdisk/`), `--origsize` (pad back to the original size), `--forceelf` (repack an ELF as ELF), `--avbkey` | not needed as options: an untouched `ramdisk.cpio` is replayed as it was (compressed bytes included), the recorded partition-size fill (`pad_to`) is always written back, an ELF is always rebuilt as an ELF (AIK's default converts an image without an `rpm` segment to an AOSP image instead; abr cannot do that conversion), and `--avb-key` / `--avb1-key` are the signing keys |
| BLOB (`blobunpack` / `blobpack`, AndroidRoot/BlobTools) | **done**, judged by the real tools: unpack / repack / info; wrapper layer between DHTB and AMONET, or a directory of its own for several partitions; see "BLOB" below |
| ChromeOS kernel blob (`futility vbutil_kernel`) | **done**, judged by the real `futility` and a Python tool: unpack / repack / info as the outermost wrapper layer (ChromeOS -> DHTB -> blob -> LOKI -> AMONET) or as a container; the signatures are kept while what they cover is unchanged and made again after an edit (the developer key of vboot_reference, or `--chromeos-key`); x86 refused; see "ChromeOS kernel blobs" below |
| Sony SIN (`sony_dump`) | **done**, judged by the real `sony_dump`: v1, v2, v3; a wrapper layer that comes off and is not put back (as in AIK); see "Sony SIN containers" below |
| Intel OSIP (`mboot`) | **done**, judged by the real `mboot`: unpack / repack / info, header rules as mboot's, the ramdisk as a directory; see "OSIP" below |
| Rockchip KRNL (`dd skip=8`, `rkcrc -k`) | **done**, oracle-verified (`rkcrc`): unpack / repack / info; a payload that is a cpio gets the ramdisk directory (AIK treats it as a ramdisk the same way); see "Rockchip KRNL" below |
| AMONET (microloader in the first 1024 bytes, `dd`/`truncate`/`cat`) | **done**, judged by AIK's own commands: unpack / repack / info, wrapper layer under DHTB; see "AMONET" below |
| LOKI (`loki_tool unlok` / `patch`, needs the device's `aboot.img`) | **done**, judged by the real `loki_tool`: unpack / repack / info as a wrapper layer (DHTB -> blob -> LOKI -> AMONET); no `aboot.img` is needed to repack, the block that was in the image is put back; patching a plain image for a bootloader that has no LOKI image of its own (`loki patch`) is not done; see "LOKI" below |
| QCDT device-tree table tooling (`dtbTool`) | the blob is carried as `dt_file`; creating one from several dtbs is not done |

`abr identify` names every row above, so none of them is reported as
"unrecognized format" any more.

Do **not** implement any of these by adding a runtime dependency on, or by
shelling out to, the actual `elftool`/`mkmtkhdr`/`loki_tool`/etc. binaries --
the point is one self-contained static binary. Their source is a reference
for the format, not something to link against or invoke.

## The ramdisk as a directory (done)

`unpack` writes `ramdisk.cpio` (decompressed, byte for byte what the image held)
and, when the archive can be one, the directory `ramdisk/` (vendor_boot:
`ramdisk0/`, `ramdisk1/`, ...) with `ramdisk.meta`. Code: `include/abr/cpio.hpp`
+ `src/cpio.cpp` (reader and writer of newc `070701` and crc `070702`),
`include/abr/ramdisk_tree.hpp` + `src/ramdisk_tree.cpp` (extract, rebuild, the
metadata), the wiring in `src/main.cpp` (`save_ramdisk_trees`,
`load_component`). Tests: `tests/unit/cpio_test.cpp` (`abr_unit_tests cpio`:
1686 checks, 150 random ramdisks with random edits among them), the "ramdisk as
a directory" section of `tests/run_tests.sh` (about 85 checks) with
`tests/tools/cpio_gen.py` (a writer and reader of its own) and
`tests/tools/ramdisk_oracle.py` (GNU cpio 2.15 as the judge: its listing and its
extraction against the directory and the metadata). `ABR_REAL_IMAGES=<dir>
tests/run_tests.sh <abr>` runs the same checks on the user's own images.

**Which file counts.** Neither `ramdisk.cpio` nor the directory changed: the
image's own compressed bytes are replayed (that is the exact round trip). Only
the file changed: the file. Only the directory: the archive rebuilt from it.
Both: an error, unless `--ramdisk-from tree|cpio`. "Changed" is a hash:
`ramdisk_orig_hash` for the file, `ramdisk_tree_hash` (SHA-256 of the archive
rebuilt from the untouched directory) for the tree -- never file times.
`--no-tree` writes only the file, `--tree-only` only the directory.

**The directives of 7 Oct, one by one.**

1. *Several cpio archives one after the other (what Magisk's cpio unpacks).*
   Supported: the archives of the stream are split (the zero fill after one
   belongs to it; the next starts at a multiple of 4; at most 64; junk or an
   odc archive between or after them keeps the whole ramdisk a file) and each
   gets `ramdisk/`, `ramdisk.vol2/`, ... with `ramdisk.meta`,
   `ramdisk.vol2.meta`, ...; the manifest says `ramdisk_tree_volumes=N` (only
   when N > 1). Each archive keeps its own magic, digit case, name style and
   fill. A volume whose directory was deleted is left out of the image (a note
   says so); if all are gone `ramdisk.cpio` is used; a directory beyond the
   last one is ignored with a warning (a new archive comes from `ramdisk.cpio`,
   not from a new directory); a foreign non-empty `ramdisk.volN/` refuses the
   whole tree ("is not an empty directory") rather than leave an archive half
   in a directory; a later unpack removes the volumes of an earlier one that
   the new image does not have.
2. *Permissions of files put into the ramdisk, which Windows loses.* They live
   in `ramdisk.meta` and are never read from the file system for an entry the
   metadata knows. A new path gets `default uid= gid= mtime= dev=` and
   `newmode file=0644 exec=0755 dir=0755 link=0777` from the header of the
   metadata (editable), where "exec" means a `#!` script, an ELF program (not
   `.so`, `.ko`, `.so.N`) or the owner-execute bit (not compiled on Windows,
   where it does not exist). A path changing its kind is new. A line of its
   own in the metadata gives any path any mode and owner. `repack` names what
   it found new (12 at most, then "and N more") and what was deleted. The
   leftovers of file managers (`.DS_Store`, `Thumbs.db`, `desktop.ini`) are
   left out, with a note.
3. *Symbolic links without administrator rights.* POSIX: a real link.
   Windows: always the Cygwin/MSYS2 file -- `!<symlink>`, the mark FF FE, the
   target in UTF-16LE (surrogate pairs beyond the first plane), `00 00` -- plus
   the System attribute (`SetFileAttributesW`, `mark_system_file()` in
   `byte_io.cpp`); that is the scheme of the user's ext4 unpacker (`attrib +s`)
   and `tar_repacker`. Read back from a real link, a Cygwin file, the older
   UTF-8 form of it, or -- when the metadata says `l` -- a text file with the
   target (CR/LF stripped). A file whose metadata line says `f` stays a file
   even if it looks like a link file (a note says how to change that). A tree
   unpacked on Linux, carried to Windows (or through git without symlinks) and
   repacked there gives the same ramdisk: the tests turn every link into a
   Cygwin file and into a text file and demand the identical image.

**What GNU cpio taught.** Its header digits are upper case (`gen_init_cpio`
too); Android's `mkbootfs`, Magisk and libarchive write lower case. The first
rebuilt archive differed from GNU's at byte 9 until `hex upper|lower` was
recorded per archive (a mix inside one archive is refused). The GNU cpio 2.15
of the test machine writes the root as `.` and every other name plain, the
archives AIK makes have `./x`: `names plain|dotslash`, the root being an entry
of its own. The fill after the trailer is a multiple of 512 (its I/O block)
counted from the start of the whole stream, which is why `tail align N` is
relative to the ramdisk and not to the archive; the heuristic tries 512 or 256
(the likelier first), 1024, 4096, no fill, else `tail size N`. GNU cpio reads
only the first archive of a stream, so the oracle cuts the stream itself.

**Refused, kept as `ramdisk.cpio` with the reason in the log:** odc and binary
archives, hard links (two names with one device and inode and a link count
above 1), a name twice, `..` or an
absolute name, a file before its directory, a link target with a line break,
mixed magics or digit cases, an archive off its boundary, junk, a cut-short
archive; on Windows also names it cannot hold (`"`, `\`, a control character, a
trailing dot or space, `CON`, `NUL` ...), and on any system a file system that
tells two names of the archive apart less well than the archive does.

**Not done / later:** odc and binary archives (rare), hard links, a helper that
makes Cygwin link files on Windows for a person who adds a link by hand (a text
file with the target works when the metadata says `l`, but a brand-new link
needs the Cygwin file or a line of its own).

**Lessons from the test suite** (they cost time): `diff -r` follows links and
exits 2 on a dangling one -- use `--no-dereference`; `producer | grep -q` or
`| head` can SIGPIPE the producer under `pipefail` -- capture first; a Windows
build printed `\` in paths, so the CLI prints `/` everywhere in these messages.

## An edit that no longer fits its partition (done)

An image made with a denser compressor than abr's usual setting outgrows its
partition as soon as the edited component is compressed again. The real case:
OrangeFox's `vendor_boot` (64 MiB) has `ramdisk0` at `zstd -19` (22,564,936
bytes for 97,479,936; `zstd -3` writes 28,201,208 for the same content). With a
file added at abr's level 3 the image plus its AVB metadata is 67,117,760 bytes,
8,896 more than the partition holds.

`repack` now builds the image the usual way and, when it does not fit, builds it
once more with everything that is compressed again at `dense_level(codec)`
(`include/abr/compression.hpp`): gzip 9, zstd 19 (windowLog 23 = 8 MiB, what
`zstd -19` writes, read by any zstd decoder), xz 9, lz4 frame 12; `-1` where the
usual setting already is the densest (LZ4 legacy HC 12, bzip2 9) or the codec has
no setting (lzma-alone, lzo). The OrangeFox edit then comes out at 67,108,864
bytes -- the partition -- with a valid AVB footer (38 s on two cores, most of it
level 19).

How it is wired (`src/main.cpp`): `DoesNotFit` (a `FormatError`, `byte_io.hpp`)
is thrown by the AVB footer layout (`src/vbmeta.cpp`) and by
`assemble_envelope()` when the image outgrew the fill it was padded to;
`build_image()` catches it, and retries only when `g_denser_would_help` says that
something was compressed at a setting with a denser one (set in
`load_component()`; a `<component>_level=` in the manifest is never overridden).
Otherwise a second try would build the same image: the first try's error (or,
for a padded image, its warning) stands, exactly as before. Messages of the
first try are held back (`Deferral`) and dropped when a second try follows, so
each appears once. If even the dense build is too big the error says
"... -- not even with what was edited compressed as densely as the codecs allow".

Why the result does not depend on `-j`: zstd derives its job size from the level,
not from the worker count, and abr always asks for at least one worker (see
`zstd_compress`); the tests compare `-j1` with `-j4` on the retried images.

Measured: `zstd -19 -T2` on that ramdisk takes 24 s (1 s at level 3), so the
second try is paid for only when the first did not fit. xz preset 9 needs about
674 MiB to compress; if the system refuses, the error names the preset and the
memory and says to put a lower one in `<component>_level=`.

Tests (8 checks in the "too big for its partition" part of `tests/run_tests.sh`,
and OrangeFox itself through `ABR_REAL_IMAGES`): a boot v4 whose ramdisk (an
mkbootfs archive with 2 MB of text) was written at zstd 19, in a partition made
by the real `avbtool add_hash_footer` as small as it allows (its reserve is
69,632 bytes: partition = dense image + 73,728, which the level-3 image does not
fit) -- the file put into `ramdisk/` is in the result, the image is exactly the
partition, `avbtool verify_image` and abr's hash check accept it, the real `zstd`
reads the ramdisk, the note appears once, `-j1` = `-j4`; the same padded with
zeros instead of an AVB footer; the same for vendor_boot v4 fragment 0; 300 KB
of noise added: refused with the "not even" message and no image left behind
(AVB), or written with one warning (padded); the same with an LZ4 legacy ramdisk:
the old refusal / warning, with no word of a second try; an untouched repack
replays the original bytes and says nothing. As a negative control the retry
was switched off once: exactly the retry-dependent checks failed.

Found on the way: the RSA-verify check corrupted a signature byte with a fixed
value (0x55), which left the signature unchanged one run in 256 -- an XOR now;
and the GNU `cpio` oracle needs the package installed in the CI jobs (added to
the `apt-get` lists of the linux, windows/wine and arm64/qemu jobs).

## The last component of a trimmed dump, edited (fixed 14 Oct 2026)

Found while testing LOKI, in the general builder: a boot or vendor_boot image whose file lacks the padding
of its last page (whoever dumped it left the final page off: what `loki_tool unlok` writes, and the dumps
`missing_tail_padding` was made for) came out of a repack **too short** after its last component grew. The
manifest kept `missing_tail_padding=N`, the number of bytes the file lacked, and `build()` cut exactly N bytes
off the end of the rebuilt image; with a bigger last component (a 5000-byte device tree made 8000 bytes) the
padding is smaller than N and the cut went into the data: 952 bytes of the dt were lost, without a word. A
smaller last component, or a different padding after any edit, came back with padding the dump never had.

The cut is now measured from where the content ends (`trim_missing_padding()` in `byte_io.hpp`): `build()` knows
the end of the last component's data, the parser records how much of the final padding the dump holds
(`tail_padding_kept`, usually 0: the file ends where the data ends), and the rebuilt image keeps that much of
its own padding. A dump that ends in the middle of its padding keeps its bytes (untouched repack: identical);
a manifest from an older abr (no `tail_padding_kept`) is cut by `missing_tail_padding` but never into the data.
Both builders have it: `BootImage::build` (v0-v4, PXA) and `VendorBootImage::build`.

Tests: new fixtures (a trimmed boot v0 with a CAF device tree last, a trimmed vendor_boot v4, a boot v2 that
ends 300 bytes into its padding) round-trip exactly, and the last component of each of the three trimmed images
is made 3000 bytes bigger, 400 smaller and 1,000,000 bigger: the rebuilt image ends exactly where the component
ends, and an independent parser (`tests/tools/verify.py boot-part`; vendor_boot: abr's own unpack) reads the
component back whole. The first version of the fix (cut by N, but at most the padding) failed these tests -- it
left padding behind -- which is what made `tail_padding_kept` necessary.

## Rockchip KRNL (done, 11 Oct 2026)

AIK's `unpackimg.sh` takes a `KRNL` file for a ramdisk image (`dd skip=8`, the
payload being what it hands to the ramdisk codecs) and `repackimg.sh` writes it
back with `rkcrc -k`. abr does the same without either tool.

The format: `"KRNL"`, u32 le size of the payload, the payload, u32 le CRC. Code:
`include/abr/legacy/krnl.hpp` + `src/legacy/krnl.cpp` (`KrnlImage::parse/build`,
`rkcrc32`), the wiring in `src/main.cpp` (`Fmt::KRNL`, `unpack_krnl`,
`repack_krnl`, the `info` case), `tests/tools/krnl_tool.py` (an independent
writer/reader), the "Rockchip KRNL" part of `tests/run_tests.sh` (8 checks).

**The CRC is not CRC-32.** It is MSB-first, start value 0, no reflection, no final
XOR, over the payload only -- and the polynomial in rkflashtool's `rkcrc.h` is
**0x04C10DB7**, the usual 0x04C11DB7 with one digit wrong (a slip every Rockchip
tool inherited). No library CRC-32 variant gives it; the first attempt with the
usual polynomial disagreed with the real `rkcrc -k`, which is how it was found.
Values the real `rkcrc` wrote, now pinned in the suite: empty -> `00000000`,
`123456789` -> `889a9615`, 1000 x 0xFF -> `f45d7ebb`, `bytes(range(256)) * 4` ->
`be63b112`.

Behaviour: the payload goes through the same codec detection as any ramdisk; if
what comes out is a cpio archive (`07070...`, or empty) it is `ramdisk_*` +
`ramdisk.cpio` + the `ramdisk/` tree (several volumes, `.meta`, all of that), else
it is `kernel_*` + `kernel`. Repack goes through `load_component`, so the tree
rules, the raw replay of an untouched file, `<prefix>_level` and the fit-aware
retry all apply. A stored CRC that is not the payload's (a damaged dump) is said
at unpack, kept in the manifest (`krnl_crc`, with `krnl_payload_sha256` of the
payload it belonged to) and written back as long as the payload is the same
bytes, so the round trip stays exact; after an edit the CRC is made right. A dump
of a whole partition keeps its fill (`pad_to`, through the usual envelope). A file
whose header declares more than it holds is refused ("cut short").

Also changed for every format: `do_unpack` removes the output directory when
*this run* made it and the unpack then failed (a refused image no longer leaves an
empty directory behind); a directory that was already there is never removed.

Judged by: the real `rkcrc -k` (compiled from rkflashtool, BSD, not vendored;
`ABR_RKCRC=<path>`; the linux CI jobs compile it with `continue-on-error`, so a
failed clone only skips the comparison) -- every image abr writes (untouched,
edited tree, edited `ramdisk.cpio`, edited kernel) equals `rkcrc -k` of the same
payload -- and by the Python tool, which writes its CRC from the C source's table
construction, not from abr's. No real Rockchip dump has been tried (none supplied);
the format is simple and the CRC verified against the real tool, but a real
`boot.img` from a Rockchip SDK build would be the best next test.

Not done for Rockchip: `rkcrc -p` ("PARM" parameter files), RKFW/RKAF update
images, `rkunpack` of the loader -- stage 2/3 of the user's own spec.

## AMONET (done, 11 Oct 2026)

The patch of Amazon's MediaTek Fire tablets: a 1024-byte microloader at offset 0,
the boot image's first 1024 bytes at offset 1024 (so "ANDROID!" is at 1024), the
rest from 2048 on as it was. What the patch loses is the original [1024, 2048):
the zero padding of the first 2048-byte page behind a v0 header (608 bytes). AIK
takes it off with `dd`/`truncate`/`cat` (zeros back in the lost 1024 bytes) and
puts it on with three `dd`s; abr does the same. Before this, an AMONET image was
read as a boot image behind a 1024-byte "vendor wrapper", with every offset 1024
too far -- it never worked.

Code: `include/abr/legacy/amonet.hpp` + `src/legacy/amonet.cpp` (`has_amonet_patch`,
`strip_amonet`, `apply_amonet`; the detection is `identify`'s rule: "ANDROID!" at
1024 and the word "microloader" behind offset 96), and in `src/main.cpp` a
`Wrappers` layer (`peel_wrappers`) shared by `unpack`, `info` and `repack`: DHTB
comes off first, the patch under it; repack puts the patch on first, DHTB over it.
The manifest has `has_amonet=true` and `amonet_microloader_file=microloader.bin`
(1024 bytes); the same two lines on the unpack of an ordinary v0 image make an
AMONET image. `apply_amonet` refuses what the patch would destroy: anything but
zeros in [1024, 2048) of the repacked image (a v1/v2 header is longer than 1024
bytes; a first page that is not 2048) -- AIK silently corrupts there -- with the
way out in the message (`has_amonet=false`), and a microloader that is not 1024
bytes. A patched file shorter than 2048 bytes is refused ("cut short").

Judged by AIK's literal commands, copied from `unpackimg.sh`/`repackimg.sh` into the
suite (`amo_aik_patch`, `amo_aik_unpatch`): they make the patched fixtures, and the
image abr repacks after an edit equals AIK's patching of the same edit repacked
without the patch (7 checks: sanity of the fixtures + identify/info; unpack and
untouched repack, GNU cpio agreeing with the tree, the same manifest and files as the
unpatched image; edit, -j1 = -j4; the patch put on an ordinary image; refusals; a
partition dump with zero fill; under a DHTB wrapper). The negative control (a binary
without the code) fails all 7. No real Amazon image was tried -- none was supplied.

## BLOB (done, 12 Oct 2026)

ASUS's Tegra blobs (AIK: "ASUS Blob Signature", `blobunpack` / `blobpack` of
AndroidRoot/BlobTools). The layout, from BlobTools' sources (`shared/blob.h`,
`blobpack.cpp`, `blobunpack.cpp`): an optional 28-byte secure header
(`"-SIGNED-BY-SIGNBLOB-"`, `datalen`, `siglen`; all u32 le), then the blob proper:
a 60-byte header (`"MSM-RADIO-UPDATE"`, version 0x00010000, header size 60, table
offset 60, the number of partitions, seven zero words), a 16-byte entry per
partition (name[4], offset counted from the start of the blob proper, size,
version 1), the partitions' data one after the other, and -- in a signed blob --
the signature behind. AIK's way: `blobunpack` for a file that has a single
partition (`mv "$file."* "$file"`; the partition name, its first three characters,
is kept as `blobtype`), and on repack `-SIGNED-BY-SIGNBLOB-` + 8 NULs (`datalen`
and `siglen` 0) in front of `blobpack`'s output.

Code: `include/abr/legacy/blob.hpp` + `src/legacy/blob.cpp` (`BlobImage::looks_like`,
`parse`, `blob_size`, `build`), in `src/main.cpp` `Fmt::BLOB` (`unpack_blob`,
`repack_blob`, `pack_blob`, `save_blob_fields`/`load_blob_fields`, the `info` case)
and a third layer in `Wrappers`: DHTB comes off first, then the blob (when it has
exactly one partition and what is in it is an image `detect_format` knows), then
the amonet patch; repack puts them on in the opposite order. Any other blob --
several partitions, or one partition that is no image -- is a directory of its
own, `type=blob`, `part<i>[_NAME].bin` per partition. `src/identify.cpp` names a
blob without the signing header (`MSM-RADIO-UPDATE blob`; AIK's magic file knows
only the signed one: "BLOB signing"). `tests/tools/blob_tool.py` writes and reads
blobs independently (written from BlobTools' layout, shares nothing with abr).

Manifest: `has_blob=true` (wrapper) or `type=blob`; `blob_secure`,
`blob_secure_datalen`, `blob_secure_siglen`, `blob_version`, `blob_unknown` (only if
one of the seven words is not zero), `blob_parts`, `blob_part<i>_name` (a word of
[0-9A-Za-z_.-]) or `blob_part<i>_name_hex` (four raw bytes), `blob_part<i>_version`,
`blob_size`, `blob_data_sha256`, and `blob_tail_file=blob_tail.bin` (the signature).
Decisions worth knowing:
- Only the layout blobpack writes is read: header size 60, table at 60, the
  partitions contiguous right behind the table. Anything else (including a gap) is
  refused with the reason, because rebuilding it in blobpack's layout would lose
  the difference silently. A blob cut short, a count over 4096 and a SIGNBLOB
  header with no blob behind it are refused too; a failed unpack leaves no directory.
- The signature cannot be made again (ASUS's key). It is kept behind the data.
  `datalen` follows the blob when it equalled the original blob's length (AIK's
  blobs have 0 and keep it); when the contents changed and a signature (siglen
  or a non-zero tail) is kept, `repack` warns that it describes the original.
- Names are kept to four bytes (AIK keeps three); `0x`-style hex names make the
  odd ones round-trip.

Judged by the real BlobTools (compiled in the CI, `ABR_BLOBPACK`/`ABR_BLOBUNPACK`;
the tests skip those checks where they are not set) and by the Python tool: the
signed blob AIK makes (28 bytes + blobpack's output) is what the tool writes and
what abr repacks; an edit equals the tool's and blobpack's output for the plain
repack; blobunpack finds the partitions of what abr wrote; signed (siglen 256,
signature kept, datalen follows, the warning); bare; three partitions with a new
size of the first (offsets move); one non-image partition; odd names/versions;
under amonet and DHTB; refusals. 8 test groups; the suites: g++-14 268/268, clang-20
268/268, Windows under wine 267/267. Negative controls: with fake
oracles (`/bin/false`) the four groups that use them fail, a binary without the
code fails all. mawk (Debian/Ubuntu `awk`) drops `\00` in printf: AIK's own
header line is written with it, abr and the tests do not depend on that. No real
ASUS blob was tried -- none was supplied.

## OSIP (done, 13 Oct 2026)

Intel's boot image for Android devices (AIK: "OSIP", opened with osm0sis' `mboot`,
after Jocelyn Falempe's `mboot.py`; the file header of `mboot.c` is GPL-2.0). The
layout, read from `mboot.c`: an optional 512-byte OSIP header (`"$OS$" 00 00 01`,
a 32-byte header proper and one 24-byte OSII entry), a signature of 0, 480, 728 or
1024 bytes, a 1024-byte cmdline, 3072 bytes of image info (u32 kernel size, u32
ramdisk size, 8 bytes "parameter", then padding: zeros, but `BD 02 BD 02 BD 12 BD 12`
right behind the parameter in a signed image), a bootstub of 4096 (8192 on some
devices) bytes, the kernel, the ramdisk (gzip cpio), and `0xFF` padding up to a
multiple of 512. What mboot's pack keeps up to date in the header: the size in
sectors (offset 48: padded size / 512 - 1), the "unsigned" bit (offset 52: 0 boot
signed, 1 boot unsigned, 0x0C / 0x0D recovery; `|= 1` when there is no
signature) and the XOR checksum (byte 7, over the first 56 bytes, itself counted as
zero). What it guesses when it unpacks: the signature size (the first of the
positions 0, 480, 728, 1024 with four letters/digits where the cmdline starts) and
the bootstub size (8192 if one of the two bytes where a 4096 stub ends is a
letter/digit), and it refuses a kernel under 500000 bytes and a ramdisk under 10000
(the suite's fixtures are 600000 and about 80000).

Code: `include/abr/legacy/osip.hpp` + `src/legacy/osip.cpp` (`OsipImage::looks_like`,
`parse`, `build`, `body_size`; `osip_header_checksum`, `osip_header_checksum_ok`,
`osip_header_sectors`, `osip_header_attribute`, `osip_refresh_header`,
`osip_set_header_checksum`), the OSIP section of `src/main.cpp` (`Fmt::OSIP`,
`unpack_osip`, `repack_osip`, `osip_padding`, `osip_cmdline_block`,
`osip_cmdline_shown`, `osip_payload_sha256`, the `info` case; `detect_format` asks
`OsipImage::looks_like` after KRNL and before the vendor-wrapper search) and
`src/identify.cpp` (only a bootstub found where the layout does not put it is still
refused, `Kind::OSIP_HEADERLESS`). `tests/tools/osip_tool.py` is the independent
tool, written from `mboot.c` (`make` = its pack, `list` / `extract` = its unpack,
`check` = its header rules).

Manifest: `type=osip`; `osip_header_file` + `osip_header_checksum_ok`;
`osip_signature_file` + `osip_signature_size`; `cmdline`; `osip_cmdline_file` (only
when the block is more than the text and NULs, or the text has white space at its
ends or a line break, which `manifest.txt` cannot hold); `osip_parameter` (16 hex
digits); `osip_info_file` (the 3056 bytes behind the parameter, trailing zeros
trimmed, absent when all zero); `bootstub_file`; `kernel_file`; the ramdisk as in a
boot image (`ramdisk_file=ramdisk.cpio`, `ramdisk_compression`, `ramdisk_tree`,
`.abr_raw/ramdisk.cpio.raw`); `osip_body_size`; `osip_payload_sha256`;
`osip_sector_pad` (`0xNN` or `none`); and the envelope keys (partition fill).
Decisions worth knowing:
- mboot's header rules are applied only when the size of the image changed or the
  signature was put in or taken away (the checksum is also redone whenever the
  original's was valid). An image that was not touched comes back as it was, with a
  header whose checksum or sector count was wrong too (`info` says
  `checksum WRONG` / `N sectors (the image has M)`, `unpack` notes it).
- The mark of a signed image behind the parameter goes in with a signature and out
  with it, as mboot's pack does; the rest of the image info is carried as it is
  (mboot's pack would zero it).
- A signature cannot be made again (Intel's key). A kept one after an edit is
  said at `repack` ("describes the ORIGINAL contents": the SHA-256 over cmdline,
  parameter, info, bootstub, kernel and ramdisk is what is compared); a signature that
  was not there before is not called stale, but a note says when the header still
  reads "unsigned" (mboot keeps it as it is: the type comes with the `hdr` file, here
  `osip_header.bin`). To take a signature off: delete `osip_signature_file=` from the
  manifest.
- The layout: mboot's guess first; another layout replaces it only if it fits the
  file, has a non-zero kernel and a ramdisk that starts like one (a codec is
  detected, or `07070`). An earlier version took any layout that fitted: a
  truncated image was then "read" as another layout with kernel 0 and ramdisk 0 and
  unpacked without a word. Found with a cut image by hand, now refused ("cut short
  ...", with the sizes the image info declares) and a test. The cases where mboot's
  guess is wrong (a cmdline that starts with a space makes mboot take a signature of
  1024 bytes; a signature that starts with four letters makes it take none) are read
  right and tested.
- A cmdline with a leading/trailing space or a line break is kept exactly:
  `manifest.txt` trims values, so the 1024-byte block becomes `osip_cmdline.bin` and
  is used as long as the text in the manifest is what it was. (Found with the
  leading-space image above; the self-check at the end of `unpack` had said so.)
- Headerless signed images: mboot cannot take them apart (a first byte that is not a
  letter is "an OSIP header" to it), so only the independent tool judges them; abr
  finds the layout from the bootstub magic and the sizes.
- The sector padding (one byte, `0xFF` where mboot wrote it) belongs to the image;
  what is behind it is the partition's fill (the common envelope). An edit that
  outgrows the partition is built and warned about, as for every format.
- An uncompressed ramdisk, one that is no cpio, and an empty one round-trip (checked
  by hand; mboot itself refuses a ramdisk under 10000 bytes).

Judged by the real `mboot` (`ABR_MBOOT`; the CI compiles it from
https://github.com/osm0sis/mboot; the checks that need it are skipped where it is
not set) and by the Python tool. 9 test groups: seven kinds of image (unsigned,
signed 480 / 728 / 1024, bootstub 4096 and 8192, headerless) - the tool packs what
mboot packs, the header is what mboot makes it, identify and info, the pieces are
those `mboot -u` writes, an untouched repack is identical; the same seven edited
(files in `ramdisk/`): sectors, unsigned bit, checksum, a fixed point of mboot,
the stale signature; headerless signed images; the signature taken away / put in
(equal to what mboot packs of the same pieces); a partition with a `0xFF` / `0x00`
fill, and an edit that outgrows it; the cmdline (leading space, line break, edit,
1025 bytes refused); headers with a wrong checksum / sector count; mboot's wrong
guesses; refusals (cut short, a bare header, bootstub / signature / parameter /
info / header that do not fit). The suites: g++-14 277/277, clang-20 277/277,
Windows under wine 276/276 (268 / 268 / 267 before). Negative controls: with an
oracle that always fails (`/bin/false`) or that packs one byte wrong, the four
groups that use mboot fail (and only those); six mutations of the code (sector
count off by one, no unsigned bit, a checksum that counts its own byte, no mark of
a signed image, only mboot's guess, zero padding) each fail the groups they should.
No real Intel image was tried -- none was supplied.

## LOKI (done, 14 Oct 2026)

Dan Rosenberg's `loki` (BSD-2-Clause, https://github.com/djrbliss/loki). `loki_tool patch` turns a plain boot or
recovery image and the `aboot.img` of the phone into an image whose signature the bootloader's check does not
reject; AIK takes the patch off with `loki_tool unlok` and asks for the `aboot.img` again when it repacks. The
layout, read from `loki.h`, `loki_patch.c` and `loki_unlok.c`:

- the header page of the plain image (version 0 header; `loki_tool patch` drops a second stage) with
  `kernel_size` = padded kernel + ramdisk size, `ramdisk_size` = 0 (one page for the targets whose table entry says
  `lg`) and `ramdisk_addr` = `check_sigs & ~0xf` (the bootloader's signature check, rounded down to 16 bytes);
- the LOKI header at byte 0x400, inside the extra command line (148 bytes): `"LOKI"`, u32 type (0 boot, 1
  recovery), `char build[128]` (the target's build), u32 original kernel size, u32 original ramdisk size, u32
  ramdisk address (`kernel_addr` + padded kernel);
- the padded kernel and ramdisk, as they were;
- a block of 0x200 bytes (a page for `lg` targets) of the `aboot.img` from `check_sigs & ~0xf`, with 65 bytes
  written over it at offset `check_sigs & 0xf` (0, 4, 8 or 12 in the table): 56 bytes of Thumb code, u32 an address
  of the bootloader (the target's `hdr`), u32 the ORIGINAL `ramdisk_addr`, a NUL;
- the device tree, `dt_size` bytes, not padded (word 10 of a version 0 header above 8 is the CAF device-tree size).

What `loki_tool unlok` writes is [header page, padded kernel, padded ramdisk, device tree]; the size of the block it
skips it guesses from the address (`ramdisk_addr > 0x88f00000 || < 0xfa00000` = a page, else 0x200), which is wrong
for the table's `0x4010fe18` entry (a page-size block at an address the guess takes for 512 bytes).

Code: `include/abr/legacy/loki.hpp` + `src/legacy/loki.cpp` (`has_loki_header`, `strip_loki`, `apply_loki`, `LokiInfo`),
the LOKI part of `src/main.cpp` (`Wrappers::loki`, `loki_build_text`, `save_loki_fields`, `load_loki_fields`,
`apply_loki_wrapper`, the `info` line, `has_loki` in `build_image_once` / `do_unpack`). The wrapper comes off after
DHTB and the blob and before AMONET, and goes on in the opposite order. Its own tail (data, or fill up to the size
of the partition) is an `Envelope` like the other wrappers'. `tests/tools/loki_tool.py` is the independent tool,
written from the layout: `aboot` makes a synthetic bootloader image (random bytes, one of loki's patterns at the
address of a table entry, the base address at byte 12 -- all that `loki_tool patch` reads), `patch` = its writer,
`unlok` / `list` / `check` = its readers (six synthetic targets: the patch code 0, 4, 8 and 12 bytes into a block of
512 bytes or of a page).

Manifest: `has_loki=true`, `loki_recovery`, `loki_build` (text; `loki_build_hex` for a field that is no text, has a
space at its end or no NUL), `loki_patched_ramdisk_addr`, `loki_patched_ramdisk_size`, `loki_hdr_ramdisk_addr` (only
when it is not `kernel_addr` + padded kernel), `loki_block_file=loki_block.bin`, `loki_shellcode_offset`, the tail
as `loki_tail_file` or `loki_pad_byte` + `loki_pad_to`; the rest of the directory is the plain image's.
Decisions worth knowing:
- **No `aboot.img` on repack.** The block is a copy of the bootloader's code taken from the image; carrying it makes
  an untouched image byte-identical and an edited one what `loki_tool patch` makes of the same plain image with the
  same `aboot.img` (only the original ramdisk address inside the patch code follows the plain header; kernel_size, the
  padded header fields and the LOKI header follow it as well). Verified against the real tool.
- **`loki patch` itself is not in abr** (the pattern search in an `aboot.img` and loki's table of about forty
  targets). Only the 56 bytes of patch code are copied from loki (BSD-2-Clause, notice kept in `src/legacy/loki.cpp`
  and named in the README). Patching an image for a bootloader that no LOKI image was unpacked from would take that
  table; it can be added later as `--loki-aboot`, if wanted.
- The size of the block is read from the header (`ramdisk_size` 0 = 0x200, = page size = a page), not guessed from
  the address like `unlok` does. The suite compares abr with the real `unlok` for every target but the one where it
  guesses wrong (the independent tool and abr agree there).
- The patch code is searched in the first 16 bytes of the block, like `unlok`; any offset 0..15 is read (the tool
  writes only 0, 4, 8, 12).
- Refused, with the reason, leaving no directory: a second stage, a header of version 1+, an implausible page size,
  a kernel size that is not padded kernel + original ramdisk of the LOKI header, a ramdisk size that is neither 0
  nor a page, no patch code in the window, a cut-short image. On repack: a block that cannot hold the patch code
  at `loki_shellcode_offset`, a build of 128 characters or more, a missing field, a command line of 929+ characters
  (the LOKI header overwrites the end of the extra command line), data behind the device tree; each names
  `has_loki=false` as the way out.
- A plain image with non-zero page padding is flagged by the self-check as for every boot image (abr does not keep
  such padding); LOKI does not change that.
- Found while testing: the general builder lost data when the last component of a dump whose final page padding is
  missing grew (what `unlok` writes is such a dump: the device tree is not padded) -- see "The last component of a
  trimmed dump, edited".

Judged by the real `loki_tool` (`ABR_LOKI_TOOL`; the CI compiles it from https://github.com/djrbliss/loki; the checks
that need it are skipped where it is not set) and by the Python tool. 9 test groups: fourteen kinds of image (six
targets, boot and recovery, with and without a device tree, pages of 2048 and 4096, whole-page sizes, a cmdline that
reaches into the extra one) -- both tools make the same bytes, the independent reader finds the image is
`loki_tool`'s patch of the plain one, identify and info, the directory is the plain image's plus the patch, without
the patch it builds what `unlok` writes, an untouched repack is identical; the same fourteen edited (ramdisk files,
or kernel bytes where the ramdisk is no archive): the result is the patch of what the directory builds without it,
the real tool makes the same bytes, the block and the rest stay, a fixed point; header edits (load addresses,
cmdline, name, a bigger kernel); a device tree that grows, shrinks or is whole pages long; tails (data, `0xFF` and
`0x00` fill to 1 MiB, an edit that outgrows the partition); fields that are not loki's (another type, a build that is
no text, another load address, data in the header page, the code at the ends of its window); manifest edits (type,
build of 127 and 128 characters, offsets, a short block, a missing field, a command line that runs into the LOKI
header or ends just before it); the patch under a blob and DHTB; refusals. The suites: g++-14 295/295, clang-20
295/295, Windows under wine 294/294 (286 / 286 / 285 before). Negative controls: with an oracle that lies (copies the
plain image for `patch` and the LOKI image for `unlok`) the five groups that use the real tool fail (and only those);
eighteen mutations of the code (no original ramdisk address in the patch code, kernel_size without the ramdisk, the
load address off by one, a page block read as 512 bytes, a window of 8 bytes, the LOKI header left in the plain
image, a device tree that loses a byte, no check of the LOKI header area, a build with a space kept as text, an odd
load address not kept, the tail dropped, a second stage accepted, the kernel size not checked, the patched ramdisk
address, the type, the shellcode offset, a build without NUL as text, a page block of a fixed 2048) each fail the
groups they should -- all but one: leaving the LOKI header in the plain image changes nothing anyone reads (the
generic parser reads the command line only up to its NUL), so that mutant is equivalent. None of the 14 real images
supplied has a LOKI header: no real LOKI image has been tried.

## ChromeOS kernel blobs (done, 16-17 Oct 2026)

The kernel partition of a Chromebook holds a *vboot* blob; Android Image Kitchen opens it with `futility vbutil_kernel
--get-vmlinuz` and builds it again with `futility vbutil_kernel --pack image-new.img --keyblock kernel.keyblock
--signprivate kernel_data_key.vbprivk --version 1 --vmlinuz unsigned-new.img --bootloader empty --config empty --arch arm
--flags 0x1` (the public developer keys of vboot_reference). The format is vboot_reference's (`2struct.h`,
`cmd_vbutil_kernel.c`; BSD-3-Clause), read from its sources and from the output of the real `futility`:

- the **keyblock**: `"CHROMEOS"`, version 2.x, its size (u64 at byte 16), a signature and a checksum of its own, flags,
  the data key (a descriptor at byte 80: offset, size, algorithm, version; the key packed as u32 `arrsize`, u32 `n0inv`,
  the modulus and `rr`, little endian). abr keeps it as it is;
- the **preamble**: `preamble_size`, the signature descriptor of the preamble (byte 8), the header version (2.0, 2.1,
  2.2), the kernel version, the load address of the body, the address and the size of the bootloader, the signature
  descriptor of the body (byte 72), for 2.1 and 2.2 the vmlinuz header address and size, for 2.2 the flags: 96, 112 or
  116 bytes; behind it the body signature, the preamble signature and zeros up to `preamble_size`;
- the keyblock and the preamble together are the verification block, **64 KiB** unless `--pad` says otherwise;
- the **body**: the kernel (aligned to 4096), the config (4096 bytes: the command line, NUL-terminated), the params
  (4096 bytes: the boot parameters of x86, zeros on ARM) and the bootloader (its size is in the preamble, a multiple
  of 4096).

Both signatures are RSA PKCS#1 v1.5 with the *data key* of the keyblock: the body's over the whole body, the preamble's
over the preamble header and the body signature. The algorithm number is vboot's: `id / 3` is the key size (1024, 2048,
4096, 8192 bits), `id % 3` the hash (SHA-1, SHA-256, SHA-512); 12 to 14 are 2048 bits with the exponent 3, 15 to 17 are
3072 bits with the exponent 3.

Code: `include/abr/legacy/chromeos.hpp` + `src/legacy/chromeos.cpp` (`has_chromeos_header`, `strip_chromeos`,
`apply_chromeos`, `ChromeosInfo`, `ChromeosSigning`, `parse_vbprivk`, `keyblock_data_key`, `chromeos_algorithm`);
`src/legacy/chromeos_devkeys.cpp` (the developer keyblock and `kernel_data_key.vbprivk` of vboot_reference as arrays,
generated by `tools/gen_chromeos_devkeys.py`, BSD-3-Clause notice in the file; the suite checks them byte for byte against
the installed `vboot-kernel-utils`); the ChromeOS part of `src/main.cpp` (`Wrappers::chromeos`, `save_chromeos_fields`,
`load_chromeos_fields`, `apply_chromeos_wrapper`, `unpack_chromeos` / `repack_chromeos`, `chromeos_description`,
`--chromeos-key` / `--chromeos-keyblock`, `has_chromeos` in `build_image_once` / `do_unpack`). The wrapper is the
outermost one: it comes off first (before DHTB, BLOB, LOKI, AMONET) and goes on last. `tests/tools/chromeos_tool.py` is
the independent tool, written from the layout (its RSA is Python's own integers): `make`, `keyblock`, `vbprivk`,
`dump`, `verify`, `kernel`, `field`, `algorithms` and `corrupt` (twenty-seven ways to damage a blob).

What is the plain image and what stays: the **kernel field of the body** is the plain image (what `--get-vmlinuz`
writes, with the zeros up to the 4096 boundary), unpacked as every other image; a boot image (or whatever abr unpacks,
DHTB header and all) in it makes the blob a wrapper layer, `has_chromeos=true`, and the directory is the image's.
Anything else is a container of its own (`type=chromeos`, the kernel is `chromeos_kernel.bin`). The rest is the manifest's:
`chromeos_keyblock_file=chromeos_keyblock.bin`, `chromeos_preamble_version` (2.0 / 2.1 / 2.2),
`chromeos_kernel_version`, `chromeos_flags` (2.2), `chromeos_body_load_address`, `chromeos_bootloader_address` (only
when it is not the load address + kernel + config + params, which is what futility writes), `chromeos_bootloader_size`,
`chromeos_vmlinuz_header_address` (2.1 and 2.2, when not 0), `chromeos_vblock_size`, `chromeos_config_file`
(`chromeos_config.txt`: the command line), `chromeos_params_file`, `chromeos_bootloader_file` (the last two without the
zeros that fill their fields), `chromeos_body_signature_file`, `chromeos_preamble_signature_file`,
`chromeos_signed_sha256`, and what follows the blob as `chromeos_tail_file` or `chromeos_pad_byte` + `chromeos_pad_to`.

Decisions worth knowing:
- **The signatures are kept while nothing they cover has changed, and made again when something has.**
  `chromeos_signed_sha256` is the SHA-256 of what the signatures cover (the keyblock, the preamble header with the
  body signature, the body). At repack the keyblock, the header and the body are built from the manifest and the
  directory; if that hash is the same, the signatures of the original go back in. So a blob that went through an unpack
  and a repack comes back byte for byte whoever signed it (a foreign keyblock, bad signatures, an algorithm abr does not
  know), and an edited one never keeps a signature that no longer fits.
- **Whom the blob is signed by.** abr has one private key: the public developer data key of vboot_reference. When the
  keyblock of the blob holds that key (the keyblock is the developer one, or another that carries the same data key) the
  signatures are made with it. `--chromeos-key <.vbprivk>` signs with a key of one's own, which must be the data key of
  the keyblock (checked: the algorithm and the modulus; the error says how to give the keyblock made for the key).
  `--chromeos-keyblock <.keyblock>` puts another keyblock in (checked: starts with `"CHROMEOS"`, its size word is the
  file's size, its data key can be read); abr **never signs under a keyblock it has no key for** (error, naming
  `--chromeos-key`).
- **A keyblock that is somebody else's** and no key of it given: an edit signs the blob with the developer key under the
  developer keyblock of vboot_reference, with a warning -- this is what AIK does (it replaces the keyblock every
  time). A Chromebook in developer mode boots such a blob; one that checks the keyblock against its own keys does not.
  Untouched blobs keep their keyblock.
- The keyblock is opaque: its own signature (or checksum) is neither checked nor made. `futility vbutil_keyblock` makes
  one; `--chromeos-keyblock` takes it.
- A plain image whose manifest gets `has_chromeos=true` (no keyblock in the directory) becomes the blob AIK's line makes:
  the developer keyblock and key, preamble 2.2 with version 1 and flags 0x1, a config and a bootloader of **one space**
  each. (futility refuses a zero-byte file for either; what AIK's `empty` file holds could not be looked up -- the
  repository was not reachable from here -- so one space is the choice. The suite compares abr with `futility --pack` of the
  same one-space files, byte for byte.) `has_chromeos=false` leaves the blob out: the plain image comes out.
- **x86 is refused**: a preamble with a vmlinuz header (size not 0) holds a bzImage no Android tool opens (`info` says so,
  `unpack` leaves no directory). So is any blob that is not laid out the way futility writes it, with the reason:
  cut short at the keyblock, the preamble or the body, a keyblock of version 3 or a size below its header, a preamble
  of version 3.2 or 2.3, reserved words that are not zero (in the preamble or in a signature descriptor), signatures
  anywhere but where futility puts them, an empty signature, data of its own behind the signatures, a bootloader or kernel
  that is not a multiple of 4096, a body too small for its fields. Nothing is ever read wrongly.
- On repack: a kernel that is empty, a preamble version that abr does not make, flags without a 2.2 preamble or a vmlinuz
  header address without 2.1, a verification block too small for the keyblock and the signatures, a config over 4096
  bytes or params over 4096 are refused with the reason (and `has_chromeos=false` as the way out).
- A uniform-byte tail behind the blob (zeros up to the size of the partition) is a fill, made again at repack
  (`chromeos_pad_byte`, `chromeos_pad_to`; an edit that outgrows the partition is refused as for every image); any
  other tail is the file `chromeos_tail.bin`.
- The chain is ChromeOS -> DHTB -> BLOB -> LOKI -> AMONET (`peel_wrappers`, one layer inside the other, put back in the
  opposite order). The blob is a wrapper only when its kernel field is something abr unpacks; otherwise it is the container.

Judged by the Python tool and, where it is installed (`ABR_FUTILITY`, else `futility` on the `PATH`; the CI installs
`vboot-kernel-utils`, where the suite prints which of the two it used), by the real `futility`. 16 test groups: the
developer keyblock and key abr embeds are the ones the package ships; nine kinds of blob (preambles 2.0 / 2.1 / 2.2,
RSA 1024 to 4096, exponent 65537 and 3, SHA-1 / 256 / 512, a kernel that needs padding and one that does not) made by the
tool -- `futility --verify` accepts them, `abr info` says what they are, unpacked and repacked untouched they are
identical; the same edited (ramdisk files) -- the blob is the tool's of what the directory builds without the blob, the
signatures are good, futility verifies it; every field of the manifest changed, one at a time and together; a partition
dump (the blob, zeros up to the size of the partition); `has_chromeos=false` and `=true` (the blob AIK's `futility --pack`
line makes, and the same under another keyblock); the version of the preamble and the vmlinuz header address; what the
manifest cannot say; a blob under somebody else's keyblock (kept, then signed under the developer keyblock with a warning,
or with the key given); keys that are not the keyblock's, keyblocks without a key, files that are no keys, no keyblocks;
twenty-one layouts that futility does not write, refused; signatures that are bad (kept by an untouched repack, good after
an edit); `futility --pack` and `futility --repack` make the same blobs as abr (the command line, a bootloader, the
version, the flags, the load address and the verification block; the developer and foreign keys; edited images);
a blob around a DHTB header; a blob of a kernel abr does not unpack (a container). With `ABR_REAL_IMAGES` every
real image supplied is wrapped in a blob by the tool and round-trips (13 of 14 unpack; the other is ext4).
The suites: g++-14 311/311, clang-20 311/311, Windows under wine 310/310 (295 / 295 / 294 before).
Negative controls: twenty-six mutations of the code (the hash taken by the wrong index; the modulus of the data key not reversed; signatures never kept; signatures always kept; the default bootloader address without the params; the kernel aligned to 2048; the flags not written; a verification block of the preamble's size only; an x86 blob accepted; data behind the signatures accepted; the reserved words of a signature descriptor ignored; a swap to the developer keyblock that keeps the foreign one; the fields not trimmed; the tail boundary off by one; the preamble signature over the header only; the body signature over the kernel only; the data size of the preamble signature not checked; the bootloader alignment not checked; the keyblock left out of the hash that decides whether signatures are kept; the developer data key never recognised; flags 0 for a fresh blob; a key given that is not checked against the keyblock; a keyblock without its key accepted; the keyblock version not checked; the signatures never verified; the size of a keyblock given not checked) each fail at least one group, ten of them exactly one, the group made for the case; none survives.

Not done, and not claimed: **no real Chromebook partition has been tried** (none at hand; the blobs in the suite hold Android
boot images and random bytes); the 8192-bit algorithms (9 to 11) are in the code and not in the tests; the keyblock's own
signature is not checked; x86 blobs are refused; a FIT image as the kernel field (abr does not read FIT yet) is read as one device-tree blob (the whole FIT, `blob0.dtb`) and round-trips byte for byte; the kernel and the device trees inside it are not taken apart.

## Windows: the command line in UTF-8 (done, 17 Oct 2026)

Looked for what the first Windows user with a Cyrillic folder would hit, and found it. A small program built with the
same toolchain (mingw-w64's libstdc++), run under wine with a UTF-8 locale, showed two things:
- the C runtime's `argv` is lossy: every character outside the ANSI code page (1252 under wine) is a `?` (0x3f) and `ü`
  is a lone 0xfc byte, so `abr.exe unpack загрузка.img` looked for a file named `????????.img`. The wide command line
  (`GetCommandLineW` + `CommandLineToArgvW`) has every character, an emoji as a surrogate pair;
- libstdc++'s `std::filesystem::path` reads a narrow string as UTF-8 and `string()` gives UTF-8 back (`fs::path` of the
  UTF-8 bytes held the right wide characters; the `?`-ridden narrow `argv` threw "Cannot convert character sequence"),
  so none of the two dozen `path.string()` / `dir / name` places needed a change: the entry point was all that was wrong.

What changed: `command_line_utf8(argc, argv)` (`src/byte_io.cpp`) returns the UTF-8 of the wide command line on Windows
(argv as it is elsewhere, and where the number of words does not match), `Utf8Console` switches the output code page of a
console to UTF-8 while abr runs (when stdout or stderr is a console; it is put back at the end; a pipe or a file gets the
bytes as they are), and `main` uses both. The `.exe` imports `SHELL32.dll` for `CommandLineToArgvW` now, besides
`KERNEL32.dll` and `msvcrt.dll` (the CI's check of the imports lists it among the system DLLs it accepts).

Tests: one group, "paths that are not ASCII": Cyrillic, an accent, Chinese and an emoji in the names of the image, of the
directory it is unpacked to, of the file it is packed to and of a file the manifest names; unpack, repack (identical),
info, identify, and no file under a `?` name is left behind. The wine wrapper of the suite sets `LC_ALL=C.UTF-8` now (wine
decodes its Unix command line with the locale; in the C locale the characters arrive as garbage). Negative control: with
`main` reading `argv` as before, exactly this group fails under wine (310 pass, 1 fails). The suites: g++-14 312/312,
clang-20 312/312, Windows under wine 311/311.

Not done: paths over 260 characters (Windows wants `\\?\` or a manifest for them; an unpack directory deep in a tree
could meet that); the console part cannot be exercised under wine (it has no console); a name that is not valid Unicode
(a lone surrogate, which NTFS allows) arrives with the replacement character.

## Sony SIN containers (done, 17-18 Oct 2026)

What Android Image Kitchen does (`unpackimg.sh`): a file whose signature is `SIN*` goes through `sony_dump . "$img"`, the result is
renamed to the image and `rm -f "$file-sigtype"` forgets that there was a container -- `repackimg.sh` then writes the plain image.
abr does the same without the program: the container is the first wrapper layer to come off (`peel_wrappers`: SIN -> ChromeOS ->
DHTB -> blob -> LOKI -> AMONET), it is **never put back** (header, hash tables and signature are Sony's; nothing here could make
them for an edited image), the unpack says so, and the self-check is about the image inside. A container whose content is not a
boot-family image (a `system.sin`, a SIN in a SIN), a content above 512 MiB or a damaged container is not a wrapper: `unpack` refuses
it, and the message says what it is (or what is wrong), with no directory left behind.

Source of the layout: the user's link, `munjeni/anyxperia_dumper`'s `sony_dump.c` (no licence file: nothing of it is in abr or in the
repository, the layout is described in `include/abr/legacy/sin.hpp`; the test suite runs the program, compiled from its source by
whoever runs the suite, as an oracle: `ABR_SONY_DUMP`). It is **v1, v2 and v3**: v1 and v2 (`01 00 00 00`, `02 00 00 00`) differ
only in the first byte, the header is the size at byte 2 plus 16, v3 (`"\x03SIN"`) has the size of the header at byte 4 and the size of the
data at 0x18. Behind the header: an MMCF block (`ADDR` parts as they are, `LZ4A` parts as raw LZ4 blocks, put one behind the other
with 0xFF in the gaps; a part that starts before the end of what there is goes to the end, as `sony_dump` does, and the unpack says
so), a loader (an ELF; the image behind it), or the image itself, possibly with data in front of it (v3). There is no SIN v4 / v5 in AIK's
magic file (and the user found no documentation of the format on the Internet either), so nothing is done for them. Where `sony_dump` reads
uninitialised memory or does not stop (an entry shorter than its own fields, a part outside the file, an LZ4 block that does not decode
to the size its entry says) abr refuses with the reason. What abr leaves out of `sony_dump`: the padding of a partition image to the size of
the ext4 file system it finds (partition images are not in scope; the test payloads have no `53 EF` at byte 1080 so that
`sony_dump` does not take them for one).

`LZ4A` parts are decoded on several threads (`par::for_each`) when there are two or more and the image is 16 MiB or more; the result is
the same for one thread (tested with two parts of 9 MiB each, 1 thread against 4).

Tests: `tests/tools/sin_tool.py` (written from the layout, no code of abr) makes the catalogue (v1/v2/v3, the image behind the header, a
loader, data in front, MMCF with ADDR and LZ4A parts, gaps, a part put at the end, longer entries, 60 parts, 18 MiB, damaged ones of
every kind) and `sony_dump` converts the same files to the same images; the suite also wraps every real image of `ABR_REAL_IMAGES` as
v3 and as v1 (LZ4A) and compares; `abr_unit_tests legacy` (`tests/unit/legacy_test.cpp`) holds the unit checks, the thread
comparison and 40,000 mutated containers. Mutation testing of the reader (79 mutants of `sin.cpp` and `elf_boot.cpp` in the first round)
found two weak checks (an error message that another error also satisfied; a damage test that did not cover a duplicate with every
other kind) and both are fixed; two mutants are equivalent. **No real `.sin` file was at hand**: the containers are made by the tool
from the layout of `sony_dump`, the confirmation of the real world is missing.

## Sony ELF boot images (reworked, 18-19 Oct 2026)

The first version wrote only elftool's layout. An image laid out otherwise was unpacked, and its repack was a different file (the
round-trip check said so). The second version keeps what is around the segments:

- `ElfBootImage` (`include/abr/legacy/elf_boot.hpp`, `src/legacy/elf_boot.cpp`): segments with role, flags, address and data;
  `parse()` records a `layout` (the block in front of the data, the order of the data, the bytes behind each segment) only when
  elftool's layout does not give the file back **and** the kept layout does; `build()` writes elftool's layout, or puts the segments
  into the kept one, patching `p_flags`, `p_vaddr`, `p_paddr` (only if it followed `p_vaddr`), `p_filesz`, `p_memsz` (follows `p_filesz` only
  if it did, else never below it), `p_offset`, `e_machine` and `e_entry` (follows the first address unless the image has its own).
  A segment that was empty keeps its `p_offset` -- moved along with the data it was behind -- and may not gain data (that has no
  place in the layout: the repack says so and writes elftool's layout). ELF32 addresses that do not fit are refused.
- Roles: by `p_flags` (ramdisk `0x80000000`, ipl `0x40000000`, rpm `0x01000000`, cmdline `0x20000000`); unflagged segments by position:
  the first is the kernel, then the ramdisk (unless a flagged one exists: fixed this round, the old code named a second "ramdisk"),
  then `extraN`. The ramdisk is a directory like everywhere. A segment with no data is no file.
- ELF64: read, and written in the layout elftool would have with 56-byte program headers and the ELF64 header (data from byte 4096). That
  is **abr's own generalisation**: elftool does ELF32 only, no real 64-bit image or tool is at hand.
- Manifest: `type=elf_boot`, `is_64bit`, `machine`, `elf_entry` (when not the first address), `segment_count`, `segmentN_role/_flags/_addr/_prefix`,
  `elf_layout=kept` with `elf_layout_order`, `elf_layout_sizes` and `.abr_raw/elf_layout.bin`; a manifest without them is elftool's layout.

Findings about the oracle (the real `elftool`, osm0sis's, compiled from its sources, not vendored): `pack` needs a header file and cannot
make an image of one part or an ELF64 file; `unpack` has no `break` after `case p_flags_rpm` (the rpm segment is written to the file
`ramdisk`, over the ramdisk if that comes first) and reads `p_memsz` bytes. The suite uses it for what it can do (images in elftool's layout
with the parts it handles; `ABR_ELFTOOL`).

Differences from AIK: AIK's magic file calls an ELF a boot image only when its OS/ABI byte is 0x61 (and `unpackimg.sh` says "Unrecognized
format." otherwise); abr opens it all the same, `identify` says "ELF (ARM)" as `file` does. AIK repacks an ELF image that has no `rpm`
segment as an **AOSP** image ("ELF format without RPM detected; will be repacked using AOSP format!"); abr writes the ELF it unpacked.

Tests: `tests/tools/elf_tool.py` (independent writer/reader/oracle driver, 16 layouts: elftool3, elftool5, kernel_only, ramdisk_empty,
unflagged3, elf64, start8k, tight, pads_tail, entry_abi, order, hdr_fill, paddr, phoff, empty_kept, elf64_all), the CLI section of
`tests/run_tests.sh` (unpack, what the independent reader finds, the ramdisk directory and GNU cpio, an untouched repack, an edited
kernel, an edited ramdisk directory and another address against the independent writer, the elftool oracle, addresses beyond 32 bits, damaged layouts that
fall back to elftool's), and `abr_unit_tests legacy` (an independent C++ writer with every layout knob, 9-10 kept layouts x 6 edits, a
segment without data in 13 positions x 5 edits for each class, fallbacks, 40,000 mutated images; also clean under ASAN/UBSAN). Unit-level mutation testing of `elf_boot.cpp`
killed every mutant but the equivalent ones (the 13 mutants of the code that moves an empty segment's offset included). **No real
`kernel.elf` was at hand**: what is judged is the layout elftool writes and what an ELF can be.

## Next steps (in order)

1. Remaining AIK parity: QCDT creation (Sony SIN and the ELF layouts are
   done). The stages 2 and 3 of the user's own spec need a scope
   decision before anything is built.
2. Housekeeping: AIK-like default levels as an opt-in, gzip OS-byte
   determinism, `zlib-ng` for faster gzip, splitting `main.cpp`.
3. Run the CI matrix on every push (the workflow only runs on `main`, pull
   requests and manual dispatch: dispatch it with
   `gh api -X POST repos/<repo>/actions/workflows/build.yml/dispatches -f ref=<branch>`).

CI status of the branch: run 39020243483 (commit `750530f`, ChromeOS kernel blobs) green on all five jobs
(linux g++-14 and clang-20, Windows under wine, arm64 under qemu-user, android-arm64); the earlier runs 38652019847
(`ccf6c3c`, LOKI), 38360970941 (`786c44a`) and 37254228679 (`5d04345`) are green as well.

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
  and Qualcomm **ELF** loaders -- CPIO is done for newc/crc (odc and binary
  are kept as files, see below); the others are not in abr yet (abr's ELF is
  the Sony boot-image ELF). Stage 2/3 (Rockchip, Amlogic upgrade packages, MediaTek
  logo/md1img, Tegra BLOB/BCT, Samsung tar.md5, sparse) is a different and
  much larger scope than "the boot-image family"; some of it already has a
  sibling tool in the suite (`tar_repacker`, `md1img_repacker`). Needs the
  user's decision before any of it is started here.

### Updated roadmap (next first)

1. ~~**AVBv1 BootSignature**~~ -- **done** (detect, verify, re-sign with the
   AOSP test key or `--avb1-key/--avb1-cert`; self-contained RSA).
2. ~~**CPIO ramdisk as a directory tree**~~ -- **done** for newc and crc
   (see "The ramdisk as a directory"); odc and binary archives stay files.
3. Remaining AIK parity: QCDT creation (SIN, PXA, KRNL/RKCRC, AMONET, BLOB,
   OSIP, LOKI, NOOK, ChromeOS are done).
4. Spec stage 1 leftovers: MBN, FIT/ITB. Spec stages 2/3: scope decision.
5. Housekeeping: CI should run the quirk suite; `main.cpp` is ~1200 lines
   and should be split per format.
