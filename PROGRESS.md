# Progress log

This file exists so work can resume from a clean session without
re-deriving anything. Read this file first. Update it after every
meaningful step (what changed, what's next) -- treat it as the
single source of truth for project status, not a changelog nobody reads.

## Goal

C++20 unpacker/repacker ("abr" = Android Boot Repack) for the Android
boot-family image formats, requested formats and current status:

| Family | Files it covers | Status |
|---|---|---|
| boot (header v0-v4) | boot.img, init_boot.img, boot-debug.img, boot-test-harness.img, recovery.img, recovery-two-step.img | **done** (`boot_image.{hpp,cpp}`) |
| vendor_boot (header v3-v4) | vendor_boot.img, vendor_boot-debug.img, vendor_kernel_boot.img | **done** (`vendor_boot.{hpp,cpp}`) |
| dtbo | dtbo.img (+ ACPIO variant) | **done** (`dtbo.{hpp,cpp}`) |
| dtb | raw/concatenated FDT blobs | **done** (`dtb.{hpp,cpp}`) |
| vbmeta (AVB) | vbmeta.img, vbmeta_system.img, + AVB footers on other partitions | **done**, RSA re-signing needs OpenSSL (`vbmeta.{hpp,cpp}`) |
| uboot | U-Boot legacy uImage (mkimage format) | **done** (`uimage.{hpp,cpp}`) |
| compression | gzip, lz4, lz4-legacy, zstd, xz, lzma(alone), bzip2 | **done** (`compression.{hpp,cpp}`) |
| manifest (unpack/repack glue) | key=value sidecar + component files | TODO |
| CLI (`abr` binary: info/unpack/repack) | `main.cpp` | TODO |
| Bundled SHA-1/256/512 (no-OpenSSL fallback) | needed so Windows/Android static builds don't require cross-built OpenSSL | TODO |
| CMake: static linking + cross toolchains | Linux native done ad hoc; need mingw-w64 (Windows) + Android NDK toolchain files | TODO |
| GitHub Actions: static build matrix (linux-x86_64, windows-x86_64, android-arm64) | not started | TODO |
| Local build test (native Linux) | not yet run against the finished CLI | TODO |
| Round-trip tests (synthetic images) | not yet written | TODO |

## Key design decisions (so nobody re-litigates them)

- One parser per *container format*, not per file name: e.g. `BootImage`
  handles boot.img/init_boot.img/boot-debug.img/boot-test-harness.img/
  recovery.img/recovery-two-step.img identically, because AOSP's own
  mkbootimg treats them as the same header-v0..v4 container with
  different build-time contents (init_boot.img is literally a v4 image
  with kernel_size==0). Verified straight from AOSP mkbootimg.py
  (`--kernel` is an optional argparse arg).
- `vendor_kernel_boot.img` uses the *same* vendor_boot header v3/v4
  struct as `vendor_boot.img` (Pixel 7+ just split one logical partition
  into two files of the same format) -- confirmed via
  cfig/Android_boot_image_editor's layout.md and AOSP partition docs.
  No separate parser needed/written.
- Endianness is format-specific and was individually verified against
  primary sources (not assumed):
  - boot / vendor_boot headers -> **little-endian** (AOSP bootimg.h)
  - AVB vbmeta header/footer/descriptors -> **big-endian** (libavb headers use
    avb_*_to_host_byte_order() swap functions)
  - dtbo dt_table_header/dt_table_entry -> **big-endian** (confirmed via
    mkdtboimg.py's `struct.pack('>8I', ...)`)
  - raw dtb (FDT) header -> **big-endian** (Devicetree Specification)
  - U-Boot legacy uImage header -> **big-endian** ("network byte order",
    stated directly in u-boot's include/image.h)
- Compression: zstd is **not** supported by AOSP mkbootimg or by current
  Magisk (checked Magisk's native/src/boot/format.rs and compress.rs on
  2026-09-15 -- no zstd there at all). Adding it is this project's own
  contribution, not something being "matched" to an existing base tool.
  lz4 legacy vs. lz4 frame magic bytes were taken from Magisk's
  format.rs (LZ4_LEG_MAGIC vs LZ41/LZ42_MAGIC) rather than guessed.
- Boot header v4 remains the newest version in AOSP mkbootimg's `main`
  branch as of this session (`mkbootimg.py` hard-rejects
  `header_version > 4`). No evidence of a v5 tied to any particular
  Android version ("Android 17") was found -- the ask is interpreted as
  "v4 needs to be solid, since that's what's current," not as "implement
  a format that doesn't exist yet." If AOSP ships a v5 later, the
  version-dispatch shape of `BootImage::parse`/`build` makes adding it a
  contained change (see the `header_version <= 2` / `== 3 || == 4`
  branches in `src/boot_image.cpp`).
- AVB descriptors are stored as opaque (tag, raw content) pairs, not
  fully-typed structs, so an unmodified descriptor round-trips
  byte-for-byte on repack. `AvbDescriptor::describe()` decodes the
  well-known tag types (hash/hashtree/property/kernel_cmdline/
  chain_partition) for `info` output only -- it's read-only.
- RSA re-signing of vbmeta uses OpenSSL (EVP, PKCS1 padding) and is
  **not validated against a real device or `avbtool verify_image`** from
  this sandbox -- flagged as best-effort in code comments. Passthrough
  repacking (no key, nothing that affects the hash changed) doesn't
  depend on this and is on solid ground.
- "uboot" in the original ask is interpreted as U-Boot's legacy
  `mkimage`/uImage container (magic 0x27051956) -- used to wrap a
  kernel/ramdisk/FDT for U-Boot-based bootchains on some Android-TV/STB
  devices. FIT (Flattened Image Tree) is U-Boot's newer image format and
  is **not** implemented; noted as a possible follow-up, not started.

## Repo / build

- GitHub: `blackeangel/android-boot-repack` (private). Created via API
  this session using a token the user pasted in chat -- **that token was
  used only for `git push`/repo creation and was never committed or
  written to memory; the user was told to rotate it.**
- Toolchain available in the Claude sandbox: g++ 13.3.0, cmake, and
  (after `apt-get install`) zlib1g-dev/liblz4-dev/libzstd-dev/
  liblzma-dev/libbz2-dev/libssl-dev, all as native x86_64-linux-gnu
  packages. **No internet access to dl.google.com (Android NDK) or to
  mingw prebuilt package mirrors from this sandbox** -- the Windows and
  Android static builds are expected to happen in GitHub Actions
  (unrestricted runner network), not locally here. If picking this back
  up in a fresh sandbox session: don't waste time trying to fetch the
  NDK here, go straight to authoring/fixing `.github/workflows/`.
- Because cross-building OpenSSL for mingw/NDK is a large time sink and
  hard to debug blind (can't run the cross-compiled binary locally),
  the plan is: bundle a small dependency-free SHA-1/256/512
  implementation for hashing (boot image `id`, AVB hash) so it works
  everywhere with zero extra deps, and treat OpenSSL (hence AVB RSA
  re-signing specifically) as an optional feature that's expected to be
  present on the Linux build and *may* be absent on Windows/Android
  static builds -- document this rather than silently degrading.

## Next steps (in order)

1. `src/manifest.{hpp,cpp}` -- key=value sidecar format binding a
   directory of component files to one of the parsed structs above.
2. `src/main.cpp` -- CLI: `abr info|unpack|repack`.
3. `third_party/sha/` -- bundled SHA-1/256/512, wire up as OpenSSL
   fallback (CMake option `ABR_WITH_OPENSSL`, default ON if found).
4. Build + smoke-test natively on Linux in the sandbox (synthetic
   images, since no real device firmware is available here).
5. `cmake/toolchains/mingw-w64.cmake`, `cmake/toolchains/android-ndk-arm64.cmake`.
6. `.github/workflows/build.yml`: matrix build, static linking
   (`-static` on Linux; `-static -static-libgcc -static-libstdc++` on
   mingw; Android NDK's own static libc++ via `-static-libstdc++` +
   NDK's static crt), upload artifacts / attach to a Release.
7. Push, trigger the workflow via the API, poll run status/logs via
   the API (`GET /repos/.../actions/runs`), fix failures.
8. Update this file's status table as each TODO clears.
