# Progress log

This file exists so work can resume from a clean session without
re-deriving anything. Read this file first. Update it after every
meaningful step (what changed, what's next) -- treat it as the
single source of truth for project status, not a changelog nobody reads.

## This project's place in the bigger picture

This repo (`blackeangel/bootimg_repacker`) is one tool in Павел's
wider suite of Android firmware C++ CLI tools (internally tracked as
"UKA_tools" on the Claude side): `f2fs_unpacker`, `tar_repacker`,
`md1img_repacker`, `utils` (utils_libarchive branch). Match that
suite's established conventions here rather than inventing new ones --
see "Conventions inherited from the sibling tools" below. This was
discovered mid-session (2026-09-16) via Claude's memory, *after* the
repo had already been created with the wrong license and a
non-matching name -- both have since been corrected (see git log).
If you're picking this up fresh and something here conflicts with
what you see in the sibling repos, the sibling repos win; update this
file to match and move on.

## Goal

C++20 unpacker/repacker ("abr" = Android Boot Repack, the internal
namespace -- the repo/binary is named `bootimg_repacker`/`abr`) for the
Android boot-family image formats:

| Family | Files it covers | Status |
|---|---|---|
| boot (header v0-v4) | boot.img, init_boot.img, boot-debug.img, boot-test-harness.img, recovery.img, recovery-two-step.img | **done** (`boot_image.{hpp,cpp}`) |
| vendor_boot (header v3-v4) | vendor_boot.img, vendor_boot-debug.img, vendor_kernel_boot.img | **done** (`vendor_boot.{hpp,cpp}`) |
| dtbo | dtbo.img (+ ACPIO variant) | **done** (`dtbo.{hpp,cpp}`) |
| dtb | raw/concatenated FDT blobs | **done** (`dtb.{hpp,cpp}`) |
| vbmeta (AVB) | vbmeta.img, vbmeta_system.img, + AVB footers on other partitions | **done**, RSA re-signing needs OpenSSL; **not yet cross-checked against Python avbtool** -- see Next steps | (`vbmeta.{hpp,cpp}`) |
| uboot | U-Boot legacy uImage (mkimage format) | **done** (`uimage.{hpp,cpp}`) |
| compression | gzip, lz4, lz4-legacy, zstd, xz, lzma(alone), bzip2 | **done** (`compression.{hpp,cpp}`). **LZO not implemented** -- u-boot's IH_COMP_LZO can't round-trip yet. Worth adding now that we're GPL (liblzo2 is GPL, same as the sibling tools already use for F2FS) |
| bundled SHA-1/256/512 | dependency-free hashing so cross builds don't need OpenSSL | **done** (`sha.{hpp,cpp}`), self-test against NIST "abc" vectors passes -- see `hash::sha_selftest()`, called from `main()` |
| manifest (unpack/repack glue) | key=value sidecar + component files | **done** (`manifest.{hpp,cpp}`) |
| CLI (`abr` binary: info/unpack/repack) | `main.cpp` | **done**, not yet build-tested end to end this session |
| CMake: FetchContent vendored static deps | must follow the sibling-tools pattern (bridge cache vars to force static .a, not system .so) | TODO -- see below, this is the main risk area |
| CMake: cross toolchains (mingw-w64, Android NDK) | | TODO |
| GitHub Actions: static build matrix (linux-x86_64, windows-x86_64, android-arm64) | | TODO |
| Local build + round-trip smoke test (native Linux) | | TODO, do this before spending time on cross-compilation |

## Conventions inherited from the sibling tools (apply here too)

- **License: GPL v3**, not MIT (corrected this session -- SPDX headers
  and LICENSE file were wrong for a few commits, now fixed). Chosen
  across the suite specifically to allow LZO inclusion.
- **Dependencies are vendored via CMake FetchContent, built as static
  libraries from source** -- NOT pulled from system packages
  (`apt-get install libzstd-dev` etc., which is what this session did
  *locally* to get a fast native build going, is fine for local
  sandbox experimentation but is **not** the shipping strategy).
  Hard-won reason from the sibling tools: system packages silently
  link as shared libs unless you're careful, which defeats "static
  build into a single binary." The fix that's already proven to work
  there: set the library's CMake cache variables (e.g. `ZLIB_LIBRARY`,
  `LIBLZMA_LIBRARY`) to point at the static `.a` path **before**
  `FetchContent_Populate`/`FetchContent_MakeAvailable` runs, so the
  dependency's own `find_package` calls can't pick up a system `.so`
  instead.
- **CMake 4.x is what's actually in use** and it rejects old
  `cmake_minimum_required` lines some vendored projects still ship --
  expect to need `FetchContent_Populate` + patch the vendored
  project's CMakeLists (or set `CMAKE_POLICY_VERSION_MINIMUM`) rather
  than a plain `FetchContent_MakeAvailable`.
- Do not use `return()` inside a CMake **macro** we write (breaks the
  caller's `add_subdirectory`/inclusion); use a `function()` or
  restructure with `if()` instead.
- **Android: bionic cannot be statically linked, and that's correct,
  not a bug.** `file` reporting "dynamically linked" on the Android
  arm64 binary is expected. What "static" means for the Android
  target here is: `ANDROID_STL=c++_static` (statically links
  libc++), plus all our own vendored deps (zlib/lz4/zstd/xz/bzip2)
  statically linked in -- so the binary needs nothing beyond what
  bionic itself always provides on-device. Don't waste time trying to
  force a fully-static Android executable; it isn't a thing.
- Cross-compilation targets across the whole suite: Linux native,
  Windows (MinGW-w64 or MSVC), Android NDK arm64-v8a, all validated in
  CI. Match this rather than a narrower matrix.
- Push early, push often, commit every logical patch separately --
  this is a *recovered* lesson from the sibling tools (a sandbox reset
  previously destroyed unpushed work there), not just something the
  user asked for this session out of general caution. Treat any
  uncommitted work as one session-reset away from gone.
- Reference/validation tools the user already relies on: Python
  `avbtool` (AOSP) for anything AVB/vbmeta, plus `img2sdat`/`sdat2img`,
  `adb`/`fastboot`. **This project's vbmeta code has not yet been
  cross-checked against avbtool** -- doing that would raise confidence
  a lot more than the from-first-principles struct-layout verification
  already in `src/vbmeta.cpp`'s header comment, and matches how
  correctness is actually judged on this suite ("byte-accurate
  round-trip", not just "compiles and looks right"). See Next steps.
- Repo naming across the suite: `f2fs_unpacker`, `tar_repacker`,
  `md1img_repacker`, `utils`. This repo was renamed mid-session from
  `android-boot-repack` to `bootimg_repacker` to match.

## Key format-level design decisions (still accurate, unaffected by the above)

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
- Endianness is format-specific and was individually verified against
  primary sources (not assumed): boot/vendor_boot headers ->
  little-endian; AVB vbmeta header/footer/descriptors, dtbo
  dt_table_header/dt_table_entry, raw dtb (FDT) header, and U-Boot
  legacy uImage header -> all big-endian. Sources for each are in the
  file-header comments of the corresponding `.hpp`/`.cpp`.
- zstd is this project's own contribution, not something matched to an
  existing base tool -- confirmed neither AOSP mkbootimg nor current
  Magisk (checked native/src/boot/{format,compress}.rs) support it.
- Boot header v4 remains the newest version in AOSP mkbootimg's `main`
  branch (hard-rejects `header_version > 4`); no evidence of a v5 tied
  to "Android 17" specifically. Interpreted the ask as "v4 needs to be
  solid" rather than "implement a format that doesn't exist yet."
- AVB descriptors are stored as opaque (tag, raw content) pairs so an
  unmodified descriptor round-trips byte-for-byte; `describe()` decodes
  well-known tag types for `info` output only, read-only.
- "uboot" is interpreted as U-Boot's legacy `mkimage`/uImage container
  (magic 0x27051956). FIT (Flattened Image Tree), U-Boot's newer
  format, is **not** implemented -- noted as a possible follow-up.

## Repo / GitHub

- `blackeangel/bootimg_repacker` (private). Created + renamed via the
  GitHub API this session using a token the user pasted in chat --
  that token was used only for API calls and `git push`, never
  committed to the repo or written to Claude's memory; the user was
  told to rotate it after this session.
- Local sandbox toolchain used for the fast native iteration so far:
  g++ 13.3.0, cmake, apt-installed zlib1g-dev/liblz4-dev/libzstd-dev/
  liblzma-dev/libbz2-dev/libssl-dev. Remember: this is **not** the
  vendoring strategy the shipped CMakeLists should use (see
  Conventions above) -- it was just the fastest way to get a
  compiling library while writing the format parsers.
- No internet access to dl.google.com (Android NDK) or to mingw
  prebuilt mirrors from inside the Claude sandbox -- Windows/Android
  builds are expected to happen in GitHub Actions (unrestricted
  runner network), driven/monitored from here via the GitHub API
  (`GET /repos/.../actions/runs`, etc.), not built locally here.

## Next steps (in order)

1. Rewrite `CMakeLists.txt` to vendor zlib/lz4/zstd/xz/bzip2 via
   FetchContent with the static-library bridge-variable technique
   (see Conventions above), instead of the apt packages used so far.
   Keep OpenSSL as an optional `find_package` (not vendored) purely
   for AVB RSA re-signing; bundled SHA covers everything else.
2. Build + smoke-test natively on Linux against that CMakeLists
   (synthetic images -- no real device firmware available in-sandbox).
   Confirm `hash::sha_selftest()` passes at startup.
3. Try cross-checking `VbmetaImage` against Python `avbtool` (fetch
   from AOSP's external/avb GitHub mirror; `pip install` its light
   deps) -- at minimum, confirm avbtool can parse a vbmeta blob this
   tool produced, and vice versa. Worth the time given how this suite
   judges correctness.
4. `cmake/toolchains/mingw-w64.cmake`,
   `cmake/toolchains/android-ndk-arm64.cmake` (`ANDROID_STL=c++_static`,
   don't fight bionic on static linking -- see Conventions).
5. `.github/workflows/build.yml`: matrix build (linux-x86_64,
   windows-x86_64 via mingw, android-arm64 via NDK), static linking
   per-platform as above, upload artifacts / attach to a Release.
6. Push, trigger the workflow via the API, poll run status/logs via
   the API, fix failures.
7. Consider adding LZO (`liblzo2`, already GPL-compatible and already
   vendored elsewhere in the suite for F2FS) so U-Boot uImage
   IH_COMP_LZO payloads round-trip too. Not blocking.
8. Update this file's status table and the Conventions section as
   things change -- don't let it go stale.
