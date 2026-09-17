# bootimg_repacker (`abr`)

A C++20 unpacker/repacker for the Android boot-family image formats,
statically linked, for Linux, Windows, and Android (arm64-v8a).

## Supported formats

One parser per **container format**, since several of the requested
file names are really the same on-disk format with different
build-time contents:

| Format | Files it covers |
|---|---|
| boot (header v0-v4) | `boot.img`, `init_boot.img`, `boot-debug.img`, `boot-test-harness.img`, `recovery.img`, `recovery-two-step.img` |
| vendor_boot (header v3-v4) | `vendor_boot.img`, `vendor_boot-debug.img`, `vendor_kernel_boot.img` |
| dtbo | `dtbo.img` (and the ACPIO variant) |
| dtb | raw or concatenated Flattened Device Tree blobs |
| vbmeta (AVB) | `vbmeta.img`, `vbmeta_system.img`, and AVB footers appended to other partitions |
| uboot | U-Boot's legacy `mkimage`/uImage container |

Compression: gzip, lz4 (frame and the Android/GKI "legacy" block
format), zstd, xz, LZMA (headerless "alone" stream), bzip2, and LZO
(wrapped in the lzop container framing that the Linux kernel's own
decompressor expects, since raw LZO1X has no header of its own to
detect or frame blocks with).

Format is auto-detected from magic bytes; you don't need to tell `abr`
what kind of file it's looking at.

## Usage

```sh
abr info   <image>
abr unpack <image> [-o <outdir>]
abr repack <dir> -o <image> [--avb-key <private_key.pem>]
```

`unpack` writes a human-readable, human-editable `manifest.txt` plus
one file per component (kernel, ramdisk, dtb, ...) into the output
directory. Edit whatever you need to, then `repack`.

**An unpack/repack round trip is byte-for-byte identical to the
original if you don't touch any of the extracted files.** Compressed
components (kernel, ramdisk, vendor ramdisk fragments) are
decompressed on unpack so they're actually editable, but the original
compressed bytes are kept on the side and replayed verbatim if the
extracted file comes back unchanged -- only an actual edit triggers
recompression. See `tests/run_tests.sh` for this being checked against
real images built with AOSP's own `mkbootimg.py`, `dtc`, and `mkimage`.

### Re-signing a vbmeta

```sh
abr repack <dir> -o vbmeta.img --avb-key my_signing_key.pem
```

Without `--avb-key`, a signed vbmeta repacks by passthrough as long as
nothing that affects its hash changed. If you *do* change something
(a descriptor, flags, rollback index) on a signed vbmeta, you must
supply a key -- `abr` will refuse to emit a self-inconsistent signed
blob rather than silently producing one that fails verification. Or
set `algorithm_type=0` in the manifest for an unsigned rebuild instead.

## Building

Requires CMake >= 3.20 and a C++20 compiler. Dependencies (zlib, lz4,
zstd, xz, bzip2) are fetched and built from source by default -- no
system dev packages needed:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DABR_STATIC_BINARY=ON
cmake --build build -j
./build/abr
```

`-DABR_STATIC_BINARY=ON` produces a single binary with no shared
library dependencies (verify with `ldd build/abr` -> "not a dynamic
executable"). Omit it for a normal dynamically-linked build during
development, which is faster to iterate on.

### Cross-compiling

```sh
# Windows (needs the mingw-w64 package)
cmake -S . -B build-windows -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64.cmake \
  -DABR_STATIC_BINARY=ON
cmake --build build-windows -j

# Android arm64-v8a (needs the Android NDK)
cmake -S . -B build-android -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/android-arm64.cmake \
  -DANDROID_NDK_HOME=/path/to/android-ndk \
  -DABR_STATIC_BINARY=ON
cmake --build build-android -j
```

See `.github/workflows/build.yml` for the exact CI recipe (including
where it gets the NDK from) and prebuilt binaries under this repo's
Actions tab / Releases.

**Note on "static" for Android:** bionic has no static libc, so an
Android executable is never fully static -- that's expected, not a
bug. `ANDROID_STL=c++_static` (set by the toolchain file) plus the
vendored static compression libraries mean the binary needs nothing
beyond what every Android system already provides.

### Platform-specific limitation: AVB re-signing

AVB RSA re-signing (`--avb-key`) needs OpenSSL, which is only
`find_package`'d (native Linux builds), not vendored/cross-built. The
Windows and Android toolchain files disable it explicitly. On those
two platforms, `--avb-key` isn't available -- everything else,
including unsigned vbmeta rebuilds and passthrough repacking of an
already-signed vbmeta, works identically on every platform, since all
hashing (boot image `id`, AVB digests) uses a bundled dependency-free
SHA-1/256/512 implementation regardless of this setting.

## What hasn't been independently verified

Everything in the table above has a byte-identical round-trip test
against a real reference tool (AOSP's `mkbootimg.py`, `dtc`, or
`mkimage`) or, for AVB signing specifically, an independent signature
check with `openssl pkeyutl -verify` -- see `tests/run_tests.sh` and
`PROGRESS.md` for exactly what's covered and how. Two exceptions:

- **dtbo.img** has no external-oracle test in this repo (couldn't get
  a working `mkdtboimg.py` mirror reachable during development); the
  implementation was checked field-for-field by reading AOSP's actual
  current source instead. Worth upgrading if a mirror turns up.
- **AVB RSA signing** produces a standards-compliant PKCS1v1.5
  signature (confirmed via OpenSSL's own independent verifier), but
  has not been checked against `avbtool verify_image` or booted on a
  real device.

## Not implemented

- U-Boot's newer FIT (Flattened Image Tree) format -- only the older
  legacy `mkimage` container is supported.

## License

GPL-3.0-or-later, see `LICENSE`. Two directories are vendored
third-party code, used only by parts of `abr` (`third_party/minilzo`)
or only by the test suite (`tests/reference/mkbootimg`), each with its
own README explaining exactly what and why -- see those for details:

- `third_party/minilzo/`: LZO1X compress/decompress, GPL-2.0-or-later
  (compatible with, and combined here under, this project's own
  GPL-3.0-or-later).
- `tests/reference/mkbootimg/`: AOSP's `mkbootimg.py` and friends,
  Apache-2.0, not linked into the `abr` binary at all.
