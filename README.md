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
| ELF boot image | Sony/Xperia-style boot images that are an ELF file with the kernel/ramdisk as segments |

Also handled transparently, wherever it appears around those: a
MediaTek (MTK) sub-header on the kernel and/or ramdisk, a DHTB wrapper
(with its SEAndroid footer/padding), an AVB hash footer on boot /
vendor_boot / dtbo, and the vendor data described below.

Compression: gzip, lz4 (frame and the Android/GKI "legacy" block
format), zstd, xz, LZMA (headerless "alone" stream), bzip2, and LZO
(wrapped in the lzop container framing that the Linux kernel's own
decompressor expects, since raw LZO1X has no header of its own to
detect or frame blocks with).

Format is auto-detected from magic bytes; you don't need to tell `abr`
what kind of file it's looking at. Things that are not boot-family
containers (an ext4/F2FS/EROFS/SquashFS filesystem, a sparse image, a
ZIP, a raw cpio) are recognised and rejected with an explanation instead
of a bare "unknown format".

## Usage

```sh
abr info   <image>
abr unpack <image> [-o <outdir>]
abr repack <dir> -o <image> [--avb-key <private_key.pem>] [--avb1-key <key> [--avb1-cert <cert>]]
```

`unpack` writes a human-readable, human-editable `manifest.txt` plus
one file per component (kernel, ramdisk, dtb, ...) into the output
directory. Edit whatever you need to, then `repack`.

**An unpack/repack round trip is byte-for-byte identical to the
original if you don't touch any of the extracted files** -- and `unpack`
checks this itself (it rebuilds the image in memory and compares), saying
so, or saying where the first difference is. 13 of the 14 real device
dumps tried so far round-trip exactly (the 14th is an ext4 filesystem).
Compressed
components (kernel, ramdisk, vendor ramdisk fragments) are
decompressed on unpack so they're actually editable, but the original
compressed bytes are kept on the side and replayed verbatim if the
extracted file comes back unchanged -- only an actual edit triggers
recompression. See `tests/run_tests.sh` for this being checked against
real images built with AOSP's own `mkbootimg.py`, `dtc`, and `mkimage`.

### What `abr` keeps so a round trip stays exact

Real images carry more than the format documents. `abr` records all of
this in the manifest / as side files and writes it back:

- bytes **before** the image (a vendor wrapper such as a BFBF/SSSS
  header) and **after** it (signature trailers, an AVBv1 `BootSignature`,
  a `SEANDROIDENFORCE` marker), and zero/0xFF **fill up to the original
  partition size**;
- the boot header `id` and **how it was computed** (AOSP SHA-1, SHA-1
  that also covers a Qualcomm dt blob, SHA-256, or an unrecognised value
  kept verbatim) -- after an edit the id is recomputed the same way;
- Qualcomm/CAF `dt_size` in a v0 header, reserved words, a non-standard
  `header_size` or `recovery_dtbo_offset`, data hidden in the header
  page, dumps whose last page was trimmed;
- vendor_boot v4 images that declare no ramdisk table;
- an AVB footer: laid out the way `avbtool` does, with the digest checked
  at unpack time and **refreshed after you edit the image** (a signed
  footer needs `--avb-key`; without it `abr` refuses rather than emit an
  image that fails verification);
- an AVBv1 boot signature (the `boot_signer` blob after the image):
  checked at unpack time and **re-created after you edit the image**
  (see below).

If you edit an image that sits inside a vendor wrapper or signature
trailer, `abr` warns: the wrapper is kept as it was, so a signature or
checksum in it no longer matches. It cannot re-create vendor signatures
it has no key for.

### Re-signing a vbmeta

```sh
abr repack <dir> -o vbmeta.img --avb-key my_signing_key.pem
```

The key may be a PEM file (`BEGIN PRIVATE KEY` or `BEGIN RSA PRIVATE KEY`)
or raw DER such as Android's `.pk8`; RSA-2048/4096/8192, as selected by
the image's `algorithm_type`. A key protected by a passphrase is refused
with the one-line `openssl` command that removes the passphrase. The
signature is computed inside `abr` (see below), the public key stored in
the vbmeta is regenerated from the key you pass, and `abr` says so when
that differs from the key the image had before.

Without `--avb-key`, a signed vbmeta repacks by passthrough as long as
nothing that affects its hash changed. If you *do* change something
(a descriptor, flags, rollback index) on a signed vbmeta, you must
supply a key -- `abr` will refuse to emit a self-inconsistent signed
blob rather than silently producing one that fails verification. Or
set `algorithm_type=0` in the manifest for an unsigned rebuild instead.

### Re-signing a boot image (AVBv1 boot signature)

Boot and recovery images of the Android 4.4-8 era (header v0-v2) often end
with a *boot signature*: the DER blob AOSP's `boot_signer` appends after the
image, which bootloaders such as LK check ("verified boot 1.0"; Android
Image Kitchen calls it AVBv1). `abr` finds it, judges it, and keeps it
exact:

- `abr info` shows the target (`/boot` or `/recovery`), how many bytes it
  covers, who signed it, and whether it **verifies** (RSA keys; an ECDSA
  signature is reported as "not checked" and kept as it is);
- an image you do not touch round-trips byte for byte -- even one whose
  signature is already invalid, which `abr` reports at unpack;
- once you edit something, the old signature cannot match any more, so
  `abr` **re-creates it** over the new image and says so. Without options
  it signs with AOSP's public test key (the Android Image Kitchen default)
  and **warns** when the original was signed by somebody else, because the
  device will not trust a test-key signature. To sign with your own key:

```sh
abr repack <dir> -o boot.img --avb1-key my.pk8 --avb1-cert my.x509.pem
abr repack <dir> -o boot.img --avb1-key my          # my.pk8 + my.x509.pem, as AIK names them
```

The key is an RSA private key (PEM, or DER such as `.pk8`); the certificate
(PEM or DER) goes into the signature and must belong to the key, which
`abr` checks. A PEM file holding both works too. An unsigned image stays
unsigned; give `--avb1-key` (or put `avb1_signature=true` in the manifest)
to add a signature.

The signature is what `boot_signer` would write byte for byte: the same
bytes from the same key and image (PKCS#1 v1.5 is deterministic), which is
how it is tested against the real tool.

## Building

Requires CMake >= 3.20 and a **C++26** compiler: GCC >= 14, Clang >= 17 (the
Android NDK r27+ qualifies) or MSVC. Ubuntu 24.04's default GCC 13 is too old
for the mode -- `apt install g++-14` and pass `-DCMAKE_CXX_COMPILER=g++-14`;
configuring with a compiler that cannot do C++26 stops with exactly that hint.
(Stuck with an older compiler? `-DABR_CXX_STANDARD=23` builds the same
sources; nothing in `abr` needs a C++26-only feature, and the test results
are identical.) Dependencies (zlib, lz4, zstd, xz, bzip2) are fetched and
built from source by default -- no system dev packages needed:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DABR_STATIC_BINARY=ON \
      -DCMAKE_CXX_COMPILER=g++-14
cmake --build build -j
./build/abr
```

`-DABR_STATIC_BINARY=ON` produces a single binary with no shared
library dependencies (verify with `ldd build/abr` -> "not a dynamic
executable"). Omit it for a normal dynamically-linked build during
development, which is faster to iterate on.

### Running the tests

```sh
cmake --build build -j          # also builds build/abr_unit_tests (-DABR_BUILD_TESTS=OFF to skip)
./tests/run_tests.sh build/abr
```

Pass the Windows build instead and the suite runs the real `abr.exe` under
`wine` (it makes small wrapper scripts, nothing else changes):
`./tests/run_tests.sh build-windows/abr.exe`.

The suite needs `python3`, `dtc`, `mkimage` and `openssl` on the PATH. The
cross-check against the real AOSP `boot_signer` is skipped unless `javac`,
`java` and BouncyCastle are present (Debian/Ubuntu: `apt install
default-jdk-headless libbcprov-java`).
They are used only as independent reference implementations to compare
`abr` against -- none of them is needed to build or use `abr`.

### Cross-compiling

```sh
# Windows x86_64, C++26: clang + the distribution's mingw-w64 runtime
#   sudo apt-get install clang-20 lld-20 mingw-w64 g++-mingw-w64-x86-64-posix
cmake -S . -B build-windows -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-clang.cmake \
  -DCMAKE_BUILD_TYPE=Release -DABR_STATIC_BINARY=ON
cmake --build build-windows -j
# (cmake/toolchains/mingw-w64.cmake is the plain mingw GCC variant; Ubuntu's is
#  GCC 13, so it builds as C++23)

# Android arm64-v8a (needs the Android NDK)
cmake -S . -B build-android -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/android-arm64.cmake \
  -DANDROID_NDK_HOME=/path/to/android-ndk \
  -DABR_STATIC_BINARY=ON
cmake --build build-android -j
```

See `.github/workflows/build.yml` for the exact CI recipe (including
where it gets the NDK from) and prebuilt binaries under this repo's
Actions tab / Releases. CI builds Linux with both g++-14 and clang-20, runs
the whole test suite on both, and runs the Windows `abr.exe` through the same
suite under wine. The `.exe` imports only `KERNEL32.dll` and `msvcrt.dll`.

**Note on "static" for Android:** bionic has no static libc, so an
Android executable is never fully static -- that's expected, not a
bug. `ANDROID_STL=c++_static` (set by the toolchain file) plus the
vendored static compression libraries mean the binary needs nothing
beyond what every Android system already provides.

### Cryptography: nothing external

`abr` links no crypto library. SHA-1/256/512, big-integer arithmetic,
RSA PKCS#1 v1.5 signing and verification, and the small DER/PEM/X.509
reader that key files need are all part of the binary (`src/bigint.cpp`,
`src/rsa.cpp`, `src/asn1.cpp`, `src/sha.cpp`), so `--avb-key` works the
same on Linux, Windows and Android and the binary stays a single file.
PKCS#1 v1.5 is deterministic, so for a given key and image the signature
is bit-for-bit what `openssl dgst -sign` or `avbtool` produce -- which
is exactly how it is tested (next section).

## How it is verified

Everything in the table above has a byte-identical round-trip test
against a real reference tool (AOSP's `mkbootimg.py`, `dtc`, or
`mkimage`); see `tests/run_tests.sh` and `PROGRESS.md` for exactly what
is covered and how. The quirks found on real device dumps are pinned by
synthetic fixtures built from the format specs (`tests/tools/fixtures.py`)
and re-checked by an independent verifier (`tests/tools/verify.py`).

AVB signing is judged by implementations that share no code with `abr`:

- the BigInt arithmetic against Python's integers (tens of thousands of
  vectors chosen to hit the rare carry/borrow paths of Knuth's division
  and Montgomery multiplication);
- RSA signatures byte-for-byte against `openssl dgst -sign` (1024/2048/
  4096-bit keys x SHA-1/256/512 x PEM / PKCS#8 / `.pk8` / PKCS#1 DER),
  and signature verification against signatures `openssl` made;
- the AVB public-key blob (`n0inv`, modulus, R^2 mod n) against
  `avbtool extract_public_key`;
- images made by the real `avbtool` (`add_hash_footer`,
  `make_vbmeta_image`, vendored in `tests/reference/avb/`): unpack+repack
  reproduces them exactly, re-signing an unchanged vbmeta with the same key
  reproduces avbtool's bytes, and an image `abr` edited and re-signed
  passes `avbtool verify_image`.

The AVBv1 boot signature is judged the same way, by two implementations
that share no code with `abr`: `tests/tools/avb1.py` (DER assembled in
Python, RSA from `openssl`) and the **real `boot_signer`**, compiled from
AOSP's own Java sources (`tests/reference/boot_signer/`). The same key and
image must give the same bytes from all three; images signed by either
reference read as VALID and round-trip exactly; images `abr` re-signed
(AOSP key and a custom RSA-4096 key, header v0, v0+QCDT, v1, v2) pass
`boot_signer -verify`. Checked once on real device dumps too: three real
AVBv1 images report VALID, and re-signing the unsigned part of a vendor
`boot.img` with the AOSP key reproduced its stored signature exactly.

What has **not** been done: booting an `abr`-signed image on a device
that enforces verified boot.

Two smaller gaps:

- **dtbo.img** has no external-oracle test in this repo (couldn't get
  a working `mkdtboimg.py` mirror reachable during development); the
  implementation was checked field-for-field by reading AOSP's actual
  current source instead. Worth upgrading if a mirror turns up.
- Chained vbmeta partitions are read and kept, but `abr` does not walk a
  chain across several image files.

## Not implemented (yet)

- **cpio ramdisk as a directory tree**: the ramdisk is extracted as one
  decompressed `ramdisk.cpio`; unpacking/packing its files is planned.
- The rest of the Android Image Kitchen format list: PXA, OSIP/KRNL,
  RKCRC, blobpack, QCDT tooling, ChromeOS `futility` signing, LOKI/AMONET,
  BLOB/NOOK/SIN. See `PROGRESS.md` for the plan.
- U-Boot's newer FIT (Flattened Image Tree) format -- only the older
  legacy `mkimage` container is supported.
- Filesystems (ext4, F2FS, EROFS, SquashFS) and sparse images: out of
  scope; see the sibling tools in the same suite.

## License

GPL-3.0-or-later, see `LICENSE`. A few directories are vendored
third-party code, used only by parts of `abr` (`third_party/minilzo`)
or only by the test suite (`tests/reference/mkbootimg`,
`tests/reference/avb`, `tests/reference/boot_signer`), each with its own
README explaining exactly what and why -- see those for details:

- `third_party/minilzo/`: LZO1X compress/decompress, GPL-2.0-or-later
  (compatible with, and combined here under, this project's own
  GPL-3.0-or-later).
- `tests/reference/mkbootimg/`: AOSP's `mkbootimg.py` and friends,
  Apache-2.0, not linked into the `abr` binary at all.
- `tests/reference/avb/`: AOSP's `avbtool.py`, MIT, used only as the
  oracle for the AVB tests.
- `tests/reference/boot_signer/`: AOSP's `boot_signer` (Java sources, with
  its public "verity" test key pair), Apache-2.0, used only as the oracle
  for the AVBv1 tests. `src/legacy/avb1_aosp_key.cpp` embeds the same
  public test key (Apache-2.0, generated by `tools/gen_aosp_verity_key.py`;
  it is the default signer of Android Image Kitchen and protects nothing).
