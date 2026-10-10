# bootimg_repacker (`abr`)

A C++26 unpacker/repacker for the Android boot-family image formats,
statically linked, for Linux, Windows, and Android (arm64-v8a).

## Supported formats

One parser per **container format**, since several of the requested
file names are really the same on-disk format with different
build-time contents:

| Format | Files it covers |
|---|---|
| boot (header v0-v4, and Marvell's PXA variant of v0) | `boot.img`, `init_boot.img`, `boot-debug.img`, `boot-test-harness.img`, `recovery.img`, `recovery-two-step.img`, the Samsung Galaxy J1 / Core Prime / Tab 4 boot images |
| vendor_boot (header v3-v4) | `vendor_boot.img`, `vendor_boot-debug.img`, `vendor_kernel_boot.img` |
| dtbo | `dtbo.img` (and the ACPIO variant) |
| dtb | raw or concatenated Flattened Device Tree blobs |
| vbmeta (AVB) | `vbmeta.img`, `vbmeta_system.img`, and AVB footers appended to other partitions |
| uboot | U-Boot's legacy `mkimage`/uImage container |
| ELF boot image | Sony/Xperia-style boot images that are an ELF file with the kernel/ramdisk as segments |

Also handled transparently, wherever it appears around those: a
MediaTek (MTK) sub-header on the kernel and/or ramdisk, a DHTB wrapper
(with its SEAndroid footer/padding), the Barnes & Noble Nook signing header
in front of an image (1 MiB, 256 KiB on the tablets), LG's Bump and
Samsung's SEAndroid footers behind it, an AVB hash footer on boot /
vendor_boot / dtbo, and the vendor data described below.

Compression: gzip, lz4 (frame and the Android/GKI "legacy" block
format), zstd, xz, LZMA (headerless "alone" stream), bzip2, and LZO
(in the lzop file format -- the framing the Linux kernel's own
decompressor expects, and the one `lzop` itself reads -- since raw LZO1X
has no header of its own to detect or frame blocks with).

Format is auto-detected from magic bytes; you don't need to tell `abr`
what kind of file it's looking at. Things that are not boot-family
containers (an ext4/F2FS/EROFS/SquashFS filesystem, a sparse image, a
ZIP, a raw cpio) are recognised and rejected with an explanation instead
of a bare "unknown format".

## Usage

```sh
abr info   <image>
abr unpack <image> [-o <outdir>] [--no-tree | --tree-only]
abr repack <dir> -o <image> [--ramdisk-from tree|cpio] [--avb-key <private_key.pem>] [--avb1-key <key> [--avb1-cert <cert>]]
abr identify [-b] <file>...   # what is it? worded like Android Image Kitchen's `file -m androidbootimg.magic`
# with any of them: -j N (or -jN, --threads N) = the most threads to use, 0 = automatic, 1 = none
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

### The ramdisk as a directory

Like Android Image Kitchen's `ramdisk/`, `unpack` also lays the ramdisk out as
files you can edit: `ramdisk/` next to `ramdisk.cpio` (a vendor_boot has
`ramdisk0/`, `ramdisk1/`, ... one per fragment). Add, change or delete files,
then `repack`: the archive is built again from the directory. Nothing is run
(no `cpio`, no `find`, no shell), so it works the same on Android, Linux and
Windows. An untouched directory is not rebuilt at all -- the image's own
compressed bytes are replayed, which keeps the round trip exact. If both
`ramdisk.cpio` and the directory were edited, `abr` stops and asks which one
counts (`--ramdisk-from tree` or `--ramdisk-from cpio`); `--no-tree` writes
only `ramdisk.cpio`, `--tree-only` only the directory.

What a directory cannot hold -- owners, modes, device nodes, the order of the
records, inode numbers, link counts -- is written beside it to `ramdisk.meta`,
one readable line per entry, and **that file, not the file system, is the
authority**. That is what makes the tree cross-platform: Windows has no owners
or modes, so a tree unpacked there (or zipped, or carried through git) would
lose them if they were read from the files.

- A file that is in the metadata keeps the mode and owner the metadata gives it,
  whatever the file system says; to change one, edit its line. A file deleted
  from the directory is deleted from the ramdisk.
- A file that is **new** gets the owner and time of the metadata's `default`
  line and the permissions of its `newmode` line: root, `0644` for a file,
  `0755` for a directory, `0777` for a link, and `0755` for an executable
  file -- one that starts with `#!`, an ELF program (not a `.so` or `.ko`), or,
  where the system has such a bit, one with the owner's executable bit. A line
  of its own in `ramdisk.meta` gives a path any mode and owner. `repack` lists
  the new and the deleted entries, so a mode that is not what you meant shows.
- **Symbolic links** are real links on Linux and Android. Windows cannot make
  them without administrator rights, so there a link is the small file that
  Cygwin and MSYS2 use (`!<symlink>`, the byte-order mark FF FE, the target in
  UTF-16LE, two zero bytes) carrying the System attribute -- no rights needed.
  Every form is read back as a link wherever the directory was carried: a real
  link, such a file, or -- where the metadata says the entry is a link -- a text
  file holding the target.
- A ramdisk that is **several cpio archives one after the other** (what
  Magisk's own `cpio` makes: the ramdisk, then an archive with `.backup/` and
  `overlay.d/`) gets a directory and a metadata file for each: `ramdisk/`,
  `ramdisk.vol2/`, `ramdisk.vol3/`, ..., with `ramdisk.meta`,
  `ramdisk.vol2.meta`, ... Every archive keeps its own magic, digit case and
  padding, and an edit rebuilds only the archive it is in. A directory that is
  deleted leaves its archive out of the image (`repack` says so); a directory
  the unpack did not make is ignored with a warning.
- The digits of a cpio header are upper case in GNU cpio and `gen_init_cpio`
  and lower case in Android's `mkbootfs`, Magisk and libarchive; the metadata
  records which (`hex upper|lower`), so a rebuilt archive is what the tool that
  made the original would write.

Only `newc` and `crc` archives become directories. One that cannot (the old
`odc` and binary kinds, hard links, a name twice, a `..` or an absolute name,
junk between archives, and on Windows a name Windows cannot hold) stays a
`ramdisk.cpio` as before, and `unpack` says why. A directory that `unpack` did
not make is never overwritten. The test suite builds ramdisks with GNU cpio 2.15
itself and with a writer of its own, and compares GNU cpio's listing and
extraction with what `abr` unpacked and rebuilt.

### `abr identify`

Android Image Kitchen decides what it is looking at by running `file` with
its own signature file (`androidbootimg.magic`) and cutting the answer
apart with `awk`. `abr` has the same signatures as code, so the same
question needs no other program: `abr identify boot.img` prints the label
(`AOSP bootimg`, `AOSP-PXA bootimg`, `NOOK signing (green loader)`,
`MTK bootimg, KERNEL, ...`, `AVBv2 signing footer`, ...), `-b` leaves the
file name off. Formats that `abr` recognises but cannot unpack yet (a
signing blob, a ChromeOS kernel, Sony SIN, Intel OSIP, Rockchip KRNL) are
named in the refusal, together with the AIK tool that opens them, instead
of "unrecognized format"; a refused `unpack` leaves no empty directory
behind. The test suite compares 98 synthetic samples with the built-in
expectation table and, when `ABR_AIK_MAGIC` points at AIK's magic file and
`file` is installed, with `file(1)` itself (the magic file is not shipped
here). It deliberately differs from `file(1)` in four documented ways; see
the header of `include/abr/identify.hpp`.

### Threads and compression levels

`abr` uses several cores where that pays: the components of an image (kernel,
ramdisk, each vendor ramdisk fragment, ...) are decoded, hashed and written
side by side; when an edited component has to be compressed again, the
independent 8 MiB blocks of an LZ4 "legacy" ramdisk and the jobs of a zstd
frame are compressed side by side. `-j N` (or `-jN`, `--threads N`, or the
environment variable `ABR_THREADS`) sets the most threads it may use. The
default is the number of hardware threads, at most 16; `-j1` runs everything
on the main thread.

**The result never depends on the number of threads.** The work is split by
the data (fixed block sizes, a fixed number of components), never by the
thread count, and results are joined in order; the test suite repacks with
`-j1` and with several threads and demands identical bytes, for every codec.
The same program on a 2-core and on a 32-core machine writes the same image.

What it buys is honest and modest, because most of the time is not
parallel: an unmodified image is never recompressed (the original compressed
bytes are replayed), and hashing -- the bulk of an unpack -- already runs on
the CPU's SHA instructions. Recompression is where threads help: on a 2-core
machine, repacking OrangeFox's `vendor_boot` after editing its 63 MB LZ4
ramdisk takes 10.0 s with `-j1` and 5.4 s with `-j2`. gzip, xz, lzma and bzip2
are written by a single stream each, so they gain nothing from more threads
(the other components of the image still run beside them).

When a component has to be compressed again, `abr` uses the codec's usual
setting. `<component>_level=N` in the manifest (`ramdisk_level=9`,
`ramdisk1_level=6`, ...) overrides it, with the codec's own meaning of the
number. For LZ4 legacy the default is the densest level (HC 12), which is what
Android's build uses (`lz4 -l -12`): a faster setting makes an edited ramdisk
enough larger to overflow a tightly sized `vendor_boot` partition.

**An edit that no longer fits its partition.** Other codecs are written at
their usual setting too (gzip 6, zstd 3, xz 6), and a build that cares about
size may have used a denser one: OrangeFox's `vendor_boot` has its `ramdisk0`
at `zstd -19` (22.6 MB; level 3 makes the same content 28.2 MB), and with one
file added at level 3 the image plus its AVB metadata is 9 KB bigger than the
64 MiB partition. So when the rebuilt image is bigger than the partition it
came out of -- more than the AVB footer's partition size allows, or more than
the fill it was padded to -- and something was compressed again at a setting
that has a denser one, `abr` says so and builds the image once more with
everything it compresses again at the densest setting the decoders still read:
gzip 9, zstd 19 (an 8 MiB window, what `zstd -19` writes), xz 9, lz4 frame 12.
```
note: image plus AVB metadata (67117760 bytes) no longer fits the original partition size (67108864 bytes); compressing what was edited again, as densely as the codecs allow
```
What the first try said is dropped, so every message appears once; the result
does not depend on `-j`; components that were not edited keep their original
bytes; a `<component>_level=N` in the manifest is never overridden. The second
try costs time -- level 19 is slow (24 s against 1 s for `zstd` on that
ramdisk, two threads) -- and only runs when the first one did not fit. If even
the densest setting is too big the error says so ("... -- not even with what
was edited compressed as densely as the codecs allow"). Where nothing has a
denser setting (LZ4 legacy and bzip2 are at their densest, lzma and lzo have no
setting) there is no second try: an AVB footer that no longer fits is refused,
a padded image is written bigger with a warning, as it always was.

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
  (see below);
- where a **long command line** was cut between the header's two fields:
  AOSP's `mkbootimg.py` fills all 512 bytes of the first one, the old C
  `mkbootimg` keeps a NUL at its end and continues after 511 (`cmdline_split`);
- a **Marvell PXA** header (`pxa=true`, and its `unknown` word).

If you edit an image that sits inside a vendor wrapper or signature
trailer, `abr` warns: the wrapper is kept as it was, so a signature or
checksum in it no longer matches. It cannot re-create vendor signatures
it has no key for. Constant additions are not signatures and do not warn:
zero fill, a `SEANDROIDENFORCE` marker, LG's Bump magic, and the Nook
header in front of the image.

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
`./tests/run_tests.sh build-windows/abr.exe`. Any other emulator works through
`ABR_RUNNER`; an arm64 build runs under qemu-user, which exercises the ARMv8
code paths (the SHA1/SHA2 instructions) without a device:
`ABR_RUNNER="qemu-aarch64 -cpu max" ./tests/run_tests.sh build-arm64/abr`.

The suite needs `python3`, `dtc`, `mkimage` and `openssl` on the PATH. When
`gzip`, `lz4`, `zstd`, `xz`, `bzip2` and `lzop` are installed it also feeds
what `abr` compressed to those programs (a missing one skips only that
check). The
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

# Linux aarch64 (glibc, static), to build and *run* the arm64 code under qemu-user
#   sudo apt-get install g++-14-aarch64-linux-gnu qemu-user
cmake -S . -B build-arm64 -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
  -DCMAKE_BUILD_TYPE=Release -DABR_STATIC_BINARY=ON
cmake --build build-arm64 -j

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

Hashing is where an unpack spends most of its time (every component is
hashed several times: boot id, replay check, AVB digest, signature check), so
SHA-1 and SHA-256 use the CPU's own instructions -- x86-64 SHA-NI, ARMv8
SHA1/SHA2 -- picked at run time, with a portable implementation that gives
identical digests everywhere else; the binary stays one file that runs on any
CPU of its architecture. On the development machine that is 240 -> 1400 MB/s
for SHA-256 and 175 -> 1560 MB/s for SHA-1 (portable code: 275 and 700 MB/s),
and unpacking a 67 MB `vendor_boot` went from 3.4 s to 1.4 s.
`ABR_SHA_IMPL=portable` forces the portable code; `abr_unit_tests sha-impl`
says which one runs. Both implementations are checked against Python's
`hashlib` on every awkward length and chunking by the test suite.

## How it is verified

Everything in the table above has a byte-identical round-trip test
against a real reference tool (AOSP's `mkbootimg.py`, `dtc`, or
`mkimage`); see `tests/run_tests.sh` and `PROGRESS.md` for exactly what
is covered and how. The quirks found on real device dumps are pinned by
synthetic fixtures built from the format specs (`tests/tools/fixtures.py`)
and re-checked by an independent verifier (`tests/tools/verify.py`).

The Marvell PXA header is judged by osm0sis's `pxa-mkbootimg` and
`pxa-unpackbootimg` (compiled from their sources, not vendored, used when
`PXA_MKBOOTIMG` / `PXA_UNPACKBOOTIMG` are set): 240 images made by the real tool
unpack and repack byte-for-byte, and 34 edited ones come out equal to what the
tool builds from the same pieces.

Compression is judged by the real tools. For every codec the suite builds a
boot image with `abr`, slices the ramdisk out of it with a separate script
(`tests/tools/verify.py`, not `abr`) and has the real `gzip`, `lz4`, `zstd`,
`xz`, `bzip2` or `lzop` decompress it, on data that mixes text with a
stretch that cannot be compressed and ends off any block boundary. The same
image is built with `-j1` and with several thread counts, and the bytes must be
identical. (This is how the LZO writer's two faults were found: its header was
not a valid lzop header, and it wrote blocks longer than the data they
contained, which the kernel's decompressor rejects as a corrupt file.)

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

- Hard links in a ramdisk's cpio archive (the ramdisk then stays one
  `ramdisk.cpio`); a directory tree is made for `newc`/`crc` archives only.
- The rest of the Android Image Kitchen format list: OSIP and KRNL
  (RKCRC) images, blobpack, QCDT tooling, ChromeOS `futility` signing,
  LOKI/AMONET, Sony SIN. `abr identify` already names all of them; what
  is missing is unpacking and packing them. See `PROGRESS.md` for the
  plan.
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
