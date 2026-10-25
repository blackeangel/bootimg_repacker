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
| ELF boot image | Sony/Xperia-style boot images that are an ELF file with the kernel/ramdisk as segments (the `kernel.elf` of an Xperia: kernel, ramdisk, `ipl`, `rpm`, command line); see below |
| Sony SIN (v1-v3) | the `.sin` files of Xperia firmware (`boot.sin`, `kernel.sin`, `FOTAKernel.sin`, ...): the container comes off, what is inside is unpacked as it would be on its own; see below |
| Rockchip KRNL | Rockchip's `kernel.img` and `boot.img` (`"KRNL"`, the size, a kernel or a gzip cpio ramdisk, Rockchip's own CRC) |
| ASUS blob | the `"MSM-RADIO-UPDATE"` blobs of ASUS Tegra tablets (what `blobpack` writes), with or without the `-SIGNED-BY-SIGNBLOB-` signing header |
| Intel OSIP | the boot images that Android Image Kitchen opens with `mboot`: an OSIP header (or none), a signature (or none), the cmdline, a bootstub, the kernel and a gzip ramdisk |

Also handled transparently, wherever it appears around those: a
MediaTek (MTK) sub-header on the kernel and/or ramdisk, a DHTB wrapper
(with its SEAndroid footer/padding), an ASUS blob that holds one image
(`has_blob=true` in the manifest; see below), the *amonet* patch of Amazon's
MediaTek Fire tablets (a 1024-byte microloader in front, the boot header
moved behind it: `unpack` keeps it as `microloader.bin` and `has_amonet=true`
in the manifest, reads the boot image under it, and `repack` puts it back;
the same two manifest lines put it on an ordinary v0 image), the *loki*
patch of `loki_tool` on a boot or recovery image (a block of the bootloader's
code behind the ramdisk: `has_loki=true`; see below), a ChromeOS (vboot) kernel
blob around an image (`has_chromeos=true`: the keyblock, the preamble's fields
and the signatures are kept in the manifest; see below), the Barnes &
Noble Nook signing header in front of an image (1 MiB, 256 KiB on the
tablets), LG's Bump and Samsung's SEAndroid footers behind it, an AVB hash
footer on boot / vendor_boot / dtbo, and the vendor data described below.

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
                            [--chromeos-key <.vbprivk> [--chromeos-keyblock <.keyblock>]]
abr identify [-b] <file>...   # what is it? worded like Android Image Kitchen's `file -m androidbootimg.magic`
# with any of them: -j N (or -jN, --threads N) = the most threads to use, 0 = automatic, 1 = none
```

`unpack` writes a human-readable, human-editable `manifest.txt` plus
one file per component (kernel, ramdisk, dtb, ...) into the output
directory. Edit whatever you need to, then `repack`.

`repack` reads what you edited strictly, and says which key and which value it will not take (it writes nothing then).
A number is decimal digits, or `0x` and hexadecimal digits (`010` is ten, not eight): no sign, no unit, no text behind it,
and no more than the field it is for holds (a 32-bit field of a header takes up to 4294967295, not "the first 32 bits of
something bigger"). A flag is `true` or `false` (`yes`, `no`, `1`, `0` in any case do too), hexadecimal digits come
in pairs, a count (ramdisks, descriptors, blobs) is at most 65536 and the size of a partition (`pad_to`) at most 1 GiB. The
files it reads are regular files: a directory, a fifo or a device (`/dev/zero`) in their place is refused at once, and
so is `-o dir/`, which is not the name of a file. A `.abr_raw/` copy that is not the component it is for is refused too (take
it out to have the component compressed again).

Paths may hold any characters. On Windows `abr.exe` reads the wide command line (the C runtime's `argv` holds a `?` for
every character outside the ANSI code page: Cyrillic on a Western system, Chinese, an emoji) and works in UTF-8 from
there, and a console is switched to UTF-8 while it runs, so a path like `C:\Users\Павел\загрузка.img` comes through
exactly as typed. (The test suite unpacks and repacks images with such names, under wine as well.)

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
file name off. A file that carries the signature of a container but is not a whole
one, or holds what `abr` does not unpack (a SIN around a system partition, a
ChromeOS blob for x86, a bare signature), is named in the refusal, with the reason
and the AIK tool that opens it, instead of "unrecognized format"; a refused `unpack`
leaves no empty directory behind. The test suite compares 98 synthetic samples with the built-in
expectation table and, when `ABR_AIK_MAGIC` points at AIK's magic file and
`file` is installed, with `file(1)` itself (the magic file is not shipped
here). It deliberately differs from `file(1)` in four documented ways; see
the header of `include/abr/identify.hpp`.

### Rockchip KRNL images

The `kernel.img` and `boot.img` of Rockchip devices are `"KRNL"`, the size
of the payload (u32 le), the payload and a CRC (u32 le). The payload is a
kernel or -- in the `boot.img` of the Rockchip Android SDK, and what Android
Image Kitchen takes it for -- a compressed cpio ramdisk. `abr` looks at the
payload once it is decompressed: a cpio archive becomes `ramdisk.cpio` and
the `ramdisk/` directory like any other ramdisk, anything else is `kernel`.
The CRC is Rockchip's own: most significant bit first, start value 0, no
reflection, no final inversion, over the payload only, and with the
polynomial 0x04C10DB7 -- the usual CRC-32 polynomial 0x04C11DB7 with one
digit changed (a slip in the table of Rockchip's tools), so no library CRC-32
gives it. It is made afresh after an edit; a CRC that was not the payload's
in the original (a damaged dump) is said at `unpack`, kept as it was while
the payload is untouched, and made right once the payload is edited. A dump
of a whole partition (zeros after the CRC) is kept at its size. The test
suite makes images with a Python tool of its own and, where `ABR_RKCRC`
names a compiled `rkcrc` (from rkflashtool, BSD; the CI compiles it), checks
that `rkcrc -k` writes the same bytes.

### ASUS blobs

ASUS packs images into blobs (the "ASUS Blob Signature" of Android Image
Kitchen; the format `blobpack` of BlobTools writes): a 60-byte header
(`"MSM-RADIO-UPDATE"`, the version 0x00010000, its own size, the offset of the
table, the number of partitions), a 16-byte entry per partition (a name of four
characters at most, such as `LNX` or `SOS`, the offset counted from the start of
the blob, the size, the version), and the data of the partitions one after the
other. A *signed* blob has 28 bytes in
front of all that -- `"-SIGNED-BY-SIGNBLOB-"`, the length of the blob
(`datalen`) and the length of the signature (`siglen`) -- and the signature
behind the data. Android Image Kitchen unpacks a blob that holds one image
with `blobunpack`, and packs it again as `-SIGNED-BY-SIGNBLOB-` and eight zero
bytes in front of `blobpack`'s output (`datalen` and `siglen` 0).

`abr` does the same without either program. A blob of one partition that holds
an image `abr` reads (a boot image in the partition `LNX`, say) is a wrapper,
like DHTB: `unpack` writes the directory of that image and
`has_blob=true`, `blob_part0_name=LNX` and the other fields of the blob into the
manifest, and `repack` puts the blob back around the repacked image (under the
blob there may be the amonet patch; the three wrappers come off and go on in
order). Any other blob -- several partitions, or one that holds no image -- is
a directory of its own: `type=blob`, a file `part<i>_<NAME>.bin` for every
partition, which can be replaced by a file of another size (the offsets after
it move the way `blobpack` lays them out). `info` lists the partitions and says
which are images.

What the signature is worth after an edit is not something `abr` can know. It
is kept where it was, behind the data (`blob_tail.bin`); `datalen` follows the
blob when it was the length of the blob in the original (a blob made by AIK has
`datalen` 0, and keeps it); and when the blob has changed and a signature is
kept, `repack` says that the signature no longer fits. Only the layout
`blobpack` writes is read (a header of 60 bytes, the table right behind it, the
partitions one after the other with no gap): a blob laid out differently, a cut
one, and a SIGNBLOB header with no blob behind it are refused with the reason,
so that nothing is lost silently. The test suite makes its blobs with a Python
tool of its own, written from the layout of BlobTools, and, where `ABR_BLOBPACK`
and `ABR_BLOBUNPACK` name a compiled `blobpack` and `blobunpack` (AndroidRoot's
BlobTools, Apache-2.0; the CI compiles them), has the real tools make and read
the same blobs.

### Intel OSIP images

Android Image Kitchen opens Intel's boot image for Android devices with
`mboot` (osm0sis', after Jocelyn Falempe's `mboot.py`). The layout,
as `mboot` reads and writes it: an optional 512-byte OSIP header (`"$OS$"`, 0, 0,
1, ...), a signature of 0, 480, 728 or 1024 bytes, 1024 bytes of cmdline, 3072
bytes of image info (the sizes of the kernel and the ramdisk, an 8-byte
"parameter", padding), a bootstub of 4096 (or 8192) bytes, the kernel, the
gzip-compressed ramdisk, and padding up to a whole 512-byte sector.

`unpack` writes `kernel`, `bootstub.bin`, the ramdisk as `ramdisk.cpio` and as
the directory `ramdisk/` (as for a boot image), `osip_header.bin` and
`osip_sig.bin` where the image has them, and the cmdline and the parameter into
`manifest.txt`. `repack` does what `mboot` does when it packs: the size of the
image in sectors (offset 48 of the header), the "unsigned" bit of the image type
(offset 52, set when there is no signature: 0 is a signed boot image, 1 an
unsigned one, 0x0C and 0x0D the same for a recovery) and the checksum of the
header (byte 7: the XOR of its first 56 bytes) are made afresh, and the mark a
signed image has behind the parameter (`BD 02 BD 02 BD 12 BD 12`) goes in or out
with the signature. That happens only when the size of the image changed or the
signature was put in or taken away: an image that was not touched comes back as
it was, whatever its header says (a checksum or a sector count that is not right
is reported by `info` and `unpack`, and kept).

To take the signature off an image, delete the line `osip_signature_file=` from
`manifest.txt`; to put one in, name a file of 480, 728 or 1024 bytes there. The
header is kept as `mboot` keeps it, so where the type should change (a signed
image that was unsigned) put the header of a signed image in `osip_header.bin`;
`repack` says so. A signature that is kept after the image changed describes the
original contents, and `repack` says that too.

`mboot` guesses the layout: four letters or digits where the cmdline starts mark
the end of the signature (so it is 0, 480, 728 or 1024 bytes), and letters
behind the bootstub make it 8192 bytes instead of 4096. `abr` makes the same
guess and keeps it if the sizes in the image info fit the file and the ramdisk
starts like one; where `mboot`'s guess is wrong (a cmdline that starts with a
space, a signature that starts with four letters) it takes the layout that fits.
A cmdline with white space at its ends or a line break is kept exactly
(`osip_cmdline_file`), and an image that is a whole partition (a fill behind it)
keeps its size. An image that is cut short, or whose bootstub, signature,
parameter or image info is not what the layout allows, is refused with the
reason and nothing is left behind.

The test suite makes its images with a Python tool of its own, written from
`mboot.c`'s layout, and, where `ABR_MBOOT` names a compiled `mboot` (osm0sis',
GPL-2.0; the CI compiles it), has the real tool pack the same pieces, read what
`abr` unpacked, and take every image `abr` wrote apart and pack it again.

### LOKI images

Android Image Kitchen takes the patch of Dan Rosenberg's `loki_tool` off a boot
or recovery image with `loki_tool unlok`, and puts it on again with
`loki_tool patch`, which needs the `aboot.img` of the phone the image is for.
What the patch makes of a boot image (version 0 header, no second stage): the
header page with `kernel_size` made the padded kernel plus the ramdisk,
`ramdisk_size` 0 (a page for the "LG-type" targets of its table) and
`ramdisk_addr` an address inside the bootloader, and a 148-byte LOKI header at
byte 1024 of it (`"LOKI"`, the type 0 for boot and 1 for recovery, the 128-byte
build the patch was made for, the original kernel and ramdisk sizes, the load
address of the ramdisk); then the padded kernel and ramdisk; a block of 512
bytes (a page for the LG-type targets) of the bootloader's own code with the 64
bytes of the patch laid over its start; and the device tree, not padded.

`abr` reads that without the bootloader. `unpack` writes the directory of the
plain boot image -- the same bytes `loki_tool unlok` writes, except where
`unlok` guesses the size of the block from an address and is wrong (one family
of its targets; `abr` reads the size from the header) -- and `has_loki=true`
with `loki_recovery`, `loki_build`, `loki_patched_ramdisk_addr`,
`loki_patched_ramdisk_size`, `loki_shellcode_offset` and the block as
`loki_block.bin` in the manifest. What follows the image (other data, or a fill
up to the size of the partition) is kept, as for the other wrappers; so are
fields that are not what `loki_tool` writes (another type, a build that is no
text, another load address in the LOKI header). `repack` builds the plain image
and puts the patch back on it. The block is the one that was in the image, so
an image that was not touched comes back as it was, and an edited one is what
`loki_tool patch` makes of the repacked plain image with the `aboot.img` the
image was patched with (the original ramdisk address inside the patch code
follows the plain header). `has_loki=false` leaves the patch out.

What `abr` does not do is patch an image for a bootloader it has no LOKI image
of: finding the signature check in an `aboot.img` and the table of targets are
`loki_tool patch`'s. An image that has the LOKI header but is not what
`loki_tool` makes (a second stage, a header of another version, sizes that do
not add up, no patch code in the first 16 bytes of the block, a cut-short
image) is refused with the reason and nothing is left behind. A command line of
more than 928 characters has no room beside the LOKI header: `repack` says so
and names `has_loki=false`.

The 56 bytes of the patch code are the one thing of loki that is in `abr`
(Copyright (c) 2013 Dan Rosenberg, BSD-2-Clause; the notice is in
`src/legacy/loki.cpp`); the layout was read from its sources.

### ChromeOS kernel blobs

The kernel partition of a Chromebook holds a *vboot* blob: a keyblock (`"CHROMEOS"`, the data key, a checksum or
signature of its own), a preamble (the version of the kernel, the load address of the body, the address and size of the
bootloader, the signature of the body, and its own signature), both padded to 64 KiB, and the body: the kernel
(aligned to 4096), the config (4096 bytes: the command line), the params (4096 bytes: the boot parameters of x86,
zeros on ARM) and the bootloader. Android Image Kitchen opens it with `futility vbutil_kernel --get-vmlinuz` and makes it
again with `futility vbutil_kernel --pack`, always signed with the public developer keys of vboot_reference. `abr` does
both on its own.

`unpack` takes the kernel field out of the body and unpacks that. A boot image (or whatever else `abr` unpacks, DHTB
header and all) in it is a directory of its own and the blob is a wrapper layer around it, like a DHTB header:
`has_chromeos=true` in the manifest. Anything else is a container (`type=chromeos`, the kernel is `chromeos_kernel.bin`).
The keyblock (`chromeos_keyblock.bin`), the version of the preamble (2.0, 2.1, 2.2), the version of the kernel, the flags,
the load address, the address and size of the bootloader, the address of the vmlinuz header, the size of the verification
block, the config (`chromeos_config.txt`), the params and the bootloader (without the zeros that fill their fields), both
signatures and what follows the blob (other data, or the fill up to the size of the partition) are in the manifest and
the files beside it. `info` says which key the keyblock holds (the algorithm: 0 to 17 of vboot, RSA of 1024 to 8192 bits,
the public exponent 65537 or 3, SHA-1, SHA-256 or SHA-512) and whether both signatures are good.

`repack` makes the blob again: the kernel is the image the directory builds, padded with zeros to 4096, and the fields are
what the manifest says. The signatures are **kept** while nothing they cover has changed -- a blob that was not touched
comes back byte for byte, whoever signed it, a bad signature included -- and **made again** when something has. `abr`
has the public developer key of vboot_reference (the one AIK signs with; it protects nothing) and signs with it when the
blob's keyblock holds the developer data key. When the keyblock is somebody else's, `abr` says so and does what AIK does:
it signs with the developer key under the developer keyblock (a Chromebook in developer mode boots that; one that checks the
keyblock against its own keys does not). `--chromeos-key <.vbprivk>` signs with a key of your own, which has to be the data
key of the keyblock (`abr` refuses one that is not), and `--chromeos-keyblock <.keyblock>` puts another keyblock in: `abr`
never signs under a keyblock it has no key for. A plain image whose manifest gets `has_chromeos=true` is made into the blob
that AIK's `futility vbutil_kernel --pack` line makes (version 1, flags 0x1, the developer keys; `futility` makes the
same bytes). `has_chromeos=false` leaves the blob out.

What `abr` does not do: it keeps the keyblock as it is and neither checks nor makes its own signature (a keyblock is signed
by the key of whoever vouches for it: `futility vbutil_keyblock` makes one, and `--chromeos-keyblock` takes it); a blob for x86
(its preamble carries a vmlinuz header: a bzImage that no Android tool opens) is refused, and so is a blob that is not laid
out the way `futility` writes it (signatures anywhere but behind the preamble header, data behind them, a bootloader or kernel
that is not a whole number of 4096 bytes, ...), with the reason and nothing left behind. The public developer keyblock and key
are in `src/legacy/chromeos_devkeys.cpp` (BSD-3-Clause, generated by `tools/gen_chromeos_devkeys.py`; see the licence notes).

### Sony SIN containers

The images in the firmware of Xperia phones (`boot.sin`, `kernel.sin`, `FOTAKernel.sin`, ...) come in a Sony SIN container.
Android Image Kitchen opens one with `sony_dump` (munjeni's anyxperia_dumper), which writes the image that is inside, and
forgets that there was a container: `repackimg.sh` writes the plain image. A SIN is Sony's -- header, hash tables and signature
are theirs, and nothing here could make one for an edited image. `abr` does the same without the program: `unpack` takes the
container off, unpacks what is inside as it would unpack that image on its own (the line that says what was unpacked calls it
`sin-wrapped`, and the self-check is about the image inside) and says that the container is not kept; `repack` writes the plain
image. Under the container the other wrappers (a DHTB header, ...) are what they are anywhere else, and are put back.

The three versions Android Image Kitchen's signature file knows are read: v1 and v2 (`01 00 00 00`, `02 00 00 00`, a header of
its own size plus 16 bytes) and v3 (`"\x03SIN"`, with the size of the header and the size of the data). What follows the header is
the image itself, a loader (an ELF; the image is behind it) or an MMCF block: parts that are an LZ4 block (`LZ4A`) or bytes as
they are (`ADDR`), put one behind the other with 0xFF where the image has a gap, as `sony_dump` does; a part that starts before
the end of what there is goes to the end, and the unpack says so. The LZ4 parts of a large container are decoded on as many
threads as there are (`-j`), and the result is the same for one. `abr info` describes the container.

A container is refused, with the reason and nothing left behind, when it is damaged -- a size that does not fit the file, an entry
shorter than its own fields, a part outside the file, a tag that is not `ADDR` or `LZ4A`, an LZ4 block that does not decode to
the size its entry says (where `sony_dump` goes on with uninitialised memory, or does not stop) -- and when it holds something
`abr` does not unpack: a partition image (a `system.sin` is far beyond the 512 MiB `abr` converts) or any other content, which the
message names. SIN v4 and v5 (newer firmware) are not in Android Image Kitchen's signature file and are not read.

The layout was read from the source of `sony_dump`, which has no licence file: nothing of it is in `abr`, and the test suite
compiles it only to put the same question to it (`ABR_SONY_DUMP`).

### Sony ELF boot images

The boot image of older Xperia phones is an ELF executable whose program headers are the parts of the image: the kernel, the
ramdisk, `ipl`, `rpm`, and the command line (a `PT_NOTE`). Android Image Kitchen opens one with `elftool` (srl3gx's, packaged by
osm0sis). `abr` reads it on its own: the role of a segment is told by its `p_flags` (`0x80000000` the ramdisk, `0x40000000`
`ipl`, `0x01000000` `rpm`, `0x20000000` the command line); one with other flags is the kernel, and, when no flag says which one is
the ramdisk, the next one is, then `extra0`, `extra1`, ... by position. Each is a file of the directory, and the ramdisk is a directory
as in any boot image (see above). The manifest has the class (`is_64bit`), the machine, the flags and address of every segment,
and the `e_entry` when it is not the address of the first one.

`elftool` writes the image one way: the 52-byte ELF header and the 32-byte program headers, zeros up to byte 4096, the data of the
segments one behind the other, `e_entry` the address of the first segment, OS/ABI `0x61`. An image that is laid out so is built
again from the manifest alone. One that is not (another size of the block in front of the data, padding between the segments or
bytes behind the last one, an `e_entry` or OS/ABI byte of its own, `p_align`, a `p_memsz` beyond `p_filesz`, a `p_paddr` that is
not the `p_vaddr`, the data in another order than the program headers, an ELF64 header) is **kept**: the unpack records what is not the
data of a segment (`elf_layout=kept` in the manifest, `.abr_raw/elf_layout.bin`), and a repack puts the segments back into it with
the sizes and offsets of the program headers made for what they now hold -- where `elftool pack` would write the image in its own
layout. A segment without data keeps its place: its `p_offset` moves with the data it was behind. Where the layout cannot be used
(a segment that had no data gets some, the number of segments is another, the file or the manifest lines of the layout are damaged,
an address is too large for an ELF32 header) the repack says so and writes elftool's layout, or, for the address, refuses with the
reason; `abr info` says which layout an image has.

ELF64 headers are read and written, with 56-byte program headers; the layout `abr` writes for one (elftool's, with the larger
headers) is its own generalisation -- `elftool` only does ELF32, and no 64-bit image of a device was at hand to compare with. What
`abr` does not do is what Android Image Kitchen does with an image that has no `rpm` segment: it warns ("ELF format without RPM
detected; will be repacked using AOSP format!") and writes an AOSP boot image. `abr` writes the ELF image it unpacked. An ELF whose
OS/ABI byte is not `0x61` is no boot image to the signature file of Android Image Kitchen (`abr identify` says `ELF (ARM)`, as
`file` does, and AIK stops with "Unrecognized format."); `abr unpack` opens it all the same.

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
  partition size**; a legacy U-Boot uImage keeps what lies behind its data
  the same way (`tail.bin`, `pad_byte`, `pad_to`);
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
- the **bytes behind the NUL** that ends the text of a fixed-size header field: the board name (16 bytes), command line
  (512) and extra command line (1024) of a boot header, the board name, command line and the name of each ramdisk
  fragment of a vendor_boot, the release string of a vbmeta (also in an AVB footer), the name in a uImage header. A text
  that was cut short in place, or a tool that never clears the field, leaves what stood there before: `console=ttyS0`, a
  NUL, then the rest of an older command line. Such a tail goes to `manifest.txt` as `cmdline_tail=`, `board_name_tail=`,
  `extra_cmdline_tail=`, `ramdisk<i>_name_tail=`, `release_string_tail=`, `avb_release_string_tail=`, `name_tail=` --
  as text when every byte is printable ASCII, otherwise as `..._tail_hex=` (hex; it wins if both are there) -- and is
  written back behind the NUL of the text. A clean image has no tail and no such key, so its manifest is what it was.
  If you edit the text, the tail stays where it was relative to the NUL and is cut to what the field has room for. A
  vbmeta header's `reserved` area (80 bytes, `reserved=` in hex, written only when not all zero; `avb_reserved=` for a
  footer) is kept the same way -- a signed vbmeta covers it, so dropping it would make the signature fail. `unpack`
  says so when an image has such bytes, and `info` lists them (`field tails:`, `unmodeled:`, `name tail:`);
- the **bytes in the padding behind a component**. Every component of an image (kernel, ramdisk, second stage, dt,
  recovery dtbo, dtb, boot signature; in a vendor_boot the ramdisk section, the dtb, the ramdisk table and the bootconfig)
  is followed by padding up to the next page boundary, and the format says it is zeros. A tool that does not clear its
  buffer, or that pads with 0xFF, leaves other bytes there. They belong to no component and they are part of the image
  (and of what an AVB footer's digest covers): `abr` keeps them, from the end of the component to the last byte that is
  not zero, in `<component>_padding.bin`, which the manifest names with `<component>_padding_file=`. A component whose
  padding is zeros has neither the file nor the key, so a clean image's directory is what it was. They are written back
  right behind the end of the component, as far as the padding up to the page boundary has room for them: if you edit
  the component, a bigger one leaves less room and cuts them, a smaller one leaves more, and one that ends on a page
  boundary has no padding at all. Take the `*_padding_file` line out of the manifest and that padding is zeros again.
  `unpack` says which components have such bytes and how many (`kernel 720, ramdisk 1402`), and `info` lists them
  (`section padding:`). Dumps whose last padding was trimmed keep working: the bytes the dump holds are kept, and the
  rebuilt image ends where the dump did;
- a **Marvell PXA** header (`pxa=true`, and its `unknown` word);
- the text of `manifest.txt` itself. It is plain text, one `key=value` per line, and a value that would not read
  back as it was -- white space at either end (a command line that ends in a space: there are such images), a line
  break, a quote or a backslash, a control byte -- is written in double quotes with the escapes of C (`\n`, `\t`,
  `\"`, `\\`, `\x1b`), the way `ramdisk.meta` writes a path. Everything else stays as it was, and a manifest written by
  hand or by an earlier `abr` (no quotes, white space around the value, CRLF line ends, `#` comments) reads as before.
  A line break in a command line used to turn what followed it into more keys of the manifest -- among them the names of
  the files `repack` reads. Those names have to lie in the directory of the manifest now: a name with `..`, an
  absolute path, a drive, a backslash or an empty part is refused with the key it came from, and nothing is written;
  `info` and the messages show the text an image has in a name or a command line the same way (also escaping the C1
  controls and bytes that are not UTF-8), and everything abr prints passes a last filter that writes such bytes as `\xNN`:
  a terminal never gets the control bytes of an image, or of a name from the command line.
  (`ABR_UNFILTERED_OUTPUT=1` turns the filter off; the fuzzer below does, to find a message that forgot to escape.)

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

`ABR_KEEP_WORK=1 ./tests/run_tests.sh build/abr` keeps the directory the suite worked in (every image it made,
every directory it unpacked) and says where it is, to look at a failure or to take the images as the seeds of the
fuzzer below.

#### Sanitizers and fuzzing

```sh
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++-14 \
      -DABR_SANITIZE=address,undefined
cmake --build build-asan
```

builds abr's own code with AddressSanitizer and UndefinedBehaviorSanitizer (GCC or Clang, a dynamic build: not
with MSVC, for Windows, or together with `ABR_STATIC_BINARY`; the vendored libraries are not instrumented). The suite
runs on it as it is. A test that expects an error would take a sanitizer's exit status for the error it wanted, so let
the sanitizers write their reports to files and look at the directory afterwards:

```sh
mkdir -p asan-logs
ASAN_OPTIONS=log_path=$PWD/asan-logs/asan:detect_leaks=1:strict_string_checks=1:detect_stack_use_after_return=1 \
UBSAN_OPTIONS=log_path=$PWD/asan-logs/ubsan:print_stacktrace=1:halt_on_error=1 \
    ./tests/run_tests.sh build-asan/abr          # (an empty asan-logs/ is a clean run)
```

`tests/tools/fuzz_images.py` damages images the ways images are damaged (a size field that is too big, a cut-off
file, a flipped bit, a block taken out or doubled, a piece of another image spliced in; the fields of a cpio header)
and runs `identify`, `info`, `unpack` and `repack` on every damaged copy. It does not ask what abr says: an image may be
refused or taken, but abr must not crash, hang, run out of memory, stop with an exception nobody meant to reach, print
a control character (a mutator puts escape sequences into the text an image holds), say nothing and then write another
image from what it unpacked, or give the sanitizers something to report:

```sh
ABR_KEEP_WORK=1 ./tests/run_tests.sh build-asan/abr      # (the images of the suite are the seeds; the last note names the directory)
tests/tools/fuzz_images.py --abr build-asan/abr --seeds <that directory> --iterations 20 --rng-seed 1 --jobs 2
```

A run is determined by `--rng-seed`, the seed and the iteration, so a finding is rebuilt by the same command; the
damaged file is kept with the command and abr's output, and `--repro FILE` runs the commands on a file again.

`tests/tools/fuzz_repack.py` does the same for `repack`, which reads something else: the directory `unpack` wrote, and
that can come from someone else (a downloaded directory, a script, an archive). It unpacks every seed once and damages
the directory the ways a hand edit or a hostile archive would: a value of `manifest.txt` (not a number, a number that does
not fit its field, a count of four billion, a flag that is neither `true` nor `false`, a key twice, a name that leaves the
directory), a component file (cut, grown, a directory, a fifo or a link to `/dev/zero` in its place), the ramdisk
directory and `ramdisk.meta`, the raw copies in `.abr_raw`, the key that signs, the `-o` argument. A directory may be
refused or taken, but `repack` must not crash, hang, run out of memory, stop with an exception of the standard library,
print a control character or a byte that is not UTF-8 (the filter that makes output safe is turned off for the run, to see
the messages that forget to escape), say nothing when it refuses, leave something behind, change the directory it reads or
write an image that depends on `-j` or `-o`, that `unpack` cannot read again, or that does not come back byte for byte:

```sh
tests/tools/fuzz_repack.py --abr build-asan/abr --seeds <that directory> --iterations 10 --rng-seed 1 --jobs 2
```

(`--families`, `--mutators` and `--deep` narrow it down; a finding is kept as a tar file with its command, `--repro FILE.tar`
runs it again.)

Beyond those, the suite compares `abr` with the programs Android Image Kitchen runs for the formats `abr` opens by
itself -- `rkcrc`, `blobpack` / `blobunpack`, `mboot`, `loki_tool`, `pxa-mkbootimg` / `pxa-unpackbootimg`, `sony_dump`,
`elftool` (and `futility`, GNU `cpio`). They are not part of this repository (several have no licence file):
`.github/scripts/build_oracles.sh <directory>` fetches them at the commits the tests were written against, compiles
them and prints the variables that tell the suite where they are (`ABR_RKCRC`, `ABR_BLOBPACK`, `ABR_BLOBUNPACK`,
`ABR_MBOOT`, `ABR_LOKI_TOOL`, `PXA_MKBOOTIMG`, `PXA_UNPACKBOOTIMG`, `ABR_SONY_DUMP`, `ABR_ELFTOOL`). A judge that is not
there is a note in its section and the comparisons with it are skipped; `ABR_REQUIRE_ORACLES=futility,cpio,rkcrc,blobtools,mboot,loki,pxa,sony_dump,elftool`
(any of those names) makes a missing one a failure instead, which is how the CI runs the suite.

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
suite under wine. The `.exe` imports only `KERNEL32.dll`, `msvcrt.dll` and `SHELL32.dll` (for the wide command line).

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

The Rockchip KRNL images are judged by `rkcrc` of rkflashtool (compiled from
its sources, not vendored, used when `ABR_RKCRC` is set): the CRCs it wrote for
four payloads are what a Python tool of the suite and `abr` compute, and every
image `abr` writes -- untouched, with an edited ramdisk, with an edited kernel,
with a ramdisk file added -- is what `rkcrc -k` writes from the same payload.

The amonet patch is judged by the commands Android Image Kitchen itself runs
for it (`dd`, `truncate` and `cat`, copied from its `unpackimg.sh` and
`repackimg.sh`): they make the patched images the tests start from and take
the patch off again, and what `abr` repacks after an edit is what they make of
the plain repack. (No real Amazon image has been tried: none was at hand.)

The ASUS blobs are judged by the real `blobpack` and `blobunpack` of BlobTools
(compiled from its sources, not vendored, used when `ABR_BLOBPACK` and
`ABR_BLOBUNPACK` are set) and by a Python tool of the suite: the signed blob
AIK makes (its 28 bytes, then `blobpack`'s output) is what `abr` writes, a blob
with an edited ramdisk, a new partition size or a signature behind it is read by
both, and `blobunpack` finds in it the partition that was put there. (No real
ASUS blob has been tried: none was at hand.)

The Intel OSIP images are judged by the real `mboot` of osm0sis (compiled from its
sources, not vendored, used when `ABR_MBOOT` is set) and by a Python tool of the
suite: images with a header or without one, unsigned or signed (signatures of 480,
728 and 1024 bytes), with a bootstub of 4096 or 8192 bytes, are packed to the same
bytes by both; `abr` unpacks them into the pieces `mboot -u` writes; an untouched
repack is identical; and an image with an edited ramdisk, with the signature taken
off or one put in, is a fixed point of `mboot` (`mboot -u`, then `mboot` on its
pieces: the same bytes). (No real Intel image has been tried: none was at hand.)

The LOKI images are judged by the real `loki_tool` (Dan Rosenberg's loki,
BSD-2-Clause; compiled from its sources, not vendored, used when `ABR_LOKI_TOOL`
is set) and by a Python tool of the suite (`tests/tools/loki_tool.py`, written
from loki's layout), against synthetic bootloader images: random bytes with the
bytes `loki_tool patch` looks for, at the addresses of six entries of its table
(the patch code 0, 4, 8 and 12 bytes into a block of 512 bytes or of a page).
Both patch the same plain images -- boot and recovery, with and without a device
tree, pages of 2048 and 4096 bytes, sizes that are whole pages, a long cmdline --
to the same bytes; `abr` unpacks them into the plain image's directory (what
`loki_tool unlok` writes); an untouched repack is identical; and what `abr`
repacks after an edit of the ramdisk, the kernel, the device tree or the header
fields is what `loki_tool patch` makes of the plain image the same directory
builds without the patch. (No real LOKI image has been tried: none was at hand.)

The ChromeOS kernel blobs are judged by a Python tool of the suite (`tests/tools/chromeos_tool.py`, written from
vboot_reference's `2struct.h` and `cmd_vbutil_kernel.c`, its RSA is Python's own integers) and, where `futility` is
installed (`ABR_FUTILITY`, or on the `PATH`; the CI installs `vboot-kernel-utils`), by the real `futility vbutil_kernel`.
Nine kinds of blob -- the preambles 2.0, 2.1 and 2.2; RSA keys of 1024, 2048, 3072 and 4096 bits, public exponents 65537
and 3, SHA-1, SHA-256 and SHA-512; kernels that need padding up to 4096 and kernels that do not -- are made by the tool,
verified by `futility`, unpacked and repacked to the same bytes; what `abr` repacks after an edit is the blob the tool makes
of the image the directory builds without the blob (with every field of the manifest changed, too), and, for what it has
options for, the blob `futility --pack` makes; `futility --repack` makes the blob `abr` signs under another keyblock; a plain
image given `has_chromeos=true` becomes the blob of AIK's command line, byte for byte; 21 kinds of layout that `futility`
does not write are refused with the reason; signatures that are bad stay as they were until an edit; a blob around a DHTB
header, a container of random bytes, and (with `ABR_REAL_IMAGES`) every real image wrapped by the tool round-trip. (No real
Chromebook kernel partition has been tried: none was at hand; the blobs hold Android boot images. The 8192-bit algorithms
are in the code and not in the tests.)

The Sony SIN containers are judged by a Python tool of the suite (`tests/tools/sin_tool.py`, written from the layout of
`sony_dump`; it shares no code with `abr`) and, where it is built from its source (`ABR_SONY_DUMP`; not vendored: the source has
no licence file), by the real `sony_dump`. The tool makes containers of versions 1, 2 and 3 -- the image behind the header, a
loader, data in front of the image, MMCF blocks with `ADDR` and `LZ4A` parts, gaps filled with 0xFF, parts put at the end, entries
longer than their fields, 60 parts, 18 MiB on several threads -- and `abr` and `sony_dump` write the same image from each; the
unpack of a container is the unpack of that image, a repack is that image and no container, an edit in the directory lands in the
plain image, and with `ABR_REAL_IMAGES` every real image wrapped as v3 and as v1 (`LZ4A`) comes back as it was. Damaged
containers are refused with the reason: the unit tests (`abr_unit_tests legacy`) feed 40,000 mutated ones and 40,000 mutated ELF
images to the readers, which have to take each or refuse it with the reason, and do nothing else. (No real `.sin` file has been
tried: none was at hand; the containers are made by the tool.)

The Sony ELF boot images are judged by a Python tool of the suite (`tests/tools/elf_tool.py`, written from the layout of `elftool`
and from the ELF format; it shares no code with `abr`), by an independent writer in the unit tests, and, where it is built from its
sources (`ABR_ELFTOOL`; not vendored), by the real `elftool`. Sixteen layouts -- `elftool`'s with three and with five segments, a
kernel alone, an empty ramdisk, segments without flags, ELF64, data from byte 8192, data right behind the program headers, padding
and a tail, an own `e_entry`/OS/ABI/`p_align`/`p_memsz`, the data in another order, a block in front that is not zeros, a `p_paddr`
of its own, program headers that are not behind the ELF header, an empty segment in a layout that is not `elftool`'s, and an ELF64
with all of that -- are unpacked; the segments are what the independent reader finds
in them; GNU cpio agrees with the ramdisk directory; an untouched repack is the image; and an edited kernel, an edited ramdisk
directory and another address in the manifest give the image the independent writer makes of the same layout. For the images in
`elftool`'s layout, `elftool pack` puts the parts of the image together into the same bytes and `elftool unpack` finds them again,
also for what `abr` repacked after an edit. (`elftool` cannot pack a single part nor an ELF64 file, and its `unpack` writes an
`rpm` segment into the file `ramdisk` -- a missing `break` in its source -- so the comparison leaves those out.) A layout that
cannot be used for a repack is said in a warning, with elftool's layout written instead. (No real `kernel.elf` of a device has
been tried: none was at hand.)

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
- The rest of the Android Image Kitchen format list: QCDT tooling.
  `abr identify` already names it; what is missing is unpacking and packing
  it. See `PROGRESS.md` for the plan. (Sony SIN is read, and never written:
  the container is Sony's. SIN v4 and v5 are not read.)
- U-Boot's newer FIT (Flattened Image Tree) format -- only the older
  legacy `mkimage` container is supported.
- Filesystems (ext4, F2FS, EROFS, SquashFS) and sparse images: out of
  scope; see the sibling tools in the same suite.

## License

GPL-3.0-or-later, see `LICENSE`. A binary of `abr` contains code of zlib, LZ4, Zstandard, liblzma and bzip2 (and the
runtime of the toolchain): their notices are in `THIRD_PARTY_NOTICES.md`, which the CI publishes next to the binaries.
A few directories are vendored
third-party code, used only by parts of `abr` (`third_party/minilzo`)
or only by the test suite (`tests/reference/mkbootimg`,
`tests/reference/avb`, `tests/reference/boot_signer`), each with its own
README explaining exactly what and why -- see those for details:

- `third_party/minilzo/`: LZO1X compress/decompress, GPL-2.0-or-later
  (compatible with, and combined here under, this project's own
  GPL-3.0-or-later).
- `src/legacy/loki.cpp`: 56 bytes of machine code (the patch of `loki_tool`,
  https://github.com/djrbliss/loki), Copyright (c) 2013 Dan Rosenberg,
  BSD-2-Clause; the full notice is kept in that file, and has to go with a
  binary distribution of `abr` (the notice of the licence, in the documentation
  or other material).
- `src/legacy/chromeos_devkeys.cpp`: the public developer keyblock and signing key of vboot_reference
  (`tests/devkeys`, https://chromium.googlesource.com/chromiumos/platform/vboot_reference), Copyright (c) 2010 The
  Chromium OS Authors, BSD-3-Clause; generated by `tools/gen_chromeos_devkeys.py`. The full notice is kept in that file
  and has to go with a binary distribution of `abr`. The private half has been public for years: the key protects
  nothing, it is there so that a blob can be signed the way Android Image Kitchen signs it.
- Nothing of `sony_dump` (munjeni's anyxperia_dumper, no licence file) and nothing of `elftool` (srl3gx's, as packaged by
  osm0sis; no licence text in its sources) is in `abr` or in this repository: the layouts were read from their sources, and the
  test suite runs the two programs, compiled from those sources by whoever runs it, only to put the same question to them.
- `tests/reference/mkbootimg/`: AOSP's `mkbootimg.py` and friends,
  Apache-2.0, not linked into the `abr` binary at all.
- `tests/reference/avb/`: AOSP's `avbtool.py`, MIT, used only as the
  oracle for the AVB tests.
- `tests/reference/boot_signer/`: AOSP's `boot_signer` (Java sources, with
  its public "verity" test key pair), Apache-2.0, used only as the oracle
  for the AVBv1 tests. `src/legacy/avb1_aosp_key.cpp` embeds the same
  public test key (Apache-2.0, generated by `tools/gen_aosp_verity_key.py`;
  it is the default signer of Android Image Kitchen and protects nothing).
