# Vendored: miniLZO (LZO1X compress/decompress subset)

`minilzo.c`, `minilzo.h`, `lzoconf.h`, `lzodefs.h`, `lzo1x.h` are
copied unmodified from the LZO real-time data compression library by
Markus F.X.J. Oberhumer (<https://www.oberhumer.com/opensource/lzo/>),
version 2.10, via the `nemequ/lzo` GitHub mirror
(<https://github.com/nemequ/lzo>). Original copyright/license headers
are kept intact in each file.

License: GPL-2.0-or-later (see the header comment in each file). This
is compatible with this project's own GPL-3.0-or-later license -- "or
later" on the LZO side means it can be used under GPL-3 terms, which
is how it's combined here. miniLZO is deliberately just the LZO1X
compress/decompress subset (not the full LZO package with its many
compression variants, tests, and utilities), which is all `abr` needs.

Used by `src/compression.cpp` (`Codec::LZO`), wrapped in the lzop
container framing (magic + block headers) that the Linux kernel's own
`lib/decompress_unlzo.c` expects -- raw LZO1X has no self-describing
header at all, so *some* framing is required for auto-detection and
for a bootloader/kernel to actually be able to decompress it; the lzop
framing is what real Android/kernel tooling already uses for this.
