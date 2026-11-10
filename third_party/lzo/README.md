# Vendored: LZO 2.10, the LZO1X family

The LZO real-time data compression library of Markus F.X.J. Oberhumer, version 2.10 (1 March 2017, the latest release of
the library), <https://www.oberhumer.com/opensource/lzo/>. The files are copied unmodified from the GitHub mirror
<https://github.com/nemequ/lzo> (commit `0083878c235a89ef96a009d1ff0b500f3a364e4b`, "Release 2.10"); the four public
headers in `include/lzo/` are byte for byte those of the `liblzo2-dev` 2.10 package of Debian. The copyright and licence
headers are kept in every file; the licence is GPL-2.0-or-later (`COPYING`), which `abr` uses under the GPL-3.0-or-later of the
rest of the project ("or later" is what makes the two fit).

Only what the LZO1X family needs is here -- the format of every LZO stream that Linux, U-Boot, `lzop` and the phones'
firmware write -- and not the other families of the library (LZO1, LZO1A, LZO1B, LZO1C, LZO1F, LZO1Y, LZO1Z, LZO2A), the
tests and the utilities:

| what | files |
|---|---|
| LZO1X-1, the fast compressor (`lzop -2` to `-6`, and the default) | `src/lzo1x_1.c` |
| LZO1X-1(15), the fastest (`lzop -1`) | `src/lzo1x_1o.c` |
| LZO1X-999, the dense compressor, levels 1 to 9 (`lzop -7` to `-9`, what the kernel's build uses for `Image.lzo` and the initramfs) | `src/lzo1x_9x.c` with `lzo_mchw.ch`, `lzo_swd.ch` |
| the optimizer of compressed blocks (`lzo1x_optimize`: the same size, a stream that decompresses faster; `lzop` runs it on the blocks of the dense compressor) | `src/lzo1x_o.c` with `lzo1x_oo.ch` |
| the decompressors (`lzo1x_decompress`, `lzo1x_decompress_safe`; one format, whatever compressor made the stream) | `src/lzo1x_d1.c`, `src/lzo1x_d2.c` with `lzo1x_d.ch`, `lzo1_d.ch` |
| the library's own checks and helpers | `src/lzo_init.c`, `lzo_ptr.c`, `lzo_str.c`, `lzo_util.c`; headers `lzo_conf.h`, `lzo_dict.h`, `lzo_func.h`, `lzo_ptr.h`, `lzo_supp.h`, `config1x.h`, `lzo1x_c.ch`, `lzo_dll.ch` |

The sources are compiled by `cmake/vendor_deps.cmake` into the static library `lzo_static`. `src/compression.cpp` (`Codec::LZO`)
puts the compressed blocks into the framing of the `lzop` file, which is what the kernel's `lib/decompress_unlzo.c` and U-Boot
read: raw LZO1X has no header of its own, nothing to tell a decompressor how big the blocks are.

This directory replaces `third_party/minilzo/` (the miniLZO amalgamation, which has the LZO1X-1 compressor only).
