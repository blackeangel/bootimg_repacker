// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::compression -- codec detection + (de)compression for the blobs
// embedded in Android boot-family images (kernel, ramdisk, vendor
// ramdisk fragments, dtb, ...).
//
// Magic bytes for gzip/lz4/lz4-legacy/xz/bzip2 detection follow the same
// values used by Magisk's magiskboot (native/src/boot/format.rs) so files
// produced by this tool and by Magisk classify identically. zstd support
// is this project's own addition -- neither AOSP's mkbootimg nor current
// Magisk auto-detect it.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "abr/byte_io.hpp"

namespace abr {

enum class Codec {
    NONE,
    GZIP,
    LZ4_LEGACY,  // Android GKI ramdisk format: magic + sequence of {u32 le size, block}
    LZ4,         // standard LZ4 frame format (liblz4 "frame" API)
    ZSTD,
    XZ,     // .xz container
    LZMA,   // legacy "LZMA alone" stream (no container), as used by 7-Zip's .lzma
    BZIP2,
    LZO,    // LZO1X wrapped in the lzop container framing (see compression.cpp for why)
};

std::string_view codec_name(Codec c);
std::optional<Codec> codec_from_name(std::string_view name);

// Sniffs the codec from the leading bytes of `data`. Returns Codec::NONE
// if nothing recognizable is found (i.e. the data is treated as raw).
Codec detect_codec(const Bytes& data);

// The most a decoder lets a stream become: no kernel, ramdisk or device tree of the family comes near a gigabyte (the same as
// the largest image, kMaxImageSize), and a stream of a few kilobytes can ask for many times that -- a gzip of zeros is a
// thousandth of what it holds -- so what a damaged or a made-up one would take of the memory has to stop somewhere.
inline constexpr size_t kMaxDecompressedSize = 0x40000000;

// Decompresses `data` (which must actually be in `codec` format; use
// detect_codec() first if unsure). Codec::NONE returns `data` unchanged.
//
// A FormatError when the stream is damaged, and when the plain data would be more than `max_size` bytes: the decoders
// never hold more than that in memory (a decoder that works in a buffer of its own has one byte more, to tell "exactly
// max_size" from "more", and one that makes the buffer larger as it goes needs the old and the new at the same moment).
// Exactly `max_size` bytes is taken.
Bytes decompress(Codec codec, const Bytes& data, size_t max_size = kMaxDecompressedSize);

// Compresses `data` with `codec`. `level` is codec-specific; -1 selects
// a sensible per-codec default (lz4_legacy: HC level 12, what Android's
// `lz4 -l -12` uses). Codec::NONE returns `data` unchanged.
//
// May use several threads (abr/parallel.hpp): the independent 8 MiB blocks of
// an lz4_legacy stream, the workers of a zstd frame. The output is the same for
// any number of threads.
//
// `on_progress`, when there is one, is told how many more bytes of `data` have been compressed -- the work as it is done, for a bar --
// by whichever thread did it; what it is told adds up to data.size() when compress() returns (gzip and lz4_legacy say it as they go, the
// other codecs when they are done).
Bytes compress(Codec codec, const Bytes& data, int level = -1, const std::function<void(size_t)>& on_progress = {});

// The level compress() uses when it is given none (-1): gzip 6, lz4_legacy 12 (HC, the densest), lz4 frame 0, zstd 3, xz 6, bzip2 9; -1 for the
// codecs that have no setting (lzma, lzo, none).
int default_level(Codec codec);

// The densest setting of a codec that the decoders in the wild still take (gzip 9, zstd 19 -- an 8 MiB
// window, what `zstd -19` writes --, xz 9, lz4 frame 12, lz4_legacy 12, bzip2 9); -1 where the codec has
// no setting. For when the usual one makes an edited image too big for its partition: the images of
// builds that care about size were compressed this way in the first place. A codec whose default_level()
// is already this one has nothing denser to try.
int dense_level(Codec codec);

// What is known of the setting a stream was made with, so that a component that is edited is compressed again the same way (the
// `<part>_level` of the manifest).
struct LevelGuess {
    int level = -1;     // the `level` of compress() that makes this stream (or its start): -1 when nothing is known
    std::string basis;  // how it is known, for a person: "the header says ...", "compress() at this level makes the same bytes"
};

// `stored` is a stream of `codec` (what detect_codec() said it is) and `plain` what it holds. bzip2 tells its level in its header; gzip
// tells whether it is the densest (9) or the fastest (1) setting; for the others, and for a gzip with no mark, the stream is made again
// at the levels in use -- all of it when it is small, the first blocks of it when the codec has blocks that stand on their own (lz4_legacy,
// zstd) -- and the first level that makes the bytes of the stream is the one. A stream that another program made in another way (GNU gzip's
// own deflate, an xz stream with its own check, an lz4 frame with its own block size) is not made again by abr: -1, and the manifest
// says no level (compress() then uses its usual one). Slow only where it has to be: a few seconds at most, on the thread that calls it.
LevelGuess detect_level(Codec codec, const Bytes& stored, const Bytes& plain);

}  // namespace abr
