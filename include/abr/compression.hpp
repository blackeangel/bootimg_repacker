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

// Decompresses `data` (which must actually be in `codec` format; use
// detect_codec() first if unsure). Codec::NONE returns `data` unchanged.
Bytes decompress(Codec codec, const Bytes& data);

// Compresses `data` with `codec`. `level` is codec-specific; -1 selects
// a sensible per-codec default (lz4_legacy: HC level 12, what Android's
// `lz4 -l -12` uses). Codec::NONE returns `data` unchanged.
//
// May use several threads (abr/parallel.hpp): the independent 8 MiB blocks of
// an lz4_legacy stream, the workers of a zstd frame. The output is the same for
// any number of threads.
Bytes compress(Codec codec, const Bytes& data, int level = -1);

// The densest setting of a codec that the decoders in the wild still take (gzip 9, zstd 19 -- an 8 MiB
// window, what `zstd -19` writes --, xz 9, lz4 frame 12); -1 where the usual setting (-1 above) already
// is the densest, or the codec has no setting. For when the usual one makes an edited image too big for
// its partition: the images of builds that care about size were compressed this way in the first place.
int dense_level(Codec codec);

}  // namespace abr
