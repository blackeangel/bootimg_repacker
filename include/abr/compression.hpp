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
// a sensible per-codec default. Codec::NONE returns `data` unchanged.
Bytes compress(Codec codec, const Bytes& data, int level = -1);

}  // namespace abr
