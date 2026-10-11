// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::amonet -- the "amonet" patch of a boot image (Amazon's MediaTek Fire tablets; Android
// Image Kitchen calls it AMONET).
//
// The patch puts a 1024-byte "microloader" at the start of the image and moves the first 1024 bytes of the
// boot image -- its header -- behind it, so that "ANDROID!" is no longer at offset 0 but at 1024:
//
//     patched image                                original boot image
//     [0, 1024)     microloader                    [0, 1024)     the header (v0: 608 bytes, then zeros)
//     [1024, 2048)  the original [0, 1024)         [1024, 2048)  zeros: the rest of the first page
//     [2048, ...)   the original [2048, ...)       [2048, ...)   kernel, ramdisk, ... as before
//
// What the patch loses is the original [1024, 2048): the padding of the first 2048-byte page behind a header
// that needs no more than 1024 bytes. Android Image Kitchen puts zeros there when it takes the patch off
// again, and so does abr; putting the patch on refuses an image that has anything but zeros there (a header
// of version 1 or 2 is longer than 1024 bytes: the microloader would overwrite its end).
//
// The reference is Android Image Kitchen's unpackimg.sh / repackimg.sh, which do it with dd, truncate and
// cat; the test suite runs those very commands and compares.
#pragma once

#include <cstddef>
#include <optional>

#include "abr/byte_io.hpp"

namespace abr::legacy {

constexpr size_t kAmonetMicroloaderSize = 1024;
constexpr size_t kAmonetHeadSize = 1024;  // the header moved behind the microloader
constexpr size_t kAmonetPrefixSize = kAmonetMicroloaderSize + kAmonetHeadSize;  // up to where the original goes on

struct AmonetInfo {
    Bytes microloader;  // kAmonetMicroloaderSize bytes: what was at the start of the patched image
};

// Android Image Kitchen's signature (androidbootimg.magic): "ANDROID!" at offset 1024 and the word
// "microloader" somewhere in the start of the file, behind offset 96.
bool has_amonet_patch(const Bytes& data);

// Takes the patch off: `original_out` is the boot image as it was (same size as `data`). If `data` is
// not patched, std::nullopt comes back and `original_out` is left alone (use `data`, there is no copy
// of it). A patched image shorter than 2048 bytes is refused.
std::optional<AmonetInfo> strip_amonet(const Bytes& data, Bytes& original_out);

// Puts the patch on `image` (same size back). Refuses a microloader that is not 1024 bytes, an image
// shorter than 2048 bytes, and an image that has something but zeros in [1024, 2048).
Bytes apply_amonet(const Bytes& image, const AmonetInfo& info);

}  // namespace abr::legacy
