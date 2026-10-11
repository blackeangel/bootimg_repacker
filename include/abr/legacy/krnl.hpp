// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::krnl -- Rockchip "KRNL" images: what Rockchip's tools call kernel.img or boot.img.
//
//     "KRNL"   u32 le payload size   payload   u32 le CRC
//
// The payload is a kernel or -- what Android Image Kitchen takes it for, and what the Rockchip Android
// SDK writes into boot.img -- a gzip-compressed cpio ramdisk. The CRC is Rockchip's own CRC-32: most
// significant bit first, start value 0, no reflection, no final inversion, taken over the payload only
// (not over the 8 header bytes) -- and with the polynomial 0x04C10DB7. That is the usual CRC-32
// polynomial 0x04C11DB7 with one digit changed (a slip in Rockchip's table that every tool of theirs
// carries), so no library CRC-32 gives it.
//
// The format is rkcrc's (rkflashtool: Fukaumi Naoki, Ivo van Poorten; BSD licence). abr has code of its
// own for it; rkcrc -k is what the test suite compares it with.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "abr/byte_io.hpp"

namespace abr::legacy {

constexpr uint8_t kKrnlMagic[4] = {'K', 'R', 'N', 'L'};
constexpr size_t kKrnlHeaderSize = 8;   // magic + payload size
constexpr size_t kKrnlTrailerSize = 4;  // the CRC

// Rockchip's CRC-32 of `size` bytes, continuing from `crc` (0 to start).
uint32_t rkcrc32(const uint8_t* data, size_t size, uint32_t crc = 0);
inline uint32_t rkcrc32(const Bytes& data) { return rkcrc32(data.data(), data.size()); }

struct KrnlImage {
    Bytes payload;
    uint32_t crc = 0;    // parse(): the CRC the file held
    bool crc_ok = true;  // parse(): it is the CRC of the payload

    // The data starts with "KRNL" (whatever follows).
    static bool looks_like(const Bytes& data);
    // Throws FormatError when the size field says more than the file holds (a cut-short file).
    static KrnlImage parse(const Bytes& data);

    // How many bytes of the file the image takes: header, payload and CRC (what follows is not part of it).
    size_t file_size() const { return kKrnlHeaderSize + payload.size() + kKrnlTrailerSize; }

    // The file. The CRC written is the payload's, unless `crc` is given (an image whose own CRC was wrong
    // is put back as it was when its payload is untouched).
    Bytes build(std::optional<uint32_t> crc = std::nullopt) const;
};

}  // namespace abr::legacy
