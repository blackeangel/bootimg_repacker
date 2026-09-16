// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::DtboImage -- parser/builder for dtbo.img (Device Tree Blob Overlay
// table). Field layout and big-endian byte order verified against AOSP
// system/libufdt utils/src/{dt_table.h,mkdtboimg.py} and the vendored
// copy in u-boot's include/dt_table.h.
#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {

constexpr uint32_t kDtTableMagic = 0xd7b7ab1e;
constexpr uint32_t kAcpioTableMagic = 0x41435049;  // 'ACPI' read as a big-endian u32

struct DtboEntry {
    uint32_t id = 0;
    uint32_t rev = 0;
    // Raw words 4..7 of the on-disk 8-word entry:
    //   header version 0: custom[0..3]
    //   header version 1: flags, custom[0..2]  (flags replaces custom[3])
    std::array<uint32_t, 4> extra{};
    Bytes data;  // always the *decompressed* DTB/ACPI blob

    // Meaningful only for dt_table_header version 1: low nibble of
    // `extra[0]` ("flags") selects per-entry compression:
    //   0 = none, 1 = zlib, 2 = gzip
    uint32_t compression() const { return extra[0] & 0x0f; }
    void set_compression(uint32_t c) { extra[0] = (extra[0] & ~0x0fu) | (c & 0x0fu); }
};

struct DtboImage {
    uint32_t version = 0;  // 0 or 1
    uint32_t page_size = 2048;
    bool acpio = false;  // ACPIO table vs. plain DTBO table (same container format)
    std::vector<DtboEntry> entries;

    static DtboImage parse(const Bytes& image);
    Bytes build() const;
};

}  // namespace abr
