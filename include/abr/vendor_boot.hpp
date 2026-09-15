// SPDX-License-Identifier: MIT
//
// abr::VendorBootImage -- parser/builder for the vendor_boot container
// (header v3/v4). Per AOSP's own layout notes ("For partitions: /vendor_boot
// or /vendor_kernel_boot"), vendor_kernel_boot.img is the *same* container
// format as vendor_boot.img -- Pixel 7+ simply split what used to be one
// vendor_boot partition into two, both still v4 vendor-boot images. This
// class therefore covers vendor_boot.img, vendor_boot-debug.img and
// vendor_kernel_boot.img alike.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {

constexpr char kVendorBootMagic[] = "VNDRBOOT";
constexpr size_t kVendorBootMagicSize = 8;
constexpr size_t kVendorBootArgsSize = 2048;
constexpr size_t kVendorBootNameSize = 16;
constexpr size_t kVendorRamdiskNameSize = 32;
constexpr size_t kVendorRamdiskTableEntrySize = 108;  // 4+4+4+32+16*4

std::string_view vendor_ramdisk_type_name(uint32_t type);
uint32_t vendor_ramdisk_type_from_name(std::string_view name);

struct VendorRamdiskEntry {
    uint32_t type = 1;  // VENDOR_RAMDISK_TYPE_PLATFORM
    std::string name;   // <=32 bytes; unused/empty for header v3
    std::array<uint32_t, 16> board_id{};
    Bytes data;  // fragment payload, exactly as stored on disk (still compressed)
};

struct VendorBootImage {
    uint32_t header_version = 4;  // 3 or 4
    uint32_t page_size = 4096;
    uint32_t kernel_addr = 0x00008000;
    uint32_t ramdisk_addr = 0x01000000;
    uint32_t tags_addr = 0x00000100;
    std::string board_name;
    std::string cmdline;  // <=2048 bytes
    uint64_t dtb_addr = 0x01f00000;

    Bytes dtb;
    Bytes bootconfig;  // v4 only

    // Header v3 has exactly one (unnamed, untyped) fragment; header v4 may
    // have several. Either way this vector is the source of truth for the
    // vendor ramdisk section.
    std::vector<VendorRamdiskEntry> ramdisk_fragments;

    static VendorBootImage parse(const Bytes& image);
    Bytes build() const;

    Bytes concatenated_ramdisk() const;
};

}  // namespace abr
