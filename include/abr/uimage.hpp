// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::UImage -- parser/builder for the U-Boot "legacy" image format
// (mkimage's classic 64-byte header, magic 0x27051956). This is the
// format used to wrap a kernel/ramdisk/FDT/firmware blob for U-Boot-based
// bootchains, which several Android-TV-box- and STB-class devices use
// ahead of (or instead of) an AOSP-style boot.img. Field layout, the
// os/arch/type/compression enumerations (including zstd, IH_COMP_ZSTD)
// and "all fields big-endian" are verified against U-Boot's own
// include/image.h (struct legacy_img_hdr).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "abr/byte_io.hpp"

namespace abr {

constexpr uint32_t kUimageMagic = 0x27051956;
constexpr size_t kUimageNameSize = 32;
constexpr size_t kUimageHeaderSize = 64;

std::string_view uboot_os_name(uint8_t v);
std::string_view uboot_arch_name(uint8_t v);
std::string_view uboot_type_name(uint8_t v);
std::string_view uboot_comp_name(uint8_t v);

struct UImage {
    uint32_t timestamp = 0;
    uint32_t load_addr = 0;
    uint32_t entry_point = 0;
    uint8_t os = 5;      // IH_OS_LINUX
    uint8_t arch = 2;    // IH_ARCH_ARM
    uint8_t type = 2;    // IH_TYPE_KERNEL
    uint8_t comp = 0;    // IH_COMP_NONE (0=none,1=gzip,2=bzip2,3=lzma,4=lzo,5=lz4,6=zstd)
    std::string name;    // <=32 bytes
    Bytes data;          // payload, exactly as stored (still compressed per `comp`)

    static UImage parse(const Bytes& image);
    Bytes build() const;
};

}  // namespace abr
