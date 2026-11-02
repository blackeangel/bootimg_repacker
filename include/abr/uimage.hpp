// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::UImage -- parser/builder for the U-Boot "legacy" image format
// (mkimage's classic 64-byte header, magic 0x27051956). This is the
// format used to wrap a kernel/ramdisk/FDT/firmware blob for U-Boot-based
// bootchains, which several Android-TV-box- and STB-class devices use
// ahead of (or instead of) an AOSP-style boot.img. The field layout and
// "all fields big-endian" follow U-Boot's own include/image.h (struct
// legacy_img_hdr); the names and numbers of the os/arch/type/compression
// fields are the ones mkimage writes (see UbootField).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "abr/byte_io.hpp"

namespace abr {

constexpr uint32_t kUimageMagic = 0x27051956;
constexpr size_t kUimageNameSize = 32;
constexpr size_t kUimageHeaderSize = 64;

// The four one-byte fields of the header that say what the image is: operating system, architecture, type, compression
// (U-Boot's IH_OS_*, IH_ARCH_*, IH_TYPE_* and IH_COMP_*). A table has the names that `mkimage -O help`, `-A help`, `-T help` and
// `-C help` list for the field, with the numbers that mkimage writes for them (the types are those that it writes into a legacy
// header; the other types are headers of their own, and a legacy image that holds one has its number). A value that has no name
// in the table is its decimal number: nothing is lost, and nothing is called "unknown".
enum class UbootField { OS, ARCH, TYPE, COMP };

// The name of the value in the table, or its decimal number.
std::string uboot_name(UbootField field, uint8_t v);
// The value of a name (in any case, as mkimage takes it; the old names `i386` and `fdt_legacy` too) or of a number: decimal digits,
// or 0x and hexadecimal digits, up to 255. nullopt for anything else; a name is not a number that is spelt wrong (`4_4bsd` is a name).
std::optional<uint8_t> uboot_value(UbootField field, std::string_view text);
// The names of the table, as a line for a message ("4_4bsd, arm-trusted-firmware, ...").
std::string uboot_names(UbootField field);
// The name of the field in a message and in the manifest ("os", "arch", "image_type", "compression").
const char* uboot_field_key(UbootField field);

inline std::string uboot_os_name(uint8_t v) { return uboot_name(UbootField::OS, v); }
inline std::string uboot_arch_name(uint8_t v) { return uboot_name(UbootField::ARCH, v); }
inline std::string uboot_type_name(uint8_t v) { return uboot_name(UbootField::TYPE, v); }
inline std::string uboot_comp_name(uint8_t v) { return uboot_name(UbootField::COMP, v); }

struct UImage {
    uint32_t timestamp = 0;
    uint32_t load_addr = 0;
    uint32_t entry_point = 0;
    uint8_t os = 5;      // IH_OS_LINUX
    uint8_t arch = 2;    // IH_ARCH_ARM
    uint8_t type = 2;    // IH_TYPE_KERNEL
    uint8_t comp = 0;    // IH_COMP_NONE (0=none,1=gzip,2=bzip2,3=lzma,4=lzo,5=lz4,6=zstd)
    std::string name;    // <=32 bytes
    Bytes name_tail;     // what the name field holds behind its NUL (see BootImage::cmdline_tail)
    Bytes data;          // payload, exactly as stored (still compressed per `comp`)
    size_t consumed = 0; // set by parse(): the bytes of the source that belong to the image (the header and `data`)

    static UImage parse(const Bytes& image);
    Bytes build() const;
};

}  // namespace abr
