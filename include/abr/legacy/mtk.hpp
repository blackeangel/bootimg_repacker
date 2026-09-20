// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::mtk -- the small MediaTek (MTK) sub-header some devices
// prepend to the *kernel* and/or *ramdisk* blob inside an otherwise
// perfectly ordinary AOSP boot.img/vendor_boot.img. Not a container
// format of its own -- this wraps a component that BootImage/
// VendorBootImage already extract, so it's applied as a strip/re-add
// step on those components rather than a whole new top-level format
// (mirroring how Android Image Kitchen's unpackimg.sh treats it: run
// after the main boot header unpack, independently for the kernel and
// the ramdisk, either of which may or may not have one).
//
// Struct layout, magic (little-endian 0x58881688) and the 512-byte
// total size with 0xFF padding (not zero -- easy to get wrong) are
// from osm0sis/mkmtkhdr's mtkimg.h and mkmtkhdr.c directly.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "abr/byte_io.hpp"

namespace abr::legacy {

constexpr uint32_t kMtkMagic = 0x58881688;
constexpr size_t kMtkHeaderSize = 512;
constexpr size_t kMtkNameSize = 32;

struct MtkHeader {
    uint32_t size = 0;   // declared size of the payload that follows
    std::string name;    // "KERNEL", "ROOTFS", or "RECOVERY" in practice
};

bool has_mtk_header(const Bytes& data);

// Splits a component into its MTK header (if present) and the
// remaining payload. Returns std::nullopt (payload unchanged) if
// `data` doesn't start with the MTK magic.
std::optional<MtkHeader> strip_mtk_header(const Bytes& data, Bytes& payload_out);

// Prepends an MTK header declaring `payload.size()` for the given
// component name (truncated to 31 chars + NUL if longer).
Bytes add_mtk_header(const Bytes& payload, const std::string& name);

}  // namespace abr::legacy
