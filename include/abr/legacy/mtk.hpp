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
    Bytes raw;           // the 512 bytes of the header as they were found
    // What the payload that followed holds beyond the size the header declares (negative: less than it declares). 0 in every header
    // that a tool of the family wrote.
    int64_t extra = 0;
    // True when add_mtk_header(payload, name) writes exactly `raw` again: the plain header (magic, size, name, 0xFF up to 512 bytes) of a
    // payload that is as long as it says. When it is not -- an address and a mode, the extension of the loader's own part_hdr_t, bytes
    // behind the zero of the name, a payload that is longer or shorter than the header says -- the bytes are kept, not made again
    // (add_mtk_header(payload, raw, extra) puts them back).
    bool plain = true;
};

bool has_mtk_header(const Bytes& data);

// Splits a component into its MTK header (if present) and the
// remaining payload. Returns std::nullopt (payload unchanged) if
// `data` doesn't start with the MTK magic.
std::optional<MtkHeader> strip_mtk_header(const Bytes& data, Bytes& payload_out);

// The plain header (512 bytes) that declares `size` for the given component name (32 characters at most).
Bytes mtk_header_bytes(uint32_t size, const std::string& name);

// Prepends the plain MTK header declaring `payload.size()` for the given
// component name (truncated to 32 chars if longer).
Bytes add_mtk_header(const Bytes& payload, const std::string& name);

// Prepends `raw`, a header that strip_mtk_header() found (512 bytes that start with the magic), with nothing changed but the size it declares:
// payload.size() - extra, in the field at byte 4. Every other byte -- the name, the address and the mode, the extension, whatever fills the
// rest -- stays as it was. FormatError for bytes that are no MTK header, or an `extra` that would make the size negative.
Bytes add_mtk_header(const Bytes& payload, const Bytes& raw, int64_t extra);

}  // namespace abr::legacy
