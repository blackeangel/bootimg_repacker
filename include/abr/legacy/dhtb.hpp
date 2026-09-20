// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::dhtb -- the DHTB wrapper some Samsung/Qualcomm-based
// devices' bootloaders require around an otherwise ordinary boot.img.
// A 512-byte header (magic, a SHA-256 "signature" that's really just
// an integrity checksum -- not a real cryptographic signature scheme,
// nothing here is keyed) followed by the wrapped image, which itself
// conventionally ends with a 16-byte "SEANDROIDENFORCE" footer and/or
// 4 bytes of 0xFF padding (present or not depending on whether the
// wrapped image already had them).
//
// Struct layout, magic, and field offsets are from osm0sis/dhtbsign's
// dhtbsign.c directly. That reference tool has its own buffer over-read
// bug (writes 12 bytes past what it allocated, so real DHTB files can
// have a handful of unspecified trailing bytes after the declared
// payload) -- handled here by preserving whatever trailing bytes exist
// verbatim rather than assuming they're always absent or always zero.
#pragma once

#include <cstdint>
#include <optional>

#include "abr/byte_io.hpp"

namespace abr::legacy {

constexpr uint8_t kDhtbMagic[8] = {0x44, 0x48, 0x54, 0x42, 0x01, 0x00, 0x00, 0x00};
constexpr size_t kDhtbHeaderSize = 512;
constexpr size_t kDhtbShaOffset = 8;
constexpr size_t kDhtbPayloadSizeOffset = 48;

struct DhtbInfo {
    bool has_seandroid_footer = false;  // payload ends with "SEANDROIDENFORCE"
    bool has_padding = false;           // ...followed by 4 bytes of 0xFF
    Bytes trailing_extra;               // any bytes past the declared payload_size
};

bool has_dhtb_header(const Bytes& data);

// Strips the DHTB header and the SEANDROIDENFORCE/padding suffix (if
// present) so `inner_out` is a clean image ready for e.g.
// BootImage::parse(). Returns std::nullopt (inner_out = data
// unchanged) if `data` isn't DHTB-wrapped at all.
std::optional<DhtbInfo> strip_dhtb(const Bytes& data, Bytes& inner_out);

// Re-wraps `inner`, recomputing the header's SHA-256 checksum fresh
// over the assembled payload (inner + footer/padding per `info`,
// matching dhtbsign's own hashing scope -- trailing_extra is appended
// after and is not covered by payload_size or the checksum, matching
// the reference tool exactly).
Bytes wrap_dhtb(const Bytes& inner, const DhtbInfo& info);

}  // namespace abr::legacy
