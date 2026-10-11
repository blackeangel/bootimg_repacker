// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/krnl.hpp"

#include <array>
#include <cstring>
#include <string>

namespace abr::legacy {

namespace {

// CRC-32 with the polynomial 0x04C10DB7 (Rockchip's -- see krnl.hpp), most significant bit first: one
// table entry is the effect of one byte on the register.
constexpr std::array<uint32_t, 256> make_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i << 24;
        for (int bit = 0; bit < 8; ++bit) c = (c & 0x80000000u) ? (c << 1) ^ 0x04C10DB7u : (c << 1);
        table[i] = c;
    }
    return table;
}
constexpr std::array<uint32_t, 256> kTable = make_table();

}  // namespace

uint32_t rkcrc32(const uint8_t* data, size_t size, uint32_t crc) {
    for (size_t i = 0; i < size; ++i) crc = (crc << 8) ^ kTable[(crc >> 24) ^ data[i]];
    return crc;
}

bool KrnlImage::looks_like(const Bytes& data) {
    return data.size() >= sizeof kKrnlMagic && std::memcmp(data.data(), kKrnlMagic, sizeof kKrnlMagic) == 0;
}

KrnlImage KrnlImage::parse(const Bytes& data) {
    if (!looks_like(data)) throw FormatError("not a Rockchip KRNL image: it does not start with \"KRNL\"");
    if (data.size() < kKrnlHeaderSize)
        throw FormatError("this Rockchip KRNL image is cut short: " + std::to_string(data.size()) +
                          " bytes, not even the 8 of its header");
    BinaryReader r(data);
    r.skip(sizeof kKrnlMagic);
    const uint64_t size = r.le32();
    if (size + kKrnlHeaderSize + kKrnlTrailerSize > data.size())
        throw FormatError("this Rockchip KRNL image is cut short: its header declares " + std::to_string(size) +
                          " bytes of payload and a 4-byte CRC, the file holds " +
                          std::to_string(data.size() - kKrnlHeaderSize) + " bytes after the header");
    KrnlImage img;
    img.payload = r.bytes(static_cast<size_t>(size));
    img.crc = r.le32();
    img.crc_ok = img.crc == rkcrc32(img.payload);
    return img;
}

Bytes KrnlImage::build(std::optional<uint32_t> crc) const {
    if (payload.size() > 0xFFFFFFFFull)
        throw FormatError("a KRNL image holds at most 4 GiB of payload (its size field has 32 bits)");
    BinaryWriter w;
    w.bytes(kKrnlMagic, sizeof kKrnlMagic);
    w.le32(static_cast<uint32_t>(payload.size()));
    w.bytes(payload);
    w.le32(crc ? *crc : rkcrc32(payload));
    return w.take();
}

}  // namespace abr::legacy
