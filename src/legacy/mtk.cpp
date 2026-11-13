// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/mtk.hpp"

#include <cstring>

namespace abr::legacy {

bool has_mtk_header(const Bytes& data) {
    if (data.size() < kMtkHeaderSize) return false;
    BinaryReader r(data);
    return r.le32() == kMtkMagic;
}

std::optional<MtkHeader> strip_mtk_header(const Bytes& data, Bytes& payload_out) {
    if (!has_mtk_header(data)) {
        payload_out = data;
        return std::nullopt;
    }
    BinaryReader r(data);
    r.le32();  // magic, already checked by has_mtk_header()
    MtkHeader h;
    h.size = r.le32();
    h.name = r.asciiz(kMtkNameSize);
    h.raw.assign(data.begin(), data.begin() + static_cast<long>(kMtkHeaderSize));
    payload_out.assign(data.begin() + static_cast<long>(kMtkHeaderSize), data.end());
    h.extra = static_cast<int64_t>(payload_out.size()) - static_cast<int64_t>(h.size);
    h.plain = h.extra == 0 && h.raw == mtk_header_bytes(h.size, h.name);
    return h;
}

Bytes mtk_header_bytes(uint32_t size, const std::string& name) {
    BinaryWriter w;
    w.le32(kMtkMagic);
    w.le32(size);
    w.asciiz(name, kMtkNameSize);
    // Real mkmtkhdr fills the rest of the 512-byte header with 0xFF,
    // not zero -- memset(hdr, 0xFF, sizeof(mtk_header)) happens before
    // the magic/size/name fields are written over the front of it.
    while (w.size() < kMtkHeaderSize) w.u8(0xFF);
    return w.take();
}

Bytes add_mtk_header(const Bytes& payload, const std::string& name) {
    Bytes out = mtk_header_bytes(static_cast<uint32_t>(payload.size()), name);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

Bytes add_mtk_header(const Bytes& payload, const Bytes& raw, int64_t extra) {
    if (raw.size() != kMtkHeaderSize)
        throw FormatError("an MTK header is " + std::to_string(kMtkHeaderSize) + " bytes; the one given is " + std::to_string(raw.size()));
    if (!has_mtk_header(raw)) throw FormatError("the bytes given as an MTK header do not start with its magic (the bytes 88 16 88 58)");
    const int64_t declared = static_cast<int64_t>(payload.size()) - extra;
    if (declared < 0 || declared > static_cast<int64_t>(UINT32_MAX))
        throw FormatError("an MTK header that sits " + std::to_string(extra) + " bytes off the size of its data cannot go in front of " +
                          std::to_string(payload.size()) + " bytes: the size it would declare is " + std::to_string(declared));
    Bytes out;
    out.reserve(raw.size() + payload.size());
    out.assign(raw.begin(), raw.end());
    for (size_t i = 0; i < 4; ++i) out[4 + i] = static_cast<uint8_t>(static_cast<uint32_t>(declared) >> (8 * i));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

}  // namespace abr::legacy
