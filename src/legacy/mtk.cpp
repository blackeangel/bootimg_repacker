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
    payload_out.assign(data.begin() + static_cast<long>(kMtkHeaderSize), data.end());
    return h;
}

Bytes add_mtk_header(const Bytes& payload, const std::string& name) {
    BinaryWriter w;
    w.le32(kMtkMagic);
    w.le32(static_cast<uint32_t>(payload.size()));
    w.asciiz(name, kMtkNameSize);
    // Real mkmtkhdr fills the rest of the 512-byte header with 0xFF,
    // not zero -- memset(hdr, 0xFF, sizeof(mtk_header)) happens before
    // the magic/size/name fields are written over the front of it.
    while (w.size() < kMtkHeaderSize) w.u8(0xFF);
    w.bytes(payload);
    return w.take();
}

}  // namespace abr::legacy
