// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/dhtb.hpp"

#include "abr/sha.hpp"

#include <algorithm>
#include <cstring>

namespace abr::legacy {

namespace {
constexpr uint8_t kSeandroidMagic[16] = {'S', 'E', 'A', 'N', 'D', 'R', 'O', 'I',
                                          'D', 'E', 'N', 'F', 'O', 'R', 'C', 'E'};
constexpr uint8_t kPayloadPadding[4] = {0xFF, 0xFF, 0xFF, 0xFF};
}  // namespace

bool has_dhtb_header(const Bytes& data) {
    return data.size() >= kDhtbHeaderSize &&
           std::equal(kDhtbMagic, kDhtbMagic + 8, data.begin());
}

std::optional<DhtbInfo> strip_dhtb(const Bytes& data, Bytes& inner_out) {
    if (!has_dhtb_header(data)) {
        inner_out = data;
        return std::nullopt;
    }
    BinaryReader r(data);
    r.seek(kDhtbPayloadSizeOffset);
    uint32_t payload_size = r.le32();
    if (kDhtbHeaderSize + payload_size > data.size())
        throw FormatError("DHTB payload_size exceeds the actual file size");

    Bytes payload(data.begin() + kDhtbHeaderSize,
                  data.begin() + kDhtbHeaderSize + payload_size);
    DhtbInfo info;
    info.trailing_extra.assign(data.begin() + kDhtbHeaderSize + payload_size, data.end());

    size_t sz = payload.size();
    if (sz >= 20 && std::equal(kPayloadPadding, kPayloadPadding + 4, payload.end() - 4) &&
        std::equal(kSeandroidMagic, kSeandroidMagic + 16, payload.end() - 20)) {
        info.has_seandroid_footer = true;
        info.has_padding = true;
        payload.resize(sz - 20);
    } else if (sz >= 16 && std::equal(kSeandroidMagic, kSeandroidMagic + 16, payload.end() - 16)) {
        info.has_seandroid_footer = true;
        payload.resize(sz - 16);
    }
    inner_out = std::move(payload);
    return info;
}

Bytes wrap_dhtb(const Bytes& inner, const DhtbInfo& info) {
    Bytes declared_payload = inner;
    if (info.has_seandroid_footer)
        declared_payload.insert(declared_payload.end(), kSeandroidMagic, kSeandroidMagic + 16);
    if (info.has_padding)
        declared_payload.insert(declared_payload.end(), kPayloadPadding, kPayloadPadding + 4);

    Bytes digest = hash::sha256(declared_payload);  // 32 bytes

    BinaryWriter w;
    w.bytes(kDhtbMagic, 8);
    w.bytes(digest.data(), digest.size());                  // offset 8..39
    w.zeros(kDhtbPayloadSizeOffset - w.size());              // offset 40..47, unused
    w.le32(static_cast<uint32_t>(declared_payload.size()));  // offset 48
    w.zeros(kDhtbHeaderSize - w.size());                     // offset 52..511
    w.bytes(declared_payload);
    w.bytes(info.trailing_extra);
    return w.take();
}

}  // namespace abr::legacy
