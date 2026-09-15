// SPDX-License-Identifier: MIT
#include "abr/dtb.hpp"

namespace abr {

bool looks_like_fdt(const Bytes& data) {
    if (data.size() < kFdtHeaderSize) return false;
    BinaryReader r(data);
    return r.be32() == kFdtMagic;
}

uint32_t fdt_total_size(const Bytes& data) {
    if (!looks_like_fdt(data)) throw FormatError("not an FDT blob (bad magic)");
    BinaryReader r(data);
    r.be32();  // magic
    return r.be32();
}

std::vector<Bytes> split_fdt_blobs(const Bytes& data) {
    std::vector<Bytes> out;
    size_t pos = 0;
    while (pos < data.size()) {
        Bytes remaining(data.begin() + static_cast<long>(pos), data.end());
        if (!looks_like_fdt(remaining)) {
            // Trailing garbage/padding after the last real blob: if it's
            // all zero, drop it silently; otherwise keep it as-is so we
            // don't silently lose data on round-trip.
            bool all_zero = true;
            for (uint8_t b : remaining)
                if (b != 0) { all_zero = false; break; }
            if (!all_zero) out.push_back(std::move(remaining));
            break;
        }
        uint32_t total = fdt_total_size(remaining);
        if (total == 0 || total > remaining.size())
            throw FormatError("FDT blob at offset " + std::to_string(pos) +
                               " has an invalid totalsize");
        out.emplace_back(remaining.begin(), remaining.begin() + total);
        pos += total;
    }
    if (out.empty()) out.push_back(data);  // empty or unrecognized input: pass through whole
    return out;
}

Bytes join_fdt_blobs(const std::vector<Bytes>& blobs) {
    Bytes out;
    size_t total = 0;
    for (auto& b : blobs) total += b.size();
    out.reserve(total);
    for (auto& b : blobs) out.insert(out.end(), b.begin(), b.end());
    return out;
}

}  // namespace abr
