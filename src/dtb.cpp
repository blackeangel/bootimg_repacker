// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/dtb.hpp"

namespace abr {

namespace {
bool has_fdt_magic(const Bytes& data) {
    if (data.size() < 4) return false;
    BinaryReader r(data);
    return r.be32() == kFdtMagic;
}
}  // namespace

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

FdtBlobs split_fdt_blobs(const Bytes& data) {
    FdtBlobs out;
    size_t pos = 0;
    while (pos < data.size()) {
        const size_t left = data.size() - pos;
        BinaryReader r(data);
        r.skip(pos);
        if (left < 4 || r.be32() != kFdtMagic) break;
        if (left < kFdtHeaderSize) {
            // Only the first blob is a mistake to be told; what follows the last one is not looked at.
            if (pos != 0) break;
            throw FormatError("this dtb is cut short: its header is " + std::to_string(kFdtHeaderSize) +
                              " bytes and the file ends after " + std::to_string(left));
        }
        const uint32_t total = r.be32();
        if (total < kFdtHeaderSize || total > left)
            throw FormatError("the FDT blob at offset " + std::to_string(pos) + " has a totalsize of " +
                              std::to_string(total) + " bytes, which " +
                              (total < kFdtHeaderSize ? "is less than its header (" + std::to_string(kFdtHeaderSize) + ")"
                                                      : "is more than the " + std::to_string(left) + " the file has left"));
        out.blobs.emplace_back(data.begin() + static_cast<std::ptrdiff_t>(pos),
                               data.begin() + static_cast<std::ptrdiff_t>(pos + total));
        pos += total;
    }
    out.consumed = pos;
    return out;
}

void check_fdt_blob(const Bytes& blob, const std::string& what) {
    if (!has_fdt_magic(blob))
        throw FormatError(what + " is not a flattened device tree (a dtb blob starts with the bytes d0 0d fe ed)");
    if (blob.size() < kFdtHeaderSize)
        throw FormatError(what + " is cut short: the header of a flattened device tree is " + std::to_string(kFdtHeaderSize) +
                          " bytes and the file has " + std::to_string(blob.size()));
    const uint32_t total = fdt_total_size(blob);
    if (total != blob.size())
        throw FormatError(what + " is " + std::to_string(blob.size()) + " bytes, but the totalsize in its header is " +
                          std::to_string(total) + "; the size is what finds the next blob, so the two have to agree (`dtc` writes "
                          "the header right; bytes that belong behind the last blob go in the trailer, not in a blob)");
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
