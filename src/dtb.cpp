// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/dtb.hpp"

#include <algorithm>

namespace abr {

namespace {
bool has_fdt_magic(const Bytes& data) {
    if (data.size() < 4) return false;
    BinaryReader r(data);
    return r.be32() == kFdtMagic;
}

// Does a flattened device tree that fits in the rest of `data` start at `pos`? (The magic, a header's worth of
// bytes, a totalsize that is a header or more and not more than is left.)
bool tree_fits_at(const Bytes& data, size_t pos) {
    if (pos >= data.size() || data.size() - pos < kFdtHeaderSize) return false;
    BinaryReader r(data);
    r.skip(pos);
    if (r.be32() != kFdtMagic) return false;
    const uint32_t total = r.be32();
    return total >= kFdtHeaderSize && total <= data.size() - pos;
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
    size_t gap = 0;  // the zero bytes in front of the blob at `pos`
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
        out.gaps.push_back(gap);
        pos += total;
        out.consumed = pos;
        // Zero bytes and then a tree: the zeros are what puts the tree at its place (a gap), and `pos` moves on to it.
        // Zeros that no tree follows, or anything else, are left where they are -- behind the last blob.
        size_t next = pos;
        while (next < data.size() && data[next] == 0) ++next;
        gap = 0;
        if (next > pos && tree_fits_at(data, next)) {
            gap = next - pos;
            pos = next;
        }
    }
    return out;
}

size_t fdt_gap_alignment(const FdtBlobs& s) {
    size_t widest = 0;  // the biggest gap
    size_t starts = 0;  // the starts of the blobs after the first, or-ed: its lowest bit is the biggest power of two they are all multiples of
    size_t at = 0;
    for (size_t i = 0; i < s.blobs.size(); ++i) {
        const size_t gap = i < s.gaps.size() ? s.gaps[i] : 0;
        at += gap;
        if (i > 0) starts |= at;
        widest = std::max(widest, gap);
        at += s.blobs[i].size();
    }
    if (widest == 0) return 0;
    size_t n = 2;
    while (n <= widest) n <<= 1;
    const size_t common = starts & (~starts + 1);
    return n <= common ? n : 0;
}

std::vector<size_t> fdt_aligned_gaps(const std::vector<Bytes>& blobs, size_t align) {
    std::vector<size_t> gaps(blobs.size(), 0);
    if (align == 0) throw FormatError("the alignment of the blobs of a dtb is 0; it is a size of 1 or more");
    size_t at = 0;
    for (size_t i = 0; i < blobs.size(); ++i) {
        if (i > 0) {
            gaps[i] = (align - at % align) % align;
            at += gaps[i];
        }
        at += blobs[i].size();
    }
    return gaps;
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

Bytes join_fdt_blobs(const std::vector<Bytes>& blobs, const std::vector<size_t>& gaps) {
    if (!gaps.empty() && gaps.size() != blobs.size())
        throw FormatError("a dtb of " + std::to_string(blobs.size()) + " blobs was given " + std::to_string(gaps.size()) +
                          " gaps; there is one in front of each blob (0 for the first), or none at all");
    Bytes out;
    size_t total = 0;
    for (auto& b : blobs) total += b.size();
    for (size_t g : gaps) total += g;
    out.reserve(total);
    for (size_t i = 0; i < blobs.size(); ++i) {
        if (!gaps.empty()) out.insert(out.end(), gaps[i], 0);
        out.insert(out.end(), blobs[i].begin(), blobs[i].end());
    }
    return out;
}

}  // namespace abr
