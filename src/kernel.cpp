// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/kernel.hpp"

#include <algorithm>
#include <cstring>

#include "abr/dtb.hpp"

namespace abr::kernel {

namespace {

uint32_t be32(const uint8_t* p) {
    return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | uint32_t{p[3]};
}

constexpr uint32_t kFdtBeginNode = 1;
constexpr uint32_t kFdtEnd = 9;

bool all_zero(const Bytes& d, size_t from) {
    return std::all_of(d.begin() + static_cast<std::ptrdiff_t>(from), d.end(), [](uint8_t b) { return b == 0; });
}

}  // namespace

bool plausible_tree(const Bytes& data, size_t pos) {
    if (pos > data.size() || data.size() - pos < kFdtHeaderSize) return false;
    const uint8_t* p = data.data() + pos;
    if (be32(p) != kFdtMagic) return false;
    const size_t avail = data.size() - pos;
    const uint32_t total = be32(p + 4), off_struct = be32(p + 8), off_strings = be32(p + 12), off_rsvmap = be32(p + 16);
    const uint32_t version = be32(p + 20), last_comp = be32(p + 24);
    if (total < kFdtHeaderSize || total > avail) return false;
    if (version < 3 || version > 17 || last_comp > version) return false;  // (what a version before 3 lacks is a header field; no tree has them)
    // The memory reservation map: eight-byte aligned, at least its terminating entry (two zero 64-bit words), in the blob.
    if (off_rsvmap < kFdtHeaderSize || off_rsvmap % 8 != 0 || off_rsvmap > total - 16) return false;
    // The structure block: four-byte aligned, in the blob, and (version 17) as long as the header says -- it starts with the root node, which
    // has no name (FDT_BEGIN_NODE, four zero bytes) and ends with FDT_END.
    if (off_struct < kFdtHeaderSize || off_struct % 4 != 0 || off_struct > total - 8) return false;
    if (be32(p + off_struct) != kFdtBeginNode) return false;
    if (version >= 17) {
        const uint32_t size_struct = be32(p + 36);
        if (size_struct < 12 || size_struct % 4 != 0 || size_struct > total - off_struct) return false;
        if (be32(p + off_struct + size_struct - 4) != kFdtEnd) return false;
    }
    if (be32(p + off_struct + 4) != 0) return false;  // the name of the root is empty: a NUL, padded to four bytes
    // The strings block (version 3 and later says its size).
    if (off_strings > total) return false;
    if (version >= 3 && be32(p + 32) > total - off_strings) return false;
    return true;
}

std::optional<Appended> find_appended_trees(const Bytes& data) {
    const size_t n = data.size();
    if (n < 2 * kFdtHeaderSize) return std::nullopt;
    const uint8_t first = static_cast<uint8_t>(kFdtMagic >> 24);
    size_t from = 1;  // (a tree at 0 is a dtb, not a kernel with trees behind it)
    while (from + 4 <= n) {
        const void* hit = std::memchr(data.data() + from, first, n - from - 3);
        if (!hit) break;
        const size_t start = static_cast<size_t>(static_cast<const uint8_t*>(hit) - data.data());
        from = start + 1;
        if (!plausible_tree(data, start)) continue;

        // The trees one behind the other from here (zeros between two when a tree follows them), as split_fdt_blobs() has them.
        size_t pos = start, trees = 0, consumed = start;
        while (plausible_tree(data, pos)) {
            pos += be32(data.data() + pos + 4);
            ++trees;
            consumed = pos;
            size_t next = pos;
            while (next < n && data[next] == 0) ++next;
            if (next > pos && plausible_tree(data, next)) pos = next;
        }
        const size_t tail = n - consumed;
        if (tail > kMaxTailBehindTrees && !all_zero(data, consumed)) continue;  // code and data behind them: they belong to the kernel

        // What pack and unpack will cut with is split_fdt_blobs(): it has to agree on where the trees end.
        FdtBlobs split;
        try {
            split = split_fdt_blobs(Bytes(data.begin() + static_cast<std::ptrdiff_t>(start), data.end()));
        } catch (const FormatError&) {
            continue;
        }
        if (split.blobs.size() != trees || split.consumed != consumed - start) continue;
        return Appended{start, trees, consumed};
    }
    return std::nullopt;
}

}  // namespace abr::kernel
