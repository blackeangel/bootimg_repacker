// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::dtb -- helpers for the raw "dtb" partition. Some devices ship a
// single Flattened Device Tree blob there; others concatenate several
// FDT blobs back to back (one per board revision) and let the bootloader
// pick the right one at runtime by matching a compatible/board-id
// property inside each blob. Either way, every blob starts with the
// standard big-endian FDT header (Devicetree Specification), so we can
// split/rejoin purely from each blob's `totalsize` field without
// understanding the tree structure itself.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {

constexpr uint32_t kFdtMagic = 0xd00dfeed;
constexpr size_t kFdtHeaderSize = 40;  // 10 big-endian uint32_t fields

bool looks_like_fdt(const Bytes& data);
// Reads the big-endian `totalsize` header field. Throws FormatError if
// `data` doesn't start with a valid FDT header.
uint32_t fdt_total_size(const Bytes& data);

// What a dtb file holds: the FDT blobs it starts with, one behind the other, each exactly its `totalsize`.
struct FdtBlobs {
    std::vector<Bytes> blobs;
    size_t consumed = 0;  // where the last blob ends; what follows it (zero fill, a trailer) is not a blob's
};

// Splits `data` into its FDT blobs (a single, ordinary dtb file yields one). Refuses (FormatError, saying
// where) a blob whose header is cut short, whose `totalsize` is less than the header or runs past the end of
// `data`. Data that does not start with an FDT has no blobs. What follows the last blob is not looked at: the
// caller keeps it (the envelope of the image).
FdtBlobs split_fdt_blobs(const Bytes& data);

// Refuses (FormatError, naming `what`) a blob that does not stand as an FDT: it does not start with the magic,
// its header is cut short, or its `totalsize` is not its size -- a blob whose size the header does not state
// is not found again where the next one starts.
void check_fdt_blob(const Bytes& blob, const std::string& what);

// Inverse of split_fdt_blobs(): concatenates with no padding in between,
// which is the layout every known Android dtb partition consumer expects.
Bytes join_fdt_blobs(const std::vector<Bytes>& blobs);

}  // namespace abr
