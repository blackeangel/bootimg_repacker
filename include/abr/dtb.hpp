// SPDX-License-Identifier: MIT
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
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {

constexpr uint32_t kFdtMagic = 0xd00dfeed;
constexpr size_t kFdtHeaderSize = 40;  // 10 big-endian uint32_t fields

bool looks_like_fdt(const Bytes& data);
// Reads the big-endian `totalsize` header field. Throws FormatError if
// `data` doesn't start with a valid FDT header.
uint32_t fdt_total_size(const Bytes& data);

// Splits `data` into one Bytes buffer per concatenated FDT blob. A
// single, ordinary dtb file yields a one-element result.
std::vector<Bytes> split_fdt_blobs(const Bytes& data);

// Inverse of split_fdt_blobs(): concatenates with no padding in between,
// which is the layout every known Android dtb partition consumer expects.
Bytes join_fdt_blobs(const std::vector<Bytes>& blobs);

}  // namespace abr
