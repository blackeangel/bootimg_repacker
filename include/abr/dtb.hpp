// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::dtb -- helpers for the raw "dtb" partition. Some devices ship a
// single Flattened Device Tree blob there; others concatenate several
// FDT blobs back to back (one per board revision), or put each at a
// multiple of 8, 16 or a page with zeros between, and let the bootloader
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

// What a dtb file holds: the FDT blobs it starts with, one behind the other, each exactly its `totalsize`; where
// the blobs are put at multiples of 8, 16 or a page, the zero bytes between two of them (the gap) as well.
struct FdtBlobs {
    std::vector<Bytes> blobs;
    std::vector<size_t> gaps;  // gaps[i]: the zero bytes between blob i-1 and blob i (gaps[0] is 0); one for each blob
    size_t consumed = 0;       // where the last blob ends; what follows it (zero fill, a trailer) is not a blob's
};

// Splits `data` into its FDT blobs (a single, ordinary dtb file yields one). Refuses (FormatError, saying
// where) a blob whose header is cut short, whose `totalsize` is less than the header or runs past the end of
// `data`. Data that does not start with an FDT has no blobs. What follows the last blob is not looked at: the
// caller keeps it (the envelope of the image).
//
// Zero bytes between two blobs are a gap when an FDT that fits in the rest of `data` follows them; zeros that
// no blob follows are not (they are behind the last blob, the caller's). A blob behind a gap that does not
// stand (a totalsize that is less than a header or runs past the end) is not refused as one right behind the
// last is: a gap is only a guess that the next thing is a tree, and what is not one stays behind the last blob.
FdtBlobs split_fdt_blobs(const Bytes& data);

// The alignment that explains the gaps of `s`: the smallest power of two that is above every gap and that every
// blob after the first starts a multiple of -- put the blobs at multiples of it, and the gaps are those. 0 when
// there are no gaps (the blobs follow one another), and when no alignment makes them.
size_t fdt_gap_alignment(const FdtBlobs& s);

// The gaps that put every blob after the first at a multiple of `align` (a size of 1 or more): gaps[i] for blob
// i, gaps[0] is 0. What pack writes when the manifest has an alignment, so that a tree that got bigger moves the
// ones behind it on to the next multiple.
std::vector<size_t> fdt_aligned_gaps(const std::vector<Bytes>& blobs, size_t align);

// Refuses (FormatError, naming `what`) a blob that does not stand as an FDT: it does not start with the magic,
// its header is cut short, or its `totalsize` is not its size -- a blob whose size the header does not state
// is not found again where the next one starts.
void check_fdt_blob(const Bytes& blob, const std::string& what);

// Inverse of split_fdt_blobs(): concatenates, with `gaps[i]` zero bytes in front of blob i (none at all when
// `gaps` is empty: the blobs follow one another, which is the layout of most Android dtb partitions). Refuses
// (FormatError) a `gaps` that has not one entry for each blob.
Bytes join_fdt_blobs(const std::vector<Bytes>& blobs, const std::vector<size_t>& gaps = {});

}  // namespace abr
