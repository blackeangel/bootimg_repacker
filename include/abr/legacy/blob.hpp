// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::blob -- the "blob" container of ASUS (NVIDIA Tegra) devices, "MSM-RADIO-UPDATE", and the
// "-SIGNED-BY-SIGNBLOB-" header in front of a signed one. Android Image Kitchen calls the signed kind BLOB
// (and opens it with AndroidRoot's blobunpack, packs it with blobpack):
//
//   "-SIGNED-BY-SIGNBLOB-"  u32 datalen  u32 siglen            28 bytes, only in a signed blob
//   "MSM-RADIO-UPDATE"  u32 version  u32 size  u32 part_offset  u32 num_parts  u32 unknown[7]
//                                                              60 bytes: the blob proper starts here
//   num_parts x { char name[4]; u32 offset; u32 size; u32 version }    16 bytes each
//   the data of the partitions, one after the other
//   the signature, in a signed blob
//
// All little endian; the offsets of the table count from the start of the blob proper ("MSM-RADIO-UPDATE"),
// not from the start of the file. `version` is 0x00010000, `size` and `part_offset` are 60 (the table follows
// the header at once), `unknown` is zero, a partition's `version` is 1, and its name is a short word that
// names a partition of the device ("LNX" is the kernel, "SOS" the recovery, "EBT" the bootloader ...): the
// boot image Android Image Kitchen works on is the data of one such partition.
//
// What datalen and siglen are is not written down anywhere abr could read; they are kept as they were
// (Android Image Kitchen writes zeros for both: an unsigned blob). The format is BlobTools'
// (shared/blob.h, blobpack.cpp, blobunpack.cpp; Apache-2.0); abr has code of its own for it and the test
// suite compares it with the real blobpack and blobunpack where they are compiled.
//
// Only the layout the tools write is read: the table right behind the header, the partitions' data one
// after the other behind the table. A blob with a gap between its parts, or a longer header, is refused
// (never read wrongly): nothing abr could keep exactly is lost.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::legacy {

constexpr size_t kBlobSecureHeaderSize = 28;
constexpr size_t kBlobHeaderSize = 60;
constexpr size_t kBlobPartEntrySize = 16;
constexpr uint32_t kBlobVersion = 0x00010000;

struct BlobPart {
    std::array<uint8_t, 4> name{};  // "LNX\0": a short word, NUL-padded
    uint32_t version = 1;
    Bytes data;
};

struct BlobImage {
    bool secure = false;  // the 28-byte "-SIGNED-BY-SIGNBLOB-" header is in front
    uint32_t secure_datalen = 0;
    uint32_t secure_siglen = 0;
    uint32_t version = kBlobVersion;
    std::array<uint32_t, 7> unknown{};
    std::vector<BlobPart> parts;
    Bytes tail;  // what follows the last partition's data: the signature of a signed blob

    // "-SIGNED-BY-SIGNBLOB-" or "MSM-RADIO-UPDATE" at the very start.
    static bool looks_like(const Bytes& data);

    // Refuses (FormatError, saying why) what is cut short, what is not laid out the way the tools write it,
    // and a signed blob with no blob behind its header.
    static BlobImage parse(const Bytes& data);

    // The blob proper: header, table, data -- what the secure header's datalen describes.
    size_t blob_size() const;

    // The secure header (if any), the blob; not the tail.
    Bytes build() const;
};

}  // namespace abr::legacy
