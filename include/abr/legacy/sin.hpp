// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::sin -- Sony SIN containers, versions 1 to 3: the packaging Xperia firmware (.ftf) puts its images
// in (kernel.sin, boot.sin, FOTAKernel.sin, loader.sin ...).
//
// Android Image Kitchen opens one with `sony_dump` (github.com/munjeni/anyxperia_dumper), which converts it to
// the image inside, and then forgets that there was a container: unpackimg.sh deletes the signature type, so
// repackimg.sh writes the plain image. A SIN is Sony's -- header, hashes and signature are theirs, nothing here
// could make one again for an edited image. abr does the same and says so: the container is a layer that comes
// off (`peel_wrappers` in main.cpp), what is inside is unpacked as any image is, and a repack writes that image.
// What is in the container's header (the hash tables, the signature) is not kept.
//
// The layout is read from the source of sony_dump, which has no licence file; nothing of it is in abr, and the
// test suite compiles it only to ask it the same question (tests/run_tests.sh, ABR_SONY_DUMP). All numbers are
// big endian.
//
//   version 1 and 2   byte 0 is the version, bytes 1 to 3 are zero (what Android Image Kitchen's signature file
//                     tests: 01 00 00 00 or 02 00 00 00); a 32-bit size H at byte 2; the header is H + 16 bytes.
//   version 3         "\x03SIN"; the size P of the header, 32 bits at byte 4; a size D, 32 bits at byte 0x18.
//
// What follows the header is one of
//
//   MMCF              "MMCF" and a 32-bit length L; then L bytes: a 24-byte block (a 4-byte word, a 4-byte word and
//                     the 16-byte GUID of the partition it was made of) and the entries of the parts, each opening
//                     with its tag and its own size:
//                       "LZ4A"  u32 entry size, u64 packed offset, u64 unpacked size, u64 packed size,
//                               u64 unpacked offset                     (40 bytes, or more)
//                       "ADDR"  u32 entry size, u64 packed offset, u64 packed size, u64 unpacked offset
//                                                                       (32 bytes, or more)
//                     the data of a part is at (header + 8 + L + packed offset): an LZ4 block for LZ4A (the raw
//                     block, not a frame), the bytes themselves for ADDR. The image is the parts one behind the other, 0xFF
//                     filling the space in front of a part that starts further on than the image has reached; a
//                     part that starts before that is put at the end. (sony_dump then looks at the first part
//                     for an ext4 superblock and pads the file with zeros to the size of the file system; that
//                     is for partition images and not done here, where only boot-family images are wanted.)
//   "\x7fELF"         a loader: the rest of the file is the image, and the size D (v3) has to say so.
//   anything else     v1 and v2: the rest of the file is the image. v3: the rest of the file, or -- when D is not
//                     what is left of it -- what follows D more bytes.
//
// parse_sin() never reads wrongly: every size is checked against the file, an entry that is smaller than its
// own fields, a part that is out of the file, an unknown tag, an LZ4 block that does not decode to exactly the
// size the entry says are refused with the reason (where sony_dump goes on with uninitialised memory or does not
// stop).
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::legacy {

// The most bytes abr converts a container to (a boot-family image is far below it; a system.sin is not one).
constexpr uint64_t kSinMaxPayload = 512ull << 20;

struct SinPart {
    bool lz4 = false;               // LZ4A (an LZ4 block) rather than ADDR (as it is)
    uint64_t entry_offset = 0;      // where the entry is in the file
    uint32_t entry_size = 0;        // its own length (the next entry follows that far on)
    uint64_t packed_offset = 0;     // as the entry says, counted from the end of the MMCF block
    uint64_t packed_size = 0;
    uint64_t unpacked_size = 0;     // LZ4A only; an ADDR part is as long as its packed size
    uint64_t unpacked_offset = 0;   // as the entry says
    uint64_t file_offset = 0;       // where the data really is in the file
    uint64_t out_offset = 0;        // where it goes in the image: unpacked_offset, or the end of what there is
    uint64_t out_size() const { return lz4 ? unpacked_size : packed_size; }
};

struct SinInfo {
    int version = 0;                // 1, 2 or 3
    uint64_t header_size = 0;       // bytes in front of the MMCF block / the image
    uint64_t data_size = 0;         // the header's size D (v3); v1 and v2: what is left of the file
    bool mmcf = false;
    uint32_t gptp_len = 0;          // MMCF: the length of what follows the 8-byte MMCF header
    std::array<uint8_t, 16> gptp_uuid{};
    std::vector<SinPart> parts;     // MMCF
    bool loader = false;            // an ELF behind the header: sony_dump's "Loader?"
    uint64_t payload_offset = 0;    // not MMCF: where the image starts in the file
    uint64_t payload_size = 0;      // what the conversion makes (the length of the image)
    std::vector<std::string> notes; // things that were unusual, in words (a part put at the end, ...)
};

// The first four bytes the way Android Image Kitchen's signature file tests them: 01 00 00 00 (SINv1),
// 02 00 00 00 (SINv2), "\x03SIN" (SINv3). Not a promise that the rest is a SIN.
bool has_sin_header(const Bytes& data);

// Reads the structure (the header, the MMCF block and its entries; nothing is decoded). Throws FormatError, with
// the reason, for what is not a container sony_dump can convert, and for one it can that is out of the file.
SinInfo parse_sin(const Bytes& data);

// The image the container holds, as sony_dump writes it. FormatError when the payload is larger than
// kSinMaxPayload or a part does not decode.
Bytes extract_sin(const Bytes& data, const SinInfo& info);

// One line for `abr info` and the note of an unpack: "Sony SIN v3, MMCF (2 parts: 1 ADDR, 1 LZ4A), ...".
std::string describe_sin(const SinInfo& info);

}  // namespace abr::legacy
