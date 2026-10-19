// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::elf -- the ELF-based boot image container used on some
// Sony (Xperia) devices instead of the standard "ANDROID!" boot.img:
// the whole file is a (32- or 64-bit, little-endian) ELF executable,
// with each ELF program header ("segment") holding one component --
// kernel, ramdisk, and optionally others -- rather than kernel/ramdisk
// being fields in a bespoke header the way AOSP's format works.
//
// Two different, independently-authored reference tools exist for
// this and don't fully agree with each other:
//   - osm0sis/elftool (srl3gx): identifies each segment by a specific
//     p_flags value (kernel=0, ramdisk=0x80000000, ipl=0x40000000,
//     cmdline=0x20000000 with p_type=PT_NOTE instead of PT_LOAD, and
//     rpm=0x01000000), 32-bit only, always writes e_machine=EM_ARM,
//     and lays out segment data starting at a fixed file offset 4096
//     with no padding between segments after that. Android Image Kitchen
//     packs with it (and unpacks with it too, keeping the first 4096
//     bytes as the "header" whose addresses a repack takes).
//   - tobiaswaldvogel/and_boot_tools' unpackelf: doesn't look at
//     p_flags at all -- treats segments purely by *position*
//     (0=kernel, 1=ramdisk, 2=device tree) plus a heuristic that any
//     segment <=4096 bytes found along the way is the cmdline text
//     instead; supports both ELF32 and ELF64.
//
// This implementation follows elftool's p_flags convention when a
// segment's p_flags matches one of its known values (unambiguous when
// present, and what AIK's own unpackimg.sh cascade is built around),
// falling back to unpackelf's positional convention (first unflagged
// PT_LOAD segment = kernel, second = ramdisk, rest = "extraN") for
// anything else -- meant to cover both conventions rather than commit
// to just one, but not verified against a real Sony device image
// (none was available); see PROGRESS.md.
//
// The layout. An image that elftool lays out the way it does (the 52-byte
// header and the 32-byte program headers, zeros up to byte 4096, the data
// of the segments one behind the other, nothing after them, e_entry the
// address of the first one) is built again from the fields of the segments
// alone. An image that is laid out otherwise -- another size of the block in
// front of the data, padding between the segments, something behind them, an
// ELF64 header, an e_entry of its own, p_align, p_memsz beyond p_filesz, an
// OS/ABI byte that is not 0x61 -- is kept as it was: parse() records the
// bytes that are not the data of a segment (`layout`) and build() puts the
// segments back into them, with the sizes and offsets of the program headers
// made for what the segments now hold. Where that does not give the file
// back (segments that overlap, data inside the header block) there is no
// layout, build() writes elftool's and the round-trip check says so.
// A segment that has no data has a p_offset all the same. Where it pointed behind
// the data of a segment (into the padding that followed it, at the end of the file),
// it moves with that data when the data in front of it grows or shrinks; where it
// pointed anywhere else (in the block in front of the data) it stays.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::legacy {

constexpr uint8_t kElfMagic[4] = {0x7F, 'E', 'L', 'F'};
constexpr uint32_t kElfDataStartOffset = 4096;  // where elftool starts writing segment data

// Known p_flags values from osm0sis/elftool's elfboot.h. Any other
// (usually 0, i.e. "unflagged") value is resolved positionally instead.
constexpr uint32_t kElfFlagsRamdisk = 0x80000000;
constexpr uint32_t kElfFlagsIpl = 0x40000000;
constexpr uint32_t kElfFlagsCmdline = 0x20000000;
constexpr uint32_t kElfFlagsRpm = 0x01000000;

struct ElfSegment {
    uint32_t flags = 0;      // raw p_flags as read (0 for positionally-resolved kernel/ramdisk)
    std::string role;        // resolved name: "kernel"/"ramdisk"/"ipl"/"cmdline"/"rpm"/"extra0"...
    uint64_t addr = 0;       // p_vaddr (p_paddr is the same in every known case; a layout keeps what it was)
    Bytes data;
};

// The bytes of an image that are not the data of a segment, and where the data goes in between: what makes an
// image that is not laid out the way elftool does it come back as it was (see the top of this file).
struct ElfLayout {
    Bytes header;                  // everything in front of the first segment's data: ELF header, program headers, the rest
    std::vector<uint32_t> order;   // the segments with data, by where that data is in the file
    std::vector<Bytes> after;      // after[k]: the bytes behind the data of segment order[k], up to the next one's (or the end)
};

struct ElfBootImage {
    bool is_64bit = false;
    uint16_t machine = 40;  // EM_ARM
    std::optional<uint64_t> entry;  // e_entry, where it is not the address of the first segment (what elftool writes)

    std::vector<ElfSegment> segments;  // original order preserved
    std::optional<ElfLayout> layout;   // set by parse() when elftool's layout would not give the file back

    static bool looks_like(const Bytes& data);
    static ElfBootImage parse(const Bytes& data);
    // With a layout: the segments in it. Without one, or when the segments no longer fit it (another count, a
    // segment that had no data and has some): elftool's layout (`note` then says why).
    Bytes build(std::string* note = nullptr) const;
    Bytes build_elftool() const;
};

}  // namespace abr::legacy
