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
//     with no padding between segments after that.
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
// (none was available this session); see PROGRESS.md.
#pragma once

#include <cstdint>
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
    uint32_t addr = 0;       // p_vaddr (always == p_paddr in every known case)
    Bytes data;
};

struct ElfBootImage {
    bool is_64bit = false;
    uint16_t machine = 40;  // EM_ARM

    std::vector<ElfSegment> segments;  // original order preserved

    static bool looks_like(const Bytes& data);
    static ElfBootImage parse(const Bytes& data);
    Bytes build() const;
};

}  // namespace abr::legacy
