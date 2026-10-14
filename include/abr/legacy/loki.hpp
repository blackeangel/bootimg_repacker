// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::loki -- boot and recovery images that went through "loki" (Dan Rosenberg's loki_tool, 2013).
// Android Image Kitchen takes the patch off with `loki_tool unlok` and puts it on again with `loki_tool patch`,
// which needs the aboot.img of the phone the image is for; abr does both without it.
//
// What loki_tool patch makes of a boot image (v0 header, no second stage):
//
//     the plain image                                the LOKI image
//     [0, page)        header page                   [0, page)        the same header page, with
//                                                                       kernel_size   = padded kernel + ramdisk_size
//                                                                       ramdisk_size  = 0 (the page size for LG targets)
//                                                                       ramdisk_addr  = an address of the bootloader
//                                                                     and the LOKI header at byte 1024 (below)
//     padded kernel                                  padded kernel
//     padded ramdisk                                 padded ramdisk
//                                                    the "block": 512 bytes (page-size bytes for LG targets) of the
//                                                      bootloader's code, with the patch code laid over them
//     the device tree (dt_size bytes)                the device tree, dt_size bytes (no padding)
//
//     the LOKI header, at 1024 in the header page (148 bytes):
//       "LOKI"  u32 recovery (0 = boot, 1 = recovery)  char build[128]  u32 original kernel_size
//       u32 original ramdisk_size  u32 ramdisk_addr (kernel_addr + the padded kernel size)
//
//     the patch code: 64 bytes at the start of the block, within the first 16 bytes of it (check_sigs & 15 of the
//     target). 56 bytes of code (the same in every image) and two words: an address inside the bootloader that
//     depends on its build, and the ORIGINAL ramdisk_addr, which the code puts back where the bootloader reads it.
//
// So the LOKI image is the plain image with a few fields moved and a block that belongs to the phone's bootloader
// put in. abr unpacks it as the plain image (loki_tool unlok writes the very same bytes; its guess of the block's
// size is wrong for one family of targets, abr reads it from the header) and keeps what was added: the LOKI header's
// fields, the block, and what follows the image. On repack the block is put back unchanged, except for the
// ramdisk address inside the patch code, which follows the plain header's ramdisk_addr -- so what loki_tool patch
// would make of the repacked plain image, with the aboot.img the image was patched with, comes out byte for byte.
// What abr does not do is patch an image for a bootloader it has no LOKI image of: that takes the aboot.img.
//
// Only what loki_tool makes is read: a v0 header (a CAF device-tree size in word 10 is fine), no second stage, the
// patch code in the first 16 bytes of the block, the sizes of the LOKI header agreeing with the header's. Any
// other image with a LOKI header is refused (never read wrongly), with the reason.
//
// The format is loki's (https://github.com/djrbliss/loki, loki.h, loki_patch.c, loki_unlok.c; BSD-2-Clause); the
// test suite compares abr with the real loki_tool wherever it is compiled.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "abr/byte_io.hpp"
#include "abr/envelope.hpp"

namespace abr::legacy {

constexpr size_t kLokiHeaderOffset = 0x400;  // where the LOKI header sits in the header page
constexpr size_t kLokiHeaderSize = 148;
constexpr size_t kLokiBuildSize = 128;
constexpr size_t kLokiPatchSize = 64;  // the patch code as it lies in the image
constexpr size_t kLokiPatchWindow = 16;  // it starts within the first 16 bytes of the block

// What the image has that the plain boot image does not (see the layout above).
struct LokiInfo {
    uint32_t recovery = 0;  // the LOKI header's type: 0 boot, 1 recovery (anything else is kept as it is)
    Bytes build;            // kLokiBuildSize bytes: the build the patch was made for, as text padded with zeros
    // The last word of the LOKI header. loki_tool writes the load address behind the padded kernel there
    // (kernel_addr + padded kernel size), and so does abr unless the image says something else: then it is kept.
    std::optional<uint32_t> hdr_ramdisk_addr;
    uint32_t patched_ramdisk_addr = 0;  // what the patched header has in ramdisk_addr (an address of the bootloader)
    uint32_t patched_ramdisk_size = 0;  // ... in ramdisk_size: 0, or the page size
    Bytes block;                        // behind the ramdisk: bootloader code with the patch code in it
    uint32_t patch_offset = 0;          // where in the block the patch code starts: 0 to kLokiPatchWindow - 1
    // Filled in by strip_loki: how much of the file the image proper takes (header page up to the device tree),
    // and what follows it -- other data, or fill up to the size of the partition.
    size_t core_size = 0;
    Envelope tail;
};

// True when `data` is laid out like a LOKI image: "ANDROID!" at 0 and "LOKI" at 1024.
bool has_loki_header(const Bytes& data);

// Takes the patch off: `plain_out` becomes the boot image as it was before loki_tool patched it (header page,
// padded kernel, padded ramdisk, device tree: what `loki_tool unlok` writes). If `data` has no LOKI header,
// std::nullopt comes back and `plain_out` is left alone. An image that has the header but is not laid out the
// way loki_tool makes it (see above) is refused: FormatError.
std::optional<LokiInfo> strip_loki(const Bytes& data, Bytes& plain_out);

// Puts the patch on `plain`: the image loki_tool patch makes of it, with the block `info` holds in the place of a
// block of the bootloader's code (and the ramdisk address of the patch code set to the plain header's). Without
// `info.tail`, which the caller adds (Envelope::assemble). Refuses an image loki_tool cannot patch -- a header of
// version 1 or more, a second stage, data in the bytes the LOKI header needs -- and a `info` that does not fit.
Bytes apply_loki(const Bytes& plain, const LokiInfo& info);

}  // namespace abr::legacy
