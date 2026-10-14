// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/loki.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <string_view>

namespace abr::legacy {

namespace {

// The patch code. These 56 bytes are what loki_tool lays over the start of the block: the first part of PATCH in
// loki.h of https://github.com/djrbliss/loki (the two words behind them -- an address inside the bootloader and
// the original ramdisk address -- differ from image to image and are not a part of this table). abr looks for the
// code to find the patch in a LOKI image, as loki_tool unlok does, and puts it back unchanged with the block it
// belongs to. Nothing else of loki is in abr; the layout above was read from its sources.
//
// loki is
//
//   Copyright (c) 2013 Dan Rosenberg. All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//     1. Redistributions of source code must retain the above copyright
//        notice, this list of conditions and the following disclaimer.
//
//     2. Redistributions in binary form must reproduce the above copyright
//        notice, this list of conditions and the following disclaimer in
//        the documentation and/or other materials provided with the
//        distribution.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INFRAE OR
//   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
//   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
//   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
constexpr std::array<uint8_t, 56> kPatchCode = {
    0xfe, 0xb5, 0x0d, 0x4d, 0xd5, 0xf8, 0x88, 0x04, 0xab, 0x68, 0x98, 0x42, 0x12, 0xd0,
    0xd5, 0xf8, 0x90, 0x64, 0x0a, 0x4c, 0xd5, 0xf8, 0x8c, 0x74, 0x07, 0xf5, 0x80, 0x57,
    0x0f, 0xce, 0x0f, 0xc4, 0x10, 0x3f, 0xfb, 0xdc, 0xd5, 0xf8, 0x88, 0x04, 0x04, 0x49,
    0xd5, 0xf8, 0x8c, 0x24, 0xa8, 0x60, 0x69, 0x61, 0x2a, 0x61, 0x00, 0x20, 0xfe, 0xbd,
};
constexpr size_t kRamdiskWordAt = kPatchCode.size() + 4;  // behind the code: the address word, then this one
static_assert(kRamdiskWordAt + 4 == kLokiPatchSize);

constexpr std::string_view kAndroidMagic = "ANDROID!";
constexpr std::string_view kLokiMagic = "LOKI";

// The header of the boot image (the fields of a v0 header that matter here).
constexpr size_t kKernelSize = 8, kKernelAddr = 12, kRamdiskSize = 16, kRamdiskAddr = 20, kSecondSize = 24,
                 kPageSize = 36, kWord10 = 40;
constexpr uint32_t kMaxHeaderVersionWord = 8;  // a larger word in position 10 is a device-tree size (CAF)

// The LOKI header.
constexpr size_t kLokiRecovery = kLokiHeaderOffset + 4;
constexpr size_t kLokiBuild = kLokiHeaderOffset + 8;
constexpr size_t kLokiOrigKernel = kLokiBuild + kLokiBuildSize;
constexpr size_t kLokiOrigRamdisk = kLokiOrigKernel + 4;
constexpr size_t kLokiHdrRamdisk = kLokiOrigRamdisk + 4;
static_assert(kLokiHdrRamdisk + 4 == kLokiHeaderOffset + kLokiHeaderSize);

constexpr size_t kSmallBlock = 0x200;  // the block of every target but the LG ones: the size of a sector

uint32_t rd32(const Bytes& b, size_t off) {
    return uint32_t(b[off]) | (uint32_t(b[off + 1]) << 8) | (uint32_t(b[off + 2]) << 16) | (uint32_t(b[off + 3]) << 24);
}
void wr32(Bytes& b, size_t off, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>(v >> (8 * i));
}

bool plausible_page_size(uint32_t v) { return v >= 2048 && v <= 131072 && (v & (v - 1)) == 0; }

struct Geometry {
    uint32_t page = 0, kernel_size = 0, kernel_addr = 0, ramdisk_size = 0, ramdisk_addr = 0, dt_size = 0;
};

// What the header of a boot image says, if it is one loki_tool works on. `what` begins the refusals.
Geometry read_geometry(const Bytes& b, const std::string& what) {
    if (b.size() < kLokiHeaderOffset + kLokiHeaderSize ||
        std::memcmp(b.data(), kAndroidMagic.data(), kAndroidMagic.size()) != 0)
        throw FormatError(what + " is not a boot image with a version 0 header");
    Geometry g;
    g.page = rd32(b, kPageSize);
    if (!plausible_page_size(g.page))
        throw FormatError(what + " has a page size (" + std::to_string(g.page) + ") that no boot image has");
    g.kernel_size = rd32(b, kKernelSize);
    g.kernel_addr = rd32(b, kKernelAddr);
    g.ramdisk_size = rd32(b, kRamdiskSize);
    g.ramdisk_addr = rd32(b, kRamdiskAddr);
    if (rd32(b, kSecondSize) != 0)
        throw FormatError(what + " has a second stage, which loki_tool leaves out of the image it makes");
    const uint32_t word = rd32(b, kWord10);
    if (word != 0 && word <= kMaxHeaderVersionWord)
        throw FormatError(what + " has a header of version " + std::to_string(word) +
                          "; loki_tool works on images with a version 0 header");
    g.dt_size = word;
    return g;
}

}  // namespace

bool has_loki_header(const Bytes& data) {
    return data.size() >= kLokiHeaderOffset + kLokiHeaderSize &&
           std::memcmp(data.data(), kAndroidMagic.data(), kAndroidMagic.size()) == 0 &&
           std::memcmp(data.data() + kLokiHeaderOffset, kLokiMagic.data(), kLokiMagic.size()) == 0;
}

std::optional<LokiInfo> strip_loki(const Bytes& data, Bytes& plain_out) {
    if (!has_loki_header(data)) return std::nullopt;
    const std::string what = "this image, which has a LOKI header,";
    const Geometry g = read_geometry(data, what);

    const uint32_t orig_kernel = rd32(data, kLokiOrigKernel);
    const uint32_t orig_ramdisk = rd32(data, kLokiOrigRamdisk);
    const uint64_t padded_kernel = align_up(orig_kernel, g.page);
    const uint64_t padded_ramdisk = align_up(orig_ramdisk, g.page);
    // loki_tool patch makes the kernel field cover the ramdisk, too (the loader takes the ramdisk for a part of
    // the kernel); the ramdisk field then is 0, or a page for the LG targets, whose block is that long.
    if (g.kernel_size != static_cast<uint32_t>(padded_kernel + orig_ramdisk))
        throw FormatError(what + " has a kernel size (" + std::to_string(g.kernel_size) +
                          ") that is not the padded original kernel (" + std::to_string(padded_kernel) +
                          ") plus the original ramdisk (" + std::to_string(orig_ramdisk) +
                          ") of its LOKI header: not an image of loki_tool");
    size_t block_size;
    if (g.ramdisk_size == 0)
        block_size = kSmallBlock;
    else if (g.ramdisk_size == g.page)
        block_size = g.page;
    else
        throw FormatError(what + " has a ramdisk size (" + std::to_string(g.ramdisk_size) +
                          ") that is neither 0 nor the page size, the two values loki_tool leaves there");

    const uint64_t base = g.page + padded_kernel + padded_ramdisk;  // where the block starts
    const uint64_t core = base + block_size + g.dt_size;
    if (data.size() < core)
        throw FormatError("this LOKI image is cut short: " + std::to_string(data.size()) + " bytes, and its header puts "
                          "the end of the device tree at " + std::to_string(core));

    // The patch code is within the first bytes of the block; the ramdisk address the bootloader is to be given
    // is the last word of it.
    size_t at = kLokiPatchWindow;
    for (size_t off = 0; off < kLokiPatchWindow; ++off) {
        if (std::memcmp(data.data() + base + off, kPatchCode.data(), kPatchCode.size()) == 0) {
            at = off;
            break;
        }
    }
    if (at == kLokiPatchWindow)
        throw FormatError("this LOKI image does not have the patch code in the first " + std::to_string(kLokiPatchWindow) +
                          " bytes behind its ramdisk, where loki_tool puts it: not an image of loki_tool");

    LokiInfo info;
    info.recovery = rd32(data, kLokiRecovery);
    info.build.assign(data.begin() + kLokiBuild, data.begin() + kLokiBuild + kLokiBuildSize);
    const uint32_t hdr_ramdisk_addr = rd32(data, kLokiHdrRamdisk);
    if (hdr_ramdisk_addr != g.kernel_addr + static_cast<uint32_t>(padded_kernel)) info.hdr_ramdisk_addr = hdr_ramdisk_addr;
    info.patched_ramdisk_addr = g.ramdisk_addr;
    info.patched_ramdisk_size = g.ramdisk_size;
    info.block.assign(data.begin() + static_cast<std::ptrdiff_t>(base),
                      data.begin() + static_cast<std::ptrdiff_t>(base + block_size));
    info.patch_offset = static_cast<uint32_t>(at);
    info.core_size = static_cast<size_t>(core);
    info.tail = Envelope::capture(data, 0, info.core_size);

    // The plain image: the header page with the original values, the padded kernel and ramdisk, the device tree.
    Bytes plain(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(base));
    wr32(plain, kKernelSize, orig_kernel);
    wr32(plain, kRamdiskSize, orig_ramdisk);
    wr32(plain, kRamdiskAddr, rd32(data, static_cast<size_t>(base) + at + kRamdiskWordAt));
    std::fill(plain.begin() + kLokiHeaderOffset, plain.begin() + kLokiHeaderOffset + kLokiHeaderSize, uint8_t{0});
    plain.insert(plain.end(), data.begin() + static_cast<std::ptrdiff_t>(base + block_size),
                 data.begin() + static_cast<std::ptrdiff_t>(core));
    plain_out = std::move(plain);
    return info;
}

Bytes apply_loki(const Bytes& plain, const LokiInfo& info) {
    if (info.build.size() != kLokiBuildSize)
        throw FormatError("the LOKI build field must be exactly " + std::to_string(kLokiBuildSize) + " bytes, this one is " +
                          std::to_string(info.build.size()));
    if (info.patch_offset >= kLokiPatchWindow || info.block.size() < info.patch_offset + kLokiPatchSize ||
        std::memcmp(info.block.data() + info.patch_offset, kPatchCode.data(), kPatchCode.size()) != 0)
        throw FormatError("the block of the LOKI patch (loki_block.bin) does not have the patch code at the offset the "
                          "manifest gives (loki_shellcode_offset, 0 to " + std::to_string(kLokiPatchWindow - 1) + ")");

    const Geometry g = read_geometry(plain, "the image to be patched");
    const uint64_t padded_kernel = align_up(g.kernel_size, g.page);
    const uint64_t padded_ramdisk = align_up(g.ramdisk_size, g.page);
    const uint64_t base = g.page + padded_kernel + padded_ramdisk;
    // The content ends at the device tree if there is one; the ramdisk's own padding may be missing from its end.
    const uint64_t content = g.dt_size ? base + g.dt_size : g.page + padded_kernel + g.ramdisk_size;
    if (plain.size() < content)
        throw FormatError("the image to be patched is cut short: " + std::to_string(plain.size()) +
                          " bytes, its header needs " + std::to_string(content));
    // What follows the content can only be padding: the LOKI image has no room for anything else (it has a tail
    // of its own, kept apart).
    for (size_t i = static_cast<size_t>(content); i < plain.size(); ++i) {
        if (plain[i] != 0)
            throw FormatError("the image to be patched has data behind its device tree (from byte " + std::to_string(content) +
                              "), which a LOKI image cannot hold");
    }
    // The LOKI header goes where a version 0 header has nothing: after the 608 bytes of its fields come 1024 of
    // the extra command line, whose last part nothing uses.
    for (size_t i = kLokiHeaderOffset; i < kLokiHeaderOffset + kLokiHeaderSize; ++i) {
        if (plain[i] != 0)
            throw FormatError("the header page of the image to be patched has data in bytes 1024 to " +
                              std::to_string(kLokiHeaderOffset + kLokiHeaderSize - 1) +
                              " (the end of a command line of more than 900 characters?), where the LOKI header goes");
    }
    const uint64_t kernel_field = padded_kernel + g.ramdisk_size;
    if (kernel_field > 0xffffffffull)
        throw FormatError("the kernel and the ramdisk of the image to be patched are too big for the kernel size field");

    Bytes out;
    out.reserve(static_cast<size_t>(base) + info.block.size() + g.dt_size);
    out.insert(out.end(), plain.begin(), plain.begin() + g.page);
    wr32(out, kKernelSize, static_cast<uint32_t>(kernel_field));
    wr32(out, kRamdiskSize, info.patched_ramdisk_size);
    wr32(out, kRamdiskAddr, info.patched_ramdisk_addr);
    std::memcpy(out.data() + kLokiHeaderOffset, kLokiMagic.data(), kLokiMagic.size());
    wr32(out, kLokiRecovery, info.recovery);
    std::copy(info.build.begin(), info.build.end(), out.begin() + kLokiBuild);
    wr32(out, kLokiOrigKernel, g.kernel_size);
    wr32(out, kLokiOrigRamdisk, g.ramdisk_size);
    wr32(out, kLokiHdrRamdisk, info.hdr_ramdisk_addr.value_or(g.kernel_addr + static_cast<uint32_t>(padded_kernel)));

    // The padded kernel and ramdisk (the padding of the ramdisk may be missing at the end of a short image).
    const size_t body_end = static_cast<size_t>(base);
    const size_t have_end = std::min(plain.size(), body_end);
    out.insert(out.end(), plain.begin() + g.page, plain.begin() + static_cast<std::ptrdiff_t>(have_end));
    out.resize(body_end, 0);

    // The block, with the original ramdisk address in the patch code.
    const size_t block_at = out.size();
    out.insert(out.end(), info.block.begin(), info.block.end());
    wr32(out, block_at + info.patch_offset + kRamdiskWordAt, g.ramdisk_addr);

    if (g.dt_size)
        out.insert(out.end(), plain.begin() + static_cast<std::ptrdiff_t>(base),
                   plain.begin() + static_cast<std::ptrdiff_t>(base + g.dt_size));
    return out;
}

}  // namespace abr::legacy
