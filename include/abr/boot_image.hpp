// SPDX-License-Identifier: MIT
//
// abr::BootImage -- parser/builder for the "boot image" container used by
// boot.img, init_boot.img, boot-debug.img, boot-test-harness.img,
// recovery.img and recovery-two-step.img.
//
// All of these are the *same on-disk container format* (AOSP
// system/tools/mkbootimg, header versions 0-4); they differ only in what
// build config puts inside (e.g. init_boot.img is a v4 image with
// kernel_size == 0, recovery-two-step.img fills the legacy "second stage"
// slot). One parser/builder therefore covers the whole family.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>

#include "abr/byte_io.hpp"

namespace abr {

constexpr char kBootMagic[] = "ANDROID!";
constexpr size_t kBootMagicSize = 8;
constexpr size_t kBootNameSize = 16;
constexpr size_t kBootArgsSize = 512;
constexpr size_t kBootExtraArgsSize = 1024;
constexpr uint32_t kBootImageV4SignatureSize = 4096;

// Bit-packed os_version/patch_level field shared by every header version.
// See boot_img_hdr_v0::SetOsVersion / SetOsPatchLevel in AOSP bootimg.h.
struct OsVersion {
    unsigned major = 0, minor = 0, patch = 0;  // A.B.C
    unsigned year = 0, month = 0;              // patch level Y-M (year is full, e.g. 2024)

    static OsVersion unpack(uint32_t v);
    uint32_t pack() const;
    std::string to_string() const;               // "A.B.C"
    std::string patch_level_string() const;       // "YYYY-MM"
    static std::optional<OsVersion> parse(const std::string& version,
                                           const std::string& patch_level);
};

struct BootImage {
    uint32_t header_version = 4;  // 0..4

    // --- v0-v2 only ---
    uint32_t kernel_addr = 0x00008000;
    uint32_t ramdisk_addr = 0x01000000;
    uint32_t second_addr = 0x00f00000;
    uint32_t tags_addr = 0x00000100;
    uint32_t dtb_addr = 0x01f00000;  // v2 only; stored as u64 on disk, high bits usually 0
    uint32_t page_size = 2048;       // v0-v2 only; v3/v4 fix this at 4096
    std::string board_name;          // v0-v2 only, <=16 bytes
    std::array<uint32_t, 8> id{};    // v0-v2 only; sha1 digest, zero-padded to 32 bytes

    // --- shared ---
    OsVersion os_version{};
    std::string cmdline;  // logical concatenation of cmdline+extra_cmdline (v0-v2) or the
                           // single cmdline field (v3-v4); see split logic in boot_image.cpp

    // --- v4 only ---
    // signature_size is derived from boot_signature.size() at build() time.

    // Payload blobs, exactly as stored on disk (still compressed if they
    // were compressed on disk -- this class does not touch compression).
    Bytes kernel;
    Bytes ramdisk;
    Bytes second;          // v0-v2 only ("second stage bootloader" / two-step recovery payload)
    Bytes recovery_dtbo;   // v1-v2 only ("recovery dtbo/acpio")
    Bytes dtb;             // v2 only (v3/v4 boot.img carries no dtb; that lives in vendor_boot)
    Bytes boot_signature;  // v4 only; GKI boot_signature blob (up to 4096/16384 bytes, AVB
                            // footer for the whole file is separate and handled by VbmetaImage)

    static BootImage parse(const Bytes& image);
    Bytes build() const;

    // Recomputes the `id` field using the same SHA-1(payload||size) scheme
    // as AOSP mkbootimg.py's write_header(); only meaningful for v0-v2.
    void recompute_id();
};

}  // namespace abr
