// SPDX-License-Identifier: GPL-3.0-or-later
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
#include <vector>

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

// How the 32-byte `id` field of a v0-v2 header was derived. The field is a
// content fingerprint that no bootloader checks, but tools disagree on how
// to compute it, so we detect which recipe matches the image at hand and
// reproduce exactly that one when a component changes. Unrecognised values
// are kept verbatim (RAW) rather than overwritten with a guess.
enum class IdScheme {
    SHA1,       // SHA-1 over kernel, ramdisk, second [, recovery_dtbo] [, dtb], each as data || le32(size)
    SHA1_DT,    // as SHA1 for v0, plus a trailing dt entry (data || le32(size), or a lone le32(0))
    SHA256,     // same input as SHA1, SHA-256 digest (osm0sis mkbootimg --hash sha256)
    SHA256_DT,  // SHA1_DT with a SHA-256 digest
    RAW,        // unknown recipe (or all-zero): keep whatever the image had
};

const char* id_scheme_name(IdScheme s);
std::optional<IdScheme> id_scheme_from_name(const std::string& name);

struct BootImage {
    uint32_t header_version = 4;  // 0..4

    // --- v0-v2 only ---
    uint32_t kernel_addr = 0x00008000;
    uint32_t ramdisk_addr = 0x01000000;
    uint32_t second_addr = 0x00f00000;
    uint32_t tags_addr = 0x00000100;
    uint64_t dtb_addr = 0x01f00000;  // v2 only; u64 on disk
    uint32_t page_size = 2048;       // v0-v2 only; v3/v4 fix this at 4096
    std::string board_name;          // v0-v2 only, <=16 bytes
    std::array<uint32_t, 8> id{};    // v0-v2 only; as found on disk (see id_scheme)
    IdScheme id_scheme = IdScheme::SHA1;

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

    // v0 only. Qualcomm/CAF ("QCDT") images reuse the header_version word
    // as `dt_size` and append a device-tree blob after `second`. A header
    // word above 8 is read that way (osm0sis' unpackbootimg does the same).
    Bytes dt;

    // Things a plain re-serialisation would silently normalise away. They
    // are recorded by parse() and reused by build() so an untouched image
    // rebuilds bit-exactly.
    std::optional<uint32_t> header_size_field;          // v1-v4: value found if not the standard one
    std::optional<uint64_t> recovery_dtbo_offset_field; // v1-v2: ditto
    std::array<uint32_t, 4> reserved{};                 // v3-v4 reserved[4]
    Bytes header_padding;                               // non-zero bytes between header struct and page end
    uint64_t missing_tail_padding = 0;                  // final page padding absent from the source file

    // Set by parse(): number of bytes of `image` that belong to the boot
    // image proper (end of the last component, page aligned, clipped to
    // the file). Anything after that is the caller's business.
    size_t consumed = 0;

    static BootImage parse(const Bytes& image);
    Bytes build() const;

    // Digest per `id_scheme` over the current components. Empty for RAW.
    Bytes compute_id(IdScheme scheme) const;
    // The scheme (if any) whose digest reproduces the id found in the source.
    IdScheme detect_id_scheme() const;
    // Recomputes `id` following `id_scheme`; RAW leaves it untouched.
    void recompute_id();
};

}  // namespace abr
