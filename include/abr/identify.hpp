// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::identify -- "what is this file?", in the vocabulary of Android Image
// Kitchen.
//
// AIK (osm0sis) decides what it is looking at by running file(1) with its own
// signature file, bin/androidbootimg.magic, and cutting the answer apart with
// awk. abr has no business starting another program, so the same signatures
// are written down here as code and the answer is a struct; the label is
// worded exactly the way file(1) words it (the test suite compares the two on
// a set of synthetic samples whenever a `file` and the magic file are at hand),
// so the output of `abr identify` reads like AIK's.
//
// This is detection only. Which of the formats abr can then unpack is up to the
// caller; Identity says enough to explain, by name, what abr was given when it
// cannot.
//
// Where abr deliberately differs from file(1):
//   * "ANDROID!" / "VNDRBOOT" and the other searched-for signatures are looked
//     for in the first kMagicSearchLimit bytes (the window the unpackers use),
//     not in the first megabytes -- what is identified as a boot image is what
//     can be unpacked as one;
//   * an MTK type word comes from the 512-byte MTK header itself, not from the
//     first "KERNEL" found anywhere in the file;
//   * a prefix signature always wins over an "ANDROID!" found later, and a
//     vendor_boot image that starts with "VNDRBOOT" is a vendor_boot image
//     (file(1) ranks the two by a strength rule that can call it a boot image).
#pragma once

#include <cstddef>
#include <string>

#include "abr/byte_io.hpp"

namespace abr {

enum class Kind {
    UNKNOWN,
    // A signing wrapper in front of the image proper ("<X> signing" in AIK).
    BLOB,      // ASUS/Qualcomm SIGNBLOB container
    NOOK,      // Barnes & Noble Nook: 1 MiB master_boot.key header
    NOOKTAB,   // Nook tablet: 256 KiB header
    CHROMEOS,  // ChromeOS kernel blob (vboot)
    DHTB,      // Samsung/Spreadtrum DHTB header
    SIN1,      // Sony SIN packaging, versions 1..3
    SIN2,
    SIN3,
    // An image.
    AOSP,             // "ANDROID!" boot / recovery (+ PXA, LOKI, AMONET, MTK variants)
    AOSP_VNDR,        // "VNDRBOOT" vendor_boot / vendor_kernel_boot
    UBOOT,            // U-Boot legacy uImage
    OSIP,             // Intel OSIP
    OSIP_HEADERLESS,  // Intel OSIP without its header
    KRNL,             // Rockchip KRNL
    ELF,              // Sony ELF boot image (or any ELF)
    // Pieces that can stand alone: split-off components and tail signatures.
    MTK,        // a kernel/ramdisk with an MTK header
    QCDT,       // Qualcomm device tree table
    AVB1,       // AVBv1 BootSignature (tail)
    AVB2,       // AVBv2 footer (tail)
    BUMP,       // LG Bump footer (tail)
    SEANDROID,  // Samsung SEAndroid footer (tail)
    // Formats abr handles that AIK's signature file does not name.
    VBMETA,
    DTBO,
    DTB,
};

enum class Patch { NONE, LOKI, AMONET };

struct Identity {
    Kind kind = Kind::UNKNOWN;
    // What `file -b -m androidbootimg.magic` prints ("data" when nothing matched).
    std::string label = "data";

    // AOSP images.
    size_t magic_offset = 0;  // where "ANDROID!" / "VNDRBOOT" was found
    int pxa_variant = 0;      // 20, 28 or 30 for a Marvell PXA header, else 0
    Patch patch = Patch::NONE;
    int loki_type = -1;        // LOKI: 0 = boot, 1 = recovery, -1 = anything else
    bool mtk_headers = false;  // an MTK header follows the first page

    // Wrappers: where the wrapped image starts, if the wrapper has a fixed size
    // (DHTB 512 bytes, Nook 1 MiB, Nook tablet 256 KiB); 0 if unknown.
    size_t payload_offset = 0;

    // Words of the label, as AIK cuts them with awk: "AOSP", "AOSP_VNDR",
    // "U-Boot", "OSIP", "KRNL", "ELF", "BLOB", "NOOK", ... ; "PXA" appended
    // for a PXA header ("AOSP-PXA").
    std::string aik_type() const;

    // A sentence for a format abr recognises but does not process, with the AIK
    // tool that does; empty when abr handles the kind.
    std::string unsupported_note() const;
};

// Looks at the start of `data` (and a little way in, as the signature file's
// "search" rules do).
Identity identify(const Bytes& data);

// What is stuck to the end of an image: AVBv1 BootSignature (and which
// partition it names), AVBv2 footer, LG Bump footer, SEAndroid footer. All that
// are present, unlike file(1), which names only the strongest.
struct Footers {
    bool avb1 = false;
    std::string avb1_type;  // "boot", "recovery" or empty
    bool avb2 = false;
    bool bump = false;
    bool seandroid = false;
    bool any() const { return avb1 || avb2 || bump || seandroid; }
};

// The last kFooterWindow bytes of `data` are searched.
constexpr size_t kFooterWindow = 8192;
Footers identify_footers(const Bytes& data);

// The 16 bytes LG's bootloader accepts instead of a signature (Bump).
extern const unsigned char kBumpMagic[16];

}  // namespace abr
