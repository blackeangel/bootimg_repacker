// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/identify.hpp"

#include <algorithm>
#include <cstring>
#include <string_view>

#include "abr/dtb.hpp"
#include "abr/dtbo.hpp"
#include "abr/envelope.hpp"
#include "abr/uimage.hpp"

using namespace std::string_view_literals;

// The rules follow bin/androidbootimg.magic of Android Image Kitchen, in the
// order of that file. The numbers are offsets from the start of the data, as
// there ("0 string ...", ">>36 string ...", ">>1024 string LOKI").

namespace abr {

const unsigned char kBumpMagic[16] = {0x41, 0xA9, 0xE4, 0x67, 0x74, 0x4D, 0x1D, 0x1B,
                                      0xA4, 0x29, 0xF2, 0xEC, 0xEA, 0x65, 0x52, 0x79};

namespace {

constexpr size_t kNone = std::string::npos;
constexpr std::string_view kMtkMagic = "\x88\x16\x88\x58"sv;
constexpr size_t kMtkHeaderSize = 512;
constexpr size_t kNookHeader = 1024 * 1024;
constexpr size_t kNookTabHeader = 256 * 1024;
constexpr size_t kDhtbHeader = 512;

// `s` at exactly `off`?
bool at(const Bytes& d, size_t off, std::string_view s) {
    return off <= d.size() && d.size() - off >= s.size() &&
           std::memcmp(d.data() + off, s.data(), s.size()) == 0;
}

// First place `s` occurs in d[from, from + window), or kNone.
size_t search(const Bytes& d, size_t from, size_t window, std::string_view s) {
    if (s.empty() || from >= d.size()) return kNone;
    const size_t span = std::min(window, d.size() - from);
    if (span < s.size()) return kNone;
    const uint8_t* base = d.data() + from;
    const uint8_t* end = base + (span - s.size() + 1);  // one past the last start
    const int first = static_cast<unsigned char>(s[0]);
    for (const uint8_t* p = base; p < end;) {
        p = static_cast<const uint8_t*>(std::memchr(p, first, static_cast<size_t>(end - p)));
        if (!p) return kNone;
        if (std::memcmp(p, s.data(), s.size()) == 0) return from + static_cast<size_t>(p - base);
        ++p;
    }
    return kNone;
}

void signed_by(Identity& id, Kind k, std::string label, size_t payload = 0) {
    id.kind = k;
    id.label = std::move(label);
    id.payload_offset = payload;
}

// "ELF bootimg (ARM)": the machine word, then ")" or "64)" for the class byte
// (so a 64-bit x86 file reads "(x86_64)").
std::string elf_label(const Bytes& d) {
    std::string s = "ELF";
    if (at(d, 5, "\x01\x01\x61"sv)) s += " bootimg";  // EI_DATA, EI_VERSION, Sony's OSABI
    if (at(d, 18, "\x28"sv)) s += " (ARM";
    else if (at(d, 18, "\x03"sv)) s += " (x86_";
    else if (at(d, 18, "\x08"sv)) s += " (MIPS";
    if (at(d, 4, "\x01"sv)) s += ")";
    else if (at(d, 4, "\x02"sv)) s += "64)";
    if (search(d, 0, kMagicSearchLimit, kMtkMagic) != kNone) s += ", MTK headers";
    return s;
}

std::string mtk_label(const Bytes& d) {
    std::string s = "MTK header";
    const size_t window = kMtkHeaderSize;
    if (search(d, 0, window, "KERNEL"sv) != kNone) s += ", kernel type";
    if (search(d, 0, window, "ROOTFS"sv) != kNone) s += ", rootfs type";
    if (search(d, 0, window, "RECOVERY"sv) != kNone) s += ", recovery type";
    return s;
}

std::string osip_label(const Bytes& d) {
    std::string s = "OSIP bootimg";
    if (at(d, 52, "\x00\x00\x00\x00"sv)) s += ", boot (signed)";
    else if (at(d, 52, "\x01\x00\x00\x00"sv)) s += ", boot (unsigned)";
    else if (at(d, 52, "\x0C\x00\x00\x00"sv)) s += ", recovery (signed)";
    else if (at(d, 52, "\x0D\x00\x00\x00"sv)) s += ", recovery (unsigned)";
    return s;
}

// The most specific footer wins, in the order file(1) ranks them (the
// signature file gives AVBv1 more bytes to match than the others).
std::string footer_label(const Footers& f) {
    if (f.avb1) {
        std::string s = "AVBv1 signing footer";
        if (f.avb1_type == "boot") s += ", boot type";
        else if (f.avb1_type == "recovery") s += ", recovery type";
        return s;
    }
    if (f.avb2) return "AVBv2 signing footer";
    if (f.bump) return "Bump footer";
    if (f.seandroid) return "SEAndroid footer";
    return "";
}

}  // namespace

Footers identify_footers(const Bytes& data) {
    Footers f;
    const size_t from = data.size() > kFooterWindow ? data.size() - kFooterWindow : 0;
    const size_t window = data.size() - from;
    if (size_t p = search(data, from, window, "\x02\x01\x01\x30\x82"sv); p != kNone) {
        f.avb1 = true;
        const bool boot = search(data, p, window, "/boot"sv) != kNone;
        const bool recovery = search(data, p, window, "/recovery"sv) != kNone;
        f.avb1_type = boot ? "boot" : (recovery ? "recovery" : "");
        // file(1) prints both words when both occur; the first one is what AIK keeps.
    }
    f.avb2 = search(data, from, window, "AVBf"sv) != kNone;
    f.bump = search(data, from, window,
                    std::string_view(reinterpret_cast<const char*>(kBumpMagic), sizeof kBumpMagic)) != kNone;
    f.seandroid = search(data, from, window, "SEANDROIDENFORCE"sv) != kNone;
    return f;
}

Identity identify(const Bytes& d) {
    Identity id;
    if (d.empty()) {
        id.label = "empty";
        return id;
    }

    // ---- signing wrappers: a fixed signature at a fixed place -----------
    if (at(d, 0, "-SIGNED-BY-SIGNBLOB-"sv)) {
        signed_by(id, Kind::BLOB, "BLOB signing");
        return id;
    }
    if (at(d, 64, "Red Loader"sv)) { signed_by(id, Kind::NOOK, "NOOK signing (red loader)", kNookHeader); return id; }
    if (at(d, 64, "Green Loader"sv)) { signed_by(id, Kind::NOOK, "NOOK signing (green loader)", kNookHeader); return id; }
    if (at(d, 64, "Green Recovery"sv)) { signed_by(id, Kind::NOOK, "NOOK signing (green recovery)", kNookHeader); return id; }
    if (at(d, 64, "eMMC boot.img+secondloader"sv)) { signed_by(id, Kind::NOOK, "NOOK signing (emmc boot)", kNookHeader); return id; }
    if (at(d, 64, "eMMC recovery.img+secondloader"sv)) { signed_by(id, Kind::NOOK, "NOOK signing (emmc recovery)", kNookHeader); return id; }
    if (at(d, 48, "BauwksBoot"sv)) {
        signed_by(id, Kind::NOOKTAB, "NOOKTAB signing (bauwks)", kNookTabHeader);
        return id;
    }
    if (at(d, 0, "CHROMEOS"sv)) {
        signed_by(id, Kind::CHROMEOS, "CHROMEOS signing");
        return id;
    }
    if (at(d, 0, "DHTB\x01\x00\x00"sv)) {
        signed_by(id, Kind::DHTB, "DHTB signing", kDhtbHeader);
        return id;
    }

    // ---- images with a signature of their own at offset 0 ----------------
    if (at(d, 0, "\x27\x05\x19\x56"sv)) {
        id.kind = Kind::UBOOT;
        id.label = "U-Boot bootimg";
        return id;
    }
    if (at(d, 0, "$OS$\x00\x00\x01"sv)) {
        id.kind = Kind::OSIP;
        id.label = osip_label(d);
        return id;
    }
    if (at(d, 0, "KRNL"sv)) {
        id.kind = Kind::KRNL;
        id.label = "KRNL bootimg";
        return id;
    }
    if (at(d, 0, "\x7f""ELF"sv)) {
        id.kind = Kind::ELF;
        id.label = elf_label(d);
        return id;
    }
    if (at(d, 0, "QCDT"sv)) {
        id.kind = Kind::QCDT;
        id.label = "QCDT header";
        return id;
    }

    // Sony SIN: three versions told apart by the first four bytes only.
    if (at(d, 0, "\x01\x00\x00\x00"sv)) { signed_by(id, Kind::SIN1, "SINv1 signing"); return id; }
    if (at(d, 0, "\x02\x00\x00\x00"sv)) { signed_by(id, Kind::SIN2, "SINv2 signing"); return id; }
    if (at(d, 0, "\x03SIN"sv)) { signed_by(id, Kind::SIN3, "SINv3 signing"); return id; }

    // ---- the Android images: "ANDROID!" / "VNDRBOOT" at offset 0 or, behind a
    //      vendor wrapper, a little further in ---------------------------------
    const size_t android = search(d, 0, kMagicSearchLimit, "ANDROID!"sv);
    const size_t vendor = search(d, 0, kMagicSearchLimit, "VNDRBOOT"sv);
    if (android != kNone && (vendor == kNone || android < vendor)) {
        id.kind = Kind::AOSP;
        id.magic_offset = android;
        std::string s = "AOSP bootimg";
        if (at(d, 36, "\x00\x00\x00\x02"sv)) { id.pxa_variant = 20; s += ", PXA variant (020)"; }
        else if (at(d, 36, "\x00\x00\x80\x02"sv)) { id.pxa_variant = 28; s += ", PXA variant (028)"; }
        else if (at(d, 36, "\x00\x00\x00\x03"sv)) { id.pxa_variant = 30; s += ", PXA variant (030)"; }
        if (search(d, 96, kMagicSearchLimit, "microloader"sv) != kNone && at(d, 1024, "ANDROID!"sv)) {
            id.patch = Patch::AMONET;
            s += ", AMONET header";
        }
        if (at(d, 1024, "LOKI"sv)) {
            id.patch = Patch::LOKI;
            s += ", LOKI header";
            if (at(d, 1028, "\x00"sv)) { id.loki_type = 0; s += " (boot)"; }
            else if (at(d, 1028, "\x01"sv)) { id.loki_type = 1; s += " (recovery)"; }
        }
        if (search(d, 2048, kMagicSearchLimit, kMtkMagic) != kNone) {
            id.mtk_headers = true;
            s += ", MTK headers";
        }
        id.label = std::move(s);
        return id;
    }
    if (vendor != kNone) {
        id.kind = Kind::AOSP_VNDR;
        id.magic_offset = vendor;
        id.label = "AOSP_VNDR bootimg";
        return id;
    }

    // ---- other containers abr handles, which AIK's file does not name ------
    if (d.size() >= 4) {
        if (at(d, 0, "AVB0"sv)) {
            id.kind = Kind::VBMETA;
            id.label = "AVB vbmeta image";
            return id;
        }
        const uint32_t be = (uint32_t(d[0]) << 24) | (uint32_t(d[1]) << 16) | (uint32_t(d[2]) << 8) | d[3];
        if (be == kDtTableMagic || be == kAcpioTableMagic) {
            id.kind = Kind::DTBO;
            id.label = "dtbo image";
            return id;
        }
        if (be == kFdtMagic) {
            id.kind = Kind::DTB;
            id.label = "flattened device tree";
            return id;
        }
    }

    // ---- weak signatures: found anywhere near the start or end ----------------
    if (size_t p = search(d, 1000, kMagicSearchLimit, "\xFC\xFA\xBC\x00"sv); p != kNone) {
        id.kind = Kind::OSIP_HEADERLESS;
        id.label = "OSIP bootimg (headerless)";
        return id;
    }
    const Footers f = identify_footers(d);
    if (f.any()) {
        id.kind = f.avb1 ? Kind::AVB1 : (f.avb2 ? Kind::AVB2 : (f.bump ? Kind::BUMP : Kind::SEANDROID));
        id.label = footer_label(f);
        return id;
    }
    if (at(d, 0, kMtkMagic)) {  // ranked below the footers, as file(1) ranks it
        id.kind = Kind::MTK;
        id.label = mtk_label(d);
        return id;
    }
    return id;  // data
}

std::string Identity::aik_type() const {
    switch (kind) {
        case Kind::AOSP: return pxa_variant ? "AOSP-PXA" : "AOSP";
        case Kind::AOSP_VNDR: return "AOSP_VNDR";
        case Kind::UBOOT: return "U-Boot";
        case Kind::OSIP:
        case Kind::OSIP_HEADERLESS: return "OSIP";
        case Kind::KRNL: return "KRNL";
        case Kind::ELF: return "ELF";
        case Kind::BLOB: return "BLOB";
        case Kind::NOOK: return "NOOK";
        case Kind::NOOKTAB: return "NOOKTAB";
        case Kind::CHROMEOS: return "CHROMEOS";
        case Kind::DHTB: return "DHTB";
        case Kind::SIN1: return "SINv1";
        case Kind::SIN2: return "SINv2";
        case Kind::SIN3: return "SINv3";
        case Kind::MTK: return "MTK";
        case Kind::QCDT: return "QCDT";
        case Kind::AVB1: return "AVBv1";
        case Kind::AVB2: return "AVBv2";
        case Kind::BUMP: return "Bump";
        case Kind::SEANDROID: return "SEAndroid";
        case Kind::VBMETA: return "vbmeta";
        case Kind::DTBO: return "dtbo";
        case Kind::DTB: return "dtb";
        case Kind::UNKNOWN: break;
    }
    return "data";
}

std::string Identity::unsupported_note() const {
    switch (kind) {
        case Kind::BLOB:
            return "this is an ASUS/Qualcomm SIGNBLOB container (Android Image Kitchen opens it with "
                   "blobunpack); abr cannot unpack it yet";
        case Kind::CHROMEOS:
            return "this is a ChromeOS kernel blob (Android Image Kitchen opens it with futility "
                   "vbutil_kernel); abr cannot unpack it yet";
        case Kind::SIN1:
        case Kind::SIN2:
        case Kind::SIN3:
            return "this looks like a Sony SIN container (" + aik_type() +
                   "; Android Image Kitchen opens it with sony_dump); abr cannot unpack it yet";
        case Kind::OSIP:
        case Kind::OSIP_HEADERLESS:
            return "this is an Intel OSIP image (Android Image Kitchen opens it with mboot); abr "
                   "cannot unpack it yet";
        case Kind::KRNL:
            return "this is a Rockchip KRNL image (kernel/ramdisk with a CRC trailer; Android Image "
                   "Kitchen unpacks it with dd and packs it with rkcrc); abr cannot unpack it yet";
        case Kind::QCDT:
            return "this is a Qualcomm device-tree table (QCDT), a part of boot images rather than a "
                   "container of its own";
        case Kind::MTK:
            return "this is a kernel or ramdisk with an MTK header, a part of a boot image rather "
                   "than a container of its own; abr removes that header when it unpacks the "
                   "boot image";
        case Kind::AVB1:
        case Kind::AVB2:
        case Kind::BUMP:
        case Kind::SEANDROID:
            return "only a trailing signature/footer (" + label +
                   ") was recognised, with no image in front of it";
        default:
            return "";
    }
}

}  // namespace abr
