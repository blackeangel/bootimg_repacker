// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr -- Android Boot Repacker: unpacks and packs the images of the Android boot family and the small firmware images of a phone's
// partitions.
//
//   abr unpack -i <input.img>    [-o <output_folder>]
//   abr pack   -i <input_folder> [-o <output_image>]
//   abr info   -i <input.img>
//   abr help
//   abr version
//
// What an image is (its format, what it is wrapped in, how its parts are compressed, how it is signed) is found out from the image
// itself; see detect_format() below.
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "abr/avb_keys.hpp"
#include "abr/boot_image.hpp"
#include "abr/byte_io.hpp"
#include "abr/compression.hpp"
#include "abr/console.hpp"
#include "abr/dtb.hpp"
#include "abr/dtbo.hpp"
#include "abr/dts.hpp"
#include "abr/envelope.hpp"
#include "abr/fdt.hpp"
#include "abr/fit.hpp"
#include "abr/identify.hpp"
#include "abr/layout.hpp"
#include "abr/legacy/amonet.hpp"
#include "abr/legacy/avb1.hpp"
#include "abr/legacy/blob.hpp"
#include "abr/legacy/chromeos.hpp"
#include "abr/legacy/dhtb.hpp"
#include "abr/legacy/elf_boot.hpp"
#include "abr/legacy/krnl.hpp"
#include "abr/legacy/loki.hpp"
#include "abr/legacy/mtk.hpp"
#include "abr/legacy/osip.hpp"
#include "abr/legacy/sin.hpp"
#include "abr/manifest.hpp"
#include "abr/mbn.hpp"
#include "abr/mtkgfh.hpp"
#include "abr/mtkimg.hpp"
#include "abr/parallel.hpp"
#include "abr/png.hpp"
#include "abr/progress.hpp"
#include "abr/qcdt.hpp"
#include "abr/ramdisk_tree.hpp"
#include "abr/sha.hpp"
#include "abr/splash.hpp"
#include "abr/textquote.hpp"
#include "abr/uimage.hpp"
#include "abr/vbmeta.hpp"
#include "abr/vendor_boot.hpp"
#include "abr/version.hpp"

namespace fs = std::filesystem;
using namespace abr;
using namespace abr::legacy;

namespace {

// A command line, a name or a release string out of an image, for a line of `info` or of a message: as it is when it is
// plain text, else in double quotes with the escapes of C. An image can hold anything there, among it the control
// sequences of a terminal, and a space at the end of a command line is not to be missed.
std::string shown(std::string_view s) { return textquote::quote_shown(s); }

// The same, for a text that a message puts in double quotes (the subject of a certificate): the quotes of `shown` when it needs
// them, else these.
std::string dquoted(std::string_view s) {
    const std::string q = textquote::quote_shown(s);
    return q == s ? "\"" + q + "\"" : q;
}

// The text fields of a header that hold bytes behind the NUL that ends their text (BinaryReader::asciiz), as
// "cmdline 37, board_name 3" -- empty when none does. What `unpack` and `info` say of them; the bytes themselves are
// kept (the `*_tail` keys of manifest.txt) and an untouched repack writes them back.
std::string tails_text(std::initializer_list<std::pair<const char*, const Bytes*>> fields) {
    std::string out;
    for (const auto& [name, tail] : fields) {
        if (tail->empty()) continue;
        if (!out.empty()) out += ", ";
        out += std::string(name) + " " + std::to_string(tail->size());
    }
    return out;
}

// ------------------------------------------------------------ detection --

enum class Fmt { BOOT, VENDOR_BOOT, DTBO, DTB, FIT, QCDT, VBMETA, UIMAGE, ELF_BOOT, KRNL, BLOB, OSIP, CHROMEOS, MTK_IMAGE, MTK_PRELOADER, MBN, MBN_ELF, SPLASH, OPLUS_LOGO, XIAOMI_LOGO, MOTO_LOGO, UNKNOWN };

// Where the "ANDROID!" container starts: within the first kMagicSearchLimit bytes (a vendor
// wrapper in front of it), or -- Barnes & Noble Nook images -- right behind the fixed-size
// signature header ("master_boot.key": 1 MiB, 256 KiB on the tablets), which is further away
// than that.
size_t find_container(const Bytes& d, const char* magic) {
    size_t at = find_magic(d, magic, 8);
    if (at != std::string::npos) return at;
    const Identity id = identify(d);
    if ((id.kind == Kind::NOOK || id.kind == Kind::NOOKTAB) && id.payload_offset &&
        id.payload_offset + 8 <= d.size() && std::memcmp(d.data() + id.payload_offset, magic, 8) == 0)
        return id.payload_offset;
    return std::string::npos;
}

Fmt detect_format(const Bytes& d) {
    if (d.size() >= 8 && std::memcmp(d.data(), "ANDROID!", 8) == 0) return Fmt::BOOT;
    if (d.size() >= 8 && std::memcmp(d.data(), "VNDRBOOT", 8) == 0) return Fmt::VENDOR_BOOT;
    if (d.size() >= 4 && std::memcmp(d.data(), "AVB0", 4) == 0) return Fmt::VBMETA;
    // The codeword and the magic of an SBL header begin nothing else: a file that has them is an MBN image, or one that abr cannot read (describe_unknown()).
    if (mbn::has_sbl_words(d)) return mbn::flat_looks_like(d) ? Fmt::MBN : Fmt::UNKNOWN;
    // The picture partitions of a phone: each has a magic word of its own (at 0, or at 0x4000 behind a preamble), and what follows it adds up or it is not one
    // (describe_unknown() says what is wrong).
    if (splash::qc_looks_like(d)) return Fmt::SPLASH;
    if (splash::moto_looks_like(d)) return Fmt::MOTO_LOGO;
    if (splash::oplus_looks_like(d)) return Fmt::OPLUS_LOGO;
    if (splash::xiaomi_looks_like(d)) return Fmt::XIAOMI_LOGO;
    if (mtkimg::looks_like(d, 0)) return Fmt::MTK_IMAGE;
    if (mtkgfh::looks_like(d)) return Fmt::MTK_PRELOADER;
    if (qcdt::looks_like(d)) return Fmt::QCDT;
    if (has_chromeos_header(d)) return Fmt::CHROMEOS;
    if (d.size() >= 4) {
        uint32_t be = (uint32_t(d[0]) << 24) | (uint32_t(d[1]) << 16) | (uint32_t(d[2]) << 8) | d[3];
        if (be == kDtTableMagic || be == kAcpioTableMagic) return Fmt::DTBO;
        if (be == kFdtMagic) return fit::looks_like(d) ? Fmt::FIT : Fmt::DTB;
        if (be == kUimageMagic) return Fmt::UIMAGE;
    }
    if (BlobImage::looks_like(d)) return Fmt::BLOB;
    if (d.size() >= 64 && std::memcmp(d.data() + d.size() - 64, "AVBf", 4) == 0) return Fmt::VBMETA;
    // An ELF with a hash segment is an image of Qualcomm's secure boot, not a Sony boot image: asked first.
    if (mbn::elf_looks_like(d)) return Fmt::MBN_ELF;
    // ... and one whose hash segment cannot be read (the .mdt of a split firmware, say) is not a Sony boot image either: describe_unknown() says what is wrong.
    if (!mbn::elf_problem(d).empty()) return Fmt::UNKNOWN;
    if (ElfBootImage::looks_like(d)) return Fmt::ELF_BOOT;
    if (KrnlImage::looks_like(d)) return Fmt::KRNL;
    if (OsipImage::looks_like(d)) return Fmt::OSIP;
    // The flat MBN image has no magic, only a small number and a version in its first two words: asked last of the formats.
    if (mbn::flat_looks_like(d)) return Fmt::MBN;
    // What starts like a Sony SIN container is never an ordinary image behind a vendor wrapper, even if an
    // "ANDROID!" can be found in the first 64 KiB: when the container holds a boot-family image,
    // peel_wrappers() has taken it off before this is asked, and when it does not (a system.sin) or is damaged,
    // describe_unknown() says what is wrong with it -- Android Image Kitchen, which names such a file a SIN by its
    // first four bytes as well, does not open it either.
    if (legacy::has_sin_header(d)) return Fmt::UNKNOWN;
    // A vendor wrapper in front of an ordinary image (Spreadtrum BFBF/SSSS,
    // for one): the container's magic is not at offset 0 but close to it.
    // This is only consulted once nothing else matched, so a stray
    // "ANDROID!" deep inside some other format cannot hijack it.
    size_t a = find_container(d, "ANDROID!");
    size_t v = find_magic(d, "VNDRBOOT", 8);
    if (a != std::string::npos && (v == std::string::npos || a < v)) return Fmt::BOOT;
    if (v != std::string::npos) return Fmt::VENDOR_BOOT;
    return Fmt::UNKNOWN;
}

// A clear message for the things people commonly feed to a boot-image tool
// by mistake, instead of a bare "unrecognized format".
std::string describe_unknown(const Bytes& d) {
    // Sony SIN: the container is described, and what is inside it, when abr cannot open that.
    if (legacy::has_sin_header(d)) {
        try {
            const legacy::SinInfo s = legacy::parse_sin(d);
            const std::string what = "this is a " + legacy::describe_sin(s);
            if (s.payload_size > legacy::kSinMaxPayload)
                return what + ". abr opens a SIN that holds a boot-family image (what Android Image Kitchen does with it); "
                              "this one holds a partition image (system, vendor, userdata ...), far too large for one";
            const Bytes inside = legacy::extract_sin(d, s);
            return what + ", and what is inside is not an image abr unpacks: " +
                   (legacy::has_sin_header(inside) ? std::string("another SIN container") : describe_unknown(inside));
        } catch (const FormatError& e) {
            return "this looks like a Sony SIN container (" + identify(d).aik_type() + ") that abr cannot read: " + e.what();
        }
    }
    auto u32le = [&](size_t off) -> uint32_t {
        if (off + 4 > d.size()) return 0;
        return uint32_t(d[off]) | (uint32_t(d[off + 1]) << 8) | (uint32_t(d[off + 2]) << 16) |
               (uint32_t(d[off + 3]) << 24);
    };
    auto u16le = [&](size_t off) -> uint32_t {
        if (off + 2 > d.size()) return 0;
        return uint32_t(d[off]) | (uint32_t(d[off + 1]) << 8);
    };
    if (u32le(0) == mtkimg::kMagic && d.size() >= 4) {
        try {
            (void)mtkimg::scan(d);
        } catch (const FormatError& e) {
            return std::string("this starts like a MediaTek partition image (the header of a section, magic 0x58881688), but abr cannot read it: ") + e.what();
        }
    }
    if (mtkgfh::find_chain(d)) {
        try {
            (void)mtkgfh::parse(d);
        } catch (const FormatError& e) {
            return std::string("this starts like the loader of a MediaTek boot ROM (a chain of GFH headers that begins with FILE_INFO), but abr cannot read it: ") + e.what();
        }
    }
    if (const std::optional<mtkgfh::Device> dev = mtkgfh::parse_device(d))
        return "this starts with the device header and the BRLYT of a MediaTek boot partition image (" + dev->boot_name + "), but there is no FILE_INFO header at offset " +
               std::to_string(dev->header_size) + ", where the BRLYT says the loader starts";
    if (const std::optional<mtkgfh::Marker> mark = mtkgfh::find_bloader_marker(d); mark && mark->offset == 0)
        return "this starts with " + mark->text + ", the text that stands near the end of the code of a MediaTek preloader: it is that record on its own, not a loader image "
               "(a preloader has the GFH headers, FILE_INFO first, in front of its code), and abr cannot unpack it";
    if (const std::string why = mbn::elf_problem(d); !why.empty())
        return "this is an ELF with a hash segment, an image of Qualcomm's secure boot (an MBN), but abr cannot read it: " + why;
    if (mbn::has_sbl_words(d)) {
        const std::string why = mbn::flat_problem(d);
        return "this starts with the codeword and the magic of the SBL header of an MBN image of Qualcomm's secure boot, but abr cannot read it: " +
               (why.empty() ? std::string("it holds no code") : why);
    }
    if (d.size() >= 40 && u32le(0) <= 0xFF && (u32le(4) == 3 || u32le(4) == 5 || u32le(4) == 6 || u32le(4) == 7)) {
        const std::string why = mbn::block_problem(d, 0, d.size());
        return "this starts like the header of an MBN image of Qualcomm's secure boot (version " + std::to_string(u32le(4)) + "), but abr cannot read it: " +
               (why.empty() ? std::string("it holds no code") : why);
    }
    if (d.size() >= sizeof splash::kQcMagic && std::memcmp(d.data(), splash::kQcMagic, sizeof splash::kQcMagic) == 0)
        return "this starts with \"SPLASH!!\", the image of the pictures that the boot loader of a Qualcomm phone shows, but abr cannot read it: " + splash::qc_problem(d);
    if (d.size() >= sizeof splash::kMotoMagic && std::memcmp(d.data(), splash::kMotoMagic, sizeof splash::kMotoMagic) == 0)
        return "this starts with \"MotoLogo\", the image of the pictures that the boot loader of a Motorola phone shows, but abr cannot read it: " + splash::moto_problem(d);
    if (d.size() >= splash::kOplusPreamble + sizeof splash::kOplusMagic && std::memcmp(d.data() + splash::kOplusPreamble, splash::kOplusMagic, sizeof splash::kOplusMagic) == 0)
        return "this has \"SPLASH LOGO!\" at 0x4000, the logo image of an OPPO, realme or OnePlus phone, but abr cannot read it: " + splash::oplus_problem(d);
    if (d.size() >= splash::kXiaomiPreamble + sizeof splash::kXiaomiMagic && std::memcmp(d.data() + splash::kXiaomiPreamble, splash::kXiaomiMagic, sizeof splash::kXiaomiMagic) == 0)
        return "this has \"LOGO!!!!\" at 0x4000, the logo image of a Xiaomi or Redmi phone, but abr cannot read it: " + splash::xiaomi_problem(d);
    if (u16le(0x438) == 0xEF53)
        return "this is an ext2/3/4 filesystem image (system/vendor/product/... or a recovery "
               "dumped as a filesystem), not a boot-family container. Filesystems are out of "
               "scope for abr; extract it with an ext4 tool (e.g. e2fstool / debugfs) instead";
    if (u32le(0) == 0xED26FF3A)
        return "this is an Android sparse image; convert it with simg2img first (sparse/"
               "filesystem images are out of scope for abr)";
    if (u32le(1024) == 0xF2F52010)
        return "this is an F2FS filesystem image; use f2fs_unpacker (filesystems are out of scope "
               "for abr)";
    if (u32le(1024) == 0xE0F5E1E2)
        return "this is an EROFS filesystem image (filesystems are out of scope for abr)";
    if (d.size() >= 4 && std::memcmp(d.data(), "hsqs", 4) == 0)
        return "this is a SquashFS image (filesystems are out of scope for abr)";
    if (d.size() >= 4 && std::memcmp(d.data(), "PK\x03\x04", 4) == 0)
        return "this is a ZIP archive, not a boot-family image";
    if (d.size() >= 6 && std::memcmp(d.data(), "070701", 6) == 0)
        return "this is a raw cpio archive (a ramdisk), not a boot-family image";
    // Not something abr unpacks, but something Android Image Kitchen's signature file names:
    // say what it is rather than "unrecognized".
    if (std::string note = identify(d).unsupported_note(); !note.empty()) return note;
    return "unrecognized image format (no boot/vendor_boot/dtbo/dtb/vbmeta/uImage/ELF signature "
           "found in the first 64 KiB)";
}

const char* fmt_name(Fmt f) {
    switch (f) {
        case Fmt::BOOT: return "boot";
        case Fmt::VENDOR_BOOT: return "vendor_boot";
        case Fmt::DTBO: return "dtbo";
        case Fmt::DTB: return "dtb";
        case Fmt::FIT: return "fit";
        case Fmt::QCDT: return "qcdt";
        case Fmt::VBMETA: return "vbmeta";
        case Fmt::UIMAGE: return "uimage";
        case Fmt::ELF_BOOT: return "elf_boot";
        case Fmt::KRNL: return "krnl";
        case Fmt::BLOB: return "blob";
        case Fmt::OSIP: return "osip";
        case Fmt::CHROMEOS: return "chromeos";
        case Fmt::MTK_IMAGE: return "mtk_image";
        case Fmt::MTK_PRELOADER: return "mtk_preloader";
        case Fmt::MBN: return "mbn";
        case Fmt::MBN_ELF: return "mbn_elf";
        case Fmt::SPLASH: return "splash";
        case Fmt::OPLUS_LOGO: return "oplus_logo";
        case Fmt::XIAOMI_LOGO: return "xiaomi_logo";
        case Fmt::MOTO_LOGO: return "moto_logo";
        case Fmt::UNKNOWN: return "unknown";
    }
    return "unknown";
}

Fmt fmt_from_name(const std::string& s) {
    if (s == "boot") return Fmt::BOOT;
    if (s == "vendor_boot") return Fmt::VENDOR_BOOT;
    if (s == "dtbo") return Fmt::DTBO;
    if (s == "dtb") return Fmt::DTB;
    if (s == "fit") return Fmt::FIT;
    if (s == "qcdt") return Fmt::QCDT;
    if (s == "vbmeta") return Fmt::VBMETA;
    if (s == "uimage") return Fmt::UIMAGE;
    if (s == "elf_boot") return Fmt::ELF_BOOT;
    if (s == "krnl") return Fmt::KRNL;
    if (s == "blob") return Fmt::BLOB;
    if (s == "osip") return Fmt::OSIP;
    if (s == "chromeos") return Fmt::CHROMEOS;
    if (s == "mtk_image") return Fmt::MTK_IMAGE;
    if (s == "mtk_preloader") return Fmt::MTK_PRELOADER;
    if (s == "mbn") return Fmt::MBN;
    if (s == "mbn_elf") return Fmt::MBN_ELF;
    if (s == "splash") return Fmt::SPLASH;
    if (s == "oplus_logo") return Fmt::OPLUS_LOGO;
    if (s == "xiaomi_logo") return Fmt::XIAOMI_LOGO;
    if (s == "moto_logo") return Fmt::MOTO_LOGO;
    return Fmt::UNKNOWN;
}

// What is put around a plain image and has to come off before anything can be read: a ChromeOS kernel blob
// (abr/legacy/chromeos.hpp), a DHTB header (abr/legacy/dhtb.hpp), an ASUS blob whose only partition holds the
// image (abr/legacy/blob.hpp), and under them the loki patch (abr/legacy/loki.hpp) or the amonet patch
// (abr/legacy/amonet.hpp). Repack puts them back in the opposite order.
struct Wrappers {
    // A Sony SIN container comes off first, and unlike the others it is not put back: it is Sony's, signed and
    // hashed, and nothing here could make one for an edited image (Android Image Kitchen forgets it as well).
    // The image it held is `sin_payload`.
    std::optional<legacy::SinInfo> sin;
    std::optional<legacy::ChromeosInfo> chromeos;  // its kernel is `chromeos_inner`
    std::optional<legacy::DhtbInfo> dhtb;
    std::optional<legacy::BlobImage> blob;  // its one partition's data is `blob_inner`, not in here
    std::optional<legacy::LokiInfo> loki;
    std::optional<legacy::AmonetInfo> amonet;
    Bytes sin_payload;
    Bytes chromeos_inner;  // what the wrappers' removal leaves is kept here, if it is not `data` itself
    Bytes dhtb_inner;
    Bytes blob_inner;
    Bytes loki_plain;
    Bytes unpatched;

    bool any() const { return sin || recorded(); }
    // The wrappers the manifest records and a repack puts back: all but the SIN.
    bool recorded() const { return chromeos || dhtb || blob || loki || amonet; }
    // "sin-wrapped ", "chromeos-wrapped ", "dhtb-wrapped ", "blob-wrapped ", "loki-patched ", "amonet-patched ", or
    // several, or nothing: for the line that says what was unpacked.
    std::string adjectives() const {
        return std::string(sin ? "sin-wrapped " : "") + (chromeos ? "chromeos-wrapped " : "") + (dhtb ? "dhtb-wrapped " : "") +
               (blob ? "blob-wrapped " : "") + (loki ? "loki-patched " : "") + (amonet ? "amonet-patched " : "");
    }
};

// Takes the wrappers off `data`. The plain image is `data` itself or lives in `w`: the reference is good
// as long as both are. A blob is a wrapper only if its single partition holds something abr unpacks
// (what Android Image Kitchen does with it); any other blob is a container of its own (Fmt::BLOB). The same
// goes for a ChromeOS kernel blob (Fmt::CHROMEOS): its kernel is the plain image if abr knows what it is.
const Bytes& peel_wrappers(const Bytes& data, Wrappers& w) {
    const Bytes* outer = &data;
    // A Sony SIN container is a wrapper only when what it holds is a boot-family image (what sony_dump hands to
    // Android Image Kitchen); a partition image in a SIN, or one that cannot be read, stays what it is, and
    // describe_unknown() says why it cannot be unpacked.
    if (legacy::has_sin_header(data)) {
        try {
            legacy::SinInfo info = legacy::parse_sin(data);
            if (info.payload_size <= legacy::kSinMaxPayload) {
                Bytes inside = legacy::extract_sin(data, info);
                if (detect_format(inside) != Fmt::UNKNOWN) {
                    w.sin = std::move(info);
                    w.sin_payload = std::move(inside);
                    outer = &w.sin_payload;
                }
            }
        } catch (const FormatError&) {
        }
    }
    if (legacy::has_chromeos_header(*outer)) {
        Bytes kernel;
        std::optional<legacy::ChromeosInfo> blob = legacy::strip_chromeos(*outer, kernel);
        if (blob && detect_format(kernel) != Fmt::UNKNOWN) {
            w.chromeos = std::move(blob);
            w.chromeos_inner = std::move(kernel);
            outer = &w.chromeos_inner;
        }
    }
    w.dhtb = strip_dhtb(*outer, w.dhtb_inner);
    const Bytes* inner = w.dhtb ? &w.dhtb_inner : outer;
    if (legacy::BlobImage::looks_like(*inner)) {
        legacy::BlobImage blob = legacy::BlobImage::parse(*inner);
        if (blob.parts.size() == 1) {
            const Fmt held = detect_format(blob.parts[0].data);
            if (held != Fmt::UNKNOWN && held != Fmt::BLOB) {
                w.blob_inner = std::move(blob.parts[0].data);
                blob.parts[0].data.clear();
                w.blob = std::move(blob);
                inner = &w.blob_inner;
            }
        }
    }
    w.loki = legacy::strip_loki(*inner, w.loki_plain);
    if (w.loki) inner = &w.loki_plain;
    w.amonet = strip_amonet(*inner, w.unpatched);
    return w.amonet ? w.unpatched : *inner;
}

// What a folder can add to a pack: keys of its own for the signatures abr makes again when the content changed (the files of
// keys/ in the folder; without them abr signs with the public test keys it has, see load_folder_keys()).
struct RepackOptions {
    std::string avb_key_pem;               // keys/avb_key.pem: AVB 2.0 signing key (file contents)
    std::optional<Signer> avb1_signer;     // keys/avb1.pk8 + keys/avb1.x509.pem: AVBv1 boot signature
    legacy::ChromeosSigning chromeos;      // keys/chromeos.vbprivk + keys/chromeos.keyblock: a ChromeOS kernel blob's signature
    // The second try of build_image(): what had to be compressed again is compressed as densely as the
    // decoders allow (dense_level()), because the first try made an image too big for its partition.
    bool dense = false;
};

// Messages for the user. Components are loaded on several threads, so these are serialised.
// While a build may still be tried again (see build_image) they are held back, so that what the
// first try said is not said twice: Deferral::flush() says them, ~Deferral() drops what is left.
std::mutex g_message_mutex;
struct HeldMessage {
    bool is_warning;
    std::string text;
};
bool g_holding_messages = false;
std::vector<HeldMessage> g_held_messages;
// Set while an image is built when something was compressed at the usual setting that a denser one
// would have made smaller: only then is a second try worth it (see build_image).
std::atomic<bool> g_denser_would_help{false};
void say(bool is_warning, const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_message_mutex);
    if (g_holding_messages) {
        g_held_messages.push_back({is_warning, msg});
    } else if (is_warning) {
        std::cerr << "warning: " << msg << "\n";
    } else {
        std::cout << "note: " << msg << "\n";
    }
}
void warn(const std::string& msg) { say(true, msg); }
void note(const std::string& msg) { say(false, msg); }

class Deferral {
public:
    Deferral() {
        std::lock_guard<std::mutex> lock(g_message_mutex);
        g_holding_messages = true;
    }
    Deferral(const Deferral&) = delete;
    Deferral& operator=(const Deferral&) = delete;
    // Say what was held back, in order, and stop holding.
    void flush() {
        std::lock_guard<std::mutex> lock(g_message_mutex);
        g_holding_messages = false;
        for (const HeldMessage& h : g_held_messages) {
            if (h.is_warning) std::cerr << "warning: " << h.text << "\n";
            else std::cout << "note: " << h.text << "\n";
        }
        g_held_messages.clear();
    }
    // Forget what was held back, and stop holding.
    void discard() {
        std::lock_guard<std::mutex> lock(g_message_mutex);
        g_holding_messages = false;
        g_held_messages.clear();
    }
    ~Deferral() { discard(); }
};

// ------------------------------------------------------- component I/O --

// Auto-detects/decompresses on the way out to a component file, and
// records the codec so repack can recompress the same way by default.
// Also stashes the exact original (still-compressed) bytes plus a hash
// of the decompressed content: if the extracted file comes back
// unmodified at repack time, we replay those original bytes verbatim
// instead of recompressing, so an untouched component round-trips
// byte-for-byte rather than merely content-equivalent (recompressing
// e.g. gzip data essentially never reproduces the exact original bytes,
// since gzip/zstd/etc. headers and encoder choices vary by tool/version
// even for identical decompressed content).
//
// Also transparently strips a MediaTek (MTK) sub-header if this
// component has one (common on MTK-based devices' kernel/ramdisk),
// recording its declared type name so repack can re-add an identical
// header -- this applies uniformly to every component that goes
// through save_components/load_components (boot's kernel/ramdisk,
// vendor_boot's ramdisk fragments) since any of them could have one.
//
// The components of one image are independent, so they are decoded, hashed
// and written on several threads (abr/parallel.hpp); only the manifest, which
// is an ordered list, is filled in afterwards, one component after another.

struct DecodedComponent {
    bool present = false;                // false: the component was empty, nothing is recorded
    std::optional<std::string> mtk_name;
    std::optional<Bytes> stripped;       // the stored bytes without their MTK sub-header, when it had one
    Codec codec = Codec::NONE;
    int level = -1;                      // the level the stream was made with, when abr could tell (detect_level()); else -1
    std::string level_basis;             // how it told
    std::optional<LzmaAloneParams> lzma; // a "LZMA alone" stream: the settings its header names (lc, lp, pb, the dictionary)
    Bytes plain;                         // decompressed
    Bytes plain_hash;                    // SHA-256 of `plain`

    // The stored (still compressed) bytes, as they go to .abr_raw.
    const Bytes& stored(const Bytes& raw) const { return stripped ? *stripped : raw; }
};

// `what` names the component in the message of a stream that cannot be decompressed (a damaged image, or a bomb: a stream
// that would be more than kMaxDecompressedSize); empty, the message does not name it.
DecodedComponent decode_component(const Bytes& raw, std::string_view what = {}, bool strip_mtk = true) {
    DecodedComponent d;
    if (raw.empty()) return d;
    d.present = true;
    Bytes after_mtk;
    if (auto mtk = strip_mtk ? strip_mtk_header(raw, after_mtk) : std::nullopt) {
        d.mtk_name = mtk->name;
        d.stripped = std::move(after_mtk);
    }
    const Bytes& working = d.stored(raw);
    d.codec = detect_codec(working);
    try {
        d.plain = decompress(d.codec, working);
    } catch (const FormatError& e) {
        throw FormatError((what.empty() ? std::string() : shown(what) + ": ") + std::string(codec_name(d.codec)) +
                          " stream cannot be decompressed: " + e.what());
    }
    d.plain_hash = hash::sha256(d.plain);
    if (d.codec != Codec::NONE) {
        const LevelGuess guess = detect_level(d.codec, working, d.plain);
        d.level = guess.level;
        d.level_basis = guess.basis;
        if (d.codec == Codec::LZMA) d.lzma = lzma_alone_params(working);
    }
    return d;
}

struct ComponentSource {
    const Bytes* raw;       // the component as found in the image
    std::string filename;   // its file in the unpack directory
};

// Decodes every component and writes its files (the decompressed content, and
// the original bytes under .abr_raw/). Results come back in input order.
std::vector<DecodedComponent> save_components(const fs::path& dir,
                                              const std::vector<ComponentSource>& sources) {
    std::vector<size_t> order(sources.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    // Biggest first: the longest job should not be the one left for last.
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return sources[a].raw->size() > sources[b].raw->size();
    });
    const bool any = !order.empty() && !sources[order[0]].raw->empty();
    if (any) fs::create_directories(dir / ".abr_raw");

    uint64_t work = 0;
    for (const ComponentSource& s : sources) work += s.raw->size();
    progress::enter("decode", work);

    std::vector<DecodedComponent> out(sources.size());
    par::for_each(sources.size(), [&](size_t k) {
        const size_t i = order[k];
        const progress::Activity doing(sources[i].filename);
        out[i] = decode_component(*sources[i].raw, sources[i].filename);
        if (out[i].present) {
            write_file(dir / sources[i].filename, out[i].plain);
            write_file(dir / ".abr_raw" / (sources[i].filename + ".raw"), out[i].stored(*sources[i].raw));
        }
        progress::advance(sources[i].raw->size());
    });
    return out;
}

void record_component(Manifest& m, const std::string& prefix, const std::string& filename,
                      const DecodedComponent& d) {
    if (!d.present) return;
    if (d.mtk_name) m.set(prefix + "_mtk_name", *d.mtk_name);
    m.set(prefix + "_file", filename);
    m.set(prefix + "_compression", std::string(codec_name(d.codec)));
    // The level of the stream, when abr could tell: pack compresses the component again at it when the file was changed. Without the
    // key (xz, lzma, lz4 frame, or a stream made in a way abr does not make) pack uses the usual level of the compression.
    if (d.level >= 0) {
        m.set(prefix + "_level", std::to_string(d.level));
        m.set(prefix + "_level_basis", d.level_basis);  // for a person: pack does not read it
    }
    // A "LZMA alone" stream has no level, it has the four settings of its header: pack makes an edited component again with them.
    if (d.lzma) {
        m.set(prefix + "_lzma_lc", std::to_string(d.lzma->lc));
        m.set(prefix + "_lzma_lp", std::to_string(d.lzma->lp));
        m.set(prefix + "_lzma_pb", std::to_string(d.lzma->pb));
        m.set(prefix + "_lzma_dict", std::to_string(d.lzma->dict_size));
    }
    m.set_hex(prefix + "_orig_hash", d.plain_hash);
}

// A ramdisk that is a cpio archive is also written as a directory (ramdisk_tree.hpp): the file
// stays what the image held, byte for byte, the directory is what a person edits. The manifest
// records the directory and the hash of the archive it builds, so that repack can tell whether it
// was edited. When an archive cannot be a directory, it stays a file only and the reason is said.
struct TreeJob {
    std::string prefix;    // "ramdisk", "ramdisk0", ...: also the name of the directory
    std::string filename;  // the archive's file, "ramdisk.cpio"
    const DecodedComponent* decoded;
};

// How many cpio archives one after the other (see ramdisk_tree.hpp) the unpack recorded for `prefix`.
size_t recorded_volumes(const Manifest& m, const std::string& prefix) {
    return static_cast<size_t>(m.get_int(prefix + "_tree_volumes", 1, 1, 256));
}

void save_ramdisk_trees(Manifest& m, const fs::path& dir, const std::vector<TreeJob>& jobs) {
    // What an earlier unpack into this directory left is replaced; a directory of the same name
    // that is anything else is somebody's, and is never touched (the library refuses to write over it).
    std::map<std::string, size_t> earlier;  // the ramdisks an earlier unpack made, and how many archives each had
    try {
        const Manifest old = Manifest::load(dir / "manifest.txt");
        for (const TreeJob& j : jobs)
            if (old.has(j.prefix + "_tree")) earlier[j.prefix] = recorded_volumes(old, j.prefix);
    } catch (const std::exception&) {
    }

    std::vector<const TreeJob*> todo;
    for (const TreeJob& j : jobs) {
        if (!j.decoded->present) continue;
        if (const auto owned = earlier.find(j.prefix); owned != earlier.end()) {
            std::error_code ec;
            for (size_t i = 0; i < owned->second; ++i) {
                const fs::path tree = dir / ramdisk_volume_name(j.prefix, i);
                if (fs::exists(fs::symlink_status(tree, ec))) fs::remove_all(tree, ec);
                fs::remove(dir / ramdisk_volume_meta(j.prefix, i), ec);
            }
        }
        todo.push_back(&j);
    }

    std::vector<RamdiskTree> results(todo.size());
    std::vector<std::string> failures(todo.size());
    uint64_t work = 0;
    for (const TreeJob* j : todo) work += j->decoded->plain.size();
    progress::enter("tree", work);
    par::for_each(todo.size(), [&](size_t k) {
        const TreeJob& j = *todo[k];
        const progress::Activity doing(j.prefix + "/");
        try {
            results[k] = extract_ramdisk_tree(j.decoded->plain, dir, j.prefix);
        } catch (const std::exception& e) {
            failures[k] = e.what();
        }
        progress::advance(j.decoded->plain.size());
    });

    for (size_t k = 0; k < todo.size(); ++k) {
        const TreeJob& j = *todo[k];
        const RamdiskTree& t = results[k];
        if (!failures[k].empty()) {
            note(j.filename + " stays a file only, the directory could not be written: " + failures[k]);
            continue;
        }
        if (!t.created) {
            if (!t.reason.empty()) note(j.filename + " stays a file only, it cannot be a directory: " + t.reason);
            continue;
        }
        m.set(j.prefix + "_tree", j.prefix);
        if (t.volumes > 1) m.set(j.prefix + "_tree_volumes", std::to_string(t.volumes));
        m.set_hex(j.prefix + "_tree_hash", t.rebuilt_sha256);
        // (with slashes whatever the system, so that "out/ramdisk/" is not "out\ramdisk/" on Windows)
        std::string where = (dir / j.prefix).generic_string() + "/";
        std::string metas = j.prefix + ".meta";
        for (size_t i = 1; i < t.volumes; ++i) {
            where += ", " + (dir / ramdisk_volume_name(j.prefix, i)).generic_string() + "/";
            metas += ", " + ramdisk_volume_meta(j.prefix, i);
        }
        std::cout << "ramdisk: " << t.entries << " entries"
                  << (t.volumes > 1 ? " in " + std::to_string(t.volumes) + " cpio archives one after the other" : std::string())
                  << " -> " << where << " (+ " << metas << ")\n";
        if (!t.exact)
            warn("the directory " + j.prefix + "/ does not give " + j.filename + " back exactly (" +
                 t.difference + "); the file is exact. An edit of the directory rebuilds the archive from it.");
    }
}

// The raw copy of a component (.abr_raw/<file>.raw) goes into the image in place of the component when that is unchanged -- it
// is what keeps the very bytes of an image that cannot be made again. It is believed only when it gives the component back:
// a directory can come from anyone, and bytes there that read as one kernel in `kernel` and are another in .abr_raw would be
// built into the image where nobody looks, or a copy that was cut short would make an image that does not start.
void check_raw_copy(const fs::path& raw_path, const Bytes& raw, const Bytes& stored_hash, const std::string& filename) {
    std::string why;
    try {
        if (hash::sha256(decompress(detect_codec(raw), raw)) == stored_hash) return;
        why = "it does not decompress to " + filename + " as it was unpacked";
    } catch (const std::exception& e) {
        why = std::string("it does not decompress (") + e.what() + ")";
    }
    throw FormatError(textquote::quote_shown(raw_path.generic_string()) + " does not belong to " + textquote::quote_shown(filename) + ": " + why +
                      ". Delete it to have " + textquote::quote_shown(filename) + " compressed again, or unpack the image again");
}

// A component that goes into the image as it is (`<prefix>_compression=none`) is not left alone when that image is unpacked, if
// it starts like a stream of one of the codecs: abr takes it for one and decompresses it. A stream put there that is damaged, or
// one that would be more than kMaxDecompressedSize, would make an image that abr refuses to unpack: it is refused here, with the
// two ways out (the plain data in the file and the compression in the manifest, or a stream that is whole).
void check_unpacks_as_is(const Bytes& stored, const std::string& prefix, const std::string& filename) {
    const Codec seen = detect_codec(stored);
    if (seen == Codec::NONE) return;
    try {
        (void)decompress(seen, stored);
    } catch (const FormatError& e) {
        throw FormatError(shown(filename) + " goes into the image as it is (" + shown(prefix + "_compression=none") + "), and the " +
                          std::string(codec_name(seen)) + " stream it starts with cannot be decompressed (" + e.what() +
                          "): abr would refuse to unpack that image. Put the plain data in the file and name its compression in "
                          "manifest.txt, or put a whole stream there");
    }
}

// What goes into the image for one component. For a ramdisk that also exists as a directory (see
// ramdisk_tree.hpp) there are two places it may have been edited, and which one counts is decided
// by what changed since unpacking, not by file times: the file by the hash of its contents, the
// directory by the hash of the archive that is built from it. Nothing changed: the bytes the image
// had are replayed. One changed: that one wins. Both: abr cannot merge them, the directory wins and abr
// says so. `replayed`, when given, says which of the two it was: true for the bytes the image had,
// false for a component that was made (compressed) again.
Bytes load_component(const Manifest& m, const fs::path& dir, const std::string& prefix,
                     const RepackOptions& opt, bool* replayed = nullptr) {
    if (replayed) *replayed = false;
    const std::string key = prefix + "_file";
    if (!m.has(key)) return {};
    const std::string filename = m.get_path(key);
    const progress::Activity doing(filename);
    const fs::path file = dir / filename;
    const fs::path raw_path = dir / ".abr_raw" / (filename + ".raw");
    const Bytes stored_hash = m.get_hex(prefix + "_orig_hash");
    const bool has_tree_entry = m.has(prefix + "_tree");
    std::optional<Bytes> from_file;
    Bytes file_hash;
    if (fs::exists(file)) {
        from_file = read_file(file);
        file_hash = hash::sha256(*from_file);
    }
    const bool file_changed = from_file && (stored_hash.empty() || file_hash != stored_hash);

    std::optional<Bytes> from_tree;
    Bytes tree_hash;
    bool tree_changed = false;
    std::string tree_name;
    PackReport report;  // what building from the directories had to say (notes are said only if it is used)
    if (has_tree_entry) {
        tree_name = m.get_path(prefix + "_tree");
        // The directories of all the archives (see ramdisk_tree.hpp): one that is gone leaves its archive
        // out, and only when every one is gone is the directory as good as not there.
        const size_t volumes = recorded_volumes(m, prefix);
        bool any_directory = false;
        for (size_t i = 0; i < volumes; ++i) any_directory = any_directory || fs::is_directory(dir / ramdisk_volume_name(tree_name, i));
        if (any_directory) {
            Bytes rebuilt = pack_ramdisk_tree(dir, tree_name, volumes, &report);
            for (const std::string& w : report.warnings) warn(w);
            tree_hash = hash::sha256(rebuilt);
            tree_changed = tree_hash != m.get_hex(prefix + "_tree_hash");
            if (tree_changed || !from_file) from_tree = std::move(rebuilt);
        }
    }
    if (tree_changed && file_changed)
        warn("both " + textquote::quote_shown(filename) + " and the directory " + textquote::quote_shown(tree_name + "/") +
             " have been changed since unpacking, and abr cannot merge the two: the image is made from the directory, and what was changed in " +
             textquote::quote_shown(filename) + " is not in it. Delete the directory to have the file used");

    const bool use_tree = from_tree.has_value();
    if (!use_tree && !from_file) from_file = read_file(file);  // neither is there: the usual error
    const Bytes& plain = use_tree ? *from_tree : *from_file;
    const bool original = !stored_hash.empty() && (use_tree ? tree_hash : file_hash) == stored_hash;

    Bytes result;
    if (original && fs::exists(raw_path)) {
        result = read_file(raw_path);  // untouched: the very bytes the image had
        check_raw_copy(raw_path, result, stored_hash, filename);
        if (replayed) *replayed = true;
        progress::advance(plain.size());
    } else {
        if (use_tree) {
            for (const std::string& n : report.notes) note(n);
            std::string from;  // "ramdisk/", "ramdisk/ and ramdisk.vol2/", "ramdisk/, ramdisk.vol2/ and ramdisk.vol3/"
            for (size_t i = 0; i < report.built.size(); ++i)
                from += (i == 0 ? "" : i + 1 == report.built.size() ? " and " : ", ") + shown(report.built[i] + "/");  // (names of the manifest)
            const std::string size = std::to_string(plain.size()) + " bytes";
            note("the " + shown(prefix) + " is built from the director" + (report.built.size() > 1 ? "ies " : "y ") + from + " (" +
                 (report.built.size() > 1 ? std::to_string(report.built.size()) + " cpio archives one after the other, " : std::string()) +
                 size + ")");
        }
        // The name of a compression that abr does not know is not taken for "none": the component would go into the image as it is,
        // and the typo of a name (`gzp`) would be the last that anyone hears of it.
        const std::string codec_text = m.get(prefix + "_compression", "none");
        const std::optional<Codec> named = codec_from_name(codec_text);
        if (!named)
            throw FormatError("manifest.txt: " + shown(prefix + "_compression=" + codec_text) +
                              " is none of the compressions abr knows (none, gzip, lz4_legacy, lz4, zstd, xz, lzma, bzip2, lzo, zlib)");
        const Codec codec = *named;
        // `<prefix>_level=N` in the manifest is the compression level (codec-specific): the one the stream of the image was made with, when
        // unpack could tell, or the one a person wrote. Absent or -1: the codec's usual level. On the second try of a build that did not fit
        // its partition it is the densest the decoders allow, when that is denser than the level above.
        int level = static_cast<int>(m.get_int(prefix + "_level", -1, -1, 22));
        const int dense = dense_level(codec);
        if (dense >= 0 && (level >= 0 ? level : default_level(codec)) < dense) {
            if (opt.dense) level = dense;
            else g_denser_would_help = true;
        }
        if (codec == Codec::LZMA && m.has(prefix + "_lzma_dict")) {
            // the settings of the stream of the image (lc, lp, pb, the dictionary), or the ones a person wrote
            LzmaAloneParams params;
            params.lc = static_cast<uint8_t>(m.get_int(prefix + "_lzma_lc", 3, 0, 8));
            params.lp = static_cast<uint8_t>(m.get_int(prefix + "_lzma_lp", 0, 0, 4));
            params.pb = static_cast<uint8_t>(m.get_int(prefix + "_lzma_pb", 2, 0, 4));
            params.dict_size = static_cast<uint32_t>(m.get_int(prefix + "_lzma_dict", 8 << 20, 4096, 0x60000000));
            result = lzma_alone_compress(plain, params);
            progress::advance(plain.size());
        } else {
            result = compress(codec, plain, level, [](size_t n) { progress::advance(n); });
        }
        if (codec == Codec::NONE) check_unpacks_as_is(result, prefix, filename);
    }
    if (m.has(prefix + "_mtk_name")) result = add_mtk_header(result, m.get(prefix + "_mtk_name"));
    return result;
}

// load_component() for several components at once, on several threads (the
// recompression of an edited one is where the time goes). In input order.
std::vector<Bytes> load_components(const Manifest& m, const fs::path& dir,
                                   const std::vector<std::string>& prefixes, const RepackOptions& opt,
                                   std::vector<char>* replayed = nullptr) {
    if (replayed) replayed->assign(prefixes.size(), 0);
    std::vector<uintmax_t> size(prefixes.size(), 0);
    std::vector<size_t> order(prefixes.size());
    for (size_t i = 0; i < prefixes.size(); ++i) {
        order[i] = i;
        std::error_code ec;
        if (m.has(prefixes[i] + "_file")) {
            auto n = fs::file_size(dir / m.get_path(prefixes[i] + "_file"), ec);
            if (!ec) size[i] = n;
        }
    }
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return size[a] > size[b]; });
    std::vector<Bytes> out(prefixes.size());
    par::for_each(prefixes.size(), [&](size_t k) {
        const size_t i = order[k];
        bool again = false;
        out[i] = load_component(m, dir, prefixes[i], opt, &again);
        if (replayed) (*replayed)[i] = again ? 1 : 0;
    });
    return out;
}

// Plain, uncompressed passthrough for blobs that are never themselves
// wrapped in a stream codec (public keys, boot_signature, bootconfig...).
void save_raw(Manifest& m, const fs::path& dir, const std::string& prefix, const Bytes& raw,
              const std::string& filename) {
    if (raw.empty()) return;
    m.set(prefix + "_file", filename);
    write_file(dir / filename, raw);
}
Bytes load_raw(const Manifest& m, const fs::path& dir, const std::string& prefix) {
    std::string key = prefix + "_file";
    if (!m.has(key)) return {};
    return read_file(dir / m.get_path(key));
}

// The bytes that are not zero in the padding behind a component (BootImage::section_padding, VendorBootImage::
// section_padding): one file for each component that has some, `<component>_padding.bin`, named by
// `<component>_padding_file` -- and nothing for a component whose padding is zeros, so an ordinary image has none.
template <typename Names>
void save_section_padding(Manifest& m, const fs::path& dir, const std::map<std::string, Bytes>& padding,
                          const Names& components) {
    for (const char* c : components)
        if (const auto it = padding.find(c); it != padding.end())
            save_raw(m, dir, std::string(c) + "_padding", it->second, std::string(c) + "_padding.bin");
}
template <typename Names>
std::map<std::string, Bytes> load_section_padding(const Manifest& m, const fs::path& dir, const Names& components) {
    std::map<std::string, Bytes> out;
    for (const char* c : components)
        if (Bytes b = load_raw(m, dir, std::string(c) + "_padding"); !b.empty()) out[c] = std::move(b);
    return out;
}
// "kernel 211, ramdisk 3" (the bytes from the end of the component to the last one that is not zero), what `unpack` and
// `info` say of such padding; empty when there is none.
template <typename Names>
std::string padding_text(const std::map<std::string, Bytes>& padding, const Names& components) {
    std::string out;
    for (const char* c : components)
        if (const auto it = padding.find(c); it != padding.end() && !it->second.empty())
            out += (out.empty() ? "" : ", ") + std::string(c) + " " + std::to_string(it->second.size());
    return out;
}

// ------------------------------------------------- envelope (prefix/tail) --
//
// See abr/envelope.hpp. The manifest records the bytes around the container
// as plain files (`prefix.bin`, `tail.bin`) plus `pad_byte`/`pad_to`, so the
// rebuilt file is the original wrapper around the rebuilt container.

// `core` is the container proper (host[core_off, core_off + core_len)). Its
// hash is recorded when something is kept around it, so repack can tell
// whether the container was edited -- see assemble_envelope().
void save_envelope(Manifest& m, const fs::path& dir, const Envelope& e, const Bytes& host,
                   size_t core_off, size_t core_len) {
    if (!e.prefix.empty()) save_raw(m, dir, "prefix", e.prefix, "prefix.bin");
    if (!e.tail.empty()) save_raw(m, dir, "tail", e.tail, "tail.bin");
    if (e.pad_to) {
        m.set_addr("pad_byte", e.pad_byte);
        m.set_u64("pad_to", e.pad_to);
    }
    if (!e.prefix.empty() || !e.tail.empty()) {
        core_off = std::min(core_off, host.size());
        core_len = std::min(core_len, host.size() - core_off);
        hash::Sha256 h;
        if (core_len) h.update(host.data() + core_off, core_len);
        m.set_hex("core_sha256", h.finish());
    }
}

// `prefix_kind` says that the bytes in front of the image are a constant signing header (Nook's), one that an edit of the image
// leaves valid, so that repack keeps it without a warning. It has to be that header still -- the whole of it, with the name that tells
// it where the bootloader looks -- or what comes out is no Nook image for anybody, abr included.
void check_prefix_kind(const std::string& kind, const Bytes& prefix) {
    if (kind != "NOOK" && kind != "NOOKTAB")
        throw FormatError("manifest.txt: prefix_kind=" + shown(kind) + " is not a kind of header that abr knows (NOOK or NOOKTAB)");
    const Identity id = identify(prefix);
    if (id.aik_type() != kind)
        throw FormatError("prefix.bin is not a " + kind + " signing header any more (prefix_kind=" + kind +
                          " in manifest.txt says it is): the name that tells it, \"Green Loader\" and the like at byte 64 (\"BauwksBoot\" "
                          "at byte 48 on a tablet), is not there");
    if (id.payload_offset != prefix.size())
        throw FormatError("prefix.bin is " + std::to_string(prefix.size()) + " bytes; a " + kind + " signing header is " +
                          std::to_string(id.payload_offset) + " bytes");
}

Envelope load_envelope(const Manifest& m, const fs::path& dir) {
    Envelope e;
    e.prefix = load_raw(m, dir, "prefix");
    if (m.has("prefix_kind")) check_prefix_kind(m.get("prefix_kind"), e.prefix);
    e.tail = load_raw(m, dir, "tail");
    e.pad_byte = static_cast<uint8_t>(m.get_bounded("pad_byte", 0, 8));
    e.pad_to = m.get_size("pad_to", 0);
    return e;
}

// A tail that is only zero fill and/or the constant footers a bootloader looks for -- Samsung's
// "SEANDROIDENFORCE", LG's Bump magic -- is not a signature of the image: they do not depend on
// its content, so they stay valid when it is edited. Anything else kept around an edited
// container is, or may be, a signature. `from` skips that many leading bytes of the tail (a
// signature abr has just regenerated for the new image).
bool tail_is_inert(const Bytes& tail, size_t from = 0) {
    static const std::string_view kMarkers[] = {
        std::string_view("SEANDROIDENFORCE"),
        std::string_view(reinterpret_cast<const char*>(kBumpMagic), sizeof kBumpMagic),
    };
    size_t i = from;
    while (i < tail.size()) {
        if (tail[i] == 0) {
            ++i;
            continue;
        }
        bool known = false;
        for (std::string_view marker : kMarkers) {
            if (tail.size() - i >= marker.size() &&
                std::memcmp(tail.data() + i, marker.data(), marker.size()) == 0) {
                i += marker.size();
                known = true;
                break;
            }
        }
        if (!known) return false;
    }
    return true;
}

// The prefix is inert when it is the Nook signature header: AIK keeps it as master_boot.key and
// puts it back in front of whatever image it builds.
bool envelope_is_inert(const Manifest& m, const Envelope& e, size_t tail_from = 0) {
    return (e.prefix.empty() || m.has("prefix_kind")) && tail_is_inert(e.tail, tail_from);
}

// Did the rebuilt container differ from the one that was unpacked? (False
// when the manifest recorded no hash, i.e. nothing was kept around it.)
bool core_changed(const Manifest& m, const Bytes& core) {
    Bytes original = m.get_hex("core_sha256");
    return !original.empty() && hash::sha256(core) != original;
}

// `regenerated`: leading bytes of e.tail that were just rebuilt for `core` (an
// AVBv1 signature) and are therefore not stale.
Bytes assemble_envelope(const Manifest& m, const Envelope& e, const Bytes& core, bool changed,
                        size_t regenerated, const RepackOptions& opt) {
    if (changed && !envelope_is_inert(m, e, regenerated)) {
        warn("the image was changed, but the " + std::to_string(e.prefix.size()) +
             " bytes before it and the " + std::to_string(e.tail.size() - regenerated) +
             " bytes after it (vendor wrapper / signature data) are kept as they were; any "
             "signature, size or checksum stored there still describes the ORIGINAL image, so a "
             "bootloader that verifies it may reject the result");
    }
    std::string outgrown;
    Bytes out = e.assemble(core, &outgrown);
    // Bigger than the partition it was padded to: if something was compressed at a setting that has a
    // denser one, build_image() tries again with that (which may cure it). Otherwise, and on that second
    // try, it is only said.
    if (!outgrown.empty()) {
        if (!opt.dense && g_denser_would_help) throw DoesNotFit(outgrown);
        warn(outgrown);
    }
    return out;
}

Bytes assemble_envelope(const Manifest& m, const fs::path& dir, const Bytes& core, const RepackOptions& opt) {
    return assemble_envelope(m, load_envelope(m, dir), core, core_changed(m, core), 0, opt);
}

// ------------------------------------------------- trailing AVB footer --
//
// Any of the container formats below (boot, vendor_boot, dtbo) can have
// an AVB hash/hashtree footer appended after its own content -- common
// with per-partition (chained) AVB configurations, where e.g. a whole
// vendor_boot.img partition is [vendor_boot content][padding][vbmeta
// blob][padding][64-byte AVBf footer]. The primary format's own parser
// doesn't need to know or care about this (it only reads what it
// declares up front), but a naive repack would otherwise silently drop
// that entire tail. Reuses VbmetaImage's existing footer handling
// (already covers recomputing offsets/hash/signature for edited
// content) rather than duplicating any of that here.

struct AvbFooter {
    bool present = false;
    VbmetaImage v;
    size_t host_size = 0;  // bytes the footer protects (== whole.size() when absent)
};

AvbFooter detect_avb_footer(const Bytes& whole) {
    AvbFooter f;
    f.host_size = whole.size();
    if (whole.size() < 64 || std::memcmp(whole.data() + whole.size() - 64, "AVBf", 4) != 0)
        return f;
    try {
        f.v = VbmetaImage::parse(whole);
    } catch (const FormatError&) {
        return f;  // "AVBf"-looking bytes that don't actually parse; leave as opaque tail
    }
    if (!f.v.has_footer) return f;
    if (f.v.footer_original_image_size == 0 || f.v.footer_original_image_size > whole.size())
        return f;
    f.present = true;
    f.host_size = static_cast<size_t>(f.v.footer_original_image_size);
    return f;
}

void save_avb_footer(Manifest& m, const fs::path& dir, const AvbFooter& f, const Bytes& host) {
    if (!f.present) return;
    const VbmetaImage& v = f.v;
    m.set_bool("has_avb_footer", true);
    m.set_u64("avb_partition_size", v.source_total_size);
    m.set_hex("avb_host_sha256", hash::sha256(host));
    m.set_u32("avb_algorithm_type", v.algorithm_type);
    m.set("avb_algorithm_name", avb_algorithm_name(v.algorithm_type));
    m.set_u64("avb_rollback_index", v.rollback_index);
    m.set_u32("avb_flags", v.flags);
    m.set_u32("avb_rollback_index_location", v.rollback_index_location);
    m.set("avb_release_string", v.release_string);
    m.set_tail("avb_release_string_tail", v.release_string_tail);
    if (!v.reserved.empty()) m.set_hex("avb_reserved", v.reserved);
    m.set_hex("avb_hash", v.hash);
    m.set_hex("avb_signature", v.signature);
    save_raw(m, dir, "avb_public_key", v.public_key, "avb_public_key.bin");
    save_raw(m, dir, "avb_public_key_metadata", v.public_key_metadata, "avb_public_key_metadata.bin");
    m.set_u32("avb_descriptor_count", static_cast<uint32_t>(v.descriptors.size()));
    for (size_t i = 0; i < v.descriptors.size(); ++i) {
        std::string p = "avb_descriptor" + std::to_string(i);
        m.set_u64(p + "_tag", v.descriptors[i].tag);
        std::string filename = p + ".bin";
        m.set(p + "_file", filename);
        write_file(dir / filename, v.descriptors[i].content);
        m.set(p + "_info", v.descriptors[i].describe());  // informational only, ignored on read
    }
    size_t bad = 0;
    size_t checked = v.verify_hash_descriptors(host, &bad);
    if (checked && bad)
        warn("the AVB hash descriptor in this image's footer does not match its content "
             "(already modified without re-signing?)");
}

// The key an AVB 2.0 vbmeta is signed with when it is built (the choice is described in abr/avb_keys.hpp): the key of the folder
// (keys/avb_key.pem) when there is one; else none while the signature the image has still covers it; else a public test key of the AVB
// project -- the image's own when that is what it was signed with, and then the new signature is as good as the old one. When the
// image's key is none of them the signature is the test key's, which only a bootloader that does not check the key accepts: that is
// said (`warned`: it was, and build() need not say that the public key was replaced).
std::string avb_signing_key(const VbmetaImage& v, const std::string& folder_key_pem, bool& warned) {
    warned = false;
    if (v.algorithm_type == 0 || !folder_key_pem.empty()) return folder_key_pem;
    if (v.can_keep_signature()) return {};
    const AvbKeyChoice choice = choose_avb_test_key(v.algorithm_type, v.public_key);
    if (!choice.key) return {};  // (ML-DSA: build() says why abr cannot)
    const std::string name = choice.key->name;
    if (choice.the_images_key) {
        note("the AVB 2.0 signature is made again with the public AVB test key " + name + ", which is the key this image was signed with");
        return choice.key->pem;
    }
    warned = true;
    warn(std::string(v.public_key.empty() ? "this vbmeta has no public key" : "this vbmeta was signed with a key abr does not have the private half of (" +
                                                                                    describe_avb_public_key(v.public_key) + ")") +
         "; it is signed with the public AVB test key " + name + " instead, and that key's public key replaces the one in the image. A bootloader that "
         "checks the image against the key it trusts will reject it. A key of your own goes in keys/avb_key.pem");
    return choice.key->pem;
}

// `host` is the freshly-built (possibly edited) protected image. Returns it
// unchanged when the source had no footer, else the full
// [host][padding][vbmeta][padding][footer] partition image.
Bytes reattach_avb_footer(const Manifest& m, const fs::path& dir, Bytes host,
                          const std::string& avb_key_pem) {
    if (!m.get_bool("has_avb_footer", false)) return host;
    VbmetaImage v;
    v.has_footer = true;
    v.source_total_size = m.get_size("avb_partition_size", 0);
    v.footer_original_image_size = host.size();
    v.algorithm_type = m.get_u32("avb_algorithm_type", 0);
    v.rollback_index = m.get_u64("avb_rollback_index", 0);
    v.flags = m.get_u32("avb_flags", 0);
    v.rollback_index_location = m.get_u32("avb_rollback_index_location", 0);
    v.release_string = m.get("avb_release_string");
    v.release_string_tail = m.get_tail("avb_release_string_tail");
    v.reserved = m.get_hex("avb_reserved");
    v.hash = m.get_hex("avb_hash");
    v.signature = m.get_hex("avb_signature");
    v.public_key = load_raw(m, dir, "avb_public_key");
    v.public_key_metadata = load_raw(m, dir, "avb_public_key_metadata");
    uint32_t count = m.get_count("avb_descriptor_count", 0);
    for (uint32_t i = 0; i < count; ++i) {
        std::string p = "avb_descriptor" + std::to_string(i);
        AvbDescriptor d;
        d.tag = m.get_u64(p + "_tag", 0);
        d.content = load_raw(m, dir, p);
        v.descriptors.push_back(std::move(d));
    }
    // Only touch the digests if the protected image really changed: an
    // untouched repack must reproduce the source byte-for-byte, even if the
    // source's own digest was already stale.
    if (hash::sha256(host) != m.get_hex("avb_host_sha256")) v.refresh_hash_descriptors(host);
    v.host_prefix = std::move(host);
    std::vector<std::string> notes;
    bool warned = false;
    const std::string signing_key = avb_signing_key(v, avb_key_pem, warned);
    Bytes built = v.build(signing_key, &notes);
    if (!warned)
        for (auto& n : notes) warn(n);
    return built;
}

// -------------------------------------------- AVBv1 boot signature --
//
// AOSP's boot_signer appends a DER BootSignature (abr/legacy/avb1.hpp) right
// after the page-aligned boot image, i.e. at the start of the envelope's
// tail. An untouched image keeps it byte for byte; once the image changes the
// old signature (which covers the old bytes) is worthless, so it is created
// anew, as Android Image Kitchen does.

std::string verdict_text(const Verification& v) {
    switch (v.verdict) {
        case SignatureVerdict::Valid: return "signature VALID";
        case SignatureVerdict::Invalid: return "signature INVALID (" + v.detail + ")";
        case SignatureVerdict::Unsupported: return "signature not checked (" + v.detail + ")";
    }
    return "";
}

// Re-creates the signature for `core` (the rebuilt image, from its magic) when
// the manifest has `avb1_signature=true` -- unpack writes it when the source
// carried a signature -- or the folder has a key for it (keys/avb1.pk8). Returns how many leading
// bytes of e.tail are the new signature (0: the tail was left alone).
size_t refresh_avb1_signature(const Manifest& m, Envelope& e, Bytes& core, uint32_t page_size,
                              bool image_changed, const RepackOptions& opt) {
    if (!m.get_bool("avb1_signature", false) && !opt.avb1_signer) return 0;
    auto existing = parse_boot_signature(e.tail, 0);
    // An untouched image keeps its signature as it is (byte-identical round
    // trip) -- unless the caller explicitly asked to sign with a given key.
    if (existing && !image_changed && !opt.avb1_signer) return 0;

    // Bootloaders look for the signature right after the page-aligned image.
    if (page_size && core.size() % page_size != 0)
        core.resize(core.size() + page_size - core.size() % page_size, 0);

    const std::string target = m.get("avb1_target", existing ? existing->target : "/boot");
    Signer signer;
    if (opt.avb1_signer) {
        signer = *opt.avb1_signer;
    } else {
        signer = aosp_test_signer();
        if (existing && !is_aosp_test_certificate(existing->certificate))
            warn("the original boot signature was made by " +
                 dquoted(certificate_subject(existing->certificate)) +
                 ", whose private key abr does not have. The new signature uses the public "
                 "AOSP test key (what Android Image Kitchen does); a bootloader that trusts only "
                 "the original key will reject the image. Put your key in keys/avb1.pk8 and its "
                 "certificate in keys/avb1.x509.pem to sign with it.");
    }
    Bytes der = build_boot_signature(core, target, signer);
    std::cout << (existing ? "re-created" : "added") << " the AVBv1 boot signature (target "
              << shown(target) << ", signed by "
              << (signer.is_aosp_test_key ? std::string("the public AOSP test key")
                                          : shown(signer.subject))
              << ")\n";

    const size_t old_size = existing ? existing->der_size : 0;
    Bytes rest(e.tail.begin() + static_cast<long>(old_size), e.tail.end());
    if (existing && der.size() != old_size) {
        // Whatever followed the old signature after a zero gap (a vendor
        // trailer at the next page, say) keeps its distance from the start
        // of the signature when the new one has a different size.
        size_t zeros = 0;
        while (zeros < rest.size() && rest[zeros] == 0) ++zeros;
        if (zeros > 0 && zeros < rest.size()) {
            const size_t keep = old_size + zeros;
            const size_t new_zeros = keep > der.size() ? keep - der.size() : 0;
            rest.erase(rest.begin(), rest.begin() + static_cast<long>(zeros));
            rest.insert(rest.begin(), new_zeros, 0);
        }
    }
    e.tail = std::move(der);
    e.tail.insert(e.tail.end(), rest.begin(), rest.end());
    return e.tail.size() - rest.size();
}

// ------------------------------------------------------------------ qcdt --
//
// A Qualcomm device tree table (abr/qcdt.hpp) is keys of a manifest and a file for every tree it holds: the same keys for a table that is a file
// of its own (no prefix, the trees beside the manifest) and for the `dt` of a boot image (`dt_`, the trees in dt/). An entry says the board its
// tree is for by numbers, and the tree by its number.

std::string qcdt_tree_file(const std::string& subdir, size_t i) {
    return (subdir.empty() ? "" : subdir + "/") + "dtb" + std::to_string(i) + ".dtb";
}

void save_qcdt(Manifest& m, const fs::path& dir, const std::string& prefix, const std::string& subdir, const qcdt::Table& t) {
    m.set_u32(prefix + "version", t.version);
    m.set_u32(prefix + "page_size", t.page_size);
    m.set_u32(prefix + "entry_count", static_cast<uint32_t>(t.entries.size()));
    for (size_t i = 0; i < t.entries.size(); ++i) {
        const qcdt::Entry& e = t.entries[i];
        const std::string p = prefix + "entry" + std::to_string(i) + "_";
        m.set_addr(p + "chipset", e.chipset);
        m.set_addr(p + "platform", e.platform);
        if (t.version >= 2) m.set_addr(p + "subtype", e.subtype);
        m.set_addr(p + "revision", e.revision);
        if (t.version >= 3)
            for (size_t k = 0; k < e.pmic.size(); ++k) m.set_addr(p + "pmic" + std::to_string(k), e.pmic[k]);
        m.set_u64(p + "dtb", e.dtb);
    }
    m.set_u32(prefix + "dtb_count", static_cast<uint32_t>(t.dtbs.size()));
    for (size_t j = 0; j < t.dtbs.size(); ++j) {
        const std::string file = qcdt_tree_file(subdir, j);
        m.set(prefix + "dtb" + std::to_string(j) + "_file", file);
        write_file(dir / file, t.dtbs[j]);
    }
}

// What a manifest says (it is read all, whatever the version: a subtype in a version 1 table is a contradiction that qcdt::build says, not a key
// that goes unread).
qcdt::Table load_qcdt(const Manifest& m, const fs::path& dir, const std::string& prefix) {
    qcdt::Table t;
    if (!m.has(prefix + "version"))
        throw FormatError("manifest.txt has no " + shown(prefix + "version") + " (1, 2 or 3: the width of an entry of the table)");
    t.version = m.get_u32(prefix + "version");
    t.page_size = m.get_u32(prefix + "page_size", qcdt::kDefaultPageSize);
    const uint32_t entries = m.get_count(prefix + "entry_count", 0);
    for (uint32_t i = 0; i < entries; ++i) {
        const std::string p = prefix + "entry" + std::to_string(i) + "_";
        qcdt::Entry e;
        e.chipset = m.get_addr32(p + "chipset", 0);
        e.platform = m.get_addr32(p + "platform", 0);
        e.subtype = m.get_addr32(p + "subtype", 0);
        e.revision = m.get_addr32(p + "revision", 0);
        for (size_t k = 0; k < e.pmic.size(); ++k) e.pmic[k] = m.get_addr32(p + "pmic" + std::to_string(k), 0);
        if (!m.has(p + "dtb")) throw FormatError("manifest.txt has no " + shown(p + "dtb") + " (the number of the device tree the entry is for)");
        e.dtb = static_cast<size_t>(m.get_bounded(p + "dtb", 0, 32));
        t.entries.push_back(e);
    }
    const uint32_t trees = m.get_count(prefix + "dtb_count", 0);
    for (uint32_t j = 0; j < trees; ++j) {
        const std::string key = prefix + "dtb" + std::to_string(j) + "_file";
        const std::string name = m.get_path(key);
        if (name.empty()) throw FormatError("manifest.txt has no " + shown(key) + " (the file of device tree " + std::to_string(j) + ")");
        t.dtbs.push_back(read_file(dir / name));
    }
    return t;
}

// A line for `info`: "version 2, page size 2048, 9 entries, 2 device trees".
std::string qcdt_summary(const qcdt::Table& t) {
    return "version " + std::to_string(t.version) + ", page size " + std::to_string(t.page_size) + ", " + std::to_string(t.entries.size()) +
           (t.entries.size() == 1 ? " entry, " : " entries, ") + std::to_string(t.dtbs.size()) + (t.dtbs.size() == 1 ? " device tree" : " device trees");
}

void unpack_qcdt(const Bytes& data, const fs::path& dir) {
    qcdt::Table t;
    try {
        t = qcdt::parse(data);
    } catch (const FormatError& e) {
        throw FormatError(std::string("this is a Qualcomm device tree table (QCDT), but abr cannot write it again byte for byte: ") + e.what());
    }
    Manifest m;
    m.set("type", "qcdt");
    save_qcdt(m, dir, "", "", t);
    save_envelope(m, dir, Envelope::capture(data, 0, t.consumed), data, 0, t.consumed);
    m.save(dir / "manifest.txt", "abr qcdt manifest -- edit then `abr pack -i " + dir.string() + " -o dt.img`");
}

Bytes repack_qcdt(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    return assemble_envelope(m, dir, qcdt::build(load_qcdt(m, dir, "")), opt);
}

// ------------------------------------------------------------- boot.img --

std::string hex_words(const std::array<uint32_t, 4>& w) {
    Bytes b;
    for (auto v : w)
        for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i)));
    Manifest tmp;
    tmp.set_hex("x", b);
    return tmp.get("x");
}

void unpack_boot(const Bytes& whole, const fs::path& dir) {
    AvbFooter footer = detect_avb_footer(whole);
    Bytes host(whole.begin(), whole.begin() + static_cast<long>(footer.host_size));

    size_t off = find_container(host, "ANDROID!");
    if (off == std::string::npos) throw FormatError("no 'ANDROID!' magic found");
    Bytes image(host.begin() + static_cast<long>(off), host.end());
    BootImage img = BootImage::parse(image);

    Manifest m;
    m.set("type", "boot");
    m.set_u32("header_version", img.header_version);
    if (img.pxa) {  // Marvell PXA1088/PXA1908: a v0 header with an extra word
        m.set_bool("pxa", true);
        m.set_addr("pxa_unknown", img.pxa_unknown);
    }
    if (img.header_version <= 2) {
        m.set_u32("page_size", img.page_size);
        m.set_addr("kernel_addr", img.kernel_addr);
        m.set_addr("ramdisk_addr", img.ramdisk_addr);
        m.set_addr("second_addr", img.second_addr);
        m.set_addr("tags_addr", img.tags_addr);
        m.set("board_name", img.board_name);
        m.set_tail("board_name_tail", img.board_name_tail);
        bool any_id = false;
        for (auto v : img.id)
            if (v) any_id = true;
        if (any_id) {
            Bytes idb;
            for (auto v : img.id) {
                idb.push_back(uint8_t(v));
                idb.push_back(uint8_t(v >> 8));
                idb.push_back(uint8_t(v >> 16));
                idb.push_back(uint8_t(v >> 24));
            }
            m.set_hex("id", idb);
        }
        m.set("id_scheme", id_scheme_name(img.id_scheme));
        if (img.header_version >= 2) m.set_addr("dtb_addr", img.dtb_addr);
        if (img.recovery_dtbo_offset_field)
            m.set_u64("recovery_dtbo_offset", *img.recovery_dtbo_offset_field);
    } else {
        bool any = false;
        for (auto v : img.reserved)
            if (v) any = true;
        if (any) m.set("reserved", hex_words(img.reserved));
    }
    if (img.header_size_field) m.set_u32("header_size", *img.header_size_field);
    m.set("os_version", img.os_version.to_string());
    m.set("os_patch_level", img.os_version.patch_level_string());
    m.set("cmdline", img.cmdline);
    m.set_tail("cmdline_tail", img.cmdline_tail);
    m.set_tail("extra_cmdline_tail", img.extra_cmdline_tail);
    if (const std::string t = tails_text({{"board_name", &img.board_name_tail},
                                          {"cmdline", &img.cmdline_tail},
                                          {"extra_cmdline", &img.extra_cmdline_tail}});
        !t.empty())
        note("bytes behind the NUL that ends the text of a header field (" + t + ") are kept in manifest.txt (*_tail)");
    if (img.cmdline_split) m.set_u32("cmdline_split", img.cmdline_split);
    if (img.missing_tail_padding) m.set_u64("missing_tail_padding", img.missing_tail_padding);
    if (img.missing_tail_padding && img.kept_tail_padding) m.set_u64("tail_padding_kept", *img.kept_tail_padding);

    {
        auto parts = save_components(dir, {{&img.kernel, "kernel"},
                                           {&img.ramdisk, "ramdisk.cpio"},
                                           {&img.second, "second"}});
        record_component(m, "kernel", "kernel", parts[0]);
        record_component(m, "ramdisk", "ramdisk.cpio", parts[1]);
        record_component(m, "second", "second", parts[2]);
        save_ramdisk_trees(m, dir, {{"ramdisk", "ramdisk.cpio", &parts[1]}});
    }
    {
        // A Qualcomm device tree table that abr can write again byte for byte is unpacked into its trees and its entries; any other dt is a file.
        bool table = false;
        if (qcdt::looks_like(img.dt)) {
            try {
                const qcdt::Table t = qcdt::parse(img.dt, img.page_size);
                if (t.consumed != img.dt.size())
                    throw FormatError(std::to_string(img.dt.size() - t.consumed) + " bytes follow the table inside dt_size (" +
                                      std::to_string(img.dt.size()) + " bytes), and the table ends at " + std::to_string(t.consumed));
                m.set("dt_format", "qcdt");
                save_qcdt(m, dir, "dt_", "dt", t);
                table = true;
            } catch (const FormatError& e) {
                note(std::string("the dt of this image is a Qualcomm device tree table, and it is kept as the file dt.img: ") + e.what());
            }
        }
        if (!table) save_raw(m, dir, "dt", img.dt, "dt.img");
    }
    save_raw(m, dir, "recovery_dtbo", img.recovery_dtbo, "recovery_dtbo.img");
    save_raw(m, dir, "dtb", img.dtb, "dtb");
    save_raw(m, dir, "boot_signature", img.boot_signature, "boot_signature.bin");
    save_raw(m, dir, "header_padding", img.header_padding, "header_padding.bin");
    save_section_padding(m, dir, img.section_padding, BootImage::kSectionNames);
    if (const std::string t = padding_text(img.section_padding, BootImage::kSectionNames); !t.empty())
        note("bytes that are not zero in the padding behind a component (" + t + ") are kept in *_padding.bin");

    Envelope env = Envelope::capture(host, off, img.consumed);
    save_envelope(m, dir, env, host, off, img.consumed);
    if (const Identity id = identify(host);
        (id.kind == Kind::NOOK || id.kind == Kind::NOOKTAB) && off == id.payload_offset)
        m.set("prefix_kind", id.aik_type());  // a constant header: nothing to go stale after an edit
    if (!env.prefix.empty() || !env.tail.empty()) {
        std::cout << "note: " << env.prefix.size() << " bytes before and " << env.tail.size()
                  << " bytes after the boot image are kept verbatim (prefix.bin / tail.bin)\n";
    }
    if (auto sig = parse_boot_signature(env.tail, 0)) {
        Verification v = verify_boot_signature(*sig, host.data() + off, host.size() - off);
        m.set_bool("avb1_signature", true);  // remove this line to keep the old blob untouched
        m.set("avb1_target", sig->target);
        m.set("avb1_info",  // informational, ignored on read
              "signed by " + certificate_subject(sig->certificate) +
                  (is_aosp_test_certificate(sig->certificate) ? " (public AOSP test key)" : "") +
                  "; covers " + std::to_string(sig->length) + " bytes; " + verdict_text(v));
        if (v.verdict == SignatureVerdict::Invalid)
            warn("the AVBv1 boot signature in this image does not match its content (" + v.detail +
                 ")");
    }
    save_avb_footer(m, dir, footer, host);

    m.save(dir / "manifest.txt", "abr boot manifest -- edit then `abr pack -i " + dir.string() +
                                      " -o out.img`");
}

Bytes repack_boot(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    BootImage img;
    img.header_version = m.get_u32("header_version", 4);
    img.pxa = m.get_bool("pxa", false);
    if (img.pxa) img.pxa_unknown = m.get_addr32("pxa_unknown", 0x03000000);
    if (img.header_version <= 2) {
        img.page_size = m.get_u32("page_size", 2048);
        img.kernel_addr = m.get_addr32("kernel_addr", 0x00008000);
        img.ramdisk_addr = m.get_addr32("ramdisk_addr", 0x01000000);
        img.second_addr = m.get_addr32("second_addr", 0x00f00000);
        img.tags_addr = m.get_addr32("tags_addr", 0x00000100);
        img.board_name = m.get("board_name");
        img.board_name_tail = m.get_tail("board_name_tail");
        if (img.header_version >= 2) img.dtb_addr = m.get_addr("dtb_addr", 0);
        Bytes idb = m.get_hex("id");
        for (size_t i = 0; i < img.id.size() && i * 4 + 3 < idb.size(); ++i)
            img.id[i] = uint32_t(idb[i * 4]) | (uint32_t(idb[i * 4 + 1]) << 8) |
                        (uint32_t(idb[i * 4 + 2]) << 16) | (uint32_t(idb[i * 4 + 3]) << 24);
        // No id_scheme in the manifest (hand-written, or from an older abr):
        // fall back to the AOSP mkbootimg recipe, as before.
        img.id_scheme =
            id_scheme_from_name(m.get("id_scheme", "sha1")).value_or(IdScheme::SHA1);
        if (m.has("recovery_dtbo_offset"))
            img.recovery_dtbo_offset_field = m.get_u64("recovery_dtbo_offset");
    } else {
        Bytes rb = m.get_hex("reserved");
        for (size_t i = 0; i < img.reserved.size() && i * 4 + 3 < rb.size(); ++i)
            img.reserved[i] = uint32_t(rb[i * 4]) | (uint32_t(rb[i * 4 + 1]) << 8) |
                              (uint32_t(rb[i * 4 + 2]) << 16) | (uint32_t(rb[i * 4 + 3]) << 24);
    }
    if (m.has("header_size")) img.header_size_field = m.get_u32("header_size");
    img.os_version = OsVersion::parse(m.get("os_version"), m.get("os_patch_level"));
    img.cmdline = m.get("cmdline");
    img.cmdline_tail = m.get_tail("cmdline_tail");
    img.extra_cmdline_tail = m.get_tail("extra_cmdline_tail");
    img.cmdline_split = m.get_u32("cmdline_split", 0);
    img.missing_tail_padding = m.get_size("missing_tail_padding", 0);
    if (m.has("tail_padding_kept")) img.kept_tail_padding = m.get_size("tail_padding_kept", 0);

    {
        auto parts = load_components(m, dir, {"kernel", "ramdisk", "second"}, opt);
        img.kernel = std::move(parts[0]);
        img.ramdisk = std::move(parts[1]);
        img.second = std::move(parts[2]);
    }
    if (m.has("dt_format")) {
        if (m.get("dt_format") != "qcdt")
            throw FormatError("manifest.txt: dt_format=" + shown(m.get("dt_format")) + " is not a format abr knows (qcdt)");
        if (m.has("dt_file"))
            throw FormatError("manifest.txt has dt_file and dt_format=qcdt: the dt of the image is either a file or a table made of the entries and trees "
                              "of the manifest. Take out the one that is not meant");
        img.dt = qcdt::build(load_qcdt(m, dir, "dt_"));
    } else {
        img.dt = load_raw(m, dir, "dt");
    }
    img.recovery_dtbo = load_raw(m, dir, "recovery_dtbo");
    img.dtb = load_raw(m, dir, "dtb");
    img.boot_signature = load_raw(m, dir, "boot_signature");
    img.header_padding = load_raw(m, dir, "header_padding");
    img.section_padding = load_section_padding(m, dir, BootImage::kSectionNames);
    img.recompute_id();  // follows id_scheme; `raw` keeps the id found in the source

    Bytes core = img.build();
    img.check_reads_back(core);
    Envelope env = load_envelope(m, dir);
    const bool changed = core_changed(m, core);
    const size_t regenerated = refresh_avb1_signature(
        m, env, core, img.header_version <= 2 ? img.page_size : 4096, changed, opt);
    Bytes host = assemble_envelope(m, env, core, changed, regenerated, opt);
    return reattach_avb_footer(m, dir, std::move(host), opt.avb_key_pem);
}

// ------------------------------------------------------- vendor_boot.img --

void unpack_vendor_boot(const Bytes& whole, const fs::path& dir) {
    AvbFooter footer = detect_avb_footer(whole);
    Bytes host(whole.begin(), whole.begin() + static_cast<long>(footer.host_size));
    size_t off = find_magic(host, "VNDRBOOT", 8);
    if (off == std::string::npos) throw FormatError("no 'VNDRBOOT' magic found");
    Bytes image(host.begin() + static_cast<long>(off), host.end());
    VendorBootImage img = VendorBootImage::parse(image);
    Manifest m;
    m.set("type", "vendor_boot");
    m.set_u32("header_version", img.header_version);
    m.set_u32("page_size", img.page_size);
    m.set_addr("kernel_addr", img.kernel_addr);
    m.set_addr("ramdisk_addr", img.ramdisk_addr);
    m.set_addr("tags_addr", img.tags_addr);
    m.set("board_name", img.board_name);
    m.set_tail("board_name_tail", img.board_name_tail);
    m.set("cmdline", img.cmdline);
    m.set_tail("cmdline_tail", img.cmdline_tail);
    {
        std::vector<std::pair<std::string, const Bytes*>> tails = {{"board_name", &img.board_name_tail},
                                                                    {"cmdline", &img.cmdline_tail}};
        for (size_t i = 0; i < img.ramdisk_fragments.size(); ++i)
            tails.push_back({"ramdisk" + std::to_string(i) + "_name", &img.ramdisk_fragments[i].name_tail});
        std::string t;
        for (const auto& [name, tail] : tails) {
            if (tail->empty()) continue;
            t += (t.empty() ? "" : ", ") + name + " " + std::to_string(tail->size());
        }
        if (!t.empty())
            note("bytes behind the NUL that ends the text of a header field (" + t + ") are kept in manifest.txt (*_tail)");
    }
    m.set_addr("dtb_addr", img.dtb_addr);
    if (img.header_size_field) m.set_u32("header_size", *img.header_size_field);
    if (img.header_version >= 4 && !img.has_ramdisk_table) m.set_bool("ramdisk_table", false);
    if (img.missing_tail_padding) m.set_u64("missing_tail_padding", img.missing_tail_padding);
    if (img.missing_tail_padding && img.kept_tail_padding) m.set_u64("tail_padding_kept", *img.kept_tail_padding);
    save_raw(m, dir, "dtb", img.dtb, "dtb");
    save_raw(m, dir, "bootconfig", img.bootconfig, "bootconfig");
    save_raw(m, dir, "header_padding", img.header_padding, "header_padding.bin");
    save_section_padding(m, dir, img.section_padding, VendorBootImage::kSectionNames);
    if (const std::string t = padding_text(img.section_padding, VendorBootImage::kSectionNames); !t.empty())
        note("bytes that are not zero in the padding behind a section (" + t + ") are kept in *_padding.bin");

    m.set_u32("ramdisk_count", static_cast<uint32_t>(img.ramdisk_fragments.size()));
    std::vector<ComponentSource> fragment_sources;
    for (size_t i = 0; i < img.ramdisk_fragments.size(); ++i) {
        const std::string p = "ramdisk" + std::to_string(i);
        fragment_sources.push_back({&img.ramdisk_fragments[i].data, p + ".cpio"});
    }
    auto fragment_parts = save_components(dir, fragment_sources);
    for (size_t i = 0; i < img.ramdisk_fragments.size(); ++i) {
        auto& e = img.ramdisk_fragments[i];
        std::string p = "ramdisk" + std::to_string(i);
        m.set(p + "_type", std::string(vendor_ramdisk_type_name(e.type)));
        m.set(p + "_name", e.name);
        m.set_tail(p + "_name_tail", e.name_tail);
        bool any_board_id = false;
        for (auto v : e.board_id)
            if (v) any_board_id = true;
        if (any_board_id) {
            Bytes b;
            for (auto v : e.board_id) {
                b.push_back(uint8_t(v));
                b.push_back(uint8_t(v >> 8));
                b.push_back(uint8_t(v >> 16));
                b.push_back(uint8_t(v >> 24));
            }
            m.set_hex(p + "_board_id", b);
        }
        record_component(m, p, p + ".cpio", fragment_parts[i]);
    }
    std::vector<TreeJob> tree_jobs;
    for (size_t i = 0; i < fragment_parts.size(); ++i) {
        const std::string p = "ramdisk" + std::to_string(i);
        tree_jobs.push_back({p, p + ".cpio", &fragment_parts[i]});
    }
    save_ramdisk_trees(m, dir, tree_jobs);
    Envelope env = Envelope::capture(host, off, img.consumed);
    save_envelope(m, dir, env, host, off, img.consumed);
    save_avb_footer(m, dir, footer, host);
    m.save(dir / "manifest.txt", "abr vendor_boot manifest -- edit then `abr pack -i " +
                                      dir.string() + " -o out.img`");
}

Bytes repack_vendor_boot(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    VendorBootImage img;
    img.header_version = m.get_u32("header_version", 4);
    img.page_size = m.get_u32("page_size", 4096);
    img.kernel_addr = m.get_addr32("kernel_addr", 0x00008000);
    img.ramdisk_addr = m.get_addr32("ramdisk_addr", 0x01000000);
    img.tags_addr = m.get_addr32("tags_addr", 0x00000100);
    img.board_name = m.get("board_name");
    img.board_name_tail = m.get_tail("board_name_tail");
    img.cmdline = m.get("cmdline");
    img.cmdline_tail = m.get_tail("cmdline_tail");
    img.dtb_addr = m.get_addr("dtb_addr", 0);
    if (m.has("header_size")) img.header_size_field = m.get_u32("header_size");
    img.has_ramdisk_table = m.get_bool("ramdisk_table", true);
    img.missing_tail_padding = m.get_size("missing_tail_padding", 0);
    if (m.has("tail_padding_kept")) img.kept_tail_padding = m.get_size("tail_padding_kept", 0);
    img.dtb = load_raw(m, dir, "dtb");
    img.bootconfig = load_raw(m, dir, "bootconfig");
    img.header_padding = load_raw(m, dir, "header_padding");
    img.section_padding = load_section_padding(m, dir, VendorBootImage::kSectionNames);

    uint32_t count = m.get_count("ramdisk_count", 0);
    std::vector<std::string> fragment_prefixes;
    for (uint32_t i = 0; i < count; ++i) fragment_prefixes.push_back("ramdisk" + std::to_string(i));
    std::vector<Bytes> fragment_data = load_components(m, dir, fragment_prefixes, opt);
    for (uint32_t i = 0; i < count; ++i) {
        std::string p = "ramdisk" + std::to_string(i);
        VendorRamdiskEntry e;
        e.type = vendor_ramdisk_type_from_name(m.get(p + "_type", "platform"));
        e.name = m.get(p + "_name");
        e.name_tail = m.get_tail(p + "_name_tail");
        Bytes b = m.get_hex(p + "_board_id");
        for (size_t j = 0; j < e.board_id.size() && j * 4 + 3 < b.size(); ++j)
            e.board_id[j] = uint32_t(b[j * 4]) | (uint32_t(b[j * 4 + 1]) << 8) |
                             (uint32_t(b[j * 4 + 2]) << 16) | (uint32_t(b[j * 4 + 3]) << 24);
        e.data = std::move(fragment_data[i]);
        img.ramdisk_fragments.push_back(std::move(e));
    }
    Bytes host = assemble_envelope(m, dir, img.build(), opt);
    return reattach_avb_footer(m, dir, std::move(host), opt.avb_key_pem);
}

// ------------------------------------------------------------ dtbo.img --

void unpack_dtbo(const Bytes& whole, const fs::path& dir) {
    AvbFooter footer = detect_avb_footer(whole);
    Bytes data(whole.begin(), whole.begin() + static_cast<long>(footer.host_size));
    DtboImage img = DtboImage::parse(data);
    Manifest m;
    m.set("type", "dtbo");
    m.set_u32("version", img.version);
    m.set_u32("page_size", img.page_size);
    m.set_bool("acpio", img.acpio);
    m.set_u32("entry_count", static_cast<uint32_t>(img.entries.size()));
    for (size_t i = 0; i < img.entries.size(); ++i) {
        auto& e = img.entries[i];
        std::string p = "entry" + std::to_string(i);
        m.set_u32(p + "_id", e.id);
        m.set_u32(p + "_rev", e.rev);
        Bytes extra;
        for (auto v : e.extra) {
            extra.push_back(uint8_t(v));
            extra.push_back(uint8_t(v >> 8));
            extra.push_back(uint8_t(v >> 16));
            extra.push_back(uint8_t(v >> 24));
        }
        m.set_hex(p + "_extra", extra);
        save_raw(m, dir, p, e.data, p + ".dtb");
    }
    save_envelope(m, dir, Envelope::capture(data, 0, img.consumed), data, 0, img.consumed);
    save_avb_footer(m, dir, footer, data);
    m.save(dir / "manifest.txt",
           "abr dtbo manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`");
}

Bytes repack_dtbo(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    DtboImage img;
    img.version = m.get_u32("version", 0);
    img.page_size = m.get_u32("page_size", 2048);
    img.acpio = m.get_bool("acpio", false);
    uint32_t count = m.get_count("entry_count", 0);
    for (uint32_t i = 0; i < count; ++i) {
        std::string p = "entry" + std::to_string(i);
        DtboEntry e;
        e.id = m.get_u32(p + "_id", 0);
        e.rev = m.get_u32(p + "_rev", 0);
        Bytes extra = m.get_hex(p + "_extra");
        for (size_t j = 0; j < e.extra.size() && j * 4 + 3 < extra.size(); ++j)
            e.extra[j] = uint32_t(extra[j * 4]) | (uint32_t(extra[j * 4 + 1]) << 8) |
                         (uint32_t(extra[j * 4 + 2]) << 16) | (uint32_t(extra[j * 4 + 3]) << 24);
        e.data = load_raw(m, dir, p);
        img.entries.push_back(std::move(e));
    }
    Bytes host = assemble_envelope(m, dir, img.build(), opt);
    return reattach_avb_footer(m, dir, std::move(host), opt.avb_key_pem);
}

// --------------------------------------------------------------- dtb --

// The blobs are the flattened device trees at the start of the file, back to back, each as long as its header says;
// what is behind the last one (the zeros a partition image is filled up with, a trailer) is the envelope's, as in the
// other images.
void unpack_dtb(const Bytes& data, const fs::path& dir) {
    const FdtBlobs split = split_fdt_blobs(data);
    if (split.blobs.empty()) throw FormatError("this is not a dtb: it does not start with a flattened device tree");
    Manifest m;
    m.set("type", "dtb");
    m.set_u32("blob_count", static_cast<uint32_t>(split.blobs.size()));
    for (size_t i = 0; i < split.blobs.size(); ++i) {
        std::string filename = "blob" + std::to_string(i) + ".dtb";
        m.set("blob" + std::to_string(i) + "_file", filename);
        write_file(dir / filename, split.blobs[i]);
    }
    save_envelope(m, dir, Envelope::capture(data, 0, split.consumed), data, 0, split.consumed);
    m.save(dir / "manifest.txt",
           "abr dtb manifest -- edit then `abr pack -i " + dir.string() + " -o out.dtb`");
}

Bytes repack_dtb(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    uint32_t count = m.get_count("blob_count", 0);
    if (count == 0) throw FormatError("manifest.txt: blob_count is 0; a dtb has at least one blob (blob0_file=...)");
    std::vector<Bytes> blobs;
    for (uint32_t i = 0; i < count; ++i) {
        const std::string key = "blob" + std::to_string(i) + "_file";
        const std::string name = m.get_path(key);
        blobs.push_back(read_file(dir / name));
        check_fdt_blob(blobs.back(), key + " (" + textquote::quote_shown(name) + ")");
    }
    return assemble_envelope(m, dir, join_fdt_blobs(blobs), opt);
}

// ------------------------------------------------------------- vbmeta --

void unpack_vbmeta(const Bytes& data, const fs::path& dir) {
    VbmetaImage v = VbmetaImage::parse(data);
    Manifest m;
    m.set("type", "vbmeta");
    m.set_u32("required_libavb_version_major", v.required_libavb_version_major);
    m.set_u32("required_libavb_version_minor", v.required_libavb_version_minor);
    m.set_u32("algorithm_type", v.algorithm_type);
    m.set("algorithm_name", avb_algorithm_name(v.algorithm_type));  // informational only
    m.set_u64("rollback_index", v.rollback_index);
    m.set_u32("flags", v.flags);
    m.set_u32("rollback_index_location", v.rollback_index_location);
    m.set("release_string", v.release_string);
    m.set_tail("release_string_tail", v.release_string_tail);
    if (!v.reserved.empty()) m.set_hex("reserved", v.reserved);
    if (const std::string t = tails_text({{"release_string", &v.release_string_tail}, {"reserved", &v.reserved}});
        !t.empty())
        note("the header holds bytes that nothing models (" + t + "): kept in manifest.txt, the hash and the signature cover them");
    m.set_hex("hash", v.hash);
    m.set_hex("signature", v.signature);
    save_raw(m, dir, "public_key", v.public_key, "public_key.bin");
    save_raw(m, dir, "public_key_metadata", v.public_key_metadata, "public_key_metadata.bin");

    m.set_bool("has_footer", v.has_footer);
    if (v.has_footer) {
        m.set_u64("footer_original_image_size", v.footer_original_image_size);
        m.set_u64("source_total_size", v.source_total_size);
        save_raw(m, dir, "host_prefix", v.host_prefix, "host_prefix.bin");
    }

    m.set_u32("descriptor_count", static_cast<uint32_t>(v.descriptors.size()));
    for (size_t i = 0; i < v.descriptors.size(); ++i) {
        std::string p = "descriptor" + std::to_string(i);
        m.set_u64(p + "_tag", v.descriptors[i].tag);
        std::string filename = p + ".bin";
        m.set(p + "_file", filename);
        write_file(dir / filename, v.descriptors[i].content);
        m.set(p + "_info", v.descriptors[i].describe());  // informational comment, ignored on read
    }
    m.save(dir / "manifest.txt",
           "abr vbmeta manifest -- edit then `abr pack -i " + dir.string() +
               " -o out.img` (keys/avb_key.pem in the folder re-signs with a key of your own)");
}

Bytes repack_vbmeta(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    VbmetaImage v;
    v.required_libavb_version_major = m.get_u32("required_libavb_version_major", 1);
    v.required_libavb_version_minor = m.get_u32("required_libavb_version_minor", 0);
    v.algorithm_type = m.get_u32("algorithm_type", 0);
    v.rollback_index = m.get_u64("rollback_index", 0);
    v.flags = m.get_u32("flags", 0);
    v.rollback_index_location = m.get_u32("rollback_index_location", 0);
    v.release_string = m.get("release_string");
    v.release_string_tail = m.get_tail("release_string_tail");
    v.reserved = m.get_hex("reserved");
    v.hash = m.get_hex("hash");
    v.signature = m.get_hex("signature");
    v.public_key = load_raw(m, dir, "public_key");
    v.public_key_metadata = load_raw(m, dir, "public_key_metadata");
    v.has_footer = m.get_bool("has_footer", false);
    if (v.has_footer) {
        v.footer_original_image_size = m.get_size("footer_original_image_size", 0);
        v.source_total_size = m.get_size("source_total_size", 0);
        v.host_prefix = load_raw(m, dir, "host_prefix");
    }
    uint32_t count = m.get_count("descriptor_count", 0);
    for (uint32_t i = 0; i < count; ++i) {
        std::string p = "descriptor" + std::to_string(i);
        AvbDescriptor d;
        d.tag = m.get_u64(p + "_tag", 0);
        d.content = load_raw(m, dir, p);
        v.descriptors.push_back(std::move(d));
    }
    std::vector<std::string> notes;
    bool warned = false;
    const std::string signing_key = avb_signing_key(v, opt.avb_key_pem, warned);
    Bytes built = v.build(signing_key, &notes);
    if (!warned)
        for (auto& n : notes) warn(n);
    return built;
}

// -------------------------------------------------------------- uimage --

void unpack_uimage(const Bytes& data, const fs::path& dir) {
    UImage img = UImage::parse(data);
    Manifest m;
    m.set("type", "uimage");
    m.set_u32("timestamp", img.timestamp);
    m.set_addr("load_addr", img.load_addr);
    m.set_addr("entry_point", img.entry_point);
    m.set("os", std::string(uboot_os_name(img.os)));
    m.set("arch", std::string(uboot_arch_name(img.arch)));
    m.set("image_type", std::string(uboot_type_name(img.type)));
    m.set("compression", std::string(uboot_comp_name(img.comp)));
    m.set("name", img.name);
    m.set_tail("name_tail", img.name_tail);
    if (const std::string t = tails_text({{"name", &img.name_tail}}); !t.empty())
        note("bytes behind the NUL that ends the text of a header field (" + t + ") are kept in manifest.txt (*_tail)");
    // The payload, the way the parts of a boot image are: a stream is decompressed (data.bin holds the plain data), and what it was is
    // in the manifest (data_compression, data_level) for pack to make it again. `compression` above is the field of the header, which U-Boot
    // reads: pack writes it as it is here, and says when the stream it makes is not the one it names.
    {
        const std::vector<DecodedComponent> parts = save_components(dir, {{&img.data, "data.bin"}});
        record_component(m, "data", "data.bin", parts[0]);
    }
    // What lies behind the image (fill up to the size of a partition, a trailer): kept like the bytes around a boot image.
    const Envelope env = Envelope::capture(data, 0, img.consumed);
    save_envelope(m, dir, env, data, 0, img.consumed);
    if (!env.tail.empty())
        note(std::to_string(env.tail.size()) + " bytes after the uImage are kept verbatim (tail.bin)");
    m.save(dir / "manifest.txt",
           "abr uimage manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`\n"
           "# NOTE: data.bin is the payload with its compression taken off (data_compression, data_level say what it\n"
           "# was; pack makes the stream again). `compression` is the field of the uImage header, which U-Boot reads.");
}

// The `compression` field of a uImage header that goes with a stream of `codec`, as the table of mkimage names it; nullopt for the codecs
// that have no name there.
std::optional<uint8_t> uboot_comp_for(Codec codec) {
    switch (codec) {
        case Codec::NONE: return uboot_value(UbootField::COMP, "none");
        case Codec::GZIP: return uboot_value(UbootField::COMP, "gzip");
        case Codec::BZIP2: return uboot_value(UbootField::COMP, "bzip2");
        case Codec::LZMA: return uboot_value(UbootField::COMP, "lzma");
        case Codec::LZO: return uboot_value(UbootField::COMP, "lzo");
        case Codec::LZ4:
        case Codec::LZ4_LEGACY: return uboot_value(UbootField::COMP, "lz4");
        case Codec::ZSTD: return uboot_value(UbootField::COMP, "zstd");
        default: return std::nullopt;
    }
}

Bytes repack_uimage(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    UImage img;
    img.timestamp = m.get_u32("timestamp", 0);
    img.load_addr = m.get_addr32("load_addr", 0);
    img.entry_point = m.get_addr32("entry_point", 0);
    // A name from U-Boot's table of the field (`mkimage -O help` ...), or a number up to 255: what is neither is refused, with the
    // names that are known (it was 0, "invalid" or "none", without a word).
    auto field = [&m](UbootField f, const char* fallback) -> uint8_t {
        const std::string key = uboot_field_key(f);
        const std::string text = m.get(key, fallback);
        if (const std::optional<uint8_t> v = uboot_value(f, text)) return *v;
        throw FormatError("manifest.txt: " + shown(key + "=" + text) + " is none of the names of U-Boot's table for it (" + uboot_names(f) +
                          ") and no number up to 255");
    };
    img.os = field(UbootField::OS, "linux");
    img.arch = field(UbootField::ARCH, "arm64");
    img.type = field(UbootField::TYPE, "kernel");
    img.comp = field(UbootField::COMP, "none");
    img.name = m.get("name");
    img.name_tail = m.get_tail("name_tail");
    bool replayed = false;
    img.data = load_component(m, dir, "data", opt, &replayed);
    // U-Boot unpacks the payload by what the header says. A stream that abr made (the file was changed) and that is not the one the header
    // names -- the header says gzip and `data_compression` was changed to xz, or the other way round -- would not boot: said. A payload that
    // was put back as it was is not looked at (an image that was odd to begin with stays what it was), nor one with a sub-header in front.
    if (!replayed && img.comp != 0 && !m.has("data_mtk_name")) {
        const Codec stream = detect_codec(img.data);
        if (uboot_comp_for(stream) != std::optional<uint8_t>(img.comp))
            warn("the header says " + shown(std::string(uboot_field_key(UbootField::COMP)) + "=" + uboot_comp_name(img.comp)) +
                 ", but what goes into the image is " + (stream == Codec::NONE ? std::string("not a compressed stream") : std::string(codec_name(stream)) + " data") +
                 ": U-Boot unpacks the payload by the header. Make `compression` and `data_compression` of manifest.txt agree");
    }
    return assemble_envelope(m, dir, img.build(), opt);
}

// ----------------------------------------------------------------- fit --
//
// A U-Boot FIT image (abr/fit.hpp). `fit.its` is the tree of it as text. The data of every image is a file of its own, named for the
// node of the image (kernel-1 is `kernel_1`, fdt@1 is `fdt_1.dtb`, ramdisk-1 is `ramdisk_1.cpio` and the directory `ramdisk_1/`), and
// `data = /incbin/("file")` says in fit.its where it goes. An image whose data was behind the tree has such a `data` too, and keeps its
// data-size and data-offset (data-position): repack makes them again when the size of an image changed. What the text cannot say is
// kept beside it: the strings block of the tree in .abr_raw/fit_strings.bin, and in the manifest where the images were (`fit_data`:
// inline, offset or position), what they are aligned to, how the end of the tree is padded (to a multiple of `fit_tree_align`, or by
// `fdt_slack` bytes) and the words of the header that are not sizes.
// A file that this cannot give back byte for byte is not unpacked as a FIT: it is a dtb, and unpack says why.

std::string ascii_lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

// The name of a component for the node of an image: letters, digits and underscores (what a manifest takes for a name).
std::string fit_word(const std::string& node_name) {
    std::string s;
    for (unsigned char c : node_name) {
        if (s.size() == 40) break;
        const bool plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
        s += plain ? static_cast<char>(c) : '_';
    }
    return s.empty() ? "image" : s;
}

// What Windows takes for a device whatever the extension: such a name is not given to a file.
bool is_device_file_name(const std::string& lower) {
    if (lower == "con" || lower == "prn" || lower == "aux" || lower == "nul") return true;
    return lower.size() == 4 && (lower.compare(0, 3, "com") == 0 || lower.compare(0, 3, "lpt") == 0) && lower[3] >= '1' && lower[3] <= '9';
}

struct FitName {
    std::string prefix;    // the component's name in the manifest
    std::string filename;  // its file
};

// One name for every image, none that another name of the directory or a key of the manifest could be (prefix, tail, fit, fdt and
// type are the beginnings of keys of its own; the files are those of the envelope, the manifest and the text).
std::vector<FitName> fit_names(const std::vector<fit::Image>& images) {
    static const std::set<std::string> reserved_prefix = {"prefix", "tail", "fit", "fdt", "type", "pad", "core", "component"};
    static const std::set<std::string> reserved_file = {"manifest.txt", "fit.its", "prefix.bin", "tail.bin"};
    std::set<std::string> used;  // in lower case: a directory may be on a file system that does not tell the cases apart
    std::vector<FitName> out;
    for (const fit::Image& im : images) {
        std::string word = fit_word(im.name);
        if (is_device_file_name(ascii_lower(word))) word = "img_" + word;
        const char* ext = im.type == "ramdisk" ? ".cpio" : im.type == "flat_dt" ? ".dtb" : im.type == "kernel" ? "" : ".bin";
        std::string prefix = word;
        for (unsigned n = 2; used.count(ascii_lower(prefix)) || reserved_prefix.count(ascii_lower(prefix)) ||
                             reserved_file.count(ascii_lower(prefix + ext));
             ++n)
            prefix = word + "_" + std::to_string(n);
        used.insert(ascii_lower(prefix));
        out.push_back({prefix, prefix + ext});
    }
    return out;
}

// The image's own idea of its compression (the `compression` property) against the codec its data is stored with. "none" is no
// claim: a ramdisk that is a gzip file is "none" for U-Boot, which hands it to the kernel as it is.
bool fit_compression_agrees(const std::string& said, const std::string& stored) {
    if (said.empty() || said == "none" || said == stored) return true;
    if (said == "lz4" && stored == "lz4_legacy") return true;
    static const std::set<std::string> known = {"gzip", "bzip2", "lzma", "lzo", "lz4", "zstd"};
    return known.count(said) == 0;
}

bool unpack_fit(const Bytes& data, const fs::path& dir, std::string& why) {
    std::optional<fit::Opened> opened = fit::open(data, why);
    if (!opened) return false;
    fit::Opened& o = *opened;
    fdt::Node* images = o.tree.root.find_child("images");
    const std::vector<FitName> names = fit_names(o.images);

    std::vector<ComponentSource> sources;
    for (size_t i = 0; i < o.images.size(); ++i) sources.push_back({&o.images[i].data, names[i].filename});
    std::vector<DecodedComponent> parts = save_components(dir, sources);

    Manifest m;
    m.set("type", "fit");
    m.set("fit_file", "fit.its");
    m.set("fit_data", fit::place_name(o.layout.place));
    if (o.layout.place != fit::Place::INLINE) {
        m.set_u32("fit_align", static_cast<uint32_t>(o.layout.align));
        m.set_u32("fit_end_align", static_cast<uint32_t>(o.layout.end_align));
        if (o.layout.tree_align) m.set_u32("fit_tree_align", static_cast<uint32_t>(o.layout.tree_align));
    }
    m.set_u32("fdt_slack", static_cast<uint32_t>(o.layout.slack));
    m.set_u32("fdt_last_comp_version", o.tree.last_comp_version);
    m.set_u32("fdt_boot_cpuid_phys", o.tree.boot_cpuid_phys);
    fs::create_directories(dir / ".abr_raw");
    write_file(dir / ".abr_raw" / "fit_strings.bin", o.tree.strings);
    m.set("fit_strings", "kept");

    uint32_t recorded = 0;
    for (size_t i = 0; i < o.images.size(); ++i) {
        if (!parts[i].present) continue;  // an image without data is `data;` in the text
        record_component(m, names[i].prefix, names[i].filename, parts[i]);
        m.set("component" + std::to_string(recorded++) + "_prefix", names[i].prefix);
        images->children[o.images[i].index].find_prop("data")->incbin = names[i].filename;
    }
    m.set_u32("fit_components", recorded);

    std::vector<TreeJob> jobs;
    for (size_t i = 0; i < o.images.size(); ++i)
        if (o.images[i].type == "ramdisk" && parts[i].present) jobs.push_back({names[i].prefix, names[i].filename, &parts[i]});
    save_ramdisk_trees(m, dir, jobs);

    const std::string text =
        "// A U-Boot FIT image, as abr unpacked it. `data = /incbin/(\"file\")` is the data of an image: the file is in this directory\n"
        "// (data-size and data-offset or data-position are made again by repack when the size of an image changed).\n\n" +
        dts::print(o.tree);
    write_file(dir / "fit.its", reinterpret_cast<const uint8_t*>(text.data()), text.size());
    m.set_hex("fit_its_hash", hash::sha256(reinterpret_cast<const uint8_t*>(text.data()), text.size()));

    const Envelope env = Envelope::capture(data, 0, o.consumed);
    save_envelope(m, dir, env, data, 0, o.consumed);
    if (!env.tail.empty()) note(std::to_string(env.tail.size()) + " bytes after the FIT are kept verbatim (tail.bin)");
    for (const std::string& w : fit::wrong_hashes(o.tree, o.images)) warn(w);
    std::cout << "fit: " << o.images.size() << (o.images.size() == 1 ? " image" : " images") << ", "
              << (o.layout.place == fit::Place::INLINE ? "the data is in the tree"
                  : o.layout.place == fit::Place::OFFSET ? "the data is behind the tree (data-offset)"
                                                          : "the data is behind the tree (data-position)")
              << " -> " << (dir / "fit.its").generic_string() << "\n";
    m.save(dir / "manifest.txt", "abr fit manifest -- edit fit.its or the files of the images, then `abr pack -i " + dir.string() + " -o out.itb`");
    return true;
}

Bytes repack_fit(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    const std::string its_name = m.get_path("fit_file", "fit.its");
    const Bytes text = read_file(dir / its_name);
    fdt::Tree tree = dts::parse(std::string_view(reinterpret_cast<const char*>(text.data()), text.size()), its_name);
    tree.last_comp_version = m.get_u32("fdt_last_comp_version", 16);
    tree.boot_cpuid_phys = m.get_u32("fdt_boot_cpuid_phys", 0);
    if (m.get("fit_strings") == "kept") {
        const fs::path file = dir / ".abr_raw" / "fit_strings.bin";
        if (!fs::exists(file)) {
            warn(shown(file.generic_string()) + " is not there: the strings of the tree are written in the order of their first use, so the tree is not the bytes it was");
        } else {
            Bytes strings = read_file(file);
            if (strings.size() > (size_t{1} << 20))
                warn(shown(file.generic_string()) + " is more than a mebibyte, which a tree does not have: it is not used");
            else
                tree.strings = std::move(strings);
        }
    }

    fit::Layout layout;
    const std::string place_text = m.get("fit_data", "inline");
    const std::optional<fit::Place> place = fit::place_from_name(place_text);
    if (!place) throw FormatError("manifest.txt: " + shown("fit_data=" + place_text) + " is none of inline, offset, position");
    layout.place = *place;
    layout.align = static_cast<size_t>(m.get_int("fit_align", 4, 4, int64_t{1} << 24));
    layout.end_align = static_cast<size_t>(m.get_int("fit_end_align", 1, 1, int64_t{1} << 24));
    layout.tree_align = static_cast<size_t>(m.get_int("fit_tree_align", 0, 0, int64_t{1} << 24));
    layout.slack = static_cast<size_t>(m.get_int("fdt_slack", 0, 0, int64_t{1} << 20));

    // The files that the unpack made components of (the data that was in the image, as it was or changed), by name.
    std::map<std::string, std::string> prefix_of;
    const uint32_t component_count = m.get_count("fit_components", 0);
    for (uint32_t i = 0; i < component_count; ++i) {
        const std::string key = "component" + std::to_string(i) + "_prefix";
        const std::string prefix = m.get_name(key, "image");
        if (!m.has(prefix + "_file")) throw FormatError("manifest.txt: " + shown(key + "=" + prefix) + " but there is no " + shown(prefix + "_file"));
        prefix_of[m.get_path(prefix + "_file")] = prefix;
    }

    fdt::Node* images = tree.root.find_child("images");
    if (!images) throw FormatError(shown(its_name) + " has no /images node: it is not a FIT image any more");
    struct Slot {
        size_t index;        // the image: a child of /images
        std::string prefix;  // the component that holds its data; empty for a file that is not one (an image put in)
        std::string file;
    };
    std::vector<Slot> slots;
    std::set<size_t> changed;  // the images whose data is not what the image had
    for (size_t i = 0; i < images->children.size(); ++i) {
        fdt::Node& n = images->children[i];
        fdt::Property* d = n.find_prop("data");
        if (!d) {
            if (layout.place != fit::Place::INLINE && (n.find_prop("data-size") || n.find_prop("data-offset") || n.find_prop("data-position")))
                warn("the image " + shown(n.name) + " has data-size or data-offset but no `data` in " + shown(its_name) +
                     ": no data is put in the file for it");
            continue;
        }
        if (d->incbin.empty()) continue;  // the bytes are in the text
        if (const char* problem = path_problem(d->incbin); *problem)
            throw FormatError(shown(its_name) + ": the image " + shown(n.name) + " has data = /incbin/(" + shown(d->incbin) + "), a name that " + problem +
                              ". A file of an image has to be in the directory it is in (a relative path without '..'); copy it there");
        const auto known = prefix_of.find(d->incbin);
        slots.push_back({i, known == prefix_of.end() ? std::string() : known->second, d->incbin});
    }
    std::vector<std::string> wanted;
    for (const Slot& s : slots)
        if (!s.prefix.empty()) wanted.push_back(s.prefix);
    std::vector<char> replayed;
    std::vector<Bytes> loaded = load_components(m, dir, wanted, opt, &replayed);
    size_t at = 0;
    for (const Slot& s : slots) {
        fdt::Node& n = images->children[s.index];
        fdt::Property* d = n.find_prop("data");
        if (!s.prefix.empty()) {
            d->value = std::move(loaded[at]);
            if (!replayed[at]) changed.insert(s.index);
            std::string said;
            const std::string stored = m.get(s.prefix + "_compression", "none");
            if (n.get_string("compression", said) && !fit_compression_agrees(said, stored))
                warn("the image " + shown(n.name) + " says compression = " + shown(said) + " in " + shown(its_name) + ", and its data goes into the image as " +
                     shown(stored) + " (" + shown(s.prefix + "_compression") + " in manifest.txt): the two do not agree");
            ++at;
        } else {
            const fs::path file = dir / s.file;
            if (!fs::exists(file))
                throw FormatError(shown(its_name) + ": the image " + shown(n.name) + " has data = /incbin/(" + shown(s.file) + ") and there is no such file in the directory");
            d->value = read_file(file);  // a file that is none of the unpacked components goes in as it is
            changed.insert(s.index);
        }
        d->incbin.clear();
    }

    // The text is not the one that was unpacked: what its bytes say (a `data = <...>`, a hash, a signature) was edited as well.
    const Bytes unpacked_hash = m.get_hex("fit_its_hash");
    const bool text_edited = unpacked_hash.empty() || hash::sha256(text) != unpacked_hash;
    if (text_edited)
        for (size_t i = 0; i < images->children.size(); ++i) {
            const fdt::Property* d = images->children[i].find_prop("data");
            if (d && std::none_of(slots.begin(), slots.end(), [&](const Slot& s) { return s.index == i; })) changed.insert(i);
        }

    const std::vector<size_t> to_refresh(changed.begin(), changed.end());
    std::vector<std::string> notes;
    const size_t refreshed = fit::refresh_hashes(tree, to_refresh, notes);
    for (const std::string& n : notes) warn(n);
    std::set<std::string> changed_names;
    std::string changed_list;
    for (size_t i : to_refresh) {
        changed_names.insert(images->children[i].name);
        changed_list += (changed_list.empty() ? "" : ", ") + shown(images->children[i].name);
    }
    if (refreshed)
        note("the hash of " + changed_list + " was made again (" + std::to_string(refreshed) + (refreshed == 1 ? " hash node" : " hash nodes") + ")");
    const std::vector<std::string> stale = fit::stale_signatures(tree, changed_names);
    auto join = [](const std::vector<std::string>& v) {
        std::string out;
        for (const std::string& s : v) out += (out.empty() ? "" : ", ") + shown(s);
        return out;
    };
    if (!stale.empty()) {
        warn("the data of " + changed_list + " is not what it was, and the signatures that cover it (" + join(stale) +
             ") are not made again: abr signs no FIT image, so they do not match any more (mkimage -F -k <keys> -r signs a FIT image whose data is in the tree again)");
    } else if (text_edited) {
        if (const std::vector<std::string> all = fit::signatures(tree); !all.empty())
            warn(shown(its_name) + " was edited and the FIT has signatures (" + join(all) +
                 ") that abr does not make again: they may not match what was changed (mkimage -F -k <keys> -r signs a FIT image whose data is in the tree again)");
    }

    return assemble_envelope(m, dir, fit::build(std::move(tree), layout), opt);
}

// ----------------------------------------------------------- elf_boot --
//
// A Sony ELF boot image (abr/legacy/elf_boot.hpp): every segment is a component. The kernel is `kernel`, the ramdisk is
// `ramdisk.cpio` and the directory `ramdisk/` (as in every other image that has one), the others (ipl, rpm, cmdline,
// whatever else there is) are files named for their role. The first segment of a role has the role's name for its
// component; a second one with the same role (never seen) is `segmentN` and a file `segmentN_<role>.bin`. What is around the
// segments -- the header block, padding between them, what follows them -- is recorded only where elftool's layout would
// not give the image back (`elf_layout=kept`, and .abr_raw/elf_layout.bin).

struct ElfNames {
    std::vector<std::string> prefix;    // the component's name in the manifest ("kernel", "ramdisk", ... or "segment3")
    std::vector<std::string> filename;  // its file
};

ElfNames elf_names(const std::vector<legacy::ElfSegment>& segments) {
    ElfNames n;
    std::set<std::string> seen;
    for (size_t i = 0; i < segments.size(); ++i) {
        const std::string& role = segments[i].role;
        if (seen.insert(role).second) {
            n.prefix.push_back(role);
            n.filename.push_back(role == "ramdisk" ? "ramdisk.cpio" : role);
        } else {
            n.prefix.push_back("segment" + std::to_string(i));
            n.filename.push_back("segment" + std::to_string(i) + "_" + role + ".bin");
        }
    }
    return n;
}

std::string join_numbers(const std::vector<uint64_t>& v) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) out += (i ? "," : "") + std::to_string(v[i]);
    return out;
}

// "3,0,12": decimal numbers, comma between. Anything else (an empty part, a sign, a letter, more than 18 digits) is a
// FormatError that names `key`.
std::vector<uint64_t> split_numbers(const std::string& key, const std::string& s) {
    std::vector<uint64_t> out;
    size_t at = 0;
    while (at <= s.size() && !s.empty()) {
        const size_t comma = s.find(',', at);
        const std::string part = s.substr(at, comma == std::string::npos ? std::string::npos : comma - at);
        if (part.empty() || part.size() > 18 || part.find_first_not_of("0123456789") != std::string::npos)
            throw FormatError("manifest.txt: " + key + "=" + textquote::quote_shown(s) + " is not a list of decimal numbers separated by commas");
        out.push_back(std::strtoull(part.c_str(), nullptr, 10));
        if (comma == std::string::npos) break;
        at = comma + 1;
    }
    return out;
}

void unpack_elf_boot(const Bytes& data, const fs::path& dir) {
    legacy::ElfBootImage img = legacy::ElfBootImage::parse(data);
    Manifest m;
    m.set("type", "elf_boot");
    m.set_bool("is_64bit", img.is_64bit);
    m.set_u32("machine", img.machine);
    if (img.entry) m.set_addr("elf_entry", *img.entry);  // (without it e_entry is the address of the first segment, as elftool writes it)
    m.set_u32("segment_count", static_cast<uint32_t>(img.segments.size()));
    const ElfNames names = elf_names(img.segments);
    std::vector<ComponentSource> segment_sources;
    for (size_t i = 0; i < img.segments.size(); ++i) segment_sources.push_back({&img.segments[i].data, names.filename[i]});
    auto segment_parts = save_components(dir, segment_sources);
    for (size_t i = 0; i < img.segments.size(); ++i) {
        auto& s = img.segments[i];
        const std::string p = "segment" + std::to_string(i);
        m.set(p + "_role", s.role);
        m.set_u32(p + "_flags", s.flags);
        m.set_addr(p + "_addr", s.addr);
        if (names.prefix[i] != p) m.set(p + "_prefix", names.prefix[i]);
        record_component(m, names.prefix[i], names.filename[i], segment_parts[i]);
    }
    std::vector<TreeJob> tree_jobs;
    for (size_t i = 0; i < img.segments.size(); ++i)
        if (names.prefix[i] == "ramdisk") tree_jobs.push_back({"ramdisk", names.filename[i], &segment_parts[i]});
    save_ramdisk_trees(m, dir, tree_jobs);
    if (img.layout) {
        const legacy::ElfLayout& L = *img.layout;
        std::vector<uint64_t> order(L.order.begin(), L.order.end());
        std::vector<uint64_t> sizes{L.header.size()};
        Bytes blob = L.header;
        for (const Bytes& a : L.after) {
            sizes.push_back(a.size());
            blob.insert(blob.end(), a.begin(), a.end());
        }
        fs::create_directories(dir / ".abr_raw");
        write_file(dir / ".abr_raw" / "elf_layout.bin", blob);
        m.set("elf_layout", "kept");
        m.set("elf_layout_order", join_numbers(order));
        m.set("elf_layout_sizes", join_numbers(sizes));
        const bool padded = std::any_of(L.after.begin(), L.after.end(), [](const Bytes& a) { return !a.empty(); });
        const bool reordered = !std::is_sorted(L.order.begin(), L.order.end());
        std::string what = std::to_string(L.header.size()) + " bytes in front of the first segment's data";
        if (padded) what += ", padding or something else behind the segments";
        if (reordered) what += ", the data is not in the order of the program headers";
        if (L.header.size() == legacy::kElfDataStartOffset && !padded && !reordered)
            what += ", but that block (the ELF header, the program headers, what is between them) is not what elftool writes: an e_entry or OS/ABI of its own, p_align, p_memsz, p_paddr, fill bytes ...";
        note("this image is not laid out the way elftool lays an image out (" + what +
             "): the bytes around the segments are kept in .abr_raw/elf_layout.bin, the image is built in that layout");
    }
    m.save(dir / "manifest.txt",
           "abr elf_boot manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`");
}

Bytes repack_elf_boot(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    legacy::ElfBootImage img;
    img.is_64bit = m.get_bool("is_64bit", false);
    img.machine = static_cast<uint16_t>(m.get_bounded("machine", 40, 16));
    if (m.has("elf_entry")) img.entry = m.get_addr("elf_entry");
    uint32_t count = m.get_count("segment_count", 0);
    std::vector<std::string> segment_prefixes;
    for (uint32_t i = 0; i < count; ++i)
        segment_prefixes.push_back(m.get_name("segment" + std::to_string(i) + "_prefix", "segment" + std::to_string(i)));
    std::vector<Bytes> segment_data = load_components(m, dir, segment_prefixes, opt);
    for (uint32_t i = 0; i < count; ++i) {
        std::string p = "segment" + std::to_string(i);
        legacy::ElfSegment s;
        s.role = m.get_name(p + "_role", "kernel");
        s.flags = m.get_u32(p + "_flags", 0);
        s.addr = m.get_addr(p + "_addr", 0);
        s.data = std::move(segment_data[i]);
        img.segments.push_back(std::move(s));
    }
    if (m.get("elf_layout", "") == "kept") {
        // The bytes around the segments, as the unpack found them: .abr_raw/elf_layout.bin, cut up by the sizes the manifest has.
        const fs::path file = dir / ".abr_raw" / "elf_layout.bin";
        try {
            const std::vector<uint64_t> order = split_numbers("elf_layout_order", m.get("elf_layout_order", ""));
            const std::vector<uint64_t> sizes = split_numbers("elf_layout_sizes", m.get("elf_layout_sizes", ""));
            if (!fs::exists(file)) throw FormatError(file.generic_string() + " is not there");
            const Bytes blob = read_file(file);
            uint64_t total = 0;
            for (uint64_t n : sizes) {
                if (n > blob.size()) throw FormatError("elf_layout_sizes does not fit " + file.generic_string());
                total += n;
            }
            for (uint64_t n : order)  // (a number that is the number of no segment is for the build to say: it falls back with the reason)
                if (n > UINT32_MAX) throw FormatError("elf_layout_order has a number that is no segment's (" + std::to_string(n) + ")");
            if (sizes.size() != order.size() + 1 || total != blob.size())
                throw FormatError("elf_layout_sizes does not fit " + file.generic_string());
            legacy::ElfLayout L;
            size_t at = 0;
            L.header.assign(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(sizes[0]));
            at = static_cast<size_t>(sizes[0]);
            for (size_t k = 0; k < order.size(); ++k) {
                L.order.push_back(static_cast<uint32_t>(order[k]));
                L.after.emplace_back(blob.begin() + static_cast<std::ptrdiff_t>(at),
                                     blob.begin() + static_cast<std::ptrdiff_t>(at + sizes[k + 1]));
                at += static_cast<size_t>(sizes[k + 1]);
            }
            img.layout = std::move(L);
        } catch (const std::exception& e) {
            warn(std::string("the layout of the image that was unpacked cannot be used (") + e.what() +
                 "); the image is written in elftool's layout");
        }
    }
    std::string why;
    Bytes out = img.build(&why);
    if (!why.empty()) warn(why + "; the image is written in elftool's layout");
    return out;
}

// ---------------------------------------------------------------- krnl --
//
// Rockchip "KRNL" (abr/legacy/krnl.hpp): 8 bytes, the payload, a CRC. What Android Image Kitchen calls a
// ramdisk: a cpio archive -- compressed, as Rockchip's boot.img has it -- becomes `ramdisk.cpio` and the
// directory `ramdisk/`; a payload that is anything else (kernel.img holds a kernel) stays `kernel`.

void unpack_krnl(const Bytes& host, const fs::path& dir) {
    legacy::KrnlImage img = legacy::KrnlImage::parse(host);
    Manifest m;
    m.set("type", "krnl");
    DecodedComponent part = decode_component(img.payload, "payload");
    const bool ramdisk = part.plain.size() < 5 || std::memcmp(part.plain.data(), "07070", 5) == 0;  // (an empty one is a ramdisk)
    const std::string prefix = ramdisk ? "ramdisk" : "kernel";
    const std::string filename = ramdisk ? "ramdisk.cpio" : "kernel";
    if (part.present) {
        fs::create_directories(dir / ".abr_raw");
        write_file(dir / filename, part.plain);
        write_file(dir / ".abr_raw" / (filename + ".raw"), part.stored(img.payload));
        record_component(m, prefix, filename, part);
        if (ramdisk) save_ramdisk_trees(m, dir, {{"ramdisk", "ramdisk.cpio", &part}});
    }
    if (!img.crc_ok) {
        // Put back as it was while the payload is untouched, so that the round trip stays exact.
        m.set_addr("krnl_crc", img.crc);
        m.set_hex("krnl_payload_sha256", hash::sha256(img.payload));
        char found[16], should[16];
        std::snprintf(found, sizeof found, "0x%08x", img.crc);
        std::snprintf(should, sizeof should, "0x%08x", legacy::rkcrc32(img.payload));
        warn(std::string("the CRC stored in this KRNL image (") + found + ") is not the CRC of its payload (" + should +
             "); it is kept as long as the payload is not changed, and computed afresh after an edit");
    }
    const Envelope env = Envelope::capture(host, 0, img.file_size());
    save_envelope(m, dir, env, host, 0, img.file_size());
    m.save(dir / "manifest.txt", "abr krnl manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`");
}

Bytes repack_krnl(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    legacy::KrnlImage img;
    img.payload = load_component(m, dir, m.has("kernel_file") ? "kernel" : "ramdisk", opt);
    std::optional<uint32_t> crc;
    if (m.has("krnl_crc") && hash::sha256(img.payload) == m.get_hex("krnl_payload_sha256"))
        crc = m.get_addr32("krnl_crc", 0);
    return assemble_envelope(m, dir, img.build(crc), opt);
}

// ---------------------------------------------------------------- blob --
//
// ASUS "MSM-RADIO-UPDATE" blob, signed ("-SIGNED-BY-SIGNBLOB-") or not (abr/legacy/blob.hpp). Android Image
// Kitchen opens a blob whose only partition holds a boot image and works on that image; abr does the same: the
// blob is a wrapper then (`has_blob=true`, as with DHTB and amonet) and the directory is the image's. Any other
// blob is a directory of its own: `type=blob`, one file per partition.

// A partition name that is a plain word ("LNX") is written as text, anything else as hex.
bool blob_name_is_word(const std::array<uint8_t, 4>& n) {
    size_t len = 0;
    while (len < n.size() && n[len] != 0) ++len;
    if (len == 0) return false;
    for (size_t i = 0; i < len; ++i) {
        const uint8_t c = n[i];
        const bool plain = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '-' || c == '.';
        if (!plain) return false;
    }
    for (size_t i = len; i < n.size(); ++i)
        if (n[i] != 0) return false;
    return true;
}
std::string blob_name_word(const std::array<uint8_t, 4>& n) {
    size_t len = 0;
    while (len < n.size() && n[len] != 0) ++len;
    return std::string(reinterpret_cast<const char*>(n.data()), len);
}

// The fields of the blob except what the partitions hold. `data_bytes` and `data_sha256` describe that
// (all partitions, one after the other): kept to see, at repack, whether the contents changed (the
// signature then no longer fits) and what the secure header's datalen was a length of.
void save_blob_fields(Manifest& m, const fs::path& dir, const legacy::BlobImage& b, size_t data_bytes,
                      const Bytes& data_sha256) {
    m.set_bool("blob_secure", b.secure);
    if (b.secure) {
        m.set_addr("blob_secure_datalen", b.secure_datalen);
        m.set_addr("blob_secure_siglen", b.secure_siglen);
    }
    m.set_addr("blob_version", b.version);
    Bytes unknown;
    bool any_unknown = false;
    for (uint32_t u : b.unknown) {
        any_unknown = any_unknown || u != 0;
        for (int i = 0; i < 4; ++i) unknown.push_back(static_cast<uint8_t>(u >> (8 * i)));
    }
    if (any_unknown) m.set_hex("blob_unknown", unknown);
    m.set_u32("blob_parts", static_cast<uint32_t>(b.parts.size()));
    for (size_t i = 0; i < b.parts.size(); ++i) {
        const std::string key = "blob_part" + std::to_string(i);
        const auto& name = b.parts[i].name;
        if (blob_name_is_word(name)) m.set(key + "_name", blob_name_word(name));
        else m.set_hex(key + "_name_hex", Bytes(name.begin(), name.end()));
        m.set_u32(key + "_version", b.parts[i].version);
    }
    m.set_u64("blob_size", legacy::kBlobHeaderSize + b.parts.size() * legacy::kBlobPartEntrySize + data_bytes);
    m.set_hex("blob_data_sha256", data_sha256);
    if (!b.tail.empty()) save_raw(m, dir, "blob_tail", b.tail, "blob_tail.bin");
}

// The blob without its partitions' data. A wrapper's has one partition; the data is the caller's to put in.
legacy::BlobImage load_blob_fields(const Manifest& m, const fs::path& dir) {
    legacy::BlobImage b;
    b.secure = m.get_bool("blob_secure", false);
    b.secure_datalen = m.get_addr32("blob_secure_datalen", 0);
    b.secure_siglen = m.get_addr32("blob_secure_siglen", 0);
    b.version = m.get_addr32("blob_version", legacy::kBlobVersion);
    const Bytes unknown = m.get_hex("blob_unknown");
    if (!unknown.empty()) {
        if (unknown.size() != 4 * b.unknown.size())
            throw FormatError("blob_unknown in manifest.txt must be " + std::to_string(4 * b.unknown.size()) + " bytes");
        for (size_t i = 0; i < b.unknown.size(); ++i)
            b.unknown[i] = uint32_t(unknown[4 * i]) | (uint32_t(unknown[4 * i + 1]) << 8) |
                           (uint32_t(unknown[4 * i + 2]) << 16) | (uint32_t(unknown[4 * i + 3]) << 24);
    }
    const uint32_t count = m.get_count("blob_parts", 1);
    for (uint32_t i = 0; i < count; ++i) {
        const std::string key = "blob_part" + std::to_string(i);
        legacy::BlobPart part;
        if (m.has(key + "_name_hex")) {
            const Bytes raw = m.get_hex(key + "_name_hex");
            if (raw.size() != part.name.size()) throw FormatError(key + "_name_hex in manifest.txt must be 4 bytes");
            std::copy(raw.begin(), raw.end(), part.name.begin());
        } else {
            const std::string word = m.get(key + "_name");
            if (word.empty() || word.size() > part.name.size())
                throw FormatError(key + "_name in manifest.txt must be 1 to 4 characters");
            std::copy(word.begin(), word.end(), part.name.begin());
        }
        part.version = m.get_u32(key + "_version", 1);
        b.parts.push_back(std::move(part));
    }
    b.tail = load_raw(m, dir, "blob_tail");
    return b;
}

Bytes blob_data_sha256(const legacy::BlobImage& b) {
    hash::Sha256 h;
    for (const legacy::BlobPart& p : b.parts)
        if (!p.data.empty()) h.update(p.data.data(), p.data.size());
    return h.finish();
}

// The blob as it goes into the file. The secure header's datalen is a length of the blob: when it was the
// length of the blob at unpack it follows an edit (zero, which Android Image Kitchen writes, stays zero). The
// signature cannot be made again: if the contents changed it is kept as it was and said not to fit.
Bytes pack_blob(const Manifest& m, legacy::BlobImage b) {
    const uint64_t was = m.get_u64("blob_size", 0);
    if (b.secure && was != 0 && b.secure_datalen == was) b.secure_datalen = static_cast<uint32_t>(b.blob_size());
    const Bytes original = m.get_hex("blob_data_sha256");
    const bool changed = !original.empty() && blob_data_sha256(b) != original;
    if (changed && b.secure && (b.secure_siglen != 0 || !tail_is_inert(b.tail)))
        warn("the blob was changed, but the " + std::to_string(b.tail.size()) +
             " bytes after it (its signature, siglen " + std::to_string(b.secure_siglen) +
             ") are kept as they were; they still describe the ORIGINAL contents, so a bootloader that verifies "
             "them may reject the result");
    Bytes out = b.build();
    out.insert(out.end(), b.tail.begin(), b.tail.end());
    return out;
}

std::string blob_part_file(size_t index, const std::array<uint8_t, 4>& name) {
    std::string file = "part" + std::to_string(index);
    if (blob_name_is_word(name)) file += "_" + blob_name_word(name);
    return file + ".bin";
}

void unpack_blob(const Bytes& host, const fs::path& dir) {
    legacy::BlobImage b = legacy::BlobImage::parse(host);
    Manifest m;
    m.set("type", "blob");
    size_t bytes = 0;
    for (const legacy::BlobPart& p : b.parts) bytes += p.data.size();
    save_blob_fields(m, dir, b, bytes, blob_data_sha256(b));
    for (size_t i = 0; i < b.parts.size(); ++i) {
        const std::string file = blob_part_file(i, b.parts[i].name);
        write_file(dir / file, b.parts[i].data);
        m.set("blob_part" + std::to_string(i) + "_file", file);
    }
    m.save(dir / "manifest.txt", "abr blob manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`");
}

Bytes repack_blob(const Manifest& m, const fs::path& dir) {
    legacy::BlobImage b = load_blob_fields(m, dir);
    for (size_t i = 0; i < b.parts.size(); ++i) {
        const std::string key = "blob_part" + std::to_string(i) + "_file";
        if (!m.has(key)) throw FormatError("manifest.txt has no " + key);
        b.parts[i].data = read_file(dir / m.get_path(key));
    }
    return pack_blob(m, std::move(b));
}

// ---------------------------------------------------------------- loki --
//
// A boot or recovery image that went through loki_tool (abr/legacy/loki.hpp) is a wrapper around the plain boot
// image, like a DHTB header: `has_loki=true`, and the directory is the plain image's. The manifest keeps what
// the patch added -- the type, the build it was made for, the block behind the ramdisk with the patch code in it,
// what follows the image -- and repack puts the patch on the image the directory builds. `has_loki=false` leaves
// it out (a plain boot image comes out).

// The build field as text if it is text: a word of printable characters (no space at either end, the manifest
// does not keep it), then zeros up to the end of the 128 bytes, with at least one. Anything else goes as hex.
std::optional<std::string> loki_build_text(const Bytes& b) {
    size_t len = 0;
    while (len < b.size() && b[len] != 0) ++len;
    if (len == b.size()) return std::nullopt;  // no NUL at all
    for (size_t i = len; i < b.size(); ++i)
        if (b[i] != 0) return std::nullopt;
    std::string text(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(len));
    for (char c : text)
        if (c < 0x20 || c > 0x7e) return std::nullopt;
    if (!text.empty() && (text.front() == ' ' || text.back() == ' ')) return std::nullopt;
    return text;
}

// The build to show a person: its printable beginning.
std::string loki_build_shown(const Bytes& b) {
    std::string out;
    for (uint8_t c : b) {
        if (c == 0) break;
        out.push_back(c >= 0x20 && c <= 0x7e ? static_cast<char>(c) : '?');
    }
    return out;
}

void save_loki_fields(Manifest& m, const fs::path& dir, const legacy::LokiInfo& l) {
    m.set_u32("loki_recovery", l.recovery);
    if (auto text = loki_build_text(l.build))
        m.set("loki_build", *text);
    else
        m.set_hex("loki_build_hex", l.build);
    m.set_addr("loki_patched_ramdisk_addr", l.patched_ramdisk_addr);
    m.set_u32("loki_patched_ramdisk_size", l.patched_ramdisk_size);
    if (l.hdr_ramdisk_addr) m.set_addr("loki_hdr_ramdisk_addr", *l.hdr_ramdisk_addr);
    save_raw(m, dir, "loki_block", l.block, "loki_block.bin");
    m.set_u32("loki_shellcode_offset", l.patch_offset);
    // What follows the image: kept as it was, and the fill up to the size of the partition made again.
    save_raw(m, dir, "loki_tail", l.tail.tail, "loki_tail.bin");
    if (l.tail.pad_to) {
        m.set_addr("loki_pad_byte", l.tail.pad_byte);
        m.set_u64("loki_pad_to", l.tail.pad_to);
    }
}

legacy::LokiInfo load_loki_fields(const Manifest& m, const fs::path& dir) {
    for (const char* key : {"loki_recovery", "loki_patched_ramdisk_addr", "loki_patched_ramdisk_size",
                            "loki_shellcode_offset", "loki_block_file"})
        if (!m.has(key))
            throw FormatError(std::string("manifest.txt says has_loki=true but has no ") + key +
                              " (has_loki=false leaves the LOKI patch out)");
    legacy::LokiInfo l;
    l.recovery = m.get_u32("loki_recovery", 0);
    if (m.has("loki_build_hex")) {
        l.build = m.get_hex("loki_build_hex");
    } else {
        const std::string text = m.get("loki_build");
        if (text.size() >= legacy::kLokiBuildSize)
            throw FormatError("loki_build in manifest.txt is " + std::to_string(text.size()) + " characters long; the field of "
                              "the LOKI header holds " + std::to_string(legacy::kLokiBuildSize - 1) + " and a zero");
        l.build.assign(text.begin(), text.end());
        l.build.resize(legacy::kLokiBuildSize, 0);
    }
    l.patched_ramdisk_addr = m.get_addr32("loki_patched_ramdisk_addr", 0);
    l.patched_ramdisk_size = m.get_u32("loki_patched_ramdisk_size", 0);
    if (m.has("loki_hdr_ramdisk_addr")) l.hdr_ramdisk_addr = m.get_addr32("loki_hdr_ramdisk_addr", 0);
    l.block = load_raw(m, dir, "loki_block");
    l.patch_offset = m.get_u32("loki_shellcode_offset", 0);
    l.tail.tail = load_raw(m, dir, "loki_tail");
    l.tail.pad_byte = static_cast<uint8_t>(m.get_bounded("loki_pad_byte", 0, 8));
    l.tail.pad_to = m.get_size("loki_pad_to", 0);
    return l;
}

// The patch put on the image the directory builds; the tail behind it (other data, fill up to the partition's
// size) as it was.
Bytes apply_loki_wrapper(const Manifest& m, const fs::path& dir, const Bytes& plain, const RepackOptions& opt) {
    const legacy::LokiInfo l = load_loki_fields(m, dir);
    Bytes core;
    try {
        core = legacy::apply_loki(plain, l);
    } catch (const FormatError& e) {
        throw FormatError(std::string(e.what()) + " (has_loki=false in manifest.txt leaves the LOKI patch out)");
    }
    return assemble_envelope(m, l.tail, core, false, 0, opt);
}

// ------------------------------------------------------------ chromeos --
//
// A ChromeOS kernel blob (abr/legacy/chromeos.hpp), which Android Image Kitchen opens with `futility vbutil_kernel`.
// When the kernel in it is something abr unpacks (an Android boot image, ...), the blob is a wrapper around it, like
// a DHTB header: `has_chromeos=true`, and the directory is the kernel's. Otherwise it is a container of its own
// (type=chromeos) whose kernel is the file chromeos_kernel.bin. The manifest keeps what the blob adds -- the keyblock,
// the fields of the preamble, the config (the kernel's command line), the params and the bootloader of the body, the
// signatures, what follows the blob -- and repack makes the blob again around the kernel the directory builds. The
// signatures are the original's while nothing they cover has changed, and made again when it has (with the developer
// key of vboot_reference, or the key of keys/chromeos.vbprivk). `has_chromeos=false` leaves the blob out (a plain image comes
// out); `has_chromeos=true` on its own (a manifest with no keyblock) makes the blob Android Image Kitchen's command
// line makes.

void save_chromeos_fields(Manifest& m, const fs::path& dir, const legacy::ChromeosInfo& c) {
    save_raw(m, dir, "chromeos_keyblock", c.keyblock, "chromeos_keyblock.bin");
    m.set("chromeos_preamble_version", std::to_string(c.preamble_major) + "." + std::to_string(c.preamble_minor));
    m.set_u32("chromeos_kernel_version", c.kernel_version);
    if (c.preamble_minor >= 2) m.set_addr("chromeos_flags", c.flags);
    m.set_addr("chromeos_body_load_address", c.body_load_address);
    if (c.bootloader_address) m.set_addr("chromeos_bootloader_address", *c.bootloader_address);
    m.set_u32("chromeos_bootloader_size", c.bootloader_size);
    if (c.preamble_minor >= 1 && c.vmlinuz_header_address) m.set_addr("chromeos_vmlinuz_header_address", c.vmlinuz_header_address);
    m.set_u32("chromeos_vblock_size", c.pad);
    // The command line, the x86 boot parameters and the bootloader of the body: as they are, without the zeros
    // that fill their fields.
    save_raw(m, dir, "chromeos_config", c.config, "chromeos_config.txt");
    save_raw(m, dir, "chromeos_params", c.params, "chromeos_params.bin");
    save_raw(m, dir, "chromeos_bootloader", c.bootloader, "chromeos_bootloader.bin");
    // The signatures, and what they cover: while that is unchanged they are put back as they were.
    save_raw(m, dir, "chromeos_body_signature", c.body_signature, "chromeos_body_signature.bin");
    save_raw(m, dir, "chromeos_preamble_signature", c.preamble_signature, "chromeos_preamble_signature.bin");
    m.set_hex("chromeos_signed_sha256", c.signed_sha256);
    // What follows the blob: kept as it was, and the fill up to the size of the partition made again.
    save_raw(m, dir, "chromeos_tail", c.tail.tail, "chromeos_tail.bin");
    if (c.tail.pad_to) {
        m.set_addr("chromeos_pad_byte", c.tail.pad_byte);
        m.set_u64("chromeos_pad_to", c.tail.pad_to);
    }
}

legacy::ChromeosInfo load_chromeos_fields(const Manifest& m, const fs::path& dir) {
    legacy::ChromeosInfo c;
    // A directory that holds no blob (a plain image with has_chromeos=true added to its manifest) gets what
    // Android Image Kitchen's `futility vbutil_kernel --pack` line makes: the developer keyblock and key, version 1,
    // flags 0x1, a config and a bootloader of one space each (futility will not take an empty file for either).
    const bool fresh = !m.has("chromeos_keyblock_file");
    c.keyblock = fresh ? legacy::chromeos_dev_keyblock() : load_raw(m, dir, "chromeos_keyblock");
    std::tie(c.preamble_major, c.preamble_minor) = m.get_version("chromeos_preamble_version", c.preamble_major, c.preamble_minor);
    c.kernel_version = m.get_u32("chromeos_kernel_version", 1);
    const uint64_t flags = m.get_addr("chromeos_flags", fresh ? 1 : 0);
    if (flags > 0xFFFFFFFFull) throw FormatError("chromeos_flags in manifest.txt does not fit in 32 bits");
    c.flags = static_cast<uint32_t>(flags);
    c.body_load_address = m.get_addr("chromeos_body_load_address", 0x100000);
    if (m.has("chromeos_bootloader_address")) c.bootloader_address = m.get_addr("chromeos_bootloader_address", 0);
    c.bootloader_size = static_cast<uint32_t>(m.get_size("chromeos_bootloader_size", legacy::kChromeosAlign));
    c.vmlinuz_header_address = m.get_addr("chromeos_vmlinuz_header_address", 0);
    c.pad = static_cast<uint32_t>(m.get_size("chromeos_vblock_size", legacy::kChromeosDefaultPad));
    const Bytes one_space{' '};
    c.config = (m.has("chromeos_config_file") || !fresh) ? load_raw(m, dir, "chromeos_config") : one_space;
    c.params = load_raw(m, dir, "chromeos_params");
    c.bootloader = (m.has("chromeos_bootloader_file") || !fresh) ? load_raw(m, dir, "chromeos_bootloader") : one_space;
    c.body_signature = load_raw(m, dir, "chromeos_body_signature");
    c.preamble_signature = load_raw(m, dir, "chromeos_preamble_signature");
    c.signed_sha256 = m.get_hex("chromeos_signed_sha256");
    if (c.body_signature.empty() || c.preamble_signature.empty()) c.signed_sha256.clear();  // nothing to keep
    c.tail.tail = load_raw(m, dir, "chromeos_tail");
    c.tail.pad_byte = static_cast<uint8_t>(m.get_bounded("chromeos_pad_byte", 0, 8));
    c.tail.pad_to = m.get_size("chromeos_pad_to", 0);
    return c;
}

// The blob made of `kernel`: the verification block and the body from the manifest, the signatures as described
// above; what follows the blob as it was. `wrapper` says which sentence an error ends with.
Bytes apply_chromeos_wrapper(const Manifest& m, const fs::path& dir, const Bytes& kernel, const RepackOptions& opt,
                             bool wrapper) {
    const legacy::ChromeosInfo c = load_chromeos_fields(m, dir);
    legacy::ChromeosSigned how = legacy::ChromeosSigned::KEPT;
    Bytes core;
    try {
        core = legacy::apply_chromeos(kernel, c, opt.chromeos, &how);
    } catch (const FormatError& e) {
        throw FormatError(std::string(e.what()) +
                          (wrapper ? " (has_chromeos=false in manifest.txt leaves the ChromeOS kernel blob out)" : ""));
    }
    switch (how) {
        case legacy::ChromeosSigned::KEPT:
            break;
        case legacy::ChromeosSigned::SIGNED: {
            const std::string with = opt.chromeos.key ? "the key given (keys/chromeos.vbprivk)" : "the developer key of vboot_reference";
            // (no signatures came with the directory: a plain image with has_chromeos=true, nothing was "changed")
            note(c.signed_sha256.empty()
                     ? "the ChromeOS kernel blob is signed with " + with
                     : "what the signatures of the ChromeOS kernel blob cover has changed: they are made again, with " + with +
                           (opt.chromeos.key ? "" : ", the data key of the blob's keyblock"));
            break;
        }
        case legacy::ChromeosSigned::NEW_KEYBLOCK:
            note("the ChromeOS kernel blob is signed under the keyblock given (keys/chromeos.keyblock)");
            break;
        case legacy::ChromeosSigned::DEVELOPER_KEYBLOCK:
            warn("what the signatures of the ChromeOS kernel blob cover has changed, and its keyblock is somebody else's: "
                 "abr has no key for it. The blob is signed with the developer key under the developer keyblock of "
                 "vboot_reference instead, as Android Image Kitchen does; a Chromebook in developer mode boots it, one "
                 "that checks the keyblock against its own keys does not. keys/chromeos.vbprivk and keys/chromeos.keyblock "
                 "sign with keys of your own");
            break;
    }
    return assemble_envelope(m, c.tail, core, false, 0, opt);
}

void unpack_chromeos(const Bytes& host, const fs::path& dir) {
    Bytes kernel;
    std::optional<legacy::ChromeosInfo> c = legacy::strip_chromeos(host, kernel);
    if (!c) throw FormatError("this is not a ChromeOS kernel blob (it does not start with a keyblock)");
    Manifest m;
    m.set("type", "chromeos");
    save_chromeos_fields(m, dir, *c);
    save_raw(m, dir, "chromeos_kernel", kernel, "chromeos_kernel.bin");
    m.save(dir / "manifest.txt", "abr ChromeOS kernel blob manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`");
}

Bytes repack_chromeos(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    if (!m.has("chromeos_kernel_file")) throw FormatError("manifest.txt has no chromeos_kernel_file");
    return apply_chromeos_wrapper(m, dir, load_raw(m, dir, "chromeos_kernel"), opt, false);
}

// What to say of a blob: the preamble, the data key, the fields of the body, whether the signatures are good.
std::string chromeos_description(const legacy::ChromeosInfo& c) {
    char word[32];
    std::string out = "vboot preamble " + std::to_string(c.preamble_major) + "." + std::to_string(c.preamble_minor) +
                      ", kernel version " + std::to_string(c.kernel_version);
    if (c.preamble_minor >= 2) {
        std::snprintf(word, sizeof word, "0x%x", c.flags);
        out += std::string(", flags ") + word;
    }
    std::snprintf(word, sizeof word, "0x%llx", static_cast<unsigned long long>(c.body_load_address));
    out += std::string(", loaded at ") + word + "; keyblock " + std::to_string(c.keyblock.size()) + " bytes, data key " +
           (c.data_key_algorithm ? legacy::chromeos_algorithm_name(*c.data_key_algorithm) : std::string("unreadable")) +
           (c.data_key_is_dev ? " (the developer key of vboot_reference)" : "") +
           "; kernel " + std::to_string(c.kernel_size) + " bytes, config " + std::to_string(c.config.size()) + " bytes, bootloader " +
           std::to_string(c.bootloader_size) + " bytes; ";
    auto verdict = [](const std::optional<bool>& ok) { return !ok ? "not checked" : *ok ? "valid" : "NOT valid"; };
    if (c.body_signature_ok == c.preamble_signature_ok)
        out += std::string("signatures ") + verdict(c.body_signature_ok);
    else
        out += std::string("body signature ") + verdict(c.body_signature_ok) + ", preamble signature " + verdict(c.preamble_signature_ok);
    return out;
}

// ---------------------------------------------------------------- osip --
//
// Intel OSIP boot image (abr/legacy/osip.hpp), which Android Image Kitchen opens with mboot: an OSIP header,
// a signature, the cmdline and the image info, the bootstub, the kernel and a gzip-compressed ramdisk. The
// kernel and the bootstub stay files as they are; the ramdisk is `ramdisk.cpio` and the directory `ramdisk/`,
// as in a boot image. mboot's habits are kept up: when the size of the image (or the presence of the signature)
// changes, the sector count, the "unsigned" bit and the checksum of the header are made afresh, and the image
// is padded up to a whole sector; an image that is not touched comes back exactly as it was.

// The padding behind the image proper that belongs to it: up to a whole sector, all of one byte (0xFF where
// mboot wrote it). What is behind that is the envelope's (the rest of a partition).
struct OsipPadding {
    bool aligned = false;  // the file has that padding
    uint8_t byte = 0xFF;
    size_t core_size = 0;  // the image with its padding
};

OsipPadding osip_padding(const Bytes& host, size_t consumed) {
    OsipPadding p;
    p.core_size = consumed;
    const size_t need = static_cast<size_t>(padding_for(consumed, kOsipSectorSize));
    if (need == 0) {
        p.aligned = true;
        return p;
    }
    if (host.size() < consumed + need) return p;
    const uint8_t first = host[consumed];
    for (size_t i = 1; i < need; ++i)
        if (host[consumed + i] != first) return p;
    p.aligned = true;
    p.byte = first;
    p.core_size = consumed + need;
    return p;
}

// What a signature would cover (and what an edit changes): all but the header and the signature.
Bytes osip_payload_sha256(const OsipImage& img) {
    hash::Sha256 h;
    auto add = [&h](const Bytes& b) {
        if (!b.empty()) h.update(b.data(), b.size());
    };
    add(img.cmdline);
    h.update(img.parameter.data(), img.parameter.size());
    add(img.info_rest);
    add(img.bootstub);
    add(img.kernel);
    add(img.ramdisk);
    return h.finish();
}

std::string osip_type_name(uint8_t attribute) {
    switch (attribute) {
        case 0x00: return "boot (signed)";
        case 0x01: return "boot (unsigned)";
        case 0x0C: return "recovery (signed)";
        case 0x0D: return "recovery (unsigned)";
    }
    char word[24];
    std::snprintf(word, sizeof word, "type 0x%02x", attribute);
    return word;
}

// The text of a cmdline as manifest.txt can hold it: a line of its own, without white space at either end.
std::string osip_cmdline_shown(std::string text) {
    for (char& c : text)
        if (c == '\n' || c == '\r') c = ' ';
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

// The cmdline block: the text of the manifest; where the block held more than that (white space at the ends,
// something behind the text that is not NULs: a file of its own then), that block, as long as the text of the
// manifest is the one that was in it.
Bytes osip_cmdline_block(const Manifest& m, const fs::path& dir) {
    const std::string text = m.get("cmdline");
    const Bytes raw = load_raw(m, dir, "osip_cmdline");
    if (raw.size() == kOsipCmdlineSize) {
        size_t len = 0;
        while (len < raw.size() && raw[len] != 0) ++len;
        if (osip_cmdline_shown(std::string(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(len))) == text) return raw;
    }
    if (text.size() > kOsipCmdlineSize)
        throw FormatError("the cmdline in manifest.txt is " + std::to_string(text.size()) + " bytes; an OSIP image has room for " +
                          std::to_string(kOsipCmdlineSize));
    Bytes block(kOsipCmdlineSize, 0);
    std::copy(text.begin(), text.end(), block.begin());
    return block;
}

void unpack_osip(const Bytes& host, const fs::path& dir) {
    OsipImage img = OsipImage::parse(host);
    Manifest m;
    m.set("type", "osip");
    if (!img.header.empty()) {
        save_raw(m, dir, "osip_header", img.header, "osip_header.bin");
        const bool ok = osip_header_checksum_ok(img.header);
        m.set_bool("osip_header_checksum_ok", ok);
        if (!ok)
            note("the checksum in the OSIP header (byte 7) is not the one mboot computes; it is kept as it is while the size of "
                 "the image does not change");
    }
    save_raw(m, dir, "osip_signature", img.signature, "osip_sig.bin");
    m.set_u32("osip_signature_size", static_cast<uint32_t>(img.signature.size()));
    {
        const std::string text = img.cmdline_text();
        const std::string shown = osip_cmdline_shown(text);
        m.set("cmdline", shown);
        Bytes plain(kOsipCmdlineSize, 0);
        std::copy(text.begin(), text.end(), plain.begin());
        if (plain != img.cmdline || shown != text) save_raw(m, dir, "osip_cmdline", img.cmdline, "osip_cmdline.bin");  // more than text and NULs
    }
    m.set_hex("osip_parameter", Bytes(img.parameter.begin(), img.parameter.end()));
    Bytes rest = img.info_rest;  // zeros behind it are not written down
    while (!rest.empty() && rest.back() == 0) rest.pop_back();
    save_raw(m, dir, "osip_info", rest, "osip_info.bin");
    save_raw(m, dir, "bootstub", img.bootstub, "bootstub.bin");
    save_raw(m, dir, "kernel", img.kernel, "kernel");

    DecodedComponent ramdisk = decode_component(img.ramdisk, "ramdisk");
    if (ramdisk.present) {
        fs::create_directories(dir / ".abr_raw");
        write_file(dir / "ramdisk.cpio", ramdisk.plain);
        write_file(dir / ".abr_raw" / "ramdisk.cpio.raw", ramdisk.stored(img.ramdisk));
        record_component(m, "ramdisk", "ramdisk.cpio", ramdisk);
        save_ramdisk_trees(m, dir, {{"ramdisk", "ramdisk.cpio", &ramdisk}});
    }

    m.set_u64("osip_body_size", img.body_size());
    m.set_hex("osip_payload_sha256", osip_payload_sha256(img));
    const OsipPadding pad = osip_padding(host, img.consumed);
    if (pad.aligned) m.set_addr("osip_sector_pad", pad.byte);
    else m.set("osip_sector_pad", "none");
    const Envelope env = Envelope::capture(host, 0, pad.core_size);
    save_envelope(m, dir, env, host, 0, pad.core_size);
    m.save(dir / "manifest.txt", "abr osip manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`");
}

Bytes repack_osip(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    OsipImage img;
    img.header = load_raw(m, dir, "osip_header");
    img.signature = load_raw(m, dir, "osip_signature");
    img.cmdline = osip_cmdline_block(m, dir);
    const Bytes parameter = m.get_hex("osip_parameter");
    if (!parameter.empty()) {
        if (parameter.size() != img.parameter.size())
            throw FormatError("osip_parameter in manifest.txt must be 8 bytes (16 hex digits)");
        std::copy(parameter.begin(), parameter.end(), img.parameter.begin());
    }
    img.info_rest = load_raw(m, dir, "osip_info");
    if (img.info_rest.size() > kOsipInfoSize - kOsipInfoFixedSize)
        throw FormatError("osip_info.bin is longer than the " + std::to_string(kOsipInfoSize - kOsipInfoFixedSize) +
                          " bytes the image info has room for behind the parameter");
    img.info_rest.resize(kOsipInfoSize - kOsipInfoFixedSize, 0);
    img.bootstub = load_raw(m, dir, "bootstub");
    img.kernel = load_raw(m, dir, "kernel");
    img.ramdisk = load_component(m, dir, "ramdisk", opt);

    // A signed image has a mark behind the parameter in the image info: put there when a signature is added,
    // taken away with it (what mboot does when it packs the pieces).
    const bool signed_now = !img.signature.empty();
    const bool signed_was = m.get_u64("osip_signature_size", 0) != 0;
    const std::array<uint8_t, 8> none{};
    if (signed_now && !signed_was) {
        if (std::equal(none.begin(), none.end(), img.info_rest.begin())) std::copy(kOsipSignedMagic, kOsipSignedMagic + 8, img.info_rest.begin());
    } else if (!signed_now && signed_was) {
        if (std::equal(kOsipSignedMagic, kOsipSignedMagic + 8, img.info_rest.begin())) std::fill_n(img.info_rest.begin(), 8, uint8_t(0));
    }

    const uint64_t body = img.body_size();
    const std::string pad_word = m.get("osip_sector_pad", "0xFF");
    const bool aligned = pad_word != "none";
    const uint8_t pad_byte = aligned ? static_cast<uint8_t>(m.get_bounded("osip_sector_pad", 0xFF, 8)) : 0;
    if (!img.header.empty()) {
        const bool size_changed = !m.has("osip_body_size") || m.get_u64("osip_body_size", 0) != body;
        if (size_changed || signed_now != signed_was) osip_refresh_header(img.header, align_up(body, kOsipSectorSize), signed_now);
        else if (m.get_bool("osip_header_checksum_ok", false)) osip_set_header_checksum(img.header);
    }

    const Bytes was = m.get_hex("osip_payload_sha256");
    if (signed_now && signed_was && !was.empty() && osip_payload_sha256(img) != was)
        warn("the image was changed, but its signature (" + std::to_string(img.signature.size()) +
             " bytes) is kept as it was; it describes the ORIGINAL contents, so a bootloader that verifies it may reject the result");
    if (signed_now && !signed_was && !img.header.empty() && (osip_header_attribute(img.header) & 1) != 0)
        note("the image has a signature now, but its header still says \"" + osip_type_name(osip_header_attribute(img.header)) +
             "\"; the header is kept as mboot keeps it (put the header of a signed image in osip_header.bin to change that)");

    Bytes core = img.build();
    if (aligned) core.insert(core.end(), static_cast<size_t>(padding_for(core.size(), kOsipSectorSize)), pad_byte);
    return assemble_envelope(m, dir, core, opt);
}

// ------------------------------------------------------------ info cmd --

void print_envelope_info(const Envelope& e) {
    if (!e.prefix.empty())
        std::cout << "wrapper:        " << e.prefix.size()
                  << " bytes before the image (kept verbatim)\n";
    if (!e.tail.empty())
        std::cout << "trailing:       " << e.tail.size()
                  << " bytes after the image (kept verbatim)\n";
    if (e.pad_to) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "0x%02x", e.pad_byte);
        std::cout << "padding:        " << buf << " fill up to " << e.pad_to << " bytes\n";
    }
}

void print_avb1_info(const Envelope& env, const Bytes& host, size_t image_off, size_t image_len) {
    auto sig = parse_boot_signature(env.tail, 0);
    if (!sig) return;
    Verification v = verify_boot_signature(*sig, host.data() + image_off, host.size() - image_off);
    std::cout << "boot signature: AVBv1 (boot_signer), target " << shown(sig->target) << "\n"
              << "  signer:       " << shown(certificate_subject(sig->certificate))
              << (is_aosp_test_certificate(sig->certificate)
                      ? "  [public AOSP test key: abr can re-sign it]"
                      : "")
              << "\n"
              << "  covers:       " << sig->length << " bytes"
              << (sig->length == image_len
                      ? " (the whole image)"
                      : " -- but the image is " + std::to_string(image_len) + " bytes")
              << "\n"
              << "  signature:    " << signature_algorithm_name(sig->algorithm_oid) << ", "
              << verdict_text(v) << "\n";
}

// What `info` says about the public key of an AVB 2.0 vbmeta: its size and id, and whether it is one of the public test keys that abr
// has the private half of (then it signs the image again itself when the content has changed).
std::string avb_key_text(const Bytes& public_key) {
    std::string text = describe_avb_public_key(public_key);
    if (find_avb_test_key(public_key)) text += " -- abr signs with it itself when the content changes";
    return text;
}

void print_avb_footer_info(const AvbFooter& f, const Bytes& host) {
    if (!f.present) return;
    const VbmetaImage& v = f.v;
    std::cout << "avb footer:     partition " << v.source_total_size << " bytes, protects the first "
              << f.host_size << ", algorithm " << avb_algorithm_name(v.algorithm_type)
              << (v.algorithm_type ? " (signed)" : " (unsigned)") << "\n";
    if (!v.public_key.empty()) std::cout << "  public key:   " << avb_key_text(v.public_key) << "\n";
    for (auto& d : v.descriptors) std::cout << "  - " << d.describe() << "\n";
    size_t bad = 0;
    size_t checked = v.verify_hash_descriptors(host, &bad);
    if (checked)
        std::cout << "  hash check:   "
                  << (bad ? "MISMATCH -- the image no longer matches its footer (modified "
                            "without re-signing?)"
                          : "OK -- every hash descriptor matches the image")
                  << "\n";
}

// ------------------------------------------------------------ mtk_image --
//
// The small images of a MediaTek phone (abr/mtkimg.hpp): md1img (the modem), lk, tee, scp, sspm, logo and the rest of that kind. `unpack` writes
// the data of every section to a file of its own, `<NN>_<name>` (NN is the number of the section, so the same name twice is no trouble),
// after taking its compression off -- a stream is known by what it holds, not by a name: gzip, xz, lzma, lz4, zstd, bzip2, lzo -- and the
// manifest says what the header of the section says (`section<i>_*`), how the data was compressed (`section<i>_compression`, the level or the
// settings of the stream), and how the sections follow one another (the alignment, the bytes of the padding). A section that is a table of
// pictures -- the logo -- becomes a folder of PNG files, `<NN>_<name>/img-000.png` and so on; a picture whose pixels are not a size that is
// known stays a file of its pixels as they are, so that nothing is lost. A picture, like any other component, is put back as the very bytes it
// was when its file is unchanged.

std::string mtk_section_prefix(size_t i) { return "section" + std::to_string(i); }
std::string mtk_picture_prefix(size_t section, size_t k) { return mtk_section_prefix(section) + "_p" + std::to_string(k); }

// `00_md1rom`: the number of the section (two digits at least), the name of the section made safe for a file name.
std::string mtk_file_name(size_t index, size_t count, std::string_view name) {
    const size_t width = std::max<size_t>(2, std::to_string(count > 0 ? count - 1 : 0).size());
    std::string number = std::to_string(index);
    if (number.size() < width) number.insert(0, width - number.size(), '0');
    std::string clean;
    for (const char c : name) {
        const bool plain = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-';
        clean += plain ? c : '_';
    }
    while (!clean.empty() && clean.back() == '.') clean.pop_back();
    return number + "_" + (clean.empty() ? "section" : clean);
}

std::string mtk_picture_file_name(const std::string& folder, size_t k, size_t count, bool png) {
    const size_t width = std::max<size_t>(3, std::to_string(count > 0 ? count - 1 : 0).size());
    std::string number = std::to_string(k);
    if (number.size() < width) number.insert(0, width - number.size(), '0');
    return folder + "/img-" + number + (png ? ".png" : ".bin");
}

// What the header of a section says, as the manifest has it. A field of an older header that says nothing (0xFFFFFFFF) is left out.
void save_mtk_header(Manifest& m, const std::string& p, const mtkimg::Header& h) {
    m.set(p + "_name", h.name_text());
    m.set_tail(p + "_name_tail", h.name_tail());
    m.set_addr(p + "_load_addr", h.maddr);
    m.set_addr(p + "_mode", h.mode);
    m.set_addr(p + "_ext_magic", h.ext_magic);
    const auto field = [&](const char* key, uint32_t value) {
        if (h.extended() || value != mtkimg::kAny) m.set_addr(p + "_" + key, value);
    };
    field("hdr_size", h.hdr_size);
    field("hdr_version", h.hdr_version);
    field("img_type", h.img_type);
    field("list_end", h.img_list_end);
    field("align", h.align_size);
    field("size_high", h.dsize_extend);
    field("load_addr_high", h.maddr_extend);
    if (std::any_of(h.reserved.begin(), h.reserved.end(), [](uint8_t b) { return b != 0xFF; })) m.set_hex(p + "_reserved", h.reserved);
}

mtkimg::Header load_mtk_header(const Manifest& m, const std::string& p, bool last) {
    using mtkimg::kAny;
    if (!m.has(p + "_name")) throw FormatError("manifest.txt: " + shown(p + "_name") + " is missing (the name of the section)");
    mtkimg::Header h = mtkimg::Header::fresh("x");
    try {
        h.set_name(m.get(p + "_name"), m.get_tail(p + "_name_tail"));
    } catch (const FormatError& e) {
        throw FormatError("manifest.txt: " + shown(p + "_name") + ": " + e.what());
    }
    h.maddr = m.get_addr32(p + "_load_addr", kAny);
    h.mode = m.get_addr32(p + "_mode", kAny);
    h.ext_magic = m.get_addr32(p + "_ext_magic", mtkimg::kExtMagic);
    const bool ext = h.extended();
    h.hdr_size = m.get_addr32(p + "_hdr_size", ext ? static_cast<uint32_t>(mtkimg::kHeaderSize) : kAny);
    h.hdr_version = m.get_addr32(p + "_hdr_version", ext ? 0 : kAny);
    h.img_type = m.get_addr32(p + "_img_type", ext ? 0 : kAny);
    h.img_list_end = m.get_addr32(p + "_list_end", ext ? (last ? 1 : 0) : kAny);
    h.align_size = m.get_addr32(p + "_align", ext ? 16 : kAny);
    h.dsize_extend = m.get_addr32(p + "_size_high", ext ? 0 : kAny);
    h.maddr_extend = m.get_addr32(p + "_load_addr_high", ext ? 0 : kAny);
    if (m.has(p + "_reserved")) {
        Bytes reserved = m.get_hex(p + "_reserved");
        if (reserved.size() != h.reserved.size())
            throw FormatError("manifest.txt: " + shown(p + "_reserved") + " is " + std::to_string(reserved.size()) + " bytes; the rest of a header is " +
                              std::to_string(h.reserved.size()));
        h.reserved = std::move(reserved);
    }
    return h;
}

// The bytes between the data of a section and the next header, as the manifest keeps them: the alignment that put the next header where it is,
// and the byte that fills (when it is not zero) or all of the bytes (when they are not one byte over and over).
void save_mtk_padding(Manifest& m, const std::string& p, const mtkimg::Span& s, const Bytes& data) {
    if (s.pad_size == 0 && s.align == 0) return;
    m.set(p + "_pad_align", std::to_string(s.align));
    if (s.pad_size == 0) return;
    const size_t at = s.data_at + static_cast<size_t>(s.data_size);
    const uint8_t first = data[at];
    if (std::all_of(data.begin() + static_cast<std::ptrdiff_t>(at), data.begin() + static_cast<std::ptrdiff_t>(at + s.pad_size), [&](uint8_t b) { return b == first; })) {
        if (first != 0) m.set_addr(p + "_pad_byte", first);
    } else {
        m.set_hex(p + "_pad_hex", Bytes(data.begin() + static_cast<std::ptrdiff_t>(at), data.begin() + static_cast<std::ptrdiff_t>(at + s.pad_size)));
    }
}

Bytes load_mtk_padding(const Manifest& m, const std::string& p, uint64_t at, uint32_t default_align) {
    const uint32_t align = static_cast<uint32_t>(m.get_int(p + "_pad_align", default_align, 1, 65536));
    const size_t n = mtkimg::pad_length(at, align);
    if (m.has(p + "_pad_hex")) {
        Bytes hex = m.get_hex(p + "_pad_hex");
        if (hex.size() == n) return hex;  // (a section whose size changed has another length of padding: the byte that fills is used)
    }
    return Bytes(n, static_cast<uint8_t>(m.get_bounded(p + "_pad_byte", 0, 8)));
}

// ---- the pictures of a logo table

struct MtkPicture {
    std::string problem;                    // why a stream that starts like zlib's could not be unpacked
    Bytes stored;                           // as it lies in the table: a zlib stream, and what follows it
    Bytes plain;                            // the pixels
    Codec codec = Codec::NONE;              // ZLIB, or NONE for bytes that are no zlib stream
    int level = -1;
    std::string level_basis;
    Bytes plain_hash;
    std::optional<mtkimg::Resolution> size;  // set when the pixels make a picture of a size abr knows
    std::optional<uint8_t> alpha;            // every pixel has this alpha: the PNG has no alpha channel
};

struct MtkLogo {
    mtkimg::PixelFormat format = mtkimg::PixelFormat::BGRA8888;
    std::vector<MtkPicture> pictures;
};

// The pictures of a table: every one is decompressed (on several threads), the pixel format that explains the sizes is told, and for every
// picture the size that its pixels have, where that is known: from the table of resolutions of abr/mtkimg.hpp, or as wide as the first
// picture that the table knows.
//
// What a table may ask of the memory is limited: no picture is more than 64 MiB unpacked (a screen of 4K by 4K at four bytes a pixel), and all of
// them together are not more than 512 MiB; a stream that would be more is kept as the bytes it is.
constexpr size_t kMtkPictureLimit = size_t{64} << 20;
constexpr uint64_t kMtkLogoLimit = uint64_t{512} << 20;

MtkLogo analyse_mtk_logo(const std::vector<Bytes>& stored, bool with_hash) {
    MtkLogo logo;
    logo.pictures.resize(stored.size());
    std::atomic<uint64_t> used{0};
    par::for_each(stored.size(), [&](size_t i) {
        MtkPicture& pic = logo.pictures[i];
        pic.stored = stored[i];
        try {
            const uint64_t so_far = used.load();
            const uint64_t room = so_far >= kMtkLogoLimit ? 0 : kMtkLogoLimit - so_far;
            pic.plain = decompress(Codec::ZLIB, pic.stored, static_cast<size_t>(std::min<uint64_t>(kMtkPictureLimit, room)));
            pic.codec = Codec::ZLIB;
            used += pic.plain.size();
        } catch (const FormatError& e) {
            const bool zlib_header = pic.stored.size() >= 6 && (pic.stored[0] & 0x0f) == 8 && ((pic.stored[0] << 8) | pic.stored[1]) % 31 == 0;
            if (zlib_header) pic.problem = e.what();
            pic.plain = pic.stored;
            pic.codec = Codec::NONE;
        }
        if (with_hash) pic.plain_hash = hash::sha256(pic.plain);
        if (pic.codec == Codec::ZLIB && !pic.plain.empty()) {
            const LevelGuess guess = detect_level(Codec::ZLIB, pic.stored, pic.plain);
            pic.level = guess.level;
            pic.level_basis = guess.basis;
        }
    });
    std::vector<size_t> sizes;
    for (const MtkPicture& pic : logo.pictures) sizes.push_back(pic.plain.size());
    logo.format = mtkimg::guess_format(sizes);
    const size_t bpp = mtkimg::bytes_per_pixel(logo.format);
    std::optional<mtkimg::Resolution> like;
    for (const MtkPicture& pic : logo.pictures)
        if (!like && !pic.plain.empty() && pic.plain.size() % bpp == 0) like = mtkimg::guess_resolution(pic.plain.size() / bpp);
    for (MtkPicture& pic : logo.pictures) {
        if (pic.plain.empty() || pic.plain.size() % bpp != 0) continue;
        const uint64_t pixels = pic.plain.size() / bpp;
        if (pixels > png::kMaxPixels) continue;
        pic.size = mtkimg::guess_resolution(pixels, like);
        if (pic.size) pic.alpha = mtkimg::constant_alpha(logo.format, pic.plain);
    }
    return logo;
}

std::string mtk_picture_text(const MtkPicture& pic, mtkimg::PixelFormat format) {
    std::string s;
    if (pic.size) s = std::to_string(pic.size->width) + "x" + std::to_string(pic.size->height) + " " + std::string(mtkimg::format_name(format));
    else s = std::to_string(pic.plain.size()) + " bytes of pixels, no size abr knows";
    s += pic.codec == Codec::ZLIB ? ", zlib" : pic.problem.empty() ? ", stored as they are (no zlib stream)" : ", stored as they are (" + pic.problem + ")";
    if (pic.level >= 0) s += " level " + std::to_string(pic.level);
    return s;
}

// ---- unpack

void unpack_mtk_image(const Bytes& data, const fs::path& dir) {
    size_t consumed = 0;
    const std::vector<mtkimg::Span> spans = mtkimg::scan(data, &consumed);
    const size_t count = spans.size();
    Manifest m;
    m.set("type", "mtk_image");
    m.set_u32("sections", static_cast<uint32_t>(count));

    struct SectionWork {
        std::string file;                       // the file of the data, or the folder of the pictures
        std::optional<mtkimg::Logo> logo;
        Bytes bytes;                            // the data of the section
        DecodedComponent decoded;               // an ordinary section
        MtkLogo pictures;                       // a table of pictures
        std::vector<std::string> picture_files;
    };
    std::vector<SectionWork> work(count);
    uint64_t total = 0;
    for (size_t i = 0; i < count; ++i) {
        SectionWork& w = work[i];
        const mtkimg::Span& s = spans[i];
        w.file = mtk_file_name(i, count, s.header.name_text());
        w.bytes.assign(data.begin() + static_cast<std::ptrdiff_t>(s.data_at), data.begin() + static_cast<std::ptrdiff_t>(s.data_at + s.data_size));
        w.logo = mtkimg::parse_logo(w.bytes);
        total += w.bytes.size();
    }
    fs::create_directories(dir / ".abr_raw");
    progress::enter("decode", total);

    // The ordinary sections: decoded, written, on several threads (the biggest first).
    std::vector<size_t> plain_sections;
    for (size_t i = 0; i < count; ++i)
        if (!work[i].logo && !work[i].bytes.empty()) plain_sections.push_back(i);
    std::stable_sort(plain_sections.begin(), plain_sections.end(), [&](size_t a, size_t b) { return work[a].bytes.size() > work[b].bytes.size(); });
    par::for_each(plain_sections.size(), [&](size_t k) {
        SectionWork& w = work[plain_sections[k]];
        const progress::Activity doing(w.file);
        w.decoded = decode_component(w.bytes, w.file, /*strip_mtk=*/false);
        write_file(dir / w.file, w.decoded.plain);
        write_file(dir / ".abr_raw" / (w.file + ".raw"), w.bytes);
        progress::advance(w.bytes.size());
    });

    // The logo tables: the pictures of each are decoded together (the pixel format is one for a table), then written.
    for (size_t i = 0; i < count; ++i) {
        SectionWork& w = work[i];
        if (!w.logo) continue;
        const progress::Activity doing(w.file + "/");
        w.pictures = analyse_mtk_logo(w.logo->pictures, /*with_hash=*/true);
        fs::create_directories(dir / w.file);
        fs::create_directories(dir / ".abr_raw" / w.file);
        const size_t n = w.pictures.pictures.size();
        w.picture_files.resize(n);
        par::for_each(n, [&](size_t k) {
            MtkPicture& pic = w.pictures.pictures[k];
            const bool is_png = pic.size.has_value();
            w.picture_files[k] = mtk_picture_file_name(w.file, k, n, is_png);
            if (is_png) {
                png::Image img;
                img.width = pic.size->width;
                img.height = pic.size->height;
                img.rgba = mtkimg::pixels_to_rgba(w.pictures.format, pic.plain, img.width, img.height);
                write_file(dir / w.picture_files[k], png::encode(img, /*with_alpha=*/!pic.alpha.has_value() && mtkimg::bytes_per_pixel(w.pictures.format) == 4));
            } else {
                write_file(dir / w.picture_files[k], pic.plain);
            }
            write_file(dir / ".abr_raw" / (w.picture_files[k] + ".raw"), pic.stored);
            progress::advance(pic.stored.size());
        });
    }

    // The manifest, in the order of the sections.
    size_t pictures = 0, opaque_pictures = 0;
    for (size_t i = 0; i < count; ++i) {
        const mtkimg::Span& s = spans[i];
        SectionWork& w = work[i];
        const std::string p = mtk_section_prefix(i);
        save_mtk_header(m, p, s.header);
        save_mtk_padding(m, p, s, data);
        if (w.logo) {
            const size_t n = w.pictures.pictures.size();
            m.set_bool(p + "_logo", true);
            m.set_u32(p + "_logo_count", static_cast<uint32_t>(n));
            m.set(p + "_logo_format", std::string(mtkimg::format_name(w.pictures.format)));
            for (size_t k = 0; k < n; ++k) {
                const MtkPicture& pic = w.pictures.pictures[k];
                DecodedComponent d;
                d.present = true;
                d.codec = pic.codec;
                d.level = pic.level;
                d.level_basis = pic.level_basis;
                d.plain_hash = pic.plain_hash;
                const std::string pp = mtk_picture_prefix(i, k);
                record_component(m, pp, w.picture_files[k], d);
                if (pic.size) {
                    m.set_u32(pp + "_width", pic.size->width);
                    m.set_u32(pp + "_height", pic.size->height);
                    if (pic.alpha) m.set_u32(pp + "_alpha", *pic.alpha);
                } else {
                    ++opaque_pictures;
                }
                ++pictures;
            }
        } else if (w.decoded.present) {
            record_component(m, p, w.file, w.decoded);
        }
    }

    const Envelope env = Envelope::capture(data, 0, consumed);
    save_envelope(m, dir, env, data, 0, consumed);
    if (!env.tail.empty()) note(std::to_string(env.tail.size()) + " bytes after the last section are kept verbatim (tail.bin)");

    std::cout << "sections: " << count << (pictures ? ", pictures: " + std::to_string(pictures) : std::string()) << "\n";
    for (size_t i = 0; i < count; ++i) {
        const SectionWork& w = work[i];
        std::string what;
        if (w.logo) what = "table of " + std::to_string(w.pictures.pictures.size()) + " pictures, " + std::string(mtkimg::format_name(w.pictures.format)) + " -> " + w.file + "/";
        else if (w.decoded.present) what = (w.decoded.codec == Codec::NONE ? std::string("plain") : std::string(codec_name(w.decoded.codec)) + " stream taken off") + " -> " + w.file;
        else what = "no data";
        std::cout << "  [" << i << "] " << shown(spans[i].header.name_text()) << ": " << spans[i].data_size << " bytes at 0x" << std::hex << spans[i].data_at << std::dec
                  << ", " << what << "\n";
    }
    for (size_t i = 0; i < count; ++i)
        for (size_t k = 0; k < work[i].pictures.pictures.size(); ++k)
            if (!work[i].pictures.pictures[k].problem.empty())
                warn("picture " + std::to_string(k) + " of section " + std::to_string(i) + " starts like a zlib stream but cannot be unpacked (" +
                     work[i].pictures.pictures[k].problem + "): it is kept as the bytes it is");
    if (opaque_pictures)
        note(std::to_string(opaque_pictures) + " picture(s) are no size that abr knows (or no pixels at all): they stay files of their bytes as they are (img-NNN.bin)");

    m.save(dir / "manifest.txt",
           "abr mtk_image manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`\n"
           "# NOTE: a section's file holds its data with the compression taken off (section<i>_compression, _level say what it was; pack makes the\n"
           "# stream again). A table of pictures (the logo) is a folder of PNG files; section<i>_logo_format is how their pixels are stored, and the\n"
           "# size of a picture is what abr guessed from its pixel count -- the PNG is as many pixels as the bootloader draws, keep its size.");
}

// ---- pack

// One picture of a logo table, made from its file: the stream of the table. The pixels of a PNG are stored in `format`.
Bytes load_mtk_picture(const Manifest& m, const fs::path& dir, const std::string& p, mtkimg::PixelFormat format, const RepackOptions& opt) {
    if (!m.has(p + "_file")) throw FormatError("manifest.txt: " + shown(p + "_file") + " is missing (the file of the picture)");
    const std::string filename = m.get_path(p + "_file");
    const progress::Activity doing(filename);
    const Bytes disk = read_file(dir / filename);
    Bytes pixels;
    if (m.has(p + "_width")) {
        png::Image img;
        try {
            img = png::decode(disk);
        } catch (const FormatError& e) {
            throw FormatError(shown(filename) + ": " + e.what());
        }
        const uint32_t want_w = m.get_u32(p + "_width", 0), want_h = m.get_u32(p + "_height", 0);
        if (img.width != want_w || img.height != want_h)
            warn(shown(filename) + " is " + std::to_string(img.width) + "x" + std::to_string(img.height) + " pixels, it was " + std::to_string(want_w) + "x" +
                 std::to_string(want_h) + ": the bootloader draws the pixels as the size it knows, a picture of another size comes out skewed or does not show");
        pixels = mtkimg::rgba_to_pixels(format, img.rgba, img.width, img.height, img.has_alpha, static_cast<uint8_t>(m.get_bounded(p + "_alpha", 255, 8)));
    } else {
        pixels = disk;
    }
    const std::string codec_text = m.get(p + "_compression", "zlib");
    const std::optional<Codec> named = codec_from_name(codec_text);
    if (!named || (*named != Codec::ZLIB && *named != Codec::NONE))
        throw FormatError("manifest.txt: " + shown(p + "_compression=" + codec_text) + " is none of the compressions of a picture of a logo table (zlib, none)");
    const Bytes hash = hash::sha256(pixels);
    const fs::path raw_path = dir / ".abr_raw" / (filename + ".raw");
    const Bytes stored_hash = m.get_hex(p + "_orig_hash");
    if (!stored_hash.empty() && hash == stored_hash && fs::exists(raw_path)) {
        Bytes raw = read_file(raw_path);  // the pixels are what they were: the very bytes the table had
        std::string why;
        try {
            const Bytes plain = *named == Codec::ZLIB ? decompress(Codec::ZLIB, raw) : raw;
            if (hash::sha256(plain) == stored_hash) {
                progress::advance(disk.size());
                return raw;
            }
            why = "it does not decompress to the pixels of " + filename + " as it was unpacked";
        } catch (const std::exception& e) {
            why = std::string("it does not decompress (") + e.what() + ")";
        }
        throw FormatError(shown(raw_path.generic_string()) + " does not belong to " + shown(filename) + ": " + why + ". Delete it to have " + shown(filename) +
                          " compressed again, or unpack the image again");
    }
    int level = static_cast<int>(m.get_int(p + "_level", -1, -1, 22));
    const int dense = dense_level(*named);
    if (dense >= 0 && (level >= 0 ? level : default_level(*named)) < dense) {
        if (opt.dense) level = dense;
        else g_denser_would_help = true;
    }
    Bytes out = compress(*named, pixels, level, [](size_t n) { progress::advance(n); });
    return out;
}

Bytes repack_mtk_image(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    const size_t count = m.get_count("sections", 0);
    if (count == 0) throw FormatError("manifest.txt: sections= is missing or 0 (the number of the sections of the image)");

    struct Job {
        size_t section;
        long picture;  // -1: the whole section
        uintmax_t size;
    };
    std::vector<Job> jobs;
    std::vector<bool> is_logo(count, false);
    std::vector<mtkimg::PixelFormat> formats(count, mtkimg::PixelFormat::BGRA8888);
    std::vector<size_t> pictures(count, 0);
    for (size_t i = 0; i < count; ++i) {
        const std::string p = mtk_section_prefix(i);
        const auto size_of = [&](const std::string& key) -> uintmax_t {
            std::error_code ec;
            if (!m.has(key)) return 0;
            const auto n = fs::file_size(dir / m.get_path(key), ec);
            return ec ? 0 : n;
        };
        if (m.get_bool(p + "_logo", false)) {
            is_logo[i] = true;
            const std::string format_name = m.get(p + "_logo_format", "bgra8888");
            const std::optional<mtkimg::PixelFormat> format = mtkimg::format_from_name(format_name);
            if (!format)
                throw FormatError("manifest.txt: " + shown(p + "_logo_format=" + format_name) +
                                  " is none of the pixel formats abr knows (bgra8888, rgba8888, rgb565, bgr888, rgb888)");
            formats[i] = *format;
            pictures[i] = m.get_count(p + "_logo_count", 0);
            if (pictures[i] == 0 || pictures[i] > 4096) throw FormatError("manifest.txt: " + shown(p + "_logo_count") + " is the number of the pictures of the table, 1 to 4096");
            for (size_t k = 0; k < pictures[i]; ++k) jobs.push_back({i, static_cast<long>(k), size_of(mtk_picture_prefix(i, k) + "_file")});
        } else {
            jobs.push_back({i, -1, size_of(p + "_file")});
        }
    }
    std::stable_sort(jobs.begin(), jobs.end(), [](const Job& a, const Job& b) { return a.size > b.size; });

    std::vector<Bytes> data(count);
    std::vector<std::vector<Bytes>> streams(count);
    for (size_t i = 0; i < count; ++i) streams[i].resize(pictures[i]);
    par::for_each(jobs.size(), [&](size_t j) {
        const Job& job = jobs[j];
        if (job.picture < 0) data[job.section] = load_component(m, dir, mtk_section_prefix(job.section), opt);
        else streams[job.section][static_cast<size_t>(job.picture)] = load_mtk_picture(m, dir, mtk_picture_prefix(job.section, static_cast<size_t>(job.picture)), formats[job.section], opt);
    });

    mtkimg::Chain chain;
    uint64_t at = 0;
    for (size_t i = 0; i < count; ++i) {
        const std::string p = mtk_section_prefix(i);
        mtkimg::Section s;
        s.header = load_mtk_header(m, p, i + 1 == count);
        s.data = is_logo[i] ? mtkimg::build_logo(streams[i]) : std::move(data[i]);
        s.align = s.header.alignment();
        at += mtkimg::kHeaderSize + s.data.size();
        if (i + 1 < count) {
            s.pad = load_mtk_padding(m, p, at, s.align);
            at += s.pad.size();
        }
        chain.sections.push_back(std::move(s));
    }
    chain.consumed = static_cast<size_t>(at);
    return assemble_envelope(m, dir, mtkimg::build(chain), opt);
}

// ---- info

void print_mtk_image_info(const Bytes& data) {
    size_t consumed = 0;
    const std::vector<mtkimg::Span> spans = mtkimg::scan(data, &consumed);
    std::cout << "sections:       " << spans.size() << "\n";
    for (size_t i = 0; i < spans.size(); ++i) {
        const mtkimg::Span& s = spans[i];
        const mtkimg::Header& h = s.header;
        char line[256];
        std::snprintf(line, sizeof line, "load address 0x%x, mode 0x%x", h.maddr, h.mode);
        std::cout << "  [" << i << "] " << shown(h.name_text()) << ": " << s.data_size << " bytes at 0x" << std::hex << s.data_at << std::dec << ", " << line;
        if (h.extended()) {
            std::cout << ", type " << h.img_type << ", header version " << h.hdr_version << ", " << (h.img_list_end == 1 ? "last of the list" : "list goes on");
            std::cout << ", alignment " << h.align_size << (h.alignment() != h.align_size ? " (taken as " + std::to_string(h.alignment()) + ")" : std::string());
        } else {
            std::cout << ", the older kind of header (no extension)";
        }
        if (s.pad_size) std::cout << ", " << s.pad_size << " bytes of padding to the next (alignment " << s.align << ")";
        if (!h.name_tail().empty()) std::cout << ", " << h.name_tail().size() << " bytes behind the name (kept)";
        std::cout << "\n";
        if (s.data_size == 0) continue;
        const Bytes bytes(data.begin() + static_cast<std::ptrdiff_t>(s.data_at), data.begin() + static_cast<std::ptrdiff_t>(s.data_at + s.data_size));
        if (const std::optional<mtkimg::Logo> logo = mtkimg::parse_logo(bytes)) {
            const MtkLogo pictures = analyse_mtk_logo(logo->pictures, /*with_hash=*/false);
            std::cout << "      table of " << pictures.pictures.size() << " pictures, pixel format " << mtkimg::format_name(pictures.format) << " (guessed from the sizes)\n";
            for (size_t k = 0; k < pictures.pictures.size(); ++k)
                std::cout << "        picture " << k << ": " << pictures.pictures[k].stored.size() << " bytes, " << mtk_picture_text(pictures.pictures[k], pictures.format) << "\n";
        } else {
            const Codec codec = detect_codec(bytes);
            std::cout << "      data: " << (codec == Codec::NONE ? std::string("not compressed") : std::string(codec_name(codec)));
            if (codec != Codec::NONE) {
                try {
                    const DecodedComponent d = decode_component(bytes, {}, /*strip_mtk=*/false);
                    std::cout << ", " << d.plain.size() << " bytes unpacked";
                    if (d.level >= 0) std::cout << ", level " << d.level;
                } catch (const FormatError& e) {
                    std::cout << " (cannot be decompressed: " << e.what() << ")";
                }
            }
            std::cout << "\n";
        }
    }
    print_envelope_info(Envelope::capture(data, 0, consumed));
}

// ------------------------------------------------------- mtk_preloader --
//
// The loader that the boot ROM of a MediaTek chip runs from the boot partition (abr/mtkgfh.hpp): a chain of GFH headers, the loader's code and a
// signature, and in an image of the partition a device header and a BRLYT in front of it. `unpack` writes
//   device.bin     the device header and the BRLYT (what is in front of the chain; only when there is any),
//   headers.bin    the GFH headers behind FILE_INFO (BL_INFO, BROM_CFG, ANTI_CLONE, ...) and the bytes of padding behind them, as they lie in the image,
//   loader.bin     the loader's code, with a compression taken off if it has one,
//   signature.bin  the signature, unless it is the SHA-256 that `pack` makes again,
// and what FILE_INFO holds that is not a size goes into the manifest. `pack` works out the sizes (those of FILE_INFO and of the BRLYT) and the SHA-256
// again from what is in the folder. A signature of another kind cannot be made again: it is kept as it is, and a warning says when what it was made
// for has changed.

constexpr size_t kPreloaderSector = 0x200;  // the images of a partition that were looked at are a multiple of it

std::string hex_text(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

// The byte that fills an image of a partition up to a multiple of kPreloaderSector behind the signature -- or nothing, when what is behind the loader is
// not that (a file of another size, other bytes in it, a file that is not an image of a partition at all).
std::optional<uint8_t> preloader_round_fill(const mtkgfh::Image& img, const Bytes& data) {
    if (!img.device || data.size() % kPreloaderSector != 0 || data.size() - img.consumed >= kPreloaderSector) return std::nullopt;
    const uint8_t fill = data.size() > img.consumed ? data[img.consumed] : 0xFF;
    for (size_t i = img.consumed; i < data.size(); ++i)
        if (data[i] != fill) return std::nullopt;
    return fill;
}

std::string preloader_basis_text(const mtkgfh::Device& v, mtkgfh::SizeBasis basis) {
    switch (basis) {
        case mtkgfh::SizeBasis::File: return "the size of the file, " + hex_text(v.total_size);
        case mtkgfh::SizeBasis::Chain: return "the end of the loader, " + hex_text(v.total_size);
        default: return hex_text(v.total_size) + ", kept as it is";
    }
}

// ---- unpack

void unpack_mtk_preloader(const Bytes& data, const fs::path& dir) {
    const mtkgfh::Image img = mtkgfh::parse(data);
    const mtkgfh::FileInfo fi = mtkgfh::read_file_info(img.chain[0]);
    Manifest m;
    m.set("type", "mtk_preloader");
    m.set_u32("file_info_version", fi.version);
    m.set_tail("file_info_name_tail", fi.name_tail());
    m.set_u32("file_ver", fi.file_ver);
    m.set_u32("file_type", fi.file_type);
    m.set_u32("flash_type", fi.flash_type);
    m.set_u32("sig_type", fi.sig_type);
    m.set_addr("load_addr", fi.load_addr);
    m.set_addr("max_size", fi.max_size);
    m.set_addr("jump_offset", fi.jump_offset);
    m.set_addr("processed", fi.processed);
    if (!fi.extra.empty()) m.set_hex("file_info_extra", fi.extra);

    // What is in front of the chain, and what is behind FILE_INFO.
    save_raw(m, dir, "device", img.prefix, "device.bin");
    if (img.device) m.set("brlyt_basis", mtkgfh::size_basis_name(img.basis));
    Bytes headers = mtkgfh::serialize_headers(img.chain, 1);
    headers.insert(headers.end(), img.chain_pad.begin(), img.chain_pad.end());
    save_raw(m, dir, "headers", headers, "headers.bin");

    // The loader's code: a compression on it is taken off, like that of any component.
    DecodedComponent loader;
    if (!img.payload.empty()) {
        progress::enter("decode", img.payload.size());
        const progress::Activity doing("loader.bin");
        fs::create_directories(dir / ".abr_raw");
        loader = decode_component(img.payload, "loader.bin", /*strip_mtk=*/false);
        write_file(dir / "loader.bin", loader.plain);
        write_file(dir / ".abr_raw" / "loader.bin.raw", loader.stored(img.payload));
        progress::advance(img.payload.size());
        record_component(m, "loader", "loader.bin", loader);
    }

    // The signature: the SHA-256 is made again by pack; any other is kept, with a hash of what it follows, to tell a changed image from an unchanged one.
    const size_t sig_at = img.consumed - img.signature.size();
    if (img.sha256_trailer) {
        m.set("signature", "sha256");
    } else if (!img.signature.empty()) {
        save_raw(m, dir, "signature", img.signature, "signature.bin");
        m.set_hex("signed_sha256", hash::sha256(data.data() + img.at(), sig_at - img.at()));
    }

    // The fill behind the signature of an image of a partition (a multiple of 0x200) is made again when the loader changes its size: its byte and
    // the multiple are in the manifest. Any other bytes behind the image are kept as the envelope keeps them.
    Envelope env = Envelope::capture(data, 0, img.consumed);
    if (const std::optional<uint8_t> fill = preloader_round_fill(img, data)) {
        env.tail.clear();
        env.pad_to = 0;
        m.set_addr("file_align", static_cast<uint32_t>(kPreloaderSector));
        m.set_addr("pad_byte", *fill);
    }
    save_envelope(m, dir, env, data, 0, img.consumed);
    if (!env.tail.empty()) note(std::to_string(env.tail.size()) + " bytes after the signature are kept verbatim (tail.bin)");

    // What was done, with the offsets and the sizes.
    std::cout << "FILE_INFO: load address " << hex_text(fi.load_addr) << ", code at " << hex_text(uint64_t{fi.load_addr} + fi.jump_offset) << ", flash type "
              << unsigned{fi.flash_type} << " (" << mtkgfh::flash_type_name(fi.flash_type) << "), signature " << mtkgfh::sig_type_name(fi.sig_type) << "\n";
    if (img.device) {
        const mtkgfh::Device& v = *img.device;
        std::cout << "  [device header and BRLYT] " << img.prefix.size() << " bytes at 0x0, " << v.boot_name << ", BRLYT " << mtkgfh::brlyt_type_name(v.type)
                  << " -> device.bin\n";
    }
    std::cout << "  [FILE_INFO] " << img.chain[0].size() << " bytes at " << hex_text(img.at()) << "\n";
    if (img.chain.size() > 1 || !img.chain_pad.empty()) {
        std::string names;
        for (size_t i = 1; i < img.chain.size(); ++i) names += (names.empty() ? "" : ", ") + mtkgfh::type_name(img.chain[i].type);
        std::cout << "  [headers] " << (img.chain.size() - 1) << " behind FILE_INFO (" << names << (img.chain_pad.empty() ? "" : "; " + std::to_string(img.chain_pad.size()) + " bytes of padding")
                  << "), " << headers.size() << " bytes at " << hex_text(img.at() + img.chain[0].size()) << " -> headers.bin\n";
    }
    if (loader.present) {
        std::cout << "  [loader] " << img.payload.size() << " bytes at " << hex_text(img.at() + fi.hdr_size) << ", "
                  << (loader.codec == Codec::NONE ? std::string("not compressed") : std::string(codec_name(loader.codec)) + " stream taken off") << " -> loader.bin\n";
        if (const std::optional<mtkgfh::Marker> mark = mtkgfh::find_bloader_marker(img.payload))
            std::cout << "           " << mark->text << " at " << hex_text(img.at() + fi.hdr_size + mark->offset) << "\n";
    }
    if (!img.signature.empty())
        std::cout << "  [signature] " << img.signature.size() << " bytes at " << hex_text(sig_at) << ", " << mtkgfh::sig_type_name(fi.sig_type)
                  << (img.sha256_trailer ? ", the SHA-256 of the image from the first header (made again by pack)" : ", kept as it is (signature.bin)") << "\n";
    if (!img.sha256_trailer && !img.signature.empty())
        note(std::string("the signature is ") + (fi.sig_type == mtkgfh::kSigSha256 ? "not the SHA-256 of the image (it is kept as it is)" : "of a kind that abr cannot make again") +
             ": a loader that is edited no longer matches it");
    if (fi.max_size && fi.total_size > fi.max_size)
        warn("the image is " + std::to_string(fi.total_size) + " bytes, more than the max_size that FILE_INFO gives (" + hex_text(fi.max_size) + ")");

    m.save(dir / "manifest.txt",
           "abr mtk_preloader manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`\n"
           "# NOTE: FILE_INFO's sizes (hdr_size, total_size, sig_size) and the sizes in the BRLYT are worked out by pack, from the files. The code that starts\n"
           "# at load_addr + jump_offset is loader.bin. headers.bin holds the GFH headers behind FILE_INFO as they are in the image (each: \"MMM\" and its\n"
           "# version, its size, its type, its body). signature=sha256 is made again by pack; signature.bin (any other signature) is kept as it is.");
}

// ---- pack

Bytes repack_mtk_preloader(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    const auto need = [&](const char* key) -> uint32_t {
        if (!m.has(key)) throw FormatError(std::string("manifest.txt: ") + shown(key) + " is missing (a number of FILE_INFO)");
        return m.get_addr32(key, 0);
    };

    mtkgfh::Image img;
    img.prefix = load_raw(m, dir, "device");
    if (!img.prefix.empty()) {
        img.device = mtkgfh::parse_device(img.prefix);
        if (!img.device)
            throw FormatError("device.bin is not the device header and the BRLYT of a boot medium (EMMC_BOOT, SF_BOOT or SDMMC_BOOT, 0x200 bytes, then \"BRLYT\")");
        if (img.device->header_size != img.prefix.size())
            throw FormatError("device.bin is " + std::to_string(img.prefix.size()) + " bytes, and its BRLYT says that the headers begin at " + hex_text(img.device->header_size) +
                              " (the BRLYT is at 0x200: header_size, then total_size)");
        const std::string basis = m.get("brlyt_basis", "literal");
        const std::optional<mtkgfh::SizeBasis> b = mtkgfh::size_basis_from_name(basis);
        if (!b) throw FormatError("manifest.txt: " + shown("brlyt_basis=" + basis) + " is none of file, chain, literal");
        img.basis = *b;
    }

    mtkgfh::FileInfo fi;
    fi.version = static_cast<uint8_t>(m.get_bounded("file_info_version", 1, 8));
    const std::string name = "FILE_INFO";
    const Bytes tail = m.get_tail("file_info_name_tail");
    if (name.size() + 1 + tail.size() > fi.name.size())
        throw FormatError("manifest.txt: " + shown("file_info_name_tail") + " is " + std::to_string(tail.size()) + " bytes; the name field holds 12, and FILE_INFO and its zero take 10");
    std::copy(name.begin(), name.end(), fi.name.begin());
    std::copy(tail.begin(), tail.end(), fi.name.begin() + static_cast<std::ptrdiff_t>(name.size() + 1));
    fi.file_ver = m.get_u32("file_ver", 1);
    fi.file_type = static_cast<uint16_t>(m.get_bounded("file_type", 1, 16));
    fi.flash_type = static_cast<uint8_t>(m.get_bounded("flash_type", 5, 8));
    fi.sig_type = static_cast<uint8_t>(m.get_bounded("sig_type", 0, 8));
    fi.load_addr = need("load_addr");
    fi.max_size = need("max_size");
    fi.jump_offset = need("jump_offset");
    fi.processed = m.get_addr32("processed", 0);
    if (m.has("file_info_extra")) fi.extra = m.get_hex("file_info_extra");

    const Bytes headers = load_raw(m, dir, "headers");
    img.chain.push_back(mtkgfh::write_file_info(fi));
    for (mtkgfh::Header& h : mtkgfh::split_headers(headers, 0, headers.size(), &img.chain_pad)) img.chain.push_back(std::move(h));

    bool replayed = false;
    img.payload = load_component(m, dir, "loader", opt, &replayed);

    const std::string signature = m.get("signature", "");
    if (signature == "sha256") {
        if (fi.sig_type != mtkgfh::kSigSha256) throw FormatError("manifest.txt: signature=sha256 is the signature of sig_type=1, and sig_type is " + std::to_string(fi.sig_type));
        img.sha256_trailer = true;
    } else if (!signature.empty()) {
        throw FormatError("manifest.txt: " + shown("signature=" + signature) + " is not sha256 (the one signature that abr makes; any other is the file signature.bin, signature_file=)");
    } else {
        img.signature = load_raw(m, dir, "signature");
    }

    Bytes core = mtkgfh::build(img);
    const uint64_t total = core.size() - img.at();
    if (!img.sha256_trailer && !img.signature.empty() && m.has("signed_sha256")) {
        const size_t from = img.at(), to = core.size() - img.signature.size();
        if (hash::sha256(core.data() + from, to - from) != m.get_hex("signed_sha256"))
            warn("the image is not the one that the signature (" + mtkgfh::sig_type_name(fi.sig_type) + ", " + std::to_string(img.signature.size()) +
                 " bytes, signature.bin) came with: it is kept as it is, abr cannot make it again, and a boot ROM that checks it will not accept this image");
    }
    if (fi.max_size && total > fi.max_size)
        warn("the image is " + std::to_string(total) + " bytes, more than the max_size of FILE_INFO (" + hex_text(fi.max_size) + "); raise max_size in manifest.txt if that is meant");

    Bytes out = assemble_envelope(m, dir, core, opt);
    const uint64_t align = m.get_int("file_align", 1, 1, 1 << 20);
    if (align > 1 && out.size() % align != 0) out.resize(static_cast<size_t>((out.size() + align - 1) / align * align), static_cast<uint8_t>(m.get_bounded("pad_byte", 0xFF, 8)));
    mtkgfh::fix_device(out, img);
    return out;
}

// ---- info

void print_mtk_preloader_info(const Bytes& data) {
    const mtkgfh::Image img = mtkgfh::parse(data);
    const mtkgfh::FileInfo fi = mtkgfh::read_file_info(img.chain[0]);
    if (img.device) {
        const mtkgfh::Device& v = *img.device;
        std::cout << "device header:  " << v.boot_name << ", version " << v.boot_version << ", " << v.boot_size << " bytes\n";
        std::cout << "BRLYT:          " << mtkgfh::brlyt_type_name(v.type) << ", version " << v.version << ", the headers begin at " << hex_text(v.header_size) << ", size "
                  << preloader_basis_text(v, img.basis) << "\n";
    }
    std::cout << "FILE_INFO:      " << shown(fi.name_text()) << ", header version " << unsigned{fi.version} << ", file version " << fi.file_ver << ", file type " << fi.file_type
              << ", flash type " << unsigned{fi.flash_type} << " (" << mtkgfh::flash_type_name(fi.flash_type) << "), processed " << hex_text(fi.processed) << "\n";
    std::cout << "load address:   " << hex_text(fi.load_addr) << ", jump offset " << hex_text(fi.jump_offset) << ": the code is at " << hex_text(uint64_t{fi.load_addr} + fi.jump_offset) << "\n";
    std::cout << "sizes:          headers " << fi.hdr_size << ", loader " << img.payload.size() << ", signature " << fi.sig_size << ", total " << fi.total_size << " bytes (max_size "
              << hex_text(fi.max_size) << (fi.max_size && fi.total_size > fi.max_size ? ": EXCEEDED" : "") << ")\n";
    std::cout << "signature:      " << mtkgfh::sig_type_name(fi.sig_type);
    if (img.sha256_trailer) std::cout << ", the SHA-256 of the image from the first header (pack makes it again)";
    else if (fi.sig_size) std::cout << ", " << fi.sig_size << " bytes, kept as it is (abr cannot make it again)";
    std::cout << "\n";
    std::cout << "headers:        " << img.chain.size() << (img.chain_pad.empty() ? std::string() : " and " + std::to_string(img.chain_pad.size()) + " bytes of padding") << "\n";
    uint64_t at = img.at();
    for (size_t i = 0; i < img.chain.size(); ++i) {
        const mtkgfh::Header& h = img.chain[i];
        std::cout << "  [" << i << "] " << mtkgfh::type_name(h.type) << " at " << hex_text(at) << ", " << h.size() << " bytes, version " << unsigned{h.version};
        if (const std::string what = i > 0 ? mtkgfh::describe(h) : std::string(); !what.empty()) std::cout << ": " << what;
        std::cout << "\n";
        at += h.size();
    }
    if (!img.payload.empty()) {
        std::cout << "loader:         " << img.payload.size() << " bytes at " << hex_text(img.at() + fi.hdr_size);
        const Codec codec = detect_codec(img.payload);
        std::cout << ", " << (codec == Codec::NONE ? std::string("not compressed") : std::string(codec_name(codec))) << "\n";
        if (const std::optional<mtkgfh::Marker> mark = mtkgfh::find_bloader_marker(img.payload))
            std::cout << "                " << mark->text << " at " << hex_text(img.at() + fi.hdr_size + mark->offset) << "\n";
    }
    print_envelope_info(Envelope::capture(data, 0, img.consumed));
}

// ------------------------------------------------------------------ mbn --
//
// The images of Qualcomm's secure boot (abr/mbn.hpp): sbl1/xbl, tz, hyp, rpm, aboot/appsboot, devcfg, keymaster and the like. One structure -- a header and what
// hangs on it: metadata, code, signature, certificate chain -- in one of two containers.
//
//   type=mbn      the file is the structure (aboot/appsboot, the SBL1 of older chips). `unpack` writes
//                   code.bin                              the code, with a compression taken off if it has one,
//                   metadata*.bin, signature*.bin, cert_chain*.bin    the other parts (QTI's and the OEM's; only those the image has),
//                 and the words of the header that are not sizes into the manifest. `pack` works out the sizes, image_size and -- where they were address
//                 plus size -- the addresses of the signature and the chain again, from the files.
//   type=mbn_elf  the file is an ELF whose program headers describe the segments of the firmware, one of them the hash segment, which holds the structure
//                 and whose code is a table of the hashes of the segments. `unpack` writes seg<N>.bin, the data of program header N (a compression on it taken
//                 off), the parts of the structure as above, and into the manifest the ELF header and every program header. `pack` writes the ELF again
//                 (the layout that Qualcomm's tools make; an ELF that is laid out in another way is kept as skeleton.bin) and makes the table of hashes
//                 again.
// A signature and a certificate chain cannot be made again: they are kept as they are, and a warning says when what they were made for has changed.

// The parts of the structure that follow the header and are files of their own (the code is a component, and in an ELF the table of hashes is made again).
struct MbnPart {
    const char* prefix;  // the prefix of its keys and the stem of its file: signature -> signature_file=signature.bin
    Bytes mbn::Block::*member;
    const char* what;
};
const MbnPart kMbnParts[] = {
    {"metadata_qti", &mbn::Block::metadata_qti, "QTI metadata"},
    {"metadata", &mbn::Block::metadata, "metadata"},
    {"signature_qti", &mbn::Block::sig_qti, "QTI signature"},
    {"cert_chain_qti", &mbn::Block::cert_qti, "QTI certificate chain"},
    {"signature", &mbn::Block::sig, "signature"},
    {"cert_chain", &mbn::Block::cert, "certificate chain"},
};

// "header version 3 (40 bytes), image id 5 (APPSBL)".
std::string mbn_block_text(const mbn::Block& b) {
    std::string s = mbn::describe_header(b);
    if (b.has_word("image_id")) {
        const uint32_t id = b.word("image_id");
        const std::string name = mbn::image_id_name(id);
        s += ", image id " + std::to_string(id) + (name.empty() ? std::string() : " (" + name + ")");
    }
    return s;
}

// What of the header is written to the manifest: the version, the words that nothing derives, how the addresses of the signature and the chain were made,
// the rounding; and the parts as files. The sizes are not: pack works them out.
void save_mbn_block(Manifest& m, const fs::path& dir, const mbn::Block& b) {
    if (b.kind == mbn::Kind::Sbl) m.set("header_kind", "sbl");
    else m.set_u32("header_version", b.version);
    for (const mbn::Field& f : mbn::fields(b.kind, b.version))
        if (f.use == mbn::Field::Use::Keep) m.set_addr(f.name, b.w[f.index]);
    if (b.has_word("sig_ptr")) {
        if (b.derived_ptrs) {
            m.set("ptrs", "derived");
            m.set_addr("ptr_base", b.ptr_base);
        } else {
            m.set("ptrs", "literal");
            m.set_addr("sig_ptr", b.word("sig_ptr"));
            m.set_addr("cert_ptr", b.word("cert_ptr"));
        }
    }
    if (b.has_word("image_size")) m.set_bool("align4", b.align4);
    if (!b.slack.empty()) m.set_hex("slack", b.slack);
    for (const MbnPart& p : kMbnParts) save_raw(m, dir, p.prefix, b.*p.member, std::string(p.prefix) + ".bin");
}

// The structure of the manifest, without the code (the caller loads that).
mbn::Block load_mbn_block(const Manifest& m, const fs::path& dir) {
    const std::string kind = m.get("header_kind", "boot");
    if (kind != "boot" && kind != "sbl") throw FormatError("manifest.txt: " + shown("header_kind=" + kind) + " is neither boot nor sbl");
    const mbn::Kind k = kind == "sbl" ? mbn::Kind::Sbl : mbn::Kind::Boot;
    uint32_t version = 0;
    if (k == mbn::Kind::Boot) {
        if (!m.has("header_version")) throw FormatError("manifest.txt: header_version is missing (3, 5, 6 or 7)");
        version = m.get_u32("header_version", 0);
        if (mbn::header_size(k, version) == 0) throw FormatError("manifest.txt: " + shown("header_version=" + m.get("header_version")) + " is none of 3, 5, 6, 7");
    }
    mbn::Block b = mbn::make_block(k, version);
    for (const mbn::Field& f : mbn::fields(b.kind, b.version))
        if (f.use == mbn::Field::Use::Keep && m.has(f.name)) b.w[f.index] = m.get_addr32(f.name, b.w[f.index]);
    if (b.has_word("sig_ptr")) {
        const std::string ptrs = m.get("ptrs", "literal");
        if (ptrs == "derived") {
            b.derived_ptrs = true;
            b.ptr_base = m.get_addr32("ptr_base", 0);
        } else if (ptrs == "literal") {
            b.set_word("sig_ptr", m.get_addr32("sig_ptr", 0));
            b.set_word("cert_ptr", m.get_addr32("cert_ptr", 0));
        } else {
            throw FormatError("manifest.txt: " + shown("ptrs=" + ptrs) + " is neither derived nor literal");
        }
    }
    if (b.has_word("image_size")) b.align4 = m.get_bool("align4", false);
    b.slack = m.get_hex("slack");
    for (const MbnPart& p : kMbnParts) b.*p.member = load_raw(m, dir, p.prefix);
    return b;
}

// SHA-256 of the signature and the certificate chains (QTI's and the OEM's), to tell at pack whether they are the ones the image came with.
Bytes mbn_signature_parts_hash(const mbn::Block& b) {
    hash::Sha256 h;
    for (const Bytes* part : {&b.sig_qti, &b.cert_qti, &b.sig, &b.cert})
        if (!part->empty()) h.update(part->data(), part->size());
    return h.finish();
}

size_t mbn_signature_bytes(const mbn::Block& b) { return b.sig_qti.size() + b.cert_qti.size() + b.sig.size() + b.cert.size(); }

// An image that was changed is no longer the one that its signature and its certificate chain were made for, and abr cannot make them again. Said
// unless the files of the signature were put there by somebody (they are not the ones the image came with).
void warn_stale_signature(const Manifest& m, const Bytes& core, const mbn::Block& b) {
    const size_t n = mbn_signature_bytes(b);
    if (n == 0 || !core_changed(m, core)) return;
    if (m.has("signature_parts_sha256") && mbn_signature_parts_hash(b) != m.get_hex("signature_parts_sha256")) return;
    warn("the image was changed, and its signature and certificate chain (" + std::to_string(n) + " bytes) are kept as they were: abr cannot sign, and a loader that checks "
         "the signature will not accept an image that is not the one it was made for");
}

// What `unpack` records of the image's own bytes: what is kept around the structure, a hash of the structure (to tell a changed image from an untouched
// one) and of the signature (to tell whether it was replaced).
void save_mbn_envelope(Manifest& m, const fs::path& dir, const Bytes& data, size_t consumed, const mbn::Block& b) {
    const Envelope env = Envelope::capture(data, 0, consumed);
    save_envelope(m, dir, env, data, 0, consumed);
    if (!env.tail.empty()) note(std::to_string(env.tail.size()) + " bytes after the image are kept verbatim (tail.bin)");
    m.set_hex("core_sha256", hash::sha256(data.data(), consumed));
    if (mbn_signature_bytes(b)) m.set_hex("signature_parts_sha256", mbn_signature_parts_hash(b));
}

// "code 350880, QTI signature 256, certificate chain 2764".
std::string mbn_sizes_text(const mbn::Block& b, const char* code_what) {
    std::string s = std::string(code_what) + " " + std::to_string(b.code.size());
    for (const MbnPart& p : kMbnParts)
        if (!(b.*p.member).empty()) s += std::string(", ") + p.what + " " + std::to_string((b.*p.member).size());
    return s;
}

// The certificates of a chain, one line each: the subject, and what the subject says of the image in the words of Qualcomm's documents (SW_ID, HW_ID, ...).
void print_mbn_chain(const std::string& label, const Bytes& chain) {
    if (chain.empty()) return;
    size_t rest = 0;
    const std::vector<mbn::Cert> certs = mbn::read_chain(chain, &rest);
    std::cout << label << chain.size() << " bytes, " << certs.size() << (certs.size() == 1 ? " certificate" : " certificates")
              << (rest ? ", then " + std::to_string(rest) + " bytes of fill" : std::string()) << "\n";
    for (size_t i = 0; i < certs.size(); ++i) {
        std::cout << "    [" << i << "] " << shown(certs[i].subject) << "\n";
        std::string attributes;
        for (const std::string& ou : certs[i].attributes)
            if (const std::string t = mbn::attribute_text(ou); !t.empty()) attributes += (attributes.empty() ? "" : ", ") + t;
        if (!attributes.empty()) std::cout << "        " << attributes << "\n";
        if (certs[i].issuer != certs[i].subject) std::cout << "        issued by " << shown(certs[i].issuer) << "\n";
    }
}

// What `info` says of a structure -- the same for a flat file and for the hash segment of an ELF.
void print_mbn_block_info(const mbn::Block& b, const char* code_what) {
    std::cout << "header:         " << mbn_block_text(b) << "\n";
    std::string words;
    for (const mbn::Field& f : mbn::fields(b.kind, b.version)) {
        if (f.use != mbn::Field::Use::Keep || std::string_view(f.name) == "image_id") continue;
        if (b.w[f.index] == 0 && std::string_view(f.name).substr(0, 8) == "reserved") continue;
        words += (words.empty() ? "" : ", ") + std::string(f.name) + " " + hex_text(b.w[f.index]);
    }
    if (!words.empty()) std::cout << "words:          " << words << "\n";
    std::cout << "sizes:          " << mbn_sizes_text(b, code_what);
    if (b.has_word("image_size")) std::cout << ", image_size " << b.word("image_size") << (b.slack.empty() ? std::string() : " (" + std::to_string(b.slack.size()) + " bytes of rounding)");
    std::cout << "\n";
    if (b.has_word("sig_ptr"))
        std::cout << "addresses:      signature " << hex_text(b.word("sig_ptr")) << ", certificate chain " << hex_text(b.word("cert_ptr"))
                  << (b.derived_ptrs ? " (pack works them out from the sizes)" : " (kept as they are)") << "\n";
    if (const size_t n = mbn_signature_bytes(b))
        std::cout << "signature:      " << n << " bytes of signature and certificate chain, kept as they are (abr cannot sign: an image that is edited no longer matches them)\n";
    print_mbn_chain("certificates:   QTI's ", b.cert_qti);
    print_mbn_chain("certificates:   ", b.cert);
}

// ---- mbn: unpack

void unpack_mbn(const Bytes& data, const fs::path& dir) {
    const mbn::Block b = mbn::parse_block(data, 0, data.size());
    Manifest m;
    m.set("type", "mbn");
    save_mbn_block(m, dir, b);

    // The code: a compression on it is taken off, like that of any component.
    DecodedComponent code;
    if (!b.code.empty()) {
        progress::enter("decode", b.code.size());
        const progress::Activity doing("code.bin");
        fs::create_directories(dir / ".abr_raw");
        code = decode_component(b.code, "code.bin", /*strip_mtk=*/false);
        write_file(dir / "code.bin", code.plain);
        write_file(dir / ".abr_raw" / "code.bin.raw", code.stored(b.code));
        progress::advance(b.code.size());
        record_component(m, "code", "code.bin", code);
    }
    save_mbn_envelope(m, dir, data, b.consumed, b);

    std::cout << "MBN: " << mbn_block_text(b) << "\n";
    if (code.present)
        std::cout << "  [code] " << b.code.size() << " bytes, " << (code.codec == Codec::NONE ? std::string("not compressed") : std::string(codec_name(code.codec)) + " stream taken off")
                  << " -> code.bin\n";
    for (const MbnPart& p : kMbnParts)
        if (!(b.*p.member).empty()) std::cout << "  [" << p.what << "] " << (b.*p.member).size() << " bytes -> " << p.prefix << ".bin\n";
    print_mbn_chain("  certificates: QTI's ", b.cert_qti);
    print_mbn_chain("  certificates: ", b.cert);
    if (mbn_signature_bytes(b))
        note("the signature and the certificate chain are kept as they are (abr cannot sign): an image that is edited no longer matches them, and a loader that checks the signature will not accept it");

    m.save(dir / "manifest.txt",
           "abr mbn manifest -- edit then `abr pack -i " + dir.string() + " -o out.mbn`\n"
           "# NOTE: pack works out the sizes of the header (code_size, sig_size, cert_size, ...), image_size and, with ptrs=derived, the addresses of the signature and the\n"
           "# chain, from the files. code.bin is the code (code_compression says what it was compressed with: it is compressed again). metadata*.bin, signature*.bin and\n"
           "# cert_chain*.bin are the other parts of the structure; delete the key of one (metadata_file, signature_file, ...) to leave it out. The other words of the header\n"
           "# are kept as they are. abr cannot sign: the signature and the chain are kept as they are, and an image that was changed no longer matches them.");
}

// ---- mbn: pack

Bytes repack_mbn(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    mbn::Block b = load_mbn_block(m, dir);
    if (!m.has("code_file")) throw FormatError("manifest.txt: code_file is missing: a flat MBN image holds code (code.bin)");
    b.code = load_component(m, dir, "code", opt);
    const Bytes core = mbn::build_block(b);
    warn_stale_signature(m, core, b);
    return assemble_envelope(m, dir, core, opt);
}

// ---- mbn: info

void print_mbn_info(const Bytes& data) {
    const mbn::Block b = mbn::parse_block(data, 0, data.size());
    print_mbn_block_info(b, "code");
    if (!b.code.empty()) {
        const Codec codec = detect_codec(b.code);
        std::cout << "code:           " << b.code.size() << " bytes, " << (codec == Codec::NONE ? std::string("not compressed") : std::string(codec_name(codec))) << "\n";
    }
    print_envelope_info(Envelope::capture(data, 0, b.consumed));
}

// ---- mbn_elf

// The type of a program header in the manifest: its name when it has one, else the number.
const char* const kPhdrTypeNames[] = {"null", "load", "dynamic", "interp", "note", "shlib", "phdr", "tls"};
constexpr size_t kPhdrTypeNameCount = sizeof kPhdrTypeNames / sizeof kPhdrTypeNames[0];

std::string phdr_type_text(uint32_t type) { return type < kPhdrTypeNameCount ? std::string(kPhdrTypeNames[type]) : hex_text(type); }

uint32_t phdr_type_value(const Manifest& m, const std::string& key, uint32_t def) {
    if (!m.has(key)) return def;
    const std::string text = m.get(key);
    for (size_t i = 0; i < kPhdrTypeNameCount; ++i)
        if (text == kPhdrTypeNames[i]) return static_cast<uint32_t>(i);
    return m.get_u32(key, def);  // a number, or the error that names the key and the value
}

std::string mbn_phdr_text(size_t index, const mbn::Segment& s) {
    const mbn::Phdr& p = s.ph;
    std::string text = "  [" + std::to_string(index) + "] " + phdr_type_text(p.type) + ", " + mbn::describe_flags(p.flags) + ": offset " + hex_text(p.offset) + ", " + std::to_string(p.filesz) +
                       " bytes, address " + hex_text(p.paddr) + (p.vaddr != p.paddr ? " (virtual " + hex_text(p.vaddr) + ")" : std::string()) + ", memory " + std::to_string(p.memsz) +
                       " bytes, align " + hex_text(p.align);
    if (s.role == mbn::Role::Headers) text += " -- placeholder for the ELF header and the program headers";
    else if (s.role == mbn::Role::Hash) text += " -- the hash segment";
    return text;
}

std::string mbn_table_text(const mbn::Elf& e) {
    if (e.block.code.empty()) return "no table of hashes";
    if (e.algo != mbn::Algo::None)
        return std::to_string(e.block.code.size() / mbn::digest_size(e.algo)) + " hashes of " + mbn::algo_name(e.algo) + ", the table abr makes of these segments (pack makes it again)";
    return std::to_string(e.block.code.size()) + " bytes, not a table that abr can make of the segments: kept as it is, and not checked";
}

void unpack_mbn_elf(const Bytes& data, const fs::path& dir) {
    const mbn::Elf e = mbn::parse_elf(data);
    Manifest m;
    m.set("type", "mbn_elf");
    m.set_u32("elf_class", e.is64 ? 64 : 32);
    m.set_u32("elf_type", e.type);
    m.set_u32("elf_machine", e.machine);
    m.set_addr("elf_entry", e.entry);
    m.set_addr("elf_flags", e.flags);
    m.set_u32("elf_shentsize", e.shentsize);
    m.set("elf_layout", e.tidy ? "tidy" : "skeleton");
    if (e.tidy) m.set_addr("elf_fill", e.fill);
    else save_raw(m, dir, "skeleton", e.skeleton, "skeleton.bin");
    m.set_u32("segments", static_cast<uint32_t>(e.seg.size()));
    if (e.tidy) {
        // (a layout that is not tidy keeps the program headers in skeleton.bin)
        for (size_t i = 0; i < e.seg.size(); ++i) {
            const mbn::Phdr& p = e.seg[i].ph;
            const std::string k = "seg" + std::to_string(i);
            m.set(k + "_type", phdr_type_text(p.type));
            m.set_addr(k + "_flags", p.flags);
            m.set_addr(k + "_offset", p.offset);
            m.set_addr(k + "_vaddr", p.vaddr);
            m.set_addr(k + "_paddr", p.paddr);
            m.set_addr(k + "_memsz", p.memsz);
            m.set_addr(k + "_align", p.align);
        }
    }
    save_mbn_block(m, dir, e.block);
    if (e.algo != mbn::Algo::None) m.set("hash_table", mbn::algo_key(e.algo));
    else save_raw(m, dir, "hash_table", e.block.code, "hash_table.bin");
    save_raw(m, dir, "hash_pad", e.hash_pad, "hash_pad.bin");

    // The data of the segments: a compression on it is taken off, like that of any component.
    std::vector<ComponentSource> sources;
    std::vector<size_t> index;
    for (size_t i = 0; i < e.seg.size(); ++i) {
        if (e.seg[i].role != mbn::Role::Plain || e.seg[i].data.empty()) continue;
        sources.push_back({&e.seg[i].data, "seg" + std::to_string(i) + ".bin"});
        index.push_back(i);
    }
    const std::vector<DecodedComponent> decoded = save_components(dir, sources);
    for (size_t k = 0; k < decoded.size(); ++k) record_component(m, "seg" + std::to_string(index[k]), sources[k].filename, decoded[k]);
    save_mbn_envelope(m, dir, data, e.consumed, e.block);

    std::cout << "MBN ELF: " << (e.is64 ? "ELF64" : "ELF32") << ", " << e.seg.size() << " program headers; the hash segment is program header " << e.hash_index << ", "
              << mbn_block_text(e.block) << "; table: " << mbn_table_text(e) << "\n";
    for (size_t k = 0; k < decoded.size(); ++k)
        if (decoded[k].codec != Codec::NONE)
            std::cout << "  [segment " << index[k] << "] " << sources[k].raw->size() << " bytes, " << codec_name(decoded[k].codec) << " stream taken off -> " << sources[k].filename << "\n";
    print_mbn_chain("  certificates: QTI's ", e.block.cert_qti);
    print_mbn_chain("  certificates: ", e.block.cert);
    if (!e.tidy)
        note("the layout of this ELF is not the one that Qualcomm's tools make (section headers, bytes between the segments that are not a fill, or other sizes of the headers): its headers and "
             "the bytes between the segments are kept in skeleton.bin, and every segment must keep its size when it is packed");
    if (e.algo == mbn::Algo::None && !e.block.code.empty())
        note("the table of hashes is not one that abr can make of these segments: it is kept as it is (hash_table.bin), and an edited segment is not in it");
    if (mbn_signature_bytes(e.block))
        note("the signature and the certificate chain are kept as they are (abr cannot sign): an image that is edited no longer matches them, and a loader that checks the signature will not accept it");

    m.save(dir / "manifest.txt",
           "abr mbn_elf manifest -- edit then `abr pack -i " + dir.string() + " -o out.mbn`\n"
           "# NOTE: seg<N>.bin is the data of program header N (seg<N>_compression says what it was compressed with: it is compressed again). pack writes the ELF header, the\n"
           "# program headers and the data of the segments in the order they were in, and works out p_filesz and the hash segment; segN_offset is where the data of segment N was\n"
           "# and is kept while the segments before it leave room (they move it on when they grow); p_memsz grows with p_filesz where it must. hash_table=sha256 (sha1, sha384) is\n"
           "# the table of hashes of the segments, made again; hash_table.bin is a table that abr cannot make: it is kept as it is. The header words, metadata*.bin, signature*.bin\n"
           "# and cert_chain*.bin are as in an `mbn` folder. With elf_layout=skeleton the ELF header, the program headers and the bytes between the segments are skeleton.bin.\n"
           "# abr cannot sign: the signature and the chain are kept as they are, and an image that was changed no longer matches them.");
}

// ---- mbn_elf: pack

Bytes repack_mbn_elf(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    const std::string layout = m.get("elf_layout", "tidy");
    mbn::Elf e;
    if (layout == "skeleton") {
        const Bytes skeleton = load_raw(m, dir, "skeleton");
        if (skeleton.empty()) throw FormatError("manifest.txt: elf_layout=skeleton needs skeleton_file (skeleton.bin): the ELF header and the program headers as they were");
        e = mbn::elf_shell(skeleton);
    } else if (layout == "tidy") {
        const uint64_t cls = m.get_int("elf_class", 32, 1, 64);
        if (cls != 32 && cls != 64) throw FormatError("manifest.txt: " + shown("elf_class=" + m.get("elf_class")) + " is neither 32 nor 64");
        e.is64 = cls == 64;
        const unsigned bits = e.is64 ? 64 : 32;
        e.type = static_cast<uint16_t>(m.get_bounded("elf_type", 2, 16));
        e.machine = static_cast<uint16_t>(m.get_bounded("elf_machine", 0, 16));
        e.entry = m.get_bounded("elf_entry", 0, bits);
        e.flags = static_cast<uint32_t>(m.get_bounded("elf_flags", 0, 32));
        e.shentsize = static_cast<uint16_t>(m.get_bounded("elf_shentsize", 0, 16));
        e.fill = static_cast<uint8_t>(m.get_bounded("elf_fill", 0, 8));
        if (!m.has("segments")) throw FormatError("manifest.txt: segments is missing (the number of program headers)");
        const uint32_t count = m.get_count("segments");
        for (uint32_t i = 0; i < count; ++i) {
            const std::string k = "seg" + std::to_string(i);
            mbn::Segment s;
            s.ph.type = phdr_type_value(m, k + "_type", 1);
            s.ph.flags = static_cast<uint32_t>(m.get_bounded(k + "_flags", 0, 32));
            s.ph.offset = m.get_bounded(k + "_offset", 0, bits);
            s.ph.vaddr = m.get_bounded(k + "_vaddr", 0, bits);
            s.ph.paddr = m.get_bounded(k + "_paddr", 0, bits);
            s.ph.memsz = m.get_bounded(k + "_memsz", 0, bits);
            s.ph.align = m.get_bounded(k + "_align", 0, bits);
            e.seg.push_back(std::move(s));
        }
        mbn::classify(e);
    } else {
        throw FormatError("manifest.txt: " + shown("elf_layout=" + layout) + " is neither tidy nor skeleton");
    }

    e.block = load_mbn_block(m, dir);
    if (m.has("hash_table")) {
        const std::string name = m.get("hash_table");
        const std::optional<mbn::Algo> algo = mbn::algo_from_key(name);
        if (!algo || *algo == mbn::Algo::None)
            throw FormatError("manifest.txt: " + shown("hash_table=" + name) + " is none of sha1, sha256, sha384 (the hashes that abr makes; a table of another kind is the file hash_table.bin, hash_table_file=)");
        e.algo = *algo;
    } else {
        e.block.code = load_raw(m, dir, "hash_table");
    }
    e.hash_pad = load_raw(m, dir, "hash_pad");

    // The data of the segments, compressed again where it is an edited file.
    std::vector<std::string> prefixes;
    std::vector<size_t> index;
    for (size_t i = 0; i < e.seg.size(); ++i) {
        const std::string k = "seg" + std::to_string(i);
        if (e.seg[i].role != mbn::Role::Plain || !m.has(k + "_file")) continue;
        prefixes.push_back(k);
        index.push_back(i);
    }
    std::vector<Bytes> data = load_components(m, dir, prefixes, opt);
    for (size_t j = 0; j < index.size(); ++j) e.seg[index[j]].data = std::move(data[j]);

    std::string moved;
    const Bytes core = mbn::build_elf(e, &moved);
    if (!moved.empty()) note("a segment grew, and what is behind it moved on: " + moved.substr(moved.find(' ') + 1));
    warn_stale_signature(m, core, e.block);
    if (e.algo == mbn::Algo::None && !e.block.code.empty() && core_changed(m, core))
        warn("the image was changed, but its table of hashes (hash_table.bin) is not one that abr can make: it is kept as it is, and a loader that checks the segments against it will not accept an image whose segments were changed");
    return assemble_envelope(m, dir, core, opt);
}

// ---- mbn_elf: info

void print_mbn_elf_info(const Bytes& data) {
    const mbn::Elf e = mbn::parse_elf(data);
    std::cout << "class:          " << (e.is64 ? "ELF64" : "ELF32") << ", little-endian, type " << e.type << ", machine " << e.machine << ", entry " << hex_text(e.entry) << ", flags "
              << hex_text(e.flags) << "\n";
    std::cout << "program headers: " << e.seg.size() << " at " << hex_text(e.phoff) << ", " << e.phentsize << " bytes each\n";
    for (size_t i = 0; i < e.seg.size(); ++i) std::cout << mbn_phdr_text(i, e.seg[i]) << "\n";
    std::cout << "layout:         "
              << (e.tidy ? "the one that Qualcomm's tools make (the ELF header, the program headers, then the segments; pack writes it again)"
                         : "not the one that Qualcomm's tools make: kept as it is (skeleton.bin), every segment keeps its size when packed")
              << "\n";
    std::cout << "hash segment:   program header " << e.hash_index << "\n";
    print_mbn_block_info(e.block, "hash table");
    std::cout << "hash table:     " << mbn_table_text(e) << "\n";
    if (!e.hash_pad.empty()) std::cout << "padding:        " << e.hash_pad.size() << " bytes behind the structure inside the hash segment (kept)\n";
    print_envelope_info(Envelope::capture(data, 0, e.consumed));
}

// ------------------------------------------------------------------ splash --
//
// The pictures that the boot loader of a Qualcomm phone shows before Android starts (abr/splash.hpp): the partitions `splash` and `logo`. Four containers, each known by
// its magic word. `unpack` writes every picture to a file of its own, and the manifest says where it lay, how it was coded (what was taken off it) and the words of the
// header that are not worked out from the pictures.
//
//   type=splash       Qualcomm's "SPLASH!!" image: one picture, or a table of up to 25. A picture is a PNG, `NN_picture.png`: its pixels as the image holds them
//                     (`picture<N>_compression=none`) or decoded from the RLE24 coding (`rle24`). `pack` codes them again that way and works out the sizes, the
//                     blocks and the places of the pictures.
//   type=oplus_logo   the "SPLASH LOGO!" image of OPPO, realme and OnePlus phones: a file for every picture (a BMP), `NN_<name>.bmp`, with the gzip taken off where
//                     the picture was a gzip stream (`entry<N>_compression`, `entry<N>_level`).
//   type=xiaomi_logo  the "LOGO!!!!" image of Xiaomi and Redmi phones: the file of every picture as it is (a BMP; a PNG in some images), `NN_picture.bmp`.
//   type=moto_logo    the "MotoLogo" image of Motorola phones: a PNG for every picture that is "MotoRun" (`entry<N>_compression=motorun`); any other picture is the
//                     file it is.
//
// A picture that is a coding of pixels (RLE24, MotoRun, the pixels of a SPLASH!! image) goes back into the image as the very bytes the image had when its PNG is not
// changed: the encoders of abr do not make the bytes that the tools of the vendors make, so those bytes are kept in .abr_raw/ and believed only while they give the
// picture back. A picture that was changed is coded again. What cannot be worked out from the pictures (the bytes in front of an OPLUS header, the words behind a
// table) is kept as it is.

// The pictures of one image may be this many bytes of pixels (three a pixel) all together, unpacked: what a header may ask of the memory is decided here.
constexpr uint64_t kSplashPixelLimit = uint64_t{512} << 20;

bool is_all_zero(const Bytes& b) {
    return std::all_of(b.begin(), b.end(), [](uint8_t v) { return v == 0; });
}

// `00_oppo_logo.bmp`: the number of the picture (two digits at least), its name made safe for a file name ("picture" when it has none), the extension of what the
// picture is. A name that ends in that extension already (logo.bmp) is not given it twice.
std::string splash_file_name(size_t index, size_t count, std::string_view name, const std::string& extension) {
    const size_t width = std::max<size_t>(2, std::to_string(count > 0 ? count - 1 : 0).size());
    std::string number = std::to_string(index);
    if (number.size() < width) number.insert(0, width - number.size(), '0');
    std::string clean;
    for (const char c : name) {
        const bool plain = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-';
        clean += plain ? c : '_';
    }
    const std::string dot = "." + extension;
    if (clean.size() > dot.size()) {
        std::string end = clean.substr(clean.size() - dot.size());
        for (char& c : end) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (end == dot) clean.resize(clean.size() - dot.size());
    }
    while (!clean.empty() && clean.back() == '.') clean.pop_back();
    if (clean.empty()) clean = "picture";
    return number + "_" + clean + dot;
}

// What `unpack` records of the image's own bytes: what is kept around the structure, and a hash of the structure (to tell a changed image from an untouched one).
void save_core_envelope(Manifest& m, const fs::path& dir, const Bytes& data, size_t consumed) {
    const Envelope env = Envelope::capture(data, 0, consumed);
    save_envelope(m, dir, env, data, 0, consumed);
    if (!env.tail.empty()) note(std::to_string(env.tail.size()) + " bytes after the last picture are kept verbatim (tail.bin)");
    m.set_hex("core_sha256", hash::sha256(data.data(), std::min(consumed, data.size())));
}

// ---- pictures that are pixels in a coding of their own

// SHA-256 of what makes a picture the one it is: its coding, its size and its pixels (the same pixels at another size or in another coding are another picture).
Bytes bitmap_hash(const splash::Bitmap& bmp, const std::string& coding) {
    hash::Sha256 h;
    h.update(reinterpret_cast<const uint8_t*>(coding.data()), coding.size());
    uint8_t size[9] = {0};  // (the zero in front ends the name of the coding)
    for (int i = 0; i < 4; ++i) {
        size[1 + i] = static_cast<uint8_t>(bmp.width >> (8 * i));
        size[5 + i] = static_cast<uint8_t>(bmp.height >> (8 * i));
    }
    h.update(size, sizeof size);
    if (!bmp.bgr.empty()) h.update(bmp.bgr.data(), bmp.bgr.size());
    return h.finish();
}

Bytes bitmap_png(const splash::Bitmap& bmp) {
    png::Image img;
    img.width = bmp.width;
    img.height = bmp.height;
    img.rgba = splash::bitmap_to_rgba(bmp);
    return png::encode(img, /*with_alpha=*/false);
}

// The picture that the PNG `filename` of the folder holds. The image has no alpha: a pixel that is not opaque is put on black, and that is said.
splash::Bitmap read_picture_png(const fs::path& dir, const std::string& filename) {
    try {
        const png::Image img = png::decode(read_file(dir / filename));
        if (img.has_alpha) {
            for (size_t i = 3; i < img.rgba.size(); i += 4) {
                if (img.rgba[i] == 255) continue;
                note(shown(filename) + " has pixels that are not opaque: the image holds no alpha, they are put on black");
                break;
            }
        }
        return splash::bitmap_from_rgba(img.rgba, img.width, img.height);
    } catch (const FormatError& e) {
        throw FormatError(shown(filename) + ": " + e.what());
    }
}

// How the pixels of a picture lie in the image: `decode` makes the pixels of the bytes the image holds (nullopt for bytes that are no picture), `encode` makes the
// bytes of pixels.
struct PictureCoding {
    std::function<std::optional<splash::Bitmap>(const Bytes&)> decode;
    std::function<Bytes(const splash::Bitmap&)> encode;
};

struct LoadedPicture {
    splash::Bitmap pixels;
    Bytes stored;            // the picture as the image holds it
    bool untouched = false;  // the picture is the one that was unpacked (its coding too)
    bool replayed = false;   // `stored` is what the image had (.abr_raw), not made of the pixels
};

// The picture of `<prefix>_file` (a PNG) as the bytes of the image: the ones it had (.abr_raw/<file>.raw) when the picture is what it was -- believed only when they
// give that picture back, as the raw copy of a component is --, else the pixels coded again.
LoadedPicture load_picture(const Manifest& m, const fs::path& dir, const std::string& prefix, const std::string& coding, const PictureCoding& how) {
    if (!m.has(prefix + "_file")) throw FormatError("manifest.txt: " + shown(prefix + "_file") + " is missing (the file of the picture)");
    const std::string filename = m.get_path(prefix + "_file");
    const progress::Activity doing(filename);
    LoadedPicture out;
    out.pixels = read_picture_png(dir, filename);
    const Bytes now = bitmap_hash(out.pixels, coding);
    const Bytes was = m.get_hex(prefix + "_orig_hash");
    const fs::path raw_path = dir / ".abr_raw" / (filename + ".raw");
    out.untouched = !was.empty() && now == was;
    if (out.untouched && fs::exists(raw_path)) {
        Bytes raw = read_file(raw_path);
        std::string why;
        try {
            const std::optional<splash::Bitmap> back = how.decode(raw);
            if (back && bitmap_hash(*back, coding) == was) {
                out.stored = std::move(raw);
                out.replayed = true;
                progress::advance(out.pixels.bgr.size());
                return out;
            }
            why = "it does not give the picture of " + filename + " as it was unpacked";
        } catch (const std::exception& e) {
            why = std::string("it does not decode (") + e.what() + ")";
        }
        throw FormatError(shown(raw_path.generic_string()) + " does not belong to " + shown(filename) + ": " + why + ". Delete it to have " + shown(filename) +
                          " coded again, or unpack the image again");
    }
    out.stored = how.encode(out.pixels);
    progress::advance(out.pixels.bgr.size());
    return out;
}

// A picture that `unpack` decoded and wrote as a PNG, as the manifest keeps it.
struct PictureFile {
    std::string file;
    uint32_t width = 0, height = 0;
    Bytes hash;  // bitmap_hash()
};

// The PNG, and the bytes as they lay in the image (.abr_raw/<file>.raw: the folder has to be there) unless `keep_raw` is false: for pixels that are kept as they are
// (what no encoder can make otherwise) the picture's bytes are the pixels, and the copy would be the same bytes again.
PictureFile write_picture(const fs::path& dir, const std::string& file, const std::string& coding, const splash::Bitmap& bmp, const Bytes& stored, bool keep_raw = true) {
    PictureFile f;
    f.file = file;
    f.width = bmp.width;
    f.height = bmp.height;
    f.hash = bitmap_hash(bmp, coding);
    write_file(dir / file, bitmap_png(bmp));
    if (keep_raw) write_file(dir / ".abr_raw" / (file + ".raw"), stored);
    return f;
}

// A folder with an empty .abr_raw/ in it has no use for the directory (a raw copy that was needed is a file in it): taken away -- remove() does not go into a directory, so one
// with files in it stays.
void drop_empty_raw_dir(const fs::path& dir) {
    std::error_code ec;
    fs::remove(dir / ".abr_raw", ec);
}

void record_picture(Manifest& m, const std::string& prefix, const PictureFile& f, const std::string& coding) {
    m.set(prefix + "_file", f.file);
    m.set(prefix + "_compression", coding);
    m.set_u32(prefix + "_width", f.width);
    m.set_u32(prefix + "_height", f.height);
    m.set_hex(prefix + "_orig_hash", f.hash);
}

// A PNG that is not the size the picture was: the header of the image says the size it has now.
void note_new_size(const std::string& filename, const splash::Bitmap& now, uint32_t was_width, uint32_t was_height) {
    if (was_width == 0 || was_height == 0 || (now.width == was_width && now.height == was_height)) return;
    note(shown(filename) + " is " + std::to_string(now.width) + "x" + std::to_string(now.height) + " pixels, it was " + std::to_string(was_width) + "x" + std::to_string(was_height) +
         ": the image says the new size");
}

std::string pixels_text(uint32_t width, uint32_t height) { return std::to_string(width) + "x" + std::to_string(height); }

// ---- splash: Qualcomm's "SPLASH!!"

void unpack_splash(const Bytes& data, const fs::path& dir) {
    const splash::QcSplash s = splash::qc_parse(data);
    const size_t n = s.pictures.size();
    uint64_t pixels = 0;
    for (const splash::QcPicture& p : s.pictures) pixels += uint64_t{p.width} * p.height * 3;
    if (pixels > kSplashPixelLimit)
        throw FormatError("the pictures of this image are " + std::to_string(pixels >> 20) + " MiB of pixels unpacked; abr unpacks " + std::to_string(kSplashPixelLimit >> 20) +
                          " MiB of them at most");
    fs::create_directories(dir / ".abr_raw");
    progress::enter("decode", pixels);
    std::vector<PictureFile> files(n);
    par::for_each(n, [&](size_t i) {
        const splash::QcPicture& p = s.pictures[i];
        const std::string name = splash_file_name(i, n, "picture", "png");
        const progress::Activity doing(name);
        const splash::Bitmap bmp = splash::qc_decode(p);
        // (pixels that the image holds as they are need no copy -- unless the bytes behind them, up to the block, are not zeros: they would be lost)
        const bool keep_raw = p.type == splash::kQcRle24 || !std::all_of(p.data.begin() + static_cast<std::ptrdiff_t>(p.stream), p.data.end(), [](uint8_t v) { return v == 0; });
        files[i] = write_picture(dir, name, p.type == splash::kQcRle24 ? "rle24" : "none", bmp, p.data, keep_raw);
        progress::advance(bmp.bgr.size());
    });

    Manifest m;
    m.set("type", "splash");
    m.set("form", s.several ? "several" : "single");
    m.set_u32("pictures", static_cast<uint32_t>(n));
    if (!s.header_rest.empty()) m.set_hex("header_rest", s.header_rest);
    for (size_t i = 0; i < n; ++i) {
        const splash::QcPicture& p = s.pictures[i];
        const std::string prefix = "picture" + std::to_string(i);
        record_picture(m, prefix, files[i], p.type == splash::kQcRle24 ? "rle24" : "none");
        m.set_u32(prefix + "_blocks", p.blocks);
    }
    // The last picture is padded up to its blocks when the image shows it (bytes behind the pixels or the packets); when it cannot -- the picture fills its blocks -- the
    // image is taken to be made the way the tool of its form makes it: the table of Magic-Splash-Wand pads every picture, the single picture of Qualcomm's logo_gen.py none.
    const splash::QcPicture& last = s.pictures.back();
    const bool fills = last.blocks != 0 && last.data.size() == size_t{last.blocks} * splash::kQcBlock;
    m.set_bool("last_padded", fills && (last.stream < last.data.size() || s.several));
    save_core_envelope(m, dir, data, s.consumed);
    drop_empty_raw_dir(dir);

    std::cout << "splash: " << (s.several ? "a table of " + std::to_string(n) + " pictures" : std::string("one picture")) << "\n";
    for (size_t i = 0; i < n; ++i) {
        const splash::QcPicture& p = s.pictures[i];
        std::cout << "  [" << i << "] " << pixels_text(p.width, p.height) << ", " << splash::qc_type_name(p.type) << ": " << p.stream << " bytes at " << hex_text(p.offset) << " ("
                  << (p.blocks == 0 ? std::string("the header counts no blocks") : std::to_string(p.blocks) + (p.blocks == 1 ? " block" : " blocks")) << ") -> " << files[i].file << "\n";
    }
    m.save(dir / "manifest.txt",
           "abr splash manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`\n"
           "# NOTE: every picture is a PNG (picture<N>_file). picture<N>_compression says how the image holds its pixels: rle24 (run-length coded) or none (as they are, blue,\n"
           "# green, red). A picture that is not changed goes back as the very bytes it was; a changed one is coded again, and pack works out its size, the blocks that\n"
           "# the header names and the places of the pictures. The size of a PNG may differ from the original: the header of the image says the size the picture has.");
}

Bytes repack_splash(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    const std::string form = m.get("form", "single");
    if (form != "single" && form != "several") throw FormatError("manifest.txt: " + shown("form=" + form) + " is neither single nor several");
    const size_t n = m.get_count("pictures", 0);
    if (n == 0 || n > splash::kQcMaxPictures || (form == "single" && n != 1))
        throw FormatError("manifest.txt: " + shown("pictures=" + m.get("pictures")) + " is the number of the pictures of the image, " +
                          (form == "single" ? std::string("1 in a single-picture image (form=single)") : "1 to " + std::to_string(splash::kQcMaxPictures)));
    splash::QcSplash s;
    s.several = form == "several";
    s.header_rest = m.get_hex("header_rest");
    s.pictures.resize(n);
    const bool last_padded = m.get_bool("last_padded", false);
    par::for_each(n, [&](size_t i) {
        const std::string prefix = "picture" + std::to_string(i);
        const std::string coding = m.get(prefix + "_compression", "rle24");
        if (coding != "rle24" && coding != "none")
            throw FormatError("manifest.txt: " + shown(prefix + "_compression=" + coding) + " is neither rle24 nor none (a picture of this image is run-length coded or kept as pixels)");
        const uint32_t type = coding == "rle24" ? splash::kQcRle24 : splash::kQcRaw;
        const uint32_t was_width = m.get_u32(prefix + "_width", 0), was_height = m.get_u32(prefix + "_height", 0);
        PictureCoding how;
        how.decode = [&](const Bytes& raw) -> std::optional<splash::Bitmap> {
            splash::QcPicture q;
            q.width = was_width;
            q.height = was_height;
            q.type = type;
            q.data = raw;
            return splash::qc_decode(q);
        };
        how.encode = [&](const splash::Bitmap& bmp) { return splash::qc_encode(bmp, type); };
        LoadedPicture loaded = load_picture(m, dir, prefix, coding, how);
        splash::QcPicture& p = s.pictures[i];
        p.type = type;
        if (loaded.replayed) {
            p.width = was_width;
            p.height = was_height;
            p.data = std::move(loaded.stored);
            p.blocks = m.get_u32(prefix + "_blocks", splash::qc_blocks(p.data.size()));
        } else {
            if (!loaded.untouched) note_new_size(m.get_path(prefix + "_file"), loaded.pixels, was_width, was_height);
            p.width = loaded.pixels.width;
            p.height = loaded.pixels.height;
            p.data = std::move(loaded.stored);
            // The blocks the header names: those it had while the picture is the one it was (an image of Qualcomm's own says 0 for its pixels), those of the data otherwise;
            // pixels that were 0 stay 0 (the picture is told by its size), a run-length coded picture has to be told how long it is.
            const uint32_t was_blocks = m.get_u32(prefix + "_blocks", 0);
            const uint32_t needed = splash::qc_blocks(p.data.size());
            if (type == splash::kQcRaw && m.has(prefix + "_blocks") && was_blocks == 0) p.blocks = 0;
            else if (loaded.untouched && m.has(prefix + "_blocks")) p.blocks = std::max(was_blocks, needed);
            else p.blocks = needed;
            // (every picture but the last is followed by the next at once; the last is padded as the image's was)
            if (p.blocks != 0 && (i + 1 < n || last_padded)) p.data.resize(size_t{p.blocks} * splash::kQcBlock, 0);
        }
    });
    return assemble_envelope(m, dir, splash::qc_build(s), opt);
}

void print_splash_info(const Bytes& data) {
    const splash::QcSplash s = splash::qc_parse(data);
    std::cout << "header:         " << (s.several ? "a table of " + std::to_string(s.pictures.size()) + " pictures" : std::string("one picture")) << ", the data in blocks of "
              << splash::kQcBlock << " bytes\n";
    for (size_t i = 0; i < s.pictures.size(); ++i) {
        const splash::QcPicture& p = s.pictures[i];
        std::cout << "  [" << i << "] " << pixels_text(p.width, p.height) << ", " << splash::qc_type_name(p.type) << ": " << p.stream << " bytes at " << hex_text(p.offset) << ", "
                  << (p.blocks == 0 ? std::string("the header counts no blocks") : std::to_string(p.blocks) + (p.blocks == 1 ? " block" : " blocks"));
        if (p.type == splash::kQcRle24) std::cout << " (" << uint64_t{p.width} * p.height * 3 << " bytes as pixels)";
        if (p.data.size() > p.stream) std::cout << ", " << p.data.size() - p.stream << " bytes of padding";
        std::cout << "\n";
    }
    if (!s.header_rest.empty()) std::cout << "header:         " << s.header_rest.size() << " more bytes behind the fields (kept)\n";
    print_envelope_info(Envelope::capture(data, 0, s.consumed));
}

// ---- oplus_logo: the "SPLASH LOGO!" image of OPPO, realme and OnePlus

// The bytes in front of the header, when they are not zeros, are kept as they are; this says it when the image is changed (what they are, abr does not know).
void warn_stale_preamble(const Manifest& m, const Bytes& core, const Bytes& preamble) {
    if (is_all_zero(preamble) || !core_changed(m, core)) return;
    const bool ddph = preamble.size() >= 4 && (uint32_t{preamble[0]} | (uint32_t{preamble[1]} << 8) | (uint32_t{preamble[2]} << 16) | (uint32_t{preamble[3]} << 24)) == splash::kDdphMagic;
    warn(std::string("the image was changed, and the ") + std::to_string(preamble.size()) + " bytes in front of its header (preamble.bin" + (ddph ? ", it begins \"DDPH\"" : "") +
         ") are kept as they were: if they hold a hash or a signature of the image, it is the one of the original");
}

void unpack_oplus_logo(const Bytes& data, const fs::path& dir) {
    const splash::OplusLogo l = splash::oplus_parse(data);
    const size_t n = l.entries.size();
    Manifest m;
    m.set("type", "oplus_logo");
    if (!is_all_zero(l.preamble)) save_raw(m, dir, "preamble", l.preamble, "preamble.bin");
    for (size_t k = 0; k < l.desc.size(); ++k) {
        if (l.desc[k].empty() && l.desc_tail[k].empty()) continue;
        m.set("description" + std::to_string(k), l.desc[k]);
        m.set_tail("description" + std::to_string(k) + "_tail", l.desc_tail[k]);
    }
    m.set_u32("logo_version", l.version);
    m.set_u32("logo_width", l.width);
    m.set_u32("logo_height", l.height);
    m.set_u32("logo_compression", l.compression);
    save_raw(m, dir, "header_rest", l.header_rest, "header_rest.bin");
    m.set_u32("entries", static_cast<uint32_t>(n));

    uint64_t work = 0;
    bool any_stream = false;
    std::vector<size_t> order(n);
    for (size_t i = 0; i < n; ++i) {
        order[i] = i;
        work += l.entries[i].data.size();
        any_stream = any_stream || detect_codec(l.entries[i].data) != Codec::NONE;
    }
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return l.entries[a].data.size() > l.entries[b].data.size(); });
    if (any_stream) fs::create_directories(dir / ".abr_raw");
    progress::enter("decode", work);
    std::vector<DecodedComponent> decoded(n);
    std::vector<std::string> files(n);
    par::for_each(n, [&](size_t k) {
        const size_t i = order[k];
        const splash::OplusEntry& e = l.entries[i];
        const std::string label = e.name.empty() ? "picture " + std::to_string(i) : e.name;
        const progress::Activity doing(label);
        decoded[i] = decode_component(e.data, label, /*strip_mtk=*/false);
        if (decoded[i].present) {
            files[i] = splash_file_name(i, n, e.name, splash::picture_extension(decoded[i].plain));
            write_file(dir / files[i], decoded[i].plain);
            if (decoded[i].codec != Codec::NONE) write_file(dir / ".abr_raw" / (files[i] + ".raw"), e.data);  // (an untouched stream comes back as it was)
        }
        progress::advance(e.data.size());
    });
    for (size_t i = 0; i < n; ++i) {
        const splash::OplusEntry& e = l.entries[i];
        const std::string prefix = "entry" + std::to_string(i);
        m.set(prefix + "_name", e.name);
        m.set_tail(prefix + "_name_tail", e.name_tail);
        m.set_u32(prefix + "_plain_size", e.plain_size);
        if (decoded[i].present) record_component(m, prefix, files[i], decoded[i]);
    }
    save_core_envelope(m, dir, data, l.consumed);
    drop_empty_raw_dir(dir);

    std::cout << "OPLUS logo: " << n << (n == 1 ? " picture" : " pictures") << ", version " << l.version << ", " << pixels_text(l.width, l.height) << "\n";
    uint64_t at = splash::kOplusDataAt;
    for (size_t i = 0; i < n; ++i) {
        const splash::OplusEntry& e = l.entries[i];
        std::cout << "  [" << i << "] " << shown(e.name) << ": " << e.data.size() << " bytes at " << hex_text(at) << ", ";
        if (!decoded[i].present) std::cout << "no data\n";
        else std::cout << (decoded[i].codec == Codec::NONE ? std::string("plain") : std::string(codec_name(decoded[i].codec)) + " stream taken off") << " -> " << files[i] << "\n";
        at += e.data.size();
    }
    if (!is_all_zero(l.preamble))
        note("the " + std::to_string(l.preamble.size()) + " bytes in front of the header are not zeros: kept as they are (preamble.bin; abr cannot make them again)");
    m.save(dir / "manifest.txt",
           "abr oplus_logo manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`\n"
           "# NOTE: entry<N>_file is the picture (a BMP) with the compression taken off (entry<N>_compression, entry<N>_level: pack compresses it again). pack works out the\n"
           "# places of the pictures and their sizes; entry<N>_plain_size is the size of the BMP as the header says (the size of the file, when the file was changed).\n"
           "# To leave a picture out delete its keys, number the ones behind it again and change entries=. The words of the header (logo_*) are kept as they are.");
}

Bytes repack_oplus_logo(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    splash::OplusLogo l;
    l.preamble = load_raw(m, dir, "preamble");
    if (l.preamble.size() > splash::kOplusPreamble)
        throw FormatError("preamble.bin is " + std::to_string(l.preamble.size()) + " bytes; the bytes in front of the header are " + std::to_string(splash::kOplusPreamble));
    for (size_t k = 0; k < l.desc.size(); ++k) {
        l.desc[k] = m.get("description" + std::to_string(k));
        l.desc_tail[k] = m.get_tail("description" + std::to_string(k) + "_tail");
    }
    l.version = m.get_u32("logo_version", 0);
    l.width = m.get_u32("logo_width", 0);
    l.height = m.get_u32("logo_height", 0);
    l.compression = m.get_u32("logo_compression", 1);
    l.header_rest = load_raw(m, dir, "header_rest");
    const size_t n = m.get_count("entries", 0);
    if (n == 0 || n > splash::kOplusMaxEntries)
        throw FormatError("manifest.txt: " + shown("entries=" + m.get("entries")) + " is the number of the pictures of the image, 1 to " + std::to_string(splash::kOplusMaxEntries));
    std::vector<std::string> prefixes(n);
    for (size_t i = 0; i < n; ++i) prefixes[i] = "entry" + std::to_string(i);
    std::vector<Bytes> stored = load_components(m, dir, prefixes, opt);
    l.entries.resize(n);
    for (size_t i = 0; i < n; ++i) {
        splash::OplusEntry& e = l.entries[i];
        e.name = m.get(prefixes[i] + "_name");
        e.name_tail = m.get_tail(prefixes[i] + "_name_tail");
        e.data = std::move(stored[i]);
        // The size of the BMP that the header says: what it said while the picture is the one it was (unpack saw it), else the size of the file.
        uint64_t plain = m.get_u32(prefixes[i] + "_plain_size", 0);
        if (m.has(prefixes[i] + "_file")) {
            const Bytes file = read_file(dir / m.get_path(prefixes[i] + "_file"));
            const bool same = m.has(prefixes[i] + "_orig_hash") && m.has(prefixes[i] + "_plain_size") && hash::sha256(file) == m.get_hex(prefixes[i] + "_orig_hash");
            if (!same) plain = file.size();
        }
        if (plain > 0xFFFFFFFFull) throw FormatError(shown(prefixes[i]) + " is more than 4 GiB: the header holds the size in 32 bits");
        e.plain_size = static_cast<uint32_t>(plain);
    }
    const Bytes core = splash::oplus_build(l);
    warn_stale_preamble(m, core, l.preamble);
    return assemble_envelope(m, dir, core, opt);
}

void print_oplus_logo_info(const Bytes& data) {
    const splash::OplusLogo l = splash::oplus_parse(data);
    std::cout << "header:         " << l.entries.size() << (l.entries.size() == 1 ? " picture" : " pictures") << ", version " << l.version << ", " << pixels_text(l.width, l.height)
              << ", compression word " << l.compression << "\n";
    for (size_t k = 0; k < l.desc.size(); ++k)
        if (!l.desc[k].empty()) std::cout << "description " << k << ":  " << shown(l.desc[k]) << "\n";
    if (!is_all_zero(l.preamble)) {
        const bool ddph = l.preamble.size() >= 4 && (uint32_t{l.preamble[0]} | (uint32_t{l.preamble[1]} << 8) | (uint32_t{l.preamble[2]} << 16) | (uint32_t{l.preamble[3]} << 24)) == splash::kDdphMagic;
        std::cout << "preamble:       " << l.preamble.size() << " bytes in front of the header" << (ddph ? ", begins with \"DDPH\"" : "") << " (kept as they are)\n";
    }
    uint64_t at = splash::kOplusDataAt;
    for (size_t i = 0; i < l.entries.size(); ++i) {
        const splash::OplusEntry& e = l.entries[i];
        std::cout << "  [" << i << "] " << shown(e.name) << ": " << e.data.size() << " bytes at " << hex_text(at);
        const Codec codec = detect_codec(e.data);
        std::cout << ", " << (codec == Codec::NONE ? std::string("not compressed") : std::string(codec_name(codec)));
        if (codec != Codec::NONE) {
            try {
                const DecodedComponent d = decode_component(e.data, {}, /*strip_mtk=*/false);
                std::cout << ", " << d.plain.size() << " bytes unpacked";
                if (d.level >= 0) std::cout << ", level " << d.level;
                std::cout << ", " << splash::picture_extension(d.plain);
            } catch (const FormatError& why) {
                std::cout << " (cannot be decompressed: " << why.what() << ")";
            }
        } else {
            std::cout << ", " << splash::picture_extension(e.data);
        }
        std::cout << ", the header says " << e.plain_size << " bytes unpacked\n";
        at += e.data.size();
    }
    print_envelope_info(Envelope::capture(data, 0, l.consumed));
}

// ---- xiaomi_logo: the "LOGO!!!!" image of Xiaomi and Redmi

void unpack_xiaomi_logo(const Bytes& data, const fs::path& dir) {
    const splash::XiaomiLogo l = splash::xiaomi_parse(data);
    const size_t n = l.pictures.size();
    Manifest m;
    m.set("type", "xiaomi_logo");
    if (!is_all_zero(l.preamble)) save_raw(m, dir, "preamble", l.preamble, "preamble.bin");
    save_raw(m, dir, "table_rest", l.table_rest, "table_rest.bin");
    m.set_u32("pictures", static_cast<uint32_t>(n));
    uint64_t work = 0;
    for (const Bytes& p : l.pictures) work += p.size();
    progress::enter("decode", work);
    std::vector<std::string> files(n);
    std::vector<size_t> content(n);
    par::for_each(n, [&](size_t i) {
        const Bytes& p = l.pictures[i];
        content[i] = splash::xiaomi_content_size(p);
        files[i] = splash_file_name(i, n, "picture", splash::picture_extension(p));
        const progress::Activity doing(files[i]);
        write_file(dir / files[i], p.data(), content[i]);
        progress::advance(p.size());
    });
    for (size_t i = 0; i < n; ++i) m.set("picture" + std::to_string(i) + "_file", files[i]);
    save_core_envelope(m, dir, data, l.consumed);

    std::cout << "Xiaomi logo: " << n << (n == 1 ? " picture" : " pictures") << "\n";
    uint64_t at = splash::kXiaomiPreamble + splash::kXiaomiTableSize;
    for (size_t i = 0; i < n; ++i) {
        std::cout << "  [" << i << "] " << splash::picture_extension(l.pictures[i]) << ": " << content[i] << " bytes at " << hex_text(at) << " (" << l.pictures[i].size() / splash::kXiaomiUnit
                  << (l.pictures[i].size() == splash::kXiaomiUnit ? " unit" : " units") << ") -> " << files[i] << "\n";
        at += l.pictures[i].size();
    }
    if (!is_all_zero(l.preamble))
        note("the " + std::to_string(l.preamble.size()) + " bytes in front of the table are not zeros: kept as they are (preamble.bin)");
    m.save(dir / "manifest.txt",
           "abr xiaomi_logo manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`\n"
           "# NOTE: picture<N>_file is the file of a picture, as the image holds it (a BMP; a PNG in some images). pack puts every file into whole units of 4096 bytes\n"
           "# (zeros behind it) and works out the table. To leave a picture out delete its key, number the ones behind it again and change pictures=.");
}

Bytes repack_xiaomi_logo(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    splash::XiaomiLogo l;
    l.preamble = load_raw(m, dir, "preamble");
    if (l.preamble.size() > splash::kXiaomiPreamble)
        throw FormatError("preamble.bin is " + std::to_string(l.preamble.size()) + " bytes; the bytes in front of the table are " + std::to_string(splash::kXiaomiPreamble));
    l.table_rest = load_raw(m, dir, "table_rest");
    const size_t n = m.get_count("pictures", 0);
    if (n == 0 || n > splash::kXiaomiMaxEntries)
        throw FormatError("manifest.txt: " + shown("pictures=" + m.get("pictures")) + " is the number of the pictures of the image, 1 to " + std::to_string(splash::kXiaomiMaxEntries));
    l.pictures.resize(n);
    for (size_t i = 0; i < n; ++i) {
        const std::string key = "picture" + std::to_string(i) + "_file";
        if (!m.has(key)) throw FormatError("manifest.txt: " + shown(key) + " is missing (the file of the picture)");
        const progress::Activity doing(m.get_path(key));
        l.pictures[i] = read_file(dir / m.get_path(key));
        progress::advance(l.pictures[i].size());
    }
    return assemble_envelope(m, dir, splash::xiaomi_build(l), opt);
}

void print_xiaomi_logo_info(const Bytes& data) {
    const splash::XiaomiLogo l = splash::xiaomi_parse(data);
    std::cout << "table:          " << l.pictures.size() << (l.pictures.size() == 1 ? " picture" : " pictures") << ", in units of " << splash::kXiaomiUnit << " bytes\n";
    if (!is_all_zero(l.preamble)) std::cout << "preamble:       " << l.preamble.size() << " bytes in front of the table, not zeros (kept as they are)\n";
    uint64_t at = splash::kXiaomiPreamble + splash::kXiaomiTableSize;
    for (size_t i = 0; i < l.pictures.size(); ++i) {
        const Bytes& p = l.pictures[i];
        std::cout << "  [" << i << "] " << splash::picture_extension(p) << ": " << splash::xiaomi_content_size(p) << " bytes at " << hex_text(at) << ", " << p.size() / splash::kXiaomiUnit
                  << (p.size() == splash::kXiaomiUnit ? " unit" : " units") << "\n";
        at += p.size();
    }
    if (!l.table_rest.empty()) std::cout << "table:          " << l.table_rest.size() << " more bytes behind the entries (kept)\n";
    print_envelope_info(Envelope::capture(data, 0, l.consumed));
}

// ---- moto_logo: the "MotoLogo" image of Motorola

bool is_moto_run(const Bytes& b) { return b.size() >= splash::kMotoHeaderSize && std::memcmp(b.data(), "MotoRun\0", 8) == 0; }

void unpack_moto_logo(const Bytes& data, const fs::path& dir) {
    const splash::MotoLogo l = splash::moto_parse(data);
    const size_t n = l.entries.size();
    Manifest m;
    m.set("type", "moto_logo");
    m.set_u32("entries", static_cast<uint32_t>(n));
    m.set_u32("align", l.align);
    m.set_addr("header_fill", l.header_fill);
    m.set_addr("gap_fill", l.gap_fill);

    // A "MotoRun" picture becomes a PNG, as many as the memory allows; every other picture, and one that is not a whole MotoRun picture after all, stays the file it is.
    std::vector<char> as_png(n, 0);
    uint64_t used = 0, work = 0;
    for (size_t i = 0; i < n; ++i) {
        const Bytes& b = l.entries[i].data;
        work += b.size();
        if (!is_moto_run(b)) continue;
        const uint64_t px = uint64_t{static_cast<uint32_t>(b[8] << 8 | b[9])} * static_cast<uint32_t>(b[10] << 8 | b[11]) * 3;
        if (used + px > kSplashPixelLimit) continue;
        as_png[i] = 1;
        used += px;
    }
    if (std::any_of(as_png.begin(), as_png.end(), [](char c) { return c != 0; })) fs::create_directories(dir / ".abr_raw");
    progress::enter("decode", work);
    std::vector<std::string> files(n);
    std::vector<PictureFile> pictures(n);
    par::for_each(n, [&](size_t i) {
        const splash::MotoEntry& e = l.entries[i];
        if (e.data.empty()) return;
        if (as_png[i]) {
            const std::string name = splash_file_name(i, n, e.name, "png");
            const progress::Activity doing(name);
            if (const std::optional<splash::Bitmap> bmp = splash::moto_decode(e.data)) {
                files[i] = name;
                pictures[i] = write_picture(dir, name, "motorun", *bmp, e.data);
                progress::advance(e.data.size());
                return;
            }
            as_png[i] = 0;
        }
        files[i] = splash_file_name(i, n, e.name, splash::picture_extension(e.data));
        const progress::Activity doing(files[i]);
        write_file(dir / files[i], e.data);
        progress::advance(e.data.size());
    });
    for (size_t i = 0; i < n; ++i) {
        const splash::MotoEntry& e = l.entries[i];
        const std::string prefix = "entry" + std::to_string(i);
        m.set(prefix + "_name", e.name);
        m.set_tail(prefix + "_name_tail", e.name_tail);
        if (e.data.empty()) continue;  // (an empty slot)
        if (as_png[i]) {
            record_picture(m, prefix, pictures[i], "motorun");
        } else {
            m.set(prefix + "_file", files[i]);
            m.set(prefix + "_compression", "none");
        }
    }
    save_core_envelope(m, dir, data, l.consumed);
    drop_empty_raw_dir(dir);

    size_t pics = 0;
    for (const splash::MotoEntry& e : l.entries) pics += e.data.empty() ? 0 : 1;
    std::cout << "Motorola logo: " << n << (n == 1 ? " entry" : " entries") << ", " << pics << (pics == 1 ? " picture" : " pictures") << ", at multiples of " << l.align << "\n";
    for (size_t i = 0; i < n; ++i) {
        const splash::MotoEntry& e = l.entries[i];
        const size_t at = splash::kMotoTableAt + i * splash::kMotoEntrySize + splash::kMotoNameSize;
        std::cout << "  [" << i << "] " << shown(e.name) << ": ";
        if (e.data.empty()) {
            std::cout << "empty slot\n";
            continue;
        }
        const uint32_t offset = static_cast<uint32_t>(data[at] | (data[at + 1] << 8) | (data[at + 2] << 16) | (uint32_t{data[at + 3]} << 24));
        std::cout << e.data.size() << " bytes at " << hex_text(offset) << ", ";
        if (as_png[i]) std::cout << "MotoRun " << pixels_text(pictures[i].width, pictures[i].height) << " -> " << files[i] << "\n";
        else std::cout << "kept as it is -> " << files[i] << "\n";
    }
    m.save(dir / "manifest.txt",
           "abr moto_logo manifest -- edit then `abr pack -i " + dir.string() + " -o out.img`\n"
           "# NOTE: a MotoRun picture is a PNG (entry<N>_file, entry<N>_compression=motorun): unchanged, it goes back as the very bytes it was; changed, it is run-length\n"
           "# coded again. Any other picture is the file it is. pack puts the pictures at multiples of align, filled up with header_fill (up to the first) and gap_fill (between\n"
           "# two), and works out the table. An entry with no entry<N>_file is an empty slot.");
}

Bytes repack_moto_logo(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    const size_t n = m.get_count("entries", 0);
    if (n == 0 || n > splash::kMotoMaxEntries)
        throw FormatError("manifest.txt: " + shown("entries=" + m.get("entries")) + " is the number of the entries of the table, 1 to " + std::to_string(splash::kMotoMaxEntries));
    splash::MotoLogo l;
    l.align = m.get_u32("align", 512);
    l.header_fill = static_cast<uint8_t>(m.get_bounded("header_fill", 0xFF, 8));
    l.gap_fill = static_cast<uint8_t>(m.get_bounded("gap_fill", 0xFF, 8));
    l.entries.resize(n);
    par::for_each(n, [&](size_t i) {
        const std::string prefix = "entry" + std::to_string(i);
        splash::MotoEntry& e = l.entries[i];
        e.name = m.get(prefix + "_name");
        e.name_tail = m.get_tail(prefix + "_name_tail");
        if (!m.has(prefix + "_file")) return;  // an empty slot
        if (m.has(prefix + "_width")) {
            const std::string coding = m.get(prefix + "_compression", "motorun");
            if (coding != "motorun")
                throw FormatError("manifest.txt: " + shown(prefix + "_compression=" + coding) + " is not motorun (the pictures that abr decodes of this image are run-length coded as MotoRun)");
            PictureCoding how;
            how.decode = [](const Bytes& raw) { return splash::moto_decode(raw); };
            how.encode = [](const splash::Bitmap& bmp) { return splash::moto_encode(bmp); };
            LoadedPicture loaded = load_picture(m, dir, prefix, coding, how);
            if (!loaded.replayed) note_new_size(m.get_path(prefix + "_file"), loaded.pixels, m.get_u32(prefix + "_width", 0), m.get_u32(prefix + "_height", 0));
            e.data = std::move(loaded.stored);
        } else {
            const std::string coding = m.get(prefix + "_compression", "none");
            if (coding != "none") throw FormatError("manifest.txt: " + shown(prefix + "_compression=" + coding) + " is not none (the picture is put into the image as the file it is)");
            const progress::Activity doing(m.get_path(prefix + "_file"));
            e.data = read_file(dir / m.get_path(prefix + "_file"));
            progress::advance(e.data.size());
        }
    });
    return assemble_envelope(m, dir, splash::moto_build(l), opt);
}

void print_moto_logo_info(const Bytes& data) {
    const splash::MotoLogo l = splash::moto_parse(data);
    size_t pics = 0;
    for (const splash::MotoEntry& e : l.entries) pics += e.data.empty() ? 0 : 1;
    std::cout << "table:          " << l.entries.size() << (l.entries.size() == 1 ? " entry" : " entries") << ", " << pics << (pics == 1 ? " picture" : " pictures") << "\n";
    std::cout << "alignment:      the pictures lie at multiples of " << l.align << ", filled up with " << hex_text(l.header_fill) << " in front of the first and " << hex_text(l.gap_fill)
              << " between them\n";
    for (size_t i = 0; i < l.entries.size(); ++i) {
        const splash::MotoEntry& e = l.entries[i];
        const size_t at = splash::kMotoTableAt + i * splash::kMotoEntrySize + splash::kMotoNameSize;
        std::cout << "  [" << i << "] " << shown(e.name) << ": ";
        if (e.data.empty()) {
            std::cout << "empty slot\n";
            continue;
        }
        const uint32_t offset = static_cast<uint32_t>(data[at] | (data[at + 1] << 8) | (data[at + 2] << 16) | (uint32_t{data[at + 3]} << 24));
        std::cout << e.data.size() << " bytes at " << hex_text(offset) << ", ";
        if (is_moto_run(e.data)) std::cout << "MotoRun " << pixels_text(static_cast<uint32_t>(e.data[8] << 8 | e.data[9]), static_cast<uint32_t>(e.data[10] << 8 | e.data[11])) << "\n";
        else std::cout << splash::picture_extension(e.data) << "\n";
    }
    print_envelope_info(Envelope::capture(data, 0, l.consumed));
}

// ------------------------------------------------------------------ layout --
//
// Where the parts of an image are (abr/layout.hpp). `unpack` says it of the image it took apart, `pack` of the image it built and `info`
// of the image it is asked about -- always from the bytes of that image, read again, so that the three tell the same numbers; `unpack`
// and `pack` also keep it in the layout block at the end of manifest.txt.

// The component a KRNL payload becomes at unpack: a ramdisk when it is a cpio archive (an empty one is a ramdisk too), else a kernel.
std::string krnl_prefix(const Bytes& payload) {
    try {
        const DecodedComponent part = decode_component(payload);
        return part.plain.size() < 5 || std::memcmp(part.plain.data(), "07070", 5) == 0 ? "ramdisk" : "kernel";
    } catch (const std::exception&) {
        return "kernel";
    }
}

// data[off, off + len) -- `data` itself when that is all of it, so that a plain image is not copied again.
const Bytes& part_of(const Bytes& data, size_t off, size_t len, Bytes& storage) {
    if (off == 0 && len == data.size()) return data;
    storage.assign(data.begin() + static_cast<long>(off), data.begin() + static_cast<long>(off + len));
    return storage;
}

// `whole` (an image with its wrappers taken off) read as a `f`. nullopt for a format whose layout abr does not tell, and for bytes that are
// not one after all.
std::optional<layout::Layout> describe_layout(Fmt f, const Bytes& whole) {
    try {
        Bytes storage;
        switch (f) {
            case Fmt::BOOT: {
                const AvbFooter footer = detect_avb_footer(whole);
                const size_t off = find_container(whole, "ANDROID!");
                if (off == std::string::npos || off >= footer.host_size) return std::nullopt;
                const BootImage img = BootImage::parse(part_of(whole, off, footer.host_size - off, storage));
                layout::Layout l = layout::boot(img);
                layout::around(l, whole, footer.host_size, off, img.consumed);
                return l;
            }
            case Fmt::VENDOR_BOOT: {
                const AvbFooter footer = detect_avb_footer(whole);
                const size_t off = find_magic(whole, "VNDRBOOT", 8);
                if (off == std::string::npos || off >= footer.host_size) return std::nullopt;
                const VendorBootImage img = VendorBootImage::parse(part_of(whole, off, footer.host_size - off, storage));
                layout::Layout l = layout::vendor_boot(img);
                layout::around(l, whole, footer.host_size, off, img.consumed);
                return l;
            }
            case Fmt::DTBO: {
                const AvbFooter footer = detect_avb_footer(whole);
                const Bytes& host = part_of(whole, 0, footer.host_size, storage);
                const DtboImage img = DtboImage::parse(host);
                layout::Layout l = layout::dtbo(host);
                layout::around(l, whole, footer.host_size, 0, img.consumed);
                return l;
            }
            case Fmt::DTB: {
                const FdtBlobs split = split_fdt_blobs(whole);
                std::vector<size_t> sizes;
                for (const Bytes& b : split.blobs) sizes.push_back(b.size());
                layout::Layout l = layout::dtb_blobs(sizes);
                layout::around(l, whole, whole.size(), 0, split.consumed);
                return l;
            }
            case Fmt::QCDT: {
                const qcdt::Table t = qcdt::parse(whole);
                layout::Layout l = layout::qcdt(whole);
                layout::around(l, whole, whole.size(), 0, t.consumed);
                return l;
            }
            case Fmt::VBMETA: {
                const VbmetaImage v = VbmetaImage::parse(whole);
                if (v.has_footer) {  // an AVB footer behind something abr has no reader for: the image it protects is one lump
                    layout::Layout l;
                    l.format = "AVB hash footer behind another image";
                    l.add("protected image", "", 0, v.footer_original_image_size);
                    layout::around(l, whole, v.footer_original_image_size, 0, v.footer_original_image_size);
                    return l;
                }
                layout::Layout l = layout::vbmeta_image(whole);
                uint64_t end = 0;
                for (const layout::Region& r : l.regions) end = std::max(end, r.offset + r.size);
                layout::around(l, whole, whole.size(), 0, end);
                return l;
            }
            case Fmt::UIMAGE: {
                const UImage img = UImage::parse(whole);
                layout::Layout l = layout::uimage(img);
                layout::around(l, whole, whole.size(), 0, img.consumed);
                return l;
            }
            case Fmt::FIT: {
                std::string why;
                const std::optional<fit::Opened> o = fit::open(whole, why);
                if (!o) return std::nullopt;  // (it is a plain device tree then)
                const std::vector<FitName> names = fit_names(o->images);
                std::vector<std::string> keys;  // by the child of /images
                for (size_t i = 0; i < o->images.size(); ++i) {
                    if (o->images[i].data.empty()) continue;
                    if (keys.size() <= o->images[i].index) keys.resize(o->images[i].index + 1);
                    keys[o->images[i].index] = names[i].prefix;
                }
                layout::Layout l = layout::fit(whole, keys);
                layout::around(l, whole, whole.size(), 0, o->consumed);
                return l;
            }
            case Fmt::ELF_BOOT: {
                const legacy::ElfBootImage img = legacy::ElfBootImage::parse(whole);
                layout::Layout l = layout::elf_boot(img, whole, elf_names(img.segments).prefix);
                layout::around(l, whole, whole.size(), 0, whole.size());
                return l;
            }
            case Fmt::KRNL: {
                const legacy::KrnlImage img = legacy::KrnlImage::parse(whole);
                layout::Layout l = layout::krnl(img, krnl_prefix(img.payload));
                layout::around(l, whole, whole.size(), 0, img.file_size());
                return l;
            }
            case Fmt::BLOB: {
                const legacy::BlobImage img = legacy::BlobImage::parse(whole);
                layout::Layout l = layout::blob(img);
                layout::around(l, whole, whole.size(), 0, whole.size());
                return l;
            }
            case Fmt::OSIP: {
                const OsipImage img = OsipImage::parse(whole);
                layout::Layout l = layout::osip(img);
                layout::around(l, whole, whole.size(), 0, img.consumed);
                return l;
            }
            case Fmt::CHROMEOS: {
                Bytes kernel;
                const std::optional<legacy::ChromeosInfo> c = legacy::strip_chromeos(whole, kernel);
                if (!c) return std::nullopt;
                layout::Layout l = layout::chromeos(*c, whole);
                layout::around(l, whole, whole.size(), 0, c->core_size);
                return l;
            }
            case Fmt::MTK_IMAGE: {
                layout::Layout l = layout::mtk_image(whole);
                if (l.regions.empty()) return std::nullopt;
                size_t consumed = 0;
                (void)mtkimg::scan(whole, &consumed);
                layout::around(l, whole, whole.size(), 0, consumed);
                return l;
            }
            case Fmt::MTK_PRELOADER: {
                layout::Layout l = layout::mtk_preloader(whole);
                if (l.regions.empty()) return std::nullopt;
                layout::around(l, whole, whole.size(), 0, mtkgfh::parse(whole).consumed);
                return l;
            }
            case Fmt::MBN: {
                layout::Layout l = layout::mbn(whole);
                if (l.regions.empty()) return std::nullopt;
                layout::around(l, whole, whole.size(), 0, mbn::parse_block(whole, 0, whole.size()).consumed);
                return l;
            }
            case Fmt::MBN_ELF: {
                layout::Layout l = layout::mbn_elf(whole);
                if (l.regions.empty()) return std::nullopt;
                layout::around(l, whole, whole.size(), 0, mbn::parse_elf(whole).consumed);
                return l;
            }
            case Fmt::SPLASH: {
                layout::Layout l = layout::qc_splash(whole);
                if (l.regions.empty()) return std::nullopt;
                layout::around(l, whole, whole.size(), 0, splash::qc_parse(whole).consumed);
                return l;
            }
            case Fmt::OPLUS_LOGO: {
                layout::Layout l = layout::oplus_logo(whole);
                if (l.regions.empty()) return std::nullopt;
                layout::around(l, whole, whole.size(), 0, splash::oplus_parse(whole).consumed);
                return l;
            }
            case Fmt::XIAOMI_LOGO: {
                layout::Layout l = layout::xiaomi_logo(whole);
                if (l.regions.empty()) return std::nullopt;
                layout::around(l, whole, whole.size(), 0, splash::xiaomi_parse(whole).consumed);
                return l;
            }
            case Fmt::MOTO_LOGO: {
                layout::Layout l = layout::moto_logo(whole);
                if (l.regions.empty()) return std::nullopt;
                layout::around(l, whole, whole.size(), 0, splash::moto_parse(whole).consumed);
                return l;
            }
            default:
                return std::nullopt;
        }
    } catch (const FormatError&) {
        return std::nullopt;
    }
}

// What the manifest of an unpacked folder says about the parts the layout names by their keys: the file each became, and the compression it
// was in (and at what level, where that is known). A manifest that cannot be read leaves the layout as it is.
void annotate_layout(layout::Layout& l, const Manifest& m, const fs::path& dir) {
    for (layout::Region& r : l.regions) {
        if (r.key.empty() || !m.has(r.key + "_file")) continue;
        try {
            const std::string codec = m.get(r.key + "_compression", "none");
            r.file = m.get(r.key + "_file");
            r.codec = codec == "none" ? std::string() : codec;
            std::error_code ec;
            const uintmax_t size = fs::file_size(dir / r.file, ec);
            r.unpacked = ec ? 0 : size;
            r.level = static_cast<int>(m.get_int(r.key + "_level", -1, -1, 22));
            if (m.has(r.key + "_tree")) r.file += " + " + m.get(r.key + "_tree") + "/";
        } catch (const std::exception&) {
        }
    }
}

// Tells where the parts of `image` (read as a `f`, wrappers off) are -- the table on the console -- and keeps it in the layout block of the
// manifest of `dir`. `what` goes into the comment of that block, `name` into the line before the table. Never an error: a layout that
// cannot be worked out is a warning.
void report_layout(Fmt f, const Bytes& image, const Wrappers& wrap, const fs::path& dir, const std::string& what, const std::string& name) {
    try {
        std::optional<layout::Layout> l = describe_layout(f, image);
        if (!l) return;
        const fs::path manifest_file = dir / "manifest.txt";
        Manifest m;
        try {
            m = Manifest::load(manifest_file);
        } catch (const std::exception&) {
        }
        annotate_layout(*l, m, dir);
        std::cout << "layout of " << name << " (" << l->format << ", " << l->size << " bytes"
                  << (wrap.recorded() || wrap.sin ? "; offsets are those of the plain image inside its wrapper" : "") << "):\n"
                  << layout::render(*l);
        layout::write_manifest_block(manifest_file, *l, what);
    } catch (const std::exception& e) {
        warn(std::string("could not work out where the parts of the image are: ") + e.what());
    }
}

// `info` has no folder to ask: what a look into each stream of the layout adds is how big its plain data is and the level it was made with
// (decode_component(), as `unpack` does it, on all the threads there are). A stream that cannot be decompressed stays as it was.
void annotate_streams(layout::Layout& l, const Bytes& image) {
    std::vector<layout::Region*> streams;
    for (layout::Region& r : l.regions)
        if (!r.codec.empty() && r.file.empty() && r.size && r.offset + r.size <= image.size()) streams.push_back(&r);
    par::for_each(streams.size(), [&](size_t i) {
        layout::Region& r = *streams[i];
        try {
            const auto first = image.begin() + static_cast<std::ptrdiff_t>(r.offset);
            const DecodedComponent d = decode_component(Bytes(first, first + static_cast<std::ptrdiff_t>(r.size)));
            if (d.codec == Codec::NONE) return;
            r.unpacked = d.plain.size();
            r.level = d.level;
        } catch (const std::exception&) {
        }
    });
}

void print_info(const fs::path& path) {
    Bytes raw = read_file(path);
    Wrappers wrap;
    const Bytes& data = peel_wrappers(raw, wrap);

    Fmt f = detect_format(data);
    std::cout << "file:   " << path.string() << " (" << raw.size() << " bytes)\n";
    if (wrap.sin) {
        std::cout << "wrapper: " << legacy::describe_sin(*wrap.sin)
                  << " (abr unpacks the image inside; a repack writes that image, not a SIN)\n";
        for (const std::string& n : wrap.sin->notes) std::cout << "  note: " << n << "\n";
    }
    if (wrap.chromeos) {
        std::cout << "wrapper: ChromeOS kernel blob (" << chromeos_description(*wrap.chromeos)
                  << (wrap.chromeos->tail.empty()
                          ? ""
                          : "; " + std::to_string(wrap.chromeos->tail.pad_to ? wrap.chromeos->tail.pad_to - wrap.chromeos->core_size
                                                                              : wrap.chromeos->tail.tail.size()) +
                                " bytes follow the blob")
                  << ")\n";
    }
    if (wrap.dhtb) {
        std::cout << "wrapper: DHTB (" << (wrap.dhtb->has_seandroid_footer ? "+SEAndroid footer " : "")
                   << (wrap.dhtb->has_padding ? "+padding " : "") << ", inner " << wrap.dhtb_inner.size()
                   << " bytes)\n";
    }
    if (wrap.blob) {
        const legacy::BlobPart& part = wrap.blob->parts[0];
        std::cout << "wrapper: ASUS blob (" << (wrap.blob->secure ? "signed header, " : "") << "partition "
                  << (blob_name_is_word(part.name) ? blob_name_word(part.name) : std::string("?")) << ", inner "
                  << wrap.blob_inner.size() << " bytes)\n";
    }
    if (wrap.amonet) {
        std::cout << "wrapper: AMONET patch (a " << wrap.amonet->microloader.size()
                   << "-byte microloader at the start; the boot image's first " << legacy::kAmonetHeadSize
                   << " bytes are at offset " << legacy::kAmonetMicroloaderSize << ")\n";
    }
    if (wrap.loki) {
        const legacy::LokiInfo& l = *wrap.loki;
        std::cout << "wrapper: LOKI patch (" << (l.recovery == 0 ? "boot" : l.recovery == 1 ? "recovery" : "type " + std::to_string(l.recovery))
                  << ", build \"" << loki_build_shown(l.build) << "\"; " << l.block.size()
                  << " bytes of the bootloader's code with the patch code behind the ramdisk"
                  << (l.tail.empty() ? ""
                                     : "; " + std::to_string(l.tail.pad_to ? l.tail.pad_to - l.core_size : l.tail.tail.size()) +
                                           " bytes follow the image")
                  << ")\n";
    }
    std::cout << "format: " << fmt_name(f) << "\n";
    switch (f) {
        case Fmt::BOOT: {
            AvbFooter footer = detect_avb_footer(data);
            Bytes host(data.begin(), data.begin() + static_cast<long>(footer.host_size));
            size_t off = find_container(host, "ANDROID!");
            BootImage img = BootImage::parse(Bytes(host.begin() + static_cast<long>(off), host.end()));
            std::cout << "header_version: " << img.header_version << "\n";
            if (img.pxa) {
                char word[16];
                std::snprintf(word, sizeof word, "0x%08x", img.pxa_unknown);
                std::cout << "variant:        Marvell PXA header (unknown=" << word << ")\n";
            }
            if (img.header_version <= 2) std::cout << "page_size:      " << img.page_size << "\n";
            std::cout << "os_version:     " << img.os_version.to_string() << "\n";
            std::cout << "patch_level:    " << img.os_version.patch_level_string() << "\n";
            std::cout << "cmdline:        " << shown(img.cmdline) << "\n";
            if (const std::string t = tails_text({{"board_name", &img.board_name_tail},
                                                  {"cmdline", &img.cmdline_tail},
                                                  {"extra_cmdline", &img.extra_cmdline_tail}});
                !t.empty())
                std::cout << "field tails:    " << t << " (bytes behind the NUL that ends the text, kept)\n";
            std::cout << "kernel:         " << img.kernel.size() << " bytes ("
                       << codec_name(detect_codec(img.kernel)) << ")\n";
            std::cout << "ramdisk:        " << img.ramdisk.size() << " bytes ("
                       << codec_name(detect_codec(img.ramdisk)) << ")\n";
            if (!img.second.empty()) std::cout << "second:         " << img.second.size() << " bytes\n";
            if (!img.dt.empty()) {
                std::cout << "dt (QCDT):      " << img.dt.size() << " bytes";
                if (qcdt::looks_like(img.dt)) {
                    std::string about;
                    try {
                        about = qcdt_summary(qcdt::parse(img.dt, img.page_size));
                    } catch (const FormatError& e) {
                        about = std::string("kept as a file: ") + e.what();
                    }
                    std::cout << " (" << about << ")";
                }
                std::cout << "\n";
            }
            if (!img.recovery_dtbo.empty())
                std::cout << "recovery_dtbo:  " << img.recovery_dtbo.size() << " bytes\n";
            if (!img.dtb.empty()) std::cout << "dtb:            " << img.dtb.size() << " bytes\n";
            if (!img.boot_signature.empty())
                std::cout << "boot_signature: " << img.boot_signature.size() << " bytes\n";
            if (img.header_version <= 2)
                std::cout << "id scheme:      " << id_scheme_name(img.id_scheme) << "\n";
            if (const std::string t = padding_text(img.section_padding, BootImage::kSectionNames); !t.empty())
                std::cout << "section padding: " << t << " (bytes that are not zero behind the end of a component, kept)\n";
            Envelope env = Envelope::capture(host, off, img.consumed);
            print_envelope_info(env);
            print_avb1_info(env, host, off, img.consumed);
            print_avb_footer_info(footer, host);
            break;
        }
        case Fmt::VENDOR_BOOT: {
            AvbFooter footer = detect_avb_footer(data);
            Bytes host(data.begin(), data.begin() + static_cast<long>(footer.host_size));
            size_t off = find_magic(host, "VNDRBOOT", 8);
            VendorBootImage img =
                VendorBootImage::parse(Bytes(host.begin() + static_cast<long>(off), host.end()));
            std::cout << "header_version: " << img.header_version << "\n";
            std::cout << "page_size:      " << img.page_size << "\n";
            std::cout << "cmdline:        " << shown(img.cmdline) << "\n";
            if (const std::string t = tails_text({{"board_name", &img.board_name_tail}, {"cmdline", &img.cmdline_tail}});
                !t.empty())
                std::cout << "field tails:    " << t << " (bytes behind the NUL that ends the text, kept)\n";
            std::cout << "dtb:            " << img.dtb.size() << " bytes\n";
            std::cout << "bootconfig:     " << img.bootconfig.size() << " bytes\n";
            std::cout << "ramdisk fragments: " << img.ramdisk_fragments.size() << "\n";
            for (size_t i = 0; i < img.ramdisk_fragments.size(); ++i) {
                auto& e = img.ramdisk_fragments[i];
                std::cout << "  [" << i << "] type=" << vendor_ramdisk_type_name(e.type)
                          << " name=" << (e.name.empty() ? "-" : shown(e.name)) << " size=" << e.data.size()
                          << " (" << codec_name(detect_codec(e.data)) << ")\n";
            }
            if (const std::string t = padding_text(img.section_padding, VendorBootImage::kSectionNames); !t.empty())
                std::cout << "section padding: " << t << " (bytes that are not zero behind the end of a section, kept)\n";
            print_envelope_info(Envelope::capture(host, off, img.consumed));
            print_avb_footer_info(footer, host);
            break;
        }
        case Fmt::DTBO: {
            AvbFooter footer = detect_avb_footer(data);
            Bytes host(data.begin(), data.begin() + static_cast<long>(footer.host_size));
            DtboImage img = DtboImage::parse(host);
            std::cout << "version:   " << img.version << (img.acpio ? " (ACPIO)" : " (DTBO)") << "\n";
            std::cout << "entries:   " << img.entries.size() << "\n";
            for (size_t i = 0; i < img.entries.size(); ++i)
                std::cout << "  [" << i << "] id=0x" << std::hex << img.entries[i].id << std::dec
                          << " rev=" << img.entries[i].rev << " size=" << img.entries[i].data.size()
                          << "\n";
            print_envelope_info(Envelope::capture(host, 0, img.consumed));
            print_avb_footer_info(footer, host);
            break;
        }
        case Fmt::DTB: {
            const FdtBlobs split = split_fdt_blobs(data);
            std::cout << "fdt blobs: " << split.blobs.size() << "\n";
            for (size_t i = 0; i < split.blobs.size(); ++i)
                std::cout << "  [" << i << "] " << split.blobs[i].size() << " bytes\n";
            print_envelope_info(Envelope::capture(data, 0, split.consumed));
            break;
        }
        case Fmt::QCDT: {
            qcdt::Table t;
            try {
                t = qcdt::parse(data);
            } catch (const FormatError& e) {
                std::cout << "unpack:      no, " << e.what() << "\n";
                break;
            }
            std::cout << "table:       " << qcdt_summary(t) << "\n";
            for (size_t i = 0; i < t.entries.size(); ++i) {
                const qcdt::Entry& e = t.entries[i];
                char line[200];
                std::snprintf(line, sizeof line, "chipset=0x%x platform=0x%x", e.chipset, e.platform);
                std::cout << "  [" << i << "] " << line;
                if (t.version >= 2) std::cout << " subtype=0x" << std::hex << e.subtype << std::dec;
                std::cout << " revision=0x" << std::hex << e.revision << std::dec;
                if (t.version >= 3) {
                    std::cout << " pmic=";
                    for (size_t k = 0; k < e.pmic.size(); ++k) std::cout << (k ? "," : "") << "0x" << std::hex << e.pmic[k] << std::dec;
                }
                std::cout << " -> device tree " << e.dtb << "\n";
            }
            for (size_t j = 0; j < t.dtbs.size(); ++j) std::cout << "  device tree " << j << ": " << t.dtbs[j].size() << " bytes\n";
            print_envelope_info(Envelope::capture(data, 0, t.consumed));
            break;
        }
        case Fmt::FIT: {
            fdt::Layout fl;
            const fdt::Tree tree = fdt::parse(data, &fl);
            const fdt::Node* images = tree.root.find_child("images");
            std::string text;
            if (tree.root.get_string("description", text)) std::cout << "description: " << shown(text) << "\n";
            std::cout << "tree:        " << fl.total_size << " bytes (flattened device tree version " << tree.version
                      << (fl.canonical ? "" : "; not laid out the way dtc writes one: " + fl.why) << ")\n";
            std::cout << "images:      " << images->children.size() << "\n";
            for (size_t i = 0; i < images->children.size(); ++i) {
                const fdt::Node& n = images->children[i];
                uint64_t size = 0, where = 0;
                std::string place = "no data";
                if (const fdt::Property* d = n.find_prop("data")) {
                    size = d->value.size();
                    place = "in the tree";
                } else if (n.get_u64("data-size", size)) {
                    if (n.get_u64("data-offset", where)) place = "behind the tree, data-offset " + std::to_string(where);
                    else if (n.get_u64("data-position", where)) place = "behind the tree, data-position " + std::to_string(where);
                }
                std::cout << "  [" << i << "] " << shown(n.name) << ": " << size << " bytes, " << place;
                if (const std::string d = fit::describe_image(n); !d.empty()) std::cout << "; " << d;
                std::cout << "\n";
            }
            for (const std::string& c : fit::describe_configurations(tree)) std::cout << "  configuration " << c << "\n";
            if (const std::vector<std::string> sigs = fit::signatures(tree); !sigs.empty())
                std::cout << "signatures:  " << sigs.size() << " (abr checks none of them and signs none)\n";
            std::string why;
            if (const std::optional<fit::Opened> o = fit::open(data, why)) {
                std::cout << "unpack:      as a FIT image (the data is " << fit::place_name(o->layout.place) << ")\n";
                for (const std::string& w : fit::wrong_hashes(o->tree, o->images)) std::cout << "hash:        " << w << "\n";
                print_envelope_info(Envelope::capture(data, 0, o->consumed));
            } else {
                std::cout << "unpack:      as a plain device tree, because " << why << "\n";
            }
            break;
        }
        case Fmt::VBMETA: {
            VbmetaImage v = VbmetaImage::parse(data);
            std::cout << "algorithm:  " << avb_algorithm_name(v.algorithm_type) << "\n";
            if (!v.public_key.empty()) std::cout << "public key: " << avb_key_text(v.public_key) << "\n";
            std::cout << "flags:      " << v.flags << "\n";
            std::cout << "rollback:   " << v.rollback_index << " @location "
                       << v.rollback_index_location << "\n";
            std::cout << "release:    " << shown(v.release_string) << "\n";
            if (const std::string t = tails_text({{"release_string", &v.release_string_tail}, {"reserved", &v.reserved}});
                !t.empty())
                std::cout << "unmodeled:  " << t << " (bytes of the header behind the release text and in the reserved area, kept)\n";
            std::cout << "has_footer: " << (v.has_footer ? "yes" : "no") << "\n";
            std::cout << "descriptors: " << v.descriptors.size() << "\n";
            for (auto& d : v.descriptors) std::cout << "  - " << d.describe() << "\n";
            break;
        }
        case Fmt::UIMAGE: {
            UImage img = UImage::parse(data);
            std::cout << "name:        " << shown(img.name) << "\n";
            if (const std::string t = tails_text({{"name", &img.name_tail}}); !t.empty())
                std::cout << "name tail:   " << t << " (bytes behind the NUL that ends the text, kept)\n";
            std::cout << "os/arch:     " << uboot_os_name(img.os) << "/" << uboot_arch_name(img.arch)
                       << "\n";
            std::cout << "type:        " << uboot_type_name(img.type) << "\n";
            std::cout << "compression: " << uboot_comp_name(img.comp) << "\n";
            std::cout << "data:        " << img.data.size() << " bytes\n";
            print_envelope_info(Envelope::capture(data, 0, img.consumed));
            break;
        }
        case Fmt::BLOB: {
            legacy::BlobImage b = legacy::BlobImage::parse(data);
            if (b.secure) {
                std::cout << "secure header:  datalen " << b.secure_datalen << ", siglen " << b.secure_siglen << "\n";
            } else {
                std::cout << "secure header:  none\n";
            }
            std::cout << "partitions:     " << b.parts.size() << "\n";
            for (size_t i = 0; i < b.parts.size(); ++i) {
                const legacy::BlobPart& p = b.parts[i];
                std::cout << "  [" << i << "] " << (blob_name_is_word(p.name) ? blob_name_word(p.name) : std::string("?"))
                          << ": " << p.data.size() << " bytes, version " << p.version;
                const Fmt held = detect_format(p.data);
                if (held != Fmt::UNKNOWN && held != Fmt::BLOB) std::cout << ", " << fmt_name(held);
                std::cout << "\n";
            }
            if (!b.tail.empty()) std::cout << "tail:           " << b.tail.size() << " bytes (a signature?)\n";
            break;
        }
        case Fmt::KRNL: {
            legacy::KrnlImage img = legacy::KrnlImage::parse(data);
            std::cout << "payload:        " << img.payload.size() << " bytes (" << codec_name(detect_codec(img.payload)) << ")\n";
            char word[16];
            std::snprintf(word, sizeof word, "0x%08x", img.crc);
            std::cout << "crc:            " << word << (img.crc_ok ? " (matches the payload)" : " (does NOT match the payload)") << "\n";
            print_envelope_info(Envelope::capture(data, 0, img.file_size()));
            break;
        }
        case Fmt::OSIP: {
            OsipImage img = OsipImage::parse(data);
            if (img.header.empty()) {
                std::cout << "header:         none\n";
            } else {
                const uint64_t expected = align_up(img.consumed, kOsipSectorSize) / kOsipSectorSize - 1;
                const uint32_t sectors = osip_header_sectors(img.header);
                std::cout << "header:         " << img.header.size() << " bytes, " << osip_type_name(osip_header_attribute(img.header))
                          << ", " << sectors << " sectors"
                          << (sectors == expected ? std::string() : " (the image has " + std::to_string(expected) + ")")
                          << ", checksum " << (osip_header_checksum_ok(img.header) ? "OK" : "WRONG") << "\n";
            }
            std::cout << "signature:      "
                      << (img.signature.empty() ? std::string("none") : std::to_string(img.signature.size()) + " bytes") << "\n";
            std::cout << "cmdline:        " << shown(img.cmdline_text()) << "\n";
            std::cout << "bootstub:       " << img.bootstub.size() << " bytes\n";
            std::cout << "kernel:         " << img.kernel.size() << " bytes\n";
            std::cout << "ramdisk:        " << img.ramdisk.size() << " bytes (" << codec_name(detect_codec(img.ramdisk)) << ")\n";
            std::string parameter;
            for (uint8_t b : img.parameter) {
                char two[4];
                std::snprintf(two, sizeof two, "%02x", b);
                parameter += two;
            }
            std::cout << "parameter:      " << parameter << "\n";
            print_envelope_info(Envelope::capture(data, 0, osip_padding(data, img.consumed).core_size));
            break;
        }
        case Fmt::ELF_BOOT: {
            legacy::ElfBootImage img = legacy::ElfBootImage::parse(data);
            std::cout << "class:    " << (img.is_64bit ? "ELF64" : "ELF32") << "\n";
            std::cout << "machine:  " << img.machine << "\n";
            if (img.entry) std::cout << "entry:    0x" << std::hex << *img.entry << std::dec << "\n";
            std::cout << "segments: " << img.segments.size() << "\n";
            for (auto& s : img.segments)
                std::cout << "  - " << s.role << " (flags=0x" << std::hex << s.flags << std::dec
                           << ") addr=0x" << std::hex << s.addr << std::dec
                           << " size=" << s.data.size() << " (" << codec_name(detect_codec(s.data))
                           << ")\n";
            if (img.layout) {
                size_t behind = 0;
                for (const Bytes& a : img.layout->after) behind += a.size();
                std::cout << "layout:   kept as found (" << img.layout->header.size() << " bytes in front of the data, " << behind
                          << " bytes between and behind the segments); it is not elftool's\n";
            } else if (img.build() == data) {
                std::cout << "layout:   elftool's (data from byte " << legacy::kElfDataStartOffset << ", one segment behind the other)\n";
            } else {
                std::cout << "layout:   not elftool's, and not one abr can keep: an untouched repack writes elftool's\n";
            }
            break;
        }
        case Fmt::MTK_IMAGE: {
            print_mtk_image_info(data);
            break;
        }
        case Fmt::MTK_PRELOADER: {
            print_mtk_preloader_info(data);
            break;
        }
        case Fmt::MBN: {
            print_mbn_info(data);
            break;
        }
        case Fmt::MBN_ELF: {
            print_mbn_elf_info(data);
            break;
        }
        case Fmt::SPLASH: {
            print_splash_info(data);
            break;
        }
        case Fmt::OPLUS_LOGO: {
            print_oplus_logo_info(data);
            break;
        }
        case Fmt::XIAOMI_LOGO: {
            print_xiaomi_logo_info(data);
            break;
        }
        case Fmt::MOTO_LOGO: {
            print_moto_logo_info(data);
            break;
        }
        case Fmt::CHROMEOS: {
            Bytes kernel;
            const std::optional<legacy::ChromeosInfo> c = legacy::strip_chromeos(data, kernel);
            std::cout << "blob:           " << chromeos_description(*c) << "\n";
            std::cout << "cmdline:        " << shown(std::string(c->config.begin(), std::find(c->config.begin(), c->config.end(), 0))) << "\n";
            std::cout << "kernel:         " << kernel.size() << " bytes\n";
            print_envelope_info(c->tail);
            break;
        }
        case Fmt::UNKNOWN: {
            const Identity id = identify(data);
            std::cout << "(unrecognized format"
                      << (id.kind == Kind::UNKNOWN ? std::string() : ": " + id.label) << ")\n";
            if (legacy::has_sin_header(data)) {
                std::cout << describe_unknown(data) << "\n";
            } else if (const std::string why = describe_unknown(data); why.rfind("unrecognized image format", 0) != 0) {
                std::cout << why << "\n";  // (what the file looks like and why abr cannot read it, unless it looks like nothing)
            }
            break;
        }
    }
    if (f != Fmt::UNKNOWN)
        if (std::optional<layout::Layout> l = describe_layout(f, data)) {
            annotate_streams(*l, data);
            std::cout << "layout (" << l->format << ", " << l->size << " bytes"
                      << (wrap.recorded() || wrap.sin ? "; offsets are those of the plain image inside its wrapper" : "") << "):\n"
                      << layout::render(*l);
        }
}

// ------------------------------------------------------------- dispatch --

// The image `repack` is about to write must be one that abr knows again: looked at the way `unpack` looks at a file (the wrappers
// off, then the magic and the layout), it is the kind of image the manifest says. What `identify` calls `data` and `unpack` refuses
// is no result of a repack, whatever made it -- a header that is not one, bytes in front of the image that push it out of place.
void check_known_again(const Bytes& image, Fmt wanted, const Manifest& m) {
    Wrappers wrap;
    Fmt got = Fmt::UNKNOWN;
    std::string why;
    try {
        const Bytes& payload = peel_wrappers(image, wrap);
        got = detect_format(payload);
        if (got == Fmt::UNKNOWN) why = describe_unknown(payload);
    } catch (const FormatError& e) {
        why = e.what();
    }
    if (wanted == Fmt::DTB && got == Fmt::FIT) got = Fmt::DTB;  // (a FIT image is a device tree, and one that was unpacked as one stays one)
    if (got != wanted)
        throw FormatError(std::string("the image abr would write is not ") + (wanted == Fmt::UNKNOWN ? "an image" : "a " + std::string(fmt_name(wanted)) + " image") +
                          " that it knows again: " + (got == Fmt::UNKNOWN ? why : "it would be taken for a " + std::string(fmt_name(got)) + " image") +
                          " (something in the directory does not agree with the rest of it: a file in front of the image, a header)");
    // The wrappers are what the manifest says: an image that is taken for a boot image because its patch is not known for one
    // (a microloader without the word that tells it) is another image than the one that was asked for, and an unpack of it reads
    // the first page of the plain image where the patch is.
    const struct {
        const char* key;
        bool peeled;
        const char* what;
    } layers[] = {
        {"has_chromeos", wrap.chromeos.has_value(), "a ChromeOS kernel blob around it"},
        {"has_dhtb", wrap.dhtb.has_value(), "a DHTB header"},
        {"has_blob", wrap.blob.has_value(), "a BLOB header"},
        {"has_loki", wrap.loki.has_value(), "the LOKI patch"},
        {"has_amonet", wrap.amonet.has_value(), "the AMONET patch"},
    };
    for (const auto& l : layers) {
        if (m.get_bool(l.key, false) == l.peeled) continue;
        throw FormatError(std::string("the image abr would write would ") + (l.peeled ? "be taken for one with " : "not be taken for one with ") + l.what +
                          " (manifest.txt says " + l.key + "=" + (l.peeled ? "false" : "true") +
                          ") and abr would not know it again: something in the directory does not agree with the rest of it (a file of the wrapper, "
                          "a header)");
    }
}

// Rebuilds the file described by an unpacked directory, once (see build_image).
Bytes build_image_once(const fs::path& dir, const RepackOptions& opt) {
    Manifest m = Manifest::load(dir / "manifest.txt");
    Fmt f = fmt_from_name(m.get("type"));
    Bytes result;
    switch (f) {
        case Fmt::BOOT: result = repack_boot(m, dir, opt); break;
        case Fmt::VENDOR_BOOT: result = repack_vendor_boot(m, dir, opt); break;
        case Fmt::DTBO: result = repack_dtbo(m, dir, opt); break;
        case Fmt::DTB: result = repack_dtb(m, dir, opt); break;
        case Fmt::FIT: result = repack_fit(m, dir, opt); break;
        case Fmt::QCDT: result = repack_qcdt(m, dir, opt); break;
        case Fmt::VBMETA: result = repack_vbmeta(m, dir, opt); break;
        case Fmt::UIMAGE: result = repack_uimage(m, dir, opt); break;
        case Fmt::ELF_BOOT: result = repack_elf_boot(m, dir, opt); break;
        case Fmt::KRNL: result = repack_krnl(m, dir, opt); break;
        case Fmt::BLOB: result = repack_blob(m, dir); break;
        case Fmt::OSIP: result = repack_osip(m, dir, opt); break;
        case Fmt::CHROMEOS: result = repack_chromeos(m, dir, opt); break;
        case Fmt::MTK_IMAGE: result = repack_mtk_image(m, dir, opt); break;
        case Fmt::MTK_PRELOADER: result = repack_mtk_preloader(m, dir, opt); break;
        case Fmt::MBN: result = repack_mbn(m, dir, opt); break;
        case Fmt::MBN_ELF: result = repack_mbn_elf(m, dir, opt); break;
        case Fmt::SPLASH: result = repack_splash(m, dir, opt); break;
        case Fmt::OPLUS_LOGO: result = repack_oplus_logo(m, dir, opt); break;
        case Fmt::XIAOMI_LOGO: result = repack_xiaomi_logo(m, dir, opt); break;
        case Fmt::MOTO_LOGO: result = repack_moto_logo(m, dir, opt); break;
        case Fmt::UNKNOWN:
            throw FormatError("manifest.txt has no (or an unrecognized) 'type=' field");
    }

    if (opt.avb1_signer && f != Fmt::BOOT)
        warn("keys/avb1.pk8 only applies to boot and recovery images; ignored here");
    if ((opt.chromeos.key || opt.chromeos.keyblock) && f != Fmt::CHROMEOS && !m.get_bool("has_chromeos", false))
        warn("keys/chromeos.vbprivk and keys/chromeos.keyblock only apply to a ChromeOS kernel blob; ignored here");

    // The wrappers go on in the opposite order to the one they came off in: the amonet patch, the loki patch, the
    // blob, DHTB, then the ChromeOS kernel blob.
    if (m.get_bool("has_amonet", false)) {
        legacy::AmonetInfo amonet;
        amonet.microloader = load_raw(m, dir, "amonet_microloader");
        try {
            result = legacy::apply_amonet(result, amonet);
        } catch (const FormatError& e) {
            throw FormatError(std::string(e.what()) + " (has_amonet=false in manifest.txt leaves the AMONET patch out)");
        }
    }
    if (m.get_bool("has_loki", false)) result = apply_loki_wrapper(m, dir, result, opt);
    if (m.get_bool("has_blob", false)) {
        legacy::BlobImage blob = load_blob_fields(m, dir);
        if (blob.parts.size() != 1)
            throw FormatError("has_blob=true wraps one image, so blob_parts must be 1 (a blob of several partitions is a "
                              "directory of its own, type=blob)");
        blob.parts[0].data = std::move(result);
        result = pack_blob(m, std::move(blob));
    }
    if (m.get_bool("has_dhtb", false)) {
        legacy::DhtbInfo dhtb;
        dhtb.has_seandroid_footer = m.get_bool("dhtb_seandroid_footer", false);
        dhtb.has_padding = m.get_bool("dhtb_padding", false);
        dhtb.trailing_extra = load_raw(m, dir, "dhtb_trailing_extra");
        result = wrap_dhtb(result, dhtb);
    }
    if (m.get_bool("has_chromeos", false)) result = apply_chromeos_wrapper(m, dir, result, opt, true);
    check_known_again(result, f, m);
    return result;
}

// Rebuilds the file described by an unpacked directory (everything `repack` does except writing the
// result). An edit can make an image too big for the partition it came out of when what was edited
// has to be compressed again and the usual setting is less dense than the one the image was made with
// (an OrangeFox vendor_boot: `zstd -19`, which abr's default level 3 does not match). Then the build is
// tried once more with everything that is compressed again as dense as the codecs allow; what the first
// try said is dropped, so it is not said twice. Where nothing was compressed at a setting that has a
// denser one, a second try would build the very same image: the first try's words and error stand.
Bytes build_image(const fs::path& dir, const RepackOptions& opt) {
    if (opt.dense) return build_image_once(dir, opt);
    Deferral held;
    g_denser_would_help = false;
    try {
        Bytes image = build_image_once(dir, opt);
        held.flush();
        return image;
    } catch (const DoesNotFit& first) {
        if (!g_denser_would_help) {
            held.flush();
            throw;
        }
        held.discard();
        note(std::string(first.what()) + "; compressing what was edited again, as densely as the codecs allow");
        RepackOptions again = opt;
        again.dense = true;
        try {
            return build_image_once(dir, again);
        } catch (const DoesNotFit& second) {
            throw DoesNotFit(std::string(second.what()) +
                             " -- not even with what was edited compressed as densely as the codecs allow");
        }
    } catch (...) {
        held.flush();  // what led up to the error is worth reading
        throw;
    }
}

// Offset of the first byte where a and b differ (or the shorter length).
size_t first_difference(const Bytes& a, const Bytes& b) {
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i)
        if (a[i] != b[i]) return i;
    return n;
}

// Right after unpacking, rebuild the image from the freshly written tree and
// compare it with the source. Every byte the tool failed to model shows up
// here, so a repack of an untouched image is either provably identical or
// the user is told, at once, where it is not.
void self_check(const fs::path& outdir, const Bytes& original, const char* what = "this image") {
    progress::enter("verify", original.size() + original.size() / 8);  // (an eighth more than the components: the rest is putting them together)
    try {
        Bytes rebuilt = build_image(outdir, RepackOptions{});
        if (rebuilt == original) {
            std::cout << "round-trip: an untouched repack reproduces " << what << " byte-for-byte\n";
            return;
        }
        std::ostringstream os;
        os << "an untouched repack does NOT reproduce " << what << " exactly (source " << original.size()
           << " bytes, rebuilt " << rebuilt.size() << " bytes, first difference at offset 0x"
           << std::hex << first_difference(original, rebuilt) << std::dec
           << "). The unpacked files are still usable, but please report this image.";
        warn(os.str());
    } catch (const std::exception& e) {
        warn(std::string("could not verify the round trip: ") + e.what());
    }
}

void do_unpack(const fs::path& in, const fs::path& outdir) {
    const progress::Scope progress_scope("unpack", {{"read", 1}, {"decode", 6}, {"tree", 2}, {"verify", 5}});
    progress::enter("read", 1);
    Bytes data = read_file(in);
    progress::advance(1);

    Wrappers wrap;
    const Bytes& payload = peel_wrappers(data, wrap);

    Fmt f = detect_format(payload);
    if (f == Fmt::UNKNOWN) throw FormatError(in.string() + ": " + describe_unknown(payload));
    // A directory this unpack made is not left behind, empty or half written, when it fails (a cut-short
    // image, say); one that was there before is not touched.
    const bool made_outdir = !fs::exists(outdir);
    fs::create_directories(outdir);
    try {
        switch (f) {
            case Fmt::BOOT: unpack_boot(payload, outdir); break;
            case Fmt::VENDOR_BOOT: unpack_vendor_boot(payload, outdir); break;
            case Fmt::DTBO: unpack_dtbo(payload, outdir); break;
            case Fmt::DTB: unpack_dtb(payload, outdir); break;
            case Fmt::QCDT: unpack_qcdt(payload, outdir); break;
            case Fmt::FIT: {
                std::string why;
                if (!unpack_fit(payload, outdir, why)) {
                    note("this is a U-Boot FIT image, but abr cannot put it back as one (" + why + "): it is unpacked as a plain device tree");
                    f = Fmt::DTB;
                    unpack_dtb(payload, outdir);
                }
                break;
            }
            case Fmt::VBMETA: unpack_vbmeta(payload, outdir); break;
            case Fmt::UIMAGE: unpack_uimage(payload, outdir); break;
            case Fmt::ELF_BOOT: unpack_elf_boot(payload, outdir); break;
            case Fmt::KRNL: unpack_krnl(payload, outdir); break;
            case Fmt::BLOB: unpack_blob(payload, outdir); break;
            case Fmt::OSIP: unpack_osip(payload, outdir); break;
            case Fmt::CHROMEOS: unpack_chromeos(payload, outdir); break;
            case Fmt::MTK_IMAGE: unpack_mtk_image(payload, outdir); break;
            case Fmt::MTK_PRELOADER: unpack_mtk_preloader(payload, outdir); break;
            case Fmt::MBN: unpack_mbn(payload, outdir); break;
            case Fmt::MBN_ELF: unpack_mbn_elf(payload, outdir); break;
            case Fmt::SPLASH: unpack_splash(payload, outdir); break;
            case Fmt::OPLUS_LOGO: unpack_oplus_logo(payload, outdir); break;
            case Fmt::XIAOMI_LOGO: unpack_xiaomi_logo(payload, outdir); break;
            case Fmt::MOTO_LOGO: unpack_moto_logo(payload, outdir); break;
            case Fmt::UNKNOWN:
                throw FormatError(in.string() + ": " + describe_unknown(payload));
        }

        if (wrap.recorded()) {
            Manifest m = Manifest::load(outdir / "manifest.txt");
            std::string what;
            if (wrap.chromeos) {
                m.set_bool("has_chromeos", true);
                save_chromeos_fields(m, outdir, *wrap.chromeos);
                what = "ChromeOS-wrapped";
            }
            if (wrap.dhtb) {
                m.set_bool("has_dhtb", true);
                m.set_bool("dhtb_seandroid_footer", wrap.dhtb->has_seandroid_footer);
                m.set_bool("dhtb_padding", wrap.dhtb->has_padding);
                save_raw(m, outdir, "dhtb_trailing_extra", wrap.dhtb->trailing_extra, "dhtb_trailing_extra.bin");
                what += std::string(what.empty() ? "" : ", ") + "DHTB-wrapped";
            }
            if (wrap.blob) {
                m.set_bool("has_blob", true);
                save_blob_fields(m, outdir, *wrap.blob, wrap.blob_inner.size(), hash::sha256(wrap.blob_inner));
                what += std::string(what.empty() ? "" : ", ") + "blob-wrapped";
            }
            if (wrap.amonet) {
                m.set_bool("has_amonet", true);
                save_raw(m, outdir, "amonet_microloader", wrap.amonet->microloader, "microloader.bin");
                what += std::string(what.empty() ? "" : ", ") + "AMONET-patched";
            }
            if (wrap.loki) {
                m.set_bool("has_loki", true);
                save_loki_fields(m, outdir, *wrap.loki);
                what += std::string(what.empty() ? "" : ", ") + "LOKI-patched";
            }
            m.save(outdir / "manifest.txt",
                   "abr manifest (" + what + ") -- edit then `abr pack -i " + outdir.string() + " -o out.img`");
        }
    } catch (...) {
        if (made_outdir) {
            std::error_code ec;
            fs::remove_all(outdir, ec);
        }
        throw;
    }

    std::cout << "unpacked " << wrap.adjectives() << fmt_name(f)
              << " -> " << outdir.string() << "/\n";
    report_layout(f, payload, wrap, outdir, "the image this folder was unpacked from", in.filename().string());
    if (wrap.sin) {
        for (const std::string& n : wrap.sin->notes) warn(n);
        note(legacy::describe_sin(*wrap.sin) + ": the container is not kept, a repack writes the plain " + fmt_name(f) +
             " image (as Android Image Kitchen does: the SIN is signed by Sony and cannot be made again)");
        self_check(outdir, wrap.sin_payload, "the image inside the SIN");
    } else {
        self_check(outdir, data);
    }
}

// A folder of device trees packed as a Qualcomm device tree table: what dtbTool does. The trees are the files of the folder whose names
// end in .dtb, in the subfolders as well but not in those whose names start with a dot, in the order of their paths (dtbTool takes them
// in the order the file system lists them, and the order is in the table where two trees are for the same board).
void pack_device_trees(const fs::path& dir, const fs::path& out, const qcdt::MakeOptions& opt) {
    std::vector<fs::path> files;
    for (fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied), end; it != end; ++it) {
        const std::string name = it->path().filename().string();
        if (it->is_directory()) {
            if (!name.empty() && name[0] == '.') it.disable_recursion_pending();
        } else if (it->is_regular_file() && name.size() > 4 && name.compare(name.size() - 4, 4, ".dtb") == 0) {
            files.push_back(it->path());
        }
    }
    std::sort(files.begin(), files.end(), [](const fs::path& a, const fs::path& b) { return a.generic_string() < b.generic_string(); });
    files.erase(std::unique(files.begin(), files.end()), files.end());
    if (files.empty())
        throw FormatError(shown(dir.string()) + " has no manifest.txt (it is not a folder that `abr unpack` made) and no file whose name ends in .dtb "
                          "(the device trees to make a Qualcomm device tree table of)");
    std::vector<qcdt::Source> sources;
    sources.reserve(files.size());
    for (const fs::path& f : files) sources.push_back({f.string(), read_file(f)});
    qcdt::Made made = qcdt::make(sources, opt);
    for (const std::string& n : made.notes) note(n);
    const Bytes table = qcdt::build(made.table);
    if (const fs::path read = find_read_file(out); !read.empty())
        throw FormatError("-o " + shown(out.string()) + " is a file this run has read (" + shown(read.string()) + "); the table would be written over it. Name another file");
    write_file(out, table);
    std::cout << "packed qcdt -> " << out.string() << " (" << table.size() << " bytes): " << qcdt_summary(made.table) << "\n";
}

// The keys a folder brings (keys/): keys of its own for what abr signs again when the content has changed. None is needed: abr has the
// public test keys of the projects the formats come from, and signs with them.
//   keys/avb_key.pem                                the key of AVB 2.0 (vbmeta, hash footers): PEM or DER
//   keys/avb1.pk8 and keys/avb1.x509.pem            the key and the certificate of the old boot signature of a boot image (AIK's names;
//                                                   keys/avb1.x509.der is as good, and so is one PEM that holds both)
//   keys/chromeos.vbprivk and keys/chromeos.keyblock  the key of the signature of a ChromeOS kernel blob, and the keyblock made for it
Signer load_avb1_signer(const fs::path& base) {
    const fs::path key_path = base.string() + ".pk8";
    if (!fs::is_regular_file(key_path))
        throw FormatError("keys/ has the certificate of an AVBv1 boot signature but not its key: " + shown(key_path.generic_string()) +
                          " is not there");
    fs::path cert_path;
    for (const char* ext : {".x509.pem", ".x509.der", ".x509.crt"})
        if (fs::is_regular_file(base.string() + ext)) {
            cert_path = base.string() + ext;
            break;
        }
    const Bytes key = read_file(key_path);
    const Bytes cert = cert_path.empty() ? Bytes() : read_file(cert_path);
    return make_signer(key, cert);
}

void load_folder_keys(const fs::path& dir, RepackOptions& opt) {
    const fs::path keys = dir / "keys";
    if (!fs::is_directory(keys)) return;
    const auto there = [&](const char* name) { return fs::is_regular_file(keys / name); };
    if (there("avb_key.pem")) {
        const Bytes key = read_file(keys / "avb_key.pem");
        opt.avb_key_pem.assign(reinterpret_cast<const char*>(key.data()), key.size());
    }
    if (there("avb1.pk8") || there("avb1.x509.pem") || there("avb1.x509.der") || there("avb1.x509.crt")) opt.avb1_signer = load_avb1_signer(keys / "avb1");
    if (there("chromeos.vbprivk")) {
        try {
            opt.chromeos.key = parse_vbprivk(read_file(keys / "chromeos.vbprivk"));
        } catch (const FormatError& e) {
            throw FormatError("keys/chromeos.vbprivk: " + std::string(e.what()));
        }
    }
    if (there("chromeos.keyblock")) {
        Bytes keyblock = read_file(keys / "chromeos.keyblock");
        if (!has_chromeos_header(keyblock))
            throw FormatError("keys/chromeos.keyblock is not a keyblock (it does not start with \"CHROMEOS\")");
        try {
            keyblock_data_key(keyblock);  // is it one?
        } catch (const FormatError& e) {
            throw FormatError("keys/chromeos.keyblock: " + std::string(e.what()));
        }
        opt.chromeos.keyblock = std::move(keyblock);
    }
}

// The options of a table that is made of the device trees of a folder whose manifest.txt says `type=qcdt` and has no table of its own
// (an `abr unpack` has one): `page_size` (default 2048: the page size of the boot image the table goes into) and `table_version`
// (1, 2 or 3; default: what the trees need).
qcdt::MakeOptions qcdt_make_options(const Manifest& m) {
    qcdt::MakeOptions o;
    o.page_size = static_cast<uint32_t>(m.get_int("page_size", qcdt::kDefaultPageSize, 1, qcdt::kMaxPageSize));
    o.version = static_cast<uint32_t>(m.get_int("table_version", 0, 0, 3));
    return o;
}

// What the folder is when it is packed: made by `abr unpack` (it has a manifest.txt), or just device trees.
bool is_device_tree_table_recipe(const Manifest& m) { return m.get("type") == "qcdt" && !m.has("version"); }

// The work of a pack, for the bar: the size of the files of the folder that go into the image (what the manifest names with `*_file`).
uint64_t folder_work(const Manifest& m, const fs::path& dir) {
    uint64_t total = 0;
    for (const auto& [key, value] : m.entries()) {
        if (key.size() < 5 || key.compare(key.size() - 5, 5, "_file") != 0 || *path_problem(value) != '\0') continue;
        std::error_code ec;
        const auto size = fs::file_size(dir / value, ec);
        if (!ec) total += size;
    }
    return total;
}

void do_pack(const fs::path& dir, const fs::path& out) {
    const progress::Scope progress_scope("pack", {{"build", 9}, {"write", 1}});
    if (!fs::is_directory(dir))
        throw FormatError(shown(dir.string()) +
                          (fs::exists(dir) ? " is a file, not a folder: `abr pack -i` takes the folder that `abr unpack -i` made of an image"
                                           : " does not exist"));
    if (fs::is_directory(out)) throw FormatError("-o " + shown(out.string()) + " is a folder: name the image file to make");
    const fs::path manifest_file = dir / "manifest.txt";
    if (!fs::exists(manifest_file)) {
        pack_device_trees(dir, out, {});
        return;
    }
    Manifest m = Manifest::load(manifest_file);
    if (is_device_tree_table_recipe(m)) {
        pack_device_trees(dir, out, qcdt_make_options(m));
        return;
    }
    RepackOptions opt;
    load_folder_keys(dir, opt);
    const Fmt f = fmt_from_name(m.get("type"));
    const uint64_t work = folder_work(m, dir);
    progress::enter("build", work + work / 8);  // (an eighth more than the files: the rest is putting the image together)
    const Bytes result = build_image(dir, opt);
    progress::enter("write");
    // The image is not written over a file this pack has read: the manifest, a component, a key, a file of the ramdisk
    // folder, or what a symbolic link among them leads to.
    if (const fs::path read = find_read_file(out); !read.empty())
        throw FormatError("-o " + shown(out.string()) + " is a file this pack has read (" + shown(read.string()) +
                          "); the image would be written over it. Name another file");
    write_file(out, result);
    std::cout << "packed " << fmt_name(f) << " -> " << out.string() << " (" << result.size() << " bytes)\n";
    {
        Wrappers wrap;
        const Bytes& payload = peel_wrappers(result, wrap);
        report_layout(f, payload, wrap, dir, "the image built from this folder (" + out.filename().string() + ")", out.filename().string());
    }
}

// ----------------------------------------------------------- command line --

// A mistake in the command line (as against one in an image or a folder): main() points to the help after it.
struct UsageError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

void usage(std::ostream& os) {
    os <<
        "abr " << kVersion << " -- Android Boot Repacker\n"
        "\n"
        "  abr unpack -i <input.img>    [-o <output_folder>]   take an image apart into a folder\n"
        "  abr pack   -i <input_folder> [-o <output_image>]    build the image again of a folder that unpack made\n"
        "  abr info   -i <input.img>                           show all there is to know about an image, without unpacking it\n"
        "  abr help                                            show this help\n"
        "  abr version                                         show the version (1.YYYYMMDD.NumberBuild)\n"
        "\n"
        "Without -o the output is made beside the input and named after it: `unpack -i dir/boot.img` makes the folder dir/boot,\n"
        "`pack -i dir/boot` makes the image dir/boot.img (dir/boot_new.img when that file is there already: the image a folder came\n"
        "from is not written over unless -o names it). A folder that `unpack` made is not unpacked into again unless -o names it.\n"
        "\n"
        "What an image is -- its format, what it is wrapped in -- abr finds out from the image itself. A ramdisk is unpacked twice:\n"
        "ramdisk.cpio (exactly what the image held) and, when it can be one, the folder ramdisk/ with ramdisk.meta (owners, modes,\n"
        "order). Edit either; pack takes the one that changed (the folder, when both did).\n"
        "A folder of device trees (files that end in .dtb) and no manifest.txt is packed as a Qualcomm device tree table (QCDT, what\n"
        "dtbTool makes); a manifest.txt of `type=qcdt` with `page_size=` and `table_version=` (1, 2 or 3) says how.\n"
        "What pack has to sign again (an AVB 2.0 hash footer or vbmeta, the boot signature of old boot images, a ChromeOS kernel blob)\n"
        "it signs with the public test keys that are built into abr (the AVB project's, AOSP's verity key, vboot's developer keys): with\n"
        "the one the image was signed with when it was one of them, else with the one of the right size, and says so. Keys of your own\n"
        "go in the folder keys/ of the unpacked folder and win: avb_key.pem (AVB 2.0), avb1.pk8 and avb1.x509.pem (the boot signature\n"
        "of old boot images), chromeos.vbprivk and chromeos.keyblock (a ChromeOS kernel blob). A signature that is untouched is kept.\n"
        "ABR_THREADS=N limits the number of threads (the result never depends on it).\n"
        "\n"
        "Supported: boot.img/init_boot.img/boot-debug.img/boot-test-harness.img,\n"
        "recovery.img/recovery-two-step.img (header v0-v4), vendor_boot.img/\n"
        "vendor_boot-debug.img/vendor_kernel_boot.img (header v3-v4), dtbo.img,\n"
        "raw dtb, Qualcomm device tree tables (QCDT: a dt.img, or the dt of a boot image), vbmeta.img/\n"
        "vbmeta_system.img (AVB), U-Boot legacy uImage and FIT image, Sony ELF\n"
        "boot images, Rockchip KRNL (kernel.img / boot.img), ASUS blobs (\"MSM-RADIO-UPDATE\",\n"
        "signed with the SIGNBLOB header or not), Intel OSIP boot images, ChromeOS kernel blobs\n"
        "(the vboot format of a Chromebook's kernel partition); firmware partitions: MediaTek images with the 0x58881688\n"
        "header (md1img/modem, lk, tee, scp, sspm, logo) and the MediaTek preloader (GFH), Qualcomm secure boot images (MBN: a flat\n"
        "file with header version 3, 5, 6 or 7 or an SBL header, or an ELF with a hash segment -- sbl1/xbl, tz, rpm, aboot, ...), and the\n"
        "picture partitions of phones (splash, logo: Qualcomm's \"SPLASH!!\" image, the \"SPLASH LOGO!\" image of OPPO/realme/OnePlus, the\n"
        "\"LOGO!!!!\" image of Xiaomi, Motorola's MotoLogo): every picture becomes a file, a PNG where its pixels are coded (RLE24, MotoRun).\n"
        "A signature of a firmware image cannot be made again: it is kept as it is, and a warning says when what it was made for changed.\n"
        "Also transparently handled: a trailing AVB hash footer on boot/\n"
        "vendor_boot/dtbo; a DHTB wrapper (with SEAndroid footer/padding) around\n"
        "any of them; a ChromeOS kernel blob or an ASUS blob around one image; the LOKI patch (loki_tool) of a\n"
        "boot or recovery image; the AMONET patch of Amazon's Fire tablets; a MediaTek\n"
        "(MTK) sub-header on the kernel and/or ramdisk.\n";
}

struct IoArgs {
    std::optional<std::string> input;
    std::optional<std::string> output;
};

bool is_io_option(const std::string& a) { return a == "-i" || a == "--input" || a == "-o" || a == "--output"; }

// The arguments of `unpack`, `pack` and `info`: -i <input> and -o <output> (also --input, --output, and --input=<input>,
// --output=<output>); an input that no -i gave may be the one argument that is not an option. `info` has no output.
IoArgs parse_io(const std::string& command, const std::vector<std::string>& args, bool takes_output) {
    IoArgs io;
    std::vector<std::string> bare;
    for (size_t i = 0; i < args.size(); ++i) {
        std::string option = args[i];
        std::string value;
        bool has_value = false;
        if (option.rfind("--", 0) == 0) {
            if (const size_t eq = option.find('='); eq != std::string::npos) {
                value = option.substr(eq + 1);
                option.resize(eq);
                has_value = true;
            }
        }
        const bool is_in = option == "-i" || option == "--input";
        const bool is_out = option == "-o" || option == "--output";
        if (!is_in && !is_out) {
            if (args[i].size() > 1 && args[i][0] == '-') throw UsageError("unknown option " + shown(args[i]));
            bare.push_back(args[i]);
            continue;
        }
        if (is_out && !takes_output) throw UsageError(command + " has no output: it takes -i only");
        if (!has_value) {
            if (i + 1 >= args.size() || is_io_option(args[i + 1]))
                throw UsageError(option + " needs " + (is_in ? "the " + std::string(command == "pack" ? "folder" : "image") + " to read" : std::string("the name of what to make")));
            value = args[++i];
        }
        if (value.empty()) throw UsageError(option + " is empty");
        std::optional<std::string>& slot = is_in ? io.input : io.output;
        if (slot) throw UsageError(std::string(is_in ? "-i" : "-o") + " is given twice (" + shown(*slot) + " and " + shown(value) + ")");
        slot = std::move(value);
    }
    if (!io.input && bare.size() == 1) io.input = bare.front();
    else if (!io.input && bare.size() > 1) throw UsageError("two inputs, " + shown(bare[0]) + " and " + shown(bare[1]) + ": the input goes after -i");
    else if (!bare.empty()) throw UsageError("unexpected argument " + shown(bare.front()) + ": the input goes after -i, the output after -o");
    if (!io.input) throw UsageError(command + " needs -i <" + (command == "pack" ? "input_folder" : "input.img") + ">");
    return io;
}

// The name of the last part of a path, whatever way it was written (boot/, ./boot, boot/., ..).
fs::path named_path(const fs::path& given) {
    const auto name_of = [](const fs::path& p) { return p.has_filename() && p.filename() != "." && p.filename() != ".."; };
    fs::path p = given.lexically_normal();
    if (!name_of(p) && !p.empty()) p = p.parent_path();  // a path that ends in a separator
    if (!name_of(p)) {
        p = fs::absolute(given).lexically_normal();
        if (!p.has_filename()) p = p.parent_path();
    }
    if (!name_of(p)) throw UsageError("there is no name in " + shown(given.string()) + " to name the output after: use -o");
    return p;
}

// Without -o, an unpack goes beside the image, named after it, without its extension: dir/boot.img -> dir/boot. A name with no
// extension to take off would be the name of the image itself: dir/boot -> dir/boot_unpacked.
fs::path default_unpack_dir(const fs::path& image) {
    const fs::path p = named_path(image);
    std::string name = p.stem().string();
    if (name.empty() || name == p.filename().string()) name = p.filename().string() + "_unpacked";
    return p.parent_path() / name;
}

// Without -o, a pack goes beside the folder, named after it, with the extension of what it makes: dir/boot -> dir/boot.img. The image
// the folder came from is likely to be there; it is not written over (dir/boot_new.img instead, which a later pack replaces).
fs::path default_pack_file(const fs::path& folder) {
    const fs::path p = named_path(folder);
    std::string extension = ".img";
    if (fs::exists(p / "manifest.txt")) {
        const Fmt f = fmt_from_name(Manifest::load(p / "manifest.txt").get("type"));
        if (f == Fmt::DTB) extension = ".dtb";
        else if (f == Fmt::FIT) extension = ".itb";
        else if (f == Fmt::MBN || f == Fmt::MBN_ELF) extension = ".mbn";
    }
    const std::string name = p.filename().string();
    fs::path out = p.parent_path() / (name + extension);
    if (fs::exists(out)) out = p.parent_path() / (name + "_new" + extension);
    return out;
}


}  // namespace

int main(int argc, char** argv) {
    set_binary_stdio();
    const Utf8Console utf8_console;  // (Windows: the console shows the paths in the messages as they are)
    const console::Printer printer;  // (the one thread that writes: abr/console.hpp; it is also what makes the text safe for a terminal)
    if (!hash::sha_selftest()) {
        std::cerr << "internal error: bundled SHA implementation failed its self-test; "
                     "refusing to run since boot ids and AVB hashes would be silently wrong\n";
        return 2;
    }
    try {
        // (UTF-8 on Windows, too: the C runtime's argv would hold '?' for every character outside the ANSI code page)
        std::vector<std::string> args = command_line_utf8(argc, argv);
        if (args.empty()) {
            usage(std::cerr);
            return 1;
        }
        const std::string cmd = args.front();
        args.erase(args.begin());

        if (cmd == "help" || cmd == "-h" || cmd == "--help") {
            usage(std::cout);
            return 0;
        }
        if (cmd == "version" || cmd == "-V" || cmd == "--version") {
            std::cout << kVersion << "\n";
            return 0;
        }
        if (std::find_if(args.begin(), args.end(), [](const std::string& a) { return a == "-h" || a == "--help"; }) != args.end()) {
            usage(std::cout);
            return 0;
        }

        if (cmd == "info") {
            const IoArgs io = parse_io(cmd, args, false);
            print_info(*io.input);
        } else if (cmd == "unpack") {
            const IoArgs io = parse_io(cmd, args, true);
            const fs::path in = *io.input;
            const fs::path outdir = io.output ? fs::path(*io.output) : default_unpack_dir(in);
            if (fs::is_directory(in))
                throw FormatError(shown(in.string()) + " is a folder, not an image: `abr unpack -i` takes an image (`abr pack -i` takes a folder)");
            if (!io.output && fs::exists(outdir) && !(fs::is_directory(outdir) && fs::is_empty(outdir)))
                throw FormatError(shown(outdir.string()) + " is there already: unpack does not write into a folder it chose itself when it is not empty. "
                                  "Take another with -o, or -o " + shown(outdir.string()) + " to unpack into this one");
            do_unpack(in, outdir);
        } else if (cmd == "pack") {
            const IoArgs io = parse_io(cmd, args, true);
            const fs::path dir = *io.input;
            const fs::path out = io.output ? fs::path(*io.output) : default_pack_file(dir);
            do_pack(dir, out);
        } else if (cmd == "identify") {
            // (not in the help: what the tests of the formats ask, worded like Android Image Kitchen's `file -m androidbootimg.magic`)
            bool brief = false;
            std::vector<std::string> files;
            for (const std::string& a : args) {
                if (a == "-b" || a == "--brief") brief = true;
                else files.push_back(a);
            }
            if (files.empty()) throw UsageError("identify needs a file");
            int status = 0;
            for (const std::string& f : files) {
                try {
                    const Identity id = identify(read_file(f));
                    if (!brief) std::cout << f << ": ";
                    std::cout << id.label << "\n";
                } catch (const std::exception& e) {
                    std::cerr << "error: " << f << ": " << e.what() << "\n";
                    status = 1;
                }
            }
            return status;
        } else {
            throw UsageError("there is no command " + shown(cmd));
        }
    } catch (const UsageError& e) {
        std::cerr << "error: " << e.what() << "\nsee 'abr help'\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
