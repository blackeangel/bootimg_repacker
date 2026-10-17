// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr -- Android boot-family image unpacker/repacker CLI.
//
//   abr info    <image>
//   abr unpack  <image> [-o <outdir>]
//   abr repack  <dir>   -o <image> [--avb-key <private_key.pem>]
//                       [--avb1-key <key[.pk8]> [--avb1-cert <cert.pem|der>]]
//                       [--chromeos-key <.vbprivk> [--chromeos-keyblock <.keyblock>]]
//
// Format is auto-detected from magic bytes; see detect_format() below.
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <optional>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "abr/boot_image.hpp"
#include "abr/byte_io.hpp"
#include "abr/compression.hpp"
#include "abr/dtb.hpp"
#include "abr/dtbo.hpp"
#include "abr/envelope.hpp"
#include "abr/identify.hpp"
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
#include "abr/manifest.hpp"
#include "abr/parallel.hpp"
#include "abr/ramdisk_tree.hpp"
#include "abr/sha.hpp"
#include "abr/uimage.hpp"
#include "abr/vbmeta.hpp"
#include "abr/vendor_boot.hpp"

namespace fs = std::filesystem;
using namespace abr;
using namespace abr::legacy;

namespace {

// ------------------------------------------------------------ detection --

enum class Fmt { BOOT, VENDOR_BOOT, DTBO, DTB, VBMETA, UIMAGE, ELF_BOOT, KRNL, BLOB, OSIP, CHROMEOS, UNKNOWN };

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
    if (has_chromeos_header(d)) return Fmt::CHROMEOS;
    if (d.size() >= 4) {
        uint32_t be = (uint32_t(d[0]) << 24) | (uint32_t(d[1]) << 16) | (uint32_t(d[2]) << 8) | d[3];
        if (be == kDtTableMagic || be == kAcpioTableMagic) return Fmt::DTBO;
        if (be == kFdtMagic) return Fmt::DTB;
        if (be == kUimageMagic) return Fmt::UIMAGE;
    }
    if (BlobImage::looks_like(d)) return Fmt::BLOB;
    if (d.size() >= 64 && std::memcmp(d.data() + d.size() - 64, "AVBf", 4) == 0) return Fmt::VBMETA;
    if (ElfBootImage::looks_like(d)) return Fmt::ELF_BOOT;
    if (KrnlImage::looks_like(d)) return Fmt::KRNL;
    if (OsipImage::looks_like(d)) return Fmt::OSIP;
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
    auto u32le = [&](size_t off) -> uint32_t {
        if (off + 4 > d.size()) return 0;
        return uint32_t(d[off]) | (uint32_t(d[off + 1]) << 8) | (uint32_t(d[off + 2]) << 16) |
               (uint32_t(d[off + 3]) << 24);
    };
    auto u16le = [&](size_t off) -> uint32_t {
        if (off + 2 > d.size()) return 0;
        return uint32_t(d[off]) | (uint32_t(d[off + 1]) << 8);
    };
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
        case Fmt::VBMETA: return "vbmeta";
        case Fmt::UIMAGE: return "uimage";
        case Fmt::ELF_BOOT: return "elf_boot";
        case Fmt::KRNL: return "krnl";
        case Fmt::BLOB: return "blob";
        case Fmt::OSIP: return "osip";
        case Fmt::CHROMEOS: return "chromeos";
        case Fmt::UNKNOWN: return "unknown";
    }
    return "unknown";
}

Fmt fmt_from_name(const std::string& s) {
    if (s == "boot") return Fmt::BOOT;
    if (s == "vendor_boot") return Fmt::VENDOR_BOOT;
    if (s == "dtbo") return Fmt::DTBO;
    if (s == "dtb") return Fmt::DTB;
    if (s == "vbmeta") return Fmt::VBMETA;
    if (s == "uimage") return Fmt::UIMAGE;
    if (s == "elf_boot") return Fmt::ELF_BOOT;
    if (s == "krnl") return Fmt::KRNL;
    if (s == "blob") return Fmt::BLOB;
    if (s == "osip") return Fmt::OSIP;
    if (s == "chromeos") return Fmt::CHROMEOS;
    return Fmt::UNKNOWN;
}

// What is put around a plain image and has to come off before anything can be read: a ChromeOS kernel blob
// (abr/legacy/chromeos.hpp), a DHTB header (abr/legacy/dhtb.hpp), an ASUS blob whose only partition holds the
// image (abr/legacy/blob.hpp), and under them the loki patch (abr/legacy/loki.hpp) or the amonet patch
// (abr/legacy/amonet.hpp). Repack puts them back in the opposite order.
struct Wrappers {
    std::optional<legacy::ChromeosInfo> chromeos;  // its kernel is `chromeos_inner`
    std::optional<legacy::DhtbInfo> dhtb;
    std::optional<legacy::BlobImage> blob;  // its one partition's data is `blob_inner`, not in here
    std::optional<legacy::LokiInfo> loki;
    std::optional<legacy::AmonetInfo> amonet;
    Bytes chromeos_inner;  // what the wrappers' removal leaves is kept here, if it is not `data` itself
    Bytes dhtb_inner;
    Bytes blob_inner;
    Bytes loki_plain;
    Bytes unpatched;

    bool any() const { return chromeos || dhtb || blob || loki || amonet; }
    // "chromeos-wrapped ", "dhtb-wrapped ", "blob-wrapped ", "loki-patched ", "amonet-patched ", or several, or
    // nothing: for the line that says what was unpacked.
    std::string adjectives() const {
        return std::string(chromeos ? "chromeos-wrapped " : "") + (dhtb ? "dhtb-wrapped " : "") + (blob ? "blob-wrapped " : "") +
               (loki ? "loki-patched " : "") + (amonet ? "amonet-patched " : "");
    }
};

// Takes the wrappers off `data`. The plain image is `data` itself or lives in `w`: the reference is good
// as long as both are. A blob is a wrapper only if its single partition holds something abr unpacks
// (what Android Image Kitchen does with it); any other blob is a container of its own (Fmt::BLOB). The same
// goes for a ChromeOS kernel blob (Fmt::CHROMEOS): its kernel is the plain image if abr knows what it is.
const Bytes& peel_wrappers(const Bytes& data, Wrappers& w) {
    const Bytes* outer = &data;
    if (legacy::has_chromeos_header(data)) {
        Bytes kernel;
        std::optional<legacy::ChromeosInfo> blob = legacy::strip_chromeos(data, kernel);
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

// What the command line can add to a repack: keys for the signatures abr
// regenerates when the content changed.
struct RepackOptions {
    std::string avb_key_pem;               // --avb-key: AVB 2.0 signing key (file contents)
    std::optional<Signer> avb1_signer;     // --avb1-key/--avb1-cert: AVBv1 boot signature
    legacy::ChromeosSigning chromeos;      // --chromeos-key/--chromeos-keyblock: a ChromeOS kernel blob's signature
    std::string ramdisk_from;              // --ramdisk-from: "tree" or "cpio" when both could be meant
    // The second try of build_image(): what had to be compressed again is compressed as densely as the
    // decoders allow (dense_level()), because the first try made an image too big for its partition.
    bool dense = false;
};

struct UnpackOptions {
    bool tree = true;       // write the ramdisk as a directory tree as well (see ramdisk_tree.hpp)
    bool keep_cpio = true;  // ... and keep ramdisk.cpio (--tree-only drops it)
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
    Bytes plain;                         // decompressed
    Bytes plain_hash;                    // SHA-256 of `plain`

    // The stored (still compressed) bytes, as they go to .abr_raw.
    const Bytes& stored(const Bytes& raw) const { return stripped ? *stripped : raw; }
};

DecodedComponent decode_component(const Bytes& raw) {
    DecodedComponent d;
    if (raw.empty()) return d;
    d.present = true;
    Bytes after_mtk;
    if (auto mtk = strip_mtk_header(raw, after_mtk)) {
        d.mtk_name = mtk->name;
        d.stripped = std::move(after_mtk);
    }
    const Bytes& working = d.stored(raw);
    d.codec = detect_codec(working);
    d.plain = decompress(d.codec, working);
    d.plain_hash = hash::sha256(d.plain);
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

    std::vector<DecodedComponent> out(sources.size());
    par::for_each(sources.size(), [&](size_t k) {
        const size_t i = order[k];
        out[i] = decode_component(*sources[i].raw);
        if (!out[i].present) return;
        write_file(dir / sources[i].filename, out[i].plain);
        write_file(dir / ".abr_raw" / (sources[i].filename + ".raw"), out[i].stored(*sources[i].raw));
    });
    return out;
}

void record_component(Manifest& m, const std::string& prefix, const std::string& filename,
                      const DecodedComponent& d) {
    if (!d.present) return;
    if (d.mtk_name) m.set(prefix + "_mtk_name", *d.mtk_name);
    m.set(prefix + "_file", filename);
    m.set(prefix + "_compression", std::string(codec_name(d.codec)));
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
    const long n = std::strtol(m.get(prefix + "_tree_volumes", "1").c_str(), nullptr, 10);
    return static_cast<size_t>(std::clamp<long>(n, 1, 256));
}

void save_ramdisk_trees(Manifest& m, const fs::path& dir, const std::vector<TreeJob>& jobs,
                        const UnpackOptions& uo) {
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
            bool removed = false;
            for (size_t i = 0; i < owned->second; ++i) {
                const fs::path tree = dir / ramdisk_volume_name(j.prefix, i);
                if (fs::exists(fs::symlink_status(tree, ec))) {
                    fs::remove_all(tree, ec);
                    removed = true;
                }
                fs::remove(dir / ramdisk_volume_meta(j.prefix, i), ec);
            }
            if (removed && !uo.tree)
                note("the directory " + (dir / j.prefix).generic_string() + " of an earlier unpack was removed");
        }
        if (uo.tree) todo.push_back(&j);
    }

    std::vector<RamdiskTree> results(todo.size());
    std::vector<std::string> failures(todo.size());
    par::for_each(todo.size(), [&](size_t k) {
        const TreeJob& j = *todo[k];
        try {
            results[k] = extract_ramdisk_tree(j.decoded->plain, dir, j.prefix);
        } catch (const std::exception& e) {
            failures[k] = e.what();
        }
    });

    for (size_t k = 0; k < todo.size(); ++k) {
        const TreeJob& j = *todo[k];
        const RamdiskTree& t = results[k];
        std::error_code ec;
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
        if (!uo.keep_cpio) {
            if (t.exact) fs::remove(dir / j.filename, ec);
            else note(j.filename + " is kept: the directory alone would not give it back exactly");
        }
    }
}

// What goes into the image for one component. For a ramdisk that also exists as a directory (see
// ramdisk_tree.hpp) there are two places it may have been edited, and which one counts is decided
// by what changed since unpacking, not by file times: the file by the hash of its contents, the
// directory by the hash of the archive that is built from it. Nothing changed: the bytes the image
// had are replayed. One changed: that one wins. Both: abr cannot merge them and says so, unless
// --ramdisk-from names the one to use.
Bytes load_component(const Manifest& m, const fs::path& dir, const std::string& prefix,
                     const RepackOptions& opt) {
    const std::string key = prefix + "_file";
    if (!m.has(key)) return {};
    const std::string filename = m.get(key);
    const fs::path file = dir / filename;
    const fs::path raw_path = dir / ".abr_raw" / (filename + ".raw");
    const Bytes stored_hash = m.get_hex(prefix + "_orig_hash");
    const bool has_tree_entry = m.has(prefix + "_tree");
    if (opt.ramdisk_from == "tree" && !has_tree_entry && prefix.rfind("ramdisk", 0) == 0)
        warn("--ramdisk-from tree: " + filename + " has no directory in this unpack, the file is used");

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
    if (has_tree_entry && opt.ramdisk_from != "cpio") {
        tree_name = m.get(prefix + "_tree");
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
            if (tree_changed || opt.ramdisk_from == "tree" || !from_file) from_tree = std::move(rebuilt);
        } else if (opt.ramdisk_from == "tree") {
            throw FormatError("--ramdisk-from tree: the directory " + (dir / tree_name).generic_string() + " is missing");
        }
    }
    if (tree_changed && file_changed && opt.ramdisk_from.empty())
        throw FormatError("both " + filename + " and the directory " + tree_name +
                          "/ have been changed since unpacking, and abr cannot merge the two. Undo one "
                          "of them, or say which one to use: --ramdisk-from tree  or  --ramdisk-from cpio");

    const bool use_tree = from_tree && (opt.ramdisk_from == "tree" || tree_changed || !from_file);
    if (!use_tree && !from_file) from_file = read_file(file);  // neither is there: the usual error
    const Bytes& plain = use_tree ? *from_tree : *from_file;
    const bool original = !stored_hash.empty() && (use_tree ? tree_hash : file_hash) == stored_hash;

    Bytes result;
    if (original && fs::exists(raw_path)) {
        result = read_file(raw_path);  // untouched: the very bytes the image had
    } else {
        if (use_tree) {
            for (const std::string& n : report.notes) note(n);
            std::string from;  // "ramdisk/", "ramdisk/ and ramdisk.vol2/", "ramdisk/, ramdisk.vol2/ and ramdisk.vol3/"
            for (size_t i = 0; i < report.built.size(); ++i)
                from += (i == 0 ? "" : i + 1 == report.built.size() ? " and " : ", ") + report.built[i] + "/";
            const std::string size = std::to_string(plain.size()) + " bytes";
            note("the " + prefix + " is built from the director" + (report.built.size() > 1 ? "ies " : "y ") + from + " (" +
                 (report.built.size() > 1 ? std::to_string(report.built.size()) + " cpio archives one after the other, " : std::string()) +
                 size + ")");
        }
        const Codec codec = codec_from_name(m.get(prefix + "_compression", "none")).value_or(Codec::NONE);
        // Optional `<prefix>_level=N` in the manifest picks the compression level
        // (codec-specific; absent or -1: the codec's default -- or, on the second try of a build
        // that did not fit its partition, the densest the decoders allow).
        int level = static_cast<int>(std::strtol(m.get(prefix + "_level", "-1").c_str(), nullptr, 10));
        if (level < 0 && opt.dense) level = dense_level(codec);
        else if (level < 0 && dense_level(codec) >= 0) g_denser_would_help = true;
        result = compress(codec, plain, level);
    }
    if (m.has(prefix + "_mtk_name")) result = add_mtk_header(result, m.get(prefix + "_mtk_name"));
    return result;
}

// load_component() for several components at once, on several threads (the
// recompression of an edited one is where the time goes). In input order.
std::vector<Bytes> load_components(const Manifest& m, const fs::path& dir,
                                   const std::vector<std::string>& prefixes, const RepackOptions& opt) {
    std::vector<uintmax_t> size(prefixes.size(), 0);
    std::vector<size_t> order(prefixes.size());
    for (size_t i = 0; i < prefixes.size(); ++i) {
        order[i] = i;
        std::error_code ec;
        if (m.has(prefixes[i] + "_file")) {
            auto n = fs::file_size(dir / m.get(prefixes[i] + "_file"), ec);
            if (!ec) size[i] = n;
        }
    }
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return size[a] > size[b]; });
    std::vector<Bytes> out(prefixes.size());
    par::for_each(prefixes.size(), [&](size_t k) {
        const size_t i = order[k];
        out[i] = load_component(m, dir, prefixes[i], opt);
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
    return read_file(dir / m.get(key));
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

Envelope load_envelope(const Manifest& m, const fs::path& dir) {
    Envelope e;
    e.prefix = load_raw(m, dir, "prefix");
    e.tail = load_raw(m, dir, "tail");
    e.pad_byte = static_cast<uint8_t>(m.get_u32("pad_byte", 0));
    e.pad_to = m.get_u64("pad_to", 0);
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

// `host` is the freshly-built (possibly edited) protected image. Returns it
// unchanged when the source had no footer, else the full
// [host][padding][vbmeta][padding][footer] partition image.
Bytes reattach_avb_footer(const Manifest& m, const fs::path& dir, Bytes host,
                          const std::string& avb_key_pem) {
    if (!m.get_bool("has_avb_footer", false)) return host;
    VbmetaImage v;
    v.has_footer = true;
    v.source_total_size = m.get_u64("avb_partition_size", 0);
    v.footer_original_image_size = host.size();
    v.algorithm_type = m.get_u32("avb_algorithm_type", 0);
    v.rollback_index = m.get_u64("avb_rollback_index", 0);
    v.flags = m.get_u32("avb_flags", 0);
    v.rollback_index_location = m.get_u32("avb_rollback_index_location", 0);
    v.release_string = m.get("avb_release_string");
    v.hash = m.get_hex("avb_hash");
    v.signature = m.get_hex("avb_signature");
    v.public_key = load_raw(m, dir, "avb_public_key");
    v.public_key_metadata = load_raw(m, dir, "avb_public_key_metadata");
    uint32_t count = m.get_u32("avb_descriptor_count", 0);
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
    if (hash::sha256(host) != m.get_hex("avb_host_sha256") && v.refresh_hash_descriptors(host)) {
        if (v.algorithm_type != 0 && avb_key_pem.empty())
            throw FormatError(
                "the image content changed, so its AVB hash descriptor (and the vbmeta signature, "
                "algorithm " + avb_algorithm_name(v.algorithm_type) +
                ") must be regenerated: pass --avb-key <private_key.pem>. Without the original "
                "vendor key the result will not verify on a locked device");
    }
    v.host_prefix = std::move(host);
    std::vector<std::string> notes;
    Bytes built = v.build(avb_key_pem, &notes);
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
// carried a signature -- or --avb1-key was given. Returns how many leading
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
            warn("the original boot signature was made by \"" +
                 certificate_subject(existing->certificate) +
                 "\", whose private key abr does not have. The new signature uses the public "
                 "AOSP test key (what Android Image Kitchen does); a bootloader that trusts only "
                 "the original key will reject the image. Use --avb1-key/--avb1-cert to sign with "
                 "your own key.");
    }
    Bytes der = build_boot_signature(core, target, signer);
    std::cout << (existing ? "re-created" : "added") << " the AVBv1 boot signature (target "
              << target << ", signed by "
              << (signer.is_aosp_test_key ? std::string("the public AOSP test key")
                                          : signer.subject)
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

// ------------------------------------------------------------- boot.img --

std::string hex_words(const std::array<uint32_t, 4>& w) {
    Bytes b;
    for (auto v : w)
        for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i)));
    Manifest tmp;
    tmp.set_hex("x", b);
    return tmp.get("x");
}

void unpack_boot(const Bytes& whole, const fs::path& dir, const UnpackOptions& uo) {
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
        save_ramdisk_trees(m, dir, {{"ramdisk", "ramdisk.cpio", &parts[1]}}, uo);
    }
    save_raw(m, dir, "dt", img.dt, "dt.img");
    save_raw(m, dir, "recovery_dtbo", img.recovery_dtbo, "recovery_dtbo.img");
    save_raw(m, dir, "dtb", img.dtb, "dtb");
    save_raw(m, dir, "boot_signature", img.boot_signature, "boot_signature.bin");
    save_raw(m, dir, "header_padding", img.header_padding, "header_padding.bin");

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

    m.save(dir / "manifest.txt", "abr boot manifest -- edit then `abr repack " + dir.string() +
                                      " -o out.img`");
}

Bytes repack_boot(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    BootImage img;
    img.header_version = m.get_u32("header_version", 4);
    img.pxa = m.get_bool("pxa", false);
    if (img.pxa) img.pxa_unknown = static_cast<uint32_t>(m.get_addr("pxa_unknown", 0x03000000));
    if (img.header_version <= 2) {
        img.page_size = m.get_u32("page_size", 2048);
        img.kernel_addr = static_cast<uint32_t>(m.get_addr("kernel_addr", 0x00008000));
        img.ramdisk_addr = static_cast<uint32_t>(m.get_addr("ramdisk_addr", 0x01000000));
        img.second_addr = static_cast<uint32_t>(m.get_addr("second_addr", 0x00f00000));
        img.tags_addr = static_cast<uint32_t>(m.get_addr("tags_addr", 0x00000100));
        img.board_name = m.get("board_name");
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
    auto ov = OsVersion::parse(m.get("os_version"), m.get("os_patch_level"));
    if (ov) img.os_version = *ov;
    img.cmdline = m.get("cmdline");
    img.cmdline_split = m.get_u32("cmdline_split", 0);
    img.missing_tail_padding = m.get_u64("missing_tail_padding", 0);
    if (m.has("tail_padding_kept")) img.kept_tail_padding = m.get_u64("tail_padding_kept", 0);

    {
        auto parts = load_components(m, dir, {"kernel", "ramdisk", "second"}, opt);
        img.kernel = std::move(parts[0]);
        img.ramdisk = std::move(parts[1]);
        img.second = std::move(parts[2]);
    }
    img.dt = load_raw(m, dir, "dt");
    img.recovery_dtbo = load_raw(m, dir, "recovery_dtbo");
    img.dtb = load_raw(m, dir, "dtb");
    img.boot_signature = load_raw(m, dir, "boot_signature");
    img.header_padding = load_raw(m, dir, "header_padding");
    img.recompute_id();  // follows id_scheme; `raw` keeps the id found in the source

    Bytes core = img.build();
    Envelope env = load_envelope(m, dir);
    const bool changed = core_changed(m, core);
    const size_t regenerated = refresh_avb1_signature(
        m, env, core, img.header_version <= 2 ? img.page_size : 4096, changed, opt);
    Bytes host = assemble_envelope(m, env, core, changed, regenerated, opt);
    return reattach_avb_footer(m, dir, std::move(host), opt.avb_key_pem);
}

// ------------------------------------------------------- vendor_boot.img --

void unpack_vendor_boot(const Bytes& whole, const fs::path& dir, const UnpackOptions& uo) {
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
    m.set("cmdline", img.cmdline);
    m.set_addr("dtb_addr", img.dtb_addr);
    if (img.header_size_field) m.set_u32("header_size", *img.header_size_field);
    if (img.header_version >= 4 && !img.has_ramdisk_table) m.set_bool("ramdisk_table", false);
    if (img.missing_tail_padding) m.set_u64("missing_tail_padding", img.missing_tail_padding);
    if (img.missing_tail_padding && img.kept_tail_padding) m.set_u64("tail_padding_kept", *img.kept_tail_padding);
    save_raw(m, dir, "dtb", img.dtb, "dtb");
    save_raw(m, dir, "bootconfig", img.bootconfig, "bootconfig");
    save_raw(m, dir, "header_padding", img.header_padding, "header_padding.bin");

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
    save_ramdisk_trees(m, dir, tree_jobs, uo);
    Envelope env = Envelope::capture(host, off, img.consumed);
    save_envelope(m, dir, env, host, off, img.consumed);
    save_avb_footer(m, dir, footer, host);
    m.save(dir / "manifest.txt", "abr vendor_boot manifest -- edit then `abr repack " +
                                      dir.string() + " -o out.img`");
}

Bytes repack_vendor_boot(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    VendorBootImage img;
    img.header_version = m.get_u32("header_version", 4);
    img.page_size = m.get_u32("page_size", 4096);
    img.kernel_addr = static_cast<uint32_t>(m.get_addr("kernel_addr", 0x00008000));
    img.ramdisk_addr = static_cast<uint32_t>(m.get_addr("ramdisk_addr", 0x01000000));
    img.tags_addr = static_cast<uint32_t>(m.get_addr("tags_addr", 0x00000100));
    img.board_name = m.get("board_name");
    img.cmdline = m.get("cmdline");
    img.dtb_addr = m.get_addr("dtb_addr", 0);
    if (m.has("header_size")) img.header_size_field = m.get_u32("header_size");
    img.has_ramdisk_table = m.get_bool("ramdisk_table", true);
    img.missing_tail_padding = m.get_u64("missing_tail_padding", 0);
    if (m.has("tail_padding_kept")) img.kept_tail_padding = m.get_u64("tail_padding_kept", 0);
    img.dtb = load_raw(m, dir, "dtb");
    img.bootconfig = load_raw(m, dir, "bootconfig");
    img.header_padding = load_raw(m, dir, "header_padding");

    uint32_t count = m.get_u32("ramdisk_count", 0);
    std::vector<std::string> fragment_prefixes;
    for (uint32_t i = 0; i < count; ++i) fragment_prefixes.push_back("ramdisk" + std::to_string(i));
    std::vector<Bytes> fragment_data = load_components(m, dir, fragment_prefixes, opt);
    for (uint32_t i = 0; i < count; ++i) {
        std::string p = "ramdisk" + std::to_string(i);
        VendorRamdiskEntry e;
        e.type = vendor_ramdisk_type_from_name(m.get(p + "_type", "platform"));
        e.name = m.get(p + "_name");
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
           "abr dtbo manifest -- edit then `abr repack " + dir.string() + " -o out.img`");
}

Bytes repack_dtbo(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    DtboImage img;
    img.version = m.get_u32("version", 0);
    img.page_size = m.get_u32("page_size", 2048);
    img.acpio = m.get_bool("acpio", false);
    uint32_t count = m.get_u32("entry_count", 0);
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

void unpack_dtb(const Bytes& data, const fs::path& dir) {
    auto blobs = split_fdt_blobs(data);
    Manifest m;
    m.set("type", "dtb");
    m.set_u32("blob_count", static_cast<uint32_t>(blobs.size()));
    for (size_t i = 0; i < blobs.size(); ++i) {
        std::string filename = "blob" + std::to_string(i) + ".dtb";
        m.set("blob" + std::to_string(i) + "_file", filename);
        write_file(dir / filename, blobs[i]);
    }
    m.save(dir / "manifest.txt",
           "abr dtb manifest -- edit then `abr repack " + dir.string() + " -o out.dtb`");
}

Bytes repack_dtb(const Manifest& m, const fs::path& dir) {
    uint32_t count = m.get_u32("blob_count", 0);
    std::vector<Bytes> blobs;
    for (uint32_t i = 0; i < count; ++i)
        blobs.push_back(read_file(dir / m.get("blob" + std::to_string(i) + "_file")));
    return join_fdt_blobs(blobs);
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
           "abr vbmeta manifest -- edit then `abr repack " + dir.string() +
               " -o out.img` (pass --avb-key key.pem to re-sign)");
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
    v.hash = m.get_hex("hash");
    v.signature = m.get_hex("signature");
    v.public_key = load_raw(m, dir, "public_key");
    v.public_key_metadata = load_raw(m, dir, "public_key_metadata");
    v.has_footer = m.get_bool("has_footer", false);
    if (v.has_footer) {
        v.footer_original_image_size = m.get_u64("footer_original_image_size", 0);
        v.source_total_size = m.get_u64("source_total_size", 0);
        v.host_prefix = load_raw(m, dir, "host_prefix");
    }
    uint32_t count = m.get_u32("descriptor_count", 0);
    for (uint32_t i = 0; i < count; ++i) {
        std::string p = "descriptor" + std::to_string(i);
        AvbDescriptor d;
        d.tag = m.get_u64(p + "_tag", 0);
        d.content = load_raw(m, dir, p);
        v.descriptors.push_back(std::move(d));
    }
    std::vector<std::string> notes;
    Bytes built = v.build(opt.avb_key_pem, &notes);
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
    save_raw(m, dir, "data", img.data, "data.bin");
    m.save(dir / "manifest.txt",
           "abr uimage manifest -- edit then `abr repack " + dir.string() + " -o out.img`\n"
           "# NOTE: 'data' is stored exactly as found in the source image -- if 'compression'\n"
           "# is not 'none', it is still compressed with that codec, this tool does not\n"
           "# transcode uImage payload compression.");
}

Bytes repack_uimage(const Manifest& m, const fs::path& dir) {
    UImage img;
    img.timestamp = m.get_u32("timestamp", 0);
    img.load_addr = static_cast<uint32_t>(m.get_addr("load_addr", 0));
    img.entry_point = static_cast<uint32_t>(m.get_addr("entry_point", 0));
    auto lookup = [](std::string_view name, auto name_fn, uint8_t max) -> uint8_t {
        for (int i = 0; i <= max; ++i)
            if (name_fn(static_cast<uint8_t>(i)) == name) return static_cast<uint8_t>(i);
        return 0;
    };
    img.os = lookup(m.get("os", "linux"), uboot_os_name, 30);
    img.arch = lookup(m.get("arch", "arm64"), uboot_arch_name, 30);
    img.type = lookup(m.get("image_type", "kernel"), uboot_type_name, 12);
    img.comp = lookup(m.get("compression", "none"), uboot_comp_name, 6);
    img.name = m.get("name");
    img.data = load_raw(m, dir, "data");
    return img.build();
}

// ----------------------------------------------------------- elf_boot --

void unpack_elf_boot(const Bytes& data, const fs::path& dir) {
    legacy::ElfBootImage img = legacy::ElfBootImage::parse(data);
    Manifest m;
    m.set("type", "elf_boot");
    m.set_bool("is_64bit", img.is_64bit);
    m.set_u32("machine", img.machine);
    m.set_u32("segment_count", static_cast<uint32_t>(img.segments.size()));
    std::vector<ComponentSource> segment_sources;
    for (size_t i = 0; i < img.segments.size(); ++i)
        segment_sources.push_back(
            {&img.segments[i].data, "segment" + std::to_string(i) + "_" + img.segments[i].role + ".bin"});
    auto segment_parts = save_components(dir, segment_sources);
    for (size_t i = 0; i < img.segments.size(); ++i) {
        auto& s = img.segments[i];
        std::string p = "segment" + std::to_string(i);
        m.set(p + "_role", s.role);
        m.set_u32(p + "_flags", s.flags);
        m.set_addr(p + "_addr", s.addr);
        record_component(m, p, segment_sources[i].filename, segment_parts[i]);
    }
    m.save(dir / "manifest.txt",
           "abr elf_boot manifest -- edit then `abr repack " + dir.string() + " -o out.img`");
}

Bytes repack_elf_boot(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    legacy::ElfBootImage img;
    img.is_64bit = m.get_bool("is_64bit", false);
    img.machine = static_cast<uint16_t>(m.get_u32("machine", 40));
    uint32_t count = m.get_u32("segment_count", 0);
    std::vector<std::string> segment_prefixes;
    for (uint32_t i = 0; i < count; ++i) segment_prefixes.push_back("segment" + std::to_string(i));
    std::vector<Bytes> segment_data = load_components(m, dir, segment_prefixes, opt);
    for (uint32_t i = 0; i < count; ++i) {
        std::string p = "segment" + std::to_string(i);
        legacy::ElfSegment s;
        s.role = m.get(p + "_role", "kernel");
        s.flags = m.get_u32(p + "_flags", 0);
        s.addr = static_cast<uint32_t>(m.get_addr(p + "_addr", 0));
        s.data = std::move(segment_data[i]);
        img.segments.push_back(std::move(s));
    }
    return img.build();
}

// ---------------------------------------------------------------- krnl --
//
// Rockchip "KRNL" (abr/legacy/krnl.hpp): 8 bytes, the payload, a CRC. What Android Image Kitchen calls a
// ramdisk: a cpio archive -- compressed, as Rockchip's boot.img has it -- becomes `ramdisk.cpio` and the
// directory `ramdisk/`; a payload that is anything else (kernel.img holds a kernel) stays `kernel`.

void unpack_krnl(const Bytes& host, const fs::path& dir, const UnpackOptions& uo) {
    legacy::KrnlImage img = legacy::KrnlImage::parse(host);
    Manifest m;
    m.set("type", "krnl");
    DecodedComponent part = decode_component(img.payload);
    const bool ramdisk = part.plain.size() < 5 || std::memcmp(part.plain.data(), "07070", 5) == 0;  // (an empty one is a ramdisk)
    const std::string prefix = ramdisk ? "ramdisk" : "kernel";
    const std::string filename = ramdisk ? "ramdisk.cpio" : "kernel";
    if (part.present) {
        fs::create_directories(dir / ".abr_raw");
        write_file(dir / filename, part.plain);
        write_file(dir / ".abr_raw" / (filename + ".raw"), part.stored(img.payload));
        record_component(m, prefix, filename, part);
        if (ramdisk) save_ramdisk_trees(m, dir, {{"ramdisk", "ramdisk.cpio", &part}}, uo);
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
    m.save(dir / "manifest.txt", "abr krnl manifest -- edit then `abr repack " + dir.string() + " -o out.img`");
}

Bytes repack_krnl(const Manifest& m, const fs::path& dir, const RepackOptions& opt) {
    legacy::KrnlImage img;
    img.payload = load_component(m, dir, m.has("kernel_file") ? "kernel" : "ramdisk", opt);
    std::optional<uint32_t> crc;
    if (m.has("krnl_crc") && hash::sha256(img.payload) == m.get_hex("krnl_payload_sha256"))
        crc = static_cast<uint32_t>(m.get_addr("krnl_crc", 0));
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
    b.secure_datalen = static_cast<uint32_t>(m.get_addr("blob_secure_datalen", 0));
    b.secure_siglen = static_cast<uint32_t>(m.get_addr("blob_secure_siglen", 0));
    b.version = static_cast<uint32_t>(m.get_addr("blob_version", legacy::kBlobVersion));
    const Bytes unknown = m.get_hex("blob_unknown");
    if (!unknown.empty()) {
        if (unknown.size() != 4 * b.unknown.size())
            throw FormatError("blob_unknown in manifest.txt must be " + std::to_string(4 * b.unknown.size()) + " bytes");
        for (size_t i = 0; i < b.unknown.size(); ++i)
            b.unknown[i] = uint32_t(unknown[4 * i]) | (uint32_t(unknown[4 * i + 1]) << 8) |
                           (uint32_t(unknown[4 * i + 2]) << 16) | (uint32_t(unknown[4 * i + 3]) << 24);
    }
    const uint32_t count = m.get_u32("blob_parts", 1);
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
    m.save(dir / "manifest.txt", "abr blob manifest -- edit then `abr repack " + dir.string() + " -o out.img`");
}

Bytes repack_blob(const Manifest& m, const fs::path& dir) {
    legacy::BlobImage b = load_blob_fields(m, dir);
    for (size_t i = 0; i < b.parts.size(); ++i) {
        const std::string key = "blob_part" + std::to_string(i) + "_file";
        if (!m.has(key)) throw FormatError("manifest.txt has no " + key);
        b.parts[i].data = read_file(dir / m.get(key));
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
    l.patched_ramdisk_addr = static_cast<uint32_t>(m.get_addr("loki_patched_ramdisk_addr", 0));
    l.patched_ramdisk_size = m.get_u32("loki_patched_ramdisk_size", 0);
    if (m.has("loki_hdr_ramdisk_addr")) l.hdr_ramdisk_addr = static_cast<uint32_t>(m.get_addr("loki_hdr_ramdisk_addr", 0));
    l.block = load_raw(m, dir, "loki_block");
    l.patch_offset = m.get_u32("loki_shellcode_offset", 0);
    l.tail.tail = load_raw(m, dir, "loki_tail");
    l.tail.pad_byte = static_cast<uint8_t>(m.get_u32("loki_pad_byte", 0));
    l.tail.pad_to = m.get_u64("loki_pad_to", 0);
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
// key of vboot_reference, or the key of --chromeos-key). `has_chromeos=false` leaves the blob out (a plain image comes
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
    if (m.has("chromeos_preamble_version")) {
        const std::string text = m.get("chromeos_preamble_version");
        unsigned major = 0, minor = 0;
        char end = 0;
        if (std::sscanf(text.c_str(), "%u.%u%c", &major, &minor, &end) != 2)
            throw FormatError("chromeos_preamble_version in manifest.txt is \"" + text + "\"; it is a version like 2.2");
        c.preamble_major = major;
        c.preamble_minor = minor;
    }
    c.kernel_version = m.get_u32("chromeos_kernel_version", 1);
    const uint64_t flags = m.get_addr("chromeos_flags", fresh ? 1 : 0);
    if (flags > 0xFFFFFFFFull) throw FormatError("chromeos_flags in manifest.txt does not fit in 32 bits");
    c.flags = static_cast<uint32_t>(flags);
    c.body_load_address = m.get_addr("chromeos_body_load_address", 0x100000);
    if (m.has("chromeos_bootloader_address")) c.bootloader_address = m.get_addr("chromeos_bootloader_address", 0);
    c.bootloader_size = m.get_u32("chromeos_bootloader_size", legacy::kChromeosAlign);
    c.vmlinuz_header_address = m.get_addr("chromeos_vmlinuz_header_address", 0);
    c.pad = m.get_u32("chromeos_vblock_size", legacy::kChromeosDefaultPad);
    const Bytes one_space{' '};
    c.config = (m.has("chromeos_config_file") || !fresh) ? load_raw(m, dir, "chromeos_config") : one_space;
    c.params = load_raw(m, dir, "chromeos_params");
    c.bootloader = (m.has("chromeos_bootloader_file") || !fresh) ? load_raw(m, dir, "chromeos_bootloader") : one_space;
    c.body_signature = load_raw(m, dir, "chromeos_body_signature");
    c.preamble_signature = load_raw(m, dir, "chromeos_preamble_signature");
    c.signed_sha256 = m.get_hex("chromeos_signed_sha256");
    if (c.body_signature.empty() || c.preamble_signature.empty()) c.signed_sha256.clear();  // nothing to keep
    c.tail.tail = load_raw(m, dir, "chromeos_tail");
    c.tail.pad_byte = static_cast<uint8_t>(m.get_u32("chromeos_pad_byte", 0));
    c.tail.pad_to = m.get_u64("chromeos_pad_to", 0);
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
            const std::string with = opt.chromeos.key ? "the key given (--chromeos-key)" : "the developer key of vboot_reference";
            // (no signatures came with the directory: a plain image with has_chromeos=true, nothing was "changed")
            note(c.signed_sha256.empty()
                     ? "the ChromeOS kernel blob is signed with " + with
                     : "what the signatures of the ChromeOS kernel blob cover has changed: they are made again, with " + with +
                           (opt.chromeos.key ? "" : ", the data key of the blob's keyblock"));
            break;
        }
        case legacy::ChromeosSigned::NEW_KEYBLOCK:
            note("the ChromeOS kernel blob is signed under the keyblock given (--chromeos-keyblock)");
            break;
        case legacy::ChromeosSigned::DEVELOPER_KEYBLOCK:
            warn("what the signatures of the ChromeOS kernel blob cover has changed, and its keyblock is somebody else's: "
                 "abr has no key for it. The blob is signed with the developer key under the developer keyblock of "
                 "vboot_reference instead, as Android Image Kitchen does; a Chromebook in developer mode boots it, one "
                 "that checks the keyblock against its own keys does not. --chromeos-key and --chromeos-keyblock sign "
                 "with keys of your own");
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
    m.save(dir / "manifest.txt", "abr ChromeOS kernel blob manifest -- edit then `abr repack " + dir.string() + " -o out.img`");
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

void unpack_osip(const Bytes& host, const fs::path& dir, const UnpackOptions& uo) {
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

    DecodedComponent ramdisk = decode_component(img.ramdisk);
    if (ramdisk.present) {
        fs::create_directories(dir / ".abr_raw");
        write_file(dir / "ramdisk.cpio", ramdisk.plain);
        write_file(dir / ".abr_raw" / "ramdisk.cpio.raw", ramdisk.stored(img.ramdisk));
        record_component(m, "ramdisk", "ramdisk.cpio", ramdisk);
        save_ramdisk_trees(m, dir, {{"ramdisk", "ramdisk.cpio", &ramdisk}}, uo);
    }

    m.set_u64("osip_body_size", img.body_size());
    m.set_hex("osip_payload_sha256", osip_payload_sha256(img));
    const OsipPadding pad = osip_padding(host, img.consumed);
    if (pad.aligned) m.set_addr("osip_sector_pad", pad.byte);
    else m.set("osip_sector_pad", "none");
    const Envelope env = Envelope::capture(host, 0, pad.core_size);
    save_envelope(m, dir, env, host, 0, pad.core_size);
    m.save(dir / "manifest.txt", "abr osip manifest -- edit then `abr repack " + dir.string() + " -o out.img`");
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
    const uint8_t pad_byte = aligned ? static_cast<uint8_t>(m.get_addr("osip_sector_pad", 0xFF)) : 0;
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
    std::cout << "boot signature: AVBv1 (boot_signer), target " << sig->target << "\n"
              << "  signer:       " << certificate_subject(sig->certificate)
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

void print_avb_footer_info(const AvbFooter& f, const Bytes& host) {
    if (!f.present) return;
    const VbmetaImage& v = f.v;
    std::cout << "avb footer:     partition " << v.source_total_size << " bytes, protects the first "
              << f.host_size << ", algorithm " << avb_algorithm_name(v.algorithm_type)
              << (v.algorithm_type ? " (signed)" : " (unsigned)") << "\n";
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

void print_info(const fs::path& path) {
    Bytes raw = read_file(path);
    Wrappers wrap;
    const Bytes& data = peel_wrappers(raw, wrap);

    Fmt f = detect_format(data);
    std::cout << "file:   " << path.string() << " (" << raw.size() << " bytes)\n";
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
            std::cout << "cmdline:        " << img.cmdline << "\n";
            std::cout << "kernel:         " << img.kernel.size() << " bytes ("
                       << codec_name(detect_codec(img.kernel)) << ")\n";
            std::cout << "ramdisk:        " << img.ramdisk.size() << " bytes ("
                       << codec_name(detect_codec(img.ramdisk)) << ")\n";
            if (!img.second.empty()) std::cout << "second:         " << img.second.size() << " bytes\n";
            if (!img.dt.empty()) std::cout << "dt (QCDT):      " << img.dt.size() << " bytes\n";
            if (!img.recovery_dtbo.empty())
                std::cout << "recovery_dtbo:  " << img.recovery_dtbo.size() << " bytes\n";
            if (!img.dtb.empty()) std::cout << "dtb:            " << img.dtb.size() << " bytes\n";
            if (!img.boot_signature.empty())
                std::cout << "boot_signature: " << img.boot_signature.size() << " bytes\n";
            if (img.header_version <= 2)
                std::cout << "id scheme:      " << id_scheme_name(img.id_scheme) << "\n";
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
            std::cout << "cmdline:        " << img.cmdline << "\n";
            std::cout << "dtb:            " << img.dtb.size() << " bytes\n";
            std::cout << "bootconfig:     " << img.bootconfig.size() << " bytes\n";
            std::cout << "ramdisk fragments: " << img.ramdisk_fragments.size() << "\n";
            for (size_t i = 0; i < img.ramdisk_fragments.size(); ++i) {
                auto& e = img.ramdisk_fragments[i];
                std::cout << "  [" << i << "] type=" << vendor_ramdisk_type_name(e.type)
                          << " name=" << (e.name.empty() ? "-" : e.name) << " size=" << e.data.size()
                          << " (" << codec_name(detect_codec(e.data)) << ")\n";
            }
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
            auto blobs = split_fdt_blobs(data);
            std::cout << "fdt blobs: " << blobs.size() << "\n";
            for (size_t i = 0; i < blobs.size(); ++i)
                std::cout << "  [" << i << "] " << blobs[i].size() << " bytes\n";
            break;
        }
        case Fmt::VBMETA: {
            VbmetaImage v = VbmetaImage::parse(data);
            std::cout << "algorithm:  " << avb_algorithm_name(v.algorithm_type) << "\n";
            std::cout << "flags:      " << v.flags << "\n";
            std::cout << "rollback:   " << v.rollback_index << " @location "
                       << v.rollback_index_location << "\n";
            std::cout << "release:    " << v.release_string << "\n";
            std::cout << "has_footer: " << (v.has_footer ? "yes" : "no") << "\n";
            std::cout << "descriptors: " << v.descriptors.size() << "\n";
            for (auto& d : v.descriptors) std::cout << "  - " << d.describe() << "\n";
            break;
        }
        case Fmt::UIMAGE: {
            UImage img = UImage::parse(data);
            std::cout << "name:        " << img.name << "\n";
            std::cout << "os/arch:     " << uboot_os_name(img.os) << "/" << uboot_arch_name(img.arch)
                       << "\n";
            std::cout << "type:        " << uboot_type_name(img.type) << "\n";
            std::cout << "compression: " << uboot_comp_name(img.comp) << "\n";
            std::cout << "data:        " << img.data.size() << " bytes\n";
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
            std::cout << "cmdline:        " << img.cmdline_text() << "\n";
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
            std::cout << "segments: " << img.segments.size() << "\n";
            for (auto& s : img.segments)
                std::cout << "  - " << s.role << " (flags=0x" << std::hex << s.flags << std::dec
                           << ") addr=0x" << std::hex << s.addr << std::dec
                           << " size=" << s.data.size() << " (" << codec_name(detect_codec(s.data))
                           << ")\n";
            break;
        }
        case Fmt::CHROMEOS: {
            Bytes kernel;
            const std::optional<legacy::ChromeosInfo> c = legacy::strip_chromeos(data, kernel);
            std::cout << "blob:           " << chromeos_description(*c) << "\n";
            std::cout << "cmdline:        " << std::string(c->config.begin(), std::find(c->config.begin(), c->config.end(), 0)) << "\n";
            std::cout << "kernel:         " << kernel.size() << " bytes\n";
            print_envelope_info(c->tail);
            break;
        }
        case Fmt::UNKNOWN: {
            const Identity id = identify(data);
            std::cout << "(unrecognized format"
                      << (id.kind == Kind::UNKNOWN ? std::string() : ": " + id.label) << ")\n";
            if (std::string note = id.unsupported_note(); !note.empty()) std::cout << note << "\n";
            break;
        }
    }
}

// ------------------------------------------------------------- dispatch --

// Rebuilds the file described by an unpacked directory, once (see build_image).
Bytes build_image_once(const fs::path& dir, const RepackOptions& opt) {
    Manifest m = Manifest::load(dir / "manifest.txt");
    Fmt f = fmt_from_name(m.get("type"));
    Bytes result;
    switch (f) {
        case Fmt::BOOT: result = repack_boot(m, dir, opt); break;
        case Fmt::VENDOR_BOOT: result = repack_vendor_boot(m, dir, opt); break;
        case Fmt::DTBO: result = repack_dtbo(m, dir, opt); break;
        case Fmt::DTB: result = repack_dtb(m, dir); break;
        case Fmt::VBMETA: result = repack_vbmeta(m, dir, opt); break;
        case Fmt::UIMAGE: result = repack_uimage(m, dir); break;
        case Fmt::ELF_BOOT: result = repack_elf_boot(m, dir, opt); break;
        case Fmt::KRNL: result = repack_krnl(m, dir, opt); break;
        case Fmt::BLOB: result = repack_blob(m, dir); break;
        case Fmt::OSIP: result = repack_osip(m, dir, opt); break;
        case Fmt::CHROMEOS: result = repack_chromeos(m, dir, opt); break;
        case Fmt::UNKNOWN:
            throw FormatError("manifest.txt has no (or an unrecognized) 'type=' field");
    }

    if (opt.avb1_signer && f != Fmt::BOOT)
        warn("--avb1-key/--avb1-cert only apply to boot and recovery images; ignored here");
    if ((opt.chromeos.key || opt.chromeos.keyblock) && f != Fmt::CHROMEOS && !m.get_bool("has_chromeos", false))
        warn("--chromeos-key/--chromeos-keyblock only apply to a ChromeOS kernel blob; ignored here");

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
void self_check(const fs::path& outdir, const Bytes& original) {
    try {
        Bytes rebuilt = build_image(outdir, RepackOptions{});
        if (rebuilt == original) {
            std::cout << "round-trip: an untouched repack reproduces this image byte-for-byte\n";
            return;
        }
        std::ostringstream os;
        os << "an untouched repack does NOT reproduce this image exactly (source " << original.size()
           << " bytes, rebuilt " << rebuilt.size() << " bytes, first difference at offset 0x"
           << std::hex << first_difference(original, rebuilt) << std::dec
           << "). The unpacked files are still usable, but please report this image.";
        warn(os.str());
    } catch (const std::exception& e) {
        warn(std::string("could not verify the round trip: ") + e.what());
    }
}

void do_unpack(const fs::path& in, const fs::path& outdir, const UnpackOptions& uo) {
    Bytes data = read_file(in);

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
            case Fmt::BOOT: unpack_boot(payload, outdir, uo); break;
            case Fmt::VENDOR_BOOT: unpack_vendor_boot(payload, outdir, uo); break;
            case Fmt::DTBO: unpack_dtbo(payload, outdir); break;
            case Fmt::DTB: unpack_dtb(payload, outdir); break;
            case Fmt::VBMETA: unpack_vbmeta(payload, outdir); break;
            case Fmt::UIMAGE: unpack_uimage(payload, outdir); break;
            case Fmt::ELF_BOOT: unpack_elf_boot(payload, outdir); break;
            case Fmt::KRNL: unpack_krnl(payload, outdir, uo); break;
            case Fmt::BLOB: unpack_blob(payload, outdir); break;
            case Fmt::OSIP: unpack_osip(payload, outdir, uo); break;
            case Fmt::CHROMEOS: unpack_chromeos(payload, outdir); break;
            case Fmt::UNKNOWN:
                throw FormatError(in.string() + ": " + describe_unknown(payload));
        }

        if (wrap.any()) {
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
                   "abr manifest (" + what + ") -- edit then `abr repack " + outdir.string() + " -o out.img`");
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
    self_check(outdir, data);
}

void do_repack(const fs::path& dir, const fs::path& out, const RepackOptions& opt) {
    Manifest m = Manifest::load(dir / "manifest.txt");
    Fmt f = fmt_from_name(m.get("type"));
    Bytes result = build_image(dir, opt);
    write_file(out, result);
    std::cout << "repacked " << fmt_name(f) << " -> " << out.string() << " (" << result.size()
              << " bytes)\n";
}

// --avb1-key is a key file, or -- as in Android Image Kitchen -- a base name N
// with N.pk8 and N.x509.pem (or .der) beside each other.
Signer load_avb1_signer(const std::string& key_arg, const std::string& cert_arg) {
    if (key_arg.empty()) throw FormatError("--avb1-cert needs --avb1-key");
    fs::path key_path = key_arg;
    fs::path cert_path = cert_arg;
    if (!fs::exists(key_path)) {
        fs::path pk8 = key_arg + ".pk8";
        if (!fs::exists(pk8))
            throw FormatError("cannot find the AVBv1 signing key '" + key_arg + "' (nor '" +
                              key_arg + ".pk8')");
        key_path = pk8;
        if (cert_arg.empty())
            for (const char* ext : {".x509.pem", ".x509.der", ".x509.crt"})
                if (fs::exists(key_arg + ext)) {
                    cert_path = key_arg + ext;
                    break;
                }
    }
    Bytes key = read_file(key_path);
    Bytes cert = cert_path.empty() ? Bytes() : read_file(cert_path);
    return make_signer(key, cert);
}

void usage() {
    std::cout <<
        "abr -- Android boot-family image unpacker/repacker\n\n"
        "  abr [-j N] info   <image>\n"
        "  abr [-j N] unpack <image> [-o <outdir>] [--no-tree | --tree-only]\n"
        "  abr [-j N] repack <dir> -o <image> [--avb-key <private_key.pem>]\n"
        "                              [--avb1-key <key> [--avb1-cert <cert.pem|cert.der>]]\n"
        "                              [--ramdisk-from tree|cpio]\n"
        "                              [--chromeos-key <.vbprivk> [--chromeos-keyblock <.keyblock>]]\n"
        "  abr identify [-b] <file>...    what it is, worded like Android Image Kitchen's\n"
        "                                 `file -m androidbootimg.magic` (-b: the label only)\n\n"
        "  -j N         threads to use (default: the number of cores, at most 16; 1 = one\n"
        "               thread; also ABR_THREADS=N). The result never depends on it.\n"
        "  --avb-key    signing key for AVB 2.0 (vbmeta / footers): PEM or DER (.pk8)\n"
        "  --avb1-key   key for the old boot_signer signature of a boot image (the public AOSP\n"
        "               test key is used when omitted); <key> may be a PEM/DER file or, as in\n"
        "               Android Image Kitchen, a base name N with N.pk8 and N.x509.pem\n"
        "  --chromeos-key  key (.vbprivk) to sign a ChromeOS kernel blob with, and\n"
        "  --chromeos-keyblock  the keyblock (.keyblock) made for it; without them the signatures\n"
        "               of the original are kept while the content is unchanged, and made with the\n"
        "               public developer key of vboot_reference (as Android Image Kitchen does) when not\n"
        "  A ramdisk is unpacked twice: ramdisk.cpio (exactly what the image held) and, when it\n"
        "  can be one, the directory ramdisk/ with ramdisk.meta (owners, modes, order). Edit\n"
        "  either; repack takes the one that changed (--ramdisk-from decides if both did).\n"
        "  --no-tree    unpack: write ramdisk.cpio only\n"
        "  --tree-only  unpack: write the directory only (ramdisk.cpio is dropped when the\n"
        "               directory gives it back exactly)\n\n"
        "Supported: boot.img/init_boot.img/boot-debug.img/boot-test-harness.img,\n"
        "recovery.img/recovery-two-step.img (header v0-v4), vendor_boot.img/\n"
        "vendor_boot-debug.img/vendor_kernel_boot.img (header v3-v4), dtbo.img,\n"
        "raw dtb, vbmeta.img/vbmeta_system.img (AVB), U-Boot legacy uImage, Sony ELF\n"
        "boot images, Rockchip KRNL (kernel.img / boot.img), ASUS blobs (\"MSM-RADIO-UPDATE\",\n"
        "signed with the SIGNBLOB header or not), Intel OSIP boot images, ChromeOS kernel blobs\n"
        "(the vboot format of a Chromebook's kernel partition).\n"
        "Also transparently handled: a trailing AVB hash footer on boot/\n"
        "vendor_boot/dtbo; a DHTB wrapper (with SEAndroid footer/padding) around\n"
        "any of them; a ChromeOS kernel blob or an ASUS blob around one image; the LOKI patch (loki_tool) of a\n"
        "boot or recovery image; the AMONET patch of Amazon's Fire tablets; a MediaTek\n"
        "(MTK) sub-header on the kernel and/or ramdisk.\n";
}

// -j N, -jN, --threads N and --threads=N, wherever they stand on the command
// line: the most threads abr may use (0 = automatic, 1 = none besides the main
// thread). Removes them from `v`; returns an error text, empty when fine.
std::string take_threads_option(std::vector<std::string>& v) {
    for (size_t i = 0; i < v.size();) {
        const std::string a = v[i];
        std::string value;
        size_t used = 1;
        if (a == "-j" || a == "--threads") {
            if (i + 1 >= v.size()) return a + " needs a number";
            value = v[i + 1];
            used = 2;
        } else if (a.rfind("--threads=", 0) == 0) {
            value = a.substr(10);
        } else if (a.size() > 2 && a.compare(0, 2, "-j") == 0 && std::isdigit(static_cast<unsigned char>(a[2]))) {
            value = a.substr(2);
        } else {
            ++i;
            continue;
        }
        if (value.empty() || value.size() > 4 ||
            !std::all_of(value.begin(), value.end(), [](char c) { return c >= '0' && c <= '9'; }))
            return "the number of threads must be a whole number (0 = automatic), not '" + value + "'";
        par::set_max_threads(static_cast<unsigned>(std::stoul(value)));
        v.erase(v.begin() + static_cast<long>(i), v.begin() + static_cast<long>(i + used));
    }
    return "";
}

}  // namespace

int main(int argc, char** argv) {
    set_binary_stdio();
    if (!hash::sha_selftest()) {
        std::cerr << "internal error: bundled SHA implementation failed its self-test; "
                     "refusing to run since boot ids and AVB hashes would be silently wrong\n";
        return 2;
    }
    try {
        if (argc < 2) {
            usage();
            return 1;
        }
        std::vector<std::string> args(argv + 1, argv + argc);
        if (std::string err = take_threads_option(args); !err.empty()) {
            std::cerr << "error: " << err << "\n";
            return 1;
        }
        if (args.empty()) {
            usage();
            return 1;
        }
        const std::string cmd = args.front();
        args.erase(args.begin());

        if (cmd == "info") {
            if (args.empty()) { usage(); return 1; }
            print_info(args[0]);
        } else if (cmd == "unpack") {
            if (args.empty()) { usage(); return 1; }
            fs::path in = args[0];
            fs::path outdir = in.stem();
            UnpackOptions uo;
            for (size_t i = 1; i < args.size(); ++i) {
                if ((args[i] == "-o" || args[i] == "--output") && i + 1 < args.size())
                    outdir = args[++i];
                else if (args[i] == "--no-tree")
                    uo.tree = false;
                else if (args[i] == "--tree-only")
                    uo.keep_cpio = false;
                else {
                    std::cerr << "unpack: unknown option " << args[i] << "\n";
                    return 1;
                }
            }
            if (!uo.tree && !uo.keep_cpio) {
                std::cerr << "unpack: --no-tree and --tree-only contradict each other\n";
                return 1;
            }
            do_unpack(in, outdir, uo);
        } else if (cmd == "identify") {
            bool brief = false;
            std::vector<std::string> files;
            for (const std::string& a : args) {
                if (a == "-b" || a == "--brief") brief = true;
                else files.push_back(a);
            }
            if (files.empty()) { usage(); return 1; }
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
        } else if (cmd == "repack") {
            if (args.empty()) { usage(); return 1; }
            fs::path dir = args[0];
            fs::path out;
            RepackOptions opt;
            std::string avb1_key, avb1_cert, chromeos_key, chromeos_keyblock;
            for (size_t i = 1; i < args.size(); ++i) {
                if ((args[i] == "-o" || args[i] == "--output") && i + 1 < args.size())
                    out = args[++i];
                else if (args[i] == "--avb-key" && i + 1 < args.size()) {
                    Bytes key_bytes = read_file(args[++i]);
                    opt.avb_key_pem.assign(reinterpret_cast<const char*>(key_bytes.data()),
                                           key_bytes.size());
                } else if (args[i] == "--avb1-key" && i + 1 < args.size())
                    avb1_key = args[++i];
                else if (args[i] == "--avb1-cert" && i + 1 < args.size())
                    avb1_cert = args[++i];
                else if (args[i] == "--chromeos-key" && i + 1 < args.size())
                    chromeos_key = args[++i];
                else if (args[i] == "--chromeos-keyblock" && i + 1 < args.size())
                    chromeos_keyblock = args[++i];
                else if (args[i] == "--ramdisk-from" && i + 1 < args.size()) {
                    opt.ramdisk_from = args[++i];
                    if (opt.ramdisk_from != "tree" && opt.ramdisk_from != "cpio") {
                        std::cerr << "repack: --ramdisk-from takes 'tree' or 'cpio', not '" << opt.ramdisk_from
                                  << "'\n";
                        return 1;
                    }
                }
                else if (args[i].rfind("-", 0) == 0) {
                    std::cerr << "repack: unknown option " << args[i] << "\n";
                    return 1;
                }
            }
            if (out.empty()) { std::cerr << "repack: -o <output image> is required\n"; return 1; }
            if (!avb1_key.empty() || !avb1_cert.empty())
                opt.avb1_signer = load_avb1_signer(avb1_key, avb1_cert);
            if (!chromeos_key.empty()) {
                try {
                    opt.chromeos.key = parse_vbprivk(read_file(chromeos_key));
                } catch (const FormatError& e) {
                    throw FormatError("--chromeos-key " + chromeos_key + ": " + e.what());
                }
            }
            if (!chromeos_keyblock.empty()) {
                Bytes keyblock = read_file(chromeos_keyblock);
                if (!has_chromeos_header(keyblock))
                    throw FormatError("--chromeos-keyblock " + chromeos_keyblock + " is not a keyblock (it does not start with \"CHROMEOS\")");
                try {
                    keyblock_data_key(keyblock);  // is it one?
                } catch (const FormatError& e) {
                    throw FormatError("--chromeos-keyblock " + chromeos_keyblock + ": " + e.what());
                }
                opt.chromeos.keyblock = std::move(keyblock);
            }
            do_repack(dir, out, opt);
        } else {
            usage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
