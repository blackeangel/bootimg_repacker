// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr -- Android boot-family image unpacker/repacker CLI.
//
//   abr info    <image>
//   abr unpack  <image> [-o <outdir>]
//   abr repack  <dir>   -o <image> [--avb-key <private_key.pem>]
//
// Format is auto-detected from magic bytes; see detect_format() below.
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "abr/boot_image.hpp"
#include "abr/byte_io.hpp"
#include "abr/compression.hpp"
#include "abr/dtb.hpp"
#include "abr/dtbo.hpp"
#include "abr/legacy/dhtb.hpp"
#include "abr/legacy/mtk.hpp"
#include "abr/manifest.hpp"
#include "abr/sha.hpp"
#include "abr/uimage.hpp"
#include "abr/vbmeta.hpp"
#include "abr/vendor_boot.hpp"

namespace fs = std::filesystem;
using namespace abr;
using namespace abr::legacy;

namespace {

// ------------------------------------------------------------ detection --

enum class Fmt { BOOT, VENDOR_BOOT, DTBO, DTB, VBMETA, UIMAGE, UNKNOWN };

Fmt detect_format(const Bytes& d) {
    if (d.size() >= 8 && std::memcmp(d.data(), "ANDROID!", 8) == 0) return Fmt::BOOT;
    if (d.size() >= 8 && std::memcmp(d.data(), "VNDRBOOT", 8) == 0) return Fmt::VENDOR_BOOT;
    if (d.size() >= 4 && std::memcmp(d.data(), "AVB0", 4) == 0) return Fmt::VBMETA;
    if (d.size() >= 4) {
        uint32_t be = (uint32_t(d[0]) << 24) | (uint32_t(d[1]) << 16) | (uint32_t(d[2]) << 8) | d[3];
        if (be == kDtTableMagic || be == kAcpioTableMagic) return Fmt::DTBO;
        if (be == kFdtMagic) return Fmt::DTB;
        if (be == kUimageMagic) return Fmt::UIMAGE;
    }
    if (d.size() >= 64 && std::memcmp(d.data() + d.size() - 64, "AVBf", 4) == 0) return Fmt::VBMETA;
    return Fmt::UNKNOWN;
}

const char* fmt_name(Fmt f) {
    switch (f) {
        case Fmt::BOOT: return "boot";
        case Fmt::VENDOR_BOOT: return "vendor_boot";
        case Fmt::DTBO: return "dtbo";
        case Fmt::DTB: return "dtb";
        case Fmt::VBMETA: return "vbmeta";
        case Fmt::UIMAGE: return "uimage";
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
    return Fmt::UNKNOWN;
}

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
// through save_component/load_component (boot's kernel/ramdisk,
// vendor_boot's ramdisk fragments) since any of them could have one.
void save_component(Manifest& m, const fs::path& dir, const std::string& prefix, const Bytes& raw,
                     const std::string& filename) {
    if (raw.empty()) return;
    Bytes after_mtk;
    auto mtk = strip_mtk_header(raw, after_mtk);
    if (mtk) m.set(prefix + "_mtk_name", mtk->name);
    const Bytes& working = mtk ? after_mtk : raw;

    Codec c = detect_codec(working);
    Bytes plain = decompress(c, working);
    m.set(prefix + "_file", filename);
    m.set(prefix + "_compression", std::string(codec_name(c)));
    write_file(dir / filename, plain);
    m.set_hex(prefix + "_orig_hash", hash::sha256(plain));
    fs::path raw_dir = dir / ".abr_raw";
    fs::create_directories(raw_dir);
    write_file(raw_dir / (filename + ".raw"), working);  // stored *without* the MTK header
}

Bytes load_component(const Manifest& m, const fs::path& dir, const std::string& prefix) {
    std::string key = prefix + "_file";
    if (!m.has(key)) return {};
    std::string filename = m.get(key);
    Bytes plain = read_file(dir / filename);

    Bytes result;
    bool have_result = false;
    Bytes stored_hash = m.get_hex(prefix + "_orig_hash");
    if (!stored_hash.empty()) {
        fs::path raw_path = dir / ".abr_raw" / (filename + ".raw");
        if (hash::sha256(plain) == stored_hash && fs::exists(raw_path)) {
            result = read_file(raw_path);
            have_result = true;
        }
    }
    if (!have_result) {
        auto c = codec_from_name(m.get(prefix + "_compression", "none"));
        result = compress(c.value_or(Codec::NONE), plain);
    }
    if (m.has(prefix + "_mtk_name")) result = add_mtk_header(result, m.get(prefix + "_mtk_name"));
    return result;
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
bool save_avb_tail(Manifest& m, const fs::path& dir, const Bytes& whole_file) {
    if (whole_file.size() < 64 ||
        std::memcmp(whole_file.data() + whole_file.size() - 64, "AVBf", 4) != 0)
        return false;
    VbmetaImage v;
    try {
        v = VbmetaImage::parse(whole_file);
    } catch (const FormatError&) {
        return false;  // "AVBf"-looking bytes that don't actually parse; leave as opaque tail
    }
    if (!v.has_footer) return false;

    m.set_bool("has_avb_footer", true);
    m.set_u64("avb_partition_size", v.source_total_size);
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
    return true;
}

// primary_content is the freshly-*built* (possibly-edited) primary
// format's bytes; returns it unchanged if there was no footer to
// restore, or the full [primary_content][...][footer] file otherwise.
Bytes reattach_avb_tail(const Manifest& m, const fs::path& dir, Bytes primary_content,
                         const std::string& avb_key_pem) {
    if (!m.get_bool("has_avb_footer", false)) return primary_content;
    VbmetaImage v;
    v.has_footer = true;
    v.source_total_size = m.get_u64("avb_partition_size", 0);
    v.footer_original_image_size = primary_content.size();
    v.host_prefix = std::move(primary_content);
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
    return v.build(avb_key_pem);
}

// ------------------------------------------------------------- boot.img --

void unpack_boot(const Bytes& data, const fs::path& dir) {
    BootImage img = BootImage::parse(data);
    Manifest m;
    m.set("type", "boot");
    m.set_u32("header_version", img.header_version);
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
        if (img.header_version >= 2) m.set_addr("dtb_addr", img.dtb_addr);
    }
    m.set("os_version", img.os_version.to_string());
    m.set("os_patch_level", img.os_version.patch_level_string());
    m.set("cmdline", img.cmdline);

    save_component(m, dir, "kernel", img.kernel, "kernel");
    save_component(m, dir, "ramdisk", img.ramdisk, "ramdisk.cpio");
    save_component(m, dir, "second", img.second, "second");
    save_raw(m, dir, "recovery_dtbo", img.recovery_dtbo, "recovery_dtbo.img");
    save_raw(m, dir, "dtb", img.dtb, "dtb");
    save_raw(m, dir, "boot_signature", img.boot_signature, "boot_signature.bin");
    save_avb_tail(m, dir, data);

    m.save(dir / "manifest.txt", "abr boot manifest -- edit then `abr repack " + dir.string() +
                                      " -o out.img`");
}

Bytes repack_boot(const Manifest& m, const fs::path& dir, const std::string& avb_key_pem) {
    BootImage img;
    img.header_version = m.get_u32("header_version", 4);
    if (img.header_version <= 2) {
        img.page_size = m.get_u32("page_size", 2048);
        img.kernel_addr = static_cast<uint32_t>(m.get_addr("kernel_addr", 0x00008000));
        img.ramdisk_addr = static_cast<uint32_t>(m.get_addr("ramdisk_addr", 0x01000000));
        img.second_addr = static_cast<uint32_t>(m.get_addr("second_addr", 0x00f00000));
        img.tags_addr = static_cast<uint32_t>(m.get_addr("tags_addr", 0x00000100));
        img.board_name = m.get("board_name");
        if (img.header_version >= 2) img.dtb_addr = static_cast<uint32_t>(m.get_addr("dtb_addr", 0));
    }
    auto ov = OsVersion::parse(m.get("os_version"), m.get("os_patch_level"));
    if (ov) img.os_version = *ov;
    img.cmdline = m.get("cmdline");

    img.kernel = load_component(m, dir, "kernel");
    img.ramdisk = load_component(m, dir, "ramdisk");
    img.second = load_component(m, dir, "second");
    img.recovery_dtbo = load_raw(m, dir, "recovery_dtbo");
    img.dtb = load_raw(m, dir, "dtb");
    img.boot_signature = load_raw(m, dir, "boot_signature");
    img.recompute_id();  // content hash -- recompute fresh rather than trust a possibly-stale manifest value

    return reattach_avb_tail(m, dir, img.build(), avb_key_pem);
}

// ------------------------------------------------------- vendor_boot.img --

void unpack_vendor_boot(const Bytes& data, const fs::path& dir) {
    VendorBootImage img = VendorBootImage::parse(data);
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
    save_raw(m, dir, "dtb", img.dtb, "dtb");
    save_raw(m, dir, "bootconfig", img.bootconfig, "bootconfig");

    m.set_u32("ramdisk_count", static_cast<uint32_t>(img.ramdisk_fragments.size()));
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
        save_component(m, dir, p, e.data, p + ".cpio");
    }
    save_avb_tail(m, dir, data);
    m.save(dir / "manifest.txt", "abr vendor_boot manifest -- edit then `abr repack " +
                                      dir.string() + " -o out.img`");
}

Bytes repack_vendor_boot(const Manifest& m, const fs::path& dir, const std::string& avb_key_pem) {
    VendorBootImage img;
    img.header_version = m.get_u32("header_version", 4);
    img.page_size = m.get_u32("page_size", 4096);
    img.kernel_addr = static_cast<uint32_t>(m.get_addr("kernel_addr", 0x00008000));
    img.ramdisk_addr = static_cast<uint32_t>(m.get_addr("ramdisk_addr", 0x01000000));
    img.tags_addr = static_cast<uint32_t>(m.get_addr("tags_addr", 0x00000100));
    img.board_name = m.get("board_name");
    img.cmdline = m.get("cmdline");
    img.dtb_addr = m.get_addr("dtb_addr", 0);
    img.dtb = load_raw(m, dir, "dtb");
    img.bootconfig = load_raw(m, dir, "bootconfig");

    uint32_t count = m.get_u32("ramdisk_count", 0);
    for (uint32_t i = 0; i < count; ++i) {
        std::string p = "ramdisk" + std::to_string(i);
        VendorRamdiskEntry e;
        e.type = vendor_ramdisk_type_from_name(m.get(p + "_type", "platform"));
        e.name = m.get(p + "_name");
        Bytes b = m.get_hex(p + "_board_id");
        for (size_t j = 0; j < e.board_id.size() && j * 4 + 3 < b.size(); ++j)
            e.board_id[j] = uint32_t(b[j * 4]) | (uint32_t(b[j * 4 + 1]) << 8) |
                             (uint32_t(b[j * 4 + 2]) << 16) | (uint32_t(b[j * 4 + 3]) << 24);
        e.data = load_component(m, dir, p);
        img.ramdisk_fragments.push_back(std::move(e));
    }
    return reattach_avb_tail(m, dir, img.build(), avb_key_pem);
}

// ------------------------------------------------------------ dtbo.img --

void unpack_dtbo(const Bytes& data, const fs::path& dir) {
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
    save_avb_tail(m, dir, data);
    m.save(dir / "manifest.txt",
           "abr dtbo manifest -- edit then `abr repack " + dir.string() + " -o out.img`");
}

Bytes repack_dtbo(const Manifest& m, const fs::path& dir, const std::string& avb_key_pem) {
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
    return reattach_avb_tail(m, dir, img.build(), avb_key_pem);
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

Bytes repack_vbmeta(const Manifest& m, const fs::path& dir, const std::string& avb_key_pem) {
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
    return v.build(avb_key_pem);
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

// ------------------------------------------------------------ info cmd --

void print_info(const fs::path& path) {
    Bytes raw = read_file(path);
    Bytes inner;
    auto dhtb = strip_dhtb(raw, inner);
    const Bytes& data = dhtb ? inner : raw;

    Fmt f = detect_format(data);
    std::cout << "file:   " << path.string() << " (" << raw.size() << " bytes)\n";
    if (dhtb) {
        std::cout << "wrapper: DHTB (" << (dhtb->has_seandroid_footer ? "+SEAndroid footer " : "")
                   << (dhtb->has_padding ? "+padding " : "") << ", inner " << data.size()
                   << " bytes)\n";
    }
    std::cout << "format: " << fmt_name(f) << "\n";
    switch (f) {
        case Fmt::BOOT: {
            BootImage img = BootImage::parse(data);
            std::cout << "header_version: " << img.header_version << "\n";
            std::cout << "os_version:     " << img.os_version.to_string() << "\n";
            std::cout << "patch_level:    " << img.os_version.patch_level_string() << "\n";
            std::cout << "cmdline:        " << img.cmdline << "\n";
            std::cout << "kernel:         " << img.kernel.size() << " bytes ("
                       << codec_name(detect_codec(img.kernel)) << ")\n";
            std::cout << "ramdisk:        " << img.ramdisk.size() << " bytes ("
                       << codec_name(detect_codec(img.ramdisk)) << ")\n";
            if (!img.second.empty()) std::cout << "second:         " << img.second.size() << " bytes\n";
            if (!img.recovery_dtbo.empty())
                std::cout << "recovery_dtbo:  " << img.recovery_dtbo.size() << " bytes\n";
            if (!img.dtb.empty()) std::cout << "dtb:            " << img.dtb.size() << " bytes\n";
            if (!img.boot_signature.empty())
                std::cout << "boot_signature: " << img.boot_signature.size() << " bytes\n";
            break;
        }
        case Fmt::VENDOR_BOOT: {
            VendorBootImage img = VendorBootImage::parse(data);
            std::cout << "header_version: " << img.header_version << "\n";
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
            break;
        }
        case Fmt::DTBO: {
            DtboImage img = DtboImage::parse(data);
            std::cout << "version:   " << img.version << (img.acpio ? " (ACPIO)" : " (DTBO)") << "\n";
            std::cout << "entries:   " << img.entries.size() << "\n";
            for (size_t i = 0; i < img.entries.size(); ++i)
                std::cout << "  [" << i << "] id=0x" << std::hex << img.entries[i].id << std::dec
                          << " rev=" << img.entries[i].rev << " size=" << img.entries[i].data.size()
                          << "\n";
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
        case Fmt::UNKNOWN:
            std::cout << "(unrecognized format)\n";
            break;
    }
}

// ------------------------------------------------------------- dispatch --

void do_unpack(const fs::path& in, const fs::path& outdir) {
    Bytes data = read_file(in);
    fs::create_directories(outdir);

    Bytes inner;
    auto dhtb = strip_dhtb(data, inner);
    const Bytes& payload = dhtb ? inner : data;

    Fmt f = detect_format(payload);
    switch (f) {
        case Fmt::BOOT: unpack_boot(payload, outdir); break;
        case Fmt::VENDOR_BOOT: unpack_vendor_boot(payload, outdir); break;
        case Fmt::DTBO: unpack_dtbo(payload, outdir); break;
        case Fmt::DTB: unpack_dtb(payload, outdir); break;
        case Fmt::VBMETA: unpack_vbmeta(payload, outdir); break;
        case Fmt::UIMAGE: unpack_uimage(payload, outdir); break;
        case Fmt::UNKNOWN: throw FormatError("unrecognized image format: " + in.string());
    }

    if (dhtb) {
        Manifest m = Manifest::load(outdir / "manifest.txt");
        m.set_bool("has_dhtb", true);
        m.set_bool("dhtb_seandroid_footer", dhtb->has_seandroid_footer);
        m.set_bool("dhtb_padding", dhtb->has_padding);
        save_raw(m, outdir, "dhtb_trailing_extra", dhtb->trailing_extra, "dhtb_trailing_extra.bin");
        m.save(outdir / "manifest.txt",
               "abr manifest (DHTB-wrapped) -- edit then `abr repack " + outdir.string() +
                   " -o out.img`");
    }

    std::cout << "unpacked " << (dhtb ? std::string("dhtb-wrapped ") : std::string()) << fmt_name(f)
              << " -> " << outdir.string() << "/\n";
}

void do_repack(const fs::path& dir, const fs::path& out, const std::string& avb_key_pem) {
    Manifest m = Manifest::load(dir / "manifest.txt");
    Fmt f = fmt_from_name(m.get("type"));
    Bytes result;
    switch (f) {
        case Fmt::BOOT: result = repack_boot(m, dir, avb_key_pem); break;
        case Fmt::VENDOR_BOOT: result = repack_vendor_boot(m, dir, avb_key_pem); break;
        case Fmt::DTBO: result = repack_dtbo(m, dir, avb_key_pem); break;
        case Fmt::DTB: result = repack_dtb(m, dir); break;
        case Fmt::VBMETA: result = repack_vbmeta(m, dir, avb_key_pem); break;
        case Fmt::UIMAGE: result = repack_uimage(m, dir); break;
        case Fmt::UNKNOWN:
            throw FormatError("manifest.txt has no (or an unrecognized) 'type=' field");
    }

    if (m.get_bool("has_dhtb", false)) {
        legacy::DhtbInfo dhtb;
        dhtb.has_seandroid_footer = m.get_bool("dhtb_seandroid_footer", false);
        dhtb.has_padding = m.get_bool("dhtb_padding", false);
        dhtb.trailing_extra = load_raw(m, dir, "dhtb_trailing_extra");
        result = wrap_dhtb(result, dhtb);
    }

    write_file(out, result);
    std::cout << "repacked " << fmt_name(f) << " -> " << out.string() << " (" << result.size()
              << " bytes)\n";
}

void usage() {
    std::cout <<
        "abr -- Android boot-family image unpacker/repacker\n\n"
        "  abr info   <image>\n"
        "  abr unpack <image> [-o <outdir>]\n"
        "  abr repack <dir> -o <image> [--avb-key <private_key.pem>]\n\n"
        "Supported: boot.img/init_boot.img/boot-debug.img/boot-test-harness.img,\n"
        "recovery.img/recovery-two-step.img (header v0-v4), vendor_boot.img/\n"
        "vendor_boot-debug.img/vendor_kernel_boot.img (header v3-v4), dtbo.img,\n"
        "raw dtb, vbmeta.img/vbmeta_system.img (AVB), U-Boot legacy uImage.\n"
        "Also transparently handled: a trailing AVB hash footer on boot/\n"
        "vendor_boot/dtbo; a DHTB wrapper (with SEAndroid footer/padding) around\n"
        "any of them; a MediaTek (MTK) sub-header on the kernel and/or ramdisk.\n";
}

}  // namespace

int main(int argc, char** argv) {
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
        std::string cmd = argv[1];
        std::vector<std::string> args(argv + 2, argv + argc);

        if (cmd == "info") {
            if (args.empty()) { usage(); return 1; }
            print_info(args[0]);
        } else if (cmd == "unpack") {
            if (args.empty()) { usage(); return 1; }
            fs::path in = args[0];
            fs::path outdir = in.stem();
            for (size_t i = 1; i < args.size(); ++i)
                if ((args[i] == "-o" || args[i] == "--output") && i + 1 < args.size())
                    outdir = args[++i];
            do_unpack(in, outdir);
        } else if (cmd == "repack") {
            if (args.empty()) { usage(); return 1; }
            fs::path dir = args[0];
            fs::path out;
            std::string avb_key_pem;
            for (size_t i = 1; i < args.size(); ++i) {
                if ((args[i] == "-o" || args[i] == "--output") && i + 1 < args.size())
                    out = args[++i];
                else if (args[i] == "--avb-key" && i + 1 < args.size()) {
                    Bytes key_bytes = read_file(args[++i]);
                    avb_key_pem.assign(reinterpret_cast<const char*>(key_bytes.data()),
                                        key_bytes.size());
                }
            }
            if (out.empty()) { std::cerr << "repack: -o <output image> is required\n"; return 1; }
            do_repack(dir, out, avb_key_pem);
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
