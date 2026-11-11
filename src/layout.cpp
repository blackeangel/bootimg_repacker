// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/layout.hpp"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <map>

#include "abr/boot_image.hpp"
#include "abr/compression.hpp"
#include "abr/dtbo.hpp"
#include "abr/envelope.hpp"
#include "abr/legacy/blob.hpp"
#include "abr/legacy/chromeos.hpp"
#include "abr/legacy/elf_boot.hpp"
#include "abr/legacy/krnl.hpp"
#include "abr/legacy/osip.hpp"
#include "abr/mbn.hpp"
#include "abr/mtkgfh.hpp"
#include "abr/mtkimg.hpp"
#include "abr/qcdt.hpp"
#include "abr/splash.hpp"
#include "abr/uimage.hpp"
#include "abr/vbmeta.hpp"
#include "abr/vendor_boot.hpp"

namespace abr::layout {

namespace {

bool within(const Bytes& d, uint64_t off, uint64_t n) { return off <= d.size() && n <= d.size() - off; }

uint32_t be32(const Bytes& d, uint64_t o) {
    return (uint32_t{d[o]} << 24) | (uint32_t{d[o + 1]} << 16) | (uint32_t{d[o + 2]} << 8) | uint32_t{d[o + 3]};
}
uint64_t be64(const Bytes& d, uint64_t o) { return (uint64_t{be32(d, o)} << 32) | be32(d, o + 4); }
uint32_t le32(const Bytes& d, uint64_t o) {
    return uint32_t{d[o]} | (uint32_t{d[o + 1]} << 8) | (uint32_t{d[o + 2]} << 16) | (uint32_t{d[o + 3]} << 24);
}

uint16_t le16(const Bytes& d, uint64_t o) { return static_cast<uint16_t>(uint32_t{d[o]} | (uint32_t{d[o + 1]} << 8)); }
uint64_t le64(const Bytes& d, uint64_t o) { return uint64_t{le32(d, o)} | (uint64_t{le32(d, o + 4)} << 32); }

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%" PRIx64, v);
    return b;
}

// The stream a part is, by its first bytes ("" for plain data).
std::string codec_of(const Bytes& b) {
    const Codec c = detect_codec(b);
    return c == Codec::NONE ? std::string() : std::string(codec_name(c));
}

// The stream the `n` bytes at `off` are, by their first bytes (the magic of a codec is all there is to look at).
std::string codec_at(const Bytes& d, uint64_t off, uint64_t n) {
    if (!within(d, off, n) || n == 0) return {};
    const auto first = d.begin() + static_cast<std::ptrdiff_t>(off);
    return codec_of(Bytes(first, first + static_cast<std::ptrdiff_t>(std::min<uint64_t>(n, 64))));
}

}  // namespace

Region& Layout::add(std::string name, std::string key, uint64_t offset, uint64_t size, unsigned depth, std::string note) {
    Region r;
    r.name = std::move(name);
    r.key = std::move(key);
    r.offset = offset;
    r.size = size;
    r.depth = depth;
    r.note = std::move(note);
    regions.push_back(std::move(r));
    return regions.back();
}

void Layout::shift(uint64_t by) {
    for (Region& r : regions) r.offset += by;
}

// ------------------------------------------------------------------------------------------------ the containers --

Layout boot(const BootImage& img) {
    Layout l;
    const uint32_t page = (img.header_version <= 2 || img.pxa) ? (img.page_size ? img.page_size : 2048) : 4096;
    l.format = "boot image, header version " + std::to_string(img.header_version) + (img.pxa ? " (Marvell PXA)" : "");
    // The header takes the pages it needs: one, unless the page is smaller than the header (512 or 1024 bytes).
    static constexpr uint32_t kHeaderBytes[] = {1632, 1648, 1660, 1580, 1584};  // version 0 to 4 (the PXA header: 1640)
    const uint64_t header_bytes = img.pxa ? 1640 : kHeaderBytes[std::min<uint32_t>(img.header_version, 4)];
    const uint64_t header = align_up(header_bytes, page);
    l.add("header", "", 0, header, 0,
          "header version " + std::to_string(img.header_version) + ", " + std::to_string(header_bytes) + " bytes, page size " + std::to_string(page));
    uint64_t pos = header;
    auto part = [&](const char* name, const char* key, const Bytes& b, const std::string& note = {}) {
        if (b.empty()) return;
        Region& r = l.add(name, key, pos, b.size(), 0, note);
        r.codec = codec_of(b);
        pos = align_up(pos + b.size(), page);
    };
    part("kernel", "kernel", img.kernel);
    part("ramdisk", "ramdisk", img.ramdisk);
    part("second", "second", img.second, "second stage");
    part("dt", "dt", img.dt, qcdt::looks_like(img.dt) ? "Qualcomm device tree table (QCDT)" : "device tree");
    part("recovery dtbo", "recovery_dtbo", img.recovery_dtbo);
    part("dtb", "dtb", img.dtb, "device tree");
    part("boot signature", "boot_signature", img.boot_signature, "GKI boot signature");
    l.size = img.consumed;
    return l;
}

Layout vendor_boot(const VendorBootImage& img) {
    Layout l;
    const uint32_t page = img.page_size ? img.page_size : 4096;
    l.format = "vendor_boot image, header version " + std::to_string(img.header_version);
    const uint64_t header_bytes = img.header_version >= 4 ? 2128 : 2112;
    const uint64_t header = align_up(header_bytes, page);  // (two pages when the page is 2048 bytes: the header is a little larger)
    l.add("header", "", 0, header, 0,
          "header version " + std::to_string(img.header_version) + ", " + std::to_string(header_bytes) + " bytes, page size " + std::to_string(page));
    uint64_t pos = header;
    uint64_t total = 0;
    for (const VendorRamdiskEntry& e : img.ramdisk_fragments) total += e.data.size();
    if (total) {
        const bool single = img.ramdisk_fragments.size() == 1;
        Region& sec = l.add("vendor ramdisk", single ? "ramdisk0" : "", pos, total);
        if (single) sec.codec = codec_of(img.ramdisk_fragments[0].data);
        if (!single) {
            uint64_t at = pos;
            for (size_t i = 0; i < img.ramdisk_fragments.size(); ++i) {
                const VendorRamdiskEntry& e = img.ramdisk_fragments[i];
                std::string note = std::string(vendor_ramdisk_type_name(e.type));
                if (!e.name.empty()) note += ", " + e.name;
                Region& f = l.add("ramdisk fragment " + std::to_string(i), "ramdisk" + std::to_string(i), at, e.data.size(), 1, note);
                f.codec = codec_of(e.data);
                at += e.data.size();
            }
        }
    }
    pos = align_up(pos + total, page);
    if (!img.dtb.empty()) {
        l.add("dtb", "dtb", pos, img.dtb.size(), 0, "device trees");
        pos = align_up(pos + img.dtb.size(), page);
    }
    if (img.header_version >= 4 && img.has_ramdisk_table && !img.ramdisk_fragments.empty()) {
        const uint64_t n = img.ramdisk_fragments.size() * kVendorRamdiskTableEntrySize;
        l.add("vendor ramdisk table", "", pos, n, 0, std::to_string(img.ramdisk_fragments.size()) + " entries");
        pos = align_up(pos + n, page);
    }
    if (!img.bootconfig.empty()) {
        l.add("bootconfig", "bootconfig", pos, img.bootconfig.size());
        pos = align_up(pos + img.bootconfig.size(), page);
    }
    l.size = img.consumed;
    return l;
}

Layout dtbo(const Bytes& t) {
    Layout l;
    l.format = "dtbo image";
    l.size = t.size();
    if (t.size() < 32) return l;
    const uint32_t magic = be32(t, 0);
    const bool acpio = magic == kAcpioTableMagic;
    const uint32_t total = be32(t, 4), header_size = be32(t, 8), entry_size = be32(t, 12), count = be32(t, 16), entries_off = be32(t, 20),
                   page = be32(t, 24), version = be32(t, 28);
    l.format = std::string(acpio ? "ACPIO table" : "dtbo image") + ", version " + std::to_string(version);
    l.size = std::min<uint64_t>(total, t.size());
    if (within(t, 0, header_size))
        l.add("header", "", 0, header_size, 0, "version " + std::to_string(version) + ", page size " + std::to_string(page));
    if (count && entry_size && within(t, entries_off, uint64_t{count} * entry_size))
        l.add("entry table", "", entries_off, uint64_t{count} * entry_size, 0, std::to_string(count) + (count == 1 ? " entry" : " entries"));
    for (uint32_t i = 0; i < count; ++i) {
        const uint64_t er = entries_off + uint64_t{i} * entry_size;
        if (entry_size < 20 || !within(t, er, entry_size)) break;
        const uint32_t size = be32(t, er), off = be32(t, er + 4), id = be32(t, er + 8), rev = be32(t, er + 12);
        Region& r = l.add("entry " + std::to_string(i), "entry" + std::to_string(i), off, size, 0, "id " + hex(id) + ", rev " + hex(rev));
        if (version == 1) {
            const uint32_t comp = be32(t, er + 16) & 0x0f;  // the low nibble of flags: 1 zlib, 2 gzip
            if (comp == 1) r.codec = "zlib";
            if (comp == 2) r.codec = "gzip";
        }
    }
    return l;
}

Layout uimage(const UImage& img) {
    Layout l;
    l.format = "U-Boot legacy image (uImage)";
    l.add("header", "", 0, kUimageHeaderSize, 0, "os " + uboot_os_name(img.os) + ", arch " + uboot_arch_name(img.arch) + ", " + uboot_type_name(img.type));
    if (!img.data.empty()) {
        Region& r = l.add("data", "data", kUimageHeaderSize, img.data.size(), 0, "");
        r.codec = codec_of(img.data);
        if (r.codec.empty() && img.comp != 0) r.note = "compression " + uboot_comp_name(img.comp) + " says the header";
    }
    l.size = img.consumed;
    return l;
}

// A FIT image. The flattened tree is walked here (the bytes of the file, not what abr made of them), so that the numbers are the ones the
// file has: a `data` property is where the data of an image is when it is in the tree, data-size and data-offset or data-position say it when
// it is behind the tree (the offset counts from the end of the tree, a multiple of 4; the position from the start of the file).
Layout fit(const Bytes& d, const std::vector<std::string>& keys) {
    Layout l;
    l.format = "FIT image (U-Boot flattened image tree)";
    l.size = d.size();
    if (d.size() < 28 || be32(d, 0) != 0xd00dfeed) return l;
    const uint64_t total = be32(d, 4), off_struct = be32(d, 8), off_strings = be32(d, 12), off_rsv = be32(d, 16);
    const uint32_t version = be32(d, 20);
    const uint64_t size_strings = version >= 3 && d.size() >= 36 ? be32(d, 32) : 0;
    const uint64_t size_struct = version >= 17 && d.size() >= 40 ? be32(d, 36) : 0;
    if (total > d.size() || off_rsv > total || off_struct > total || off_strings > total || size_struct > total - off_struct ||
        size_strings > total - off_strings)
        return l;
    l.add("FDT header", "", 0, std::min<uint64_t>(off_rsv, version >= 17 ? 40 : 36), 0, "version " + std::to_string(version) + ", total size " + std::to_string(total));
    if (off_struct > off_rsv) l.add("memory reservation map", "", off_rsv, off_struct - off_rsv, 0, "");
    l.add("structure block", "", off_struct, size_struct, 0, "the nodes and properties of the tree");

    struct Img {
        std::string name, type;
        uint64_t data_at = 0, data_len = 0;
        bool inline_data = false;
        std::optional<uint32_t> size, offset, position;
    };
    std::vector<Img> images;
    std::vector<std::string> path;  // the names of the open nodes: ["", "images", "kernel-1"]
    auto text_at = [&](uint64_t at, uint64_t end) {
        std::string s;
        while (at < end && d[at]) s.push_back(static_cast<char>(d[at++]));
        return s;
    };
    uint64_t p = off_struct;
    const uint64_t end = off_struct + size_struct;
    bool walking = true;
    while (walking && p + 4 <= end) {
        const uint32_t token = be32(d, p);
        p += 4;
        switch (token) {
            case 1: {  // FDT_BEGIN_NODE, the name, padded to 4
                const uint64_t from = p;
                while (p < end && d[p]) ++p;
                if (p >= end) { walking = false; break; }
                path.push_back(std::string(d.begin() + static_cast<std::ptrdiff_t>(from), d.begin() + static_cast<std::ptrdiff_t>(p)));
                p = align_up(p + 1, 4);
                if (path.size() == 3 && path[1] == "images") {
                    images.emplace_back();
                    images.back().name = path[2];
                }
                break;
            }
            case 2:  // FDT_END_NODE
                if (!path.empty()) path.pop_back();
                break;
            case 3: {  // FDT_PROP: length, offset of the name in the strings block, the value, padded to 4
                if (p + 8 > end) { walking = false; break; }
                const uint64_t len = be32(d, p), name_off = be32(d, p + 4);
                p += 8;
                if (len > end - p) { walking = false; break; }
                if (path.size() == 3 && path[1] == "images" && !images.empty() && name_off < size_strings) {
                    Img& im = images.back();
                    const std::string name = text_at(off_strings + name_off, off_strings + size_strings);
                    if (name == "data") {
                        im.data_at = p;
                        im.data_len = len;
                        im.inline_data = true;
                    } else if ((name == "data-size" || name == "data-offset" || name == "data-position") && len == 4) {
                        (name == "data-size" ? im.size : name == "data-offset" ? im.offset : im.position) = be32(d, p);
                    } else if (name == "type") {
                        im.type = text_at(p, p + len);
                    }
                }
                p = align_up(p + len, 4);
                break;
            }
            case 4:  // FDT_NOP
                break;
            default:  // FDT_END, or a token that is none
                walking = false;
                break;
        }
    }
    for (size_t i = 0; i < images.size(); ++i) {
        const Img& im = images[i];
        const std::string key = i < keys.size() ? keys[i] : std::string();
        const std::string what = im.type.empty() ? std::string() : im.type;
        if (im.inline_data) {
            if (im.data_len && within(d, im.data_at, im.data_len)) {
                Region& r = l.add("image " + im.name, key, im.data_at, im.data_len, 1, what.empty() ? "in the tree" : what + ", in the tree");
                r.codec = codec_at(d, r.offset, r.size);
            }
        } else if (im.size && (im.offset || im.position)) {
            const uint64_t at = im.position ? *im.position : align_up(total, 4) + *im.offset;
            if (*im.size && within(d, at, *im.size)) {
                Region& r = l.add("image " + im.name, key, at, *im.size, 0, what.empty() ? "behind the tree" : what + ", behind the tree");
                r.codec = codec_at(d, r.offset, r.size);
            }
        }
    }
    if (size_strings) l.add("strings block", "", off_strings, size_strings, 0, "the names of the properties");
    std::stable_sort(l.regions.begin(), l.regions.end(), [](const Region& a, const Region& b) {
        return a.offset != b.offset ? a.offset < b.offset : a.depth < b.depth;
    });
    return l;
}

Layout elf_boot(const legacy::ElfBootImage& img, const Bytes& d, const std::vector<std::string>& keys) {
    Layout l;
    l.size = d.size();
    l.format = std::string("ELF boot image (") + (img.is_64bit ? "ELF64, " : "ELF32, ") + std::to_string(img.segments.size()) +
               (img.segments.size() == 1 ? " segment)" : " segments)");
    const bool is64 = img.is_64bit;
    const uint64_t aw = is64 ? 8 : 4;
    const uint64_t after = 24 + 3 * aw + 4;  // e_ehsize, e_phentsize, e_phnum come behind e_entry, e_phoff, e_shoff, e_flags
    if (!within(d, 0, after + 6)) return l;
    const uint64_t phoff = is64 ? le64(d, 32) : le32(d, 28);
    const uint64_t ehsize = le16(d, after), phentsize = le16(d, after + 2), phnum = le16(d, after + 4);
    const uint64_t ehdr = ehsize ? ehsize : (is64 ? 64 : 52);
    if (within(d, 0, ehdr)) l.add("ELF header", "", 0, ehdr, 0, "machine " + std::to_string(img.machine));
    if (phnum && phentsize && phentsize <= d.size() && phnum <= d.size() && within(d, phoff, phnum * phentsize))
        l.add("program headers", "", phoff, phnum * phentsize, 0, std::to_string(phnum) + (phnum == 1 ? " header" : " headers"));
    const uint64_t phdr_min = is64 ? 56 : 32;
    for (uint64_t i = 0; i < phnum && i < img.segments.size(); ++i) {
        const uint64_t at = phoff + i * phentsize;
        if (phentsize < phdr_min || !within(d, at, phdr_min)) break;
        const uint64_t off = is64 ? le64(d, at + 8) : le32(d, at + 4);
        const uint64_t filesz = is64 ? le64(d, at + 32) : le32(d, at + 16);
        if (!filesz || !within(d, off, filesz)) continue;
        const legacy::ElfSegment& s = img.segments[i];
        Region& r = l.add("segment " + std::to_string(i) + " (" + s.role + ")", i < keys.size() ? keys[i] : std::string(), off, filesz, 0,
                          "address " + hex(s.addr) + (s.flags ? ", flags " + hex(s.flags) : std::string()));
        r.codec = codec_at(d, off, filesz);
    }
    return l;
}

Layout krnl(const legacy::KrnlImage& img, const std::string& key) {
    Layout l;
    l.format = "Rockchip KRNL image";
    l.add("header", "", 0, legacy::kKrnlHeaderSize, 0, "KRNL, payload of " + std::to_string(img.payload.size()) + " bytes");
    if (!img.payload.empty()) {
        Region& r = l.add("payload", key, legacy::kKrnlHeaderSize, img.payload.size());
        r.codec = codec_of(img.payload);
    }
    l.add("CRC", "", legacy::kKrnlHeaderSize + img.payload.size(), legacy::kKrnlTrailerSize, 0,
          img.crc_ok ? "Rockchip CRC-32 " + hex(img.crc) + ", the payload's" : "Rockchip CRC-32 " + hex(img.crc) + ", NOT the payload's");
    l.size = img.file_size();
    return l;
}

Layout blob(const legacy::BlobImage& img) {
    using namespace legacy;
    Layout l;
    l.format = img.secure ? "ASUS blob, signed (-SIGNED-BY-SIGNBLOB-)" : "ASUS blob (MSM-RADIO-UPDATE)";
    uint64_t at = 0;
    if (img.secure) {
        l.add("secure header", "", 0, kBlobSecureHeaderSize, 0,
              "datalen " + std::to_string(img.secure_datalen) + ", siglen " + std::to_string(img.secure_siglen));
        at = kBlobSecureHeaderSize;
    }
    l.add("blob header", "", at, kBlobHeaderSize, 0,
          "version " + hex(img.version) + ", " + std::to_string(img.parts.size()) + (img.parts.size() == 1 ? " partition" : " partitions"));
    at += kBlobHeaderSize;
    if (!img.parts.empty()) l.add("partition table", "", at, img.parts.size() * kBlobPartEntrySize, 0, "");
    at += img.parts.size() * kBlobPartEntrySize;
    for (size_t i = 0; i < img.parts.size(); ++i) {
        const BlobPart& part = img.parts[i];
        std::string name;
        for (uint8_t c : part.name)
            if (c) name.push_back(c >= 0x20 && c < 0x7f ? static_cast<char>(c) : '?');
        if (!part.data.empty()) {
            Region& r = l.add("partition " + (name.empty() ? std::to_string(i) : name), "blob_part" + std::to_string(i), at, part.data.size(), 0,
                              "version " + std::to_string(part.version));
            r.codec = codec_of(part.data);
        }
        at += part.data.size();
    }
    if (!img.tail.empty()) {
        l.add(img.secure ? "signature" : "after the partitions", "blob_tail", at, img.tail.size());
        at += img.tail.size();
    }
    l.size = at;
    return l;
}

Layout osip(const legacy::OsipImage& img) {
    using namespace legacy;
    Layout l;
    l.format = img.header.empty() ? "Intel OSIP boot image (no OSIP header)" : "Intel OSIP boot image";
    uint64_t at = 0;
    auto put = [&](const std::string& name, const std::string& key, uint64_t size, std::string note = {}) -> Region* {
        if (!size) return nullptr;
        Region& r = l.add(name, key, at, size, 0, std::move(note));
        at += size;
        return &r;
    };
    put("OSIP header", "osip_header", img.header.size(), "the $OS$ header and its OSII entry");
    put("signature", "osip_signature", img.signature.size(), "Intel's signature");
    std::string cmd = img.cmdline_text();
    if (cmd.size() > 60) cmd = cmd.substr(0, 57) + "...";
    put("cmdline", "osip_cmdline", img.cmdline.size(), cmd.empty() ? std::string() : "\"" + cmd + "\"");
    put("image info", "osip_info", kOsipInfoFixedSize + img.info_rest.size(),
        std::to_string(img.kernel.size()) + " bytes of kernel, " + std::to_string(img.ramdisk.size()) + " of ramdisk");
    put("bootstub", "bootstub", img.bootstub.size());
    put("kernel", "kernel", img.kernel.size());
    if (Region* r = put("ramdisk", "ramdisk", img.ramdisk.size())) r->codec = codec_of(img.ramdisk);
    l.size = at;
    return l;
}

Layout chromeos(const legacy::ChromeosInfo& c, const Bytes& d) {
    using namespace legacy;
    Layout l;
    l.format = "ChromeOS kernel blob (vboot preamble " + std::to_string(c.preamble_major) + "." + std::to_string(c.preamble_minor) + ")";
    const uint64_t core = std::min<uint64_t>(c.core_size, d.size());
    const uint64_t pad = std::min<uint64_t>(c.pad, core);
    const uint64_t keyblock = std::min<uint64_t>(c.keyblock.size(), pad);
    l.size = core;
    l.add("verification block", "", 0, pad, 0, "the keyblock and the preamble, zeros up to the " + std::to_string(pad) + " bytes");
    if (keyblock) l.add("keyblock", "", 0, keyblock, 1, "the data key and the signature of the keyblock");
    const uint64_t preamble = within(d, keyblock, 4) ? le32(d, keyblock) : 0;  // preamble_size: its first field
    if (preamble && preamble <= pad - keyblock)
        l.add("preamble", "", keyblock, preamble, 1, "kernel version " + std::to_string(c.kernel_version) + ", loaded at " + hex(c.body_load_address));
    if (core > pad) {
        l.add("body", "", pad, core - pad, 0, "signed as one: the kernel, the config, the params, the bootloader");
        uint64_t at = pad;
        auto part = [&](const std::string& name, const std::string& key, uint64_t size, const std::string& note) {
            size = std::min<uint64_t>(size, core - at);
            if (size) l.add(name, key, at, size, 1, note);
            at += size;
        };
        part("kernel", "chromeos_kernel", c.kernel_size, "the plain image, zeros up to " + std::to_string(kChromeosAlign));
        part("config", "", kChromeosConfigSize, "the command line");
        part("params", "", kChromeosParamsSize, "the x86 boot parameters (zeros on ARM)");
        part("bootloader", "", align_up(c.bootloader_size, kChromeosAlign), "");
    }
    return l;
}

Layout qcdt(const Bytes& d, const std::string& kp) {
    Layout l;
    l.format = "Qualcomm device tree table (QCDT)";
    l.size = d.size();
    if (d.size() < qcdt::kHeaderSize || !qcdt::looks_like(d)) return l;
    const uint32_t version = le32(d, 4), count = le32(d, 8);
    const size_t es = qcdt::entry_size(version);
    if (!es) return l;
    const uint64_t fits = (d.size() - qcdt::kHeaderSize) / es;
    const uint64_t n = std::min<uint64_t>(count, fits);
    l.add("QCDT table", "", 0, qcdt::kHeaderSize + n * es + 4, 0,
          "version " + std::to_string(version) + ", " + std::to_string(count) + (count == 1 ? " entry" : " entries"));
    std::map<uint64_t, uint64_t> trees;  // offset -> size, in the order of the file
    for (uint64_t k = 0; k < n; ++k) {
        const uint64_t er = qcdt::kHeaderSize + k * es;
        const uint32_t off = le32(d, er + es - 8), size = le32(d, er + es - 4);
        if (within(d, off, 1)) trees.emplace(off, size);
    }
    size_t j = 0;
    for (const auto& [off, size] : trees) {
        std::string note = "device tree";
        if (within(d, off, 8) && be32(d, off) == 0xd00dfeed) note += " of " + std::to_string(be32(d, off + 4)) + " bytes, zeros up to the page";
        l.add("device tree " + std::to_string(j), kp + "dtb" + std::to_string(j), off, std::min<uint64_t>(size, d.size() - off), 0, note);
        ++j;
    }
    return l;
}

void vbmeta(Layout& l, const Bytes& d, uint64_t at, unsigned depth, const std::string& key_prefix) {
    if (!within(d, at, 256) || std::memcmp(d.data() + at, "AVB0", 4) != 0) return;
    const uint64_t auth_size = be64(d, at + 12), aux_size = be64(d, at + 20);
    const uint32_t algorithm = be32(d, at + 28);
    const uint64_t hash_off = be64(d, at + 32), hash_size = be64(d, at + 40), sig_off = be64(d, at + 48), sig_size = be64(d, at + 56),
                   key_off = be64(d, at + 64), key_size = be64(d, at + 72), meta_off = be64(d, at + 80), meta_size = be64(d, at + 88),
                   desc_off = be64(d, at + 96), desc_size = be64(d, at + 104);
    const uint64_t auth_at = at + 256;
    if (auth_size > d.size() || aux_size > d.size() || !within(d, auth_at, auth_size + aux_size)) return;
    const uint64_t aux_at = auth_at + auth_size;
    l.add("vbmeta header", "", at, 256, depth, "algorithm " + avb_algorithm_name(algorithm));
    if (auth_size) {
        l.add("authentication block", "", auth_at, auth_size, depth);
        if (hash_size && hash_off <= auth_size && hash_size <= auth_size - hash_off) l.add("hash", "", auth_at + hash_off, hash_size, depth + 1);
        if (sig_size && sig_off <= auth_size && sig_size <= auth_size - sig_off) l.add("signature", "", auth_at + sig_off, sig_size, depth + 1);
    }
    if (aux_size) {
        l.add("auxiliary block", "", aux_at, aux_size, depth);
        auto inside = [&](uint64_t off, uint64_t size) { return size && off <= aux_size && size <= aux_size - off; };
        if (inside(desc_off, desc_size)) {
            l.add("descriptors", "", aux_at + desc_off, desc_size, depth + 1, "");
            uint64_t p = aux_at + desc_off;
            const uint64_t end = p + desc_size;
            for (size_t i = 0; p + 16 <= end; ++i) {
                const uint64_t tag = be64(d, p), following = be64(d, p + 8);
                if (following > end - p - 16) break;
                AvbDescriptor desc;
                desc.tag = tag;
                desc.content.assign(d.begin() + static_cast<long>(p + 16), d.begin() + static_cast<long>(p + 16 + following));
                l.add("descriptor " + std::to_string(i), key_prefix + "descriptor" + std::to_string(i), p, 16 + following, depth + 2, desc.describe());
                p += 16 + following;
            }
        }
        if (inside(key_off, key_size)) l.add("public key", key_prefix + "public_key", aux_at + key_off, key_size, depth + 1);
        if (inside(meta_off, meta_size)) l.add("public key metadata", key_prefix + "public_key_metadata", aux_at + meta_off, meta_size, depth + 1);
    }
}

Layout vbmeta_image(const Bytes& d) {
    Layout l;
    l.format = "vbmeta image";
    l.size = d.size();
    vbmeta(l, d, 0, 0, "");
    return l;
}

Layout dtb_blobs(const std::vector<size_t>& sizes) {
    Layout l;
    l.format = "flattened device trees";
    uint64_t at = 0;
    for (size_t i = 0; i < sizes.size(); ++i) {
        l.add("device tree " + std::to_string(i), "blob" + std::to_string(i), at, sizes[i]);
        at += sizes[i];
    }
    l.size = at;
    return l;
}

// ----------------------------------------------------------------------------------------------------- around --

namespace {

// A zlib stream by its first two bytes: the method (deflate, a window of at most 32 KiB), the check of the pair, no preset dictionary.
bool starts_like_zlib(const Bytes& d, uint64_t off, uint64_t n) {
    if (n < 6 || !within(d, off, n)) return false;
    const unsigned cmf = d[off], flg = d[off + 1];
    return (cmf & 0x0f) == 8 && (cmf >> 4) <= 7 && ((cmf << 8) | flg) % 31 == 0 && !(flg & 0x20);
}

}  // namespace

Layout mtk_image(const Bytes& d) {
    Layout l;
    l.format = "MediaTek partition image";
    l.size = d.size();
    std::vector<mtkimg::Span> spans;
    try {
        spans = mtkimg::scan(d);
    } catch (const FormatError&) {
        return l;
    }
    for (size_t i = 0; i < spans.size(); ++i) {
        const mtkimg::Span& s = spans[i];
        const std::string name = s.header.name_text();
        const std::string head = "section " + std::to_string(i);
        std::string note = "load address " + hex(s.header.maddr) + (s.header.extended() ? ", type " + hex(s.header.img_type) : ", older header");
        l.add(head + " header", "", s.header_at, mtkimg::kHeaderSize, 0, name + "; " + note);
        const std::string key = "section" + std::to_string(i);
        const uint64_t size = s.data_size;
        if (size != 0) {
            const std::optional<std::vector<uint32_t>> offsets = mtkimg::logo_offsets(d.data() + s.data_at, static_cast<size_t>(size));
            if (offsets) {
                l.add(head + " data (" + name + ")", "", s.data_at, size, 0, "table of " + std::to_string(offsets->size()) + " pictures");
                for (size_t k = 0; k < offsets->size(); ++k) {
                    const uint64_t at = s.data_at + (*offsets)[k];
                    const uint64_t n = (k + 1 < offsets->size() ? uint64_t{(*offsets)[k + 1]} : size) - (*offsets)[k];
                    Region& r = l.add("picture " + std::to_string(k), key + "_p" + std::to_string(k), at, n, 1, "");
                    if (starts_like_zlib(d, at, n)) r.codec = "zlib";
                }
            } else {
                Region& r = l.add(head + " data (" + name + ")", key, s.data_at, size, 0, "");
                r.codec = codec_at(d, s.data_at, size);
            }
        }
        if (s.pad_size) l.add("padding", "", s.data_at + size, s.pad_size, 0, "alignment " + std::to_string(s.align));
    }
    return l;
}

Layout mtk_preloader(const Bytes& d) {
    Layout l;
    l.format = "MediaTek preloader (GFH)";
    l.size = d.size();
    mtkgfh::Image img;
    try {
        img = mtkgfh::parse(d);
    } catch (const FormatError&) {
        return l;
    }
    const mtkgfh::FileInfo fi = mtkgfh::read_file_info(img.chain[0]);
    const uint64_t at = img.at();
    if (img.device) {
        const mtkgfh::Device& v = *img.device;
        l.add("device header and BRLYT", "device", 0, at, 0, "");
        l.add("device header", "", 0, std::min<uint64_t>(v.boot_size, at), 1, v.boot_name + ", version " + std::to_string(v.boot_version));
        if (at >= mtkgfh::kDeviceHeaderSize + mtkgfh::kBrlytSize)
            l.add("BRLYT", "", mtkgfh::kDeviceHeaderSize, mtkgfh::kBrlytSize, 1,
                  mtkgfh::brlyt_type_name(v.type) + ", headers at " + hex(v.header_size) + ", size " + hex(v.total_size));
    }
    const mtkgfh::Header& first = img.chain[0];
    l.add("FILE_INFO", "", at, first.size(), 0,
          "load address " + hex(fi.load_addr) + ", code at " + hex(uint64_t{fi.load_addr} + fi.jump_offset) + ", signature " + mtkgfh::sig_type_name(fi.sig_type));
    uint64_t o = at + first.size();
    const uint64_t headers_end = at + fi.hdr_size;
    if (headers_end > o) {
        l.add("GFH headers", "headers", o, headers_end - o, 0, std::to_string(img.chain.size() - 1) + " behind FILE_INFO");
        for (size_t i = 1; i < img.chain.size(); ++i) {
            const mtkgfh::Header& h = img.chain[i];
            l.add(mtkgfh::type_name(h.type), "", o, h.size(), 1, mtkgfh::describe(h));
            o += h.size();
        }
        if (headers_end > o) l.add("padding", "", o, headers_end - o, 1, "");
    }
    if (!img.payload.empty()) {
        Region& r = l.add("loader", "loader", headers_end, img.payload.size(), 0, "");
        r.codec = codec_at(d, r.offset, r.size);
        if (const std::optional<mtkgfh::Marker> m = mtkgfh::find_bloader_marker(img.payload)) r.note = m->text + " at " + hex(headers_end + m->offset);
    }
    if (!img.signature.empty()) {
        const uint64_t sig_at = img.consumed - img.signature.size();
        l.add("signature", img.sha256_trailer ? "" : "signature", sig_at, img.signature.size(), 0,
              img.sha256_trailer ? "SHA-256 of the image from the first header; pack makes it again" : mtkgfh::sig_type_name(fi.sig_type) + ", kept as it is");
    }
    return l;
}

// ----------------------------------------------------------------------------------------------------- Qualcomm MBN --

namespace {

// What names a certificate in a line of the layout: the common name of its subject (the whole subject when it has none).
std::string subject_label(const std::string& subject) {
    const size_t cn = subject.rfind("CN=");
    return cn == std::string::npos ? subject : subject.substr(cn + 3);
}

// The certificates of the chain that lies at `at`, one region each.
void add_chain(Layout& l, const Bytes& chain, uint64_t at, unsigned depth) {
    const std::vector<mbn::Cert> certs = mbn::read_chain(chain);
    for (size_t i = 0; i < certs.size(); ++i) l.add("certificate " + std::to_string(i), "", at + certs[i].offset, certs[i].size, depth, subject_label(certs[i].subject));
}

// "a, b" for the parts that are not empty.
std::string joined(std::initializer_list<std::string> parts) {
    std::string out;
    for (const std::string& p : parts)
        if (!p.empty()) out += (out.empty() ? "" : ", ") + p;
    return out;
}

// The regions of the structure `b` that lies at `at` in `d`: its header, then its parts one behind the other, all at `depth`. What the code is called
// (an ELF has a table of hashes there) and its note are the caller's; only a code that is a key of `code` can be a stream.
void add_block(Layout& l, const Bytes& d, const mbn::Block& b, uint64_t at, unsigned depth, const char* code_name, const char* code_key, const std::string& code_note) {
    std::string head = mbn::describe_header(b);
    if (b.has_word("image_id")) {
        const uint32_t id = b.word("image_id");
        const std::string name = mbn::image_id_name(id);
        head += ", image id " + std::to_string(id) + (name.empty() ? std::string() : " (" + name + ")");
    }
    l.add("header", "", at, b.header_bytes(), depth, head);
    uint64_t pos = at + b.header_bytes();
    const auto part = [&](const char* name, const char* key, const Bytes& bytes, bool chain) {
        if (bytes.empty()) return;
        l.add(name, key, pos, bytes.size(), depth);
        if (chain) add_chain(l, bytes, pos, depth + 1);
        pos += bytes.size();
    };
    part("QTI metadata", "metadata_qti", b.metadata_qti, false);
    part("metadata", "metadata", b.metadata, false);
    if (!b.code.empty()) {
        Region& r = l.add(code_name, code_key, pos, b.code.size(), depth, code_note);
        if (std::strcmp(code_key, "code") == 0) r.codec = codec_at(d, pos, b.code.size());
        pos += b.code.size();
    }
    part("QTI signature", "signature_qti", b.sig_qti, false);
    part("QTI certificate chain", "cert_chain_qti", b.cert_qti, true);
    part("signature", "signature", b.sig, false);
    part("certificate chain", "cert_chain", b.cert, true);
    if (!b.slack.empty()) l.add("rounding", "", pos, b.slack.size(), depth, b.align4 ? "up to a multiple of 4" : "behind the parts, inside image_size");
}

}  // namespace

Layout mbn(const Bytes& d) {
    Layout l;
    l.size = d.size();
    mbn::Block b;
    try {
        b = mbn::parse_block(d, 0, d.size());
    } catch (const FormatError&) {
        return l;
    }
    l.format = b.kind == mbn::Kind::Sbl ? "Qualcomm SBL image" : "Qualcomm MBN image, header version " + std::to_string(b.version);
    add_block(l, d, b, 0, 0, "code", "code", "");
    return l;
}

Layout mbn_elf(const Bytes& d) {
    Layout l;
    l.size = d.size();
    mbn::Elf e;
    try {
        e = mbn::parse_elf(d);
    } catch (const FormatError&) {
        return l;
    }
    const std::string cls = e.is64 ? "ELF64" : "ELF32";
    l.format = "Qualcomm " + cls + " image, header version " + std::to_string(e.block.version);
    l.add("ELF header", "", 0, e.ehsize, 0, cls + ", machine " + std::to_string(e.machine) + ", entry " + hex(e.entry));
    l.add("program headers", "", e.phoff, uint64_t{e.seg.size()} * e.phentsize, 0, std::to_string(e.seg.size()) + " entries");
    for (size_t i = 0; i < e.seg.size(); ++i) {
        const mbn::Segment& s = e.seg[i];
        if (s.role == mbn::Role::Headers || s.ph.filesz == 0) continue;
        const std::string where = "program header " + std::to_string(i);
        const std::string flags = mbn::describe_flags(s.ph.flags);
        if (s.role == mbn::Role::Hash) {
            l.add("hash segment", "", s.ph.offset, s.ph.filesz, 0, joined({where, flags}));
            std::string table = "kept as it is";
            if (e.algo != mbn::Algo::None) table = std::to_string(e.block.code.size() / mbn::digest_size(e.algo)) + " hashes (" + mbn::algo_name(e.algo) + "), made again by pack";
            add_block(l, d, e.block, s.ph.offset, 1, "hash table", "hash_table", table);
            if (!e.hash_pad.empty()) l.add("padding", "", s.ph.offset + e.block.consumed, e.hash_pad.size(), 1);
        } else {
            Region& r = l.add("segment " + std::to_string(i), "seg" + std::to_string(i), s.ph.offset, s.ph.filesz, 0, joined({where, flags, "address " + hex(s.ph.paddr)}));
            r.codec = codec_at(d, r.offset, r.size);
        }
    }
    return l;
}

// ------------------------------------------------------------------------------------------------ the picture partitions --

namespace {

std::string pixels_text(uint32_t width, uint32_t height) { return std::to_string(width) + "x" + std::to_string(height); }

bool all_zero(const Bytes& b) { return std::all_of(b.begin(), b.end(), [](uint8_t v) { return v == 0; }); }

}  // namespace

Layout qc_splash(const Bytes& d) {
    Layout l;
    l.size = d.size();
    splash::QcSplash s;
    try {
        s = splash::qc_parse(d);
    } catch (const FormatError&) {
        return l;
    }
    l.format = "Qualcomm splash image (SPLASH!!)";
    l.add("header", "", 0, splash::kQcHeaderSize, 0,
          s.several ? "table of " + std::to_string(s.pictures.size()) + " pictures" + (s.header_rest.empty() ? std::string() : ", " + std::to_string(s.header_rest.size()) + " more bytes kept")
                    : std::string("one picture"));
    for (size_t i = 0; i < s.pictures.size(); ++i) {
        const splash::QcPicture& p = s.pictures[i];
        // (the bytes of the pictures up to the block are padding: they are not a part)
        l.add("picture " + std::to_string(i), "picture" + std::to_string(i), p.offset, p.stream, 0,
              pixels_text(p.width, p.height) + ", " + splash::qc_type_name(p.type) + ", " +
                  (p.blocks == 0 ? std::string("no block count in the header") : std::to_string(p.blocks) + (p.blocks == 1 ? " block" : " blocks")));
    }
    return l;
}

Layout oplus_logo(const Bytes& d) {
    Layout l;
    l.size = d.size();
    splash::OplusLogo o;
    try {
        o = splash::oplus_parse(d);
    } catch (const FormatError&) {
        return l;
    }
    l.format = "OPLUS splash logo image";
    const bool ddph = o.preamble.size() >= 4 && le32(o.preamble, 0) == splash::kDdphMagic;
    const bool zeros = all_zero(o.preamble);
    l.add("preamble", zeros ? "" : "preamble", 0, splash::kOplusPreamble, 0, zeros ? "zeros" : ddph ? "DDPH header, kept as it is" : "kept as it is");
    l.add("header", "", splash::kOplusPreamble, splash::kOplusHeaderSize, 0,
          std::to_string(o.entries.size()) + (o.entries.size() == 1 ? " picture" : " pictures") + ", version " + std::to_string(o.version) + ", " + pixels_text(o.width, o.height));
    l.add("descriptions", "", splash::kOplusPreamble + 12, 4 * splash::kOplusDescSize, 1, "");
    l.add("table", "", splash::kOplusPreamble + splash::kOplusTableAt, o.entries.size() * splash::kOplusEntrySize, 1, std::to_string(o.entries.size()) + " entries");
    uint64_t at = splash::kOplusDataAt;
    for (size_t i = 0; i < o.entries.size(); ++i) {
        const splash::OplusEntry& e = o.entries[i];
        l.add("picture " + std::to_string(i), "entry" + std::to_string(i), at, e.data.size(), 0, e.name + "; " + std::to_string(e.plain_size) + " bytes unpacked");
        at += e.data.size();
    }
    return l;
}

Layout xiaomi_logo(const Bytes& d) {
    Layout l;
    l.size = d.size();
    splash::XiaomiLogo x;
    try {
        x = splash::xiaomi_parse(d);
    } catch (const FormatError&) {
        return l;
    }
    l.format = "Xiaomi logo image (LOGO!!!!)";
    l.add("preamble", all_zero(x.preamble) ? "" : "preamble", 0, splash::kXiaomiPreamble, 0, all_zero(x.preamble) ? "zeros" : "kept as it is");
    l.add("table", "", splash::kXiaomiPreamble, splash::kXiaomiTableSize, 0, std::to_string(x.pictures.size()) + (x.pictures.size() == 1 ? " picture" : " pictures") + ", in units of 4096 bytes");
    uint64_t at = splash::kXiaomiPreamble + splash::kXiaomiTableSize;
    for (size_t i = 0; i < x.pictures.size(); ++i) {
        const Bytes& p = x.pictures[i];
        // (a picture lies in whole units; what is behind the file in the last of them is padding)
        const size_t content = splash::xiaomi_content_size(p);
        l.add("picture " + std::to_string(i), "picture" + std::to_string(i), at, content, 0, splash::picture_extension(p) + ", " + std::to_string(p.size() / splash::kXiaomiUnit) + " units");
        at += p.size();
    }
    return l;
}

Layout moto_logo(const Bytes& d) {
    Layout l;
    l.size = d.size();
    splash::MotoLogo m;
    try {
        m = splash::moto_parse(d);
    } catch (const FormatError&) {
        return l;
    }
    l.format = "Motorola logo image (MotoLogo)";
    size_t pictures = 0;
    for (const splash::MotoEntry& e : m.entries) pictures += e.data.empty() ? 0 : 1;
    l.add("table", "", 0, le32(d, 9), 0,
          std::to_string(m.entries.size()) + " entries, " + std::to_string(pictures) + (pictures == 1 ? " picture" : " pictures") + ", pictures at multiples of " + std::to_string(m.align));
    for (size_t i = 0; i < m.entries.size(); ++i) {
        const splash::MotoEntry& e = m.entries[i];
        if (e.data.empty()) continue;
        const size_t at = splash::kMotoTableAt + i * splash::kMotoEntrySize + splash::kMotoNameSize;
        std::string note = e.name;
        if (e.data.size() >= splash::kMotoHeaderSize && std::memcmp(e.data.data(), "MotoRun\0", 8) == 0)
            note += "; MotoRun, " + pixels_text(static_cast<uint32_t>(e.data[8] << 8 | e.data[9]), static_cast<uint32_t>(e.data[10] << 8 | e.data[11]));
        else
            note += "; " + splash::picture_extension(e.data);
        l.add("picture " + std::to_string(i), "entry" + std::to_string(i), le32(d, at), e.data.size(), 0, note);
    }
    return l;
}

void around(Layout& l, const Bytes& whole, size_t host_size, size_t core_off, size_t core_len) {
    l.size = whole.size();
    host_size = std::min(host_size, whole.size());
    core_off = std::min(core_off, host_size);
    core_len = std::min(core_len, host_size - core_off);
    l.shift(core_off);
    const Bytes host(whole.begin(), whole.begin() + static_cast<long>(host_size));
    const Envelope env = Envelope::capture(host, core_off, core_len);
    if (core_off) l.regions.insert(l.regions.begin(), Region{"prefix", "prefix", 0, core_off, 0, "kept as it is (prefix.bin)", "", "", 0, -1});
    const uint64_t core_end = core_off + core_len;
    if (!env.tail.empty()) l.add("tail", "tail", core_end, env.tail.size(), 0, "kept as it is (tail.bin)");
    if (env.pad_to) {
        const uint64_t from = core_end + env.tail.size();
        if (env.pad_to > from) {
            char b[40];
            std::snprintf(b, sizeof b, "fill, all bytes 0x%02x", env.pad_byte);
            l.add("fill", "", from, env.pad_to - from, 0, b);
        }
    }
    if (host_size < whole.size() && whole.size() >= 64 && std::memcmp(whole.data() + whole.size() - 64, "AVBf", 4) == 0) {
        const uint64_t footer_at = whole.size() - 64;
        const uint64_t vb_off = be64(whole, footer_at + 20), vb_size = be64(whole, footer_at + 28);
        if (vb_off >= host_size && vb_off <= footer_at && vb_size <= footer_at - vb_off) {
            if (vb_off > host_size) l.add("padding", "", host_size, vb_off - host_size);
            l.add("AVB vbmeta", "", vb_off, vb_size, 0, "the AVB footer's signed block");
            vbmeta(l, whole, vb_off, 1, "avb_");
            if (vb_off + vb_size < footer_at) l.add("padding", "", vb_off + vb_size, footer_at - (vb_off + vb_size));
        }
        l.add("AVB footer", "", footer_at, 64, 0, "protects the first " + std::to_string(host_size) + " bytes");
    }
    std::stable_sort(l.regions.begin(), l.regions.end(), [](const Region& a, const Region& b) {
        return a.offset != b.offset ? a.offset < b.offset : a.depth < b.depth;
    });
}

// ----------------------------------------------------------------------------------------------------- the text --

namespace {

std::string stream_text(const Region& r) {
    std::string s;
    if (!r.file.empty()) {
        s = r.codec.empty() ? "file " + r.file : r.codec + " -> " + r.file;
        if (!r.codec.empty()) {
            s += " (" + std::to_string(r.unpacked) + " bytes";
            if (r.level >= 0) s += ", level " + std::to_string(r.level);
            s += ")";
        }
    } else if (!r.codec.empty()) {
        s = r.codec;
        if (r.unpacked || r.level >= 0) {  // (what `info` found out by looking into the stream)
            s += " (";
            if (r.unpacked) s += std::to_string(r.unpacked) + " bytes unpacked";
            if (r.level >= 0) s += (r.unpacked ? ", level " : "level ") + std::to_string(r.level);
            s += ")";
        }
    }
    return s;
}

std::string slug(const std::string& name) {
    std::string s;
    for (char c : name) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (std::isalnum(u))
            s += static_cast<char>(std::tolower(u));
        else if (!s.empty() && s.back() != '_')
            s += '_';
    }
    while (!s.empty() && s.back() == '_') s.pop_back();
    return s.empty() ? "region" : s;
}

}  // namespace

std::string render(const Layout& l, const std::string& indent) {
    uint64_t top = 0;
    size_t name_w = 4, size_w = 4;
    for (const Region& r : l.regions) {
        top = std::max(top, r.offset + r.size);
        name_w = std::max(name_w, r.depth * 2 + r.name.size());
        size_w = std::max(size_w, std::to_string(r.size).size());
    }
    name_w = std::min<size_t>(name_w, 36);
    int hex_w = 8;
    for (uint64_t v = top >> 32; v; v >>= 4) ++hex_w;

    std::string out;
    char buf[64];
    std::snprintf(buf, sizeof buf, "%-*s", hex_w + 2, "offset");
    out += indent + buf + "  " + std::string(size_w > 4 ? size_w - 4 : 0, ' ') + "size  part\n";
    for (const Region& r : l.regions) {
        std::snprintf(buf, sizeof buf, "0x%0*" PRIx64, hex_w, r.offset);
        std::string name = std::string(r.depth * 2, ' ') + r.name;
        if (name.size() > name_w) name = name.substr(0, name_w - 1) + "~";
        std::string what = r.note;
        if (const std::string s = stream_text(r); !s.empty()) what += (what.empty() ? "" : "; ") + s;
        char size[32];
        std::snprintf(size, sizeof size, "%*" PRIu64, static_cast<int>(size_w), r.size);
        std::string line = indent + buf + "  " + size + "  " + name;
        if (!what.empty()) line += std::string(name_w - name.size(), ' ') + "  " + what;
        out += line + "\n";
    }
    return out;
}

std::vector<std::pair<std::string, std::string>> manifest_lines(const Layout& l) {
    std::vector<std::pair<std::string, std::string>> out;
    std::map<std::string, int> seen;
    for (const Region& r : l.regions) {
        std::string name = r.key.empty() ? slug(r.name) : r.key;
        if (const int n = seen[name]++; n) name += "_" + std::to_string(n + 1);
        out.emplace_back("layout_" + name + "_offset", hex(r.offset));
        out.emplace_back("layout_" + name + "_size", std::to_string(r.size));
        if (!r.codec.empty() && r.unpacked) out.emplace_back("layout_" + name + "_unpacked_size", std::to_string(r.unpacked));
    }
    return out;
}

bool write_manifest_block(const std::filesystem::path& path, const Layout& l, const std::string& what) {
    try {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(path, ec)) return false;
        const Bytes raw = read_file(path);
        const std::string text(raw.begin(), raw.end());
        std::string out;
        for (size_t pos = 0; pos < text.size();) {
            size_t nl = text.find('\n', pos);
            const size_t end = nl == std::string::npos ? text.size() : nl + 1;
            const std::string line = text.substr(pos, end - pos);
            pos = end;
            if (line.rfind("layout_", 0) == 0 || line.rfind("# layout", 0) == 0) continue;  // an earlier block
            out += line;
        }
        while (out.size() >= 2 && out[out.size() - 1] == '\n' && out[out.size() - 2] == '\n') out.pop_back();
        if (!out.empty() && out.back() != '\n') out += '\n';
        out += "\n# layout of " + what + " -- information only, pack does not read these lines\n";
        for (const auto& [k, v] : manifest_lines(l)) out += k + "=" + v + "\n";
        write_file(path, reinterpret_cast<const uint8_t*>(out.data()), out.size());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace abr::layout
