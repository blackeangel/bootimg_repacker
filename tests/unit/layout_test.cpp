// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr::layout (include/abr/layout.hpp): for images made here with the builders of abr, the bytes at [offset, offset + size)
// of every region that names a part are that part. Run by tests/run_tests.sh as `abr_unit_tests layout`.
//
//   * boot images of every header version (0 to 4, a Marvell PXA header, a version 0 header with a device tree behind the second stage),
//     page sizes 2048 and 4096, parts that are streams (gzip is told by the first bytes), parts of a size that is no multiple of the page;
//   * vendor_boot v3 and v4 (one fragment, three fragments, a v4 header with no table), with a dtb and a bootconfig;
//   * dtbo v0 and v1, with entries stored as zlib and as gzip;
//   * a uImage; a Qualcomm device tree table made by qcdt::build; flattened device trees one after the other;
//   * a vbmeta image (header, hash, signature, descriptors, public key) and the vbmeta block and footer of an AVB hash footer;
//   * the bytes around a container: a prefix, a tail, the fill up to the partition size;
//   * the text (render) and the lines of a manifest (manifest_lines, write_manifest_block: an earlier block is replaced, the rest stays).
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "abr/avb_keys.hpp"
#include "abr/boot_image.hpp"
#include "abr/byte_io.hpp"
#include "abr/compression.hpp"
#include "abr/dtbo.hpp"
#include "abr/layout.hpp"
#include "abr/qcdt.hpp"
#include "abr/uimage.hpp"
#include "abr/vbmeta.hpp"
#include "abr/vendor_boot.hpp"

using namespace abr;
namespace fs = std::filesystem;

namespace {

int g_failures = 0;
int g_checks = 0;

#define EXPECT(cond)                                                      \
    do {                                                                  \
        ++g_checks;                                                       \
        if (!(cond)) {                                                    \
            ++g_failures;                                                 \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                 \
    } while (0)

// Bytes that are no stream of any codec (they start with 0xAB) and differ from one part to another.
Bytes pattern(size_t n, uint8_t seed) {
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>((i * 7 + seed * 13 + (i >> 8)) | 1);
    if (n) b[0] = 0xAB;
    return b;
}

bool same_at(const Bytes& file, uint64_t off, const Bytes& part) {
    return off + part.size() <= file.size() && std::equal(part.begin(), part.end(), file.begin() + static_cast<long>(off));
}

const layout::Region* find_key(const layout::Layout& l, const std::string& key) {
    for (const auto& r : l.regions)
        if (r.key == key) return &r;
    return nullptr;
}

const layout::Region* find_name(const layout::Layout& l, const std::string& name) {
    for (const auto& r : l.regions)
        if (r.name == name) return &r;
    return nullptr;
}

// Every region lies in the file; the regions of depth 0 are in order and do not overlap; one of depth 1 or more lies in the one of depth
// 0 before it. Every part that has bytes has a region of its key with exactly those bytes at its place.
void check_layout(const layout::Layout& l, const Bytes& file, const std::map<std::string, Bytes>& parts) {
    uint64_t end0 = 0, parent_end = 0;
    for (const auto& r : l.regions) {
        EXPECT(r.offset + r.size <= file.size());
        if (r.depth == 0) {
            EXPECT(r.offset >= end0);
            end0 = r.offset + r.size;
            parent_end = end0;
        } else {
            EXPECT(r.offset + r.size <= parent_end);
        }
    }
    std::set<std::string> seen;
    for (const auto& r : l.regions) {
        const auto it = parts.find(r.key);
        if (r.key.empty() || it == parts.end()) continue;
        EXPECT(r.size == it->second.size());
        EXPECT(same_at(file, r.offset, it->second));
        seen.insert(r.key);
    }
    for (const auto& [key, bytes] : parts) {
        if (bytes.empty()) continue;
        EXPECT(seen.count(key) == 1);
        if (!seen.count(key)) std::printf("    (no region for %s)\n", key.c_str());
    }
}

std::map<std::string, Bytes> boot_parts(const BootImage& p) {
    return {{"kernel", p.kernel},       {"ramdisk", p.ramdisk}, {"second", p.second}, {"dt", p.dt},
            {"recovery_dtbo", p.recovery_dtbo}, {"dtb", p.dtb}, {"boot_signature", p.boot_signature}};
}

void boot_case(uint32_t version, uint32_t page, bool pxa, bool with_dt, size_t ksize, size_t rsize) {
    BootImage img;
    img.header_version = version;
    img.page_size = page;
    img.pxa = pxa;
    img.kernel = pattern(ksize, 1);
    img.ramdisk = pattern(rsize, 2);
    if (version <= 2) img.second = pattern(page / 2 + 3, 3);
    if (version == 0 && with_dt) img.dt = pattern(3000, 4);
    if (version >= 1 && version <= 2) img.recovery_dtbo = pattern(page + 5, 5);
    if (version == 2) img.dtb = pattern(1234, 6);
    if (version == 4) img.boot_signature = pattern(4096, 7);
    img.recompute_id();
    const Bytes built = img.build();
    const BootImage parsed = BootImage::parse(built);
    layout::Layout l = layout::boot(parsed);
    layout::around(l, built, built.size(), 0, parsed.consumed);
    check_layout(l, built, boot_parts(parsed));
    EXPECT(l.regions.front().name == "header");
    EXPECT(l.regions.front().offset == 0);
    {
        static const uint32_t header_bytes[] = {1632, 1648, 1660, 1580, 1584};
        const uint64_t bytes = pxa ? 1640 : header_bytes[version];
        EXPECT(l.regions.front().size == align_up(bytes, version <= 2 || pxa ? page : 4096));
    }
    EXPECT(l.size == built.size());
    // The parts follow each other, each at the next page.
    uint64_t at = l.regions.front().size;
    for (size_t i = 1; i < l.regions.size(); ++i) {
        EXPECT(l.regions[i].offset == at);
        at = align_up(l.regions[i].offset + l.regions[i].size, version <= 2 || pxa ? page : 4096);
    }
    EXPECT(at == built.size());
}

void test_boot() {
    boot_case(0, 2048, false, false, 5000, 3000);
    boot_case(0, 1024, false, false, 5000, 3000);        // a page smaller than the header: the header takes two
    boot_case(2, 512, false, false, 700, 300);
    boot_case(0, 4096, false, false, 4096, 4096);        // parts of exactly a page
    boot_case(0, 2048, false, true, 70000, 5000);        // a device tree behind the second stage
    boot_case(0, 2048, true, true, 7000, 9000);          // Marvell PXA
    boot_case(1, 2048, false, false, 100001, 20000);
    boot_case(2, 4096, false, false, 33333, 12345);
    boot_case(2, 2048, false, false, 1, 1);
    boot_case(3, 4096, false, false, 8000, 6000);
    boot_case(4, 4096, false, false, 8000, 6000);
    boot_case(4, 4096, false, false, 0, 6000);           // init_boot: no kernel
    {
        // A part that is a stream is told by its first bytes.
        BootImage img;
        img.header_version = 4;
        img.kernel = compress(Codec::GZIP, pattern(5000, 9));
        img.ramdisk = compress(Codec::LZ4_LEGACY, pattern(9000, 8));
        const Bytes built = img.build();
        const BootImage parsed = BootImage::parse(built);
        layout::Layout l = layout::boot(parsed);
        EXPECT(find_key(l, "kernel") && find_key(l, "kernel")->codec == "gzip");
        EXPECT(find_key(l, "ramdisk") && find_key(l, "ramdisk")->codec == "lz4_legacy");
    }
    {
        // Known offsets of a plain image: version 2 with a 2 KiB page.
        BootImage img;
        img.header_version = 2;
        img.page_size = 2048;
        img.kernel = pattern(2049, 1);  // two pages
        img.ramdisk = pattern(10, 2);   // one page
        const Bytes built = img.build();
        const layout::Layout l = layout::boot(BootImage::parse(built));
        EXPECT(find_key(l, "kernel")->offset == 2048);
        EXPECT(find_key(l, "ramdisk")->offset == 2048 + 4096);
        EXPECT(built.size() == 2048 + 4096 + 2048);
    }
}

void test_vendor_boot() {
    for (int variant = 0; variant < 5; ++variant) {
        VendorBootImage img;
        img.header_version = variant == 0 ? 3 : 4;
        img.page_size = variant == 4 ? 2048 : 4096;
        img.dtb = pattern(2500, 1);
        if (variant != 3 && variant != 0) img.bootconfig = pattern(300, 2);
        if (variant == 0 || variant == 1 || variant == 4) {
            VendorRamdiskEntry e;
            e.type = variant == 0 ? 0 : 1;
            e.data = pattern(5000, 3);
            img.ramdisk_fragments.push_back(e);
        } else {
            for (int i = 0; i < 3; ++i) {
                VendorRamdiskEntry e;
                e.type = 1 + i % 3;
                e.name = i == 1 ? "dlkm" : "";
                e.data = pattern(1000 + 777 * i, static_cast<uint8_t>(10 + i));
                img.ramdisk_fragments.push_back(e);
            }
        }
        if (variant == 3) img.has_ramdisk_table = false;
        const Bytes built = img.build();
        const VendorBootImage parsed = VendorBootImage::parse(built);
        layout::Layout l = layout::vendor_boot(parsed);
        layout::around(l, built, built.size(), 0, parsed.consumed);
        std::map<std::string, Bytes> parts = {{"dtb", parsed.dtb}, {"bootconfig", parsed.bootconfig}};
        Bytes all;
        for (size_t i = 0; i < parsed.ramdisk_fragments.size(); ++i) {
            parts["ramdisk" + std::to_string(i)] = parsed.ramdisk_fragments[i].data;
            all.insert(all.end(), parsed.ramdisk_fragments[i].data.begin(), parsed.ramdisk_fragments[i].data.end());
        }
        check_layout(l, built, parts);
        const layout::Region* section = find_name(l, "vendor ramdisk");
        EXPECT(section != nullptr);
        if (section) {
            EXPECT(section->size == all.size());
            EXPECT(same_at(built, section->offset, all));
        }
        const layout::Region* table = find_name(l, "vendor ramdisk table");
        if (parsed.header_version >= 4 && parsed.has_ramdisk_table && !parsed.ramdisk_fragments.empty()) {
            EXPECT(table != nullptr);
            if (table) {
                EXPECT(table->size == parsed.ramdisk_fragments.size() * kVendorRamdiskTableEntrySize);
                // The table's first entry says the size of the first fragment.
                EXPECT(built[table->offset] == (parsed.ramdisk_fragments[0].data.size() & 0xff));
            }
        } else {
            EXPECT(table == nullptr);
        }
        EXPECT(l.regions.front().size == align_up(img.header_version >= 4 ? 2128 : 2112, img.page_size));
        // Fragments are of depth 1, inside the section.
        if (parsed.ramdisk_fragments.size() > 1)
            for (const auto& r : l.regions)
                if (r.key.rfind("ramdisk", 0) == 0) EXPECT(r.depth == 1);
    }
}

void test_dtbo() {
    for (uint32_t version = 0; version <= 1; ++version) {
        DtboImage img;
        img.version = version;
        img.page_size = 4096;
        for (uint32_t i = 0; i < 4; ++i) {
            DtboEntry e;
            e.id = 100 + i;
            e.rev = i;
            e.data = pattern(200 + 55 * i, static_cast<uint8_t>(i + 1));
            if (version == 1 && i == 1) e.set_compression(1);
            if (version == 1 && i == 3) e.set_compression(2);
            img.entries.push_back(e);
        }
        const Bytes built = img.build();
        const layout::Layout l = layout::dtbo(built);
        EXPECT(find_name(l, "header") && find_name(l, "header")->size == 32);
        EXPECT(find_name(l, "entry table") && find_name(l, "entry table")->offset == 32 && find_name(l, "entry table")->size == 4 * 32);
        uint64_t next = 32 + 4 * 32;
        for (uint32_t i = 0; i < 4; ++i) {
            const layout::Region* r = find_key(l, "entry" + std::to_string(i));
            EXPECT(r != nullptr);
            if (!r) continue;
            EXPECT(r->offset == next);
            next = r->offset + r->size;
            const uint32_t comp = img.entries[i].compression();
            if (version == 0 || comp == 0) {
                EXPECT(r->codec.empty());
                EXPECT(r->size == img.entries[i].data.size());
                EXPECT(same_at(built, r->offset, img.entries[i].data));
            } else {
                EXPECT(r->codec == (comp == 1 ? "zlib" : "gzip"));
                EXPECT(built[r->offset] == (comp == 1 ? 0x78 : 0x1f));  // zlib's CMF byte, gzip's first magic byte
            }
        }
        EXPECT(next == built.size());
    }
}

void test_uimage_and_dtb() {
    UImage img;
    img.name = "Linux";
    img.data = pattern(1000, 4);
    const Bytes built = img.build();
    layout::Layout l = layout::uimage(UImage::parse(built));
    layout::around(l, built, built.size(), 0, built.size());
    check_layout(l, built, {{"data", img.data}});
    EXPECT(find_name(l, "header")->size == 64);
    EXPECT(find_key(l, "data")->offset == 64);

    const layout::Layout d = layout::dtb_blobs({100, 200, 50});
    EXPECT(d.regions.size() == 3 && d.regions[2].offset == 300 && d.regions[2].size == 50 && d.regions[2].key == "blob2");
}

// The smallest flattened device tree there is: the header, the empty memory reservation block, an empty root node, no strings.
Bytes tiny_fdt(uint8_t marker) {
    Bytes b;
    auto be32 = [&](uint32_t v) {
        b.push_back(uint8_t(v >> 24));
        b.push_back(uint8_t(v >> 16));
        b.push_back(uint8_t(v >> 8));
        b.push_back(uint8_t(v));
    };
    be32(0xd00dfeed);
    be32(72);  // totalsize
    be32(56);  // off_dt_struct
    be32(72);  // off_dt_strings
    be32(40);  // off_mem_rsvmap
    be32(17);
    be32(16);
    be32(marker);  // boot_cpuid_phys: tells the trees apart
    be32(0);       // size_dt_strings
    be32(16);      // size_dt_struct
    for (int i = 0; i < 16; ++i) b.push_back(0);  // the reservation block's end
    be32(1);                                       // FDT_BEGIN_NODE
    be32(0);                                       // the name of the root: "" and its padding
    be32(2);                                       // FDT_END_NODE
    be32(9);                                       // FDT_END
    return b;
}

void test_qcdt() {
    for (uint32_t version = 1; version <= 3; ++version) {
        qcdt::Table t;
        t.version = version;
        t.page_size = 2048;
        t.dtbs = {tiny_fdt(1), tiny_fdt(2)};
        for (uint32_t i = 0; i < 3; ++i) {
            qcdt::Entry e;
            e.chipset = 0x100 + i;
            e.platform = 8;
            e.revision = 0x10000;
            e.dtb = i < 2 ? 0 : 1;
            t.entries.push_back(e);
        }
        const Bytes built = qcdt::build(t);
        const layout::Layout l = layout::qcdt(built, "dt_");
        const layout::Region* table = find_name(l, "QCDT table");
        EXPECT(table && table->offset == 0);
        EXPECT(table && table->size == 12 + 3 * qcdt::entry_size(version) + 4);
        for (size_t j = 0; j < 2; ++j) {
            const layout::Region* r = find_key(l, "dt_dtb" + std::to_string(j));
            EXPECT(r != nullptr);
            if (!r) continue;
            EXPECT(r->offset % 2048 == 0);
            EXPECT(r->size % 2048 == 0);
            EXPECT(same_at(built, r->offset, t.dtbs[j]));
            // behind the tree: zeros up to the end of the region
            bool zeros = true;
            for (uint64_t k = r->offset + t.dtbs[j].size(); k < r->offset + r->size; ++k) zeros = zeros && built[k] == 0;
            EXPECT(zeros);
        }
        EXPECT(l.regions.size() == 3);  // the three entries share two trees
    }
}

AvbDescriptor property_descriptor(const std::string& key, const std::string& value) {
    Bytes c;
    auto be64 = [&](uint64_t v) {
        for (int i = 7; i >= 0; --i) c.push_back(uint8_t(v >> (8 * i)));
    };
    be64(key.size());
    be64(value.size());
    c.insert(c.end(), key.begin(), key.end());
    c.push_back(0);
    c.insert(c.end(), value.begin(), value.end());
    c.push_back(0);
    while (c.size() % 8) c.push_back(0);
    AvbDescriptor d;
    d.tag = 0;
    d.content = c;
    return d;
}

void test_vbmeta() {
    const AvbTestKey& key = avb_test_keys()[0];
    for (int signed_image = 0; signed_image < 2; ++signed_image) {
        VbmetaImage v;
        v.release_string = "abr test";
        v.algorithm_type = signed_image ? static_cast<uint32_t>(AvbAlgorithm::SHA256_RSA2048) : 0;
        v.descriptors.push_back(property_descriptor("a", "bc"));
        v.descriptors.push_back(property_descriptor("longer key", "and a longer value, too"));
        v.descriptors.push_back(property_descriptor("z", ""));
        const Bytes built = signed_image ? v.build(key.pem) : v.build();
        const VbmetaImage p = VbmetaImage::parse(built);
        const layout::Layout l = layout::vbmeta_image(built);
        EXPECT(find_name(l, "vbmeta header") && find_name(l, "vbmeta header")->offset == 0 && find_name(l, "vbmeta header")->size == 256);
        EXPECT(find_name(l, "auxiliary block") != nullptr);
        EXPECT(find_name(l, "descriptors") != nullptr);
        for (size_t i = 0; i < p.descriptors.size(); ++i) {
            const layout::Region* r = find_key(l, "descriptor" + std::to_string(i));
            EXPECT(r != nullptr);
            if (!r) continue;
            EXPECT(r->depth == 2);
            EXPECT(r->size == 16 + p.descriptors[i].content.size());
            EXPECT(same_at(built, r->offset + 16, p.descriptors[i].content));
        }
        if (signed_image) {
            EXPECT(find_name(l, "authentication block") != nullptr);
            EXPECT(find_name(l, "hash") && same_at(built, find_name(l, "hash")->offset, p.hash));
            EXPECT(find_name(l, "signature") && same_at(built, find_name(l, "signature")->offset, p.signature));
            EXPECT(find_key(l, "public_key") && same_at(built, find_key(l, "public_key")->offset, p.public_key));
            EXPECT(find_name(l, "vbmeta header")->note == "algorithm SHA256_RSA2048");
        } else {
            EXPECT(find_name(l, "signature") == nullptr);
        }
        check_layout(l, built, {{"public_key", p.public_key}});
    }
    // What is not a vbmeta gives nothing, and never a crash.
    layout::Layout none;
    layout::vbmeta(none, Bytes(1000, 0), 0, 0, "");
    layout::vbmeta(none, Bytes(10, 0), 0, 0, "");
    layout::vbmeta(none, Bytes(), 5, 0, "");
    EXPECT(none.regions.empty());
    {
        VbmetaImage v;
        v.algorithm_type = 0;
        v.descriptors.push_back(property_descriptor("k", "v"));
        Bytes built = v.build();
        for (size_t cut : {size_t{0}, size_t{4}, size_t{255}, size_t{256}, size_t{300}, built.size() - 1}) {
            Bytes shorter(built.begin(), built.begin() + static_cast<long>(cut));
            (void)layout::vbmeta_image(shorter);  // must not crash
        }
        Bytes lying = built;
        for (int i = 0; i < 8; ++i) lying[12 + i] = 0xff;  // an authentication block of 2^64-1 bytes
        EXPECT(layout::vbmeta_image(lying).regions.empty());
    }
}

void test_around() {
    BootImage img;
    img.header_version = 4;
    img.kernel = pattern(5000, 1);
    img.ramdisk = pattern(3000, 2);
    const Bytes core = img.build();
    {
        // a prefix, a tail, fill up to the partition size
        Bytes whole(100, 0x5a);
        whole.insert(whole.end(), core.begin(), core.end());
        Bytes tail = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        whole.insert(whole.end(), tail.begin(), tail.end());
        whole.resize(1 << 20, 0xff);
        layout::Layout l = layout::boot(BootImage::parse(core));
        layout::around(l, whole, whole.size(), 100, core.size());
        EXPECT(l.size == whole.size());
        EXPECT(l.regions.front().name == "prefix" && l.regions.front().offset == 0 && l.regions.front().size == 100);
        EXPECT(find_name(l, "header") && find_name(l, "header")->offset == 100);
        EXPECT(find_key(l, "kernel") && find_key(l, "kernel")->offset == 100 + 4096);
        EXPECT(same_at(whole, find_key(l, "kernel")->offset, img.kernel));
        const layout::Region* t = find_name(l, "tail");
        EXPECT(t && t->offset == 100 + core.size() && t->size == tail.size() && same_at(whole, t->offset, tail));
        const layout::Region* f = find_name(l, "fill");
        EXPECT(f && f->offset == t->offset + t->size && f->offset + f->size == whole.size());
        EXPECT(f && f->note == "fill, all bytes 0xff");
        bool all = true;
        if (f)
            for (uint64_t k = f->offset; k < f->offset + f->size; ++k) all = all && whole[k] == 0xff;
        EXPECT(all);
        EXPECT(l.regions.back().offset + l.regions.back().size == whole.size());
    }
    {
        // an AVB hash footer behind the image: the vbmeta block and the footer, and the padding between
        VbmetaImage v;
        v.has_footer = true;
        v.host_prefix = core;
        v.footer_original_image_size = core.size();
        v.source_total_size = 1 << 20;
        v.algorithm_type = 0;
        v.release_string = "abr test";
        v.descriptors.push_back(property_descriptor("key", "value"));
        const Bytes whole = v.build();
        EXPECT(whole.size() == (1u << 20));
        layout::Layout l = layout::boot(BootImage::parse(core));
        layout::around(l, whole, core.size(), 0, core.size());
        const layout::Region* b = find_name(l, "AVB vbmeta");
        const layout::Region* f = find_name(l, "AVB footer");
        EXPECT(b && f);
        if (b && f) {
            EXPECT(f->offset == whole.size() - 64 && f->size == 64);
            EXPECT(std::memcmp(whole.data() + f->offset, "AVBf", 4) == 0);
            EXPECT(b->offset >= core.size() && std::memcmp(whole.data() + b->offset, "AVB0", 4) == 0);
            const layout::Region* d = find_key(l, "avb_descriptor0");
            EXPECT(d && d->depth == 3 && d->offset > b->offset && d->offset < b->offset + b->size);
        }
        EXPECT(find_name(l, "padding") != nullptr);
        EXPECT(find_name(l, "vbmeta header") && find_name(l, "vbmeta header")->depth == 1);
        EXPECT(find_key(l, "kernel") && same_at(whole, find_key(l, "kernel")->offset, img.kernel));
        check_layout(l, whole, {{"kernel", img.kernel}, {"ramdisk", img.ramdisk}});
    }
    {
        // a file that ends where the container does has nothing around it
        layout::Layout l = layout::boot(BootImage::parse(core));
        layout::around(l, core, core.size(), 0, core.size());
        EXPECT(find_name(l, "prefix") == nullptr && find_name(l, "tail") == nullptr && find_name(l, "fill") == nullptr);
        EXPECT(find_name(l, "AVB footer") == nullptr);
        // sizes that are too big for the file are cut, not trusted
        layout::Layout x = layout::boot(BootImage::parse(core));
        layout::around(x, core, core.size() + 100, 5000, core.size() * 2);
        EXPECT(!x.regions.empty());  // (the sizes it was told are cut to the file: no crash, nothing past the end)
        for (const auto& r : x.regions) EXPECT(r.offset <= 5000 + core.size());
    }
}

void test_text() {
    BootImage img;
    img.header_version = 2;
    img.page_size = 2048;
    img.kernel = compress(Codec::GZIP, pattern(5000, 1));
    img.ramdisk = pattern(300, 2);
    const Bytes built = img.build();
    layout::Layout l = layout::boot(BootImage::parse(built));
    layout::around(l, built, built.size(), 0, built.size());
    layout::Region* k = const_cast<layout::Region*>(find_key(l, "kernel"));
    k->file = "kernel";
    k->unpacked = 5000;
    k->level = 6;
    const std::string text = layout::render(l);
    EXPECT(text.find("0x00000800") != std::string::npos);
    EXPECT(text.find("gzip -> kernel (5000 bytes, level 6)") != std::string::npos);
    EXPECT(text.find("header version 2, 1660 bytes, page size 2048") != std::string::npos);
    EXPECT(text.find("\n  0x") != std::string::npos);
    EXPECT(text.rfind("\n") == text.size() - 1);

    const auto lines = layout::manifest_lines(l);
    std::map<std::string, std::string> m(lines.begin(), lines.end());
    EXPECT(m.size() == lines.size());  // no key twice
    EXPECT(m["layout_header_offset"] == "0x0");
    EXPECT(m["layout_header_size"] == "2048");
    EXPECT(m["layout_kernel_offset"] == "0x800");
    EXPECT(m["layout_kernel_size"] == std::to_string(img.kernel.size()));
    EXPECT(m["layout_kernel_unpacked_size"] == "5000");
    EXPECT(m.count("layout_ramdisk_offset") == 1);
    EXPECT(m.count("layout_ramdisk_unpacked_size") == 0);

    // two regions of one name get different keys
    layout::Layout twice;
    twice.add("padding", "", 0, 10);
    twice.add("padding", "", 20, 10);
    twice.add("AVB footer", "", 40, 10);
    const auto t = layout::manifest_lines(twice);
    std::set<std::string> keys;
    for (const auto& kv : t) keys.insert(kv.first);
    EXPECT(keys.size() == t.size());
    EXPECT(keys.count("layout_padding_offset") && keys.count("layout_padding_2_offset") && keys.count("layout_avb_footer_offset"));
}

void test_manifest_block() {
    const fs::path dir = fs::temp_directory_path() / ("abr_layout_test_" + std::to_string(reinterpret_cast<uintptr_t>(&g_checks)));
    fs::create_directories(dir);
    const fs::path file = dir / "manifest.txt";
    const std::string first = "# abr boot manifest\ntype=boot\nkernel_file=kernel\n";
    write_file(file, reinterpret_cast<const uint8_t*>(first.data()), first.size());
    layout::Layout l;
    l.add("header", "", 0, 2048);
    l.add("kernel", "kernel", 2048, 100);
    EXPECT(layout::write_manifest_block(file, l, "the image this folder was unpacked from"));
    Bytes raw = read_file(file);
    std::string text(raw.begin(), raw.end());
    EXPECT(text.rfind(first, 0) == 0);
    EXPECT(text.find("# layout of the image this folder was unpacked from") != std::string::npos);
    EXPECT(text.find("layout_kernel_offset=0x800\n") != std::string::npos);
    // a second block replaces the first, and a line of someone's own that is behind it stays
    text += "my_own_key=1\n";
    write_file(file, reinterpret_cast<const uint8_t*>(text.data()), text.size());
    layout::Layout l2;
    l2.add("kernel", "kernel", 4096, 200);
    EXPECT(layout::write_manifest_block(file, l2, "the image built from this folder"));
    raw = read_file(file);
    text.assign(raw.begin(), raw.end());
    EXPECT(text.find("layout_kernel_offset=0x1000\n") != std::string::npos);
    EXPECT(text.find("layout_kernel_offset=0x800\n") == std::string::npos);
    EXPECT(text.find("layout_header_offset") == std::string::npos);
    EXPECT(text.find("my_own_key=1\n") != std::string::npos);
    EXPECT(text.find("# layout of the image this folder was unpacked from") == std::string::npos);
    size_t blocks = 0;
    for (size_t at = 0; (at = text.find("# layout of", at)) != std::string::npos; ++at) ++blocks;
    EXPECT(blocks == 1);
    // the same block again changes nothing
    const std::string before = text;
    EXPECT(layout::write_manifest_block(file, l2, "the image built from this folder"));
    raw = read_file(file);
    EXPECT(std::string(raw.begin(), raw.end()) == before);
    // no file, no block
    EXPECT(!layout::write_manifest_block(dir / "nothing.txt", l2, "x"));
    EXPECT(!fs::exists(dir / "nothing.txt"));
    std::error_code ec;
    fs::remove_all(dir, ec);
}

}  // namespace

int run_layout_tests() {
    test_boot();
    test_vendor_boot();
    test_dtbo();
    test_uimage_and_dtb();
    test_qcdt();
    test_vbmeta();
    test_around();
    test_text();
    test_manifest_block();
    if (g_failures == 0) std::printf("layout: ok (%d checks)\n", g_checks);
    else std::printf("layout: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
