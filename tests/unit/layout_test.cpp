// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr::layout (include/abr/layout.hpp): for images made here with the builders of abr, the bytes at [offset, offset + size)
// of every region that names a part are that part. Run by tests/run_tests.sh as `abr_unit_tests layout`.
//
//   * boot images of every header version (0 to 4, a Marvell PXA header, a version 0 header with a device tree behind the second stage),
//     page sizes 2048 and 4096, parts that are streams (gzip is told by the first bytes), parts of a size that is no multiple of the page;
//   * vendor_boot v3 and v4 (one fragment, three fragments, a v4 header with no table), with a dtb and a bootconfig;
//   * dtbo v0 and v1, with entries stored as zlib and as gzip; the device trees inside the dtb and recovery_dtbo sections of a boot and a vendor_boot
//     image (trees, a dtbo table, a QCDT) as regions of their own;
//   * a uImage; a Qualcomm device tree table made by qcdt::build; flattened device trees one after the other;
//   * a FIT image with its data in the tree, behind it by data-offset and by data-position; a Sony ELF boot image (ELF32 and ELF64); a
//     Rockchip KRNL image; an ASUS blob, signed and not; an Intel OSIP image with and without its header; a ChromeOS kernel blob;
//   * the picture partitions: Qualcomm's SPLASH!! (one picture, one that counts no blocks, a table), the OPLUS logo image (with a zero and a DDPH
//     preamble, the most pictures the header holds), the Xiaomi LOGO!!!! (BMP, PNG, other pictures, a preamble that is kept) and the Motorola
//     MotoLogo (with an empty slot, two alignments); for each, what is not an image and a header damaged anywhere give no exception;
//   * a vbmeta image (header, hash, signature, descriptors, public key) and the vbmeta block and footer of an AVB hash footer;
//   * the bytes around a container: a prefix, a tail, the fill up to the partition size;
//   * the text (render) and the lines of a manifest (manifest_lines, write_manifest_block: an earlier block is replaced, the rest stays).
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "abr/aml.hpp"
#include "abr/avb_keys.hpp"
#include "abr/boot_image.hpp"
#include "abr/byte_io.hpp"
#include "abr/compression.hpp"
#include "abr/dtbo.hpp"
#include "abr/fdt.hpp"
#include "abr/fit.hpp"
#include "abr/layout.hpp"
#include "abr/legacy/blob.hpp"
#include "abr/legacy/chromeos.hpp"
#include "abr/legacy/elf_boot.hpp"
#include "abr/legacy/krnl.hpp"
#include "abr/legacy/osip.hpp"
#include "abr/qcdt.hpp"
#include "abr/splash.hpp"
#include "abr/textquote.hpp"
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
    // zeros between the trees are regions of their own, the trees keep their keys
    const layout::Layout g = layout::dtb_blobs({100, 200, 50}, {0, 4, 0});
    EXPECT(g.regions.size() == 4 && g.size == 354);
    EXPECT(g.regions.size() == 4 && g.regions[1].name == "padding" && g.regions[1].offset == 100 && g.regions[1].size == 4 && g.regions[1].key.empty());
    EXPECT(g.regions.size() == 4 && g.regions[2].key == "blob1" && g.regions[2].offset == 104 && g.regions[3].key == "blob2" && g.regions[3].offset == 304);
    EXPECT(layout::dtb_blobs({100, 200}, {0, 0}).regions.size() == 2);
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

// The device trees inside a section of a boot or vendor_boot image: the trees one behind the other (with the zeros between two and behind the last), or
// a dtbo table; and what the layouts of the images make of them.
void test_tree_sections() {
    const Bytes t1 = tiny_fdt(1), t2 = tiny_fdt(2);
    {
        Bytes section = t1;
        section.insert(section.end(), 4, 0);
        section.insert(section.end(), t2.begin(), t2.end());
        section.insert(section.end(), 12, 0);
        layout::Layout l;
        layout::tree_section(l, section, 4096, 1, "dtb");
        EXPECT(l.regions.size() == 4);
        if (l.regions.size() == 4) {
            EXPECT(l.regions[0].key == "dtb0" && l.regions[0].offset == 4096 && l.regions[0].size == 72 && l.regions[0].depth == 1);
            EXPECT(l.regions[1].name == "padding" && l.regions[1].key.empty() && l.regions[1].offset == 4096 + 72 && l.regions[1].size == 4);
            EXPECT(l.regions[2].key == "dtb1" && l.regions[2].offset == 4096 + 76 && l.regions[2].size == 72 && l.regions[2].depth == 1);
            EXPECT(l.regions[3].name == "padding" && l.regions[3].offset == 4096 + 148 && l.regions[3].size == 12 && l.regions[3].key.empty());
        }
    }
    {
        // what follows the last tree and is not zeros is a file of its own
        Bytes section = t1;
        const Bytes tail = {'T', 'A', 'I', 'L', 0, 0, 7};
        section.insert(section.end(), tail.begin(), tail.end());
        layout::Layout l;
        layout::tree_section(l, section, 0, 1, "dtb");
        EXPECT(l.regions.size() == 2 && l.regions[1].key == "dtb_tail" && l.regions[1].offset == 72 && l.regions[1].size == tail.size());
    }
    {
        // bytes that are no tree: nothing is added, and nothing that is empty
        layout::Layout l;
        layout::tree_section(l, pattern(500, 3), 0, 1, "dtb");
        layout::tree_section(l, Bytes(), 0, 1, "dtb");
        EXPECT(l.regions.empty());
    }
    {
        // a dtbo table: its header, its table of entries, its entries (with the keys of the entries of a section), and the zeros behind them
        DtboImage dtbo;
        dtbo.version = 0;
        dtbo.page_size = 4096;
        for (uint32_t i = 0; i < 2; ++i) {
            DtboEntry e;
            e.id = i;
            e.data = i ? t2 : t1;
            dtbo.entries.push_back(e);
        }
        Bytes section = dtbo.build();
        const size_t used = section.size();
        section.insert(section.end(), 100, 0);
        layout::Layout l;
        layout::tree_section(l, section, 8192, 1, "recovery_dtbo");
        EXPECT(find_name(l, "header") && find_name(l, "header")->offset == 8192 && find_name(l, "header")->depth == 1);
        EXPECT(find_name(l, "entry table") && find_name(l, "entry table")->offset == 8192 + 32);
        const layout::Region* e0 = find_key(l, "recovery_dtbo_entry0");
        const layout::Region* e1 = find_key(l, "recovery_dtbo_entry1");
        EXPECT(e0 && e1 && e0->size == 72 && e1->size == 72 && e1->offset == e0->offset + 72 && e0->depth == 1);
        EXPECT(e0 && same_at(section, e0->offset - 8192, t1));
        EXPECT(l.regions.back().name == "padding" && l.regions.back().offset == 8192 + used && l.regions.back().size == 100);
    }
    // the layouts of the images list them: a boot image of header version 2 (a table in the recovery dtbo section of version 1 and 2, trees in dtb) ...
    {
        DtboImage dtbo;
        dtbo.version = 0;
        dtbo.page_size = 2048;
        DtboEntry e;
        e.data = t1;
        dtbo.entries.push_back(e);
        BootImage img;
        img.header_version = 2;
        img.page_size = 2048;
        img.kernel = pattern(3000, 1);
        img.ramdisk = pattern(2500, 2);
        img.recovery_dtbo = dtbo.build();
        img.dtb = t1;
        img.dtb.insert(img.dtb.end(), t2.begin(), t2.end());
        img.recompute_id();
        const Bytes built = img.build();
        const BootImage parsed = BootImage::parse(built);
        layout::Layout l = layout::boot(parsed);
        layout::around(l, built, built.size(), 0, parsed.consumed);
        check_layout(l, built, boot_parts(parsed));
        const layout::Region* r0 = find_key(l, "dtb0");
        const layout::Region* r1 = find_key(l, "dtb1");
        const layout::Region* section = find_key(l, "dtb");
        EXPECT(r0 && r1 && section && r0->depth == 1 && r0->offset == section->offset && r1->offset == section->offset + 72);
        EXPECT(r0 && same_at(built, r0->offset, t1) && r1 && same_at(built, r1->offset, t2));
        const layout::Region* e0 = find_key(l, "recovery_dtbo_entry0");
        EXPECT(e0 && e0->depth == 1 && same_at(built, e0->offset, t1));
        EXPECT(find_key(l, "recovery_dtbo") != nullptr);
    }
    // ... a boot image of header version 0 with a Qualcomm device tree table (the trees are `dt_dtb<N>`) ...
    {
        qcdt::Table t;
        t.version = 2;
        t.page_size = 2048;
        t.dtbs = {t1, t2};
        for (uint32_t i = 0; i < 2; ++i) {
            qcdt::Entry e;
            e.chipset = 0x100 + i;
            e.platform = 8;
            e.revision = 0x10000;
            e.dtb = i;
            t.entries.push_back(e);
        }
        BootImage img;
        img.header_version = 0;
        img.page_size = 2048;
        img.kernel = pattern(3000, 1);
        img.ramdisk = pattern(2500, 2);
        img.dt = qcdt::build(t);
        img.recompute_id();
        const Bytes built = img.build();
        const BootImage parsed = BootImage::parse(built);
        layout::Layout l = layout::boot(parsed);
        layout::around(l, built, built.size(), 0, parsed.consumed);
        check_layout(l, built, boot_parts(parsed));
        for (size_t j = 0; j < 2; ++j) {
            const layout::Region* r = find_key(l, "dt_dtb" + std::to_string(j));
            EXPECT(r && r->depth == 1 && same_at(built, r->offset, j ? t2 : t1));
        }
        EXPECT(find_name(l, "QCDT table") && find_name(l, "QCDT table")->depth == 1);
    }
    // ... a boot image whose second stage is an Amlogic container of device trees (`second_dtb<N>`, nested in the row of the second)
    {
        aml::Table t;
        t.version = 2;
        t.page_size = 2048;
        t.dtbs = {t1, t2};
        for (size_t i = 0; i < 2; ++i) {
            aml::Entry e;
            e.soc = "gxl";
            e.platform = "p212";
            e.variant = i ? "2g" : "1g";
            e.dtb = i;
            t.entries.push_back(e);
        }
        BootImage img;
        img.header_version = 0;
        img.page_size = 2048;
        img.kernel = pattern(3000, 1);
        img.ramdisk = pattern(2500, 2);
        img.second = aml::build(t);
        img.recompute_id();
        const Bytes built = img.build();
        const BootImage parsed = BootImage::parse(built);
        layout::Layout l = layout::boot(parsed);
        layout::around(l, built, built.size(), 0, parsed.consumed);
        check_layout(l, built, boot_parts(parsed));
        const layout::Region* second = find_key(l, "second");
        EXPECT(second && second->depth == 0 && second->note.find("Amlogic device tree container") != std::string::npos);
        const layout::Region* table = find_name(l, "AML_ table");
        EXPECT(table && table->depth == 1 && second && table->offset == second->offset && table->size == 12 + 2 * 56);
        for (size_t j = 0; j < 2; ++j) {
            const layout::Region* r = find_key(l, "second_dtb" + std::to_string(j));
            EXPECT(r && r->depth == 1 && second && r->offset == second->offset + 2048 + 2048 * j && r->size == 2048);
            EXPECT(r && same_at(built, r->offset, j ? t2 : t1));
        }
    }
    // ... and a vendor_boot image (trees in dtb)
    {
        VendorBootImage img;
        img.header_version = 4;
        img.page_size = 4096;
        img.dtb = t1;
        img.dtb.insert(img.dtb.end(), t2.begin(), t2.end());
        VendorRamdiskEntry e;
        e.type = 1;
        e.data = pattern(5000, 3);
        img.ramdisk_fragments.push_back(e);
        const Bytes built = img.build();
        const VendorBootImage parsed = VendorBootImage::parse(built);
        layout::Layout l = layout::vendor_boot(parsed);
        layout::around(l, built, built.size(), 0, parsed.consumed);
        const layout::Region* r0 = find_key(l, "dtb0");
        const layout::Region* r1 = find_key(l, "dtb1");
        EXPECT(r0 && r1 && r0->depth == 1 && same_at(built, r0->offset, t1) && same_at(built, r1->offset, t2));
        const layout::Region* section = find_key(l, "dtb");
        EXPECT(section && section->depth == 0 && r0 && r0->offset == section->offset);
    }
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

void test_aml() {
    for (uint32_t version = 1; version <= 2; ++version) {
        for (const uint32_t page : {512u, 2048u}) {
            aml::Table t;
            t.version = version;
            t.page_size = page;
            t.dtbs = {tiny_fdt(1), tiny_fdt(2)};
            const char* variants[] = {"1g", "2g", "4g"};
            for (size_t i = 0; i < 3; ++i) {
                aml::Entry e;
                e.soc = "gxl";
                e.platform = "p21";
                e.variant = variants[i];
                e.dtb = i < 2 ? 0 : 1;  // the first two entries share the first tree
                t.entries.push_back(e);
            }
            const Bytes built = aml::build(t);
            const layout::Layout l = layout::aml(built, "second_");
            EXPECT(l.format == "Amlogic device tree container (AML_)" && l.size == built.size());
            const size_t table_size = 12 + 3 * aml::entry_size(version);
            const layout::Region* table = find_name(l, "AML_ table");
            EXPECT(table && table->offset == 0 && table->size == table_size && table->depth == 0);
            EXPECT(l.regions.size() == 3);  // the table and the two trees
            const uint64_t first = (table_size / page + 1) * page;
            for (size_t j = 0; j < 2; ++j) {
                const layout::Region* r = find_key(l, "second_dtb" + std::to_string(j));
                EXPECT(r != nullptr);
                if (!r) continue;
                EXPECT(r->name == "device tree " + std::to_string(j));
                EXPECT(r->offset == first + page * j && r->size == page);  // (a tree of 72 bytes: one page each)
                EXPECT(same_at(built, r->offset, t.dtbs[j]));
            }
            // the boards of the trees are in the notes: the first tree is for two of them, the second for one
            const layout::Region* r0 = find_key(l, "second_dtb0");
            const layout::Region* r1 = find_key(l, "second_dtb1");
            EXPECT(r0 && r0->note.find("for gxl_p21_1g, gxl_p21_2g") != std::string::npos && r0->note.find("72 bytes") != std::string::npos);
            EXPECT(r1 && r1->note.find("for gxl_p21_4g") != std::string::npos);
        }
    }
    // what is not a container, or is cut short, is a layout without regions or with the regions that are there
    EXPECT(layout::aml(Bytes(100, 0)).regions.empty());
    EXPECT(layout::aml(Bytes{'A', 'M', 'L', '_', 3, 0, 0, 0, 1, 0, 0, 0}).regions.empty());  // a version there is not
    {
        aml::Table t;
        t.version = 2;
        t.page_size = 2048;
        t.dtbs = {tiny_fdt(1)};
        aml::Entry e;
        e.soc = "a";
        e.platform = "b";
        e.variant = "c";
        t.entries = {e};
        Bytes built = aml::build(t);
        built.resize(2048 + 40);  // cut inside the tree
        const layout::Layout l = layout::aml(built);
        const layout::Region* r = find_name(l, "device tree 0");
        EXPECT(r && r->offset == 2048 && r->size == 40);
        built.resize(60);  // cut inside the table
        EXPECT(layout::aml(built).regions.size() == 1);
        EXPECT(layout::aml(built).regions[0].size == 12);  // (no entry is whole: the table has the header)
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


// ----------------------------------------------------------------------------------------------------- the legacy ones --

void test_krnl() {
    legacy::KrnlImage img;
    img.payload = pattern(1000, 8);
    const Bytes built = img.build();
    const legacy::KrnlImage p = legacy::KrnlImage::parse(built);
    layout::Layout l = layout::krnl(p, "kernel");
    layout::around(l, built, built.size(), 0, p.file_size());
    check_layout(l, built, {{"kernel", img.payload}});
    EXPECT(find_name(l, "header")->offset == 0 && find_name(l, "header")->size == 8);
    EXPECT(find_key(l, "kernel")->offset == 8 && find_key(l, "kernel")->size == 1000);
    const layout::Region* crc = find_name(l, "CRC");
    EXPECT(crc && crc->offset == 1008 && crc->size == 4 && crc->note.find("the payload's") != std::string::npos);
    EXPECT(l.size == built.size());
    // a ramdisk that is a gzip stream says so; the fill behind it is told
    legacy::KrnlImage gz;
    gz.payload = compress(Codec::GZIP, pattern(3000, 9));
    Bytes padded = gz.build();
    const size_t image_size = padded.size();
    padded.resize(image_size + 4096, 0);
    layout::Layout g = layout::krnl(legacy::KrnlImage::parse(padded), "ramdisk");
    layout::around(g, padded, padded.size(), 0, image_size);
    EXPECT(find_key(g, "ramdisk")->codec == "gzip");
    EXPECT(g.regions.back().offset == image_size && g.regions.back().size == 4096);
    // a CRC that is not the payload's
    Bytes bad = built;
    bad[bad.size() - 1] ^= 0x55;
    EXPECT(find_name(layout::krnl(legacy::KrnlImage::parse(bad), "kernel"), "CRC")->note.find("NOT") != std::string::npos);
}

void test_elf_boot() {
    using legacy::ElfSegment;
    for (bool is64 : {false, true}) {
        ElfSegment k, r, c;
        k.role = "kernel";
        k.addr = 0x8000;
        k.data = pattern(5000, 10);
        r.role = "ramdisk";
        r.flags = legacy::kElfFlagsRamdisk;
        r.addr = 0x2000000;
        r.data = pattern(777, 11);
        c.role = "cmdline";
        c.flags = legacy::kElfFlagsCmdline;
        c.data = pattern(43, 12);
        legacy::ElfBootImage img;
        img.is_64bit = is64;
        img.segments = {k, r, c};
        const Bytes built = img.build_elftool();
        const legacy::ElfBootImage p = legacy::ElfBootImage::parse(built);
        layout::Layout l = layout::elf_boot(p, built, {"kernel", "ramdisk", "cmdline"});
        layout::around(l, built, built.size(), 0, built.size());
        check_layout(l, built, {{"kernel", k.data}, {"ramdisk", r.data}, {"cmdline", c.data}});
        EXPECT(find_name(l, "ELF header")->offset == 0 && find_name(l, "ELF header")->size == (is64 ? 64u : 52u));
        EXPECT(find_name(l, "program headers")->size == 3 * (is64 ? 56u : 32u));
        EXPECT(find_key(l, "kernel")->offset == 4096 && find_key(l, "ramdisk")->offset == 4096 + 5000);
        EXPECT(find_key(l, "ramdisk")->note.find("0x2000000") != std::string::npos);
        EXPECT(l.format.find(is64 ? "ELF64" : "ELF32") != std::string::npos && l.size == built.size());
        // a segment that has no data has no region; one that is a gzip stream says so
        ElfSegment empty = k;
        empty.role = "extra0";
        empty.data.clear();
        ElfSegment zipped = r;
        zipped.data = compress(Codec::GZIP, pattern(2000, 13));
        legacy::ElfBootImage two;
        two.is_64bit = is64;
        two.segments = {k, empty, zipped};
        const Bytes b2 = two.build_elftool();
        const legacy::ElfBootImage p2 = legacy::ElfBootImage::parse(b2);
        const layout::Layout l2 = layout::elf_boot(p2, b2, {"kernel", "", "ramdisk"});
        EXPECT(find_key(l2, "kernel") && find_key(l2, "ramdisk") && find_key(l2, "ramdisk")->codec == "gzip");
        size_t segments = 0;
        for (const auto& region : l2.regions) segments += region.name.rfind("segment ", 0) == 0;
        EXPECT(segments == 2);
    }
}

void test_blob() {
    for (bool secure : {false, true}) {
        legacy::BlobPart lnx, sos;
        lnx.name = {'L', 'N', 'X', 0};
        lnx.data = pattern(3000, 14);
        sos.name = {'S', 'O', 'S', 0};
        sos.data = pattern(1500, 15);
        legacy::BlobImage b;
        b.secure = secure;
        b.parts = {lnx, sos};
        if (secure) {
            b.secure_datalen = 7000;
            b.secure_siglen = 256;
            b.tail = pattern(256, 16);
        }
        Bytes built = b.build();
        built.insert(built.end(), b.tail.begin(), b.tail.end());
        const legacy::BlobImage p = legacy::BlobImage::parse(built);
        layout::Layout l = layout::blob(p);
        layout::around(l, built, built.size(), 0, built.size());
        check_layout(l, built, {{"blob_part0", lnx.data}, {"blob_part1", sos.data}, {"blob_tail", b.tail}});
        EXPECT(l.size == built.size());
        EXPECT(find_name(l, "blob header")->offset == (secure ? 28u : 0u) && find_name(l, "blob header")->size == 60);
        EXPECT(find_name(l, "partition table")->size == 32);
        EXPECT(find_name(l, "partition LNX") && find_name(l, "partition SOS"));
        EXPECT((find_name(l, "secure header") != nullptr) == secure);
        EXPECT(find_key(l, "blob_part0")->offset == (secure ? 28u : 0u) + 60 + 32);
    }
}

void test_osip() {
    legacy::OsipImage img;
    img.cmdline.assign(legacy::kOsipCmdlineSize, 0);
    const std::string cmd = "console=ttyS0 androidboot.hardware=unit";
    std::copy(cmd.begin(), cmd.end(), img.cmdline.begin());
    img.info_rest.assign(legacy::kOsipInfoSize - legacy::kOsipInfoFixedSize, 0);
    img.bootstub = pattern(4096, 17);
    const uint8_t stub_magic[4] = {0xFC, 0xFA, 0xBC, 0x00};
    std::copy(stub_magic, stub_magic + 4, img.bootstub.begin());
    img.kernel = pattern(700, 18);
    img.kernel[0] = 0xEB;
    img.kernel[1] = 0x3C;
    img.ramdisk = Bytes(300, 0);
    std::copy_n("070701", 6, img.ramdisk.begin());
    for (bool with_header : {false, true}) {
        legacy::OsipImage x = img;
        if (with_header) {
            x.header.assign(legacy::kOsipHeaderSize, 0);
            std::copy_n("$OS$\0\0\1", 7, x.header.begin());
        }
        const Bytes built = x.build();
        const legacy::OsipImage p = legacy::OsipImage::parse(built);
        layout::Layout l = layout::osip(p);
        layout::around(l, built, built.size(), 0, p.consumed);
        check_layout(l, built, {{"kernel", x.kernel}, {"ramdisk", x.ramdisk}, {"bootstub", x.bootstub}, {"osip_header", x.header}});
        const uint64_t front = with_header ? legacy::kOsipHeaderSize : 0;
        EXPECT(find_name(l, "cmdline")->offset == front && find_name(l, "cmdline")->size == legacy::kOsipCmdlineSize);
        EXPECT(find_name(l, "cmdline")->note.find("console=ttyS0") != std::string::npos);
        EXPECT(find_name(l, "image info")->offset == front + 1024 && find_name(l, "image info")->size == legacy::kOsipInfoSize);
        EXPECT(find_key(l, "bootstub")->offset == front + 4096 && find_key(l, "kernel")->offset == front + 4096 + 4096);
        EXPECT((find_name(l, "OSIP header") != nullptr) == with_header);
        EXPECT(l.size == built.size());
    }
}

void test_chromeos() {
    legacy::ChromeosInfo info;
    info.keyblock = legacy::chromeos_dev_keyblock();
    const std::string cmdline = "console=ttyS0 root=/dev/mmcblk0p3";
    info.config.assign(cmdline.begin(), cmdline.end());
    const Bytes kernel = pattern(5000, 19);
    const Bytes blob = legacy::apply_chromeos(kernel, info);
    Bytes k;
    const std::optional<legacy::ChromeosInfo> c = legacy::strip_chromeos(blob, k);
    EXPECT(c.has_value());
    if (!c) return;
    layout::Layout l = layout::chromeos(*c, blob);
    layout::around(l, blob, blob.size(), 0, c->core_size);
    check_layout(l, blob, {{"chromeos_kernel", k}});
    EXPECT(find_name(l, "verification block")->offset == 0 && find_name(l, "verification block")->size == c->pad);
    EXPECT(find_name(l, "keyblock")->size == info.keyblock.size() && find_name(l, "keyblock")->depth == 1);
    EXPECT(find_name(l, "preamble") && find_name(l, "preamble")->offset == info.keyblock.size());
    EXPECT(find_name(l, "body")->offset == c->pad && find_name(l, "body")->size == c->core_size - c->pad);
    EXPECT(find_key(l, "chromeos_kernel")->offset == c->pad);
    EXPECT(find_name(l, "config")->size == 4096 && find_name(l, "params")->size == 4096);
    EXPECT(find_name(l, "config")->offset == c->pad + c->kernel_size);
    EXPECT(l.size == c->core_size);
    // the fill of a partition behind it
    Bytes dump = blob;
    dump.resize(dump.size() + 8192, 0xFF);
    const std::optional<legacy::ChromeosInfo> c2 = legacy::strip_chromeos(dump, k);
    EXPECT(c2.has_value());
    if (c2) {
        layout::Layout l2 = layout::chromeos(*c2, dump);
        layout::around(l2, dump, dump.size(), 0, c2->core_size);
        EXPECT(l2.regions.back().offset == blob.size() && l2.regions.back().size == 8192);
    }
}

fdt::Property fit_text(const std::string& name, const std::string& text) {
    fdt::Property p;
    p.name = name;
    p.value.assign(text.begin(), text.end());
    p.value.push_back(0);
    return p;
}

fdt::Node fit_image(const std::string& name, const std::string& type, const Bytes* data, bool with_hash) {
    fdt::Node n;
    n.name = name;
    n.props.push_back(fit_text("description", name));
    n.props.push_back(fit_text("type", type));
    n.props.push_back(fit_text("compression", "none"));
    if (data) {
        fdt::Property p;
        p.name = "data";
        p.value = *data;
        n.props.push_back(std::move(p));
    }
    if (with_hash) {  // (a node inside an image node: its properties are not the image's)
        fdt::Node h;
        h.name = "hash-1";
        h.props.push_back(fit_text("algo", "crc32"));
        fdt::Property v;
        v.name = "value";
        v.value = {1, 2, 3, 4};
        h.props.push_back(std::move(v));
        n.children.push_back(std::move(h));
    }
    return n;
}

void fit_case(fit::Place place) {
    const Bytes d0 = pattern(1000, 20), d1 = pattern(300, 21), d2 = pattern(4097, 22);
    const Bytes gz = compress(Codec::GZIP, pattern(2000, 23));
    fdt::Tree t;
    t.root.props.push_back(fit_text("description", "layout test"));
    fdt::Node images;
    images.name = "images";
    images.children.push_back(fit_image("kernel-1", "kernel", &d0, true));
    images.children.push_back(fit_image("script-1", "script", nullptr, false));  // no data
    images.children.push_back(fit_image("fdt-1", "flat_dt", &d1, false));
    images.children.push_back(fit_image("ramdisk-1", "ramdisk", &gz, true));
    images.children.push_back(fit_image("firmware-1", "firmware", &d2, false));
    t.root.children.push_back(std::move(images));
    fdt::Node configs;
    configs.name = "configurations";
    configs.props.push_back(fit_text("default", "conf-1"));
    t.root.children.push_back(std::move(configs));

    fit::Layout lay;
    lay.place = place;
    const Bytes file = fit::build(t, lay);
    const std::vector<std::string> keys = {"kernel_1", "", "fdt_1", "ramdisk_1", "firmware_1"};
    layout::Layout l = layout::fit(file, keys);
    layout::around(l, file, file.size(), 0, file.size());
    check_layout(l, file, {{"kernel_1", d0}, {"fdt_1", d1}, {"ramdisk_1", gz}, {"firmware_1", d2}});
    EXPECT(find_name(l, "FDT header") && find_name(l, "FDT header")->offset == 0);
    const layout::Region* structure = find_name(l, "structure block");
    const layout::Region* strings = find_name(l, "strings block");
    EXPECT(structure && strings && strings->offset >= structure->offset + structure->size);
    EXPECT(find_key(l, "ramdisk_1")->codec == "gzip");
    EXPECT(find_name(l, "image script-1") == nullptr);  // (it has no data)
    EXPECT(find_name(l, "image kernel-1")->note.find("kernel") == 0);
    for (const char* key : {"kernel_1", "fdt_1", "ramdisk_1", "firmware_1"}) {
        const layout::Region* r = find_key(l, key);
        if (!r || !structure) continue;
        if (place == fit::Place::INLINE) {
            EXPECT(r->depth == 1 && r->offset >= structure->offset && r->offset + r->size <= structure->offset + structure->size);
        } else {
            EXPECT(r->depth == 0 && r->offset >= strings->offset + strings->size);
        }
    }
    EXPECT(l.size == file.size());
}

void test_fit() {
    fit_case(fit::Place::INLINE);
    fit_case(fit::Place::OFFSET);
    fit_case(fit::Place::POSITION);
    // not a tree: nothing breaks, nothing is made up
    EXPECT(layout::fit(Bytes(), {}).regions.empty());
    EXPECT(layout::fit(Bytes(100, 7), {}).regions.empty());
    Bytes cut = tiny_fdt(1);
    cut.resize(30);
    EXPECT(layout::fit(cut, {}).regions.empty());
    // a tree that is damaged anywhere never throws
    const Bytes good = tiny_fdt(2);
    for (size_t at = 0; at < good.size(); ++at) {
        Bytes bad = good;
        bad[at] ^= 0xff;
        (void)layout::fit(bad, {});
    }
}

// ---------------------------------------------------------------------------------------------------- the picture partitions --

void put_le32(Bytes& b, size_t at, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) b[at + i] = static_cast<uint8_t>(v >> (8 * i));
}

// A picture with runs of one colour and some pixels that differ.
splash::Bitmap picture(uint32_t w, uint32_t h, uint8_t seed) {
    splash::Bitmap b;
    b.width = w;
    b.height = h;
    b.bgr.resize(size_t{w} * h * 3);
    for (uint32_t y = 0; y < h; ++y)
        for (uint32_t x = 0; x < w; ++x)
            for (uint32_t c = 0; c < 3; ++c) b.bgr[(size_t{y} * w + x) * 3 + c] = static_cast<uint8_t>(((x / 5 + y / 3) * (c + 2) + seed) * 17 + ((x * y) % 11 == 0 ? x : 0));
    return b;
}

splash::QcPicture qc_picture(const splash::Bitmap& bmp, uint32_t type, bool padded) {
    splash::QcPicture p;
    p.width = bmp.width;
    p.height = bmp.height;
    p.type = type;
    p.data = splash::qc_encode(bmp, type);
    p.stream = p.data.size();
    p.blocks = splash::qc_blocks(p.data.size());
    if (padded) p.data.resize(size_t{p.blocks} * splash::kQcBlock, 0);
    return p;
}

// What a layout describes lies in the file, whatever the bytes are.
void expect_inside(const layout::Layout& l, const Bytes& file) {
    for (const auto& r : l.regions) EXPECT(r.offset + r.size <= file.size());
}

bool has_line(const layout::Layout& l, const std::string& key, const std::string& value) {
    for (const auto& [k, v] : layout::manifest_lines(l))
        if (k == key && v == value) return true;
    return false;
}

std::string hex_of(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

bool contains(const std::string& text, const std::string& what) { return text.find(what) != std::string::npos; }

void test_qc_splash() {
    const splash::Bitmap a = picture(40, 25, 1), b = picture(13, 7, 2), c = picture(64, 48, 3);
    const Bytes ea = splash::qc_encode(a, splash::kQcRle24), eb = splash::qc_encode(b, splash::kQcRaw), ec = splash::qc_encode(c, splash::kQcRle24);
    EXPECT(ea.size() % splash::kQcBlock != 0 && eb.size() == 13 * 7 * 3 && ec.size() % splash::kQcBlock != 0);  // (so there is padding to tell from the pictures)

    {  // one picture, run-length coded, padded up to the block
        splash::QcSplash s;
        s.pictures.push_back(qc_picture(a, splash::kQcRle24, true));
        const Bytes file = splash::qc_build(s);
        const layout::Layout l = layout::qc_splash(file);
        EXPECT(l.size == file.size());
        EXPECT(contains(l.format, "SPLASH!!"));
        EXPECT(l.regions.size() == 2);
        const layout::Region* h = find_name(l, "header");
        EXPECT(h && h->offset == 0 && h->size == 512 && h->depth == 0 && h->note == "one picture");
        const layout::Region* p = find_key(l, "picture0");
        EXPECT(p && p->offset == 512 && p->size == ea.size());
        EXPECT(p && p->offset + p->size < file.size());  // (the padding up to the block is no part)
        EXPECT(p && contains(p->note, "40x25") && contains(p->note, splash::qc_type_name(splash::kQcRle24)) && contains(p->note, "blocks"));
        check_layout(l, file, {{"picture0", ea}});
    }
    {  // one picture that counts no blocks (the sample images of Qualcomm): the pixels are the rest of the file
        splash::QcSplash s;
        splash::QcPicture p = qc_picture(b, splash::kQcRaw, false);
        p.blocks = 0;
        s.pictures.push_back(p);
        const Bytes file = splash::qc_build(s);
        EXPECT(file.size() == 512 + eb.size());
        const layout::Layout l = layout::qc_splash(file);
        const layout::Region* r = find_key(l, "picture0");
        EXPECT(r && r->offset == 512 && r->size == eb.size());
        EXPECT(r && contains(r->note, "no block count"));
        check_layout(l, file, {{"picture0", eb}});
    }
    {  // a table: three pictures, the first two padded up to their blocks, the last not
        splash::QcSplash s;
        s.several = true;
        s.pictures = {qc_picture(a, splash::kQcRle24, true), qc_picture(b, splash::kQcRaw, true), qc_picture(c, splash::kQcRle24, false)};
        const Bytes file = splash::qc_build(s);
        const layout::Layout l = layout::qc_splash(file);
        EXPECT(l.regions.size() == 4);
        const layout::Region* h = find_name(l, "header");
        EXPECT(h && h->offset == 0 && h->size == 512 && contains(h->note, "table of 3 pictures"));
        const Bytes* parts[3] = {&ea, &eb, &ec};
        uint64_t at = 512;
        std::map<std::string, Bytes> want;
        for (size_t i = 0; i < 3; ++i) {
            const std::string key = "picture" + std::to_string(i);
            const layout::Region* r = find_key(l, key);
            EXPECT(r && r->offset == at && r->size == parts[i]->size());
            EXPECT(has_line(l, "layout_" + key + "_offset", hex_of(at)));
            EXPECT(has_line(l, "layout_" + key + "_size", std::to_string(parts[i]->size())));
            at += s.pictures[i].data.size();
            want[key] = *parts[i];
        }
        EXPECT(at == file.size());
        check_layout(l, file, want);
        EXPECT(contains(layout::render(l), "picture 2"));

        // not an image: nothing is made up; a header that is damaged anywhere, a file that is cut anywhere: no exception, what is described is in the file
        EXPECT(layout::qc_splash(Bytes()).regions.empty());
        EXPECT(layout::qc_splash(Bytes(700, 9)).regions.empty());
        EXPECT(layout::qc_splash(Bytes(file.begin(), file.begin() + 600)).regions.empty());
        for (size_t at2 = 0; at2 < 512; ++at2) {
            Bytes bad = file;
            bad[at2] ^= 0xFF;
            expect_inside(layout::qc_splash(bad), bad);
        }
        for (size_t cut = 0; cut < file.size(); cut += 331) {
            const Bytes bad(file.begin(), file.begin() + static_cast<long>(cut));
            expect_inside(layout::qc_splash(bad), bad);
        }
    }
}

splash::OplusLogo oplus_sample(bool ddph, size_t entries) {
    splash::OplusLogo o;
    o.preamble = Bytes(splash::kOplusPreamble, 0);
    if (ddph) {
        o.preamble = pattern(splash::kOplusPreamble, 9);
        put_le32(o.preamble, 0, splash::kDdphMagic);
    }
    o.desc[0] = "test logo";
    o.version = 2;
    o.width = 1080;
    o.height = 2400;
    o.compression = 1;
    for (size_t i = 0; i < entries; ++i) {
        splash::OplusEntry e;
        e.name = i == 1 ? "fhd_wallpaper.bmp" : "logo" + std::to_string(i);
        e.data = pattern(300 + 217 * i, static_cast<uint8_t>(i + 1));
        e.plain_size = static_cast<uint32_t>(e.data.size() * 3);
        o.entries.push_back(std::move(e));
    }
    return o;
}

void test_oplus_logo() {
    for (const bool ddph : {false, true}) {
        const splash::OplusLogo o = oplus_sample(ddph, 3);
        const Bytes file = splash::oplus_build(o);
        const layout::Layout l = layout::oplus_logo(file);
        EXPECT(l.size == file.size());
        EXPECT(contains(l.format, "OPLUS"));
        const layout::Region* pre = find_name(l, "preamble");
        EXPECT(pre && pre->offset == 0 && pre->size == 0x4000 && pre->depth == 0);
        EXPECT(pre && (pre->key == "preamble") == ddph);  // (a preamble of zeros is not a file of its own)
        EXPECT(pre && contains(pre->note, ddph ? "DDPH" : "zeros"));
        const layout::Region* h = find_name(l, "header");
        EXPECT(h && h->offset == 0x4000 && h->size == 0x4000 && h->depth == 0 && contains(h->note, "3 pictures, version 2, 1080x2400"));
        const layout::Region* d = find_name(l, "descriptions");
        EXPECT(d && d->offset == 0x400C && d->size == 256 && d->depth == 1);
        const layout::Region* t = find_name(l, "table");
        EXPECT(t && t->offset == 0x4000 + 288 && t->size == 3 * 128 && t->depth == 1);
        uint64_t at = 0x8000;
        std::map<std::string, Bytes> want;
        for (size_t i = 0; i < 3; ++i) {
            const std::string key = "entry" + std::to_string(i);
            const layout::Region* r = find_key(l, key);
            EXPECT(r && r->offset == at && r->size == o.entries[i].data.size());
            EXPECT(r && r->depth == 0 && contains(r->note, o.entries[i].name) && contains(r->note, std::to_string(o.entries[i].plain_size)));
            at += o.entries[i].data.size();
            want[key] = o.entries[i].data;
        }
        if (ddph) want["preamble"] = o.preamble;
        EXPECT(at == file.size());
        check_layout(l, file, want);
    }
    {  // the most the header holds
        splash::OplusLogo o = oplus_sample(false, splash::kOplusMaxEntries);
        for (auto& e : o.entries) e.data.resize(5);
        const Bytes file = splash::oplus_build(o);
        const layout::Layout l = layout::oplus_logo(file);
        EXPECT(l.regions.size() == 4 + splash::kOplusMaxEntries);  // preamble, header, descriptions, table, the pictures
        const layout::Region* t = find_name(l, "table");
        EXPECT(t && t->offset + t->size <= 0x8000);
        check_layout(l, file, {});
    }
    {  // not an image
        const Bytes file = splash::oplus_build(oplus_sample(false, 2));
        EXPECT(layout::oplus_logo(Bytes()).regions.empty());
        EXPECT(layout::oplus_logo(Bytes(0x9000, 0)).regions.empty());
        EXPECT(layout::oplus_logo(Bytes(file.begin(), file.end() - 5)).regions.empty());  // the last picture is cut short
        for (size_t at = 0x4000; at < 0x4000 + 600; ++at) {
            Bytes bad = file;
            bad[at] ^= 0xFF;
            expect_inside(layout::oplus_logo(bad), bad);
        }
    }
}

Bytes bmp_file(size_t size, uint8_t seed) {
    Bytes b = pattern(size, seed);
    b[0] = 'B';
    b[1] = 'M';
    put_le32(b, 2, static_cast<uint32_t>(size));
    return b;
}

// A PNG that has the chunks that make one a file (a signature, IHDR, IDAT of `idat` bytes, IEND); the bytes in them are not a picture.
Bytes png_file(size_t idat) {
    static constexpr uint8_t kSignature[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    Bytes b(kSignature, kSignature + 8);
    const auto chunk = [&b](const char* type, size_t len) {
        const size_t at = b.size();
        b.resize(at + 12 + len, 0x55);
        for (size_t i = 0; i < 4; ++i) b[at + i] = static_cast<uint8_t>(len >> (24 - 8 * i));
        std::memcpy(b.data() + at + 4, type, 4);
    };
    chunk("IHDR", 13);
    chunk("IDAT", idat);
    chunk("IEND", 0);
    return b;
}

void test_xiaomi_logo() {
    for (const bool kept : {false, true}) {
        splash::XiaomiLogo x;
        x.preamble = kept ? pattern(splash::kXiaomiPreamble, 7) : Bytes(splash::kXiaomiPreamble, 0);
        const Bytes bmp = bmp_file(9270, 1), png = png_file(5000), other = pattern(4096, 3), tiny = bmp_file(100, 4);
        x.pictures = {bmp, png, other, tiny};
        const Bytes file = splash::xiaomi_build(x);
        const layout::Layout l = layout::xiaomi_logo(file);
        EXPECT(l.size == file.size());
        EXPECT(contains(l.format, "Xiaomi"));
        const layout::Region* pre = find_name(l, "preamble");
        EXPECT(pre && pre->offset == 0 && pre->size == 0x4000 && (pre->key == "preamble") == kept);
        const layout::Region* t = find_name(l, "table");
        EXPECT(t && t->offset == 0x4000 && t->size == 0x1000 && contains(t->note, "4 pictures"));
        const Bytes* parts[4] = {&bmp, &png, &other, &tiny};
        const char* kinds[4] = {"bmp", "png", "bin", "bmp"};
        uint64_t at = 0x5000;
        std::map<std::string, Bytes> want;
        for (size_t i = 0; i < 4; ++i) {
            const std::string key = "picture" + std::to_string(i);
            const layout::Region* r = find_key(l, key);
            EXPECT(r && r->offset == at && r->size == parts[i]->size());  // the file, not the units that hold it
            EXPECT(r && contains(r->note, kinds[i]) && contains(r->note, "unit"));
            at += (parts[i]->size() + splash::kXiaomiUnit - 1) / splash::kXiaomiUnit * splash::kXiaomiUnit;
            want[key] = *parts[i];
        }
        if (kept) want["preamble"] = x.preamble;
        EXPECT(at == file.size());
        check_layout(l, file, want);
    }
    {  // not an image
        splash::XiaomiLogo x;
        x.preamble = Bytes(splash::kXiaomiPreamble, 0);
        x.pictures = {bmp_file(5000, 1), bmp_file(300, 2)};
        const Bytes file = splash::xiaomi_build(x);
        EXPECT(layout::xiaomi_logo(Bytes()).regions.empty());
        EXPECT(layout::xiaomi_logo(Bytes(0x5000, 0)).regions.empty());
        EXPECT(layout::xiaomi_logo(Bytes(file.begin(), file.end() - 4096)).regions.empty());  // the last picture is cut short
        for (size_t at = 0x4000; at < 0x4000 + 64; ++at) {
            Bytes bad = file;
            bad[at] ^= 0xFF;
            expect_inside(layout::xiaomi_logo(bad), bad);
        }
    }
}

// What a picture of the Motorola image that is run-length coded begins with: "MotoRun", a zero, the width and the height (big-endian); the rest is not decoded here.
Bytes motorun_stub(uint16_t w, uint16_t h, size_t payload) {
    Bytes b = pattern(splash::kMotoHeaderSize + payload, 6);
    std::memcpy(b.data(), "MotoRun\0", 8);
    b[8] = static_cast<uint8_t>(w >> 8);
    b[9] = static_cast<uint8_t>(w);
    b[10] = static_cast<uint8_t>(h >> 8);
    b[11] = static_cast<uint8_t>(h);
    return b;
}

void test_moto_logo() {
    for (const uint32_t align : {512u, 4096u}) {
        splash::MotoLogo m;
        m.align = align;
        splash::MotoEntry boot, empty, raw, battery;
        boot.name = "logo_boot";
        boot.data = motorun_stub(64, 48, 6000);
        empty.name = "empty_slot";
        raw.name = "raw_data";
        raw.data = pattern(380, 5);
        battery.name = "logo_battery";
        battery.data = motorun_stub(300, 20, 100);
        m.entries = {boot, empty, raw, battery};
        const Bytes file = splash::moto_build(m);
        const layout::Layout l = layout::moto_logo(file);
        EXPECT(l.size == file.size());
        EXPECT(contains(l.format, "Motorola"));
        const layout::Region* t = find_name(l, "table");
        EXPECT(t && t->offset == 0 && t->size == 13 + 32 * 4 && contains(t->note, "4 entries, 3 pictures") && contains(t->note, std::to_string(align)));
        EXPECT(find_key(l, "entry1") == nullptr);  // (an empty slot is no part)
        const auto up = [align](uint64_t v) { return (v + align - 1) / align * align; };
        uint64_t end = 13 + 32 * 4;
        std::map<std::string, Bytes> want;
        const char* notes[4] = {"logo_boot; MotoRun, 64x48", "", "raw_data; bin", "logo_battery; MotoRun, 300x20"};
        for (const size_t i : {size_t{0}, size_t{2}, size_t{3}}) {
            const std::string key = "entry" + std::to_string(i);
            const layout::Region* r = find_key(l, key);
            const uint64_t at = up(end);
            EXPECT(r && r->offset == at && r->size == m.entries[i].data.size());
            EXPECT(r && contains(r->note, notes[i]));
            end = at + m.entries[i].data.size();
            want[key] = m.entries[i].data;
        }
        EXPECT(end == file.size());
        check_layout(l, file, want);
    }
    {  // not an image
        splash::MotoLogo m;
        splash::MotoEntry e;
        e.name = "logo";
        e.data = motorun_stub(10, 10, 300);
        m.entries = {e};
        const Bytes file = splash::moto_build(m);
        EXPECT(layout::moto_logo(Bytes()).regions.empty());
        EXPECT(layout::moto_logo(Bytes(100, 0xFF)).regions.empty());
        EXPECT(layout::moto_logo(Bytes(file.begin(), file.end() - 1)).regions.empty());  // the picture is cut short
        for (size_t at = 0; at < 80; ++at) {
            Bytes bad = file;
            bad[at] ^= 0xFF;
            expect_inside(layout::moto_logo(bad), bad);
        }
    }
}

// What a terminal would act on in a line of the table: the control characters, the C1 controls (in UTF-8 C2 80 to C2 9F), the bytes that are not UTF-8.
bool terminal_clean(const std::string& text) {
    for (size_t i = 0; i < text.size();) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c == '\n' || c == '\t') {
            ++i;
        } else if (c < 0x20 || c == 0x7F) {
            return false;
        } else if (c < 0x80) {
            ++i;
        } else if (c >= 0xC2 && c <= 0xDF && i + 1 < text.size() && (static_cast<unsigned char>(text[i + 1]) & 0xC0) == 0x80) {
            if (c == 0xC2 && static_cast<unsigned char>(text[i + 1]) < 0xA0) return false;
            i += 2;
        } else if (c >= 0xE0 && c <= 0xEF && i + 2 < text.size() && (static_cast<unsigned char>(text[i + 1]) & 0xC0) == 0x80 &&
                   (static_cast<unsigned char>(text[i + 2]) & 0xC0) == 0x80) {
            i += 3;
        } else {
            return false;
        }
    }
    return true;
}

void test_text_of_images() {
    // the escaper: what a terminal acts on becomes \xNN, everything else (UTF-8 text, quotes, backslashes, blanks) stays
    EXPECT(textquote::escape_for_terminal("plain text, \"quoted\" \\ and\ttab") == "plain text, \"quoted\" \\ and\\x09tab");
    EXPECT(textquote::escape_for_terminal("a\x1b[2Jb") == "a\\x1b[2Jb");
    EXPECT(textquote::escape_for_terminal("bell\x07" "del\x7f") == "bell\\x07del\\x7f");
    EXPECT(textquote::escape_for_terminal("line\nbreak") == "line\\x0abreak");
    EXPECT(textquote::escape_for_terminal("caf\xc3\xa9 \xe2\x82\xac") == "caf\xc3\xa9 \xe2\x82\xac");       // UTF-8 is text
    EXPECT(textquote::escape_for_terminal("c1\xc2\x9b" "31m") == "c1\\xc2\\x9b31m");                           // U+009B starts a sequence in a UTF-8 terminal
    EXPECT(textquote::escape_for_terminal("cut\xe2\x82") == "cut\\xe2\\x82");                                   // a character that is cut off
    EXPECT(textquote::escape_for_terminal("\xff\xfe") == "\\xff\\xfe");
    EXPECT(textquote::escape_for_terminal("\xed\xa0\x80") == "\\xed\\xa0\\x80");                               // a surrogate is no character
    EXPECT(textquote::escape_for_terminal("\xc0\x80") == "\\xc0\\x80");                                         // an overlong NUL
    EXPECT(textquote::escape_for_terminal("").empty());
    EXPECT(terminal_clean(textquote::escape_for_terminal(std::string("\x00\x01\x1b\x7f\x80\x9b\xc2\x85\xff", 9))));
    // (the judge itself: it sees what it is there for)
    EXPECT(!terminal_clean("a\x1b[2J") && !terminal_clean("bell\x07") && !terminal_clean("c1\xc2\x9b" "31m") && !terminal_clean("cut\xe2\x82") && !terminal_clean("\xff"));
    EXPECT(terminal_clean("caf\xc3\xa9 \xe2\x82\xac and\ttab\nlines"));

    const std::vector<std::string> hostile = {"\x1b[2J\x1b[Hx", "a\x07" "b\x08" "c\x7f" "d", "cut\xe2\x82", "c1\xc2\x9b" "31mx", "\xff\xfe\x80" "ab", "two\nlines", "tab\there"};
    for (const std::string& name : hostile) {
        {  // Motorola: the name of a picture
            splash::MotoLogo m;
            splash::MotoEntry e;
            e.name = name;
            e.data = motorun_stub(10, 10, 300);
            m.entries = {e};
            const Bytes file = splash::moto_build(m);
            const std::string text = layout::render(layout::moto_logo(file));
            EXPECT(!text.empty());
            EXPECT(terminal_clean(text));
        }
        {  // vendor_boot v4: the name of a ramdisk fragment
            VendorBootImage v;
            v.header_version = 4;
            v.page_size = 4096;
            v.dtb = pattern(2500, 1);
            VendorRamdiskEntry a, b;
            a.name = name;
            a.data = pattern(100, 1);
            b.name = "second";
            b.data = pattern(100, 2);
            v.ramdisk_fragments = {a, b};
            const Bytes built = v.build();
            const std::string text = layout::render(layout::vendor_boot(VendorBootImage::parse(built)));
            EXPECT(text.find("ramdisk fragment 0") != std::string::npos);
            EXPECT(terminal_clean(text));
        }
        {  // OPLUS: the name of a picture
            splash::OplusLogo o;
            splash::OplusEntry e;
            e.name = name;
            e.plain_size = 100;
            e.data = pattern(50, 3);
            o.entries = {e};
            const std::string text = layout::render(layout::oplus_logo(splash::oplus_build(o)));
            EXPECT(terminal_clean(text));
        }
    }
    {  // a long name is cut on a character boundary, with its ~
        splash::MotoLogo m;
        splash::MotoEntry e;
        e.name = "";
        for (int i = 0; i < 8; ++i) e.name += "\xe2\x82\xac";  // eight euro signs: the name column is cut inside the name
        e.data = motorun_stub(10, 10, 300);
        m.entries = {e};
        layout::Layout l = layout::moto_logo(splash::moto_build(m));
        l.add(std::string(30, 'x') + "\xe2\x82\xac" + "\xe2\x82\xac" + "\xe2\x82\xac", "", 5000, 1, 0, "n");  // (the 36th column falls inside a character)
        EXPECT(terminal_clean(layout::render(l)));
    }
    for (const std::string& name : hostile) {  // the file a part was unpacked to, which the caller that knows the manifest puts on the part
        layout::Layout l;
        l.format = "boot image";
        l.size = 4096;
        layout::Region& plain = l.add("kernel", "kernel", 0, 100, 0, "");
        plain.file = name;                    // "file <name>"
        layout::Region& packed = l.add("ramdisk", "ramdisk", 100, 100, 0, "a note");
        packed.codec = "gzip";
        packed.file = "ramdisk.cpio + " + name + "/";  // "gzip -> <the files> (N bytes, level 9)"
        packed.unpacked = 300;
        packed.level = 9;
        layout::Region& looked = l.add("second", "second", 200, 100, 0, "");
        looked.codec = name;                   // (what `info` found by looking into a stream: a name that is not one of the codecs)
        const std::string text = layout::render(l);
        EXPECT(text.find("kernel") != std::string::npos && text.find("gzip -> ") != std::string::npos);
        EXPECT(terminal_clean(text));
    }
}

// The table for a screen that is too narrow for it: nothing is lost, the offsets and the sizes stay a column, nothing is wider than the
// screen, nothing a terminal would act on comes out.
void test_text_narrow() {
    layout::Layout l;
    l.format = "boot image";
    l.size = 6ull << 30;  // (an offset that needs nine hex digits)
    l.add("header", "", 0, 4096, 0, "header version 4, 2128 bytes, page size 4096");
    layout::Region& frag = l.add("ramdisk fragment 0", "ramdisk0", 4096, 22564936, 1, "platform");
    frag.codec = "zstd";
    frag.file = "ramdisk0.cpio + ramdisk0/";
    frag.unpacked = 97479936;
    frag.level = 19;
    l.add("descriptor 0", "", 30000000, 208, 3, "hash: partition=vendor_boot algo=sha256 image_size=61710336 digest=32B; file avb_descriptor0.bin");
    l.add("a name that is much longer than the room beside the numbers of any narrow screen", "", 31000000, 1, 2, "n");
    l.add("caf\xc3\xa9 \xe2\x82\xac\xe2\x82\xac\xe2\x82\xac", "", 32000000, 9, 0, "one \xe2\x82\xac two \xe2\x82\xac three");
    l.add("padding", "", 33000000, 4294967296ull, 0, "");
    l.add("tail", "", 5000000000ull, 100, 0, "a/very/long/word/that/has/no/blanks/in/it/and/does/not/fit/on/any/line/of/a/narrow/screen.bin");
    l.add("\x1b[2Jevil\x07", "", 5000000100ull, 5, 0, "\x1b[31mred\xc2\x9b" "31m");

    const std::string wide = layout::render(l);
    EXPECT(layout::render(l, "  ", 0) == wide);  // (no screen: the table of a pipe, as it always was)
    size_t widest = 0;
    {
        std::istringstream in(wide);
        for (std::string line; std::getline(in, line);) {
            size_t n = 0;
            for (const char c : line) n += (static_cast<unsigned char>(c) & 0xc0) != 0x80;
            widest = std::max(widest, n);
        }
    }
    EXPECT(widest > 60);
    EXPECT(layout::render(l, "  ", static_cast<unsigned>(widest + 1)) == wide);  // (it fits: the same table)
    EXPECT(layout::render(l, "  ", 1000) == wide);

    const auto squeeze = [](const std::string& s) {
        std::string out;
        for (const char c : s)
            if (c != ' ' && c != '\n') out += c;
        return out;
    };
    for (const unsigned columns : {40u, 44u, 48u, 56u, 64u, 72u, 80u, 100u, 120u, 160u}) {
        const std::string text = layout::render(l, "  ", columns);
        EXPECT(terminal_clean(text));
        std::vector<std::string> lines;
        {
            std::istringstream in(text);
            for (std::string line; std::getline(in, line);) lines.push_back(line);
        }
        // not wider than the screen leaves room for (the last column is left alone), and no blank at the end of a line
        for (const std::string& line : lines) {
            size_t n = 0;
            for (const char c : line) n += (static_cast<unsigned char>(c) & 0xc0) != 0x80;
            EXPECT(n + 1 <= columns);
            EXPECT(line.empty() || line.back() != ' ');
        }
        // one line of numbers for every region, in the order of the regions: the offset, and the size in the column of sizes
        std::vector<size_t> at;
        for (size_t i = 0; i < lines.size(); ++i)
            if (lines[i].rfind("  0x", 0) == 0) at.push_back(i);
        EXPECT(at.size() == l.regions.size());
        if (at.size() != l.regions.size()) continue;
        std::string rest, expected;
        for (size_t r = 0; r < at.size(); ++r) {
            const layout::Region& reg = l.regions[r];
            char numbers[96];
            std::snprintf(numbers, sizeof numbers, "  0x%09llx  %10llu", static_cast<unsigned long long>(reg.offset),
                          static_cast<unsigned long long>(reg.size));
            EXPECT(lines[at[r]].compare(0, std::strlen(numbers), numbers) == 0);
            // nothing is lost: what follows the numbers, on that line and under it, is the name and the notes of the region, in order
            std::string tail = lines[at[r]].substr(std::min(lines[at[r]].size(), std::strlen(numbers)));
            const size_t end = r + 1 < at.size() ? at[r + 1] : lines.size();
            for (size_t k = at[r] + 1; k < end; ++k) tail += "\n" + lines[k];
            rest += squeeze(tail);
            expected += squeeze(textquote::escape_for_terminal(reg.name));
            std::string what = textquote::escape_for_terminal(reg.note);
            std::string s;
            if (!reg.file.empty()) {
                s = reg.codec.empty() ? "file " + reg.file : reg.codec + " -> " + reg.file;
                if (!reg.codec.empty()) s += " (" + std::to_string(reg.unpacked) + " bytes, level " + std::to_string(reg.level) + ")";
            }
            if (!s.empty()) what += (what.empty() ? "" : "; ") + textquote::escape_for_terminal(s);
            expected += squeeze(what);
        }
        EXPECT(rest == expected);
        if (rest != expected) std::printf("  [columns %u]\n  have %s\n  want %s\n", columns, rest.c_str(), expected.c_str());
    }
    // the first line is the heading of the three columns, and the table keeps its indent
    EXPECT(layout::render(l, "    ", 60).rfind("    offset", 0) == 0);
}

}  // namespace

int run_layout_tests() {
    test_boot();
    test_vendor_boot();
    test_dtbo();
    test_uimage_and_dtb();
    test_qcdt();
    test_aml();
    test_tree_sections();
    test_krnl();
    test_elf_boot();
    test_blob();
    test_osip();
    test_chromeos();
    test_fit();
    test_qc_splash();
    test_oplus_logo();
    test_xiaomi_logo();
    test_moto_logo();
    test_vbmeta();
    test_around();
    test_text();
    test_text_of_images();
    test_text_narrow();
    test_manifest_block();
    if (g_failures == 0) std::printf("layout: ok (%d checks)\n", g_checks);
    else std::printf("layout: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
