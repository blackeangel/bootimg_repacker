// SPDX-License-Identifier: MIT
#include "abr/vendor_boot.hpp"

#include <algorithm>

namespace abr {

std::string_view vendor_ramdisk_type_name(uint32_t type) {
    switch (type) {
        case 0: return "none";
        case 1: return "platform";
        case 2: return "recovery";
        case 3: return "dlkm";
        default: return "unknown";
    }
}

uint32_t vendor_ramdisk_type_from_name(std::string_view name) {
    if (name == "none") return 0;
    if (name == "platform") return 1;
    if (name == "recovery") return 2;
    if (name == "dlkm") return 3;
    return 0;
}

namespace {
constexpr uint32_t kHeaderSizeV3 = 2112;
constexpr uint32_t kHeaderSizeV4 = 2128;
}  // namespace

VendorBootImage VendorBootImage::parse(const Bytes& image) {
    if (!(image.size() >= kVendorBootMagicSize &&
          std::equal(kVendorBootMagic, kVendorBootMagic + kVendorBootMagicSize, image.begin())))
        throw FormatError("not a vendor_boot image (magic mismatch, expected 'VNDRBOOT')");

    BinaryReader r(image);
    r.skip(kVendorBootMagicSize);

    VendorBootImage img;
    img.header_version = r.le32();
    if (img.header_version < 3 || img.header_version > 4)
        throw FormatError("unsupported vendor_boot header version: " +
                           std::to_string(img.header_version));
    img.page_size = r.le32();
    if (img.page_size == 0) throw FormatError("vendor_boot page_size is zero");
    img.kernel_addr = r.le32();
    img.ramdisk_addr = r.le32();
    uint32_t vendor_ramdisk_size = r.le32();
    img.cmdline = r.asciiz(kVendorBootArgsSize);
    img.tags_addr = r.le32();
    img.board_name = r.asciiz(kVendorBootNameSize);
    r.le32();  // header_size, recomputed on build()
    uint32_t dtb_size = r.le32();
    img.dtb_addr = r.le64();

    uint32_t table_entry_num = 0, table_entry_size = 0, bootconfig_size = 0;
    if (img.header_version >= 4) {
        r.le32();  // vendor_ramdisk_table_size, recomputed on build()
        table_entry_num = r.le32();
        table_entry_size = r.le32();
        bootconfig_size = r.le32();
        if (table_entry_num > 0 && table_entry_size < kVendorRamdiskTableEntrySize)
            throw FormatError("vendor ramdisk table entry size too small: " +
                               std::to_string(table_entry_size));
    }

    r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
    Bytes ramdisk_section = r.bytes(vendor_ramdisk_size);
    r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
    img.dtb = r.bytes(dtb_size);
    r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));

    if (img.header_version >= 4 && table_entry_num > 0) {
        size_t table_start = r.pos();
        for (uint32_t i = 0; i < table_entry_num; ++i) {
            BinaryReader er(image);
            er.seek(table_start + static_cast<size_t>(i) * table_entry_size);
            VendorRamdiskEntry e;
            uint32_t rsize = er.le32();
            uint32_t roffset = er.le32();
            e.type = er.le32();
            e.name = er.asciiz(kVendorRamdiskNameSize);
            for (auto& b : e.board_id) b = er.le32();
            if (static_cast<uint64_t>(roffset) + rsize > ramdisk_section.size())
                throw FormatError("vendor ramdisk table entry " + std::to_string(i) +
                                   " points outside the ramdisk section");
            e.data.assign(ramdisk_section.begin() + roffset,
                           ramdisk_section.begin() + roffset + rsize);
            img.ramdisk_fragments.push_back(std::move(e));
        }
        r.seek(table_start + static_cast<size_t>(table_entry_num) * table_entry_size);
        r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
        if (bootconfig_size > 0) {
            img.bootconfig = r.bytes(bootconfig_size);
            r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
        }
    } else {
        VendorRamdiskEntry e;
        e.type = 0;
        e.data = std::move(ramdisk_section);
        img.ramdisk_fragments.push_back(std::move(e));
    }
    return img;
}

Bytes VendorBootImage::concatenated_ramdisk() const {
    Bytes out;
    size_t total = 0;
    for (auto& e : ramdisk_fragments) total += e.data.size();
    out.reserve(total);
    for (auto& e : ramdisk_fragments) out.insert(out.end(), e.data.begin(), e.data.end());
    return out;
}

Bytes VendorBootImage::build() const {
    if (header_version < 3 || header_version > 4)
        throw FormatError("unsupported vendor_boot header version: " +
                           std::to_string(header_version));
    uint32_t page_sz = page_size ? page_size : 4096;

    BinaryWriter w;
    w.bytes(reinterpret_cast<const uint8_t*>(kVendorBootMagic), kVendorBootMagicSize);
    w.le32(header_version);
    w.le32(page_sz);
    w.le32(kernel_addr);
    w.le32(ramdisk_addr);
    Bytes ramdisk_section = concatenated_ramdisk();
    w.le32(static_cast<uint32_t>(ramdisk_section.size()));
    w.asciiz(cmdline, kVendorBootArgsSize);
    w.le32(tags_addr);
    w.asciiz(board_name, kVendorBootNameSize);
    w.le32(header_version == 3 ? kHeaderSizeV3 : kHeaderSizeV4);
    w.le32(static_cast<uint32_t>(dtb.size()));
    w.le64(dtb_addr);

    if (header_version >= 4) {
        w.le32(static_cast<uint32_t>(ramdisk_fragments.size() * kVendorRamdiskTableEntrySize));
        w.le32(static_cast<uint32_t>(ramdisk_fragments.size()));
        w.le32(static_cast<uint32_t>(kVendorRamdiskTableEntrySize));
        w.le32(static_cast<uint32_t>(bootconfig.size()));
    }
    w.align(page_sz);
    w.bytes(ramdisk_section);
    w.align(page_sz);
    w.bytes(dtb);
    w.align(page_sz);

    if (header_version >= 4) {
        uint32_t running_offset = 0;
        for (auto& e : ramdisk_fragments) {
            w.le32(static_cast<uint32_t>(e.data.size()));
            w.le32(running_offset);
            w.le32(e.type);
            w.asciiz(e.name, kVendorRamdiskNameSize);
            for (auto b : e.board_id) w.le32(b);
            running_offset += static_cast<uint32_t>(e.data.size());
        }
        w.align(page_sz);
        if (!bootconfig.empty()) {
            w.bytes(bootconfig);
            w.align(page_sz);
        }
    }
    return w.take();
}

}  // namespace abr
