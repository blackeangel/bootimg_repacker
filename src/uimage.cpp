// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/uimage.hpp"

#include <zlib.h>

namespace abr {

std::string_view uboot_os_name(uint8_t v) {
    switch (v) {
        case 0: return "invalid";
        case 5: return "linux";
        case 17: return "u-boot";
        default: return "unknown";
    }
}

std::string_view uboot_arch_name(uint8_t v) {
    switch (v) {
        case 0: return "invalid";
        case 2: return "arm";
        case 3: return "i386";
        case 5: return "mips";
        case 6: return "mips64";
        case 22: return "arm64";
        case 24: return "x86_64";
        case 26: return "riscv";
        default: return "unknown";
    }
}

std::string_view uboot_type_name(uint8_t v) {
    switch (v) {
        case 0: return "invalid";
        case 1: return "standalone";
        case 2: return "kernel";
        case 3: return "ramdisk";
        case 4: return "multi";
        case 5: return "firmware";
        case 6: return "script";
        case 7: return "filesystem";
        case 8: return "flat_dt";
        default: return "unknown";
    }
}

std::string_view uboot_comp_name(uint8_t v) {
    switch (v) {
        case 0: return "none";
        case 1: return "gzip";
        case 2: return "bzip2";
        case 3: return "lzma";
        case 4: return "lzo";
        case 5: return "lz4";
        case 6: return "zstd";
        default: return "unknown";
    }
}

UImage UImage::parse(const Bytes& image) {
    if (image.size() < kUimageHeaderSize) throw FormatError("u-boot image too small for a header");
    BinaryReader r(image);
    uint32_t magic = r.be32();
    if (magic != kUimageMagic)
        throw FormatError("not a u-boot legacy image (bad magic, expected 0x27051956)");
    uint32_t header_crc = r.be32();
    UImage img;
    img.timestamp = r.be32();
    uint32_t size = r.be32();
    img.load_addr = r.be32();
    img.entry_point = r.be32();
    uint32_t data_crc = r.be32();
    img.os = r.u8();
    img.arch = r.u8();
    img.type = r.u8();
    img.comp = r.u8();
    img.name = r.asciiz(kUimageNameSize);

    Bytes header_zeroed(image.begin(), image.begin() + kUimageHeaderSize);
    header_zeroed[4] = header_zeroed[5] = header_zeroed[6] = header_zeroed[7] = 0;
    uint32_t computed_header_crc = static_cast<uint32_t>(
        crc32(0, header_zeroed.data(), static_cast<uInt>(header_zeroed.size())));
    if (computed_header_crc != header_crc)
        throw FormatError("u-boot image header CRC mismatch (corrupt file, or not a real uImage)");

    if (image.size() < kUimageHeaderSize + size)
        throw FormatError("u-boot image truncated: declared data size exceeds file size");
    img.data = r.bytes(size);
    uint32_t computed_data_crc =
        static_cast<uint32_t>(crc32(0, img.data.data(), static_cast<uInt>(img.data.size())));
    if (computed_data_crc != data_crc)
        throw FormatError("u-boot image data CRC mismatch (corrupt file?)");

    return img;
}

Bytes UImage::build() const {
    BinaryWriter w;
    w.be32(kUimageMagic);
    w.be32(0);  // header_crc placeholder, patched below
    w.be32(timestamp);
    w.be32(static_cast<uint32_t>(data.size()));
    w.be32(load_addr);
    w.be32(entry_point);
    w.be32(static_cast<uint32_t>(crc32(0, data.data(), static_cast<uInt>(data.size()))));
    w.u8(os);
    w.u8(arch);
    w.u8(type);
    w.u8(comp);
    w.asciiz(name, kUimageNameSize);
    // w now holds exactly the 64-byte header, with the crc field still zero.
    uint32_t hcrc = static_cast<uint32_t>(crc32(0, w.data().data(), static_cast<uInt>(w.data().size())));
    w.patch_be32(4, hcrc);
    Bytes out = w.take();
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

}  // namespace abr
