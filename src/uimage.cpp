// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/uimage.hpp"

#include <zlib.h>

#include <algorithm>
#include <vector>

namespace abr {

namespace {

struct Entry {
    uint8_t value;
    const char* name;
};

// The names are the ones that `mkimage -O help` lists, the numbers are what mkimage (u-boot-tools 2025.10) writes into the header for
// them. The first name of a value is the one that is printed.
constexpr Entry kOs[] = {
    {0, "invalid"},  {1, "openbsd"}, {2, "netbsd"},   {3, "freebsd"},  {4, "4_4bsd"},  {5, "linux"},
    {6, "svr4"},     {7, "esix"},    {8, "solaris"},  {9, "irix"},     {10, "sco"},    {11, "dell"},
    {12, "ncr"},     {14, "vxworks"}, {15, "psos"},   {16, "qnx"},     {17, "u-boot"}, {18, "rtems"},
    {21, "integrity"}, {22, "ose"},  {23, "plan9"},   {24, "openrtos"}, {25, "arm-trusted-firmware"},
    {26, "tee"},     {27, "opensbi"}, {28, "efi"},
};
constexpr Entry kArch[] = {
    {0, "invalid"}, {1, "alpha"},  {2, "arm"},     {3, "x86"},    {4, "ia64"},      {5, "mips"},   {6, "mips64"},
    {7, "powerpc"}, {8, "s390"},   {9, "sh"},      {10, "sparc"}, {11, "sparc64"},  {12, "m68k"},  {14, "microblaze"},
    {15, "nios2"},  {16, "blackfin"}, {17, "avr32"}, {19, "sandbox"}, {20, "nds32"}, {21, "or1k"},  {22, "arm64"},
    {23, "arc"},    {24, "x86_64"}, {25, "xtensa"}, {26, "riscv"},
};
// Of the types, those that mkimage writes into a legacy header (`-T flat_dt` makes a FIT, which is not this header).
constexpr Entry kType[] = {
    {0, "invalid"},    {1, "standalone"}, {2, "kernel"},        {3, "ramdisk"},       {4, "multi"},        {5, "firmware"},
    {6, "script"},     {7, "filesystem"}, {8, "flat_dt"},       {14, "kernel_noload"}, {32, "firmware_ivt"},
};
constexpr Entry kComp[] = {
    {0, "none"}, {1, "gzip"}, {2, "bzip2"}, {3, "lzma"}, {4, "lzo"}, {5, "lz4"}, {6, "zstd"},
};
// Names that an older abr wrote, or that mkimage takes for a value that the table names otherwise: read, never written.
constexpr Entry kArchOld[] = {{3, "i386"}};
constexpr Entry kTypeOld[] = {{8, "fdt_legacy"}};

template <size_t N>
const Entry* find_value(const Entry (&table)[N], uint8_t v) {
    for (const Entry& e : table)
        if (e.value == v) return &e;
    return nullptr;
}

// mkimage takes a name in any case (`-O Linux`), so does this.
bool same_name(std::string_view text, const char* name) {
    const std::string_view n(name);
    if (text.size() != n.size()) return false;
    for (size_t i = 0; i < n.size(); ++i) {
        char a = text[i];
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
        if (a != n[i]) return false;
    }
    return true;
}

template <size_t N>
const Entry* find_name(const Entry (&table)[N], std::string_view name) {
    for (const Entry& e : table)
        if (same_name(name, e.name)) return &e;
    return nullptr;
}

// The names in the order of the alphabet, as mkimage lists them.
template <size_t N>
void append_names(std::string& out, const Entry (&table)[N]) {
    std::vector<std::string_view> names;
    for (const Entry& e : table) names.emplace_back(e.name);
    std::sort(names.begin(), names.end());
    for (std::string_view n : names) {
        if (!out.empty()) out += ", ";
        out += n;
    }
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decimal digits, or 0x and hexadecimal digits, and nothing else; up to 255.
std::optional<uint8_t> small_number(std::string_view text) {
    unsigned base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    }
    if (text.empty()) return std::nullopt;
    unsigned v = 0;
    for (char c : text) {
        const int d = hex_digit(c);
        if (d < 0 || static_cast<unsigned>(d) >= base) return std::nullopt;
        v = v * base + static_cast<unsigned>(d);
        if (v > 255) return std::nullopt;
    }
    return static_cast<uint8_t>(v);
}

}  // namespace

std::string uboot_name(UbootField field, uint8_t v) {
    const Entry* e = nullptr;
    switch (field) {
        case UbootField::OS: e = find_value(kOs, v); break;
        case UbootField::ARCH: e = find_value(kArch, v); break;
        case UbootField::TYPE: e = find_value(kType, v); break;
        case UbootField::COMP: e = find_value(kComp, v); break;
    }
    return e ? std::string(e->name) : std::to_string(v);
}

std::optional<uint8_t> uboot_value(UbootField field, std::string_view text) {
    const Entry* e = nullptr;
    switch (field) {
        case UbootField::OS: e = find_name(kOs, text); break;
        case UbootField::ARCH: e = find_name(kArch, text); if (!e) e = find_name(kArchOld, text); break;
        case UbootField::TYPE: e = find_name(kType, text); if (!e) e = find_name(kTypeOld, text); break;
        case UbootField::COMP: e = find_name(kComp, text); break;
    }
    if (e) return e->value;
    return small_number(text);
}

std::string uboot_names(UbootField field) {
    std::string out;
    switch (field) {
        case UbootField::OS: append_names(out, kOs); break;
        case UbootField::ARCH: append_names(out, kArch); break;
        case UbootField::TYPE: append_names(out, kType); break;
        case UbootField::COMP: append_names(out, kComp); break;
    }
    return out;
}

const char* uboot_field_key(UbootField field) {
    switch (field) {
        case UbootField::OS: return "os";
        case UbootField::ARCH: return "arch";
        case UbootField::TYPE: return "image_type";
        case UbootField::COMP: return "compression";
    }
    return "";
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
    img.name = r.asciiz(kUimageNameSize, img.name_tail);

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

    img.consumed = kUimageHeaderSize + img.data.size();
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
    w.asciiz(name, kUimageNameSize, name_tail);
    // w now holds exactly the 64-byte header, with the crc field still zero.
    uint32_t hcrc = static_cast<uint32_t>(crc32(0, w.data().data(), static_cast<uInt>(w.data().size())));
    w.patch_be32(4, hcrc);
    Bytes out = w.take();
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

}  // namespace abr
