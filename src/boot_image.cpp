// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/boot_image.hpp"

#include "abr/sha.hpp"

#include <algorithm>
#include <cstdio>

namespace abr {

// ------------------------------------------------------------ OsVersion --

OsVersion OsVersion::unpack(uint32_t v) {
    OsVersion o;
    o.major = (v >> 25) & 0x7f;
    o.minor = (v >> 18) & 0x7f;
    o.patch = (v >> 11) & 0x7f;
    unsigned y = (v >> 4) & 0x7f;
    o.year = y ? y + 2000 : 0;
    o.month = v & 0xf;
    return o;
}

uint32_t OsVersion::pack() const {
    unsigned y = year ? (year - 2000) : 0;
    return ((major & 0x7fu) << 25) | ((minor & 0x7fu) << 18) | ((patch & 0x7fu) << 11) |
           ((y & 0x7fu) << 4) | (month & 0xfu);
}

std::string OsVersion::to_string() const {
    if (major == 0 && minor == 0 && patch == 0) return "";
    return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
}

std::string OsVersion::patch_level_string() const {
    if (year == 0 && month == 0) return "";
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%04u-%02u", year, month);
    return buf;
}

std::optional<OsVersion> OsVersion::parse(const std::string& version,
                                           const std::string& patch_level) {
    OsVersion o;
    if (!version.empty()) {
        unsigned a = 0, b = 0, c = 0;
        if (std::sscanf(version.c_str(), "%u.%u.%u", &a, &b, &c) < 1) return std::nullopt;
        o.major = a;
        o.minor = b;
        o.patch = c;
    }
    if (!patch_level.empty()) {
        unsigned y = 0, m = 0;
        if (std::sscanf(patch_level.c_str(), "%u-%u", &y, &m) != 2) return std::nullopt;
        o.year = y;
        o.month = m;
    }
    return o;
}

// ------------------------------------------------------------ BootImage --

namespace {
constexpr uint32_t kHeaderSizeV1 = 1648;
constexpr uint32_t kHeaderSizeV2 = 1660;
constexpr uint32_t kHeaderSizeV3 = 1580;
constexpr uint32_t kHeaderSizeV4 = 1584;
}  // namespace

BootImage BootImage::parse(const Bytes& image) {
    if (!(image.size() >= kBootMagicSize &&
          std::equal(kBootMagic, kBootMagic + kBootMagicSize, image.begin())))
        throw FormatError("not a boot image (magic mismatch, expected 'ANDROID!')");

    // header_version sits at byte offset 40 in *every* header layout
    // (v0-v2 and v3-v4 both place 8 leading 4-byte fields before it).
    if (image.size() < 44) throw FormatError("boot image too small to contain a header");
    BinaryReader peek(image);
    peek.seek(40);
    uint32_t header_version = peek.le32();

    BootImage img;
    img.header_version = header_version;

    BinaryReader r(image);
    r.skip(kBootMagicSize);

    if (header_version <= 2) {
        uint32_t kernel_size = r.le32();
        img.kernel_addr = r.le32();
        uint32_t ramdisk_size = r.le32();
        img.ramdisk_addr = r.le32();
        uint32_t second_size = r.le32();
        img.second_addr = r.le32();
        img.tags_addr = r.le32();
        img.page_size = r.le32();
        r.le32();  // header_version, already known
        img.os_version = OsVersion::unpack(r.le32());
        img.board_name = r.asciiz(kBootNameSize);
        std::string part1 = r.asciiz(kBootArgsSize);
        for (auto& w : img.id) w = r.le32();
        std::string part2 = r.asciiz(kBootExtraArgsSize);
        img.cmdline = part1 + part2;

        uint32_t recovery_dtbo_size = 0;
        if (header_version >= 1) {
            recovery_dtbo_size = r.le32();
            r.le64();  // recovery_dtbo_offset -- recomputed on build(), not trusted here
            r.le32();  // header_size -- ditto
        }
        uint32_t dtb_size = 0;
        if (header_version >= 2) {
            dtb_size = r.le32();
            img.dtb_addr = static_cast<uint32_t>(r.le64());
        }

        if (img.page_size == 0) throw FormatError("boot image page_size is zero");
        r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
        img.kernel = r.bytes(kernel_size);
        r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
        img.ramdisk = r.bytes(ramdisk_size);
        r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
        img.second = r.bytes(second_size);
        r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
        if (header_version >= 1) {
            img.recovery_dtbo = r.bytes(recovery_dtbo_size);
            r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
        }
        if (header_version >= 2) {
            img.dtb = r.bytes(dtb_size);
            r.seek(static_cast<size_t>(align_up(r.pos(), img.page_size)));
        }
    } else if (header_version == 3 || header_version == 4) {
        uint32_t kernel_size = r.le32();
        uint32_t ramdisk_size = r.le32();
        img.os_version = OsVersion::unpack(r.le32());
        r.le32();       // header_size, recomputed on build()
        r.skip(4 * 4);  // reserved[4]
        r.le32();       // header_version, already known
        img.cmdline = r.asciiz(kBootArgsSize + kBootExtraArgsSize);
        uint32_t signature_size = 0;
        if (header_version == 4) signature_size = r.le32();
        img.page_size = 4096;

        r.seek(static_cast<size_t>(align_up(r.pos(), 4096)));
        img.kernel = r.bytes(kernel_size);
        r.seek(static_cast<size_t>(align_up(r.pos(), 4096)));
        img.ramdisk = r.bytes(ramdisk_size);
        r.seek(static_cast<size_t>(align_up(r.pos(), 4096)));
        if (signature_size > 0) {
            img.boot_signature = r.bytes(signature_size);
            r.seek(static_cast<size_t>(align_up(r.pos(), 4096)));
        }
    } else {
        throw FormatError("unsupported boot header version: " + std::to_string(header_version));
    }
    return img;
}

Bytes BootImage::build() const {
    BinaryWriter w;
    w.bytes(reinterpret_cast<const uint8_t*>(kBootMagic), kBootMagicSize);

    if (header_version <= 2) {
        uint32_t page_sz = page_size ? page_size : 2048;
        w.le32(static_cast<uint32_t>(kernel.size()));
        w.le32(kernel_addr);
        w.le32(static_cast<uint32_t>(ramdisk.size()));
        w.le32(ramdisk_addr);
        w.le32(static_cast<uint32_t>(second.size()));
        w.le32(second_addr);
        w.le32(tags_addr);
        w.le32(page_sz);
        w.le32(header_version);
        w.le32(os_version.pack());
        w.asciiz(board_name, kBootNameSize);
        std::string part1 = cmdline.substr(0, std::min(cmdline.size(), kBootArgsSize));
        std::string part2 =
            cmdline.size() > kBootArgsSize ? cmdline.substr(kBootArgsSize) : std::string();
        w.asciiz(part1, kBootArgsSize);
        for (auto v : id) w.le32(v);
        w.asciiz(part2, kBootExtraArgsSize);

        // recovery_dtbo_offset mirrors AOSP's get_recovery_dtbo_offset():
        // pages(header=1) + pages(kernel) + pages(ramdisk) + pages(second).
        auto pages = [&](size_t n) { return align_up(n, page_sz) / page_sz; };
        uint64_t recovery_dtbo_offset =
            page_sz * (1 + pages(kernel.size()) + pages(ramdisk.size()) + pages(second.size()));

        if (header_version >= 1) {
            w.le32(static_cast<uint32_t>(recovery_dtbo.size()));
            w.le64(recovery_dtbo.empty() ? 0 : recovery_dtbo_offset);
            w.le32(header_version == 1 ? kHeaderSizeV1 : kHeaderSizeV2);
        }
        if (header_version >= 2) {
            w.le32(static_cast<uint32_t>(dtb.size()));
            w.le64(dtb_addr);
        }
        w.align(page_sz);
        w.bytes(kernel);
        w.align(page_sz);
        w.bytes(ramdisk);
        w.align(page_sz);
        w.bytes(second);
        w.align(page_sz);
        if (header_version >= 1) {
            w.bytes(recovery_dtbo);
            w.align(page_sz);
        }
        if (header_version >= 2) {
            w.bytes(dtb);
            w.align(page_sz);
        }
    } else if (header_version == 3 || header_version == 4) {
        w.le32(static_cast<uint32_t>(kernel.size()));
        w.le32(static_cast<uint32_t>(ramdisk.size()));
        w.le32(os_version.pack());
        w.le32(header_version == 3 ? kHeaderSizeV3 : kHeaderSizeV4);
        w.zeros(4 * 4);
        w.le32(header_version);
        w.asciiz(cmdline, kBootArgsSize + kBootExtraArgsSize);
        if (header_version == 4) w.le32(static_cast<uint32_t>(boot_signature.size()));
        w.align(4096);
        w.bytes(kernel);
        w.align(4096);
        w.bytes(ramdisk);
        w.align(4096);
        if (!boot_signature.empty()) {
            w.bytes(boot_signature);
            w.align(4096);
        }
    } else {
        throw FormatError("unsupported boot header version: " + std::to_string(header_version));
    }
    return w.take();
}

void BootImage::recompute_id() {
    if (header_version > 2) {
        id.fill(0);
        return;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw FormatError("EVP_MD_CTX_new failed");
    EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
    auto feed = [&](const Bytes& data) {
        if (!data.empty()) EVP_DigestUpdate(ctx, data.data(), data.size());
        uint32_t sz = static_cast<uint32_t>(data.size());
        uint8_t le[4] = {static_cast<uint8_t>(sz), static_cast<uint8_t>(sz >> 8),
                          static_cast<uint8_t>(sz >> 16), static_cast<uint8_t>(sz >> 24)};
        EVP_DigestUpdate(ctx, le, 4);
    };
    feed(kernel);
    feed(ramdisk);
    feed(second);
    if (header_version >= 1) feed(recovery_dtbo);
    if (header_version >= 2) feed(dtb);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);
    id.fill(0);
    std::memcpy(id.data(), digest, std::min<size_t>(len, sizeof(id)));
}

}  // namespace abr
