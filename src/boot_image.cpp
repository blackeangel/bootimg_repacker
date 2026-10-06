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

const char* id_scheme_name(IdScheme s) {
    switch (s) {
        case IdScheme::SHA1: return "sha1";
        case IdScheme::SHA1_DT: return "sha1_dt";
        case IdScheme::SHA256: return "sha256";
        case IdScheme::SHA256_DT: return "sha256_dt";
        case IdScheme::RAW: return "raw";
    }
    return "raw";
}

std::optional<IdScheme> id_scheme_from_name(const std::string& name) {
    for (IdScheme s : {IdScheme::SHA1, IdScheme::SHA1_DT, IdScheme::SHA256, IdScheme::SHA256_DT,
                       IdScheme::RAW})
        if (name == id_scheme_name(s)) return s;
    return std::nullopt;
}

namespace {
constexpr uint32_t kHeaderSizeV1 = 1648;
constexpr uint32_t kHeaderSizeV2 = 1660;
constexpr uint32_t kHeaderSizeV3 = 1580;
constexpr uint32_t kHeaderSizeV4 = 1584;

// Header word 10 (byte offset 40) is `header_version` in AOSP images. The
// Qualcomm/CAF variant of the v0 header stores `dt_size` there instead;
// osm0sis' unpackbootimg treats anything above 8 as a size, so do we.
constexpr uint32_t kMaxHeaderVersionWord = 8;

uint32_t le32_at(const Bytes& b, size_t off) {
    return uint32_t(b[off]) | (uint32_t(b[off + 1]) << 8) | (uint32_t(b[off + 2]) << 16) |
           (uint32_t(b[off + 3]) << 24);
}

// A flash page size: a power of two from 2 KiB to 128 KiB (what mkbootimg's own list holds).
bool plausible_page_size(uint32_t v) { return v >= 2048 && v <= 131072 && (v & (v - 1)) == 0; }

// In a standard v0-v2 header the page size is the word at offset 36. A PXA header
// (osm0sis/pxa-mkbootimg, AIK's "AOSP-PXA") has `unknown` there -- an address such as
// 0x02000000 -- and the page size one word later. Neither v3/v4 nor the CAF flavour of v0
// can be mistaken for it: their word at 36 is zero or a real page size, their word at 40 a
// header version or a dt size that is no page size.
bool looks_like_pxa(const Bytes& image) {
    if (image.size() < 48) return false;
    return !plausible_page_size(le32_at(image, 36)) && plausible_page_size(le32_at(image, 44)) &&
           le32_at(image, 40) > kMaxHeaderVersionWord;
}

uint32_t standard_header_size(uint32_t version) {
    switch (version) {
        case 1: return kHeaderSizeV1;
        case 2: return kHeaderSizeV2;
        case 3: return kHeaderSizeV3;
        case 4: return kHeaderSizeV4;
        default: return 0;
    }
}

// Where AOSP's get_recovery_dtbo_offset() puts the recovery dtbo.
uint64_t computed_recovery_dtbo_offset(uint32_t page, size_t kernel, size_t ramdisk,
                                       size_t second) {
    auto pages = [&](size_t n) { return align_up(n, page) / page; };
    return static_cast<uint64_t>(page) * (1 + pages(kernel) + pages(ramdisk) + pages(second));
}

std::array<uint32_t, 8> id_words(const Bytes& digest) {
    std::array<uint32_t, 8> out{};
    for (size_t i = 0; i < out.size() && i * 4 < digest.size(); ++i) {
        uint32_t w = 0;
        for (size_t b = 0; b < 4 && i * 4 + b < digest.size(); ++b)
            w |= static_cast<uint32_t>(digest[i * 4 + b]) << (8 * b);
        out[i] = w;
    }
    return out;
}
}  // namespace

BootImage BootImage::parse(const Bytes& image) {
    if (!(image.size() >= kBootMagicSize &&
          std::equal(kBootMagic, kBootMagic + kBootMagicSize, image.begin())))
        throw FormatError("not a boot image (magic mismatch, expected 'ANDROID!')");

    // Word 10 sits at byte offset 40 in *every* header layout (v0-v2 and
    // v3-v4 both place 8 leading 4-byte fields before it).
    if (image.size() < 44) throw FormatError("boot image too small to contain a header");
    const bool pxa = looks_like_pxa(image);
    BinaryReader peek(image);
    peek.seek(40);
    uint32_t version_word = pxa ? 0 : peek.le32();  // (a PXA header has tags_addr there)

    BootImage img;
    uint32_t dt_size = 0;
    if (version_word > kMaxHeaderVersionWord) {
        img.header_version = 0;  // CAF v0 header: the word is a device-tree size
        dt_size = version_word;
    } else {
        img.header_version = version_word;
    }
    const uint32_t header_version = img.header_version;

    BinaryReader r(image);
    r.skip(kBootMagicSize);

    // Moves to the next page boundary, but never past the end of the file:
    // dumps whose final page padding was trimmed are common and harmless.
    auto to_page = [&](uint32_t page) {
        r.seek(static_cast<size_t>(std::min<uint64_t>(align_up(r.pos(), page), image.size())));
    };

    // Whatever sits between the end of the header struct and the end of its page is padding
    // by definition -- unless a vendor stashed something there, in which case it must survive
    // a repack.
    auto keep_header_padding = [&](size_t struct_end, uint32_t page) {
        size_t page_end =
            static_cast<size_t>(std::min<uint64_t>(align_up(struct_end, page), image.size()));
        for (size_t i = struct_end; i < page_end; ++i)
            if (image[i] != 0) {
                img.header_padding.assign(image.begin() + static_cast<long>(struct_end),
                                          image.begin() + static_cast<long>(page_end));
                break;
            }
    };

    if (pxa) {
        img.pxa = true;
        uint32_t kernel_size = r.le32();
        img.kernel_addr = r.le32();
        uint32_t ramdisk_size = r.le32();
        img.ramdisk_addr = r.le32();
        uint32_t second_size = r.le32();
        img.second_addr = r.le32();
        dt_size = r.le32();
        img.pxa_unknown = r.le32();
        img.tags_addr = r.le32();
        img.page_size = r.le32();
        img.board_name = r.asciiz(kPxaNameSize);
        std::string part1 = r.asciiz(kBootArgsSize);
        for (auto& w : img.id) w = r.le32();
        std::string part2 = r.asciiz(kBootExtraArgsSize);
        img.cmdline = part1 + part2;
        if (!part2.empty() && part1.size() != kBootArgsSize)
            img.cmdline_split = static_cast<uint32_t>(part1.size());

        keep_header_padding(r.pos(), img.page_size);
        to_page(img.page_size);
        img.kernel = r.bytes(kernel_size);
        to_page(img.page_size);
        img.ramdisk = r.bytes(ramdisk_size);
        to_page(img.page_size);
        img.second = r.bytes(second_size);
        to_page(img.page_size);
        if (dt_size) {
            img.dt = r.bytes(dt_size);
            to_page(img.page_size);
        }
        img.consumed = r.pos();
        img.id_scheme = img.detect_id_scheme();
    } else if (header_version <= 2) {
        uint32_t kernel_size = r.le32();
        img.kernel_addr = r.le32();
        uint32_t ramdisk_size = r.le32();
        img.ramdisk_addr = r.le32();
        uint32_t second_size = r.le32();
        img.second_addr = r.le32();
        img.tags_addr = r.le32();
        img.page_size = r.le32();
        r.le32();  // header_version / dt_size, already known
        img.os_version = OsVersion::unpack(r.le32());
        img.board_name = r.asciiz(kBootNameSize);
        std::string part1 = r.asciiz(kBootArgsSize);
        for (auto& w : img.id) w = r.le32();
        std::string part2 = r.asciiz(kBootExtraArgsSize);
        img.cmdline = part1 + part2;
        if (!part2.empty() && part1.size() != kBootArgsSize)
            img.cmdline_split = static_cast<uint32_t>(part1.size());

        uint32_t recovery_dtbo_size = 0;
        uint64_t recovery_dtbo_offset = 0;
        if (header_version >= 1) {
            recovery_dtbo_size = r.le32();
            recovery_dtbo_offset = r.le64();
            uint32_t hs = r.le32();
            if (hs != standard_header_size(header_version)) img.header_size_field = hs;
        }
        uint32_t dtb_size = 0;
        if (header_version >= 2) {
            dtb_size = r.le32();
            img.dtb_addr = r.le64();
        }

        if (img.page_size == 0) throw FormatError("boot image page_size is zero");

        keep_header_padding(r.pos(), img.page_size);
        to_page(img.page_size);
        img.kernel = r.bytes(kernel_size);
        to_page(img.page_size);
        img.ramdisk = r.bytes(ramdisk_size);
        to_page(img.page_size);
        img.second = r.bytes(second_size);
        to_page(img.page_size);
        if (header_version == 0 && dt_size) {
            img.dt = r.bytes(dt_size);
            to_page(img.page_size);
        }
        if (header_version >= 1) {
            img.recovery_dtbo = r.bytes(recovery_dtbo_size);
            to_page(img.page_size);
            uint64_t expected =
                recovery_dtbo_size
                    ? computed_recovery_dtbo_offset(img.page_size, kernel_size, ramdisk_size,
                                                    second_size)
                    : 0;
            if (recovery_dtbo_offset != expected) img.recovery_dtbo_offset_field = recovery_dtbo_offset;
        }
        if (header_version >= 2) {
            img.dtb = r.bytes(dtb_size);
            to_page(img.page_size);
        }
        img.consumed = r.pos();
        img.id_scheme = img.detect_id_scheme();
    } else if (header_version == 3 || header_version == 4) {
        uint32_t kernel_size = r.le32();
        uint32_t ramdisk_size = r.le32();
        img.os_version = OsVersion::unpack(r.le32());
        uint32_t hs = r.le32();
        if (hs != standard_header_size(header_version)) img.header_size_field = hs;
        for (auto& w : img.reserved) w = r.le32();
        r.le32();  // header_version, already known
        img.cmdline = r.asciiz(kBootArgsSize + kBootExtraArgsSize);
        uint32_t signature_size = 0;
        if (header_version == 4) signature_size = r.le32();
        img.page_size = 4096;

        keep_header_padding(r.pos(), 4096);
        to_page(4096);
        img.kernel = r.bytes(kernel_size);
        to_page(4096);
        img.ramdisk = r.bytes(ramdisk_size);
        to_page(4096);
        if (signature_size > 0) {
            img.boot_signature = r.bytes(signature_size);
            to_page(4096);
        }
        img.consumed = r.pos();
    } else {
        throw FormatError("unsupported boot header version: " + std::to_string(version_word));
    }

    // If the file ends inside the final page (trailing padding trimmed by
    // whoever dumped it), remember by how much, so build() can reproduce
    // the same short file rather than "fixing" it.
    {
        // `consumed` was clipped at image.size(); anything left to the next
        // page boundary was missing from the source.
        uint64_t nominal = align_up(img.consumed, img.page_size);
        if (img.consumed == image.size() && nominal > img.consumed)
            img.missing_tail_padding = nominal - img.consumed;
    }
    return img;
}

Bytes BootImage::build() const {
    BinaryWriter w;
    w.bytes(reinterpret_cast<const uint8_t*>(kBootMagic), kBootMagicSize);

    if (pxa) {
        const uint32_t page_sz = page_size ? page_size : 2048;
        w.le32(static_cast<uint32_t>(kernel.size()));
        w.le32(kernel_addr);
        w.le32(static_cast<uint32_t>(ramdisk.size()));
        w.le32(ramdisk_addr);
        w.le32(static_cast<uint32_t>(second.size()));
        w.le32(second_addr);
        w.le32(static_cast<uint32_t>(dt.size()));
        w.le32(pxa_unknown);
        w.le32(tags_addr);
        w.le32(page_sz);
        w.asciiz(board_name, kPxaNameSize);
        const size_t split = cmdline_split ? cmdline_split : kBootArgsSize;
        w.asciiz(cmdline.substr(0, std::min(cmdline.size(), split)), kBootArgsSize);
        for (auto v : id) w.le32(v);
        w.asciiz(cmdline.size() > split ? cmdline.substr(split) : std::string(), kBootExtraArgsSize);
        if (!header_padding.empty()) w.bytes(header_padding);
        w.align(page_sz);
        w.bytes(kernel);
        w.align(page_sz);
        w.bytes(ramdisk);
        w.align(page_sz);
        w.bytes(second);
        w.align(page_sz);
        if (!dt.empty()) {
            w.bytes(dt);
            w.align(page_sz);
        }
    } else if (header_version <= 2) {
        uint32_t page_sz = page_size ? page_size : 2048;
        w.le32(static_cast<uint32_t>(kernel.size()));
        w.le32(kernel_addr);
        w.le32(static_cast<uint32_t>(ramdisk.size()));
        w.le32(ramdisk_addr);
        w.le32(static_cast<uint32_t>(second.size()));
        w.le32(second_addr);
        w.le32(tags_addr);
        w.le32(page_sz);
        // Word 10: header_version, or -- CAF v0 images -- the dt size.
        w.le32((header_version == 0 && !dt.empty()) ? static_cast<uint32_t>(dt.size())
                                                   : header_version);
        w.le32(os_version.pack());
        w.asciiz(board_name, kBootNameSize);
        const size_t split = cmdline_split ? cmdline_split : kBootArgsSize;
        std::string part1 = cmdline.substr(0, std::min(cmdline.size(), split));
        std::string part2 = cmdline.size() > split ? cmdline.substr(split) : std::string();
        w.asciiz(part1, kBootArgsSize);
        for (auto v : id) w.le32(v);
        w.asciiz(part2, kBootExtraArgsSize);

        if (header_version >= 1) {
            w.le32(static_cast<uint32_t>(recovery_dtbo.size()));
            uint64_t off = recovery_dtbo_offset_field.value_or(
                recovery_dtbo.empty()
                    ? 0
                    : computed_recovery_dtbo_offset(page_sz, kernel.size(), ramdisk.size(),
                                                    second.size()));
            w.le64(off);
            w.le32(header_size_field.value_or(standard_header_size(header_version)));
        }
        if (header_version >= 2) {
            w.le32(static_cast<uint32_t>(dtb.size()));
            w.le64(dtb_addr);
        }
        if (!header_padding.empty()) w.bytes(header_padding);
        w.align(page_sz);
        w.bytes(kernel);
        w.align(page_sz);
        w.bytes(ramdisk);
        w.align(page_sz);
        w.bytes(second);
        w.align(page_sz);
        if (header_version == 0 && !dt.empty()) {
            w.bytes(dt);
            w.align(page_sz);
        }
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
        w.le32(header_size_field.value_or(standard_header_size(header_version)));
        for (auto v : reserved) w.le32(v);
        w.le32(header_version);
        w.asciiz(cmdline, kBootArgsSize + kBootExtraArgsSize);
        if (header_version == 4) w.le32(static_cast<uint32_t>(boot_signature.size()));
        if (!header_padding.empty()) w.bytes(header_padding);
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
    Bytes out = w.take();
    if (missing_tail_padding && missing_tail_padding <= out.size())
        out.resize(out.size() - static_cast<size_t>(missing_tail_padding));
    return out;
}

Bytes BootImage::compute_id(IdScheme scheme) const {
    if (scheme == IdScheme::RAW || header_version > 2) return {};
    const bool sha256 = scheme == IdScheme::SHA256 || scheme == IdScheme::SHA256_DT;
    const bool with_dt = scheme == IdScheme::SHA1_DT || scheme == IdScheme::SHA256_DT;
    auto run = [&](auto& h) {
        auto feed = [&](const Bytes& data) {
            if (!data.empty()) h.update(data.data(), data.size());
            uint32_t sz = static_cast<uint32_t>(data.size());
            uint8_t le[4] = {static_cast<uint8_t>(sz), static_cast<uint8_t>(sz >> 8),
                             static_cast<uint8_t>(sz >> 16), static_cast<uint8_t>(sz >> 24)};
            h.update(le, 4);
        };
        feed(kernel);
        feed(ramdisk);
        feed(second);
        if (header_version == 0 && with_dt) feed(dt);
        if (header_version >= 1) feed(recovery_dtbo);
        if (header_version >= 2) feed(dtb);
        return h.finish();
    };
    if (sha256) {
        hash::Sha256 h;
        return run(h);
    }
    hash::Sha1 h;
    return run(h);
}

IdScheme BootImage::detect_id_scheme() const {
    if (header_version > 2) return IdScheme::RAW;
    bool any = false;
    for (auto v : id)
        if (v) any = true;
    if (!any) return IdScheme::RAW;  // nothing to reproduce; leave it zero
    for (IdScheme s : {IdScheme::SHA1, IdScheme::SHA1_DT, IdScheme::SHA256, IdScheme::SHA256_DT}) {
        if ((s == IdScheme::SHA1_DT || s == IdScheme::SHA256_DT) && header_version != 0) continue;
        if (id_words(compute_id(s)) == id) return s;
    }
    return IdScheme::RAW;
}

void BootImage::recompute_id() {
    if (header_version > 2 || id_scheme == IdScheme::RAW) return;
    id = id_words(compute_id(id_scheme));
}

}  // namespace abr
