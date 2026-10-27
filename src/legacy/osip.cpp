// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/osip.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "abr/compression.hpp"

namespace abr::legacy {

const uint8_t kOsipSignedMagic[8] = {0xBD, 0x02, 0xBD, 0x02, 0xBD, 0x12, 0xBD, 0x12};

namespace {

constexpr uint8_t kHeaderMagic[7] = {'$', 'O', 'S', '$', 0x00, 0x00, 0x01};
constexpr uint8_t kBootstubMagic[4] = {0xFC, 0xFA, 0xBC, 0x00};
constexpr size_t kSignatureSizes[] = {0, 480, 728, 1024};
constexpr size_t kBootstubSizes[] = {4096, 8192};

bool is_alnum(uint8_t c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

// How many of the `count` bytes at `pos` are letters or digits (mboot's check_byte; bytes past the end are not).
size_t alnum_count(const Bytes& d, size_t pos, size_t count) {
    size_t n = 0;
    for (size_t i = 0; i < count && pos + i < d.size(); ++i) n += is_alnum(d[pos + i]) ? 1 : 0;
    return n;
}

bool matches(const Bytes& d, uint64_t pos, const uint8_t* magic, size_t len) {
    return pos <= d.size() && d.size() - pos >= len && std::memcmp(d.data() + pos, magic, len) == 0;
}

uint32_t le32_at(const Bytes& d, size_t pos) {
    return uint32_t(d[pos]) | (uint32_t(d[pos + 1]) << 8) | (uint32_t(d[pos + 2]) << 16) | (uint32_t(d[pos + 3]) << 24);
}

bool has_header(const Bytes& d) { return matches(d, 0, kHeaderMagic, sizeof kHeaderMagic); }

// mboot's guess at the size of the signature: the first of 0, 480, 728 and 1024 bytes after which the cmdline
// starts, which is four letters or digits in a row (if none does, 1024).
size_t guess_signature_size(const Bytes& d, size_t header) {
    static constexpr size_t deltas[] = {0, 480, 248, 296};
    size_t pos = header;
    for (size_t delta : deltas) {
        pos += delta;
        if (alnum_count(d, pos, 4) >= 4) break;
    }
    return pos - header;
}

// ... and at the size of the bootstub: 4096, unless the two bytes where those end hold a letter or a digit.
size_t guess_bootstub_size(const Bytes& d, size_t first) {
    return alnum_count(d, first + kOsipFirstBlockSize + 4096, 2) >= 1 ? 8192 : 4096;
}

struct Layout {
    size_t signature = 0;
    size_t bootstub = 0;
    uint64_t kernel = 0;
    uint64_t ramdisk = 0;
    uint64_t end = 0;  // where the ramdisk ends
    int score = 0;     // 0: does not fit the file, 1: fits, 2: fits, has a kernel and a ramdisk, and the ramdisk starts like one
};

bool looks_like_ramdisk(const Bytes& d, uint64_t pos, uint64_t size) {
    if (size == 0) return false;
    const size_t n = static_cast<size_t>(std::min<uint64_t>(size, 64));
    const Bytes head(d.begin() + static_cast<std::ptrdiff_t>(pos), d.begin() + static_cast<std::ptrdiff_t>(pos + n));
    if (detect_codec(head) != Codec::NONE) return true;
    return n >= 5 && std::memcmp(head.data(), "07070", 5) == 0;  // a cpio archive that is not compressed
}

Layout evaluate(const Bytes& d, size_t header, size_t signature, size_t bootstub) {
    Layout l;
    l.signature = signature;
    l.bootstub = bootstub;
    const uint64_t first = uint64_t(header) + signature;  // where the cmdline starts
    if (first + kOsipFirstBlockSize > d.size()) return l;
    l.kernel = le32_at(d, static_cast<size_t>(first) + kOsipCmdlineSize);
    l.ramdisk = le32_at(d, static_cast<size_t>(first) + kOsipCmdlineSize + 4);
    l.end = first + kOsipFirstBlockSize + bootstub + l.kernel + l.ramdisk;
    if (l.end > d.size()) return l;
    l.score = l.kernel > 0 && looks_like_ramdisk(d, l.end - l.ramdisk, l.ramdisk) ? 2 : 1;
    return l;
}

}  // namespace

bool OsipImage::looks_like(const Bytes& data) {
    if (has_header(data)) return true;
    for (size_t signature : kSignatureSizes)
        if (matches(data, signature + kOsipFirstBlockSize, kBootstubMagic, sizeof kBootstubMagic)) return true;
    return false;
}

OsipImage OsipImage::parse(const Bytes& data) {
    const bool headered = has_header(data);
    const size_t header = headered ? kOsipHeaderSize : 0;
    if (data.size() < header + kOsipFirstBlockSize)
        throw FormatError("this OSIP image is cut short: " + std::to_string(data.size()) + " bytes, and the " +
                          (headered ? "512-byte header and " : "") + "4096 bytes of cmdline and image info alone need " +
                          std::to_string(header + kOsipFirstBlockSize));

    // mboot's guess first. Another layout takes its place only if that one fits the file, has a kernel and a
    // ramdisk, and the ramdisk starts like one (the sizes read at the wrong place are mostly zeros or noise, which
    // does not pass for that): a guess that fits the file but does not look quite right is kept as it is.
    const size_t guessed_signature = guess_signature_size(data, header);
    const size_t guessed_bootstub = guess_bootstub_size(data, header + guessed_signature);
    std::vector<std::pair<size_t, size_t>> candidates{{guessed_signature, guessed_bootstub},
                                                       {guessed_signature, guessed_bootstub == 4096 ? 8192u : 4096u}};
    for (size_t signature : kSignatureSizes)
        for (size_t bootstub : kBootstubSizes)
            if (std::find(candidates.begin(), candidates.end(), std::make_pair(signature, bootstub)) == candidates.end())
                candidates.emplace_back(signature, bootstub);
    Layout best = evaluate(data, header, candidates[0].first, candidates[0].second);
    for (size_t i = 1; i < candidates.size() && best.score < 2; ++i) {
        const Layout l = evaluate(data, header, candidates[i].first, candidates[i].second);
        if (l.score == 2) best = l;
    }
    if (best.score == 0) {
        const uint64_t first = uint64_t(header) + guessed_signature;
        std::string why = "the signature is taken to be " + std::to_string(guessed_signature) + " bytes and the bootstub " +
                          std::to_string(guessed_bootstub) + ", ";
        if (first + kOsipFirstBlockSize > data.size()) {
            why += "and the file ends inside the cmdline and image info";
        } else {
            const uint64_t kernel = le32_at(data, static_cast<size_t>(first) + kOsipCmdlineSize);
            const uint64_t ramdisk = le32_at(data, static_cast<size_t>(first) + kOsipCmdlineSize + 4);
            why += "the image info declares a kernel of " + std::to_string(kernel) + " bytes and a ramdisk of " +
                   std::to_string(ramdisk) + ", which need " +
                   std::to_string(first + kOsipFirstBlockSize + guessed_bootstub + kernel + ramdisk) + " bytes of the " +
                   std::to_string(data.size()) + " there are";
        }
        throw FormatError(std::string("this ") + (headered ? "" : "headerless ") +
                          "OSIP image is cut short or is not laid out the way mboot expects (a 4096-byte block of cmdline "
                          "and image info, a bootstub of 4096 or 8192 bytes, then the kernel and the ramdisk): " + why);
    }

    OsipImage img;
    BinaryReader r(data);
    if (headered) img.header = r.bytes(kOsipHeaderSize);
    img.signature = r.bytes(best.signature);
    img.cmdline = r.bytes(kOsipCmdlineSize);
    r.skip(8);  // the two sizes: they are the sizes of the kernel and the ramdisk
    img.parameter = r.fixed_bytes<8>();
    img.info_rest = r.bytes(kOsipInfoSize - kOsipInfoFixedSize);
    img.bootstub = r.bytes(best.bootstub);
    img.kernel = r.bytes(static_cast<size_t>(best.kernel));
    img.ramdisk = r.bytes(static_cast<size_t>(best.ramdisk));
    img.consumed = r.pos();
    return img;
}

size_t OsipImage::body_size() const {
    return header.size() + signature.size() + kOsipFirstBlockSize + bootstub.size() + kernel.size() + ramdisk.size();
}

Bytes OsipImage::build() const {
    if (!header.empty() && header.size() != kOsipHeaderSize)
        throw FormatError("the OSIP header is 512 bytes, not " + std::to_string(header.size()));
    // What tells the image apart once it is written: the header's magic, or -- an image of a device without a
    // header -- the bootstub where the layout puts it.
    if (!header.empty() && !has_header(header))
        throw FormatError("the OSIP header does not start with \"$OS$\" 00 00 01, which is how an OSIP image is told; "
                          "the image would not be known for one");
    if (header.empty() && !matches(bootstub, 0, kBootstubMagic, sizeof kBootstubMagic))
        throw FormatError("an OSIP image without a header is told by its bootstub, which starts with FC FA BC 00; this "
                          "one does not, so the image would not be known for an OSIP image");
    if (!signature.empty() && signature.size() != 480 && signature.size() != 728 && signature.size() != 1024)
        throw FormatError("the signature of an OSIP image is 480, 728 or 1024 bytes (mboot reads no other), not " +
                          std::to_string(signature.size()));
    if (cmdline.size() != kOsipCmdlineSize)
        throw FormatError("the cmdline block of an OSIP image is " + std::to_string(kOsipCmdlineSize) + " bytes");
    if (info_rest.size() != kOsipInfoSize - kOsipInfoFixedSize)
        throw FormatError("the image info of an OSIP image is " + std::to_string(kOsipInfoSize) + " bytes");
    if (bootstub.size() != 4096 && bootstub.size() != 8192)
        throw FormatError("the bootstub of an OSIP image is 4096 or 8192 bytes (mboot reads no other), not " +
                          std::to_string(bootstub.size()));
    if (kernel.size() > 0xFFFFFFFFull || ramdisk.size() > 0xFFFFFFFFull)
        throw FormatError("the kernel and the ramdisk of an OSIP image are less than 4 GiB each");
    BinaryWriter w;
    w.bytes(header);
    w.bytes(signature);
    w.bytes(cmdline);
    w.le32(static_cast<uint32_t>(kernel.size()));
    w.le32(static_cast<uint32_t>(ramdisk.size()));
    w.bytes(parameter.data(), parameter.size());
    w.bytes(info_rest);
    w.bytes(bootstub);
    w.bytes(kernel);
    w.bytes(ramdisk);
    return w.take();
}

std::string OsipImage::cmdline_text() const {
    size_t len = 0;
    while (len < cmdline.size() && cmdline[len] != 0) ++len;
    return std::string(reinterpret_cast<const char*>(cmdline.data()), len);
}

uint8_t osip_header_checksum(const Bytes& header) {
    uint8_t x = 0;
    for (size_t i = 0; i < kOsipChecksummedSize && i < header.size(); ++i)
        if (i != kOsipChecksumOffset) x ^= header[i];
    return x;
}

bool osip_header_checksum_ok(const Bytes& header) {
    return header.size() >= kOsipChecksummedSize && header[kOsipChecksumOffset] == osip_header_checksum(header);
}

uint32_t osip_header_sectors(const Bytes& header) {
    return header.size() >= kOsipSectorsOffset + 4 ? le32_at(header, kOsipSectorsOffset) : 0;
}

uint8_t osip_header_attribute(const Bytes& header) {
    return header.size() > kOsipAttributeOffset ? header[kOsipAttributeOffset] : 0;
}

void osip_set_header_checksum(Bytes& header) {
    if (header.size() < kOsipChecksummedSize) return;
    header[kOsipChecksumOffset] = osip_header_checksum(header);
}

void osip_refresh_header(Bytes& header, uint64_t padded_size, bool signed_image) {
    if (header.size() < kOsipChecksummedSize) return;
    const uint32_t sectors = static_cast<uint32_t>(padded_size / kOsipSectorSize) - 1;
    for (int i = 0; i < 4; ++i) header[kOsipSectorsOffset + i] = static_cast<uint8_t>(sectors >> (8 * i));
    if (!signed_image) header[kOsipAttributeOffset] |= 0x01;
    osip_set_header_checksum(header);
}

}  // namespace abr::legacy
