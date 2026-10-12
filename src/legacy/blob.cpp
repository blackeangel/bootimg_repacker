// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/blob.hpp"

#include <cstring>
#include <string>

namespace abr::legacy {

namespace {

constexpr char kSecureMagic[] = "-SIGNED-BY-SIGNBLOB-";
constexpr size_t kSecureMagicSize = 20;
constexpr char kMagic[] = "MSM-RADIO-UPDATE";
constexpr size_t kMagicSize = 16;
constexpr uint32_t kMaxParts = 4096;  // a corrupt count must not make a table of gigabytes

bool starts_with(const Bytes& d, size_t off, const char* magic, size_t len) {
    return d.size() >= off && d.size() - off >= len && std::memcmp(d.data() + off, magic, len) == 0;
}

std::string name_of(const std::array<uint8_t, 4>& n) {
    size_t len = 0;
    while (len < n.size() && n[len] != 0) ++len;
    return std::string(reinterpret_cast<const char*>(n.data()), len);
}

}  // namespace

bool BlobImage::looks_like(const Bytes& data) {
    return starts_with(data, 0, kSecureMagic, kSecureMagicSize) || starts_with(data, 0, kMagic, kMagicSize);
}

BlobImage BlobImage::parse(const Bytes& data) {
    BlobImage b;
    size_t base = 0;  // where the blob proper starts
    if (starts_with(data, 0, kSecureMagic, kSecureMagicSize)) {
        if (data.size() < kBlobSecureHeaderSize)
            throw FormatError("this SIGNBLOB file is cut short: its 28-byte secure header does not fit");
        BinaryReader r(data);
        r.seek(kSecureMagicSize);
        b.secure = true;
        b.secure_datalen = r.le32();
        b.secure_siglen = r.le32();
        base = kBlobSecureHeaderSize;
    }
    if (!starts_with(data, base, kMagic, kMagicSize))
        throw FormatError(b.secure ? "this file has the ASUS SIGNBLOB header, but no \"MSM-RADIO-UPDATE\" blob behind it"
                                   : "this file has no \"MSM-RADIO-UPDATE\" blob header");
    if (data.size() - base < kBlobHeaderSize)
        throw FormatError("this blob is cut short: its 60-byte header does not fit");

    BinaryReader r(data);
    r.seek(base + kMagicSize);
    b.version = r.le32();
    const uint32_t header_size = r.le32();
    const uint32_t part_offset = r.le32();
    const uint32_t num_parts = r.le32();
    for (uint32_t& u : b.unknown) u = r.le32();
    if (header_size != kBlobHeaderSize || part_offset != kBlobHeaderSize)
        throw FormatError("this blob declares a header of " + std::to_string(header_size) + " bytes and its table at " +
                          std::to_string(part_offset) + "; abr reads only the layout blobpack writes (60 and 60)");
    if (num_parts > kMaxParts)
        throw FormatError("this blob declares " + std::to_string(num_parts) + " partitions: not a blob");
    const uint64_t table_end = uint64_t(base) + kBlobHeaderSize + uint64_t(num_parts) * kBlobPartEntrySize;
    if (table_end > data.size())
        throw FormatError("this blob is cut short: its table of " + std::to_string(num_parts) + " partitions does not fit");

    // The partitions must follow the table, one after the other, as blobpack lays them out.
    uint64_t expected = kBlobHeaderSize + uint64_t(num_parts) * kBlobPartEntrySize;  // relative to the blob proper
    for (uint32_t i = 0; i < num_parts; ++i) {
        BlobPart part;
        r.seek(base + kBlobHeaderSize + size_t(i) * kBlobPartEntrySize);
        part.name = r.fixed_bytes<4>();
        const uint32_t offset = r.le32();
        const uint32_t size = r.le32();
        part.version = r.le32();
        const std::string label = "partition " + std::to_string(i) + " (" + name_of(part.name) + ")";
        if (offset != expected)
            throw FormatError("this blob has " + label + " at offset " + std::to_string(offset) + ", where blobpack puts it at " +
                              std::to_string(expected) + " (the partitions one after the other, right behind the table); " +
                              "a blob laid out differently is not read, so that nothing is lost");
        if (uint64_t(base) + offset + size > data.size())
            throw FormatError("this blob is cut short: " + label + " takes " + std::to_string(size) + " bytes at offset " +
                              std::to_string(offset) + ", and the file ends before");
        part.data.assign(data.begin() + static_cast<std::ptrdiff_t>(base + offset),
                         data.begin() + static_cast<std::ptrdiff_t>(base + offset + size));
        expected += size;
        b.parts.push_back(std::move(part));
    }
    b.tail.assign(data.begin() + static_cast<std::ptrdiff_t>(base + expected), data.end());
    return b;
}

size_t BlobImage::blob_size() const {
    size_t n = kBlobHeaderSize + parts.size() * kBlobPartEntrySize;
    for (const BlobPart& p : parts) n += p.data.size();
    return n;
}

Bytes BlobImage::build() const {
    for (const BlobPart& p : parts)
        if (p.data.size() > 0xFFFFFFFFu) throw FormatError("a blob partition cannot be 4 GiB or more");
    if (blob_size() > 0xFFFFFFFFu) throw FormatError("a blob cannot be 4 GiB or more");
    BinaryWriter w;
    if (secure) {
        w.bytes(reinterpret_cast<const uint8_t*>(kSecureMagic), kSecureMagicSize);
        w.le32(secure_datalen);
        w.le32(secure_siglen);
    }
    w.bytes(reinterpret_cast<const uint8_t*>(kMagic), kMagicSize);
    w.le32(version);
    w.le32(static_cast<uint32_t>(kBlobHeaderSize));
    w.le32(static_cast<uint32_t>(kBlobHeaderSize));
    w.le32(static_cast<uint32_t>(parts.size()));
    for (uint32_t u : unknown) w.le32(u);
    uint32_t offset = static_cast<uint32_t>(kBlobHeaderSize + parts.size() * kBlobPartEntrySize);
    for (const BlobPart& p : parts) {
        w.bytes(p.name.data(), p.name.size());
        w.le32(offset);
        w.le32(static_cast<uint32_t>(p.data.size()));
        w.le32(p.version);
        offset += static_cast<uint32_t>(p.data.size());
    }
    for (const BlobPart& p : parts) w.bytes(p.data);
    return w.take();
}

}  // namespace abr::legacy
