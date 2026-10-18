// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/sin.hpp"

#include <lz4.h>

#include <climits>
#include <cstddef>
#include <cstdio>
#include <cstring>

#include "abr/parallel.hpp"

namespace abr::legacy {

namespace {

constexpr uint64_t kMinFileSize = 1024;  // sony_dump reads the first 1024 bytes
constexpr uint64_t kMmcfHeaderSize = 8;  // "MMCF" and the length
constexpr uint64_t kGptpBlockSize = 24;
constexpr uint64_t kLz4aFields = 40;     // tag, entry size, four 64-bit words
constexpr uint64_t kAddrFields = 32;     // tag, entry size, three 64-bit words
// The decoding of LZ4 parts goes to several threads once there is this much to decode (and two parts or more).
constexpr uint64_t kParallelThreshold = 16ull << 20;

uint32_t be32(const Bytes& d, uint64_t off) {
    return (uint32_t(d[off]) << 24) | (uint32_t(d[off + 1]) << 16) | (uint32_t(d[off + 2]) << 8) | d[off + 3];
}

uint64_t be64(const Bytes& d, uint64_t off) { return (uint64_t(be32(d, off)) << 32) | be32(d, off + 4); }

bool tag_is(const Bytes& d, uint64_t off, const char* tag) { return std::memcmp(d.data() + off, tag, 4) == 0; }

std::string hex(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

[[noreturn]] void bad(const std::string& why) { throw FormatError("Sony SIN: " + why); }

// a + b, or -1 (as false) when it does not fit.
bool add(uint64_t a, uint64_t b, uint64_t& out) {
    if (a > UINT64_MAX - b) return false;
    out = a + b;
    return true;
}

}  // namespace

bool has_sin_header(const Bytes& d) {
    if (d.size() < 4) return false;
    return (d[0] == 0x01 || d[0] == 0x02) ? (d[1] == 0 && d[2] == 0 && d[3] == 0)
                                          : (d[0] == 0x03 && d[1] == 'S' && d[2] == 'I' && d[3] == 'N');
}

SinInfo parse_sin(const Bytes& d) {
    if (!has_sin_header(d)) bad("the file does not start like one (01 00 00 00, 02 00 00 00 or \"\\x03SIN\")");
    const uint64_t size = d.size();
    if (size < kMinFileSize) bad("the file is " + std::to_string(size) + " bytes, a SIN is at least 1024");

    SinInfo s;
    s.version = d[0];
    if (s.version < 3) {
        const uint64_t h = be32(d, 2);
        if (h < 1) bad("the size of the header is 0");
        if (!add(h, 16, s.header_size) || s.header_size >= size)
            bad("the header (" + std::to_string(h) + " + 16 bytes) leaves no room for data in a file of " +
                std::to_string(size) + " bytes");
        s.data_size = size - s.header_size;
    } else {
        s.header_size = be32(d, 4);
        s.data_size = be32(d, 0x18);
        if (s.header_size < 1 || s.data_size < 1) bad("the size of the header or of the data is 0");
        if (s.header_size > size)
            bad("the header is " + std::to_string(s.header_size) + " bytes, the file " + std::to_string(size));
    }
    const uint64_t at = s.header_size;  // what follows the header

    if (at + kMmcfHeaderSize <= size && tag_is(d, at, "MMCF")) {
        s.mmcf = true;
        s.gptp_len = be32(d, at + 4);
        if (s.gptp_len == 0) bad("the MMCF block is empty (no parts)");
        if (s.gptp_len < kGptpBlockSize)
            bad("the MMCF block is " + std::to_string(s.gptp_len) + " bytes, less than its 24-byte GPTP block");
        const uint64_t block = at + kMmcfHeaderSize;
        uint64_t data_base = 0;
        if (!add(block, s.gptp_len, data_base) || data_base > size)
            bad("the MMCF block (" + std::to_string(s.gptp_len) + " bytes at " + hex(block) + ") is out of the file");
        std::memcpy(s.gptp_uuid.data(), d.data() + block + 8, 16);

        const uint64_t entries = block + kGptpBlockSize;
        const uint64_t region = s.gptp_len - kGptpBlockSize;
        uint64_t end = 0;  // what the image holds so far
        for (uint64_t t = 0; t < region;) {
            const uint64_t pos = entries + t;
            const std::string which = "part " + std::to_string(s.parts.size() + 1);
            if (pos + 8 > size) bad(which + ": its entry (at " + hex(pos) + ") is cut short");
            SinPart p;
            p.entry_offset = pos;
            p.entry_size = be32(d, pos + 4);
            if (tag_is(d, pos, "LZ4A")) p.lz4 = true;
            else if (!tag_is(d, pos, "ADDR")) {
                char tag[32];
                std::snprintf(tag, sizeof tag, "%02x %02x %02x %02x", d[pos], d[pos + 1], d[pos + 2], d[pos + 3]);
                bad(which + ": unknown type " + tag + " at " + hex(pos) + " (LZ4A and ADDR are the ones there are)");
            }
            const uint64_t fields = p.lz4 ? kLz4aFields : kAddrFields;
            if (p.entry_size < fields)
                bad(which + ": its entry is " + std::to_string(p.entry_size) + " bytes, shorter than the " +
                    std::to_string(fields) + " bytes of its fields");
            if (pos + fields > size) bad(which + ": its entry (at " + hex(pos) + ") is cut short");
            p.packed_offset = be64(d, pos + 8);
            if (p.lz4) {
                p.unpacked_size = be64(d, pos + 16);
                p.packed_size = be64(d, pos + 24);
                p.unpacked_offset = be64(d, pos + 32);
            } else {
                p.packed_size = be64(d, pos + 16);
                p.unpacked_offset = be64(d, pos + 24);
            }
            uint64_t rel = 0;
            if (!add(data_base, p.packed_offset, rel) || !add(rel, p.packed_size, rel) || rel > size)
                bad(which + ": its data (" + std::to_string(p.packed_size) + " bytes at " + hex(data_base) + " + " +
                    hex(p.packed_offset) + ") is out of the file");
            p.file_offset = data_base + p.packed_offset;
            if (p.lz4) {
                if (p.packed_size < 1 || p.unpacked_size < 1) bad(which + ": an LZ4 part with no data");
                if (p.packed_size > INT_MAX || p.unpacked_size > INT_MAX)
                    bad(which + ": an LZ4 block of " + std::to_string(p.packed_size) + " bytes decoding to " +
                        std::to_string(p.unpacked_size) + " is beyond what LZ4 can hold");
            }
            if (p.unpacked_offset < end)
                s.notes.push_back(which + " starts at " + hex(p.unpacked_offset) + ", but the image is " + hex(end) +
                                  " bytes long already: it is put at the end, as sony_dump does");
            p.out_offset = p.unpacked_offset < end ? end : p.unpacked_offset;
            if (!add(p.out_offset, p.out_size(), end))
                bad(which + ": the image would be larger than 2^64 bytes");
            s.parts.push_back(p);
            t += p.entry_size;
        }
        if (s.parts.empty()) bad("the MMCF block has no parts");
        s.payload_size = end;
        if (s.payload_size == 0) bad("every part of the MMCF block is empty");
        return s;
    }

    if (at + 4 <= size && tag_is(d, at, "\x7f""ELF")) {
        // A loader: sony_dump takes the rest of the file, and wants the header's size to say it is that long.
        s.loader = true;
        if (s.header_size + s.data_size != size)
            bad("the data size (" + hex(s.data_size) + ") does not fit the file: " + hex(s.header_size) + " + " +
                hex(s.data_size) + " is not " + hex(size));
        s.payload_offset = s.header_size;
    } else if (s.header_size + s.data_size != size) {
        // Version 3 with a size that is not what is left: that many bytes in front of the image.
        if (s.header_size + s.data_size > size)
            bad("the data size (" + hex(s.data_size) + ") is more than the file holds behind the header (" +
                hex(size - s.header_size) + ")");
        s.payload_offset = s.header_size + s.data_size;
    } else {
        s.payload_offset = s.header_size;
    }
    s.payload_size = size - s.payload_offset;
    return s;
}

Bytes extract_sin(const Bytes& d, const SinInfo& s) {
    if (s.payload_size > kSinMaxPayload)
        throw FormatError("Sony SIN: the image inside is " + std::to_string(s.payload_size) +
                          " bytes, more than the " + std::to_string(kSinMaxPayload) +
                          " abr converts (this is a partition image, not a boot-family one)");
    if (!s.mmcf) {
        if (s.payload_offset > d.size() || d.size() - s.payload_offset != s.payload_size)
            throw FormatError("Sony SIN: the description does not belong to this file");
        return Bytes(d.begin() + static_cast<std::ptrdiff_t>(s.payload_offset), d.end());
    }
    Bytes out(static_cast<size_t>(s.payload_size), 0xFF);  // what no part covers stays 0xFF
    auto one = [&](size_t i) {
        const SinPart& p = s.parts[i];
        if (p.file_offset > d.size() || d.size() - p.file_offset < p.packed_size ||
            p.out_offset > out.size() || out.size() - p.out_offset < p.out_size())
            throw FormatError("Sony SIN: the description does not belong to this file");
        const uint8_t* src = d.data() + p.file_offset;
        uint8_t* dst = out.data() + p.out_offset;
        if (!p.lz4) {
            if (p.packed_size) std::memcpy(dst, src, static_cast<size_t>(p.packed_size));
            return;
        }
        const int n = LZ4_decompress_safe(reinterpret_cast<const char*>(src), reinterpret_cast<char*>(dst),
                                          static_cast<int>(p.packed_size), static_cast<int>(p.unpacked_size));
        if (n < 0)
            throw FormatError("Sony SIN: part " + std::to_string(i + 1) + ": the LZ4 block is damaged");
        if (static_cast<uint64_t>(n) != p.unpacked_size)
            throw FormatError("Sony SIN: part " + std::to_string(i + 1) + ": the LZ4 block decodes to " +
                              std::to_string(n) + " bytes, the entry says " + std::to_string(p.unpacked_size));
    };
    uint64_t lz4_bytes = 0;
    size_t lz4_parts = 0;
    for (const SinPart& p : s.parts)
        if (p.lz4) {
            lz4_bytes += p.unpacked_size;
            ++lz4_parts;
        }
    if (lz4_parts >= 2 && lz4_bytes >= kParallelThreshold) {
        par::for_each(s.parts.size(), one);
    } else {
        for (size_t i = 0; i < s.parts.size(); ++i) one(i);
    }
    return out;
}

std::string describe_sin(const SinInfo& s) {
    std::string out = "Sony SIN v" + std::to_string(s.version);
    if (s.mmcf) {
        size_t lz4 = 0;
        for (const SinPart& p : s.parts) lz4 += p.lz4;
        char uuid[40];
        std::snprintf(uuid, sizeof uuid, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      s.gptp_uuid[0], s.gptp_uuid[1], s.gptp_uuid[2], s.gptp_uuid[3], s.gptp_uuid[4], s.gptp_uuid[5],
                      s.gptp_uuid[6], s.gptp_uuid[7], s.gptp_uuid[8], s.gptp_uuid[9], s.gptp_uuid[10],
                      s.gptp_uuid[11], s.gptp_uuid[12], s.gptp_uuid[13], s.gptp_uuid[14], s.gptp_uuid[15]);
        out += ", MMCF (" + std::to_string(s.parts.size()) + (s.parts.size() == 1 ? " part: " : " parts: ") +
               std::to_string(s.parts.size() - lz4) + " ADDR, " + std::to_string(lz4) + " LZ4A; GPTP " + uuid + ")";
    } else if (s.loader) {
        out += ", a loader (ELF behind the header)";
    } else if (s.payload_offset != s.header_size) {
        out += ", " + std::to_string(s.payload_offset - s.header_size) + " bytes of data in front of the image";
    }
    out += ", header " + std::to_string(s.header_size) + " bytes, image " + std::to_string(s.payload_size) + " bytes";
    return out;
}

}  // namespace abr::legacy
