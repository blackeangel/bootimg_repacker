// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/cpio.hpp"

#include <cstring>
#include <string_view>

namespace abr::cpio {

namespace {

constexpr size_t kMaxNameSize = 65536;  // far beyond any path a kernel accepts (PATH_MAX is 4096)

int hex_value(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Reads one field; `upper` and `lower` are set when it has a digit A-F / a-f.
bool read_field(const uint8_t* p, uint32_t& out, bool& upper, bool& lower) {
    uint32_t v = 0;
    for (int i = 0; i < 8; ++i) {
        const int h = hex_value(p[i]);
        if (h < 0) return false;
        if (p[i] >= 'A' && p[i] <= 'F') upper = true;
        if (p[i] >= 'a' && p[i] <= 'f') lower = true;
        v = (v << 4) | static_cast<uint32_t>(h);
    }
    out = v;
    return true;
}

void put_field(Bytes& out, uint32_t v, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    for (int shift = 28; shift >= 0; shift -= 4) out.push_back(static_cast<uint8_t>(digits[(v >> shift) & 0xF]));
}

// What the crc format keeps in a header: the byte sum for a regular file, zero for the rest
// (which is what GNU cpio writes).
uint32_t check_for(const Entry& e) { return e.type() == kRegular ? byte_sum(e.data) : 0; }

void put_record(Bytes& out, Magic magic, bool upper, const Entry& e, std::string_view name) {
    if (e.data.size() > 0xFFFFFFFFull) throw FormatError("'" + std::string(name) + "' is too large for a cpio archive");
    const char* tag = magic == Magic::CRC ? "070702" : "070701";
    out.insert(out.end(), tag, tag + 6);
    put_field(out, e.ino, upper);
    put_field(out, e.mode, upper);
    put_field(out, e.uid, upper);
    put_field(out, e.gid, upper);
    put_field(out, e.nlink, upper);
    put_field(out, e.mtime, upper);
    put_field(out, static_cast<uint32_t>(e.data.size()), upper);
    put_field(out, e.devmajor, upper);
    put_field(out, e.devminor, upper);
    put_field(out, e.rdevmajor, upper);
    put_field(out, e.rdevminor, upper);
    put_field(out, static_cast<uint32_t>(name.size() + 1), upper);
    put_field(out, magic == Magic::CRC ? check_for(e) : 0, upper);
    out.insert(out.end(), name.begin(), name.end());
    out.push_back(0);
    out.resize(out.size() + padding_for(kHeaderSize + name.size() + 1, 4), 0);
    out.insert(out.end(), e.data.begin(), e.data.end());
    out.resize(out.size() + padding_for(e.data.size(), 4), 0);
}

bool all_zero(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (p[i]) return false;
    return true;
}

}  // namespace

uint32_t byte_sum(const Bytes& data) {
    uint32_t sum = 0;
    for (uint8_t b : data) sum += b;
    return sum;
}

bool looks_like_cpio(const uint8_t* data, size_t size) {
    return size >= 6 && (std::memcmp(data, "070701", 6) == 0 || std::memcmp(data, "070702", 6) == 0);
}

bool looks_like_other_cpio(const uint8_t* data, size_t size) {
    if (size >= 6 && std::memcmp(data, "070707", 6) == 0) return true;  // odc
    return size >= 2 && ((data[0] == 0xC7 && data[1] == 0x71) || (data[0] == 0x71 && data[1] == 0xC7));  // binary
}

std::optional<Parsed> parse(const uint8_t* data, size_t size, std::string& error) {
    Parsed result;
    Archive& archive = result.archive;
    size_t pos = 0;
    bool first = true;
    bool saw_upper = false;
    bool saw_lower = false;
    for (;;) {
        if (size - pos < kHeaderSize) {
            error = "the archive is cut short at offset " + std::to_string(pos) + " (no TRAILER!!! record)";
            return std::nullopt;
        }
        Magic magic;
        if (std::memcmp(data + pos, "070701", 6) == 0) magic = Magic::NEWC;
        else if (std::memcmp(data + pos, "070702", 6) == 0) magic = Magic::CRC;
        else {
            error = "no cpio record at offset " + std::to_string(pos);
            return std::nullopt;
        }
        if (first) {
            archive.magic = magic;
            first = false;
        } else if (magic != archive.magic) {
            error = "records of the 070701 and 070702 kinds are mixed (offset " + std::to_string(pos) + ")";
            return std::nullopt;
        }
        uint32_t f[13];
        for (int i = 0; i < 13; ++i) {
            if (!read_field(data + pos + 6 + 8 * static_cast<size_t>(i), f[i], saw_upper, saw_lower)) {
                error = "a header field at offset " + std::to_string(pos) + " is not hexadecimal";
                return std::nullopt;
            }
        }
        if (saw_upper && saw_lower) {
            error = "the hexadecimal digits of the headers are upper case in some records and lower case in others (offset " +
                    std::to_string(pos) + ")";
            return std::nullopt;
        }
        Entry e;
        e.ino = f[0];
        e.mode = f[1];
        e.uid = f[2];
        e.gid = f[3];
        e.nlink = f[4];
        e.mtime = f[5];
        const size_t filesize = f[6];
        e.devmajor = f[7];
        e.devminor = f[8];
        e.rdevmajor = f[9];
        e.rdevminor = f[10];
        const size_t namesize = f[11];
        const uint32_t check = f[12];

        if (namesize == 0 || namesize > kMaxNameSize) {
            error = "the record at offset " + std::to_string(pos) + " has a name of " + std::to_string(namesize) + " bytes";
            return std::nullopt;
        }
        const size_t name_off = pos + kHeaderSize;
        const size_t data_off = pos + align_up(kHeaderSize + namesize, 4);
        if (size - name_off < namesize || data_off > size || size - data_off < filesize) {
            error = "the record at offset " + std::to_string(pos) + " runs past the end of the data";
            return std::nullopt;
        }
        if (data[name_off + namesize - 1] != 0) {
            error = "the name in the record at offset " + std::to_string(pos) + " does not end with a NUL";
            return std::nullopt;
        }
        for (size_t i = 0; i + 1 < namesize; ++i) {
            if (data[name_off + i] == 0) {
                error = "the name in the record at offset " + std::to_string(pos) + " has a NUL inside";
                return std::nullopt;
            }
        }
        if (!all_zero(data + name_off + namesize, data_off - name_off - namesize)) {
            error = "the padding after the name at offset " + std::to_string(pos) + " is not zero";
            return std::nullopt;
        }
        e.name.assign(reinterpret_cast<const char*>(data) + name_off, namesize - 1);
        e.data.assign(data + data_off, data + data_off + filesize);
        const size_t next = data_off + align_up(filesize, 4);
        if (next > size) {
            error = "the data of the record at offset " + std::to_string(pos) + " is missing its padding";
            return std::nullopt;
        }
        if (!all_zero(data + data_off + filesize, next - data_off - filesize)) {
            error = "the padding after the data at offset " + std::to_string(data_off) + " is not zero";
            return std::nullopt;
        }
        if (magic == Magic::CRC && check != check_for(e)) {
            error = "the checksum of '" + e.name + "' is wrong";
            return std::nullopt;
        }
        if (magic == Magic::NEWC && check != 0) {
            error = "'" + e.name + "' has a checksum, which the 070701 format does not use";
            return std::nullopt;
        }
        pos = next;
        if (e.name == kTrailerName) {
            if (!e.data.empty()) {
                error = "the TRAILER!!! record has data";
                return std::nullopt;
            }
            archive.trailer = std::move(e);
            archive.upper_hex = saw_upper;  // the end record's name length (0B) always has a letter in it
            result.length = pos;
            return result;
        }
        archive.entries.push_back(std::move(e));
    }
}

Bytes write(const Archive& archive) {
    size_t estimate = 2 * (kHeaderSize + 16);
    for (const Entry& e : archive.entries) estimate += kHeaderSize + e.name.size() + 8 + e.data.size();
    Bytes out;
    out.reserve(estimate);
    for (const Entry& e : archive.entries) put_record(out, archive.magic, archive.upper_hex, e, e.name);
    Entry trailer = archive.trailer;
    trailer.data.clear();
    put_record(out, archive.magic, archive.upper_hex, trailer, kTrailerName);
    return out;
}

}  // namespace abr::cpio
