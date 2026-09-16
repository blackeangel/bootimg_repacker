// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::byte_io -- small binary I/O helpers used by every image parser in
// this project.
//
// Design notes
// ------------
// Every on-disk format handled by this repacker fixes its own byte order:
//   - Android boot / vendor_boot headers (bootimg.h)  -> little-endian
//   - AVB vbmeta header / footer / descriptors         -> big-endian
//   - DTBO dt_table_header / dt_table_entry            -> big-endian
//   - Flattened Device Tree (dtb) header               -> big-endian
//   - U-Boot legacy uImage header                      -> big-endian
//
// Rather than relying on struct layout + host endianness (fragile, and
// wrong on a little-endian x86/ARM host for anything AVB/DTBO/FDT/uImage
// related), every field is read/written explicitly through BinaryReader /
// BinaryWriter below. This also gives us bounds checking for free, which
// matters a lot when parsing untrusted/possibly-corrupt images.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace abr {

using Bytes = std::vector<uint8_t>;

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

class FormatError : public std::runtime_error {
public:
    explicit FormatError(const std::string& what) : std::runtime_error(what) {}
};

// ---------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------

Bytes read_file(const std::filesystem::path& path);
void write_file(const std::filesystem::path& path, const Bytes& data);
void write_file(const std::filesystem::path& path, const uint8_t* data, size_t size);

// ---------------------------------------------------------------------
// Alignment helpers
// ---------------------------------------------------------------------

constexpr uint64_t align_up(uint64_t value, uint64_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) / alignment * alignment;
}

constexpr uint64_t padding_for(uint64_t value, uint64_t alignment) {
    return align_up(value, alignment) - value;
}

// ---------------------------------------------------------------------
// BinaryReader -- bounds-checked cursor over an in-memory buffer.
// ---------------------------------------------------------------------

class BinaryReader {
public:
    BinaryReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}
    explicit BinaryReader(const Bytes& buf) : data_(buf.data()), size_(buf.size()) {}

    size_t pos() const { return pos_; }
    size_t size() const { return size_; }
    size_t remaining() const { return size_ - pos_; }
    const uint8_t* data() const { return data_; }

    void seek(size_t abs_pos) {
        if (abs_pos > size_) throw FormatError("BinaryReader: seek out of range");
        pos_ = abs_pos;
    }

    void skip(size_t n) {
        require(n);
        pos_ += n;
    }

    void require(size_t n) const {
        if (pos_ + n > size_ || pos_ + n < pos_ /* overflow */) {
            throw FormatError("unexpected end of data while parsing image (need " +
                               std::to_string(n) + " bytes at offset " + std::to_string(pos_) +
                               ", have " + std::to_string(size_) + ")");
        }
    }

    // Fixed-width little-endian reads.
    uint8_t u8() { require(1); return data_[pos_++]; }
    uint16_t le16() { return read_le<uint16_t>(); }
    uint32_t le32() { return read_le<uint32_t>(); }
    uint64_t le64() { return read_le<uint64_t>(); }

    // Fixed-width big-endian reads.
    uint16_t be16() { return read_be<uint16_t>(); }
    uint32_t be32() { return read_be<uint32_t>(); }
    uint64_t be64() { return read_be<uint64_t>(); }

    // Raw byte block; returns a copy.
    Bytes bytes(size_t n) {
        require(n);
        Bytes out(data_ + pos_, data_ + pos_ + n);
        pos_ += n;
        return out;
    }

    // Fixed-size array of raw bytes.
    template <size_t N>
    std::array<uint8_t, N> fixed_bytes() {
        require(N);
        std::array<uint8_t, N> out{};
        std::memcpy(out.data(), data_ + pos_, N);
        pos_ += N;
        return out;
    }

    // Reads exactly N bytes and returns them as a NUL-trimmed string
    // (Android headers store asciiz strings in fixed-size fields).
    std::string asciiz(size_t field_size) {
        require(field_size);
        const char* p = reinterpret_cast<const char*>(data_ + pos_);
        size_t len = 0;
        while (len < field_size && p[len] != '\0') ++len;
        std::string out(p, len);
        pos_ += field_size;
        return out;
    }

    bool starts_with(const char* magic, size_t len) const {
        if (pos_ + len > size_) return false;
        return std::memcmp(data_ + pos_, magic, len) == 0;
    }

private:
    template <typename T>
    T read_le() {
        require(sizeof(T));
        T v = 0;
        for (size_t i = 0; i < sizeof(T); ++i) v |= static_cast<T>(data_[pos_ + i]) << (8 * i);
        pos_ += sizeof(T);
        return v;
    }
    template <typename T>
    T read_be() {
        require(sizeof(T));
        T v = 0;
        for (size_t i = 0; i < sizeof(T); ++i) v = (v << 8) | data_[pos_ + i];
        pos_ += sizeof(T);
        return v;
    }

    const uint8_t* data_;
    size_t size_;
    size_t pos_ = 0;
};

// ---------------------------------------------------------------------
// BinaryWriter -- append-only byte buffer builder.
// ---------------------------------------------------------------------

class BinaryWriter {
public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void le16(uint16_t v) { write_le(v); }
    void le32(uint32_t v) { write_le(v); }
    void le64(uint64_t v) { write_le(v); }
    void be16(uint16_t v) { write_be(v); }
    void be32(uint32_t v) { write_be(v); }
    void be64(uint64_t v) { write_be(v); }

    void bytes(const uint8_t* p, size_t n) { buf_.insert(buf_.end(), p, p + n); }
    void bytes(const Bytes& b) { bytes(b.data(), b.size()); }

    // Writes `field_size` bytes total: the string content followed by
    // NUL padding, truncating if the string is too long for the field.
    void asciiz(const std::string& s, size_t field_size) {
        size_t n = std::min(s.size(), field_size);
        buf_.insert(buf_.end(), s.begin(), s.begin() + n);
        buf_.insert(buf_.end(), field_size - n, 0);
    }

    void zeros(size_t n) { buf_.insert(buf_.end(), n, 0); }

    // Pads the buffer up to the next multiple of `alignment` with zero
    // bytes. No-op if already aligned.
    void align(uint64_t alignment) {
        uint64_t pad = padding_for(buf_.size(), alignment);
        if (pad) zeros(static_cast<size_t>(pad));
    }

    size_t size() const { return buf_.size(); }
    const Bytes& data() const { return buf_; }
    Bytes&& take() { return std::move(buf_); }

    // Overwrite bytes already written (used for backpatching size/crc
    // fields once the final value is known).
    void patch_le32(size_t offset, uint32_t v) {
        for (size_t i = 0; i < 4; ++i) buf_[offset + i] = static_cast<uint8_t>(v >> (8 * i));
    }
    void patch_be32(size_t offset, uint32_t v) {
        for (size_t i = 0; i < 4; ++i) buf_[offset + i] = static_cast<uint8_t>(v >> (8 * (3 - i)));
    }

private:
    template <typename T>
    void write_le(T v) {
        for (size_t i = 0; i < sizeof(T); ++i) buf_.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }
    template <typename T>
    void write_be(T v) {
        for (size_t i = 0; i < sizeof(T); ++i)
            buf_.push_back(static_cast<uint8_t>(v >> (8 * (sizeof(T) - 1 - i))));
    }

    Bytes buf_;
};

}  // namespace abr
