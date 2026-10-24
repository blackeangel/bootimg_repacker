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

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
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

// The rebuilt image is bigger than the partition it came out of. Its own kind of error because a
// denser compression of what was edited can cure it: `repack` tries that before it gives up.
class DoesNotFit : public FormatError {
public:
    using FormatError::FormatError;
};

// ---------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------

Bytes read_file(const std::filesystem::path& path);
void write_file(const std::filesystem::path& path, const Bytes& data);
void write_file(const std::filesystem::path& path, const uint8_t* data, size_t size);

// Windows only (a no-op elsewhere): put stdin/stdout/stderr in binary mode, so a line ends in LF
// as it does on every other platform instead of CRLF (the console still shows it correctly).
void set_binary_stdio();

// The command line as UTF-8 text, without the program name. On Windows the C runtime hands main() the
// version in the ANSI code page, in which whatever that code page cannot hold has become '?' (Cyrillic on a
// Western system, Chinese, emoji): this asks Windows for the wide command line and converts it, so such a
// path arrives as it is. (std::filesystem reads a narrow path as UTF-8 in the library abr is built with on
// Windows, so nothing else has to change.) Elsewhere: argv as it is.
std::vector<std::string> command_line_utf8(int argc, char** argv);

// Windows only (a no-op elsewhere, and where the output is not a console): the console shows UTF-8 -- the
// paths abr names in its messages -- for as long as this object lives, then gets its code page back. A pipe
// or a file gets the bytes as they are in any case.
class Utf8Console {
public:
    Utf8Console();
    ~Utf8Console();
    Utf8Console(const Utf8Console&) = delete;
    Utf8Console& operator=(const Utf8Console&) = delete;

private:
    unsigned saved_ = 0;  // the code page to put back; 0: nothing was changed
};

// Windows only: gives a file the System attribute, which is how Cygwin and MSYS2 mark the files that
// stand for their symbolic links. A no-op elsewhere. False when Windows refused (the file is still there).
bool mark_system_file(const std::filesystem::path& path);

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

// A flash page size as a header may give it: a power of two from 512 bytes to 16 MiB (mkbootimg's own list is 2 KiB to
// 16 KiB). Anything else is a header that is damaged -- or not a header -- and the padding of every part that is worked
// out from it would be nonsense, or gigabytes of zeros.
constexpr bool is_flash_page_size(uint64_t v) { return v >= 512 && v <= (uint64_t{16} << 20) && (v & (v - 1)) == 0; }

// A dump whose last page of padding was cut off by whoever made it: the parser records how many bytes were
// missing (`missing`) and how many of the padding the file does hold (`kept`, usually none: the file ends where
// the last component's data ends). The rebuilt image is cut the same way -- by what its own padding allows: an
// edit of the last component changes how much padding there is, and cutting by the old count would eat into
// the component itself (or leave padding that the dump did not have). `data_end` is where the content ends in
// `out`; what lies behind it is padding. Without `kept` (a manifest of an older abr) the count `missing` is the
// limit of the cut and nothing more.
inline void trim_missing_padding(Bytes& out, uint64_t missing, std::optional<uint64_t> kept, size_t data_end) {
    if (missing == 0 || data_end >= out.size()) return;
    const uint64_t room = out.size() - data_end;
    const uint64_t cut = kept ? room - std::min(*kept, room) : std::min(missing, room);
    out.resize(out.size() - static_cast<size_t>(cut));
}

// The padding that follows a component: from `end` (where its data ends) to the next multiple of `page`, but not past
// the end of `image` (a dump may lack its last bytes). Zeros are what a padding is meant to hold; when it holds
// something else -- a buffer that nobody cleared, the rest of an older image -- this returns the bytes from `end` up to
// the last one that is not zero, and an empty vector when all of it is zero. BinaryWriter::align(page, kept) puts them
// back.
inline Bytes nonzero_padding(const Bytes& image, size_t end, uint64_t page) {
    const size_t stop = static_cast<size_t>(std::min<uint64_t>(align_up(end, page), image.size()));
    size_t last = end;  // one past the last byte that is not zero
    for (size_t i = end; i < stop; ++i)
        if (image[i] != 0) last = i + 1;
    return last > end ? Bytes(image.begin() + static_cast<std::ptrdiff_t>(end),
                              image.begin() + static_cast<std::ptrdiff_t>(last))
                      : Bytes{};
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
        Bytes tail;
        return asciiz(field_size, tail);
    }

    // The same, and what the field holds behind the NUL that ends the text goes to `tail`, up to its last non-zero byte:
    // nothing in a field that a tool wrote as text and zeros, the rest of an older text in one that was cut short in place
    // (a hex editor, a tool that never clears the field). It is no part of the text, but it is part of the image.
    std::string asciiz(size_t field_size, Bytes& tail) {
        require(field_size);
        const uint8_t* p = data_ + pos_;
        size_t len = 0;
        while (len < field_size && p[len] != 0) ++len;
        tail.clear();
        if (len < field_size) {  // there is a NUL; is there anything behind it?
            size_t end = field_size;
            while (end > len + 1 && p[end - 1] == 0) --end;
            if (end > len + 1) tail.assign(p + len + 1, p + end);
        }
        std::string out(reinterpret_cast<const char*>(p), len);
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

    // The same, with `tail` behind the NUL that ends the text (BinaryReader::asciiz gives it): as much of it as the
    // field has room for -- a text that grew pushes it out, a text that shrank leaves it where it was in the image.
    void asciiz(const std::string& s, size_t field_size, const Bytes& tail) {
        asciiz(s, field_size);
        if (s.size() + 1 >= field_size) return;  // no room behind the text's NUL
        const size_t room = field_size - s.size() - 1;
        std::copy_n(tail.begin(), std::min(room, tail.size()),
                    buf_.end() - static_cast<std::ptrdiff_t>(room));
    }

    void zeros(size_t n) { buf_.insert(buf_.end(), n, 0); }

    // Pads the buffer up to the next multiple of `alignment` with zero
    // bytes. No-op if already aligned.
    void align(uint64_t alignment) {
        uint64_t pad = padding_for(buf_.size(), alignment);
        if (pad) zeros(static_cast<size_t>(pad));
    }

    // The same, with `kept` (nonzero_padding() of the source) at the start of the padding: as much of it as the padding
    // has room for -- a component that grew pushes it out, one that shrank leaves it where it was in the source.
    void align(uint64_t alignment, const Bytes& kept) {
        const size_t pad = static_cast<size_t>(padding_for(buf_.size(), alignment));
        const size_t n = std::min(pad, kept.size());
        buf_.insert(buf_.end(), kept.begin(), kept.begin() + static_cast<std::ptrdiff_t>(n));
        zeros(pad - n);
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
