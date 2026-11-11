// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/splash.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "abr/parallel.hpp"

namespace abr::splash {

namespace {

uint32_t le32(const Bytes& d, size_t at) {
    return uint32_t{d[at]} | (uint32_t{d[at + 1]} << 8) | (uint32_t{d[at + 2]} << 16) | (uint32_t{d[at + 3]} << 24);
}

void put32(Bytes& out, size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) out[at + i] = static_cast<uint8_t>(v >> (8 * i));
}

bool all_equal(const Bytes& d, size_t from, size_t to, uint8_t value) {
    for (size_t i = from; i < to; ++i)
        if (d[i] != value) return false;
    return true;
}

// d[from, to) up to its last byte that is not zero (empty when all of it is zero).
Bytes trimmed_rest(const Bytes& d, size_t from, size_t to) {
    size_t end = to;
    while (end > from && d[end - 1] == 0) --end;
    return Bytes(d.begin() + static_cast<std::ptrdiff_t>(from), d.begin() + static_cast<std::ptrdiff_t>(end));
}

std::string hex(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

// A text field of `size` bytes at d[at]: the text up to its first zero, and what is behind that zero up to the last byte that is not zero.
std::string text_field(const Bytes& d, size_t at, size_t size, Bytes& tail) {
    BinaryReader r(d.data() + at, size);
    return r.asciiz(size, tail);
}

void put_text(Bytes& out, size_t at, size_t size, const std::string& text, const Bytes& tail) {
    BinaryWriter w;
    w.asciiz(text, size, tail);
    std::copy(w.data().begin(), w.data().end(), out.begin() + static_cast<std::ptrdiff_t>(at));
}

bool same_pixel(const uint8_t* p, size_t a, size_t b) { return p[3 * a] == p[3 * b] && p[3 * a + 1] == p[3 * b + 1] && p[3 * a + 2] == p[3 * b + 2]; }

void check_size(uint32_t width, uint32_t height, const char* what) {
    if (width == 0 || height == 0 || width > kMaxSide || height > kMaxSide || uint64_t{width} * height > kMaxPixels)
        throw FormatError(std::string(what) + ": a picture of " + std::to_string(width) + "x" + std::to_string(height) + " pixels (the sides are 1 to " + std::to_string(kMaxSide) +
                          ", and the pixels not more than " + std::to_string(kMaxPixels) + ")");
}

}  // namespace

// ------------------------------------------------------------------------------------------------------------------------- pictures --

Bitmap bitmap_from_rgba(const Bytes& rgba, uint32_t width, uint32_t height) {
    const size_t n = size_t{width} * height;
    if (rgba.size() != n * 4) throw FormatError("splash: " + std::to_string(rgba.size()) + " bytes of pixels is not " + std::to_string(width) + "x" + std::to_string(height) + " RGBA");
    Bitmap bmp;
    bmp.width = width;
    bmp.height = height;
    bmp.bgr.resize(n * 3);
    // PIL's paste of a picture on black through its alpha: BLEND(mask, 0, c) = DIV255(c * mask).
    const auto on_black = [](uint32_t c, uint32_t a) {
        const uint32_t t = c * a + 128;
        return static_cast<uint8_t>(((t >> 8) + t) >> 8);
    };
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* s = &rgba[i * 4];
        uint8_t* d = &bmp.bgr[i * 3];
        if (s[3] == 255) {
            d[0] = s[2];
            d[1] = s[1];
            d[2] = s[0];
        } else {
            d[0] = on_black(s[2], s[3]);
            d[1] = on_black(s[1], s[3]);
            d[2] = on_black(s[0], s[3]);
        }
    }
    return bmp;
}

Bytes bitmap_to_rgba(const Bitmap& bmp) {
    const size_t n = size_t{bmp.width} * bmp.height;
    if (bmp.bgr.size() != n * 3) throw FormatError("splash: " + std::to_string(bmp.bgr.size()) + " bytes of pixels is not " + std::to_string(bmp.width) + "x" + std::to_string(bmp.height));
    Bytes rgba(n * 4);
    for (size_t i = 0; i < n; ++i) {
        rgba[i * 4] = bmp.bgr[i * 3 + 2];
        rgba[i * 4 + 1] = bmp.bgr[i * 3 + 1];
        rgba[i * 4 + 2] = bmp.bgr[i * 3];
        rgba[i * 4 + 3] = 255;
    }
    return rgba;
}

// ---------------------------------------------------------------------------------------------------------------------------- RLE24 --

namespace {

// The packets of one row of `n` pixels at `p`, behind the bytes of `out`.
void rle24_row(const uint8_t* p, size_t n, Bytes& out) {
    size_t i = 0;
    while (i < n) {
        size_t run = 1;
        while (i + run < n && run < 128 && same_pixel(p, i, i + run)) ++run;
        if (run >= 2) {
            out.push_back(static_cast<uint8_t>(0x80 | (run - 1)));
            out.insert(out.end(), p + 3 * i, p + 3 * i + 3);
            i += run;
            continue;
        }
        size_t len = 1;  // the pixels up to where a run of two begins
        while (i + len < n && len < 128 && !(i + len + 1 < n && same_pixel(p, i + len, i + len + 1))) ++len;
        out.push_back(static_cast<uint8_t>(len - 1));
        out.insert(out.end(), p + 3 * i, p + 3 * (i + len));
        i += len;
    }
}

}  // namespace

Bytes rle24_encode(const Bytes& bgr, uint32_t width, uint32_t height) {
    if (bgr.size() != size_t{width} * height * 3) throw FormatError("rle24: " + std::to_string(bgr.size()) + " bytes of pixels is not " + std::to_string(width) + "x" + std::to_string(height));
    std::vector<Bytes> rows(height);
    par::for_each(height, [&](size_t y) { rle24_row(bgr.data() + y * width * 3, width, rows[y]); });
    Bytes out;
    size_t total = 0;
    for (const Bytes& r : rows) total += r.size();
    out.reserve(total);
    for (const Bytes& r : rows) out.insert(out.end(), r.begin(), r.end());
    return out;
}

Bytes rle24_decode(const uint8_t* data, size_t size, uint32_t width, uint32_t height, size_t* used) {
    const uint64_t total = uint64_t{width} * height;
    // Four bytes make at most 128 pixels: a stream that is short cannot hold a picture that big (and nothing is made ready for it).
    if (total > (uint64_t{size} / 4 + 1) * 128) throw FormatError("rle24: " + std::to_string(size) + " bytes cannot hold a picture of " + std::to_string(width) + "x" + std::to_string(height));
    Bytes out(static_cast<size_t>(total) * 3);
    size_t pos = 0;
    uint64_t px = 0;
    while (px < total) {
        if (pos >= size) throw FormatError("rle24: the stream ends after " + std::to_string(px) + " of " + std::to_string(total) + " pixels");
        const uint8_t c = data[pos++];
        const uint64_t n = (c & 0x7Fu) + 1u;
        if (px + n > total) throw FormatError("rle24: a packet of " + std::to_string(n) + " pixels at pixel " + std::to_string(px) + " goes beyond the " + std::to_string(total) + " of the picture");
        if (c & 0x80) {
            if (pos + 3 > size) throw FormatError("rle24: the stream ends in a packet");
            for (uint64_t k = 0; k < n; ++k) std::memcpy(&out[static_cast<size_t>(px + k) * 3], data + pos, 3);
            pos += 3;
        } else {
            if (pos + 3 * n > size) throw FormatError("rle24: the stream ends in a packet");
            std::memcpy(&out[static_cast<size_t>(px) * 3], data + pos, static_cast<size_t>(3 * n));
            pos += static_cast<size_t>(3 * n);
        }
        px += n;
    }
    if (used) *used = pos;
    return out;
}

// -------------------------------------------------------------------------------------------------------------------------- MotoRun --

namespace {

void moto_row(const uint8_t* p, size_t n, Bytes& out) {
    size_t i = 0;
    while (i < n) {
        size_t run = 1;
        while (i + run < n && run < 0xFFF && same_pixel(p, i, i + run)) ++run;
        if (run >= 3) {
            out.push_back(static_cast<uint8_t>(0x80 | (run >> 8)));
            out.push_back(static_cast<uint8_t>(run & 0xFF));
            out.insert(out.end(), p + 3 * i, p + 3 * i + 3);
            i += run;
            continue;
        }
        size_t len = 1;  // the pixels up to where a run of three begins
        while (i + len < n && len < 0xFFF && !(i + len + 2 < n && same_pixel(p, i + len, i + len + 1) && same_pixel(p, i + len + 1, i + len + 2))) ++len;
        out.push_back(static_cast<uint8_t>(len >> 8));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), p + 3 * i, p + 3 * (i + len));
        i += len;
    }
}

}  // namespace

std::optional<Bitmap> moto_decode(const Bytes& data) {
    static constexpr char kMagic[8] = {'M', 'o', 't', 'o', 'R', 'u', 'n', '\0'};
    if (data.size() < kMotoHeaderSize || std::memcmp(data.data(), kMagic, sizeof kMagic) != 0) return std::nullopt;
    const uint32_t width = (uint32_t{data[8]} << 8) | data[9], height = (uint32_t{data[10]} << 8) | data[11];
    if (width == 0 || height == 0 || uint64_t{width} * height > kMaxPixels) return std::nullopt;
    const uint64_t total = uint64_t{width} * height;
    // A packet of 4095 pixels is five bytes: the stream cannot make a picture that is bigger than that (nothing is made ready for it).
    if (total > (uint64_t{data.size()} / 5 + 1) * 0xFFF) return std::nullopt;
    Bitmap bmp;
    bmp.width = width;
    bmp.height = height;
    bmp.bgr.resize(static_cast<size_t>(total) * 3);
    size_t pos = kMotoHeaderSize;
    uint64_t px = 0;
    while (pos < data.size()) {
        const uint8_t first = data[pos++];
        if ((first & 0x70) != 0 || pos >= data.size()) return std::nullopt;
        const uint64_t n = (uint64_t{first & 0x0Fu} << 8) | data[pos++];
        if (px + n > total) return std::nullopt;
        if (first & 0x80) {
            if (pos + 3 > data.size()) return std::nullopt;
            for (uint64_t k = 0; k < n; ++k) std::memcpy(&bmp.bgr[static_cast<size_t>(px + k) * 3], data.data() + pos, 3);
            pos += 3;
        } else {
            if (pos + 3 * n > data.size()) return std::nullopt;
            std::memcpy(&bmp.bgr[static_cast<size_t>(px) * 3], data.data() + pos, static_cast<size_t>(3 * n));
            pos += static_cast<size_t>(3 * n);
        }
        px += n;
    }
    if (px != total) return std::nullopt;
    return bmp;
}

Bytes moto_encode(const Bitmap& bmp) {
    if (bmp.width == 0 || bmp.height == 0 || bmp.width > kMotoMaxSide || bmp.height > kMotoMaxSide)
        throw FormatError("moto: a picture of " + std::to_string(bmp.width) + "x" + std::to_string(bmp.height) + " pixels (the sides are 1 to 65535)");
    if (bmp.bgr.size() != size_t{bmp.width} * bmp.height * 3) throw FormatError("moto: " + std::to_string(bmp.bgr.size()) + " bytes of pixels is not " + std::to_string(bmp.width) + "x" + std::to_string(bmp.height));
    std::vector<Bytes> rows(bmp.height);
    par::for_each(bmp.height, [&](size_t y) { moto_row(bmp.bgr.data() + y * bmp.width * 3, bmp.width, rows[y]); });
    Bytes out = {'M', 'o', 't', 'o', 'R', 'u', 'n', 0, static_cast<uint8_t>(bmp.width >> 8), static_cast<uint8_t>(bmp.width), static_cast<uint8_t>(bmp.height >> 8), static_cast<uint8_t>(bmp.height)};
    for (const Bytes& r : rows) out.insert(out.end(), r.begin(), r.end());
    return out;
}

// -------------------------------------------------------------------------------------------------------- Qualcomm's "SPLASH!!" --

namespace {

// The fields of a header of either form, and what is wrong with them where they are not one. The data is not looked at.
struct QcFields {
    bool several = false;
    std::vector<QcPicture> pictures;
    std::string why;  // empty when the header is one
};

QcFields qc_read_fields(const Bytes& d) {
    QcFields f;
    if (d.size() < kQcHeaderSize || std::memcmp(d.data(), kQcMagic, sizeof kQcMagic) != 0) {
        f.why = "no \"SPLASH!!\" and 512 bytes of header";
        return f;
    }
    // (the one picture of the single form may say 0 blocks, as the images of Qualcomm's own do: the picture then tells how long its data is)
    const auto picture_problem = [&](const QcPicture& p, const std::string& who, bool zero_blocks_ok) -> std::string {
        if (p.width == 0 || p.height == 0 || p.width > kMaxSide || p.height > kMaxSide || uint64_t{p.width} * p.height > kMaxPixels)
            return who + " is " + std::to_string(p.width) + "x" + std::to_string(p.height) + " pixels (the sides are 1 to " + std::to_string(kMaxSide) + ")";
        if (p.type > kQcRle24) return who + " has the type " + std::to_string(p.type) + "; abr knows 0 (pixels) and 1 (RLE24)";
        if (p.blocks == 0 && !zero_blocks_ok) return who + " has no blocks";
        return {};
    };

    // The several-pictures form: the second word is a small count, and the table that follows adds up.
    const uint32_t count = le32(d, 8);
    std::string several_why;
    if (count >= 1 && count <= kQcMaxPictures) {
        std::vector<QcPicture> list;
        uint64_t expected = kQcHeaderSize;
        for (uint32_t i = 0; i < count && several_why.empty(); ++i) {
            const size_t at = 12 + size_t{i} * 20;
            QcPicture p;
            p.width = le32(d, at);
            p.height = le32(d, at + 4);
            p.type = le32(d, at + 8);
            p.blocks = le32(d, at + 12);
            p.offset = le32(d, at + 16);
            const std::string who = "picture " + std::to_string(i);
            several_why = picture_problem(p, who, false);
            if (several_why.empty() && p.offset != expected)
                several_why = who + " is at " + hex(p.offset) + ", not right behind the one before it (" + hex(expected) + ")";
            if (several_why.empty() && p.offset >= d.size()) several_why = who + " begins at " + hex(p.offset) + ", past the end of the file";
            expected += uint64_t{p.blocks} * kQcBlock;
            if (several_why.empty() && i + 1 < count && expected > d.size()) several_why = who + " is cut short: the file ends at " + hex(d.size()) + ", its blocks end at " + hex(expected);
            list.push_back(p);
        }
        if (several_why.empty()) {
            f.several = true;
            f.pictures = std::move(list);
            return f;
        }
    } else {
        several_why = "the count " + std::to_string(count) + " is not 1 to " + std::to_string(kQcMaxPictures);
    }

    // The single picture.
    QcPicture p;
    p.width = le32(d, 8);
    p.height = le32(d, 12);
    p.type = le32(d, 16);
    p.blocks = le32(d, 20);
    p.offset = static_cast<uint32_t>(kQcHeaderSize);
    if (const std::string why = picture_problem(p, "the picture", true); !why.empty()) {
        // A count that could be one makes the table a reading worth naming.
        f.why = count >= 1 && count <= kQcMaxPictures ? "as a table of " + std::to_string(count) + " pictures: " + several_why + "; as a single picture: " + why : why;
        return f;
    }
    if (d.size() <= kQcHeaderSize) {
        f.why = "the file ends with the header: there is no data";
        return f;
    }
    f.pictures.push_back(p);
    return f;
}

}  // namespace

bool qc_looks_like(const Bytes& d) { return qc_read_fields(d).why.empty(); }

std::string qc_problem(const Bytes& d) {
    try {
        (void)qc_parse(d);
    } catch (const FormatError& e) {
        return e.what();
    }
    return {};
}

QcSplash qc_parse(const Bytes& d) {
    QcFields f = qc_read_fields(d);
    if (!f.why.empty()) throw FormatError("splash: " + f.why);
    QcSplash s;
    s.several = f.several;
    s.pictures = std::move(f.pictures);
    const size_t fields_end = s.several ? 12 + s.pictures.size() * 20 : 24;
    s.header_rest = trimmed_rest(d, fields_end, kQcHeaderSize);
    for (size_t i = 0; i < s.pictures.size(); ++i) {
        QcPicture& p = s.pictures[i];
        const std::string who = s.several ? "picture " + std::to_string(i) : "the picture";
        // The blocks of the header give the extent of the data (the file may end before them). A picture that says 0 blocks -- the images that Qualcomm's own tool
        // makes of pixels do -- has the data its pixels take, or the packets that make it.
        uint64_t end = p.blocks ? std::min<uint64_t>(d.size(), uint64_t{p.offset} + uint64_t{p.blocks} * kQcBlock) : d.size();
        if (p.type == kQcRaw) {
            p.stream = size_t{p.width} * p.height * 3;
            if (end - p.offset < p.stream)
                throw FormatError("splash: " + who + " is cut short: its " + std::to_string(p.width) + "x" + std::to_string(p.height) + " pixels are " + std::to_string(p.stream) +
                                  " bytes, the file holds " + std::to_string(end - p.offset) + " from its start");
            if (!p.blocks) end = p.offset + p.stream;
        } else {
            try {
                (void)rle24_decode(d.data() + p.offset, static_cast<size_t>(end - p.offset), p.width, p.height, &p.stream);
            } catch (const FormatError& e) {
                throw FormatError("splash: " + who + ": " + e.what());
            }
            if (!p.blocks) end = p.offset + p.stream;
        }
        p.data.assign(d.begin() + p.offset, d.begin() + static_cast<std::ptrdiff_t>(end));
        s.consumed = static_cast<size_t>(end);
    }
    return s;
}

Bitmap qc_decode(const QcPicture& p) {
    Bitmap bmp;
    bmp.width = p.width;
    bmp.height = p.height;
    check_size(p.width, p.height, "splash");
    if (p.type == kQcRaw) {
        const size_t n = size_t{p.width} * p.height * 3;
        if (p.data.size() < n) throw FormatError("splash: the data of the picture is " + std::to_string(p.data.size()) + " bytes, " + std::to_string(n) + " are its pixels");
        bmp.bgr.assign(p.data.begin(), p.data.begin() + static_cast<std::ptrdiff_t>(n));
    } else if (p.type == kQcRle24) {
        bmp.bgr = rle24_decode(p.data.data(), p.data.size(), p.width, p.height);
    } else {
        throw FormatError("splash: the type " + std::to_string(p.type) + " is none that abr knows (0 pixels, 1 RLE24)");
    }
    return bmp;
}

Bytes qc_encode(const Bitmap& bmp, uint32_t type) {
    check_size(bmp.width, bmp.height, "splash");
    if (type == kQcRaw) {
        if (bmp.bgr.size() != size_t{bmp.width} * bmp.height * 3) throw FormatError("splash: the pixels are " + std::to_string(bmp.bgr.size()) + " bytes, not " + std::to_string(bmp.width) + "x" + std::to_string(bmp.height) + "x3");
        return bmp.bgr;
    }
    if (type == kQcRle24) return rle24_encode(bmp.bgr, bmp.width, bmp.height);
    throw FormatError("splash: the type " + std::to_string(type) + " is none that abr knows (0 pixels, 1 RLE24)");
}

uint32_t qc_blocks(uint64_t size) { return static_cast<uint32_t>((size + kQcBlock - 1) / kQcBlock); }

std::string qc_type_name(uint32_t type) { return type == kQcRaw ? "pixels" : type == kQcRle24 ? "RLE24" : "type " + std::to_string(type); }

Bytes qc_build(const QcSplash& s) {
    if (s.pictures.empty()) throw FormatError("splash: no pictures");
    if (s.several ? s.pictures.size() > kQcMaxPictures : s.pictures.size() != 1)
        throw FormatError("splash: " + std::to_string(s.pictures.size()) + " pictures (the header holds " + (s.several ? "1 to " + std::to_string(kQcMaxPictures) : std::string("one")) + ")");
    Bytes out(kQcHeaderSize, 0);
    std::memcpy(out.data(), kQcMagic, sizeof kQcMagic);
    const size_t fields_end = s.several ? 12 + s.pictures.size() * 20 : 24;
    if (fields_end + s.header_rest.size() > kQcHeaderSize) throw FormatError("splash: the bytes that follow the fields of the header do not fit in the 512 bytes of it");
    std::copy(s.header_rest.begin(), s.header_rest.end(), out.begin() + static_cast<std::ptrdiff_t>(fields_end));
    uint64_t offset = kQcHeaderSize;
    if (s.several) put32(out, 8, static_cast<uint32_t>(s.pictures.size()));
    for (size_t i = 0; i < s.pictures.size(); ++i) {
        const QcPicture& p = s.pictures[i];
        if (s.several && p.blocks == 0) throw FormatError("splash: picture " + std::to_string(i) + " has no blocks (only the single picture may say 0: its data is the pixels or the packets)");
        if (s.several && i + 1 < s.pictures.size() && p.data.size() != size_t{p.blocks} * kQcBlock)
            throw FormatError("splash: the data of picture " + std::to_string(i) + " is " + std::to_string(p.data.size()) + " bytes, its " + std::to_string(p.blocks) +
                              " blocks are " + std::to_string(size_t{p.blocks} * kQcBlock) + " (the next picture follows at once)");
        if (s.several) {
            const size_t at = 12 + i * 20;
            put32(out, at, p.width);
            put32(out, at + 4, p.height);
            put32(out, at + 8, p.type);
            put32(out, at + 12, p.blocks);
            put32(out, at + 16, static_cast<uint32_t>(offset));
        } else {
            put32(out, 8, p.width);
            put32(out, 12, p.height);
            put32(out, 16, p.type);
            put32(out, 20, p.blocks);
        }
        offset += p.data.size();
        if (offset > 0xFFFFFFFFull) throw FormatError("splash: the image is bigger than the 4 GiB an offset can name");
    }
    out.reserve(static_cast<size_t>(offset));
    for (const QcPicture& p : s.pictures) out.insert(out.end(), p.data.begin(), p.data.end());
    return out;
}

// ------------------------------------------------------------------------------------------------------------- the OPLUS image --

namespace {

constexpr size_t kOplusCountAt = 12 + 4 * kOplusDescSize;  // 268

struct OplusSlot {
    uint32_t offset = 0, plain = 0, stored = 0;
};

// The reason the bytes are no image of this kind; empty when they are. `slots` (when given) are the entries of the table.
std::string oplus_check(const Bytes& d, std::vector<OplusSlot>* slots) {
    if (d.size() < kOplusDataAt) return "the file is " + std::to_string(d.size()) + " bytes; the pictures begin at " + hex(kOplusDataAt);
    if (std::memcmp(d.data() + kOplusPreamble, kOplusMagic, sizeof kOplusMagic) != 0) return "no \"SPLASH LOGO!\" at " + hex(kOplusPreamble);
    const size_t base = kOplusPreamble;
    const uint32_t count = le32(d, base + kOplusCountAt);
    if (count == 0 || count > kOplusMaxEntries) return "the table holds " + std::to_string(count) + " pictures (1 to " + std::to_string(kOplusMaxEntries) + " fit in the header)";
    uint64_t running = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const size_t at = base + kOplusTableAt + size_t{i} * kOplusEntrySize;
        OplusSlot s;
        s.offset = le32(d, at);
        s.plain = le32(d, at + 4);
        s.stored = le32(d, at + 8);
        if (s.offset != running)
            return "picture " + std::to_string(i) + " is at " + hex(kOplusDataAt + s.offset) + ", not right behind the one before it (" + hex(kOplusDataAt + running) + ")";
        running += s.stored;
        if (kOplusDataAt + running > d.size())
            return "picture " + std::to_string(i) + " is cut short: it ends at " + hex(kOplusDataAt + running) + ", the file at " + hex(d.size());
        if (slots) slots->push_back(s);
    }
    return {};
}

}  // namespace

bool oplus_looks_like(const Bytes& d) { return oplus_check(d, nullptr).empty(); }

std::string oplus_problem(const Bytes& d) { return oplus_check(d, nullptr); }

OplusLogo oplus_parse(const Bytes& d) {
    std::vector<OplusSlot> slots;
    if (const std::string why = oplus_check(d, &slots); !why.empty()) throw FormatError("splash: " + why);
    OplusLogo l;
    const size_t base = kOplusPreamble;
    l.preamble.assign(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(kOplusPreamble));
    for (size_t i = 0; i < 4; ++i) l.desc[i] = text_field(d, base + 12 + i * kOplusDescSize, kOplusDescSize, l.desc_tail[i]);
    l.version = le32(d, base + kOplusCountAt + 4);
    l.width = le32(d, base + kOplusCountAt + 8);
    l.height = le32(d, base + kOplusCountAt + 12);
    l.compression = le32(d, base + kOplusCountAt + 16);
    for (size_t i = 0; i < slots.size(); ++i) {
        OplusEntry e;
        const size_t at = base + kOplusTableAt + i * kOplusEntrySize;
        e.name = text_field(d, at + 12, kOplusNameSize, e.name_tail);
        e.plain_size = slots[i].plain;
        const size_t from = kOplusDataAt + slots[i].offset;
        e.data.assign(d.begin() + static_cast<std::ptrdiff_t>(from), d.begin() + static_cast<std::ptrdiff_t>(from + slots[i].stored));
        l.consumed = from + slots[i].stored;
        l.entries.push_back(std::move(e));
    }
    l.header_rest = trimmed_rest(d, base + kOplusTableAt + slots.size() * kOplusEntrySize, base + kOplusHeaderSize);
    return l;
}

Bytes oplus_build(const OplusLogo& l) {
    if (l.entries.empty() || l.entries.size() > kOplusMaxEntries)
        throw FormatError("splash: " + std::to_string(l.entries.size()) + " pictures (the header holds 1 to " + std::to_string(kOplusMaxEntries) + ")");
    Bytes out(kOplusDataAt, 0);
    if (l.preamble.size() > kOplusPreamble) throw FormatError("splash: the bytes in front of the header are " + std::to_string(l.preamble.size()) + "; they are " + std::to_string(kOplusPreamble));
    std::copy(l.preamble.begin(), l.preamble.end(), out.begin());
    const size_t base = kOplusPreamble;
    std::memcpy(out.data() + base, kOplusMagic, sizeof kOplusMagic);
    for (size_t i = 0; i < 4; ++i) put_text(out, base + 12 + i * kOplusDescSize, kOplusDescSize, l.desc[i], l.desc_tail[i]);
    put32(out, base + kOplusCountAt, static_cast<uint32_t>(l.entries.size()));
    put32(out, base + kOplusCountAt + 4, l.version);
    put32(out, base + kOplusCountAt + 8, l.width);
    put32(out, base + kOplusCountAt + 12, l.height);
    put32(out, base + kOplusCountAt + 16, l.compression);
    const size_t table_end = base + kOplusTableAt + l.entries.size() * kOplusEntrySize;
    if (table_end + l.header_rest.size() > base + kOplusHeaderSize) throw FormatError("splash: the bytes behind the table do not fit in the header");
    std::copy(l.header_rest.begin(), l.header_rest.end(), out.begin() + static_cast<std::ptrdiff_t>(table_end));
    uint64_t offset = 0;
    for (size_t i = 0; i < l.entries.size(); ++i) {
        const OplusEntry& e = l.entries[i];
        const size_t at = base + kOplusTableAt + i * kOplusEntrySize;
        put32(out, at, static_cast<uint32_t>(offset));
        put32(out, at + 4, e.plain_size);
        put32(out, at + 8, static_cast<uint32_t>(e.data.size()));
        put_text(out, at + 12, kOplusNameSize, e.name, e.name_tail);
        offset += e.data.size();
        if (offset > 0xFFFFFFFFull - kOplusDataAt) throw FormatError("splash: the pictures are more than an offset can name");
    }
    out.reserve(kOplusDataAt + static_cast<size_t>(offset));
    for (const OplusEntry& e : l.entries) out.insert(out.end(), e.data.begin(), e.data.end());
    return out;
}

// ------------------------------------------------------------------------------------------------------------ the Xiaomi image --

namespace {

struct XiaomiSlot {
    uint32_t offset = 0, size = 0;  // in units
};

std::string xiaomi_check(const Bytes& d, std::vector<XiaomiSlot>* slots) {
    if (d.size() < kXiaomiPreamble + kXiaomiTableSize) return "the file is " + std::to_string(d.size()) + " bytes; the table ends at " + hex(kXiaomiPreamble + kXiaomiTableSize);
    if (std::memcmp(d.data() + kXiaomiPreamble, kXiaomiMagic, sizeof kXiaomiMagic) != 0) return "no \"LOGO!!!!\" at " + hex(kXiaomiPreamble);
    uint64_t expected = (kXiaomiPreamble + kXiaomiTableSize) / kXiaomiUnit;
    uint32_t n = 0;
    for (; n < kXiaomiMaxEntries; ++n) {
        const size_t at = kXiaomiPreamble + 8 + size_t{n} * 8;
        XiaomiSlot s;
        s.offset = le32(d, at);
        s.size = le32(d, at + 4);
        if (s.offset == 0) break;  // the end of the list (what the tool of the image does)
        const std::string who = "picture " + std::to_string(n);
        if (s.offset != expected) return who + " is at unit " + std::to_string(s.offset) + " (" + hex(uint64_t{s.offset} * kXiaomiUnit) + "), not right behind the one before it (unit " + std::to_string(expected) + ")";
        if ((uint64_t{s.offset} + s.size) * kXiaomiUnit > d.size())
            return who + " is cut short: it ends at " + hex((uint64_t{s.offset} + s.size) * kXiaomiUnit) + ", the file at " + hex(d.size());
        expected += s.size;
        if (slots) slots->push_back(s);
    }
    if (n == 0) return "the table holds no picture";
    return {};
}

}  // namespace

bool xiaomi_looks_like(const Bytes& d) { return xiaomi_check(d, nullptr).empty(); }

std::string xiaomi_problem(const Bytes& d) { return xiaomi_check(d, nullptr); }

XiaomiLogo xiaomi_parse(const Bytes& d) {
    std::vector<XiaomiSlot> slots;
    if (const std::string why = xiaomi_check(d, &slots); !why.empty()) throw FormatError("splash: " + why);
    XiaomiLogo l;
    l.preamble.assign(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(kXiaomiPreamble));
    for (const XiaomiSlot& s : slots) {
        const size_t from = size_t{s.offset} * kXiaomiUnit, to = (size_t{s.offset} + s.size) * kXiaomiUnit;
        l.pictures.emplace_back(d.begin() + static_cast<std::ptrdiff_t>(from), d.begin() + static_cast<std::ptrdiff_t>(to));
        l.consumed = to;
    }
    l.table_rest = trimmed_rest(d, kXiaomiPreamble + 8 + slots.size() * 8, kXiaomiPreamble + kXiaomiTableSize);
    return l;
}

Bytes xiaomi_build(const XiaomiLogo& l) {
    if (l.pictures.empty() || l.pictures.size() > kXiaomiMaxEntries)
        throw FormatError("splash: " + std::to_string(l.pictures.size()) + " pictures (the table holds 1 to " + std::to_string(kXiaomiMaxEntries) + ")");
    if (l.preamble.size() > kXiaomiPreamble) throw FormatError("splash: the bytes in front of the table are " + std::to_string(l.preamble.size()) + "; they are " + std::to_string(kXiaomiPreamble));
    const size_t table_end = 8 + l.pictures.size() * 8;
    if (table_end + l.table_rest.size() > kXiaomiTableSize) throw FormatError("splash: the bytes behind the entries do not fit in the table");
    Bytes out(kXiaomiPreamble + kXiaomiTableSize, 0);
    std::copy(l.preamble.begin(), l.preamble.end(), out.begin());
    std::memcpy(out.data() + kXiaomiPreamble, kXiaomiMagic, sizeof kXiaomiMagic);
    std::copy(l.table_rest.begin(), l.table_rest.end(), out.begin() + static_cast<std::ptrdiff_t>(kXiaomiPreamble + table_end));
    uint64_t unit = out.size() / kXiaomiUnit;
    for (size_t i = 0; i < l.pictures.size(); ++i) {
        const uint64_t units = (l.pictures[i].size() + kXiaomiUnit - 1) / kXiaomiUnit;
        if (unit + units > 0xFFFFFFFFull) throw FormatError("splash: the pictures are more than an offset can name");
        put32(out, kXiaomiPreamble + 8 + i * 8, static_cast<uint32_t>(unit));
        put32(out, kXiaomiPreamble + 8 + i * 8 + 4, static_cast<uint32_t>(units));
        unit += units;
    }
    out.reserve(static_cast<size_t>(unit) * kXiaomiUnit);
    for (const Bytes& p : l.pictures) {
        out.insert(out.end(), p.begin(), p.end());
        out.resize(static_cast<size_t>(align_up(out.size(), kXiaomiUnit)), 0);
    }
    return out;
}

size_t xiaomi_content_size(const Bytes& data) {
    const size_t full = data.size();
    const auto rest_is_zero = [&](size_t from) { return from <= full && all_equal(data, from, full, 0); };
    if (full >= 14 && data[0] == 'B' && data[1] == 'M') {
        const size_t size = le32(data, 2);
        if (size >= 14 && size <= full && rest_is_zero(size)) return size;
        return full;
    }
    static constexpr uint8_t kPng[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    if (full >= 8 && std::memcmp(data.data(), kPng, 8) == 0) {
        size_t pos = 8;
        while (pos + 12 <= full) {
            const uint64_t len = (uint64_t{data[pos]} << 24) | (uint64_t{data[pos + 1]} << 16) | (uint64_t{data[pos + 2]} << 8) | data[pos + 3];
            const uint64_t next = pos + 12 + len;
            if (next > full) return full;
            if (std::memcmp(data.data() + pos + 4, "IEND", 4) == 0) return rest_is_zero(static_cast<size_t>(next)) ? static_cast<size_t>(next) : full;
            pos = static_cast<size_t>(next);
        }
    }
    return full;
}

// ----------------------------------------------------------------------------------------------------------- the Motorola image --

namespace {

struct MotoSlot {
    uint32_t offset = 0, size = 0;
};

struct MotoRead {
    std::string why;
    std::vector<MotoSlot> slots;
    uint32_t table_size = 0;
    uint32_t align = 512;
    uint8_t header_fill = 0xFF, gap_fill = 0xFF;
    size_t consumed = 0;
};

MotoRead moto_read(const Bytes& d) {
    MotoRead r;
    if (d.size() < kMotoTableAt + kMotoEntrySize || std::memcmp(d.data(), kMotoMagic, sizeof kMotoMagic) != 0) {
        r.why = "no \"MotoLogo\" and a table";
        return r;
    }
    r.table_size = le32(d, 9);
    if (r.table_size < kMotoTableAt + kMotoEntrySize || r.table_size > d.size() || (r.table_size - kMotoTableAt) % kMotoEntrySize != 0 ||
        (r.table_size - kMotoTableAt) / kMotoEntrySize > kMotoMaxEntries) {
        r.why = "the size of the table is " + std::to_string(r.table_size) + " (it is 13 + 32 for every entry, and the file is " + std::to_string(d.size()) + " bytes)";
        return r;
    }
    const size_t n = (r.table_size - kMotoTableAt) / kMotoEntrySize;
    std::vector<size_t> present;
    for (size_t i = 0; i < n; ++i) {
        const size_t at = kMotoTableAt + i * kMotoEntrySize + kMotoNameSize;
        MotoSlot s;
        s.offset = le32(d, at);
        s.size = le32(d, at + 4);
        const std::string who = "entry " + std::to_string(i);
        if (s.offset == 0 && s.size == 0) {
            r.slots.push_back(s);
            continue;
        }
        if (s.offset == 0 || s.size == 0) {
            r.why = who + " has the offset " + hex(s.offset) + " and the size " + hex(s.size);
            return r;
        }
        if (s.offset < r.table_size || uint64_t{s.offset} + s.size > d.size()) {
            r.why = who + " lies at " + hex(s.offset) + ", " + std::to_string(s.size) + " bytes: not in the file (the table ends at " + hex(r.table_size) + ", the file at " + hex(d.size()) + ")";
            return r;
        }
        present.push_back(i);
        r.slots.push_back(s);
    }
    if (present.empty()) {
        r.why = "no entry has a picture";
        return r;
    }
    // The pictures in the order of the table, one behind the other.
    for (size_t k = 1; k < present.size(); ++k) {
        const MotoSlot& a = r.slots[present[k - 1]];
        const MotoSlot& b = r.slots[present[k]];
        if (uint64_t{b.offset} < uint64_t{a.offset} + a.size) {
            r.why = "entry " + std::to_string(present[k]) + " (at " + hex(b.offset) + ") begins before entry " + std::to_string(present[k - 1]) + " ends (" + hex(uint64_t{a.offset} + a.size) + ")";
            return r;
        }
    }
    const MotoSlot& first = r.slots[present.front()];
    // The fill between the table and the first picture is one byte; the alignment that puts the pictures where they are is the largest that does.
    if (first.offset > r.table_size) {
        r.header_fill = d[r.table_size];
        if (!all_equal(d, r.table_size, first.offset, r.header_fill)) {
            r.why = "the bytes between the table (" + hex(r.table_size) + ") and the first picture (" + hex(first.offset) + ") are not one byte over and over";
            return r;
        }
    }
    bool aligned = false;
    for (uint64_t a = 65536; a >= 4 && !aligned; a >>= 1) {
        if (align_up(r.table_size, a) != first.offset) continue;
        bool ok = true;
        std::optional<uint8_t> fill;
        for (size_t k = 1; k < present.size() && ok; ++k) {
            const MotoSlot& p = r.slots[present[k - 1]];
            const MotoSlot& q = r.slots[present[k]];
            const uint64_t end = uint64_t{p.offset} + p.size;
            if (align_up(end, a) != q.offset) {
                ok = false;
                break;
            }
            if (q.offset > end) {
                const uint8_t f = d[static_cast<size_t>(end)];
                if (fill && *fill != f) ok = false;
                if (!all_equal(d, static_cast<size_t>(end), q.offset, f)) ok = false;
                fill = f;
            }
        }
        if (ok) {
            aligned = true;
            r.align = static_cast<uint32_t>(a);
            r.gap_fill = fill.value_or(r.header_fill);
        }
    }
    if (!aligned) {
        r.why = "the pictures are not at multiples of one alignment (a power of two), each right behind the one before it, with one byte filling between them";
        return r;
    }
    const MotoSlot& last = r.slots[present.back()];
    r.consumed = static_cast<size_t>(uint64_t{last.offset} + last.size);
    return r;
}

}  // namespace

bool moto_looks_like(const Bytes& d) { return moto_read(d).why.empty(); }

std::string moto_problem(const Bytes& d) { return moto_read(d).why; }

MotoLogo moto_parse(const Bytes& d) {
    MotoRead r = moto_read(d);
    if (!r.why.empty()) throw FormatError("splash: " + r.why);
    MotoLogo l;
    l.align = r.align;
    l.header_fill = r.header_fill;
    l.gap_fill = r.gap_fill;
    l.consumed = r.consumed;
    for (size_t i = 0; i < r.slots.size(); ++i) {
        MotoEntry e;
        e.name = text_field(d, kMotoTableAt + i * kMotoEntrySize, kMotoNameSize, e.name_tail);
        if (r.slots[i].size) e.data.assign(d.begin() + r.slots[i].offset, d.begin() + static_cast<std::ptrdiff_t>(uint64_t{r.slots[i].offset} + r.slots[i].size));
        l.entries.push_back(std::move(e));
    }
    return l;
}

Bytes moto_build(const MotoLogo& l) {
    if (l.entries.empty() || l.entries.size() > kMotoMaxEntries)
        throw FormatError("splash: " + std::to_string(l.entries.size()) + " entries (the table holds 1 to " + std::to_string(kMotoMaxEntries) + ")");
    if (l.align < 4 || l.align > 65536 || (l.align & (l.align - 1)) != 0) throw FormatError("splash: the alignment " + std::to_string(l.align) + " is no power of two from 4 to 65536");
    const size_t table_size = kMotoTableAt + l.entries.size() * kMotoEntrySize;
    Bytes out(table_size, 0);
    std::memcpy(out.data(), kMotoMagic, sizeof kMotoMagic);
    put32(out, 9, static_cast<uint32_t>(table_size));
    uint64_t cursor = table_size;
    bool first = true;
    for (size_t i = 0; i < l.entries.size(); ++i) {
        const MotoEntry& e = l.entries[i];
        const size_t at = kMotoTableAt + i * kMotoEntrySize;
        put_text(out, at, kMotoNameSize, e.name, e.name_tail);
        if (e.data.empty()) continue;
        const uint64_t offset = align_up(cursor, l.align);
        if (offset + e.data.size() > 0xFFFFFFFFull) throw FormatError("splash: the pictures are more than an offset can name");
        put32(out, at + kMotoNameSize, static_cast<uint32_t>(offset));
        put32(out, at + kMotoNameSize + 4, static_cast<uint32_t>(e.data.size()));
        // (the bytes up to the first picture are the header's fill; between two pictures they are the gap's)
        out.resize(static_cast<size_t>(offset), first ? l.header_fill : l.gap_fill);
        out.insert(out.end(), e.data.begin(), e.data.end());
        cursor = offset + e.data.size();
        first = false;
    }
    if (first) throw FormatError("splash: no entry has a picture");
    return out;
}

// ------------------------------------------------------------------------------------------------------------------------- the rest --

std::string picture_extension(const Bytes& data) {
    static constexpr uint8_t kPng[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    if (data.size() >= 26 && data[0] == 'B' && data[1] == 'M') return "bmp";
    if (data.size() >= 8 && std::memcmp(data.data(), kPng, 8) == 0) return "png";
    if (data.size() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) return "jpg";
    return "bin";
}

}  // namespace abr::splash
