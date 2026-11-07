// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/png.hpp"

#include <zlib.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "abr/compression.hpp"

namespace abr::png {

namespace {

constexpr uint8_t kSignature[8] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};

[[noreturn]] void fail(const std::string& what) { throw FormatError("png: " + what); }

uint32_t be32(const uint8_t* p) { return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | p[3]; }

void put_be32(Bytes& out, uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
}

void put_chunk(Bytes& out, const char (&type)[5], const uint8_t* data, size_t n) {
    put_be32(out, static_cast<uint32_t>(n));
    const size_t at = out.size();
    out.insert(out.end(), type, type + 4);
    if (n) out.insert(out.end(), data, data + n);
    put_be32(out, static_cast<uint32_t>(crc32(0, out.data() + at, static_cast<uInt>(4 + n))));
}

int paeth(int a, int b, int c) {
    const int p = a + b - c;
    const int pa = std::abs(p - a), pb = std::abs(p - b), pc = std::abs(p - c);
    if (pa <= pb && pa <= pc) return a;
    return pb <= pc ? b : c;
}

// ----------------------------------------------------------------------------------------------------------------------- reading --

struct Header {
    uint32_t width = 0, height = 0;
    unsigned depth = 0, ctype = 0;
    bool interlaced = false;
};

unsigned channels_of(unsigned ctype) {
    switch (ctype) {
        case 0: return 1;
        case 2: return 3;
        case 3: return 1;
        case 4: return 2;
        default: return 4;  // 6
    }
}

// Undoes the filters of `rows` scanlines of `rowbytes` bytes (each behind its filter byte), in place: the filtered rows are
// [filter][bytes...], and what is left in front of each is the plain bytes. `bpp` is the bytes per pixel, at least 1.
void unfilter(uint8_t* data, size_t rowbytes, size_t rows, size_t bpp) {
    const size_t stride = rowbytes + 1;
    for (size_t y = 0; y < rows; ++y) {
        uint8_t* row = data + y * stride + 1;
        const uint8_t filter = data[y * stride];
        const uint8_t* prev = y ? data + (y - 1) * stride + 1 : nullptr;
        switch (filter) {
            case 0: break;
            case 1:
                for (size_t i = bpp; i < rowbytes; ++i) row[i] = static_cast<uint8_t>(row[i] + row[i - bpp]);
                break;
            case 2:
                if (prev)
                    for (size_t i = 0; i < rowbytes; ++i) row[i] = static_cast<uint8_t>(row[i] + prev[i]);
                break;
            case 3:
                for (size_t i = 0; i < rowbytes; ++i) {
                    const int a = i >= bpp ? row[i - bpp] : 0;
                    const int b = prev ? prev[i] : 0;
                    row[i] = static_cast<uint8_t>(row[i] + ((a + b) >> 1));
                }
                break;
            case 4:
                for (size_t i = 0; i < rowbytes; ++i) {
                    const int a = i >= bpp ? row[i - bpp] : 0;
                    const int b = prev ? prev[i] : 0;
                    const int c = (prev && i >= bpp) ? prev[i - bpp] : 0;
                    row[i] = static_cast<uint8_t>(row[i] + paeth(a, b, c));
                }
                break;
            default: fail("a scanline with the filter " + std::to_string(filter) + " (there are five)");
        }
        // (This row is plain now, in place, and the next one is filtered against it as it is.)
    }
}

struct Palette {
    uint8_t rgb[256][3];
    uint8_t alpha[256];
    size_t entries = 0;
};

struct Key {  // the transparent colour of tRNS for greyscale and truecolour (16-bit values, as they are written)
    bool present = false;
    uint16_t v[3] = {0, 0, 0};
};

// One scanline of `count` pixels (`row`, plain bytes) as RGBA, to `out` at every `step`-th pixel from `x0`.
void convert_row(const Header& h, const Palette& pal, const Key& key, const uint8_t* row, size_t count, uint8_t* out, size_t step) {
    const unsigned depth = h.depth;
    const auto sample = [&](size_t i) -> unsigned {  // the i-th sample of a row of one-channel pixels at depth 1, 2, 4, 8
        if (depth == 8) return row[i];
        const size_t bit = i * depth;
        return (row[bit >> 3] >> (8 - depth - (bit & 7))) & ((1u << depth) - 1);
    };
    const auto sample16 = [&](size_t index) { return static_cast<unsigned>((row[2 * index] << 8) | row[2 * index + 1]); };
    for (size_t i = 0; i < count; ++i, out += 4 * step) {
        switch (h.ctype) {
            case 0: {
                unsigned v = depth == 16 ? sample16(i) : sample(i);
                const bool transparent = key.present && v == key.v[0];
                const unsigned grey = depth == 16 ? v >> 8 : depth == 8 ? v : v * 255 / ((1u << depth) - 1);
                out[0] = out[1] = out[2] = static_cast<uint8_t>(grey);
                out[3] = transparent ? 0 : 255;
                break;
            }
            case 2: {
                uint16_t v[3];
                for (int c = 0; c < 3; ++c) v[c] = depth == 16 ? static_cast<uint16_t>(sample16(3 * i + c)) : row[3 * i + c];
                for (int c = 0; c < 3; ++c) out[c] = depth == 16 ? static_cast<uint8_t>(v[c] >> 8) : static_cast<uint8_t>(v[c]);
                out[3] = key.present && v[0] == key.v[0] && v[1] == key.v[1] && v[2] == key.v[2] ? 0 : 255;
                break;
            }
            case 3: {
                const unsigned index = sample(i);
                if (index >= pal.entries) fail("a pixel that names the palette entry " + std::to_string(index) + " of " + std::to_string(pal.entries));
                out[0] = pal.rgb[index][0];
                out[1] = pal.rgb[index][1];
                out[2] = pal.rgb[index][2];
                out[3] = pal.alpha[index];
                break;
            }
            case 4:
                out[0] = out[1] = out[2] = depth == 16 ? row[4 * i] : row[2 * i];
                out[3] = depth == 16 ? row[4 * i + 2] : row[2 * i + 1];
                break;
            default:  // 6
                if (depth == 16) {
                    for (int c = 0; c < 4; ++c) out[c] = row[8 * i + 2 * c];
                } else {
                    std::memcpy(out, row + 4 * i, 4);
                }
                break;
        }
    }
}

}  // namespace

bool looks_like(const Bytes& data) { return data.size() >= sizeof(kSignature) && std::memcmp(data.data(), kSignature, sizeof(kSignature)) == 0; }

Image decode(const Bytes& png) {
    if (!looks_like(png)) fail("not a PNG (the eight bytes it begins with are not there)");
    Header h;
    bool have_header = false, ended = false;
    Palette pal{};
    Key key;
    Bytes idat;
    bool have_palette = false, have_trns = false;
    size_t pos = sizeof(kSignature);
    while (pos < png.size() && !ended) {
        if (png.size() - pos < 12) fail("cut short in a chunk");
        const uint32_t length = be32(&png[pos]);
        if (length > 0x7fffffffu || length > png.size() - pos - 12) fail("a chunk is longer than the file");
        const char* type = reinterpret_cast<const char*>(&png[pos + 4]);
        const uint8_t* body = &png[pos + 8];
        const uint32_t crc = be32(&png[pos + 8 + length]);
        if (crc != static_cast<uint32_t>(crc32(0, &png[pos + 4], 4 + length))) fail(std::string("the CRC of the chunk ") + std::string(type, 4) + " is wrong");
        const std::string name(type, 4);
        if (!have_header && name != "IHDR") fail("the first chunk is " + name + ", not IHDR");
        if (name == "IHDR") {
            if (have_header || length != 13) fail("a bad IHDR");
            h.width = be32(body);
            h.height = be32(body + 4);
            h.depth = body[8];
            h.ctype = body[9];
            if (body[10] != 0 || body[11] != 0) fail("a compression or filter method that PNG does not have");
            if (body[12] > 1) fail("an interlace method that PNG does not have");
            h.interlaced = body[12] == 1;
            const bool ok = (h.ctype == 0 && (h.depth == 1 || h.depth == 2 || h.depth == 4 || h.depth == 8 || h.depth == 16)) ||
                            ((h.ctype == 2 || h.ctype == 4 || h.ctype == 6) && (h.depth == 8 || h.depth == 16)) ||
                            (h.ctype == 3 && (h.depth == 1 || h.depth == 2 || h.depth == 4 || h.depth == 8));
            if (!ok) fail("colour type " + std::to_string(h.ctype) + " at " + std::to_string(h.depth) + " bits is not one PNG has");
            if (h.width == 0 || h.height == 0) fail("a picture of no pixels");
            if (uint64_t{h.width} * h.height > kMaxPixels)
                fail(std::to_string(h.width) + "x" + std::to_string(h.height) + " is more than " + std::to_string(kMaxPixels >> 20) + " million pixels");
            have_header = true;
        } else if (name == "PLTE") {
            if (length % 3 != 0 || length == 0 || length > 768) fail("a bad PLTE");
            pal.entries = length / 3;
            for (size_t i = 0; i < pal.entries; ++i) {
                std::memcpy(pal.rgb[i], body + 3 * i, 3);
                pal.alpha[i] = 255;
            }
            have_palette = true;
        } else if (name == "tRNS") {
            if (h.ctype == 3) {
                if (!have_palette) fail("tRNS before PLTE");
                for (size_t i = 0; i < std::min<size_t>(length, pal.entries); ++i) pal.alpha[i] = body[i];
                have_trns = true;
            } else if (h.ctype == 0 && length == 2) {
                key = {true, {static_cast<uint16_t>((body[0] << 8) | body[1]), 0, 0}};
                have_trns = true;
            } else if (h.ctype == 2 && length == 6) {
                key = {true, {static_cast<uint16_t>((body[0] << 8) | body[1]), static_cast<uint16_t>((body[2] << 8) | body[3]),
                              static_cast<uint16_t>((body[4] << 8) | body[5])}};
                have_trns = true;
            }
        } else if (name == "IDAT") {
            if (idat.size() + length > (size_t{1} << 31)) fail("more picture data than any picture holds");
            idat.insert(idat.end(), body, body + length);
        } else if (name == "IEND") {
            ended = true;
        } else if ((type[0] & 0x20) == 0) {
            fail("a chunk (" + name + ") that a reader has to know and this one does not");  // critical (upper case first letter)
        }
        pos += 12 + length;
    }
    if (!have_header) fail("no IHDR");
    if (idat.empty()) fail("no picture data");
    if (h.ctype == 3 && !have_palette) fail("a palette picture without a palette");

    const unsigned bits_pp = channels_of(h.ctype) * h.depth;
    const size_t bpp = std::max<unsigned>(1, bits_pp / 8);
    // The passes: one for a picture that is not interlaced, seven (Adam7) for one that is.
    struct Pass {
        size_t x0, y0, dx, dy;
    };
    static const Pass adam7[7] = {{0, 0, 8, 8}, {4, 0, 8, 8}, {0, 4, 4, 8}, {2, 0, 4, 4}, {0, 2, 2, 4}, {1, 0, 2, 2}, {0, 1, 1, 2}};
    static const Pass whole[1] = {{0, 0, 1, 1}};
    const Pass* passes = h.interlaced ? adam7 : whole;
    const size_t pass_count = h.interlaced ? 7 : 1;
    struct Size {
        size_t w = 0, h = 0, rowbytes = 0;
    };
    Size sizes[7];
    size_t expected = 0;
    for (size_t p = 0; p < pass_count; ++p) {
        const Pass& ps = passes[p];
        if (h.width > ps.x0 && h.height > ps.y0) {
            sizes[p].w = (h.width - ps.x0 + ps.dx - 1) / ps.dx;
            sizes[p].h = (h.height - ps.y0 + ps.dy - 1) / ps.dy;
            sizes[p].rowbytes = (sizes[p].w * bits_pp + 7) / 8;
            expected += (sizes[p].rowbytes + 1) * sizes[p].h;
        }
    }
    Bytes raw;
    try {
        raw = decompress(Codec::ZLIB, idat, expected);
    } catch (const FormatError& e) {
        fail(std::string("the picture data cannot be inflated: ") + e.what());
    }
    if (raw.size() < expected) fail("the picture data is shorter than the picture (" + std::to_string(raw.size()) + " of " + std::to_string(expected) + " bytes)");

    Image img;
    img.width = h.width;
    img.height = h.height;
    img.has_alpha = h.ctype == 4 || h.ctype == 6 || have_trns;
    img.rgba.assign(size_t{h.width} * h.height * 4, 0);
    size_t at = 0;
    for (size_t p = 0; p < pass_count; ++p) {
        const Size& sz = sizes[p];
        if (sz.w == 0) continue;
        unfilter(raw.data() + at, sz.rowbytes, sz.h, bpp);
        for (size_t y = 0; y < sz.h; ++y) {
            const uint8_t* row = raw.data() + at + y * (sz.rowbytes + 1) + 1;
            uint8_t* out = img.rgba.data() + ((passes[p].y0 + y * passes[p].dy) * h.width + passes[p].x0) * 4;
            convert_row(h, pal, key, row, sz.w, out, passes[p].dx);
        }
        at += (sz.rowbytes + 1) * sz.h;
    }
    return img;
}

// ----------------------------------------------------------------------------------------------------------------------- writing --

Bytes encode(const Image& img, bool with_alpha) {
    const size_t w = img.width, h = img.height;
    if (w == 0 || h == 0 || img.rgba.size() != w * h * 4) fail("encode: the pixels are not width * height * 4 bytes");
    if (uint64_t{img.width} * img.height > kMaxPixels) fail("encode: too many pixels");
    const size_t bpp = with_alpha ? 4 : 3;
    const size_t rowbytes = w * bpp;

    Bytes raw((rowbytes + 1) * h);
    Bytes row(rowbytes), prev(rowbytes, 0);
    Bytes cand[5];
    for (Bytes& c : cand) c.resize(rowbytes);
    for (size_t y = 0; y < h; ++y) {
        const uint8_t* src = img.rgba.data() + y * w * 4;
        if (with_alpha) {
            std::memcpy(row.data(), src, rowbytes);
        } else {
            for (size_t x = 0; x < w; ++x) std::memcpy(&row[3 * x], src + 4 * x, 3);
        }
        for (size_t i = 0; i < rowbytes; ++i) {
            const int a = i >= bpp ? row[i - bpp] : 0, b = prev[i], c = i >= bpp ? prev[i - bpp] : 0;
            cand[0][i] = row[i];
            cand[1][i] = static_cast<uint8_t>(row[i] - a);
            cand[2][i] = static_cast<uint8_t>(row[i] - b);
            cand[3][i] = static_cast<uint8_t>(row[i] - ((a + b) >> 1));
            cand[4][i] = static_cast<uint8_t>(row[i] - paeth(a, b, c));
        }
        // The filter whose bytes, taken as signed numbers, add up to the least (the usual rule of thumb: what is near zero deflates best).
        size_t best = 0;
        uint64_t best_sum = UINT64_MAX;
        for (size_t f = 0; f < 5; ++f) {
            uint64_t sum = 0;
            for (uint8_t v : cand[f]) sum += v < 128 ? v : 256 - v;
            if (sum < best_sum) best_sum = sum, best = f;
        }
        raw[y * (rowbytes + 1)] = static_cast<uint8_t>(best);
        std::memcpy(&raw[y * (rowbytes + 1) + 1], cand[best].data(), rowbytes);
        prev = row;
    }

    Bytes out(kSignature, kSignature + sizeof(kSignature));
    uint8_t ihdr[13];
    ihdr[0] = static_cast<uint8_t>(img.width >> 24), ihdr[1] = static_cast<uint8_t>(img.width >> 16), ihdr[2] = static_cast<uint8_t>(img.width >> 8), ihdr[3] = static_cast<uint8_t>(img.width);
    ihdr[4] = static_cast<uint8_t>(img.height >> 24), ihdr[5] = static_cast<uint8_t>(img.height >> 16), ihdr[6] = static_cast<uint8_t>(img.height >> 8), ihdr[7] = static_cast<uint8_t>(img.height);
    ihdr[8] = 8;
    ihdr[9] = with_alpha ? 6 : 2;
    ihdr[10] = ihdr[11] = ihdr[12] = 0;
    put_chunk(out, "IHDR", ihdr, sizeof(ihdr));
    const Bytes deflated = compress(Codec::ZLIB, raw, 6);
    put_chunk(out, "IDAT", deflated.data(), deflated.size());
    put_chunk(out, "IEND", nullptr, 0);
    return out;
}

}  // namespace abr::png
