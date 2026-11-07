// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr/png.hpp, the PNG reader and writer of the picture formats. Run by tests/run_tests.sh as `abr_unit_tests png`.
//
//   * what encode() writes is read back as the same pixels (with and without alpha), always the same bytes for the same picture, and the
//     chunks are the ones PNG asks for (signature, IHDR, one IDAT, IEND, every CRC right);
//   * decode() reads the kinds of PNG that an editor may write: greyscale at 1, 2, 4, 8 and 16 bits, grey with alpha, truecolour at 16 bits, palette
//     at 1, 2, 4 and 8 bits with and without tRNS, the colour keys of tRNS, Adam7 interlacing, every filter type of a scanline;
//   * a PNG that is damaged (signature, CRC, a chunk longer than the file, cut short, data that is too short or too long, a palette entry that
//     is not there, a filter that does not exist, a critical chunk it does not know) is a FormatError, as is a picture of too many pixels.
#include <zlib.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "abr/compression.hpp"
#include "abr/png.hpp"

using namespace abr;

namespace {

int g_failures = 0;
int g_checks = 0;

#define EXPECT(cond)                                                      \
    do {                                                                  \
        ++g_checks;                                                       \
        if (!(cond)) {                                                    \
            ++g_failures;                                                 \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                 \
    } while (0)

template <typename F>
bool throws(F&& f) {
    try {
        f();
    } catch (const FormatError&) {
        return true;
    }
    return false;
}

void be32(Bytes& b, uint32_t v) {
    for (int s = 24; s >= 0; s -= 8) b.push_back(uint8_t(v >> s));
}

void chunk(Bytes& out, const std::string& type, const Bytes& body) {
    be32(out, uint32_t(body.size()));
    const size_t at = out.size();
    out.insert(out.end(), type.begin(), type.end());
    out.insert(out.end(), body.begin(), body.end());
    be32(out, uint32_t(crc32(0, out.data() + at, uInt(4 + body.size()))));
}

// A PNG made here, by hand: `scan` is what goes into the zlib stream (every row behind its filter byte, the passes one after the other).
Bytes make_png(uint32_t w, uint32_t h, unsigned depth, unsigned ctype, bool interlaced, const Bytes& scan, const Bytes& plte = {}, const Bytes& trns = {}) {
    Bytes out{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
    Bytes ihdr;
    be32(ihdr, w);
    be32(ihdr, h);
    ihdr.insert(ihdr.end(), {uint8_t(depth), uint8_t(ctype), 0, 0, uint8_t(interlaced ? 1 : 0)});
    chunk(out, "IHDR", ihdr);
    if (!plte.empty()) chunk(out, "PLTE", plte);
    if (!trns.empty()) chunk(out, "tRNS", trns);
    chunk(out, "IDAT", compress(Codec::ZLIB, scan, 6));
    chunk(out, "IEND", {});
    return out;
}

Bytes rgba_pattern(uint32_t w, uint32_t h, uint32_t seed) {
    Bytes px(size_t(w) * h * 4);
    uint32_t x = seed * 2654435761u + 7;
    for (size_t i = 0; i < px.size(); ++i) {
        x = x * 1664525u + 1013904223u;
        // smooth runs and noise, so that every filter has its rows
        px[i] = (i / 4 % 17 < 9) ? uint8_t((i / 4) * 3 + (i % 4) * 40) : uint8_t(x >> 24);
    }
    return px;
}

void test_roundtrip() {
    for (const auto [w, h] : {std::pair<uint32_t, uint32_t>{1, 1}, {7, 5}, {64, 33}, {300, 2}, {2, 300}}) {
        png::Image img;
        img.width = w;
        img.height = h;
        img.rgba = rgba_pattern(w, h, w * 31 + h);
        const Bytes with = png::encode(img, true);
        EXPECT(png::looks_like(with));
        EXPECT(png::encode(img, true) == with);  // the same picture, the same bytes
        const png::Image back = png::decode(with);
        EXPECT(back.width == w && back.height == h && back.rgba == img.rgba && back.has_alpha);
        const Bytes without = png::encode(img, false);
        const png::Image plain = png::decode(without);
        EXPECT(plain.width == w && plain.height == h && !plain.has_alpha);
        bool same = plain.rgba.size() == img.rgba.size();
        for (size_t i = 0; same && i < img.rgba.size(); i += 4)
            same = plain.rgba[i] == img.rgba[i] && plain.rgba[i + 1] == img.rgba[i + 1] && plain.rgba[i + 2] == img.rgba[i + 2] && plain.rgba[i + 3] == 255;
        EXPECT(same);
    }
    // the chunks: signature, IHDR, one IDAT, IEND, every CRC right
    png::Image img;
    img.width = 40;
    img.height = 30;
    img.rgba = rgba_pattern(40, 30, 3);
    const Bytes data = png::encode(img, true);
    size_t pos = 8;
    std::vector<std::string> names;
    bool crcs = true;
    while (pos + 12 <= data.size()) {
        const uint32_t len = (uint32_t(data[pos]) << 24) | (uint32_t(data[pos + 1]) << 16) | (uint32_t(data[pos + 2]) << 8) | data[pos + 3];
        names.emplace_back(reinterpret_cast<const char*>(&data[pos + 4]), 4);
        const uint32_t want = (uint32_t(data[pos + 8 + len]) << 24) | (uint32_t(data[pos + 9 + len]) << 16) | (uint32_t(data[pos + 10 + len]) << 8) | data[pos + 11 + len];
        crcs = crcs && want == uint32_t(crc32(0, &data[pos + 4], uInt(4 + len)));
        pos += 12 + len;
    }
    EXPECT(pos == data.size() && crcs);
    EXPECT((names == std::vector<std::string>{"IHDR", "IDAT", "IEND"}));
    // a picture of one colour: the smallest rows
    png::Image flat;
    flat.width = 100;
    flat.height = 100;
    flat.rgba.assign(100 * 100 * 4, 0x80);
    EXPECT(png::decode(png::encode(flat, true)).rgba == flat.rgba);
    // a width and a height the writer is not given right are refused
    png::Image bad;
    bad.width = 4;
    bad.height = 4;
    bad.rgba.assign(10, 0);
    EXPECT(throws([&] { png::encode(bad, true); }));
    bad.width = 0;
    EXPECT(throws([&] { png::encode(bad, true); }));
}

void test_kinds() {
    // greyscale 8 bits, 3x2: rows 10 20 30 / 40 50 60
    {
        const png::Image im = png::decode(make_png(3, 2, 8, 0, false, {0, 10, 20, 30, 0, 40, 50, 60}));
        EXPECT(im.width == 3 && im.height == 2 && !im.has_alpha);
        EXPECT(im.rgba[0] == 10 && im.rgba[1] == 10 && im.rgba[2] == 10 && im.rgba[3] == 255);
        EXPECT(im.rgba[4 * 5] == 60 && im.rgba[4 * 5 + 3] == 255);
    }
    // greyscale 1 bit, 10x1: 1010101011 (two bytes: 0xAA 0xC0) -> white black white ...
    {
        const png::Image im = png::decode(make_png(10, 1, 1, 0, false, {0, 0xAA, 0xC0}));
        EXPECT(im.rgba[0] == 255 && im.rgba[4] == 0 && im.rgba[8] == 255 && im.rgba[4 * 8] == 255 && im.rgba[4 * 9] == 255 && im.rgba[4 * 7] == 0);
    }
    // greyscale 2 bits: values 0..3 -> 0, 85, 170, 255
    {
        const png::Image im = png::decode(make_png(4, 1, 2, 0, false, {0, 0x1B}));  // 00 01 10 11
        EXPECT(im.rgba[0] == 0 && im.rgba[4] == 85 && im.rgba[8] == 170 && im.rgba[12] == 255);
    }
    // greyscale 4 bits
    {
        const png::Image im = png::decode(make_png(2, 1, 4, 0, false, {0, 0x0F}));
        EXPECT(im.rgba[0] == 0 && im.rgba[4] == 255);
    }
    // greyscale 16 bits: the high byte
    {
        const png::Image im = png::decode(make_png(2, 1, 16, 0, false, {0, 0x12, 0x34, 0xAB, 0xCD}));
        EXPECT(im.rgba[0] == 0x12 && im.rgba[4] == 0xAB);
    }
    // grey with alpha at 8 and 16 bits
    {
        const png::Image im = png::decode(make_png(1, 1, 8, 4, false, {0, 77, 33}));
        EXPECT(im.has_alpha && im.rgba[0] == 77 && im.rgba[3] == 33);
        const png::Image im16 = png::decode(make_png(1, 1, 16, 4, false, {0, 0x80, 0x01, 0x40, 0x02}));
        EXPECT(im16.rgba[0] == 0x80 && im16.rgba[3] == 0x40);
    }
    // truecolour at 8 and 16 bits, with the colour key of tRNS
    {
        const png::Image im = png::decode(make_png(2, 1, 8, 2, false, {0, 1, 2, 3, 4, 5, 6}, {}, {0, 4, 0, 5, 0, 6}));
        EXPECT(im.has_alpha && im.rgba[0] == 1 && im.rgba[3] == 255 && im.rgba[4] == 4 && im.rgba[7] == 0);
        const png::Image im16 = png::decode(make_png(1, 1, 16, 2, false, {0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}));
        EXPECT(im16.rgba[0] == 0x11 && im16.rgba[1] == 0x33 && im16.rgba[2] == 0x55 && im16.rgba[3] == 255);
    }
    // greyscale with a colour key
    {
        const png::Image im = png::decode(make_png(2, 1, 8, 0, false, {0, 9, 200}, {}, {0, 200}));
        EXPECT(im.rgba[3] == 255 && im.rgba[7] == 0 && im.has_alpha);
    }
    // palette: 4 bits (two pixels per byte), tRNS naming the alpha of the first entries only
    {
        const Bytes plte{255, 0, 0, 0, 255, 0, 0, 0, 255};
        const png::Image im = png::decode(make_png(3, 1, 4, 3, false, {0, 0x01, 0x20}, plte, {128, 64}));
        EXPECT(im.rgba[0] == 255 && im.rgba[3] == 128 && im.rgba[4 + 1] == 255 && im.rgba[7] == 64 && im.rgba[8 + 2] == 255 && im.rgba[11] == 255);
        // 1 bit, 2 bits, 8 bits
        EXPECT(png::decode(make_png(2, 1, 1, 3, false, {0, 0x40}, plte)).rgba[4 + 1] == 255);
        EXPECT(png::decode(make_png(2, 1, 2, 3, false, {0, 0x60}, plte)).rgba[4 + 2] == 255);
        EXPECT(png::decode(make_png(2, 1, 8, 3, false, {0, 2, 1}, plte)).rgba[2] == 255);
        EXPECT(throws([&] { png::decode(make_png(1, 1, 8, 3, false, {0, 3}, plte)); }));  // an entry that is not there
        EXPECT(throws([&] { png::decode(make_png(1, 1, 8, 3, false, {0, 0})); }));        // no palette at all
    }
    // filters: sub, up, average, paeth on 4 pixels of RGB, two rows; made by applying the filter to rows that are known
    {
        const uint8_t row0[12] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120};
        const uint8_t row1[12] = {15, 25, 35, 41, 52, 61, 90, 70, 100, 99, 120, 130};
        for (uint8_t filter = 1; filter <= 4; ++filter) {
            Bytes scan{0};
            scan.insert(scan.end(), row0, row0 + 12);
            scan.push_back(filter);
            for (int i = 0; i < 12; ++i) {
                const int a = i >= 3 ? row1[i - 3] : 0, b = row0[i], c = i >= 3 ? row0[i - 3] : 0;
                int predict = 0;
                if (filter == 1) predict = a;
                if (filter == 2) predict = b;
                if (filter == 3) predict = (a + b) >> 1;
                if (filter == 4) {
                    const int p = a + b - c, pa = std::abs(p - a), pb = std::abs(p - b), pc = std::abs(p - c);
                    predict = (pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c);
                }
                scan.push_back(uint8_t(row1[i] - predict));
            }
            // row 0 is stored with filter 0 above, so its bytes are plain: the second row is the one that is filtered
            const png::Image im = png::decode(make_png(4, 2, 8, 2, false, scan));
            bool ok = im.rgba.size() == 32;
            for (int i = 0; ok && i < 4; ++i)
                for (int c = 0; c < 3; ++c) ok = ok && im.rgba[(4 + i) * 4 + c] == row1[3 * i + c];
            EXPECT(ok);
        }
    }
    // Adam7: a picture of 5x5 RGB made pass by pass, filter 0
    {
        const uint32_t w = 5, h = 5;
        Bytes plain(w * h * 3);
        for (size_t i = 0; i < plain.size(); ++i) plain[i] = uint8_t(i * 7 + 3);
        struct Pass {
            uint32_t x0, y0, dx, dy;
        };
        const Pass passes[7] = {{0, 0, 8, 8}, {4, 0, 8, 8}, {0, 4, 4, 8}, {2, 0, 4, 4}, {0, 2, 2, 4}, {1, 0, 2, 2}, {0, 1, 1, 2}};
        Bytes scan;
        for (const Pass& p : passes)
            for (uint32_t y = p.y0; y < h; y += p.dy) {
                if (p.x0 >= w) continue;
                scan.push_back(0);
                for (uint32_t x = p.x0; x < w; x += p.dx)
                    for (int c = 0; c < 3; ++c) scan.push_back(plain[(y * w + x) * 3 + c]);
            }
        const png::Image im = png::decode(make_png(w, h, 8, 2, true, scan));
        bool ok = im.width == w && im.height == h;
        for (uint32_t i = 0; ok && i < w * h; ++i)
            ok = im.rgba[4 * i] == plain[3 * i] && im.rgba[4 * i + 1] == plain[3 * i + 1] && im.rgba[4 * i + 2] == plain[3 * i + 2] && im.rgba[4 * i + 3] == 255;
        EXPECT(ok);
    }
}

void test_damage() {
    png::Image img;
    img.width = 20;
    img.height = 10;
    img.rgba = rgba_pattern(20, 10, 5);
    const Bytes good = png::encode(img, true);
    EXPECT(!throws([&] { png::decode(good); }));
    EXPECT(throws([&] { png::decode(Bytes()); }));
    EXPECT(throws([&] { png::decode(Bytes{'n', 'o', 't', ' ', 'a', ' ', 'p', 'n', 'g', '!'}); }));
    Bytes b = good;
    b[b.size() / 2] ^= 0x01;  // a bit of the picture data: the CRC
    EXPECT(throws([&] { png::decode(b); }));
    for (size_t cut : {size_t(5), size_t(20), size_t(40), good.size() - 13, good.size() - 1}) {
        const Bytes c(good.begin(), good.begin() + cut);
        EXPECT(throws([&] { png::decode(c); }));
    }
    {
        Bytes c = good;  // a chunk that says it is longer than the file
        c[8 + 3] = 0xff;
        c[8 + 2] = 0xff;
        EXPECT(throws([&] { png::decode(c); }));
    }
    // data too short for the picture, and too long
    EXPECT(throws([&] { png::decode(make_png(4, 4, 8, 0, false, Bytes(16, 0))); }));
    EXPECT(throws([&] { png::decode(make_png(4, 4, 8, 0, false, Bytes(20 + 5, 0))); }));
    EXPECT(throws([&] { png::decode(make_png(1, 1, 8, 0, false, {9, 5})); }));  // the filter 9
    EXPECT(throws([&] { png::decode(make_png(1, 1, 3, 0, false, {0, 5})); }));  // 3 bits is no depth
    EXPECT(throws([&] { png::decode(make_png(1, 1, 16, 3, false, {0, 5, 5}, {1, 2, 3})); }));  // a palette at 16 bits is none
    EXPECT(throws([&] { png::decode(make_png(0, 1, 8, 0, false, {0, 5})); }));
    // too many pixels: a header that asks for 60000 x 60000 would be 13 GB
    EXPECT(throws([&] { png::decode(make_png(60000, 60000, 8, 0, false, {0, 5})); }));
    // a critical chunk that is not known, an ancillary one that is not
    {
        Bytes with_unknown{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
        Bytes ihdr;
        be32(ihdr, 1);
        be32(ihdr, 1);
        ihdr.insert(ihdr.end(), {8, 0, 0, 0, 0});
        chunk(with_unknown, "IHDR", ihdr);
        Bytes ancillary = with_unknown, critical = with_unknown;
        chunk(ancillary, "tEXt", {'a', 0, 'b'});
        chunk(critical, "ABCD", {1, 2, 3});
        for (Bytes* p : {&ancillary, &critical}) {
            chunk(*p, "IDAT", compress(Codec::ZLIB, Bytes{0, 200}, 6));
            chunk(*p, "IEND", {});
        }
        EXPECT(!throws([&] { png::decode(ancillary); }) && png::decode(ancillary).rgba[0] == 200);
        EXPECT(throws([&] { png::decode(critical); }));
    }
}

}  // namespace

// `abr_unit_tests png-decode in.png out.rgba` writes the pixels of a PNG as 8-bit RGBA, and prints "<width> <height> <alpha 0|1>";
// `abr_unit_tests png-encode in.rgba <width> <height> out.png [noalpha]` makes the PNG that abr writes of such pixels. For a comparison
// with another PNG program (the oracle of tests/run_tests.sh).
int run_png_tool(int argc, char** argv) {
    const std::string cmd = argv[1];
    if (cmd == "png-decode" && argc == 4) {
        const png::Image img = png::decode(read_file(argv[2]));
        write_file(argv[3], img.rgba);
        std::printf("%u %u %d\n", img.width, img.height, img.has_alpha ? 1 : 0);
        return 0;
    }
    if (cmd == "png-encode" && (argc == 6 || argc == 7)) {
        png::Image img;
        img.rgba = read_file(argv[2]);
        img.width = uint32_t(std::stoul(argv[3]));
        img.height = uint32_t(std::stoul(argv[4]));
        write_file(argv[5], png::encode(img, !(argc == 7 && std::string(argv[6]) == "noalpha")));
        return 0;
    }
    std::fprintf(stderr, "usage: png-decode in.png out.rgba | png-encode in.rgba width height out.png [noalpha]\n");
    return 2;
}

int run_png_tests() {
    test_roundtrip();
    test_kinds();
    test_damage();
    if (g_failures == 0) std::printf("png: ok (%d checks)\n", g_checks);
    else std::printf("png: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
