// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr/splash.hpp, the splash and logo partitions of Qualcomm phones. Run by tests/run_tests.sh as `abr_unit_tests splash`.
// The images here are made by hand, the way the sources named in the header of splash.hpp describe them (no image from a device was at
// hand); the checks that compare with other implementations (Qualcomm's logo_gen.py, Pillow) are those of the live tests of the script.
//
//   * the pictures: RLE24 and MotoRun round trips on many shapes (widths from 1 to 5000, solid, noise, long runs), the packets of known
//     small pictures byte by byte, no packet across the end of a row, every cut of a stream refused, packets that go beyond the picture, the
//     guard against a size that a short stream cannot fill; the alpha of a PNG put on black;
//   * Qualcomm's "SPLASH!!": the single picture and the table of pictures, pixels and RLE24, the padding of the last block, the bytes behind the
//     fields kept, every refusal (type, size, blocks, offsets), and that what is read is built again to the same bytes -- also of damaged headers;
//   * the OPLUS "SPLASH LOGO!": the preamble ("DDPH" or zeros), the descriptions and names with what follows their zero, the offsets and sizes
//     made again, the refusals;
//   * the Xiaomi "LOGO!!!!": the table in units of 4096 bytes, the content size of a BMP and of a PNG, the refusals;
//   * the Motorola "MotoLogo": the header of a real image (the dump in the source of moto-bootlogo) made byte for byte, the alignment found from
//     the image, the fills, empty slots, the refusals;
//   * that each container is found by its own magic and structure and by none of the others.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <string>
#include <vector>

#include "abr/splash.hpp"

using namespace abr;
using namespace abr::splash;

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

uint32_t g_seed = 12345;
uint32_t next_random() {
    g_seed = g_seed * 1664525u + 1013904223u;
    return g_seed >> 8;
}

Bytes pattern(size_t n, uint8_t seed) {
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>(seed + i * 13 + (i >> 7));
    return b;
}

// A picture of a kind: 0 solid, 1 gradient, 2 noise, 3 runs of every length, 4 stripes of two colours, 5 noise with a few long runs.
Bitmap make_bitmap(uint32_t w, uint32_t h, int kind) {
    Bitmap b;
    b.width = w;
    b.height = h;
    b.bgr.resize(size_t{w} * h * 3);
    uint32_t run_left = 0;
    uint8_t color[3] = {1, 2, 3};
    for (uint32_t y = 0; y < h; ++y)
        for (uint32_t x = 0; x < w; ++x) {
            uint8_t* p = &b.bgr[(size_t{y} * w + x) * 3];
            switch (kind) {
                case 0: p[0] = 10, p[1] = 20, p[2] = 30; break;
                case 1: p[0] = static_cast<uint8_t>(x * 3 + y), p[1] = static_cast<uint8_t>(x + y * 5), p[2] = static_cast<uint8_t>(x ^ y); break;
                case 2: p[0] = static_cast<uint8_t>(next_random()), p[1] = static_cast<uint8_t>(next_random()), p[2] = static_cast<uint8_t>(next_random()); break;
                case 3:
                    if (run_left == 0) {
                        run_left = 1 + next_random() % 300;
                        color[0] = static_cast<uint8_t>(next_random()), color[1] = static_cast<uint8_t>(next_random()), color[2] = static_cast<uint8_t>(next_random());
                    }
                    --run_left;
                    p[0] = color[0], p[1] = color[1], p[2] = color[2];
                    break;
                case 4: p[0] = p[1] = p[2] = ((x / 2 + y) & 1) ? 255 : 0; break;
                default:
                    if (run_left == 0 && next_random() % 9 == 0) run_left = 1 + next_random() % 600;
                    if (run_left) {
                        --run_left;
                        p[0] = 200, p[1] = 100, p[2] = 50;
                    } else {
                        p[0] = static_cast<uint8_t>(next_random()), p[1] = static_cast<uint8_t>(next_random()), p[2] = static_cast<uint8_t>(next_random());
                    }
                    break;
            }
        }
    return b;
}

// The packets of an RLE24 stream, as (pixels, repeat): and whether none crosses the end of a row.
bool rle24_rows_ok(const Bytes& stream, uint32_t width, uint32_t height) {
    size_t pos = 0;
    uint64_t x = 0, rows = 0;
    while (pos < stream.size()) {
        const uint8_t c = stream[pos++];
        const uint64_t n = (c & 0x7Fu) + 1u;
        pos += (c & 0x80) ? 3 : 3 * n;
        x += n;
        if (x > width) return false;
        if (x == width) x = 0, ++rows;
    }
    return x == 0 && rows == height;
}

Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const Bytes& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

void put32(Bytes& d, size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) d[at + i] = static_cast<uint8_t>(v >> (8 * i));
}
uint32_t get32(const Bytes& d, size_t at) { return uint32_t{d[at]} | (uint32_t{d[at + 1]} << 8) | (uint32_t{d[at + 2]} << 16) | (uint32_t{d[at + 3]} << 24); }

// ------------------------------------------------------------------------------------------------------------------------- pictures --

void test_rle24() {
    // Known packets: A A A B C -> a run of three, then two pixels.
    {
        const Bytes px = {1, 2, 3, 1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        const Bytes want = {0x82, 1, 2, 3, 0x01, 4, 5, 6, 7, 8, 9};
        EXPECT(rle24_encode(px, 5, 1) == want);
        size_t used = 0;
        EXPECT(rle24_decode(want.data(), want.size(), 5, 1, &used) == px);
        EXPECT(used == want.size());
    }
    // A run of 300 pixels in one row: 128, 128 and 44.
    {
        Bytes px;
        for (int i = 0; i < 300; ++i) px.insert(px.end(), {9, 8, 7});
        const Bytes want = {0xFF, 9, 8, 7, 0xFF, 9, 8, 7, 0xAB, 9, 8, 7};
        EXPECT(rle24_encode(px, 300, 1) == want);
    }
    // A row of one pixel is one packet of its own; no packet crosses a row (the run of equal pixels at the end of a row and the start of the next).
    {
        const Bytes px = {1, 1, 1, 2, 2, 2, 2, 2, 2};
        const Bytes want = {0x00, 1, 1, 1, 0x00, 2, 2, 2, 0x00, 2, 2, 2};
        EXPECT(rle24_encode(px, 1, 3) == want);
    }
    {
        const Bytes px = {5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5};  // 2 x 2, all equal: two packets of two
        const Bytes want = {0x81, 5, 5, 5, 0x81, 5, 5, 5};
        EXPECT(rle24_encode(px, 2, 2) == want);
        // A stream that runs across rows is read all the same (a loader decodes a stream of pixels).
        const Bytes across = {0x83, 5, 5, 5};
        EXPECT(rle24_decode(across.data(), across.size(), 2, 2) == px);
    }

    // Round trips on many shapes; the stream is the whole of what the decoder uses, and no packet crosses a row.
    const uint32_t widths[] = {1, 2, 3, 7, 127, 128, 129, 255, 256, 300, 1080};
    const uint32_t heights[] = {1, 2, 5, 40};
    for (uint32_t w : widths)
        for (uint32_t h : heights)
            for (int kind = 0; kind < 6; ++kind) {
                if (size_t{w} * h > 60000) continue;
                const Bitmap b = make_bitmap(w, h, kind);
                const Bytes stream = rle24_encode(b.bgr, w, h);
                size_t used = 0;
                const Bytes back = rle24_decode(stream.data(), stream.size(), w, h, &used);
                EXPECT(back == b.bgr);
                EXPECT(used == stream.size());
                EXPECT(rle24_rows_ok(stream, w, h));
                EXPECT(stream.size() <= b.bgr.size() + (b.bgr.size() / 3 + 127) / 128 * 1 + h * 2);  // (never much worse than the pixels)
                if (kind == 0) EXPECT(stream.size() < b.bgr.size() || w == 1);                       // (a solid picture is shorter than its pixels)
            }
    // The same picture always makes the same bytes, on one thread and on many.
    {
        const Bitmap b = make_bitmap(300, 200, 5);
        EXPECT(rle24_encode(b.bgr, 300, 200) == rle24_encode(b.bgr, 300, 200));
    }

    // Damage: every cut of a stream, a packet that goes beyond the picture, a packet cut short, a size that a stream cannot fill.
    {
        const Bitmap b = make_bitmap(20, 6, 3);
        const Bytes stream = rle24_encode(b.bgr, 20, 6);
        for (size_t cut = 0; cut < stream.size(); ++cut) EXPECT(throws([&] { rle24_decode(stream.data(), cut, 20, 6); }));
        Bytes more = stream;
        more.insert(more.end(), {0x00, 1, 2, 3});  // (bytes behind the picture are not read)
        size_t used = 0;
        EXPECT(rle24_decode(more.data(), more.size(), 20, 6, &used) == b.bgr && used == stream.size());
        const Bytes over = {0xFF, 1, 2, 3};
        EXPECT(throws([&] { rle24_decode(over.data(), over.size(), 10, 1); }));
        EXPECT(throws([&] { rle24_decode(over.data(), over.size(), 200, 1); }));      // (one packet of 128: 72 pixels are missing)
        const Bytes raw_short = {0x03, 1, 2, 3, 4, 5, 6};
        EXPECT(throws([&] { rle24_decode(raw_short.data(), raw_short.size(), 4, 1); }));
        EXPECT(throws([&] { rle24_decode(over.data(), over.size(), 16384, 16384); }));  // (a stream of four bytes cannot make 268 million pixels)
    }
    EXPECT(throws([&] { rle24_encode(Bytes(5), 2, 1); }));
}

void test_moto() {
    // Known packets.
    {
        const Bytes want = {'M', 'o', 't', 'o', 'R', 'u', 'n', 0, 0, 3, 0, 1, 0x80, 0x03, 1, 2, 3};
        Bitmap b;
        b.width = 3, b.height = 1, b.bgr = {1, 2, 3, 1, 2, 3, 1, 2, 3};
        EXPECT(moto_encode(b) == want);
        const std::optional<Bitmap> back = moto_decode(want);
        EXPECT(back && back->width == 3 && back->height == 1 && back->bgr == b.bgr);
        // Two equal pixels in a row of different ones are part of the packet of the others (a packet of two costs more than it saves).
        Bitmap c;
        c.width = 4, c.height = 1, c.bgr = {1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3};
        const Bytes want_c = {'M', 'o', 't', 'o', 'R', 'u', 'n', 0, 0, 4, 0, 1, 0x00, 0x04, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3};
        EXPECT(moto_encode(c) == want_c);
        // A packet of no pixels is read as one (the decoder of the tool does), and a run of 4095 is the longest.
        const Bytes zero = {'M', 'o', 't', 'o', 'R', 'u', 'n', 0, 0, 3, 0, 1, 0x00, 0x00, 0x80, 0x03, 7, 8, 9};
        const std::optional<Bitmap> z = moto_decode(zero);
        EXPECT(z && z->bgr == Bytes({7, 8, 9, 7, 8, 9, 7, 8, 9}));
    }
    // Round trips; a width past 4095 needs more than one packet to a row.
    const uint32_t widths[] = {1, 2, 3, 4, 5, 100, 4095, 4096, 5000};
    const uint32_t heights[] = {1, 3, 20};
    for (uint32_t w : widths)
        for (uint32_t h : heights)
            for (int kind = 0; kind < 6; ++kind) {
                if (size_t{w} * h > 60000) continue;
                const Bitmap b = make_bitmap(w, h, kind);
                const Bytes data = moto_encode(b);
                const std::optional<Bitmap> back = moto_decode(data);
                EXPECT(back && back->width == w && back->height == h && back->bgr == b.bgr);
            }
    // Not a picture: another magic, a short header, a size of zero, a packet that is not one (bit 4 set), the stream cut at every place, pixels
    // that are too many or too few.
    {
        const Bitmap b = make_bitmap(30, 4, 3);
        const Bytes good = moto_encode(b);
        for (size_t cut = 0; cut + 1 < good.size(); ++cut) {
            const Bytes part(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(cut));
            // (a cut between two packets is a picture with fewer pixels: refused all the same)
            EXPECT(!moto_decode(part));
        }
        Bytes bad = good;
        bad[0] = 'm';
        EXPECT(!moto_decode(bad));
        bad = good;
        bad[9] = 0, bad[8] = 0;  // width 0
        EXPECT(!moto_decode(bad));
        bad = good;
        bad[kMotoHeaderSize] |= 0x10;
        EXPECT(!moto_decode(bad));
        bad = good;
        bad[11] = static_cast<uint8_t>(bad[11] + 1);  // a row more than there are pixels for
        EXPECT(!moto_decode(bad));
        bad = good;
        bad[11] = static_cast<uint8_t>(bad[11] - 1);  // a row less: the packets go beyond
        EXPECT(!moto_decode(bad));
        EXPECT(!moto_decode(Bytes{}));
        EXPECT(!moto_decode(Bytes(12, 0)));
    }
    Bitmap too_big;
    too_big.width = 70000, too_big.height = 1;
    EXPECT(throws([&] { moto_encode(too_big); }));
}

void test_bitmap() {
    Bytes rgba = {10, 20, 30, 255, 255, 255, 255, 0, 255, 255, 255, 128, 100, 100, 100, 100, 7, 8, 9, 1};
    const Bitmap b = bitmap_from_rgba(rgba, 5, 1);
    EXPECT(b.width == 5 && b.height == 1 && b.bgr.size() == 15);
    EXPECT((Bytes(b.bgr.begin(), b.bgr.begin() + 3) == Bytes{30, 20, 10}));  // opaque: red and blue swapped
    EXPECT((Bytes(b.bgr.begin() + 3, b.bgr.begin() + 6) == Bytes{0, 0, 0}));  // alpha 0: black
    EXPECT((Bytes(b.bgr.begin() + 6, b.bgr.begin() + 9) == Bytes{128, 128, 128}));  // 255 at 128 of 255
    EXPECT((Bytes(b.bgr.begin() + 9, b.bgr.begin() + 12) == Bytes{39, 39, 39}));    // 100 at 100 of 255 is 39.2
    EXPECT((Bytes(b.bgr.begin() + 12, b.bgr.end()) == Bytes{0, 0, 0}));             // 9 at 1 of 255 is 0.04
    const Bytes back = bitmap_to_rgba(b);
    EXPECT(back.size() == 20 && back[3] == 255 && back[0] == 10 && back[2] == 30);
    EXPECT(bitmap_from_rgba(back, 5, 1).bgr == b.bgr);
    EXPECT(throws([&] { bitmap_from_rgba(Bytes(7), 2, 1); }));
}

// ---------------------------------------------------------------------------------------------------------------- Qualcomm's SPLASH!! --

QcPicture qc_picture(const Bitmap& b, uint32_t type, bool pad_to_block) {
    QcPicture p;
    p.width = b.width, p.height = b.height, p.type = type;
    p.data = qc_encode(b, type);
    p.stream = p.data.size();
    p.blocks = qc_blocks(p.data.size());
    if (pad_to_block) p.data.resize(size_t{p.blocks} * kQcBlock, 0);
    return p;
}

void test_qc() {
    EXPECT(qc_blocks(0) == 0 && qc_blocks(1) == 1 && qc_blocks(512) == 1 && qc_blocks(513) == 2);
    EXPECT(qc_type_name(0) == "pixels" && qc_type_name(1) == "RLE24" && qc_type_name(7) == "type 7");

    // The single picture, the way logo_gen.py writes it: the header, and the data with no padding.
    for (uint32_t type : {kQcRaw, kQcRle24}) {
        const Bitmap b = make_bitmap(37, 21, 5);
        QcSplash s;
        s.pictures.push_back(qc_picture(b, type, false));
        const Bytes file = qc_build(s);
        EXPECT(file.size() == kQcHeaderSize + s.pictures[0].data.size());
        EXPECT(std::equal(kQcMagic, kQcMagic + 8, file.begin()));
        EXPECT(get32(file, 8) == 37 && get32(file, 12) == 21 && get32(file, 16) == type && get32(file, 20) == s.pictures[0].blocks);
        EXPECT(std::all_of(file.begin() + 24, file.begin() + 512, [](uint8_t v) { return v == 0; }));
        EXPECT(qc_looks_like(file) && qc_problem(file).empty());
        const QcSplash back = qc_parse(file);
        EXPECT(!back.several && back.pictures.size() == 1 && back.consumed == file.size() && back.header_rest.empty());
        const QcPicture& p = back.pictures[0];
        EXPECT(p.width == 37 && p.height == 21 && p.type == type && p.blocks == s.pictures[0].blocks && p.offset == 512);
        EXPECT(p.stream == s.pictures[0].data.size() && p.data == s.pictures[0].data);
        EXPECT(qc_decode(p).bgr == b.bgr);
        EXPECT(qc_build(back) == file);

        // Padded to the block, and a partition's fill behind: the data is the blocks, the fill is no part of the image.
        QcSplash padded;
        padded.pictures.push_back(qc_picture(b, type, true));
        Bytes part = qc_build(padded);
        const size_t image_end = part.size();
        part.resize(image_end + 5000, 0);
        const QcSplash again = qc_parse(part);
        EXPECT(again.consumed == image_end && again.pictures[0].data.size() == size_t{again.pictures[0].blocks} * 512);
        EXPECT(again.pictures[0].stream == s.pictures[0].data.size());
        EXPECT(qc_build(again) == Bytes(part.begin(), part.begin() + static_cast<std::ptrdiff_t>(image_end)));
    }

    // Bytes in the header behind the fields are kept; the padding that is not zero is part of the data.
    {
        const Bitmap b = make_bitmap(10, 10, 2);
        QcSplash s;
        s.pictures.push_back(qc_picture(b, kQcRaw, true));
        s.pictures[0].data.back() = 0x5A;
        s.header_rest = Bytes(200, 0);
        s.header_rest[0] = 1, s.header_rest[199] = 0xEE;
        const Bytes file = qc_build(s);
        const QcSplash back = qc_parse(file);
        EXPECT(back.header_rest.size() == 200 && back.header_rest[199] == 0xEE);
        EXPECT(qc_build(back) == file);
        EXPECT(qc_decode(back.pictures[0]).bgr == b.bgr);
        s.header_rest = Bytes(500, 1);
        EXPECT(throws([&] { qc_build(s); }));
    }

    // A single picture that says 0 blocks, as the sample images of Qualcomm's own do (mm_splash.img, lp_splash.img: 1080x1920, type 0, blocks 0, exactly the
    // pixels behind the header): its data is its pixels, or the packets that make the picture.
    for (uint32_t type : {kQcRaw, kQcRle24}) {
        const Bitmap b = make_bitmap(37, 21, 6);
        QcSplash s;
        s.pictures.push_back(qc_picture(b, type, false));
        s.pictures[0].blocks = 0;
        const Bytes file = qc_build(s);
        EXPECT(get32(file, 20) == 0 && file.size() == kQcHeaderSize + s.pictures[0].data.size());
        EXPECT(qc_looks_like(file) && qc_problem(file).empty());
        const QcSplash back = qc_parse(file);
        EXPECT(!back.several && back.pictures[0].blocks == 0 && back.consumed == file.size());
        EXPECT(back.pictures[0].stream == s.pictures[0].data.size() && back.pictures[0].data == s.pictures[0].data);
        EXPECT(qc_decode(back.pictures[0]).bgr == b.bgr);
        EXPECT(qc_build(back) == file);
        // The fill of a partition behind the picture is no part of it (with the blocks it would have been the end of the last block).
        Bytes part = file;
        part.resize(file.size() + 3000, 0xFF);
        const QcSplash in_part = qc_parse(part);
        EXPECT(in_part.consumed == file.size() && in_part.pictures[0].data == s.pictures[0].data && qc_build(in_part) == file);
        // Cut short, the picture is refused whatever the type.
        for (size_t cut = 513; cut < file.size(); cut += 41) {
            const Bytes cutoff(file.begin(), file.begin() + static_cast<std::ptrdiff_t>(cut));
            EXPECT(throws([&] { qc_parse(cutoff); }));
        }
        // A table has no entry of 0 blocks: refused when it is read (the header is no table, and no single picture either) and when it is built.
        QcSplash t;
        t.several = true;
        t.pictures.push_back(qc_picture(b, type, true));
        t.pictures.push_back(qc_picture(b, type, false));
        Bytes table = qc_build(t);
        EXPECT(qc_looks_like(table));
        put32(table, 12 + 12, 0);
        EXPECT(!qc_looks_like(table) || throws([&] { qc_parse(table); }));
        t.pictures[1].blocks = 0;
        EXPECT(throws([&] { qc_build(t); }));
    }

    // Several pictures: the table, the offsets one behind the other, the last one in the middle of its block.
    {
        const Bitmap b0 = make_bitmap(40, 30, 1), b1 = make_bitmap(100, 7, 3), b2 = make_bitmap(5, 5, 5);
        QcSplash s;
        s.several = true;
        s.pictures.push_back(qc_picture(b0, kQcRaw, true));
        s.pictures.push_back(qc_picture(b1, kQcRle24, true));
        s.pictures.push_back(qc_picture(b2, kQcRle24, false));
        const Bytes file = qc_build(s);
        EXPECT(get32(file, 8) == 3);
        EXPECT(get32(file, 12 + 16) == 512);
        EXPECT(get32(file, 12 + 20 + 16) == 512 + s.pictures[0].data.size());
        EXPECT(get32(file, 12 + 40 + 16) == 512 + s.pictures[0].data.size() + s.pictures[1].data.size());
        EXPECT(qc_looks_like(file));
        const QcSplash back = qc_parse(file);
        EXPECT(back.several && back.pictures.size() == 3 && back.consumed == file.size());
        EXPECT(qc_decode(back.pictures[0]).bgr == b0.bgr && qc_decode(back.pictures[1]).bgr == b1.bgr && qc_decode(back.pictures[2]).bgr == b2.bgr);
        EXPECT(back.pictures[2].offset == get32(file, 12 + 40 + 16));
        EXPECT(qc_build(back) == file);
        // (a picture in the middle that is not whole blocks cannot be followed at once)
        QcSplash bad = s;
        bad.pictures[0].data.pop_back();
        EXPECT(throws([&] { qc_build(bad); }));
        QcSplash none;
        EXPECT(throws([&] { qc_build(none); }));
        QcSplash two;
        two.pictures = {s.pictures[0], s.pictures[1]};
        EXPECT(throws([&] { qc_build(two); }));  // (two pictures are the several-pictures form)
        QcSplash many;
        many.several = true;
        many.pictures.assign(26, qc_picture(make_bitmap(2, 2, 0), kQcRaw, true));
        EXPECT(throws([&] { qc_build(many); }));
        many.pictures.resize(25);
        const QcSplash twenty_five = qc_parse(qc_build(many));
        EXPECT(twenty_five.pictures.size() == 25);
    }

    // Not an image of this kind, and why.
    {
        const Bitmap b = make_bitmap(16, 16, 2);
        QcSplash s;
        s.pictures.push_back(qc_picture(b, kQcRaw, false));
        const Bytes good = qc_build(s);
        const auto refused = [&](const Bytes& d) { return !qc_looks_like(d) || throws([&] { qc_parse(d); }); };
        Bytes d = good;
        put32(d, 16, 2);  // a type nobody knows
        EXPECT(!qc_looks_like(d) && !qc_problem(d).empty());
        d = good, put32(d, 8, 0);
        EXPECT(!qc_looks_like(d));
        d = good, put32(d, 12, kMaxSide + 1);
        EXPECT(!qc_looks_like(d));
        d = good, put32(d, 20, 0);  // (0 blocks is the single picture as Qualcomm's own images say it: its data is the pixels; a table has none such, see below)
        EXPECT(qc_looks_like(d) && !throws([&] { qc_parse(d); }));
        d = good, d[3] = 'X';
        EXPECT(!qc_looks_like(d) && !qc_problem(d).empty());
        EXPECT(!qc_looks_like(Bytes(good.begin(), good.begin() + 511)));  // (the header is not whole)
        EXPECT(!qc_looks_like(Bytes(good.begin(), good.begin() + 512)));  // (and no data behind it)
        // The pixels cut short: the header is one, the picture is not.
        for (size_t cut = 513; cut < good.size(); cut += 37) {
            const Bytes part(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(cut));
            EXPECT(qc_looks_like(part) && throws([&] { qc_parse(part); }) && !qc_problem(part).empty());
        }
        // A stream of RLE24 that does not make the picture (pixels of 0x7F: a packet of 128 raw pixels, and the next one is cut short).
        {
            Bitmap sevens;
            sevens.width = 16, sevens.height = 16, sevens.bgr = Bytes(768, 0x7F);
            QcSplash seven;
            seven.pictures.push_back(qc_picture(sevens, kQcRaw, false));
            Bytes e = qc_build(seven);
            EXPECT(qc_looks_like(e) && !throws([&] { qc_parse(e); }));
            put32(e, 16, 1);
            EXPECT(qc_looks_like(e) && throws([&] { qc_parse(e); }) && qc_problem(e).find("rle24") != std::string::npos);
        }
        // A table whose offsets are not one behind the other.
        QcSplash t;
        t.several = true;
        t.pictures.push_back(qc_picture(make_bitmap(8, 8, 2), kQcRaw, true));
        t.pictures.push_back(qc_picture(make_bitmap(8, 8, 3), kQcRaw, true));
        Bytes table = qc_build(t);
        EXPECT(qc_looks_like(table));
        put32(table, 12 + 20 + 16, 4096);
        EXPECT(refused(table));
        table = qc_build(t);
        put32(table, 8, 0);  // a count of none: read as a single picture of width 0
        EXPECT(refused(table));
        // The count that is none of the pictures of a table, and the fields that are not a single picture: both readings are told.
        table = qc_build(t);
        put32(table, 12 + 8, 9);  // type 9 in the first entry
        EXPECT(refused(table) && qc_problem(table).find("type 9") != std::string::npos);
    }

    // What is read is built again to the same bytes, whatever damage the header has had (parse() accepted it or refused it).
    {
        const Bitmap b0 = make_bitmap(24, 12, 1), b1 = make_bitmap(30, 9, 5);
        QcSplash s;
        s.several = true;
        s.pictures.push_back(qc_picture(b0, kQcRaw, true));
        s.pictures.push_back(qc_picture(b1, kQcRle24, false));
        const Bytes good = qc_build(s);
        QcSplash one;
        one.pictures.push_back(qc_picture(b1, kQcRle24, false));
        const Bytes good_one = qc_build(one);
        int accepted = 0, refused = 0;
        for (const Bytes& base : {good, good_one})
            for (int round = 0; round < 1500; ++round) {
                Bytes d = base;
                const int flips = 1 + static_cast<int>(next_random() % 3);
                for (int k = 0; k < flips; ++k) d[next_random() % 80] ^= static_cast<uint8_t>(1 + next_random() % 255);
                try {
                    const QcSplash p = qc_parse(d);
                    ++accepted;
                    const Bytes again = qc_build(p);
                    EXPECT(again == Bytes(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(p.consumed)));
                } catch (const FormatError&) {
                    ++refused;
                }
            }
        EXPECT(accepted > 100 && refused > 100);
    }
}

// ----------------------------------------------------------------------------------------------------------------------- OPLUS --

Bytes bmp_file(uint32_t w, uint32_t h, uint8_t seed) {
    // A 24-bit BMP: file header, BITMAPINFOHEADER, rows of w * 3 bytes rounded up to four, bottom row first.
    const uint32_t row = (w * 3 + 3) / 4 * 4;
    Bytes d(54 + size_t{row} * h);
    d[0] = 'B', d[1] = 'M';
    put32(d, 2, static_cast<uint32_t>(d.size()));
    put32(d, 10, 54);
    put32(d, 14, 40);
    put32(d, 18, w);
    put32(d, 22, h);
    d[26] = 1;
    d[28] = 24;
    put32(d, 34, row * h);
    const Bytes px = pattern(size_t{row} * h, seed);
    std::copy(px.begin(), px.end(), d.begin() + 54);
    return d;
}

OplusLogo make_oplus(int count, bool ddph) {
    OplusLogo l;
    l.preamble = Bytes(kOplusPreamble, 0);
    if (ddph) put32(l.preamble, 0, kDdphMagic), put32(l.preamble, 4, 1);
    l.desc = {"OPPO", "", "", "boot logos"};
    l.version = 1, l.width = 1080, l.height = 2400, l.compression = 1;
    for (int i = 0; i < count; ++i) {
        OplusEntry e;
        e.name = "logo_" + std::to_string(i);
        e.data = pattern(100 + i * 331, static_cast<uint8_t>(i * 7));
        e.plain_size = static_cast<uint32_t>(e.data.size() * 3);
        l.entries.push_back(std::move(e));
    }
    return l;
}

void test_oplus() {
    for (bool ddph : {false, true})
        for (int count : {1, 2, 5, 125}) {
            const OplusLogo l = make_oplus(count, ddph);
            const Bytes file = oplus_build(l);
            // The header where the sources have it.
            EXPECT(std::equal(kOplusMagic, kOplusMagic + 12, file.begin() + 0x4000));
            EXPECT(get32(file, 0x410C) == static_cast<uint32_t>(count) && get32(file, 0x4110) == 1 && get32(file, 0x4114) == 1080 && get32(file, 0x4118) == 2400 &&
                   get32(file, 0x411C) == 1);
            EXPECT(get32(file, 0x4120) == 0 && get32(file, 0x4124) == l.entries[0].plain_size && get32(file, 0x4128) == l.entries[0].data.size());
            if (count > 1) EXPECT(get32(file, 0x4120 + 128) == l.entries[0].data.size());
            EXPECT(std::equal(l.entries[0].data.begin(), l.entries[0].data.end(), file.begin() + 0x8000));
            EXPECT(file[0x4000 + 12] == 'O' && file[0x4000 + 12 + 64 * 3] == 'b');
            EXPECT(ddph ? get32(file, 0) == kDdphMagic : get32(file, 0) == 0);
            EXPECT(oplus_looks_like(file) && oplus_problem(file).empty());
            const OplusLogo back = oplus_parse(file);
            EXPECT(back.entries.size() == static_cast<size_t>(count) && back.preamble == l.preamble && back.consumed == file.size());
            EXPECT(back.version == 1 && back.width == 1080 && back.height == 2400 && back.compression == 1);
            EXPECT(back.desc[0] == "OPPO" && back.desc[3] == "boot logos");
            for (int i = 0; i < count; ++i)
                EXPECT(back.entries[i].name == l.entries[i].name && back.entries[i].data == l.entries[i].data && back.entries[i].plain_size == l.entries[i].plain_size);
            EXPECT(oplus_build(back) == file);
        }
    // Text fields keep what follows the zero; the bytes behind the table and in the preamble are kept; an image that goes on (the fill of a partition).
    {
        OplusLogo l = make_oplus(3, true);
        l.desc_tail[1] = {0x41, 0x42};
        l.desc[1] = "x";
        l.entries[1].name_tail = {1, 2, 3};
        l.preamble[0x3FFF] = 9;
        l.header_rest = Bytes(40, 0);
        l.header_rest[39] = 7;
        Bytes file = oplus_build(l);
        file.resize(file.size() + 3000, 0xFF);
        const OplusLogo back = oplus_parse(file);
        EXPECT(back.desc[1] == "x" && back.desc_tail[1] == l.desc_tail[1] && back.entries[1].name_tail == l.entries[1].name_tail);
        EXPECT(back.preamble[0x3FFF] == 9 && back.header_rest == l.header_rest);
        EXPECT(oplus_build(back) == Bytes(file.begin(), file.begin() + static_cast<std::ptrdiff_t>(back.consumed)));
        EXPECT(back.consumed == file.size() - 3000);
        // A picture that changes its size moves the ones behind it, and the table says so.
        OplusLogo grown = back;
        grown.entries[0].data.resize(5000, 3);
        grown.entries[0].plain_size = 6000;
        const Bytes grown_file = oplus_build(grown);
        const OplusLogo grown_back = oplus_parse(grown_file);
        EXPECT(grown_back.entries[0].data.size() == 5000 && grown_back.entries[1].data == back.entries[1].data && grown_back.entries[0].plain_size == 6000);
        EXPECT(get32(grown_file, 0x4120 + 128) == 5000);
    }
    // Refusals.
    {
        const Bytes good = oplus_build(make_oplus(3, false));
        const auto refused = [&](const Bytes& d) { return !oplus_looks_like(d) && throws([&] { oplus_parse(d); }) && !oplus_problem(d).empty(); };
        EXPECT(refused(Bytes(100, 0)));
        EXPECT(refused(Bytes(0x9000, 0)));
        Bytes d = good;
        d[0x4005] = 'x';
        EXPECT(refused(d));
        d = good, put32(d, 0x410C, 0);
        EXPECT(refused(d));
        d = good, put32(d, 0x410C, 126);
        EXPECT(refused(d));
        d = good, put32(d, 0x4120 + 128, 5);  // not right behind the one before it
        EXPECT(refused(d));
        d = good, put32(d, 0x4128, 1 << 20);  // a picture that goes beyond the file
        EXPECT(refused(d));
        d = Bytes(good.begin(), good.end() - 1);  // the last picture cut short
        EXPECT(refused(d));
        OplusLogo none;
        EXPECT(throws([&] { oplus_build(none); }));
        OplusLogo many = make_oplus(126, false);
        EXPECT(throws([&] { oplus_build(many); }));
        OplusLogo big_preamble = make_oplus(1, false);
        big_preamble.preamble.resize(kOplusPreamble + 1);
        EXPECT(throws([&] { oplus_build(big_preamble); }));
        OplusLogo big_rest = make_oplus(125, false);
        big_rest.header_rest = Bytes(400, 1);
        EXPECT(throws([&] { oplus_build(big_rest); }));
    }
    // What is read from a damaged header is built again to the same bytes.
    {
        const Bytes good = oplus_build(make_oplus(4, true));
        int accepted = 0, refused = 0;
        for (int round = 0; round < 1500; ++round) {
            Bytes d = good;
            const int flips = 1 + static_cast<int>(next_random() % 3);
            for (int k = 0; k < flips; ++k) d[0x4000 + next_random() % 700] ^= static_cast<uint8_t>(1 + next_random() % 255);
            try {
                const OplusLogo p = oplus_parse(d);
                ++accepted;
                EXPECT(oplus_build(p) == Bytes(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(p.consumed)));
            } catch (const FormatError&) {
                ++refused;
            }
        }
        EXPECT(accepted > 100 && refused > 100);
    }
}

// ---------------------------------------------------------------------------------------------------------------------- Xiaomi --

XiaomiLogo make_xiaomi(int count) {
    XiaomiLogo l;
    l.preamble = Bytes(kXiaomiPreamble, 0);
    for (int i = 0; i < count; ++i) {
        Bytes bmp = bmp_file(20 + i * 7, 10 + i, static_cast<uint8_t>(i));
        bmp.resize(static_cast<size_t>(align_up(bmp.size(), kXiaomiUnit)), 0);
        l.pictures.push_back(std::move(bmp));
    }
    return l;
}

void test_xiaomi() {
    for (int count : {1, 2, 6, 511}) {
        XiaomiLogo l = make_xiaomi(count > 20 ? 1 : count);
        if (count > 20) l.pictures.assign(static_cast<size_t>(count), Bytes(kXiaomiUnit, 7));
        const Bytes file = xiaomi_build(l);
        EXPECT(std::equal(kXiaomiMagic, kXiaomiMagic + 8, file.begin() + 0x4000));
        EXPECT(get32(file, 0x4008) == 5 && get32(file, 0x400C) == l.pictures[0].size() / 4096);  // the first picture at 0x5000
        if (count > 1) EXPECT(get32(file, 0x4010) == 5 + l.pictures[0].size() / 4096);
        if (count < 511) EXPECT(get32(file, 0x4008 + 8 * count) == 0);
        EXPECT(xiaomi_looks_like(file) && xiaomi_problem(file).empty());
        const XiaomiLogo back = xiaomi_parse(file);
        EXPECT(back.pictures.size() == l.pictures.size() && back.pictures == l.pictures && back.preamble == l.preamble && back.consumed == file.size());
        EXPECT(xiaomi_build(back) == file);
    }
    // Pictures that are not whole units are padded with zeros; the fill of a partition behind; the bytes behind the entries.
    {
        XiaomiLogo l;
        l.preamble = Bytes(kXiaomiPreamble, 0);
        l.preamble[100] = 5;
        l.pictures = {bmp_file(30, 30, 1), Bytes(10000, 0x33)};
        l.table_rest = Bytes(20, 0);
        l.table_rest[19] = 0x77;
        Bytes file = xiaomi_build(l);
        EXPECT(file.size() == 0x5000 + 4096 * 1 + 4096 * 3);  // (the BMP of 30 x 30 is 2814 bytes)
        EXPECT(get32(file, 0x400C) == 1 && get32(file, 0x4014) == 3);
        file.resize(file.size() + (size_t{1} << 20), 0);
        file.resize(file.size() + 4096, 0xFF);
        const XiaomiLogo back = xiaomi_parse(file);
        EXPECT(back.pictures.size() == 2 && back.pictures[0].size() == 4096 && back.pictures[1].size() == 3 * 4096);
        EXPECT(back.preamble[100] == 5 && back.table_rest == l.table_rest);
        EXPECT(back.consumed == 0x5000 + 4 * 4096);
        EXPECT(xiaomi_build(back) == Bytes(file.begin(), file.begin() + static_cast<std::ptrdiff_t>(back.consumed)));
        // A bigger picture moves the next.
        XiaomiLogo grown = back;
        grown.pictures[0] = Bytes(9000, 1);
        const XiaomiLogo again = xiaomi_parse(xiaomi_build(grown));
        EXPECT(again.pictures[0].size() == 3 * 4096 && again.pictures[1] == back.pictures[1]);
    }
    // The size of a picture inside its units: a BMP by its header, a PNG by IEND, anything else whole, nothing when what follows is not zero.
    {
        Bytes bmp = bmp_file(30, 30, 3);
        const size_t real = bmp.size();
        bmp.resize(4096, 0);
        EXPECT(xiaomi_content_size(bmp) == real);
        bmp[4000] = 1;
        EXPECT(xiaomi_content_size(bmp) == 4096);
        Bytes png = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
        const Bytes chunk_a = {0, 0, 0, 3, 'I', 'D', 'A', 'T', 1, 2, 3, 9, 9, 9, 9};
        const Bytes iend = {0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82};
        png.insert(png.end(), chunk_a.begin(), chunk_a.end());
        png.insert(png.end(), iend.begin(), iend.end());
        const size_t png_real = png.size();
        png.resize(8192, 0);
        EXPECT(xiaomi_content_size(png) == png_real);
        png[8000] = 2;
        EXPECT(xiaomi_content_size(png) == 8192);
        EXPECT(xiaomi_content_size(Bytes(5000, 0)) == 5000);
        EXPECT(xiaomi_content_size(Bytes{}) == 0);
        Bytes lying = bmp_file(30, 30, 3);
        put32(lying, 2, 99999);  // a size beyond the data
        EXPECT(xiaomi_content_size(lying) == lying.size());
        put32(lying, 2, 0);
        EXPECT(xiaomi_content_size(lying) == lying.size());
        Bytes cut_png(png.begin(), png.begin() + 20);  // a chunk that runs past the end
        EXPECT(xiaomi_content_size(cut_png) == 20);
    }
    // Refusals.
    {
        const Bytes good = xiaomi_build(make_xiaomi(3));
        const auto refused = [&](const Bytes& d) { return !xiaomi_looks_like(d) && throws([&] { xiaomi_parse(d); }) && !xiaomi_problem(d).empty(); };
        EXPECT(refused(Bytes(100, 0)));
        EXPECT(refused(Bytes(0x6000, 0)));
        Bytes d = good;
        d[0x4003] = 'X';
        EXPECT(refused(d));
        d = good, put32(d, 0x4008, 6);  // the first picture not at the end of the table
        EXPECT(refused(d));
        d = good, put32(d, 0x4008 + 8, 99);  // not right behind
        EXPECT(refused(d));
        d = good, put32(d, 0x400C, 1000);  // beyond the file
        EXPECT(refused(d));
        d = good, put32(d, 0x4008, 0);  // no picture
        EXPECT(refused(d));
        d = Bytes(good.begin(), good.end() - 1);
        EXPECT(refused(d));
        XiaomiLogo none;
        EXPECT(throws([&] { xiaomi_build(none); }));
        XiaomiLogo many;
        many.pictures.assign(512, Bytes(1, 0));
        EXPECT(throws([&] { xiaomi_build(many); }));
        XiaomiLogo rest = make_xiaomi(511);
        rest.table_rest = Bytes(5, 1);
        EXPECT(throws([&] { xiaomi_build(rest); }));
    }
    // What is read from a damaged table is built again to the same bytes.
    {
        const Bytes good = xiaomi_build(make_xiaomi(5));
        int accepted = 0, refused = 0;
        for (int round = 0; round < 1500; ++round) {
            Bytes d = good;
            const int flips = 1 + static_cast<int>(next_random() % 3);
            for (int k = 0; k < flips; ++k) d[0x4000 + next_random() % 80] ^= static_cast<uint8_t>(1 + next_random() % 255);
            try {
                const XiaomiLogo p = xiaomi_parse(d);
                ++accepted;
                EXPECT(xiaomi_build(p) == Bytes(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(p.consumed)));
            } catch (const FormatError&) {
                ++refused;
            }
        }
        EXPECT(accepted > 100 && refused > 100);
    }
}

// --------------------------------------------------------------------------------------------------------------------- Motorola --

MotoLogo make_moto(std::initializer_list<size_t> sizes, uint32_t align = 512, uint8_t header_fill = 0xFF, uint8_t gap_fill = 0xFF) {
    MotoLogo l;
    l.align = align, l.header_fill = header_fill, l.gap_fill = gap_fill;
    int i = 0;
    for (size_t n : sizes) {
        MotoEntry e;
        e.name = "logo_" + std::to_string(i);
        if (n) e.data = pattern(n, static_cast<uint8_t>(i * 11 + 1));
        l.entries.push_back(std::move(e));
        ++i;
    }
    return l;
}

void test_moto_container() {
    // The header of a real image (the dump in the source of moto-bootlogo): three pictures, "logo_boot", "logo_battery", "logo_unlocked".
    {
        static const uint8_t kDump[112] = {
            0x4d, 0x6f, 0x74, 0x6f, 0x4c, 0x6f, 0x67, 0x6f, 0x00, 0x6d, 0x00, 0x00, 0x00, 0x6c, 0x6f, 0x67, 0x6f, 0x5f, 0x62, 0x6f, 0x6f, 0x74, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0xa5, 0x20, 0x07, 0x00, 0x6c, 0x6f, 0x67,
            0x6f, 0x5f, 0x62, 0x61, 0x74, 0x74, 0x65, 0x72, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x07,
            0x00, 0x04, 0x33, 0x00, 0x00, 0x6c, 0x6f, 0x67, 0x6f, 0x5f, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x07, 0x00, 0x77, 0x77, 0x00, 0x00, 0xff, 0xff, 0xff};
        MotoLogo l;
        const char* names[] = {"logo_boot", "logo_battery", "logo_unlocked"};
        const size_t sizes[] = {0x720a5, 0x3304, 0x7777};
        for (int i = 0; i < 3; ++i) {
            MotoEntry e;
            e.name = names[i];
            e.data = pattern(sizes[i], static_cast<uint8_t>(i));
            l.entries.push_back(std::move(e));
        }
        const Bytes file = moto_build(l);
        EXPECT(std::equal(kDump, kDump + 112, file.begin()));
        EXPECT(std::all_of(file.begin() + 112, file.begin() + 512, [](uint8_t v) { return v == 0xFF; }));
        EXPECT(get32(file, 37) == 0x200 && get32(file, 69) == 0x72400 && get32(file, 101) == 0x75800);
        EXPECT(file.size() == 0x75800 + 0x7777);
        const MotoLogo back = moto_parse(file);
        EXPECT(back.align == 512 && back.header_fill == 0xFF && back.entries.size() == 3 && back.consumed == file.size());
        EXPECT(back.entries[1].name == "logo_battery" && back.entries[2].data == l.entries[2].data);
        EXPECT(moto_build(back) == file);
        // (the bytes between the pictures are a fill of one byte)
        Bytes zeros = file;
        std::fill(zeros.begin() + 0x200 + 0x720a5, zeros.begin() + 0x72400, 0);
        std::fill(zeros.begin() + 0x72400 + 0x3304, zeros.begin() + 0x75800, 0);
        const MotoLogo zero_gap = moto_parse(zeros);
        EXPECT(zero_gap.gap_fill == 0 && zero_gap.header_fill == 0xFF && moto_build(zero_gap) == zeros);
    }
    // Alignments, fills, an empty slot, a picture that grows.
    for (uint32_t align : {16u, 512u, 4096u, 65536u}) {
        for (uint8_t fill : {uint8_t{0xFF}, uint8_t{0}}) {
            const MotoLogo l = make_moto({700, 0, 1300, 20}, align, fill, fill);
            const Bytes file = moto_build(l);
            EXPECT(moto_looks_like(file) && moto_problem(file).empty());
            const MotoLogo back = moto_parse(file);
            EXPECT(back.entries.size() == 4 && back.align == align && back.header_fill == fill && back.gap_fill == fill);
            EXPECT(back.entries[1].data.empty() && back.entries[1].name == "logo_1" && back.entries[2].data == l.entries[2].data);
            EXPECT(moto_build(back) == file);
            EXPECT(get32(file, 13 + 32 + 24) == 0 && get32(file, 13 + 32 + 28) == 0);  // the empty slot has no offset and no size
            MotoLogo grown = back;
            grown.entries[0].data.resize(5000, 9);
            const Bytes grown_file = moto_build(grown);
            const MotoLogo again = moto_parse(grown_file);
            EXPECT(again.entries[0].data.size() == 5000 && again.entries[2].data == back.entries[2].data && again.align == align);
            EXPECT(get32(grown_file, 13 + 64 + 24) % align == 0);
        }
    }
    // Names keep what follows their zero.
    {
        MotoLogo l = make_moto({600, 600});
        l.entries[0].name_tail = {9, 9};
        const Bytes file = moto_build(l);
        const MotoLogo back = moto_parse(file);
        EXPECT(back.entries[0].name_tail == l.entries[0].name_tail && moto_build(back) == file);
    }
    // Refusals.
    {
        const Bytes good = moto_build(make_moto({600, 700, 800}));
        const auto refused = [&](const Bytes& d) { return !moto_looks_like(d) && throws([&] { moto_parse(d); }) && !moto_problem(d).empty(); };
        EXPECT(refused(Bytes(10, 0)));
        Bytes d = good;
        d[2] = 'x';
        EXPECT(refused(d));
        d = good, put32(d, 9, 14);  // a table size that is no 13 + 32n
        EXPECT(refused(d));
        d = good, put32(d, 9, 13);
        EXPECT(refused(d));
        d = good, put32(d, 9, 5000000);
        EXPECT(refused(d));
        d = good, put32(d, 13 + 24, 0);  // a size but no offset
        EXPECT(refused(d));
        d = good, put32(d, 13 + 28, 0);  // an offset but no size
        EXPECT(refused(d));
        d = good, put32(d, 13 + 24, 20);  // a picture inside the table
        EXPECT(refused(d));
        d = good, put32(d, 13 + 28, 1 << 20);  // beyond the file
        EXPECT(refused(d));
        d = good, put32(d, 13 + 32 + 24, get32(good, 13 + 24) + 4);  // the second begins inside the first
        EXPECT(refused(d));
        d = good, put32(d, 13 + 32 + 24, get32(good, 13 + 32 + 24) + 1);  // not at a multiple of any alignment
        EXPECT(refused(d));
        d = good, d[200] = 0x12;  // the fill between the table and the first picture is not one byte
        EXPECT(refused(d));
        d = good, d[get32(good, 13 + 24) + get32(good, 13 + 28) + 2] = 0x44, d[get32(good, 13 + 24) + get32(good, 13 + 28) + 3] = 0x45;  // nor is the gap
        EXPECT(refused(d));
        MotoLogo none;
        EXPECT(throws([&] { moto_build(none); }));
        MotoLogo empties = make_moto({0, 0});
        EXPECT(throws([&] { moto_build(empties); }));
        MotoLogo bad_align = make_moto({100});
        bad_align.align = 500;
        EXPECT(throws([&] { moto_build(bad_align); }));
    }
    // What is read from a damaged table is built again to the same bytes.
    {
        const Bytes good = moto_build(make_moto({600, 0, 700, 800}));
        int accepted = 0, refused = 0;
        for (int round = 0; round < 3000; ++round) {
            Bytes d = good;
            const int flips = 1 + static_cast<int>(next_random() % 3);
            for (int k = 0; k < flips; ++k) d[next_random() % 200] ^= static_cast<uint8_t>(1 + next_random() % 255);
            try {
                const MotoLogo p = moto_parse(d);
                ++accepted;
                EXPECT(moto_build(p) == Bytes(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(p.consumed)));
            } catch (const FormatError&) {
                ++refused;
            }
        }
        EXPECT(accepted > 50 && refused > 100);
    }
}

// ------------------------------------------------------------------------------------------------------------------- the others --

void test_detection() {
    QcSplash qs;
    qs.pictures.push_back(qc_picture(make_bitmap(30, 30, 2), kQcRaw, false));
    const Bytes qc = qc_build(qs);
    QcSplash qm;
    qm.several = true;
    qm.pictures.push_back(qc_picture(make_bitmap(30, 30, 2), kQcRle24, true));
    qm.pictures.push_back(qc_picture(make_bitmap(10, 10, 3), kQcRaw, false));
    const Bytes qc_many = qc_build(qm);
    const Bytes oplus = oplus_build(make_oplus(3, true));
    const Bytes xiaomi = xiaomi_build(make_xiaomi(3));
    const Bytes moto = moto_build(make_moto({600, 700}));
    const std::vector<Bytes> zeros = {Bytes(), Bytes(100, 0), Bytes(0x10000, 0), Bytes(0x10000, 0xFF), pattern(0x10000, 3)};
    for (const Bytes& d : {qc, qc_many}) EXPECT(qc_looks_like(d) && !oplus_looks_like(d) && !xiaomi_looks_like(d) && !moto_looks_like(d));
    EXPECT(!qc_looks_like(oplus) && oplus_looks_like(oplus) && !xiaomi_looks_like(oplus) && !moto_looks_like(oplus));
    EXPECT(!qc_looks_like(xiaomi) && !oplus_looks_like(xiaomi) && xiaomi_looks_like(xiaomi) && !moto_looks_like(xiaomi));
    EXPECT(!qc_looks_like(moto) && !oplus_looks_like(moto) && !xiaomi_looks_like(moto) && moto_looks_like(moto));
    for (const Bytes& d : zeros) EXPECT(!qc_looks_like(d) && !oplus_looks_like(d) && !xiaomi_looks_like(d) && !moto_looks_like(d));
    EXPECT(picture_extension(bmp_file(4, 4, 1)) == "bmp");
    EXPECT(picture_extension(Bytes{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 0}) == "png");
    EXPECT(picture_extension(Bytes{0xFF, 0xD8, 0xFF, 0xE0}) == "jpg");
    EXPECT(picture_extension(Bytes{'B', 'M'}) == "bin" && picture_extension(Bytes(30, 1)) == "bin" && picture_extension(Bytes{}) == "bin");
}

}  // namespace

int run_splash_tests() {
    test_rle24();
    test_moto();
    test_bitmap();
    test_qc();
    test_oplus();
    test_xiaomi();
    test_moto_container();
    test_detection();
    if (g_failures == 0) std::printf("splash: ok (%d checks)\n", g_checks);
    else std::printf("splash: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
