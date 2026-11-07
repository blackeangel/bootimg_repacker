// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of detect_level() (abr/compression.hpp): what level a stream was made with, from its header or by making it again. Run by
// tests/run_tests.sh as `abr_unit_tests levels`.
//
//   * bzip2 says its level in the header, gzip says "densest" and "fastest" (9 and 1), gzip with no mark is found at level 6 when abr's
//     deflate makes the same data, and not found (-1) when it was made at a level in between;
//   * a gzip header with a name in it (FNAME) does not confuse where the deflate data begins;
//   * lz4_legacy: the level found makes the very stream (compress() at it equals the stream), one block or several, with bytes behind it;
//   * zstd: frames made by the library on one thread (the command line) with and without the content checksum, and by compress() (abr);
//   * zlib (what a MediaTek logo.bin holds): the group in the header, the level in the group by making the stream again; xz: the dictionary of
//     the first block names the preset, and the one at which the stream is made again the same is the level;
//   * the settings of a "LZMA alone" stream (lzma_alone_params(): known and unknown size, other lc/lp/pb, a dictionary of 2^n + 2^(n-1)), a stream
//     made again with them, and data that merely begins like one is not taken for it;
//   * what cannot be known (lzma, lz4 frame, lzo, no codec) is -1; nothing breaks on empty, damaged or cut streams.
#include <zstd.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "abr/compression.hpp"

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

// Text-like data that compresses unevenly: words from a small list in a pseudo-random order, here and there a run of one byte.
Bytes text(size_t n, uint32_t seed) {
    static const char* const words[] = {"android", "boot", "ramdisk", "kernel", "init", "service", "property", "mount", "/system/bin/", "setprop",
                                        "on", "early-init", "chmod", "0755", "symlink", "write", "/sys/class/", "trigger", "exec", "class_start"};
    Bytes out;
    out.reserve(n + 32);
    uint32_t x = seed * 2654435761u + 1;
    while (out.size() < n) {
        x = x * 1664525u + 1013904223u;
        const std::string w = words[(x >> 16) % 20];
        out.insert(out.end(), w.begin(), w.end());
        out.push_back((x >> 8) % 7 == 0 ? '\n' : ' ');
        if ((x >> 20) % 97 == 0) out.insert(out.end(), 40 + (x >> 24) % 60, static_cast<uint8_t>(x & 0x3f));
        if ((x >> 12) % 5 == 0) out.push_back(static_cast<uint8_t>(x >> 4));  // a little noise
    }
    out.resize(n);
    return out;
}

void test_gzip() {
    const Bytes data = text(1500000, 1);
    const LevelGuess nine = detect_level(Codec::GZIP, compress(Codec::GZIP, data, 9), data);
    EXPECT(nine.level == 9 && !nine.basis.empty());
    const LevelGuess one = detect_level(Codec::GZIP, compress(Codec::GZIP, data, 1), data);
    EXPECT(one.level == 1);
    const Bytes six = compress(Codec::GZIP, data, 6);
    EXPECT(detect_level(Codec::GZIP, six, data).level == 6);
    EXPECT(detect_level(Codec::GZIP, compress(Codec::GZIP, data, -1), data).level == 6);  // the default is 6
    for (int level : {2, 3, 4, 5, 7, 8}) EXPECT(detect_level(Codec::GZIP, compress(Codec::GZIP, data, level), data).level == -1);  // (no mark, not 6)

    // a header with a name (FNAME) and a comment (FCOMMENT) and an extra field (FEXTRA): the data begins later, the level is the same
    Bytes named(six.begin(), six.begin() + 10);
    named[3] = 0x04 | 0x08 | 0x10;
    named.push_back(3);  // xlen
    named.push_back(0);
    named.insert(named.end(), {'a', 'b', 'c'});
    for (char c : std::string("boot.cpio")) named.push_back(static_cast<uint8_t>(c));
    named.push_back(0);
    for (char c : std::string("a comment")) named.push_back(static_cast<uint8_t>(c));
    named.push_back(0);
    named.insert(named.end(), six.begin() + 10, six.end());
    EXPECT(detect_level(Codec::GZIP, named, data).level == 6);
    // bytes behind the stream (padding to a block) do not matter
    Bytes padded = six;
    padded.resize(padded.size() + 100, 0);
    EXPECT(detect_level(Codec::GZIP, padded, data).level == 6);
    // other data than the stream holds: not made again
    Bytes other = data;
    other[1000] ^= 0x55;
    EXPECT(detect_level(Codec::GZIP, six, other).level == -1);
    // too big to try: the header is all there is
    EXPECT(detect_level(Codec::GZIP, six, Bytes(20u << 20, 7)).level == -1);
    // short and damaged
    for (size_t n : {size_t{0}, size_t{1}, size_t{2}, size_t{9}, size_t{10}, size_t{17}, size_t{18}, size_t{30}}) {
        Bytes cut(six.begin(), six.begin() + static_cast<long>(std::min(n, six.size())));
        (void)detect_level(Codec::GZIP, cut, data);
    }
    Bytes bad = six;
    bad[3] = 0xff;  // all the optional fields, which are not there
    (void)detect_level(Codec::GZIP, bad, data);
    EXPECT(detect_level(Codec::GZIP, six, Bytes()).level == -1);
}

void test_bzip2() {
    const Bytes data = text(300000, 2);
    for (int level : {1, 3, 9}) {
        const LevelGuess g = detect_level(Codec::BZIP2, compress(Codec::BZIP2, data, level), data);
        EXPECT(g.level == level);
    }
    EXPECT(detect_level(Codec::BZIP2, Bytes{'B', 'Z', 'h', '0'}, data).level == -1);
    EXPECT(detect_level(Codec::BZIP2, Bytes{'B', 'Z', 'h'}, data).level == -1);
}

void test_lz4_legacy() {
    const Bytes data = text(1200000, 3);
    for (int level : {12, 9, 4, 3, 1}) {
        const Bytes stream = compress(Codec::LZ4_LEGACY, data, level);
        const LevelGuess g = detect_level(Codec::LZ4_LEGACY, stream, data);
        EXPECT(g.level >= 1);
        EXPECT(g.level >= 1 && compress(Codec::LZ4_LEGACY, data, g.level) == stream);  // whichever level it says, it makes this stream
        if (level == 12 || level == 4) EXPECT(g.level == level);
    }
    {
        // the kernel's form: the size of the plain data behind the last block
        Bytes stream = compress(Codec::LZ4_LEGACY, data, 9);
        stream.insert(stream.end(), {0x40, 0x4f, 0x12, 0x00});
        EXPECT(detect_level(Codec::LZ4_LEGACY, stream, data).level >= 1);
    }
    {
        // two blocks (the first is 8 MiB): the first block is what is told
        Bytes big = text(9u << 20, 4);
        const Bytes stream = compress(Codec::LZ4_LEGACY, big, 3);
        const LevelGuess g = detect_level(Codec::LZ4_LEGACY, stream, big);
        EXPECT(g.level >= 1);
        EXPECT(g.level >= 1 && compress(Codec::LZ4_LEGACY, big, g.level) == stream);
    }
    EXPECT(detect_level(Codec::LZ4_LEGACY, compress(Codec::LZ4_LEGACY, data, 9), text(1200000, 5)).level == -1);  // not this data
    const Bytes whole = compress(Codec::LZ4_LEGACY, data, 9);
    for (size_t n : {size_t{0}, size_t{4}, size_t{8}, size_t{11}, size_t{12}, size_t{40}}) (void)detect_level(Codec::LZ4_LEGACY, Bytes(whole.begin(), whole.begin() + static_cast<long>(n)), data);
    Bytes lying = whole;
    lying[4] = lying[5] = lying[6] = lying[7] = 0xff;  // a first block longer than the stream
    EXPECT(detect_level(Codec::LZ4_LEGACY, lying, data).level == -1);
}

// A frame as the zstd command line makes it: one thread, the size of the data known, a checksum or none.
Bytes zstd_frame(const Bytes& data, int level, bool checksum) {
    ZSTD_CCtx* c = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, level);
    ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, checksum ? 1 : 0);
    Bytes out(ZSTD_compressBound(data.size()));
    const size_t n = ZSTD_compress2(c, out.data(), out.size(), data.data(), data.size());
    ZSTD_freeCCtx(c);
    out.resize(n);
    return out;
}

void test_zstd() {
    const Bytes data = text(900000, 6);
    for (bool checksum : {false, true}) {
        for (int level : {3, 19, 7}) {
            const Bytes frame = zstd_frame(level == 19 ? Bytes(data.begin(), data.begin() + 300000) : data, level, checksum);
            const Bytes plain = level == 19 ? Bytes(data.begin(), data.begin() + 300000) : data;
            const LevelGuess g = detect_level(Codec::ZSTD, frame, plain);
            EXPECT(g.level >= 1);
            if (g.level >= 1) {
                // whichever level it says, the library at it makes this frame (a stream that is all there is to see) or its start
                const Bytes again = zstd_frame(plain, g.level, checksum);
                EXPECT(again == frame || std::equal(again.begin(), again.begin() + 1000, frame.begin()));
            }
            if (level == 7 || level == 3) EXPECT(g.level == level);
        }
    }
    {
        // what compress() makes: found at the levels abr picks itself (3 by default, 19 when dense), or told so
        for (int level : {-1, 3, 19}) {
            const Bytes plain(data.begin(), data.begin() + 400000);
            const Bytes stream = compress(Codec::ZSTD, plain, level);
            const LevelGuess g = detect_level(Codec::ZSTD, stream, plain);
            std::printf("    compress() at %d: found %d (%s)\n", level, g.level, g.basis.c_str());
            EXPECT(g.level == (level < 0 ? 3 : level));
        }
    }
    EXPECT(detect_level(Codec::ZSTD, zstd_frame(data, 3, false), text(900000, 7)).level == -1);
    EXPECT(detect_level(Codec::ZSTD, Bytes{0x28, 0xb5, 0x2f, 0xfd}, data).level == -1);
    EXPECT(detect_level(Codec::ZSTD, Bytes{0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x00}, data).level == -1);
    EXPECT(detect_level(Codec::ZSTD, zstd_frame(data, 3, false), Bytes()).level == -1);
}

void test_zlib() {
    const Bytes data = text(700000, 9);
    for (const int level : {1, 6, 9}) {
        const Bytes stream = compress(Codec::ZLIB, data, level);
        EXPECT(stream.size() > 6 && stream[0] == 0x78);
        EXPECT(decompress(Codec::ZLIB, stream) == data);
        EXPECT(detect_codec(stream) == Codec::NONE);  // (it starts like any data: only a format that knows says it is one)
        const LevelGuess g = detect_level(Codec::ZLIB, stream, data);
        EXPECT(g.level == level && !g.basis.empty());
    }
    EXPECT(compress(Codec::ZLIB, data, -1) == compress(Codec::ZLIB, data, 6));
    EXPECT(default_level(Codec::ZLIB) == 6 && dense_level(Codec::ZLIB) == 9);
    EXPECT(codec_from_name("zlib") == Codec::ZLIB && codec_name(Codec::ZLIB) == "zlib");
    // bytes behind the stream (the padding of a table of pictures) do not matter to the reading or to the level
    Bytes padded = compress(Codec::ZLIB, data, 9);
    padded.insert(padded.end(), 37, 0xFF);
    EXPECT(decompress(Codec::ZLIB, padded) == data);
    EXPECT(detect_level(Codec::ZLIB, padded, data).level == 9);
    // another level in the group (7, a stream abr's table does not name by its header): the group says 9 and the basis says why
    const Bytes seven = compress(Codec::ZLIB, data, 7);
    EXPECT(detect_level(Codec::ZLIB, seven, data).level == 7);
    // a stream that does not match what it is said to hold: the header's group
    const LevelGuess other = detect_level(Codec::ZLIB, compress(Codec::ZLIB, data, 9), text(700000, 10));
    EXPECT(other.level == 9 && other.basis.find("header") != std::string::npos);
    EXPECT(detect_level(Codec::ZLIB, Bytes{0x78, 0x9c}, data).level == -1);
    EXPECT(detect_level(Codec::ZLIB, Bytes{0x78, 0x9d, 1, 2, 3, 4, 5, 6}, data).level == -1);  // (not a zlib header: FCHECK)
    EXPECT(detect_level(Codec::ZLIB, Bytes(), Bytes()).level == -1);
    // empty data is a stream of its own
    EXPECT(decompress(Codec::ZLIB, compress(Codec::ZLIB, Bytes(), 6)).empty());
}

void test_xz() {
    const Bytes data = text(300000, 11);
    for (const int level : {0, 1, 2, 6}) {
        const Bytes stream = compress(Codec::XZ, data, level);
        const LevelGuess g = detect_level(Codec::XZ, stream, data);
        EXPECT(g.level == level && !g.basis.empty());
    }
    // 3 and 5 have the dictionary of 4 and 6: the stream names the pair, and the trial finds which of the two made it
    for (const int level : {3, 4, 5}) EXPECT(detect_level(Codec::XZ, compress(Codec::XZ, data, level), data).level == level);
    // what the encoder of another program made (here: the check is another) is not the same bytes, but the dictionary still names the level
    Bytes crc64 = compress(Codec::XZ, data, 6);
    crc64[7] = 0x04;  // the check type in the stream flags (this is no longer a valid stream, and nobody decompresses it)
    const LevelGuess g = detect_level(Codec::XZ, crc64, data);
    EXPECT(g.level == 6 && g.basis.find("dictionary") != std::string::npos);
    EXPECT(detect_level(Codec::XZ, Bytes(), Bytes()).level == -1);
    EXPECT(detect_level(Codec::XZ, Bytes{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, data).level == -1);
    EXPECT(detect_level(Codec::XZ, compress(Codec::XZ, data, 6), Bytes()).level == 6);  // (nothing to make it again from: the dictionary alone)
}

Bytes alone_header(uint8_t props, uint32_t dict, uint64_t size, uint8_t first = 0, size_t extra = 20) {
    Bytes b{props, uint8_t(dict), uint8_t(dict >> 8), uint8_t(dict >> 16), uint8_t(dict >> 24)};
    for (int i = 0; i < 8; ++i) b.push_back(uint8_t(size >> (8 * i)));
    b.push_back(first);
    b.insert(b.end(), extra, 0x41);
    return b;
}

void test_lzma_alone() {
    const Bytes data = text(120000, 12);
    // the stream abr makes: lc 3, lp 0, pb 2, 8 MiB, size unknown
    const Bytes made = compress(Codec::LZMA, data);
    const auto p = lzma_alone_params(made);
    EXPECT(p && p->lc == 3 && p->lp == 0 && p->pb == 2 && p->dict_size == (8u << 20) && !p->size_known);
    EXPECT(detect_codec(made) == Codec::LZMA);
    // other settings come back, and a stream made with them has them
    for (const LzmaAloneParams want : {LzmaAloneParams{0, 2, 0, 1u << 16, false}, LzmaAloneParams{4, 0, 4, 3u << 20, false}, LzmaAloneParams{3, 0, 2, 1u << 24, false}}) {
        const Bytes stream = lzma_alone_compress(data, want);
        const auto got = lzma_alone_params(stream);
        EXPECT(got && got->lc == want.lc && got->lp == want.lp && got->pb == want.pb && got->dict_size == want.dict_size);
        EXPECT(decompress(Codec::LZMA, stream) == data);
    }
    // a header that holds the size (an `lzma file` stream, or the modem of a phone): taken, with the size flag
    const auto known = lzma_alone_params(alone_header(0x5d, 0x01000000, 123456));
    EXPECT(known && known->size_known && known->dict_size == 0x01000000);
    EXPECT(detect_codec(alone_header(0x5d, 0x01000000, 123456)) == Codec::LZMA);
    // ... and a dictionary of 2^n + 2^(n-1)
    EXPECT(lzma_alone_params(alone_header(0x5d, 3u << 20, UINT64_MAX)).has_value());
    // data that begins like one is not one: a dictionary that is neither, a properties byte out of range, a size that is too big, a first byte that is not zero
    EXPECT(!lzma_alone_params(alone_header(0x5d, 0x01000001, UINT64_MAX)));
    EXPECT(!lzma_alone_params(alone_header(0x5d, 1024, UINT64_MAX)));
    EXPECT(!lzma_alone_params(alone_header(225, 1u << 20, UINT64_MAX)));
    EXPECT(!lzma_alone_params(alone_header(0x5d, 1u << 20, uint64_t{1} << 40)));
    EXPECT(!lzma_alone_params(alone_header(0x5d, 1u << 20, UINT64_MAX, 1)));
    EXPECT(!lzma_alone_params(Bytes(13, 0x5d)));
    EXPECT(!lzma_alone_params(Bytes()));
    EXPECT(detect_codec(alone_header(0x5d, 0x01000001, UINT64_MAX)) == Codec::NONE);
    // (an ASCII text that starts with "]" is not a stream either)
    EXPECT(detect_codec(Bytes{']', ' ', 't', 'e', 'x', 't', ' ', 'o', 'f', ' ', 'a', ' ', 'f', 'i', 'l', 'e', '.', '\n'}) == Codec::NONE);
}

void test_unknown() {
    const Bytes data = text(200000, 8);
    for (Codec c : {Codec::LZMA, Codec::LZ4, Codec::LZO, Codec::NONE}) EXPECT(detect_level(c, compress(c, data), data).level == -1);
    EXPECT(detect_level(Codec::LZMA, Bytes(), Bytes()).level == -1);
}

}  // namespace

int run_levels_tests() {
    test_gzip();
    test_bzip2();
    test_lz4_legacy();
    test_zstd();
    test_zlib();
    test_xz();
    test_lzma_alone();
    test_unknown();
    if (g_failures == 0) std::printf("levels: ok (%d checks)\n", g_checks);
    else std::printf("levels: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
