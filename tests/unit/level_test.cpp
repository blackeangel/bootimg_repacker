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
//   * what cannot be known (xz, lzma, lz4 frame, lzo, no codec) is -1; nothing breaks on empty, damaged or cut streams.
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

void test_unknown() {
    const Bytes data = text(200000, 8);
    for (Codec c : {Codec::XZ, Codec::LZMA, Codec::LZ4, Codec::LZO, Codec::NONE}) EXPECT(detect_level(c, compress(c, data), data).level == -1);
    EXPECT(detect_level(Codec::XZ, Bytes(), Bytes()).level == -1);
}

}  // namespace

int run_levels_tests() {
    test_gzip();
    test_bzip2();
    test_lz4_legacy();
    test_zstd();
    test_unknown();
    if (g_failures == 0) std::printf("levels: ok (%d checks)\n", g_checks);
    else std::printf("levels: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
