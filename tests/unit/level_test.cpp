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
//   * lzo (an lzop file): the method byte of the header and, from lzop 0.94, the level byte say it -- 1 is `lzop -1`, 3 is `-2` to `-6`, 7 to 9 are `-7` to `-9`;
//     every level makes the blocks that the library makes at that setting (on one thread, the reference), whatever the number of threads, and the blocks
//     that the real lzop 1.04 wrote for a text (known answers, `lzop -1` and `-9`; the dense levels need lzo1x_optimize() for that); a file with other sizes
//     of block or other checksums (what the other tools write) is read, one of another method (the NRV ones, zlib) is refused, and so is every cut one;
//   * what cannot be known (lzma, lz4 frame, no codec) is -1; nothing breaks on empty, damaged or cut streams.
#include <lzo/lzo1x.h>
#include <zstd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
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

// ------------------------------------------------------------------------------------------------------------------------ lzo --

// What an lzop file that abr writes (no file name) begins with: the magic (9), the three versions (6), the method, the level, the flags (4), the mode (4),
// the two times (8), the length of the name (1) and the checksum of the header (4). The method byte is at 15, the level byte behind it, the flags at 17.
constexpr size_t kLzopHeader = 38;
constexpr size_t kLzopMethodAt = 15;
constexpr size_t kLzopLevelAt = 16;
constexpr size_t kLzopFlagsAt = 17;
constexpr size_t kBlock = 256 * 1024;  // what abr cuts the data into (and the kernel takes)

uint32_t be32_at(const Bytes& b, size_t at) {
    return (uint32_t{b[at]} << 24) | (uint32_t{b[at + 1]} << 16) | (uint32_t{b[at + 2]} << 8) | b[at + 3];
}

// The blocks of a stream that abr wrote: how much plain data each stands for, and what it holds as the stream stores it.
struct LzoBlock {
    uint32_t plain;
    Bytes stored;
};

std::vector<LzoBlock> lzo_blocks(const Bytes& s) {
    std::vector<LzoBlock> out;
    size_t pos = kLzopHeader;
    while (pos + 4 <= s.size()) {
        const uint32_t plain = be32_at(s, pos);
        pos += 4;
        if (plain == 0) break;
        if (pos + 8 > s.size()) break;
        const uint32_t size = be32_at(s, pos);
        pos += 8;  // the size, and the Adler-32 of the plain data
        if (pos + size > s.size()) break;
        out.push_back({plain, Bytes(s.begin() + static_cast<long>(pos), s.begin() + static_cast<long>(pos + size))});
        pos += size;
    }
    return out;
}

// What the library makes of one block, here on this thread, with the setting that `level` stands for (lzop -1, -2 to -6, -7 to -9; the dense one with the
// optimizer after it, as lzop). Empty if it fails.
Bytes lzo_reference(int level, const uint8_t* p, size_t n) {
    Bytes out(n + n / 16 + 64 + 3);
    lzo_uint len = 0;
    int rc = LZO_E_ERROR;
    if (level <= 1) {
        Bytes work(LZO1X_1_15_MEM_COMPRESS);
        rc = lzo1x_1_15_compress(p, n, out.data(), &len, work.data());
    } else if (level <= 6) {
        Bytes work(LZO1X_1_MEM_COMPRESS);
        rc = lzo1x_1_compress(p, n, out.data(), &len, work.data());
    } else {
        Bytes work(LZO1X_999_MEM_COMPRESS);
        rc = lzo1x_999_compress_level(p, n, out.data(), &len, work.data(), nullptr, 0, nullptr, level);
        if (rc == LZO_E_OK && len >= 3 && len < n) {  // the step that lzop adds: the same size, and a stream that decompresses faster
            Bytes plain(n + 64);
            lzo_uint plain_len = n;
            rc = lzo1x_optimize(out.data(), len, plain.data(), &plain_len, nullptr);
        }
    }
    out.resize(rc == LZO_E_OK ? len : 0);
    return out;
}

// An lzop file as another tool writes it: blocks of `block` bytes (lzop -b), and the checksum words that `flags` ask for (they are not checked, so
// they are filler). The header is abr's, with the flags changed.
Bytes foreign_stream(const Bytes& data, size_t block, uint32_t flags, int level) {
    Bytes head = compress(Codec::LZO, Bytes(), level);
    head.resize(kLzopHeader);  // (without the marker of the end)
    for (int i = 0; i < 4; ++i) head[kLzopFlagsAt + static_cast<size_t>(i)] = static_cast<uint8_t>(flags >> (24 - 8 * i));
    BinaryWriter w;
    w.bytes(head);
    for (size_t pos = 0; pos < data.size(); pos += block) {
        const size_t n = std::min(block, data.size() - pos);
        const Bytes packed = lzo_reference(level, data.data() + pos, n);
        const bool stored = packed.empty() || packed.size() >= n;
        w.be32(static_cast<uint32_t>(n));
        w.be32(static_cast<uint32_t>(stored ? n : packed.size()));
        if (flags & 0x001) w.be32(0x11111111);  // Adler-32 of the plain data
        if (flags & 0x100) w.be32(0x22222222);  // CRC-32 of the plain data
        if (!stored && (flags & 0x002)) w.be32(0x33333333);  // Adler-32 of the packed data
        if (!stored && (flags & 0x200)) w.be32(0x44444444);  // CRC-32 of the packed data
        if (stored) w.bytes(data.data() + pos, n);
        else w.bytes(packed);
    }
    w.be32(0);
    return w.take();
}

bool refused(const Bytes& stream) {
    try {
        (void)decompress(Codec::LZO, stream);
    } catch (const FormatError&) {
        return true;
    }
    return false;
}

void test_lzo() {
    EXPECT(lzo_init() == LZO_E_OK);
    EXPECT(default_level(Codec::LZO) == 9 && dense_level(Codec::LZO) == 9);
    const Bytes data = text(3 * kBlock + 777, 13);  // four blocks, the last not full

    // the level that is asked for and the one the stream says: 1 and less is lzop -1, 2 to 6 is its default (all alike), 7 to 9 is the dense compressor,
    // more than that is 9, and none is 9 (what the kernel's build makes)
    struct Ask {
        int asked, said;
    };
    for (const Ask a : {Ask{-1, 9}, Ask{0, 1}, Ask{1, 1}, Ask{2, 3}, Ask{3, 3}, Ask{4, 3}, Ask{6, 3}, Ask{7, 7}, Ask{8, 8}, Ask{9, 9}, Ask{22, 9}}) {
        const Bytes stream = compress(Codec::LZO, data, a.asked);
        EXPECT(decompress(Codec::LZO, stream) == data);
        const LevelGuess g = detect_level(Codec::LZO, stream, data);
        EXPECT(g.level == a.said && !g.basis.empty());
        EXPECT(compress(Codec::LZO, data, g.level) == stream);  // whichever level it says, it makes this stream
    }
    // the dense compressor is dense: a good deal less than the default of lzop on text
    EXPECT(compress(Codec::LZO, data, 9).size() < compress(Codec::LZO, data, 3).size());

    // what the header says of the level, as lzop writes it: -1 is method 2 and level 1, -2 to -6 are method 1 and level 5, -7 to -9 are method 3 and the level
    struct Written {
        int asked;
        uint8_t method, level;
    };
    for (const Written h : {Written{1, 2, 1}, Written{3, 1, 5}, Written{7, 3, 7}, Written{8, 3, 8}, Written{9, 3, 9}}) {
        const Bytes s = compress(Codec::LZO, data, h.asked);
        EXPECT(s.size() > kLzopHeader && s[kLzopMethodAt] == h.method && s[kLzopLevelAt] == h.level);
        EXPECT(be32_at(s, kLzopFlagsAt) == 0x0300000d);  // unix, Adler-32 of the plain data, stdin, stdout
        EXPECT(s[9] == 0x10 && s[10] == 0x40 && s[13] == 0x09 && s[14] == 0x40);  // version 1.04, 0.94 needed to read it
    }

    // every block is what the library makes of it on one thread, however many threads made the stream
    for (int level : {1, 3, 7, 8, 9}) {
        const auto blocks = lzo_blocks(compress(Codec::LZO, data, level));
        EXPECT(blocks.size() == 4);
        size_t pos = 0;
        for (const LzoBlock& b : blocks) {
            EXPECT(b.plain == std::min(kBlock, data.size() - pos));
            const Bytes ref = lzo_reference(level, data.data() + pos, b.plain);
            EXPECT(!ref.empty() && ref.size() < b.plain && b.stored == ref);
            pos += b.plain;
        }
        EXPECT(pos == data.size());
    }

    // data that does not pack is stored as it is (a "packed" block that is longer is what the kernel calls a corrupt file)
    {
        Bytes noise(kBlock + 4321);
        uint32_t x = 12345;
        for (uint8_t& c : noise) {
            x = x * 1664525u + 1013904223u;
            c = static_cast<uint8_t>(x >> 24);
        }
        for (int level : {1, 3, 9}) {
            const Bytes s = compress(Codec::LZO, noise, level);
            EXPECT(decompress(Codec::LZO, s) == noise);
            const auto blocks = lzo_blocks(s);
            EXPECT(blocks.size() == 2);
            size_t pos = 0;
            for (const LzoBlock& b : blocks) {
                EXPECT(b.stored.size() == b.plain && std::equal(b.stored.begin(), b.stored.end(), noise.begin() + static_cast<long>(pos)));
                pos += b.plain;
            }
            EXPECT(s.size() == kLzopHeader + noise.size() + 2 * 12 + 4);
        }
    }

    // nothing: the header and the marker of the end
    for (int level : {1, 3, 9}) {
        const Bytes s = compress(Codec::LZO, Bytes(), level);
        EXPECT(s.size() == kLzopHeader + 4);
        EXPECT(decompress(Codec::LZO, s).empty());
        EXPECT(detect_level(Codec::LZO, s, Bytes()).level == (level == 1 ? 1 : level == 3 ? 3 : 9));
    }

    // what other tools write: blocks of other sizes (lzop -b; more than the 256 KiB of the kernel, and less), and the checksum words that the flags ask for
    {
        const Bytes plain = text((size_t{1} << 20) + 4099, 14);
        for (const size_t block : {size_t{64} << 10, size_t{256} << 10, size_t{1} << 20, size_t{4} << 20}) {
            // the fast compressor with every combination of checksums, the dense one (which is slow) with all of them
            for (const uint32_t flags : {0x0300000du, 0x0300000fu, 0x0300030fu, 0x03000000u, 0x03000100u})
                EXPECT(decompress(Codec::LZO, foreign_stream(plain, block, flags, 3)) == plain);
            EXPECT(decompress(Codec::LZO, foreign_stream(plain, block, 0x0300030fu, 9)) == plain);
        }
    }

    // the header of an older lzop (below 0.94: no byte for the level) and the odd levels: what compress() offers that is the nearest
    {
        const Bytes s = compress(Codec::LZO, text(1000, 15), 9);
        const auto with = [&](size_t at, uint8_t v) {
            Bytes c = s;
            c[at] = v;
            return c;
        };
        Bytes old = s;
        old[9] = 0x09;
        old[10] = 0x30;  // version 0.930
        EXPECT(detect_level(Codec::LZO, old, Bytes()).level == 9);
        EXPECT(detect_level(Codec::LZO, with(kLzopLevelAt, 0), Bytes()).level == 9);   // no level in it: the densest
        EXPECT(detect_level(Codec::LZO, with(kLzopLevelAt, 7), Bytes()).level == 7);
        EXPECT(detect_level(Codec::LZO, with(kLzopLevelAt, 8), Bytes()).level == 8);
        EXPECT(detect_level(Codec::LZO, with(kLzopLevelAt, 5), Bytes()).level == 7);   // (lzop's dense compressor is 7 to 9)
        EXPECT(detect_level(Codec::LZO, with(kLzopLevelAt, 200), Bytes()).level == 9);
        EXPECT(detect_level(Codec::LZO, with(kLzopMethodAt, 1), Bytes()).level == 3);
        EXPECT(detect_level(Codec::LZO, with(kLzopMethodAt, 2), Bytes()).level == 1);
        // a file of another method (the NRV ones of lzop 0.x, zlib) is not LZO1X: nothing to say of its level, and nothing that abr decodes
        for (const uint8_t method : {uint8_t{0}, uint8_t{4}, uint8_t{0x1a}, uint8_t{0x1b}, uint8_t{0x2b}, uint8_t{0x2d}, uint8_t{0x2e}, uint8_t{0x80}, uint8_t{0xff}}) {
            const Bytes odd = with(kLzopMethodAt, method);
            EXPECT(detect_level(Codec::LZO, odd, Bytes()).level == -1);
            EXPECT(refused(odd));
        }
        // too short to have the method and the level (the 17th byte is the last of them), or not an lzop file
        for (size_t n : {size_t{0}, size_t{8}, size_t{9}, size_t{15}, size_t{16}})
            EXPECT(detect_level(Codec::LZO, Bytes(s.begin(), s.begin() + static_cast<long>(n)), Bytes()).level == -1);
        EXPECT(detect_level(Codec::LZO, Bytes(s.begin(), s.begin() + 17), Bytes()).level == 9);  // (the header is all there is to read)
        EXPECT(detect_level(Codec::LZO, with(0, 0x88), Bytes()).level == -1);
    }

    // blocks that cannot be: bigger than anything lzop writes, and longer packed than plain
    {
        Bytes head = compress(Codec::LZO, Bytes(), 9);
        head.resize(kLzopHeader);
        BinaryWriter big;
        big.bytes(head);
        big.be32((uint32_t{64} << 20) + 1);
        big.be32(100);
        big.zeros(100);
        EXPECT(refused(big.take()));
        BinaryWriter longer;
        longer.bytes(head);
        longer.be32(100);
        longer.be32(101);
        longer.zeros(200);
        EXPECT(refused(longer.take()));
    }

    // a cut stream is refused wherever it is cut (it has no marker of the end), and one that is damaged is refused or made into something else, never a crash
    {
        const Bytes tiny = compress(Codec::LZO, text(3000, 16), 9);
        EXPECT(decompress(Codec::LZO, tiny) == text(3000, 16));
        for (size_t n = 0; n < tiny.size(); ++n) EXPECT(refused(Bytes(tiny.begin(), tiny.begin() + static_cast<long>(n))));
        uint32_t x = 777;
        for (int i = 0; i < 400; ++i) {
            Bytes bad = tiny;
            x = x * 1664525u + 1013904223u;
            bad[kLzopHeader + (x >> 8) % (bad.size() - kLzopHeader)] ^= static_cast<uint8_t>(1u << ((x >> 4) % 8));
            try {
                (void)decompress(Codec::LZO, bad);
            } catch (const FormatError&) {
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------------------------ lzo, real --

// What the real `lzop 1.04` (LZO library 2.10) writes, with the time of the day of that run in its header: a text, and the whole files that `lzop -1` and
// `lzop -9` made of it from standard input. `-2` to `-6` make the blocks of -1 on this text with the other method, and `-7` to `-9` the blocks of -9: the dense
// compressor's blocks are those of lzo1x_999_compress_level() put through lzo1x_optimize() (the same size, and other bytes, when it is left out).
const char* const kKatText = R"KAT(on early-init
    write /proc/sys/kernel/sched_boost 1
    write /sys/block/mmcblk0/queue/read_ahead_kb 512
    mkdir /dev/stune/top-app 0755 system system
    mkdir /dev/stune/foreground 0755 system system
    mkdir /dev/stune/background 0755 system system
    chown system system /dev/stune/top-app/tasks
    chown system system /dev/stune/foreground/tasks
    chmod 0664 /dev/stune/top-app/tasks
    chmod 0664 /dev/stune/foreground/tasks

on init
    symlink /system/etc /etc
    symlink /sys/kernel/debug /d
    mount cgroup none /dev/cpuctl cpu
    chown system system /dev/cpuctl
    chmod 0755 /dev/cpuctl/tasks
    write /dev/cpuctl/cpu.rt_runtime_us 950000
    write /dev/cpuctl/cpu.rt_period_us 1000000
    mkdir /dev/cpuctl/bg_non_interactive
    chown system system /dev/cpuctl/bg_non_interactive/tasks
    chmod 0666 /dev/cpuctl/bg_non_interactive/tasks
    write /dev/cpuctl/bg_non_interactive/cpu.shares 52
    write /proc/sys/vm/overcommit_memory 1
    write /proc/sys/vm/min_free_order_shift 4

service ueventd /system/bin/ueventd
    class core
    critical
    seclabel u:r:ueventd:s0
    shutdown critical

service logd /system/bin/logd
    class core
    socket logd stream 0666 logd logd
    socket logdr seqpacket 0666 logd logd
    socket logdw dgram+passcred 0222 logd logd
    seclabel u:r:logd:s0

service servicemanager /system/bin/servicemanager
    class core animation
    user system
    group system readproc
    critical
    onrestart restart healthd
    onrestart restart zygote
    onrestart restart audioserver
    onrestart restart media
    onrestart restart surfaceflinger
    onrestart restart inputflinger
    onrestart restart drm
    onrestart restart cameraserver
)KAT";

const char* const kLzopFast =
    "894c5a4f000d0a1a0a104020a0094002010300000d000081a46af2c49e000000"
    "00003f740550000006ae000003525a1f483700246f6e206561726c792d696e69"
    "740a202020207772697465202f70726f632f7379732f6b65726e656c2f736368"
    "65645f626f6f737420312aa0006c040009626c6f636b2f6d6d63626c6b302f71"
    "756575652f726561645f61687400036b6220353132900600126d6b646972202f"
    "6465762f7374756e652f746f702d61707020303735352073797374656dd80034"
    "bc0007666f726567726f756e642008c800016261636b3cc8000263686f776ed8"
    "0ef800308c02032f7461736b7398123dc0002890022bcc00056d6f6420303636"
    "3431fc033f9c002f4801010a6f6e2027d0060573796d6c696e6b206436057465"
    "6d2f65746320700090152a71002fd839056465627567202f648004046d6f756e"
    "7420636c240470206e6f6e6520901f0763707563746c20637075940437cc03bc"
    "04cc048c1c6c39290801297003d44b7c3fb80600072f6370752e72745f72756e"
    "74696d655f7573203935303030309c0937b80003706572696f647505317005d8"
    "05297409d40b0f62675f6e6f6e5f696e7465726163746976659c0a3d2d032f30"
    "d800290e036368931c3636362a9c043ccc003020033188016821057368617265"
    "732035b865d80627300e0002766d2f6f766572636f6d6d69745f6d656d6f7279"
    "2c380e2aa80000166d696e5f667265655f6f726465725f736869667420340a0a"
    "7365727669636520756576656e746420f4460162696e2fcc02b424056c617373"
    "20636f72d026047269746963616c8c030a7365636c6162656c20753a723ad206"
    "3a73b436027368757464656a63e40627cb016c6f672cbc016002810a632cb001"
    "04736f636b6574207803042073747265616d696736a002740290062994000472"
    "2073657170619506306c33700498052ea40000037720646772616d2b70617373"
    "63726564203032323284059000b8052a780364096c1b271403c028046d616e61"
    "67657227d40d7c272c68008c092864030720616e696d6174696f6e8003017573"
    "6572d88d9c01a070d0a07ca77039840327200564b4076f6e7265737461727420"
    "fc00036865616c7468b079307400027a79676f74a83830700002617564696f72"
    "166572840d308400026d65646961356c000973757266616365666c696e673700"
    "0102696e7075743c8b0064726d3284010d72742063616d657261736572766572"
    "0a11000000000000";

const char* const kLzopDense =
    "894c5a4f000d0a1a0a104020a0094003090300000d000081a46af2c49e000000"
    "000040170559000006ae000002dc5a1f4837206f6e206561726c792d696e6974"
    "0a20420077720002000e65202f70726f632f7379732f6b65726e656c2f736368"
    "65645f626f6f737420312aa0006e04626c000b00056b2f6d6d63626c6b302f71"
    "756575652f726561645f61687400036b62203531329006000c6d6b646972202f"
    "6465762f7374756e652f746f702d6170702030373535204f0974656dd80034be"
    "00666f0116670f26756e642008ca00626100273cc8000263686f776e2c5c0031"
    "8c02032f7461736b732003c0002890022bce006d6f47103636343e6c01329c00"
    "2f49010a483727d0060473796d6c696e6b94314c11022f6574632070002f7000"
    "f8390264656275675c0ba4265b0a7420637b0b70206e0d1565a00f0463707563"
    "746c2058003ccc03bc042aec02742c296800297003d046296c0058000f2e7274"
    "5f72756e74696d655f75732039353040003cb900700b31696f64770531303027"
    "b80029e807db0562675f411a5f093f74010c61030469766520032c0331d80032"
    "8106362009cc0030200331b8006e1b736809e3650635353233310e7609766f03"
    "0a72636f0dda6901416d072d6f727908e336a9006d02175f660613655f050964"
    "010d5f0a166966097934058e730303766963010b75052365091f6427d508620d"
    "0b2fcc02a11d6c0f2f732063444fb801470c696361a63d736554030562656c20"
    "753a723ad2063a73bb307368750003602c27c40027cb016c6f672cbc01600232"
    "b10173468a6574be05737451896da42e800227d000299500724b127170619c01"
    "3ca7007720640bba616d2b020b73730528654b393232322eb8002a780374026c"
    "1b271403dc00046d616e616765722b3c032c68002d65032005056905067405ae"
    "6e81037550052a1812a070d8517ca7703930ea056f6e4544740a897420fc0054"
    "ac016c746864357400037a79676f7465357200617509cc6f7016d0153085006d"
    "06486961356c000573757266616365665d8b67370201696e0db5743c8b006472"
    "6d35670063616d5c63c01411000000000000";

Bytes unhex(const char* s) {
    Bytes out;
    const auto nibble = [](char c) { return static_cast<uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10); };
    for (; s[0] != '\0' && s[1] != '\0'; s += 2) out.push_back(static_cast<uint8_t>((nibble(s[0]) << 4) | nibble(s[1])));
    return out;
}

void test_lzo_real() {
    const Bytes plain(kKatText, kKatText + std::strlen(kKatText));
    EXPECT(plain.size() == 1710);
    const Bytes fast = unhex(kLzopFast), dense = unhex(kLzopDense);
    EXPECT(fast.size() == 904 && dense.size() == 786);

    // what lzop wrote is read, and its header says the level
    EXPECT(decompress(Codec::LZO, fast) == plain);
    EXPECT(decompress(Codec::LZO, dense) == plain);
    EXPECT(detect_level(Codec::LZO, fast, plain).level == 1);
    EXPECT(detect_level(Codec::LZO, dense, plain).level == 9);

    // and abr writes what lzop does: the blocks byte for byte, the header but for the time and its checksum (bytes 25 to 32 and 34 to 37)
    struct Case {
        int level;
        const Bytes* real;
    };
    for (const Case c : {Case{1, &fast}, Case{3, &fast}, Case{7, &dense}, Case{8, &dense}, Case{9, &dense}}) {
        const Bytes s = compress(Codec::LZO, plain, c.level);
        EXPECT(s.size() == c.real->size());
        if (s.size() != c.real->size()) continue;
        EXPECT(std::equal(s.begin() + static_cast<long>(kLzopHeader), s.end(), c.real->begin() + static_cast<long>(kLzopHeader)));
        EXPECT(std::equal(s.begin(), s.begin() + static_cast<long>(kLzopMethodAt), c.real->begin()));  // the magic and the versions
        EXPECT(std::equal(s.begin() + static_cast<long>(kLzopFlagsAt), s.begin() + 25, c.real->begin() + static_cast<long>(kLzopFlagsAt)));  // flags and mode
        EXPECT(s[33] == (*c.real)[33]);  // no name
    }
}

void test_unknown() {
    const Bytes data = text(200000, 8);
    for (Codec c : {Codec::LZMA, Codec::LZ4, Codec::NONE}) EXPECT(detect_level(c, compress(c, data), data).level == -1);
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
    test_lzo();
    test_lzo_real();
    test_unknown();
    if (g_failures == 0) std::printf("levels: ok (%d checks)\n", g_checks);
    else std::printf("levels: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
