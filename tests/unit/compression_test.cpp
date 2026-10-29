// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of the limit on what a decoder lets a stream become (include/abr/compression.hpp: kMaxDecompressedSize, and the
// `max_size` of decompress()). Run by tests/run_tests.sh as `abr_unit_tests compression`.
//
// For every codec, with plain data of several kinds and sizes, and limits on both sides of the size of the data:
//   * exactly `max_size` bytes is taken and comes back as it was; no limit at all (SIZE_MAX) is not an overflow of the
//     sizes the decoders keep;
//   * one byte more than `max_size` is a FormatError that says how much it may be -- whatever size of buffer the decoder began
//     with and however it grew it: the data covers a stream that fits the first buffer, one that needs it doubled many times, one
//     of several blocks (lz4_legacy: 8 MiB, lzo: 256 KiB), and one whose plain data ends where a buffer ends;
//   * a damaged stream is still the error it was, and the empty stream is not a problem for the smallest limit;
//   * a zstd frame that declares more than the limit is refused before a buffer of that size is made (this one declares a
//     terabyte: believing it would end the test with an out-of-memory), a frame that declares less than it holds is refused
//     as the damaged one it is, and a frame that declares nothing is cut off at the limit like any stream;
//   * a stream that is a thousand times its own size (a gzip of zeros, a zstd frame of run-length blocks) stops at the
//     limit, where the plain data the decoder had made so far is a few megabytes, not the gigabytes it asks for.
#include <cstdint>
#include <cstdio>
#include <optional>
#include <random>
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

// "it would be more than N MiB decompressed ..." / "... N bytes ...": what a decoder says for a limit of `max`
std::string limit_text(size_t max) {
    const size_t mib = size_t(1) << 20;
    return max % mib == 0 ? std::to_string(max / mib) + " MiB" : std::to_string(max) + " bytes";
}

// What decompress() says to a stream and a limit: "" when it takes it (and gives `plain` back), else the message.
std::string verdict(Codec codec, const Bytes& stream, size_t max, const Bytes* plain) {
    try {
        const Bytes got = decompress(codec, stream, max);
        if (plain && got != *plain) return "<wrong data: " + std::to_string(got.size()) + " bytes>";
        return "";
    } catch (const FormatError& e) {
        return e.what();
    }
}

bool refused_as_too_big(const std::string& said, size_t max) {
    return said == "it would be more than " + limit_text(max) + " decompressed, and no component of the family is that big";
}

// What compresses (runs, a few words) with what does not (random bytes), in pieces of random length: every codec has blocks of
// both kinds.
Bytes mixed(size_t n, uint32_t seed) {
    Bytes out;
    out.reserve(n);
    std::mt19937 rng(seed);
    while (out.size() < n) {
        const size_t run = 1 + rng() % 3000;
        const unsigned kind = rng() % 3;
        for (size_t i = 0; i < run && out.size() < n; ++i)
            out.push_back(kind == 0 ? uint8_t(0) : kind == 1 ? uint8_t("abcdefgh"[i % 8]) : static_cast<uint8_t>(rng()));
    }
    return out;
}

const Codec kCodecs[] = {Codec::GZIP, Codec::LZ4_LEGACY, Codec::LZ4, Codec::ZSTD, Codec::XZ, Codec::LZMA, Codec::BZIP2, Codec::LZO};

struct Sample {
    const char* what;
    Bytes plain;
    bool every_codec;  // the large ones go through the codecs that are quick with them only
};

// One codec, one plain data: the limits around its size.
void check_limits(Codec codec, const Sample& s) {
    const std::string name = std::string(codec_name(codec)) + " of " + s.what;
    Bytes stream;
    try {
        stream = compress(codec, s.plain);
    } catch (const std::exception& e) {
        ++g_failures;
        std::printf("  FAIL %s: cannot be made: %s\n", name.c_str(), e.what());
        return;
    }
    const size_t n = s.plain.size();
    // Exactly the size, and more than the size: taken, and the data comes back.
    for (size_t extra : {size_t(0), size_t(1), size_t(4096), size_t(1) << 20}) {
        const std::string said = verdict(codec, stream, n + extra, &s.plain);
        if (!said.empty()) std::printf("  note %s, limit %zu: %s\n", name.c_str(), n + extra, said.c_str());
        EXPECT(said.empty());
    }
    EXPECT(verdict(codec, stream, SIZE_MAX, &s.plain).empty());
    // One byte less, and a good deal less: refused, with the limit in the message.
    if (n >= 1) {
        for (size_t less : {size_t(1), size_t(2), size_t(7), n / 2, n}) {
            if (less == 0 || less > n) continue;
            const size_t max = n - less;
            const std::string said = verdict(codec, stream, max, nullptr);
            if (!refused_as_too_big(said, max)) std::printf("  note %s, limit %zu: said '%s'\n", name.c_str(), max, said.c_str());
            EXPECT(refused_as_too_big(said, max));
        }
    }
}

void test_limits_every_codec() {
    std::vector<Sample> samples;
    samples.push_back({"nothing", Bytes{}, true});
    samples.push_back({"one byte", Bytes{0x5a}, true});
    samples.push_back({"4095 mixed bytes", mixed(4095, 1), true});
    samples.push_back({"4096 mixed bytes", mixed(4096, 2), true});
    samples.push_back({"100000 mixed bytes", mixed(100000, 3), true});
    samples.push_back({"300001 mixed bytes", mixed(300001, 4), true});  // (more than one block of lzo)
    samples.push_back({"3 MiB of zeros", Bytes(size_t(3) << 20, 0), true});
    samples.push_back({"3 MiB + 1 of zeros", Bytes((size_t(3) << 20) + 1, 0), true});
    for (const Sample& s : samples)
        for (Codec codec : kCodecs) check_limits(codec, s);
    // Several blocks of lz4_legacy (8 MiB each), the last one not full, the end of the data on a block's end, and the limit on both.
    for (size_t n : {(size_t(16) << 20), (size_t(16) << 20) + 5})
        check_limits(Codec::LZ4_LEGACY, {"zeros over two blocks", Bytes(n, 0), true});
}

void test_none_is_not_limited() {
    const Bytes data = mixed(1000, 9);
    EXPECT(decompress(Codec::NONE, data, 1) == data);  // nothing is decoded, and the data is what the caller has already
    EXPECT(decompress(Codec::NONE, data) == data);
    EXPECT(kMaxDecompressedSize == 0x40000000);
}

// The default limit is the one of the header: a plain data that is within it is taken without naming a limit.
void test_default_limit() {
    const Bytes data = mixed(50000, 11);
    for (Codec codec : kCodecs) EXPECT(decompress(codec, compress(codec, data)) == data);
}

// A damaged stream is the error it always was, not "it would be more than ...", even when the limit is small.
void test_damaged_streams() {
    const Bytes data = mixed(20000, 12);
    for (Codec codec : {Codec::GZIP, Codec::XZ, Codec::BZIP2}) {  // (those that check what they decode)
        Bytes stream = compress(codec, data);
        stream[stream.size() / 2] ^= 0xFF;
        stream[stream.size() / 2 + 1] ^= 0xA5;
        for (size_t max : {size_t(100), size_t(20000), kMaxDecompressedSize}) {
            const std::string said = verdict(codec, stream, max, nullptr);
            EXPECT(!said.empty());
            if (max >= 20000) EXPECT(said.find("it would be more than") == std::string::npos);
        }
    }
}

// A zstd frame, made by hand: `n` zeros as run-length blocks (4 bytes for up to 128 KiB), and in its header either the size it
// declares (in the 8 bytes of a single-segment frame) or no size (a window descriptor instead).
Bytes zstd_rle_frame(uint64_t n, std::optional<uint64_t> declared) {
    Bytes f = {0x28, 0xb5, 0x2f, 0xfd};
    if (declared) {
        f.push_back(0xe0);  // single segment, a size of 8 bytes, no checksum, no dictionary
        for (int i = 0; i < 8; ++i) f.push_back(static_cast<uint8_t>(*declared >> (8 * i)));
    } else {
        f.push_back(0x00);  // no size, a window descriptor follows
        f.push_back(0x38);  // 128 KiB
    }
    constexpr uint64_t kBlock = 128 * 1024;
    if (n == 0) {
        f.insert(f.end(), {0x01, 0x00, 0x00});  // an empty last block (raw)
        return f;
    }
    for (uint64_t left = n; left > 0;) {
        const uint64_t take = left < kBlock ? left : kBlock;
        left -= take;
        const uint32_t header = (left == 0 ? 1u : 0u) | (1u << 1) | static_cast<uint32_t>(take << 3);  // run-length, last or not
        f.push_back(static_cast<uint8_t>(header));
        f.push_back(static_cast<uint8_t>(header >> 8));
        f.push_back(static_cast<uint8_t>(header >> 16));
        f.push_back(0x00);  // the byte that is repeated
    }
    return f;
}

void test_zstd_frames() {
    // The frames made by hand are what they say.
    {
        const Bytes plain(300000, 0);
        EXPECT(decompress(Codec::ZSTD, zstd_rle_frame(300000, 300000)) == plain);
        EXPECT(decompress(Codec::ZSTD, zstd_rle_frame(300000, std::nullopt)) == plain);
        EXPECT(decompress(Codec::ZSTD, zstd_rle_frame(0, std::nullopt)).empty());
    }
    // A frame that declares a terabyte: refused at once (a decoder that made the buffer would not come back).
    {
        const Bytes frame = zstd_rle_frame(1000, uint64_t(1) << 40);
        for (size_t max : {kMaxDecompressedSize, size_t(1) << 20, size_t(5000)})
            EXPECT(refused_as_too_big(verdict(Codec::ZSTD, frame, max, nullptr), max));
    }
    // A frame that declares the limit, and one byte more.
    {
        const Bytes at = zstd_rle_frame(300000, 300000);
        EXPECT(verdict(Codec::ZSTD, at, 300000, nullptr).empty());
        EXPECT(refused_as_too_big(verdict(Codec::ZSTD, at, 299999, nullptr), 299999));
    }
    // A frame that declares less than it holds is damaged (and not taken for the size it declares).
    {
        const Bytes frame = zstd_rle_frame(300000, 1000);
        const std::string said = verdict(Codec::ZSTD, frame, kMaxDecompressedSize, nullptr);
        EXPECT(!said.empty());
        EXPECT(said.find("it would be more than") == std::string::npos);
    }
    // A frame that declares nothing is cut off at the limit; on the limit, it is taken.
    {
        const Bytes frame = zstd_rle_frame(5 * 131072 + 7, std::nullopt);
        const size_t n = 5 * 131072 + 7;
        EXPECT(verdict(Codec::ZSTD, frame, n, nullptr).empty());
        EXPECT(refused_as_too_big(verdict(Codec::ZSTD, frame, n - 1, nullptr), n - 1));
        EXPECT(refused_as_too_big(verdict(Codec::ZSTD, frame, 131072, nullptr), 131072));
        EXPECT(refused_as_too_big(verdict(Codec::ZSTD, frame, 0, nullptr), 0));
    }
}

// Streams that are many times their own size, at the limits of a test (a few megabytes).
void test_bombs() {
    const size_t cap = size_t(4) << 20;  // 4 MiB
    {
        // A gzip of 64 MiB of zeros: 64 KiB or so.
        Bytes zeros(size_t(64) << 20, 0);
        const Bytes stream = compress(Codec::GZIP, zeros);
        EXPECT(stream.size() < zeros.size() / 500);
        EXPECT(refused_as_too_big(verdict(Codec::GZIP, stream, cap, nullptr), cap));
        EXPECT(verdict(Codec::GZIP, stream, zeros.size(), &zeros).empty());
        EXPECT(refused_as_too_big(verdict(Codec::GZIP, stream, zeros.size() - 1, nullptr), zeros.size() - 1));
    }
    {
        // A zstd frame of run-length blocks that declares nothing: 32 KiB for a gigabyte; the limit stops it after four megabytes.
        const Bytes stream = zstd_rle_frame(uint64_t(1) << 30, std::nullopt);
        EXPECT(stream.size() < (size_t(1) << 20) / 16);
        EXPECT(refused_as_too_big(verdict(Codec::ZSTD, stream, cap, nullptr), cap));
    }
}

}  // namespace

int run_compression_tests() {
    test_none_is_not_limited();
    test_default_limit();
    test_damaged_streams();
    test_zstd_frames();
    test_limits_every_codec();
    test_bombs();
    if (g_failures == 0) std::printf("compression: ok (%d checks)\n", g_checks);
    else std::printf("compression: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
