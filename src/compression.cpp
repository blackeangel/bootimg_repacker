// SPDX-License-Identifier: MIT
#include "abr/compression.hpp"

#include <bzlib.h>
#include <lz4.h>
#include <lz4frame.h>
#include <lzma.h>
#include <zlib.h>
#include <zstd.h>

#include <algorithm>
#include <cstring>

namespace abr {

namespace {

// Android's GKI ramdisk "lz4 legacy" block format works in fixed 8 MiB
// (uncompressed) chunks; see Magisk's LZ4_BLOCK_SIZE and the historical
// lz4demo legacy frame format it mirrors.
constexpr size_t kLz4LegacyBlockSize = 0x800000;

constexpr uint8_t kGzipMagic[] = {0x1f, 0x8b};
constexpr uint8_t kLz4LegacyMagic[] = {0x02, 0x21, 0x4c, 0x18};  // LE(0x184C2102)
constexpr uint8_t kLz4FrameMagic[] = {0x04, 0x22, 0x4d, 0x18};   // LE(0x184D2204)
constexpr uint8_t kZstdMagic[] = {0x28, 0xb5, 0x2f, 0xfd};       // LE(0xFD2FB528)
constexpr uint8_t kXzMagic[] = {0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00};
constexpr uint8_t kBzip2Magic[] = {0x42, 0x5a, 0x68};  // "BZh"

bool starts_with(const Bytes& d, const uint8_t* magic, size_t len) {
    return d.size() >= len && std::memcmp(d.data(), magic, len) == 0;
}

// Heuristic used by magiskboot/AIK to spot a headerless "LZMA alone"
// stream: byte 0 is the packed (pb*5+lp)*9+lc properties byte (0x5D for
// the default lc=3,lp=0,pb=2), bytes 1..4 are a power-of-two dictionary
// size, and bytes 5..12 are the (usually unknown-length) 0xFF marker.
bool looks_like_lzma_alone(const Bytes& d) {
    if (d.size() <= 13 || d[0] != 0x5d) return false;
    uint32_t dict = d[1] | (d[2] << 8) | (d[3] << 16) | (uint32_t(d[4]) << 24);
    if (dict == 0 || (dict & (dict - 1)) != 0) return false;
    for (int i = 5; i < 13; ++i)
        if (d[i] != 0xff) return false;
    return true;
}

[[noreturn]] void fail(const std::string& what) { throw FormatError(what); }

// ---------------------------------------------------------------- gzip --

Bytes zlib_run(const Bytes& in, bool encode, int level, int window_bits) {
    z_stream strm{};
    int rc = encode ? deflateInit2(&strm, level, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY)
                     : inflateInit2(&strm, window_bits);
    if (rc != Z_OK) fail("zlib init failed");

    Bytes out;
    out.resize(std::max<size_t>(64, in.size() * (encode ? 1 : 3) + 4096));
    strm.next_in = const_cast<Bytef*>(in.data());
    strm.avail_in = static_cast<uInt>(in.size());
    size_t produced = 0;

    int action = encode ? Z_FINISH : Z_FINISH;
    for (;;) {
        if (produced == out.size()) out.resize(out.size() * 2);
        strm.next_out = out.data() + produced;
        strm.avail_out = static_cast<uInt>(out.size() - produced);
        rc = encode ? deflate(&strm, action) : inflate(&strm, action);
        produced = out.size() - strm.avail_out;
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK && rc != Z_BUF_ERROR) {
            (encode ? deflateEnd : inflateEnd)(&strm);
            fail(std::string("zlib ") + (encode ? "deflate" : "inflate") + " failed: " +
                 (strm.msg ? strm.msg : std::to_string(rc)));
        }
        if (rc == Z_BUF_ERROR && strm.avail_out != 0 && strm.avail_in == 0) {
            // No forward progress possible and no more input: for a
            // truncated/corrupt stream this avoids spinning forever.
            break;
        }
    }
    (encode ? deflateEnd : inflateEnd)(&strm);
    out.resize(produced);
    return out;
}

Bytes gzip_compress(const Bytes& in, int level) {
    if (level < 0) level = Z_DEFAULT_COMPRESSION;
    return zlib_run(in, /*encode=*/true, level, /*windowBits=*/15 + 16);
}
Bytes gzip_decompress(const Bytes& in) {
    return zlib_run(in, /*encode=*/false, 0, /*windowBits=*/15 + 32 /* auto zlib/gzip */);
}

// ------------------------------------------------------------ lz4 frame --

Bytes lz4_frame_compress(const Bytes& in, int level) {
    LZ4F_preferences_t prefs{};
    prefs.compressionLevel = (level < 0) ? 0 : level;
    prefs.frameInfo.contentSize = in.size();
    size_t bound = LZ4F_compressFrameBound(in.size(), &prefs);
    Bytes out(bound);
    size_t n = LZ4F_compressFrame(out.data(), out.size(), in.data(), in.size(), &prefs);
    if (LZ4F_isError(n)) fail(std::string("LZ4F_compressFrame failed: ") + LZ4F_getErrorName(n));
    out.resize(n);
    return out;
}

Bytes lz4_frame_decompress(const Bytes& in) {
    LZ4F_decompressionContext_t ctx;
    if (LZ4F_isError(LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION)))
        fail("LZ4F_createDecompressionContext failed");
    struct Guard {
        LZ4F_decompressionContext_t c;
        ~Guard() { LZ4F_freeDecompressionContext(c); }
    } guard{ctx};

    Bytes out;
    out.reserve(in.size() * 3 + 4096);
    size_t in_pos = 0;
    Bytes chunk(1 << 20);
    while (in_pos < in.size()) {
        size_t src_size = in.size() - in_pos;
        size_t dst_size = chunk.size();
        size_t rc = LZ4F_decompress(ctx, chunk.data(), &dst_size, in.data() + in_pos, &src_size,
                                     nullptr);
        if (LZ4F_isError(rc)) fail(std::string("LZ4F_decompress failed: ") + LZ4F_getErrorName(rc));
        out.insert(out.end(), chunk.data(), chunk.data() + dst_size);
        in_pos += src_size;
        if (rc == 0) break;  // frame fully decoded
        if (src_size == 0 && dst_size == 0) break;  // no progress; avoid spinning
    }
    return out;
}

// ---------------------------------------------------------- lz4 legacy --

Bytes lz4_legacy_compress(const Bytes& in) {
    BinaryWriter w;
    w.bytes(kLz4LegacyMagic, sizeof(kLz4LegacyMagic));
    size_t pos = 0;
    Bytes cbuf(LZ4_compressBound(static_cast<int>(kLz4LegacyBlockSize)));
    while (pos < in.size()) {
        int chunk = static_cast<int>(std::min(kLz4LegacyBlockSize, in.size() - pos));
        int csize = LZ4_compress_default(reinterpret_cast<const char*>(in.data() + pos),
                                          reinterpret_cast<char*>(cbuf.data()), chunk,
                                          static_cast<int>(cbuf.size()));
        if (csize <= 0) fail("LZ4_compress_default failed");
        w.le32(static_cast<uint32_t>(csize));
        w.bytes(cbuf.data(), static_cast<size_t>(csize));
        pos += static_cast<size_t>(chunk);
    }
    return w.take();
}

Bytes lz4_legacy_decompress(const Bytes& in) {
    BinaryReader r(in);
    if (!r.starts_with(reinterpret_cast<const char*>(kLz4LegacyMagic), 4))
        fail("not an lz4-legacy stream (bad magic)");
    r.skip(4);
    Bytes out;
    Bytes scratch(kLz4LegacyBlockSize);
    while (r.remaining() > 0) {
        if (r.remaining() < 4) break;  // trailing pad, not a real block
        uint32_t block_size = r.le32();
        if (block_size == 0 || block_size > r.remaining()) break;
        Bytes block = r.bytes(block_size);
        int n = LZ4_decompress_safe(reinterpret_cast<const char*>(block.data()),
                                     reinterpret_cast<char*>(scratch.data()),
                                     static_cast<int>(block.size()),
                                     static_cast<int>(scratch.size()));
        if (n < 0) fail("LZ4_decompress_safe failed on lz4-legacy block");
        out.insert(out.end(), scratch.data(), scratch.data() + n);
    }
    return out;
}

// --------------------------------------------------------------- zstd --

Bytes zstd_compress(const Bytes& in, int level) {
    if (level < 0) level = ZSTD_CLEVEL_DEFAULT;
    Bytes out(ZSTD_compressBound(in.size()));
    size_t n = ZSTD_compress(out.data(), out.size(), in.data(), in.size(), level);
    if (ZSTD_isError(n)) fail(std::string("ZSTD_compress failed: ") + ZSTD_getErrorName(n));
    out.resize(n);
    return out;
}

Bytes zstd_decompress(const Bytes& in) {
    unsigned long long content_size = ZSTD_getFrameContentSize(in.data(), in.size());
    if (content_size == ZSTD_CONTENTSIZE_ERROR) fail("not a valid zstd frame");
    if (content_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        // Streamed with unknown size (e.g. produced without contentSizeFlag):
        // fall back to the streaming API into a growable buffer.
        ZSTD_DStream* ds = ZSTD_createDStream();
        if (!ds) fail("ZSTD_createDStream failed");
        struct Guard { ZSTD_DStream* d; ~Guard() { ZSTD_freeDStream(d); } } guard{ds};
        ZSTD_initDStream(ds);
        ZSTD_inBuffer in_buf{in.data(), in.size(), 0};
        Bytes out;
        Bytes chunk(1 << 20);
        size_t rc;
        do {
            ZSTD_outBuffer out_buf{chunk.data(), chunk.size(), 0};
            rc = ZSTD_decompressStream(ds, &out_buf, &in_buf);
            if (ZSTD_isError(rc)) fail(std::string("ZSTD_decompressStream failed: ") +
                                        ZSTD_getErrorName(rc));
            out.insert(out.end(), chunk.data(), chunk.data() + out_buf.pos);
        } while (in_buf.pos < in_buf.size && rc != 0);
        return out;
    }
    Bytes out(static_cast<size_t>(content_size));
    size_t n = ZSTD_decompress(out.data(), out.size(), in.data(), in.size());
    if (ZSTD_isError(n)) fail(std::string("ZSTD_decompress failed: ") + ZSTD_getErrorName(n));
    out.resize(n);
    return out;
}

// ----------------------------------------------------------------- xz --

Bytes xz_compress(const Bytes& in, int level) {
    uint32_t preset = (level < 0) ? 6u : static_cast<uint32_t>(level);
    size_t bound = lzma_stream_buffer_bound(in.size());
    Bytes out(bound);
    size_t out_pos = 0;
    lzma_ret rc = lzma_easy_buffer_encode(preset, LZMA_CHECK_CRC32, nullptr, in.data(), in.size(),
                                           out.data(), &out_pos, out.size());
    if (rc != LZMA_OK) fail("lzma_easy_buffer_encode failed: rc=" + std::to_string(rc));
    out.resize(out_pos);
    return out;
}

Bytes xz_decompress(const Bytes& in) {
    Bytes out(std::max<size_t>(in.size() * 4, 4096));
    for (;;) {
        uint64_t memlimit = UINT64_MAX;
        size_t in_pos = 0, out_pos = 0;
        lzma_ret rc = lzma_stream_buffer_decode(&memlimit, 0, nullptr, in.data(), &in_pos,
                                                 in.size(), out.data(), &out_pos, out.size());
        if (rc == LZMA_OK) {
            out.resize(out_pos);
            return out;
        }
        if (rc == LZMA_BUF_ERROR) {  // output buffer too small; grow and retry
            out.resize(out.size() * 2);
            continue;
        }
        fail("lzma_stream_buffer_decode failed: rc=" + std::to_string(rc));
    }
}

// -------------------------------------------------- lzma "alone" stream --

Bytes lzma_stream_run(const Bytes& in, bool encode) {
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret rc;
    if (encode) {
        lzma_options_lzma opt;
        if (lzma_lzma_preset(&opt, 6)) fail("lzma_lzma_preset failed");
        rc = lzma_alone_encoder(&strm, &opt);
    } else {
        rc = lzma_alone_decoder(&strm, UINT64_MAX);
    }
    if (rc != LZMA_OK) fail("lzma alone (en|de)coder init failed: rc=" + std::to_string(rc));

    Bytes out;
    out.resize(std::max<size_t>(4096, in.size() * (encode ? 1 : 3)));
    strm.next_in = in.data();
    strm.avail_in = in.size();
    size_t produced = 0;
    for (;;) {
        if (produced == out.size()) out.resize(out.size() * 2);
        strm.next_out = out.data() + produced;
        strm.avail_out = out.size() - produced;
        rc = lzma_code(&strm, LZMA_FINISH);
        produced = out.size() - strm.avail_out;
        if (rc == LZMA_STREAM_END) break;
        if (rc != LZMA_OK) {
            lzma_end(&strm);
            fail("lzma_code failed: rc=" + std::to_string(rc));
        }
    }
    lzma_end(&strm);
    out.resize(produced);
    return out;
}

// -------------------------------------------------------------- bzip2 --

Bytes bzip2_compress(const Bytes& in, int level) {
    if (level < 1 || level > 9) level = 9;
    unsigned int out_len = static_cast<unsigned int>(in.size() + in.size() / 100 + 600);
    Bytes out(out_len);
    int rc = BZ2_bzBuffToBuffCompress(reinterpret_cast<char*>(out.data()), &out_len,
                                       const_cast<char*>(reinterpret_cast<const char*>(in.data())),
                                       static_cast<unsigned int>(in.size()), level, 0, 0);
    if (rc != BZ_OK) fail("BZ2_bzBuffToBuffCompress failed: rc=" + std::to_string(rc));
    out.resize(out_len);
    return out;
}

Bytes bzip2_decompress(const Bytes& in) {
    unsigned int out_len = static_cast<unsigned int>(std::max<size_t>(in.size() * 4, 4096));
    for (;;) {
        Bytes out(out_len);
        unsigned int produced = out_len;
        int rc = BZ2_bzBuffToBuffDecompress(
            reinterpret_cast<char*>(out.data()), &produced,
            const_cast<char*>(reinterpret_cast<const char*>(in.data())),
            static_cast<unsigned int>(in.size()), 0, 0);
        if (rc == BZ_OK) {
            out.resize(produced);
            return out;
        }
        if (rc == BZ_OUTBUFF_FULL) {
            out_len *= 2;
            continue;
        }
        fail("BZ2_bzBuffToBuffDecompress failed: rc=" + std::to_string(rc));
    }
}

}  // namespace

std::string_view codec_name(Codec c) {
    switch (c) {
        case Codec::NONE: return "none";
        case Codec::GZIP: return "gzip";
        case Codec::LZ4_LEGACY: return "lz4_legacy";
        case Codec::LZ4: return "lz4";
        case Codec::ZSTD: return "zstd";
        case Codec::XZ: return "xz";
        case Codec::LZMA: return "lzma";
        case Codec::BZIP2: return "bzip2";
    }
    return "none";
}

std::optional<Codec> codec_from_name(std::string_view name) {
    if (name == "none") return Codec::NONE;
    if (name == "gzip") return Codec::GZIP;
    if (name == "lz4_legacy") return Codec::LZ4_LEGACY;
    if (name == "lz4") return Codec::LZ4;
    if (name == "zstd") return Codec::ZSTD;
    if (name == "xz") return Codec::XZ;
    if (name == "lzma") return Codec::LZMA;
    if (name == "bzip2") return Codec::BZIP2;
    return std::nullopt;
}

Codec detect_codec(const Bytes& d) {
    if (starts_with(d, kGzipMagic, sizeof(kGzipMagic))) return Codec::GZIP;
    if (starts_with(d, kLz4LegacyMagic, sizeof(kLz4LegacyMagic))) return Codec::LZ4_LEGACY;
    if (starts_with(d, kLz4FrameMagic, sizeof(kLz4FrameMagic))) return Codec::LZ4;
    if (starts_with(d, kZstdMagic, sizeof(kZstdMagic))) return Codec::ZSTD;
    if (starts_with(d, kXzMagic, sizeof(kXzMagic))) return Codec::XZ;
    if (starts_with(d, kBzip2Magic, sizeof(kBzip2Magic))) return Codec::BZIP2;
    if (looks_like_lzma_alone(d)) return Codec::LZMA;
    return Codec::NONE;
}

Bytes decompress(Codec codec, const Bytes& data) {
    switch (codec) {
        case Codec::NONE: return data;
        case Codec::GZIP: return gzip_decompress(data);
        case Codec::LZ4_LEGACY: return lz4_legacy_decompress(data);
        case Codec::LZ4: return lz4_frame_decompress(data);
        case Codec::ZSTD: return zstd_decompress(data);
        case Codec::XZ: return xz_decompress(data);
        case Codec::LZMA: return lzma_stream_run(data, /*encode=*/false);
        case Codec::BZIP2: return bzip2_decompress(data);
    }
    fail("unknown codec");
}

Bytes compress(Codec codec, const Bytes& data, int level) {
    switch (codec) {
        case Codec::NONE: return data;
        case Codec::GZIP: return gzip_compress(data, level);
        case Codec::LZ4_LEGACY: return lz4_legacy_compress(data);
        case Codec::LZ4: return lz4_frame_compress(data, level);
        case Codec::ZSTD: return zstd_compress(data, level);
        case Codec::XZ: return xz_compress(data, level);
        case Codec::LZMA: return lzma_stream_run(data, /*encode=*/true);
        case Codec::BZIP2: return bzip2_compress(data, level);
    }
    fail("unknown codec");
}

}  // namespace abr
