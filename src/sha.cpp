// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/sha.hpp"

#include <algorithm>
#include <cstring>

namespace abr::hash {

namespace {
inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

inline uint32_t load_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24);
    p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);
    p[3] = uint8_t(v);
}
inline uint64_t load_be64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
inline void store_be64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = uint8_t(v >> (8 * (7 - i)));
}
}  // namespace

// ------------------------------------------------------------------ SHA-1 --

Sha1::Sha1() {
    h_[0] = 0x67452301;
    h_[1] = 0xEFCDAB89;
    h_[2] = 0x98BADCFE;
    h_[3] = 0x10325476;
    h_[4] = 0xC3D2E1F0;
}

void Sha1::process_block(const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4);
    for (int i = 16; i < 80; ++i) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32(b, 30); b = a; a = temp;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e;
}

void Sha1::update(const uint8_t* data, size_t len) {
    total_bits_ += uint64_t(len) * 8;
    while (len > 0) {
        size_t n = std::min(len, size_t(64) - buffer_len_);
        std::memcpy(buffer_ + buffer_len_, data, n);
        buffer_len_ += n;
        data += n;
        len -= n;
        if (buffer_len_ == 64) {
            process_block(buffer_);
            buffer_len_ = 0;
        }
    }
}

Bytes Sha1::finish() {
    uint64_t bits = total_bits_;
    uint8_t pad = 0x80;
    // Feed padding through the same buffering path, but via a temporary
    // update()-like call that must NOT perturb total_bits_ again -- so we
    // bypass update() here and drive the buffer directly.
    auto absorb = [&](const uint8_t* p, size_t n) {
        while (n > 0) {
            size_t k = std::min(n, size_t(64) - buffer_len_);
            std::memcpy(buffer_ + buffer_len_, p, k);
            buffer_len_ += k;
            p += k;
            n -= k;
            if (buffer_len_ == 64) {
                process_block(buffer_);
                buffer_len_ = 0;
            }
        }
    };
    absorb(&pad, 1);
    uint8_t zero = 0;
    while (buffer_len_ != 56) absorb(&zero, 1);
    uint8_t lenbuf[8];
    store_be64(lenbuf, bits);
    absorb(lenbuf, 8);

    Bytes out(20);
    for (int i = 0; i < 5; ++i) store_be32(out.data() + i * 4, h_[i]);
    return out;
}

// ---------------------------------------------------------------- SHA-256 --

namespace {
constexpr uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
}  // namespace

Sha256::Sha256() {
    h_[0] = 0x6a09e667; h_[1] = 0xbb67ae85; h_[2] = 0x3c6ef372; h_[3] = 0xa54ff53a;
    h_[4] = 0x510e527f; h_[5] = 0x9b05688c; h_[6] = 0x1f83d9ab; h_[7] = 0x5be0cd19;
}

void Sha256::process_block(const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = hh + S1 + ch + kSha256K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hh;
}

void Sha256::update(const uint8_t* data, size_t len) {
    total_bits_ += uint64_t(len) * 8;
    while (len > 0) {
        size_t n = std::min(len, size_t(64) - buffer_len_);
        std::memcpy(buffer_ + buffer_len_, data, n);
        buffer_len_ += n;
        data += n;
        len -= n;
        if (buffer_len_ == 64) {
            process_block(buffer_);
            buffer_len_ = 0;
        }
    }
}

Bytes Sha256::finish() {
    uint64_t bits = total_bits_;
    auto absorb = [&](const uint8_t* p, size_t n) {
        while (n > 0) {
            size_t k = std::min(n, size_t(64) - buffer_len_);
            std::memcpy(buffer_ + buffer_len_, p, k);
            buffer_len_ += k;
            p += k;
            n -= k;
            if (buffer_len_ == 64) {
                process_block(buffer_);
                buffer_len_ = 0;
            }
        }
    };
    uint8_t pad = 0x80;
    absorb(&pad, 1);
    uint8_t zero = 0;
    while (buffer_len_ != 56) absorb(&zero, 1);
    uint8_t lenbuf[8];
    store_be64(lenbuf, bits);
    absorb(lenbuf, 8);

    Bytes out(32);
    for (int i = 0; i < 8; ++i) store_be32(out.data() + i * 4, h_[i]);
    return out;
}

// ---------------------------------------------------------------- SHA-512 --

namespace {
constexpr uint64_t kSha512K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};
}  // namespace

Sha512::Sha512() {
    h_[0] = 0x6a09e667f3bcc908ULL; h_[1] = 0xbb67ae8584caa73bULL;
    h_[2] = 0x3c6ef372fe94f82bULL; h_[3] = 0xa54ff53a5f1d36f1ULL;
    h_[4] = 0x510e527fade682d1ULL; h_[5] = 0x9b05688c2b3e6c1fULL;
    h_[6] = 0x1f83d9abfb41bd6bULL; h_[7] = 0x5be0cd19137e2179ULL;
}

void Sha512::process_block(const uint8_t block[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = load_be64(block + i * 8);
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t temp1 = hh + S1 + ch + kSha512K[i] + w[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = S0 + maj;
        hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hh;
}

void Sha512::update(const uint8_t* data, size_t len) {
    uint64_t add_bits = uint64_t(len) * 8;
    uint64_t old = total_bits_lo_;
    total_bits_lo_ += add_bits;
    if (total_bits_lo_ < old) total_bits_hi_++;
    while (len > 0) {
        size_t n = std::min(len, size_t(128) - buffer_len_);
        std::memcpy(buffer_ + buffer_len_, data, n);
        buffer_len_ += n;
        data += n;
        len -= n;
        if (buffer_len_ == 128) {
            process_block(buffer_);
            buffer_len_ = 0;
        }
    }
}

Bytes Sha512::finish() {
    uint64_t bits_lo = total_bits_lo_, bits_hi = total_bits_hi_;
    auto absorb = [&](const uint8_t* p, size_t n) {
        while (n > 0) {
            size_t k = std::min(n, size_t(128) - buffer_len_);
            std::memcpy(buffer_ + buffer_len_, p, k);
            buffer_len_ += k;
            p += k;
            n -= k;
            if (buffer_len_ == 128) {
                process_block(buffer_);
                buffer_len_ = 0;
            }
        }
    };
    uint8_t pad = 0x80;
    absorb(&pad, 1);
    uint8_t zero = 0;
    while (buffer_len_ != 112) absorb(&zero, 1);
    uint8_t lenbuf[16];
    store_be64(lenbuf, bits_hi);
    store_be64(lenbuf + 8, bits_lo);
    absorb(lenbuf, 16);

    Bytes out(64);
    for (int i = 0; i < 8; ++i) store_be64(out.data() + i * 8, h_[i]);
    return out;
}

// ------------------------------------------------------------- one-shot --

Bytes sha1(const Bytes& data) {
    Sha1 h;
    h.update(data);
    return h.finish();
}
Bytes sha256(const Bytes& data) {
    Sha256 h;
    h.update(data);
    return h.finish();
}
Bytes sha512(const Bytes& data) {
    Sha512 h;
    h.update(data);
    return h.finish();
}

bool sha_selftest() {
    const Bytes abc = {'a', 'b', 'c'};
    auto hex = [](const Bytes& b) {
        static const char* d = "0123456789abcdef";
        std::string s;
        s.reserve(b.size() * 2);
        for (uint8_t c : b) {
            s.push_back(d[c >> 4]);
            s.push_back(d[c & 0xf]);
        }
        return s;
    };
    bool ok = true;
    ok = ok && hex(sha1(abc)) == "a9993e364706816aba3e25717850c26c9cd0d89d";
    ok = ok && hex(sha256(abc)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    ok = ok && hex(sha512(abc)) ==
                   "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39"
                   "a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    return ok;
}

}  // namespace abr::hash
