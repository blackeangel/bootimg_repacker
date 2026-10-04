// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/sha.hpp"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <string_view>

// CPU-specific code. Each block below is compiled only for its architecture,
// and its functions carry a per-function `target` attribute instead of a
// global -m flag: the binary still runs on a CPU without the extension, and
// the choice is made at run time (backend()).
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define ABR_SHA_X86 1
#include <cpuid.h>
#include <immintrin.h>
#endif
#if defined(__aarch64__) && !defined(__ARM_BIG_ENDIAN) && (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__linux__) || defined(__ANDROID__) || defined(_WIN32))
#define ABR_SHA_ARM 1
#include <arm_neon.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/auxv.h>
#endif
#endif

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

alignas(16) constexpr uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// ------------------------------------------------------------ portable --
// Both compress functions take whole 64-byte blocks straight from the caller's
// buffer: `nb` blocks starting at `p`. The rounds are fully unrolled with
// literal round numbers, so the 16-word message window and the round constants
// are addressed at compile time and the working variables rotate by renaming
// (the macro arguments are permuted) instead of by moves.

// Round R of SHA-1 (R a literal 0..79); the message schedule for R >= 16 is
// extended in place (w[R-3], w[R-8], w[R-14], w[R-16] are R+13, R+8, R+2, R
// modulo 16). F is Ch / parity / Maj of b, c, d.
#define ABR_SHA1_CH(b, c, d) ((d) ^ ((b) & ((c) ^ (d))))
#define ABR_SHA1_PAR(b, c, d) ((b) ^ (c) ^ (d))
#define ABR_SHA1_MAJ(b, c, d) (((b) & (c)) | ((d) & ((b) | (c))))
#define ABR_SHA1_R(a, b, c, d, e, F, K, R)                                                              \
    do {                                                                                                \
        if ((R) >= 16)                                                                                  \
            w[(R) & 15] = rotl32(w[((R) + 13) & 15] ^ w[((R) + 8) & 15] ^ w[((R) + 2) & 15] ^ w[(R) & 15], 1); \
        e += rotl32(a, 5) + F(b, c, d) + (K) + w[(R) & 15];                                             \
        b = rotl32(b, 30);                                                                              \
    } while (0)
#define ABR_SHA1_5(F, K, R)                    \
    ABR_SHA1_R(a, b, c, d, e, F, K, (R) + 0);  \
    ABR_SHA1_R(e, a, b, c, d, F, K, (R) + 1);  \
    ABR_SHA1_R(d, e, a, b, c, F, K, (R) + 2);  \
    ABR_SHA1_R(c, d, e, a, b, F, K, (R) + 3);  \
    ABR_SHA1_R(b, c, d, e, a, F, K, (R) + 4)

void sha1_blocks_portable(uint32_t st[5], const uint8_t* p, size_t nb) {
    for (; nb; --nb, p += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; ++i) w[i] = load_be32(p + 4 * i);
        uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4];
        ABR_SHA1_5(ABR_SHA1_CH, 0x5A827999u, 0);
        ABR_SHA1_5(ABR_SHA1_CH, 0x5A827999u, 5);
        ABR_SHA1_5(ABR_SHA1_CH, 0x5A827999u, 10);
        ABR_SHA1_5(ABR_SHA1_CH, 0x5A827999u, 15);
        ABR_SHA1_5(ABR_SHA1_PAR, 0x6ED9EBA1u, 20);
        ABR_SHA1_5(ABR_SHA1_PAR, 0x6ED9EBA1u, 25);
        ABR_SHA1_5(ABR_SHA1_PAR, 0x6ED9EBA1u, 30);
        ABR_SHA1_5(ABR_SHA1_PAR, 0x6ED9EBA1u, 35);
        ABR_SHA1_5(ABR_SHA1_MAJ, 0x8F1BBCDCu, 40);
        ABR_SHA1_5(ABR_SHA1_MAJ, 0x8F1BBCDCu, 45);
        ABR_SHA1_5(ABR_SHA1_MAJ, 0x8F1BBCDCu, 50);
        ABR_SHA1_5(ABR_SHA1_MAJ, 0x8F1BBCDCu, 55);
        ABR_SHA1_5(ABR_SHA1_PAR, 0xCA62C1D6u, 60);
        ABR_SHA1_5(ABR_SHA1_PAR, 0xCA62C1D6u, 65);
        ABR_SHA1_5(ABR_SHA1_PAR, 0xCA62C1D6u, 70);
        ABR_SHA1_5(ABR_SHA1_PAR, 0xCA62C1D6u, 75);
        st[0] += a;
        st[1] += b;
        st[2] += c;
        st[3] += d;
        st[4] += e;
    }
}
#undef ABR_SHA1_CH
#undef ABR_SHA1_PAR
#undef ABR_SHA1_MAJ
#undef ABR_SHA1_R
#undef ABR_SHA1_5

// Round R of SHA-256 (R a literal 0..63); the schedule for R >= 16 is extended
// in place in the 16-word window (w[R-15], w[R-7], w[R-2] are R+1, R+9, R+14
// modulo 16, and w[R&15] still holds w[R-16]).
#define ABR_SHA256_RND(a, b, c, d, e, f, g, h, R)                                                          \
    do {                                                                                                    \
        if ((R) >= 16) {                                                                                    \
            const uint32_t w15 = w[((R) + 1) & 15], w2 = w[((R) + 14) & 15];                                \
            w[(R) & 15] += (rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >> 3)) + w[((R) + 9) & 15] +           \
                           (rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >> 10));                                  \
        }                                                                                                   \
        const uint32_t t1 = h + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + (g ^ (e & (f ^ g))) +      \
                            kSha256K[R] + w[(R) & 15];                                                      \
        const uint32_t t2 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) | (c & (a | b)));     \
        d += t1;                                                                                            \
        h = t1 + t2;                                                                                        \
    } while (0)
#define ABR_SHA256_8(R)                                  \
    ABR_SHA256_RND(a, b, c, d, e, f, g, h, (R) + 0);     \
    ABR_SHA256_RND(h, a, b, c, d, e, f, g, (R) + 1);     \
    ABR_SHA256_RND(g, h, a, b, c, d, e, f, (R) + 2);     \
    ABR_SHA256_RND(f, g, h, a, b, c, d, e, (R) + 3);     \
    ABR_SHA256_RND(e, f, g, h, a, b, c, d, (R) + 4);     \
    ABR_SHA256_RND(d, e, f, g, h, a, b, c, (R) + 5);     \
    ABR_SHA256_RND(c, d, e, f, g, h, a, b, (R) + 6);     \
    ABR_SHA256_RND(b, c, d, e, f, g, h, a, (R) + 7)

void sha256_blocks_portable(uint32_t st[8], const uint8_t* p, size_t nb) {
    for (; nb; --nb, p += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; ++i) w[i] = load_be32(p + 4 * i);
        uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
        ABR_SHA256_8(0);
        ABR_SHA256_8(8);
        ABR_SHA256_8(16);
        ABR_SHA256_8(24);
        ABR_SHA256_8(32);
        ABR_SHA256_8(40);
        ABR_SHA256_8(48);
        ABR_SHA256_8(56);
        st[0] += a;
        st[1] += b;
        st[2] += c;
        st[3] += d;
        st[4] += e;
        st[5] += f;
        st[6] += g;
        st[7] += h;
    }
}
#undef ABR_SHA256_RND
#undef ABR_SHA256_8

// --------------------------------------------------- x86-64 SHA extensions --
#ifdef ABR_SHA_X86

#define ABR_X86_SHA_TARGET __attribute__((target("sha,sse4.1,ssse3")))
#define ABR_FORCE_INLINE inline __attribute__((always_inline))

bool x86_has_sha_ni() {
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return false;
    if (!(ecx & (1u << 9)) || !(ecx & (1u << 19))) return false;  // SSSE3, SSE4.1
    if (__get_cpuid_max(0, nullptr) < 7) return false;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1u << 29)) != 0;  // SHA
}

// Four rounds of SHA-256. The state is kept as ABEF / CDGH (what the
// instructions want); m[] holds the message schedule four words at a time and
// is extended in place: X[g] = msg2(msg1(X[g-4], X[g-3]) + (X[g-1]:X[g-2] >> 4 bytes), X[g-1]).
template <int G>
ABR_X86_SHA_TARGET ABR_FORCE_INLINE void sha256_quad_ni(__m128i& s0, __m128i& s1, __m128i (&m)[4]) {
    if constexpr (G >= 4) {
        constexpr int a = G & 3, b = (G + 1) & 3, c = (G + 2) & 3, d = (G + 3) & 3;
        __m128i t = _mm_sha256msg1_epu32(m[a], m[b]);
        t = _mm_add_epi32(t, _mm_alignr_epi8(m[d], m[c], 4));
        m[a] = _mm_sha256msg2_epu32(t, m[d]);
    }
    __m128i wk = _mm_add_epi32(m[G & 3], _mm_loadu_si128(reinterpret_cast<const __m128i*>(kSha256K + 4 * G)));
    s1 = _mm_sha256rnds2_epu32(s1, s0, wk);
    wk = _mm_shuffle_epi32(wk, 0x0E);
    s0 = _mm_sha256rnds2_epu32(s0, s1, wk);
}

ABR_X86_SHA_TARGET void sha256_blocks_ni(uint32_t st[8], const uint8_t* p, size_t nb) {
    const __m128i mask = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
    __m128i tmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(st));      // a b c d
    __m128i s1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(st + 4));   // e f g h
    tmp = _mm_shuffle_epi32(tmp, 0xB1);                                        // b a d c
    s1 = _mm_shuffle_epi32(s1, 0x1B);                                          // h g f e
    __m128i s0 = _mm_alignr_epi8(tmp, s1, 8);                                  // f e b a  (ABEF)
    s1 = _mm_blend_epi16(s1, tmp, 0xF0);                                       // h g d c  (CDGH)

    for (; nb; --nb, p += 64) {
        const __m128i abef = s0, cdgh = s1;
        __m128i m[4];
        m[0] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p)), mask);
        m[1] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 16)), mask);
        m[2] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 32)), mask);
        m[3] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 48)), mask);
        sha256_quad_ni<0>(s0, s1, m);
        sha256_quad_ni<1>(s0, s1, m);
        sha256_quad_ni<2>(s0, s1, m);
        sha256_quad_ni<3>(s0, s1, m);
        sha256_quad_ni<4>(s0, s1, m);
        sha256_quad_ni<5>(s0, s1, m);
        sha256_quad_ni<6>(s0, s1, m);
        sha256_quad_ni<7>(s0, s1, m);
        sha256_quad_ni<8>(s0, s1, m);
        sha256_quad_ni<9>(s0, s1, m);
        sha256_quad_ni<10>(s0, s1, m);
        sha256_quad_ni<11>(s0, s1, m);
        sha256_quad_ni<12>(s0, s1, m);
        sha256_quad_ni<13>(s0, s1, m);
        sha256_quad_ni<14>(s0, s1, m);
        sha256_quad_ni<15>(s0, s1, m);
        s0 = _mm_add_epi32(s0, abef);
        s1 = _mm_add_epi32(s1, cdgh);
    }

    tmp = _mm_shuffle_epi32(s0, 0x1B);        // a b e f
    s1 = _mm_shuffle_epi32(s1, 0xB1);         // d c h g
    s0 = _mm_blend_epi16(tmp, s1, 0xF0);      // d c b a
    s1 = _mm_alignr_epi8(s1, tmp, 8);         // h g f e
    _mm_storeu_si128(reinterpret_cast<__m128i*>(st), s0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(st + 4), s1);
}

// Four rounds of SHA-1. abcd keeps A in its top lane; `prev` is the value abcd
// had before the previous group, from which sha1nexte derives E.
template <int G>
ABR_X86_SHA_TARGET ABR_FORCE_INLINE void sha1_quad_ni(__m128i& abcd, __m128i& prev, const __m128i& e_init,
                                                      __m128i (&m)[4]) {
    if constexpr (G >= 4) {
        constexpr int a = G & 3, b = (G + 1) & 3, c = (G + 2) & 3, d = (G + 3) & 3;
        __m128i t = _mm_sha1msg1_epu32(m[a], m[b]);
        t = _mm_xor_si128(t, m[c]);
        m[a] = _mm_sha1msg2_epu32(t, m[d]);
    }
    __m128i e;
    if constexpr (G == 0)
        e = _mm_add_epi32(e_init, m[0]);
    else
        e = _mm_sha1nexte_epu32(prev, m[G & 3]);
    prev = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e, G / 5);
}

ABR_X86_SHA_TARGET void sha1_blocks_ni(uint32_t st[5], const uint8_t* p, size_t nb) {
    const __m128i mask = _mm_set_epi64x(0x0001020304050607LL, 0x08090a0b0c0d0e0fLL);
    __m128i abcd = _mm_shuffle_epi32(_mm_loadu_si128(reinterpret_cast<const __m128i*>(st)), 0x1B);
    __m128i e0 = _mm_set_epi32(static_cast<int>(st[4]), 0, 0, 0);

    for (; nb; --nb, p += 64) {
        const __m128i abcd_save = abcd, e0_save = e0;
        __m128i m[4], prev = abcd;
        m[0] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p)), mask);
        m[1] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 16)), mask);
        m[2] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 32)), mask);
        m[3] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 48)), mask);
        sha1_quad_ni<0>(abcd, prev, e0, m);
        sha1_quad_ni<1>(abcd, prev, e0, m);
        sha1_quad_ni<2>(abcd, prev, e0, m);
        sha1_quad_ni<3>(abcd, prev, e0, m);
        sha1_quad_ni<4>(abcd, prev, e0, m);
        sha1_quad_ni<5>(abcd, prev, e0, m);
        sha1_quad_ni<6>(abcd, prev, e0, m);
        sha1_quad_ni<7>(abcd, prev, e0, m);
        sha1_quad_ni<8>(abcd, prev, e0, m);
        sha1_quad_ni<9>(abcd, prev, e0, m);
        sha1_quad_ni<10>(abcd, prev, e0, m);
        sha1_quad_ni<11>(abcd, prev, e0, m);
        sha1_quad_ni<12>(abcd, prev, e0, m);
        sha1_quad_ni<13>(abcd, prev, e0, m);
        sha1_quad_ni<14>(abcd, prev, e0, m);
        sha1_quad_ni<15>(abcd, prev, e0, m);
        sha1_quad_ni<16>(abcd, prev, e0, m);
        sha1_quad_ni<17>(abcd, prev, e0, m);
        sha1_quad_ni<18>(abcd, prev, e0, m);
        sha1_quad_ni<19>(abcd, prev, e0, m);
        e0 = _mm_sha1nexte_epu32(prev, e0_save);
        abcd = _mm_add_epi32(abcd, abcd_save);
    }

    _mm_storeu_si128(reinterpret_cast<__m128i*>(st), _mm_shuffle_epi32(abcd, 0x1B));
    st[4] = static_cast<uint32_t>(_mm_extract_epi32(e0, 3));
}

#endif  // ABR_SHA_X86

// ------------------------------------------------------ ARMv8 SHA1 / SHA2 --
#ifdef ABR_SHA_ARM

#if defined(__clang__)
#define ABR_ARM_SHA_TARGET __attribute__((target("sha2")))
#else
#define ABR_ARM_SHA_TARGET __attribute__((target("arch=armv8-a+crypto")))
#endif
#define ABR_FORCE_INLINE inline __attribute__((always_inline))

#ifndef HWCAP_SHA1
#define HWCAP_SHA1 (1 << 5)
#endif
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1 << 6)
#endif

bool arm_has_sha1() {
#if defined(_WIN32)
    return IsProcessorFeaturePresent(30 /* PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE */) != 0;
#else
    return (getauxval(AT_HWCAP) & HWCAP_SHA1) != 0;
#endif
}
bool arm_has_sha2() {
#if defined(_WIN32)
    return IsProcessorFeaturePresent(30 /* PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE */) != 0;
#else
    return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#endif
}

template <int G>
ABR_ARM_SHA_TARGET ABR_FORCE_INLINE void sha256_quad_arm(uint32x4_t& s0, uint32x4_t& s1, uint32x4_t (&m)[4]) {
    if constexpr (G >= 4) {
        constexpr int a = G & 3, b = (G + 1) & 3, c = (G + 2) & 3, d = (G + 3) & 3;
        m[a] = vsha256su1q_u32(vsha256su0q_u32(m[a], m[b]), m[c], m[d]);
    }
    const uint32x4_t wk = vaddq_u32(m[G & 3], vld1q_u32(kSha256K + 4 * G));
    const uint32x4_t old0 = s0;
    s0 = vsha256hq_u32(s0, s1, wk);
    s1 = vsha256h2q_u32(s1, old0, wk);
}

ABR_ARM_SHA_TARGET void sha256_blocks_arm(uint32_t st[8], const uint8_t* p, size_t nb) {
    uint32x4_t s0 = vld1q_u32(st), s1 = vld1q_u32(st + 4);
    for (; nb; --nb, p += 64) {
        const uint32x4_t save0 = s0, save1 = s1;
        uint32x4_t m[4];
        m[0] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)));
        m[1] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16)));
        m[2] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 32)));
        m[3] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 48)));
        sha256_quad_arm<0>(s0, s1, m);
        sha256_quad_arm<1>(s0, s1, m);
        sha256_quad_arm<2>(s0, s1, m);
        sha256_quad_arm<3>(s0, s1, m);
        sha256_quad_arm<4>(s0, s1, m);
        sha256_quad_arm<5>(s0, s1, m);
        sha256_quad_arm<6>(s0, s1, m);
        sha256_quad_arm<7>(s0, s1, m);
        sha256_quad_arm<8>(s0, s1, m);
        sha256_quad_arm<9>(s0, s1, m);
        sha256_quad_arm<10>(s0, s1, m);
        sha256_quad_arm<11>(s0, s1, m);
        sha256_quad_arm<12>(s0, s1, m);
        sha256_quad_arm<13>(s0, s1, m);
        sha256_quad_arm<14>(s0, s1, m);
        sha256_quad_arm<15>(s0, s1, m);
        s0 = vaddq_u32(s0, save0);
        s1 = vaddq_u32(s1, save1);
    }
    vst1q_u32(st, s0);
    vst1q_u32(st + 4, s1);
}

template <int G>
ABR_ARM_SHA_TARGET ABR_FORCE_INLINE void sha1_quad_arm(uint32x4_t& abcd, uint32_t& e, uint32x4_t (&m)[4]) {
    if constexpr (G >= 4) {
        constexpr int a = G & 3, b = (G + 1) & 3, c = (G + 2) & 3, d = (G + 3) & 3;
        m[a] = vsha1su1q_u32(vsha1su0q_u32(m[a], m[b], m[c]), m[d]);
    }
    constexpr uint32_t k = G < 5 ? 0x5A827999u : G < 10 ? 0x6ED9EBA1u : G < 15 ? 0x8F1BBCDCu : 0xCA62C1D6u;
    const uint32x4_t wk = vaddq_u32(m[G & 3], vdupq_n_u32(k));
    const uint32_t e_next = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    if constexpr (G < 5)
        abcd = vsha1cq_u32(abcd, e, wk);
    else if constexpr (G < 10)
        abcd = vsha1pq_u32(abcd, e, wk);
    else if constexpr (G < 15)
        abcd = vsha1mq_u32(abcd, e, wk);
    else
        abcd = vsha1pq_u32(abcd, e, wk);
    e = e_next;
}

ABR_ARM_SHA_TARGET void sha1_blocks_arm(uint32_t st[5], const uint8_t* p, size_t nb) {
    uint32x4_t abcd = vld1q_u32(st);
    uint32_t e = st[4];
    for (; nb; --nb, p += 64) {
        const uint32x4_t abcd_save = abcd;
        const uint32_t e_save = e;
        uint32x4_t m[4];
        m[0] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)));
        m[1] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16)));
        m[2] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 32)));
        m[3] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 48)));
        sha1_quad_arm<0>(abcd, e, m);
        sha1_quad_arm<1>(abcd, e, m);
        sha1_quad_arm<2>(abcd, e, m);
        sha1_quad_arm<3>(abcd, e, m);
        sha1_quad_arm<4>(abcd, e, m);
        sha1_quad_arm<5>(abcd, e, m);
        sha1_quad_arm<6>(abcd, e, m);
        sha1_quad_arm<7>(abcd, e, m);
        sha1_quad_arm<8>(abcd, e, m);
        sha1_quad_arm<9>(abcd, e, m);
        sha1_quad_arm<10>(abcd, e, m);
        sha1_quad_arm<11>(abcd, e, m);
        sha1_quad_arm<12>(abcd, e, m);
        sha1_quad_arm<13>(abcd, e, m);
        sha1_quad_arm<14>(abcd, e, m);
        sha1_quad_arm<15>(abcd, e, m);
        sha1_quad_arm<16>(abcd, e, m);
        sha1_quad_arm<17>(abcd, e, m);
        sha1_quad_arm<18>(abcd, e, m);
        sha1_quad_arm<19>(abcd, e, m);
        abcd = vaddq_u32(abcd, abcd_save);
        e += e_save;
    }
    vst1q_u32(st, abcd);
    st[4] = e;
}

#endif  // ABR_SHA_ARM

// ------------------------------------------------------------- selection --

using Sha1Blocks = void (*)(uint32_t*, const uint8_t*, size_t);
using Sha256Blocks = void (*)(uint32_t*, const uint8_t*, size_t);

struct Backend {
    const char* name;
    Sha1Blocks sha1;
    Sha256Blocks sha256;
};

const Backend kPortable{"portable", sha1_blocks_portable, sha256_blocks_portable};

const Backend& detected() {
    static const Backend& chosen = []() -> const Backend& {
        const char* forced = std::getenv("ABR_SHA_IMPL");
        if (forced && std::string_view(forced) == "portable") return kPortable;
#ifdef ABR_SHA_X86
        static const Backend kNi{"x86 SHA-NI", sha1_blocks_ni, sha256_blocks_ni};
        if (x86_has_sha_ni()) return kNi;
#endif
#ifdef ABR_SHA_ARM
        static const Backend kBoth{"ARMv8 SHA1/SHA2", sha1_blocks_arm, sha256_blocks_arm};
        static const Backend kSha2Only{"ARMv8 SHA2 + portable SHA-1", sha1_blocks_portable, sha256_blocks_arm};
        static const Backend kSha1Only{"ARMv8 SHA1 + portable SHA-256", sha1_blocks_arm, sha256_blocks_portable};
        const bool s1 = arm_has_sha1(), s2 = arm_has_sha2();
        if (s1 && s2) return kBoth;
        if (s2) return kSha2Only;
        if (s1) return kSha1Only;
#endif
        return kPortable;
    }();
    return chosen;
}

std::atomic<const Backend*> g_override{nullptr};

inline const Backend& backend() {
    const Backend* o = g_override.load(std::memory_order_relaxed);
    return o ? *o : detected();
}

}  // namespace

const char* implementation_name() { return backend().name; }

void force_portable(bool on) { g_override.store(on ? &kPortable : nullptr, std::memory_order_relaxed); }

// ------------------------------------------------------------------ SHA-1 --

Sha1::Sha1() {
    h_[0] = 0x67452301;
    h_[1] = 0xEFCDAB89;
    h_[2] = 0x98BADCFE;
    h_[3] = 0x10325476;
    h_[4] = 0xC3D2E1F0;
}

void Sha1::update(const uint8_t* data, size_t len) {
    if (len == 0) return;
    total_bits_ += uint64_t(len) * 8;
    const auto blocks = backend().sha1;
    if (buffer_len_) {
        size_t n = std::min(len, size_t(64) - buffer_len_);
        std::memcpy(buffer_ + buffer_len_, data, n);
        buffer_len_ += n;
        data += n;
        len -= n;
        if (buffer_len_ < 64) return;
        blocks(h_, buffer_, 1);
        buffer_len_ = 0;
    }
    if (size_t nb = len / 64) {
        blocks(h_, data, nb);
        data += nb * 64;
        len -= nb * 64;
    }
    if (len) {
        std::memcpy(buffer_, data, len);
        buffer_len_ = len;
    }
}

Bytes Sha1::finish() {
    uint8_t tail[128] = {};
    std::memcpy(tail, buffer_, buffer_len_);
    tail[buffer_len_] = 0x80;
    const size_t total = (buffer_len_ + 1 + 8 <= 64) ? 64 : 128;
    store_be64(tail + total - 8, total_bits_);
    backend().sha1(h_, tail, total / 64);

    Bytes out(20);
    for (int i = 0; i < 5; ++i) store_be32(out.data() + i * 4, h_[i]);
    return out;
}

// ---------------------------------------------------------------- SHA-256 --

Sha256::Sha256() {
    h_[0] = 0x6a09e667; h_[1] = 0xbb67ae85; h_[2] = 0x3c6ef372; h_[3] = 0xa54ff53a;
    h_[4] = 0x510e527f; h_[5] = 0x9b05688c; h_[6] = 0x1f83d9ab; h_[7] = 0x5be0cd19;
}

void Sha256::update(const uint8_t* data, size_t len) {
    if (len == 0) return;
    total_bits_ += uint64_t(len) * 8;
    const auto blocks = backend().sha256;
    if (buffer_len_) {
        size_t n = std::min(len, size_t(64) - buffer_len_);
        std::memcpy(buffer_ + buffer_len_, data, n);
        buffer_len_ += n;
        data += n;
        len -= n;
        if (buffer_len_ < 64) return;
        blocks(h_, buffer_, 1);
        buffer_len_ = 0;
    }
    if (size_t nb = len / 64) {
        blocks(h_, data, nb);
        data += nb * 64;
        len -= nb * 64;
    }
    if (len) {
        std::memcpy(buffer_, data, len);
        buffer_len_ = len;
    }
}

Bytes Sha256::finish() {
    uint8_t tail[128] = {};
    std::memcpy(tail, buffer_, buffer_len_);
    tail[buffer_len_] = 0x80;
    const size_t total = (buffer_len_ + 1 + 8 <= 64) ? 64 : 128;
    store_be64(tail + total - 8, total_bits_);
    backend().sha256(h_, tail, total / 64);

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

Bytes sha1(const uint8_t* data, size_t len) {
    Sha1 h;
    h.update(data, len);
    return h.finish();
}
Bytes sha256(const uint8_t* data, size_t len) {
    Sha256 h;
    h.update(data, len);
    return h.finish();
}
Bytes sha512(const uint8_t* data, size_t len) {
    Sha512 h;
    h.update(data, len);
    return h.finish();
}
Bytes sha1(const Bytes& data) { return sha1(data.data(), data.size()); }
Bytes sha256(const Bytes& data) { return sha256(data.data(), data.size()); }
Bytes sha512(const Bytes& data) { return sha512(data.data(), data.size()); }

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
