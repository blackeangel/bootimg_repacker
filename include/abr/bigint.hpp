// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::BigInt -- an unsigned arbitrary-precision integer, just enough for
// RSA (modular exponentiation, parsing/serialising big-endian numbers).
//
// Why this exists: AVB and boot-signature re-signing need RSA, and the
// project goal is one self-contained static binary that behaves the same on
// Linux, Windows and Android -- not "re-signing works only where OpenSSL
// happened to be installed". The algorithms are the textbook ones (Knuth
// vol. 2, 4.3.1 algorithm D for division; Montgomery CIOS multiplication
// for the modular exponentiation) and are checked against Python's
// arbitrary-precision integers by tests/tools/gen_bigint_vectors.py.
//
// Not constant-time. This tool signs images on a developer's own machine
// with their own key; it is not a network service and nothing here tries to
// resist timing side channels.
#pragma once

#include "abr/byte_io.hpp"

#include <cstdint>
#include <vector>

namespace abr {

class BigInt {
public:
    BigInt() = default;
    explicit BigInt(uint64_t v);

    // Big-endian magnitude, as used by DER INTEGER contents, RSA moduli and
    // PKCS#1 signatures. Leading zero bytes are accepted and ignored.
    static BigInt from_bytes_be(const uint8_t* p, size_t n);
    static BigInt from_bytes_be(const Bytes& b) { return from_bytes_be(b.data(), b.size()); }

    // Big-endian, left-padded with zeros to `width` bytes. width == 0 means
    // "as short as possible, but at least one byte". Throws FormatError if
    // the value does not fit in `width` bytes.
    Bytes to_bytes_be(size_t width = 0) const;

    size_t bit_length() const;
    bool is_zero() const { return d_.empty(); }
    bool is_odd() const { return !d_.empty() && (d_[0] & 1u); }
    bool bit(size_t index) const;
    uint32_t low32() const { return d_.empty() ? 0 : d_[0]; }
    size_t limbs() const { return d_.size(); }

    static int compare(const BigInt& a, const BigInt& b);
    friend bool operator==(const BigInt& a, const BigInt& b) { return a.d_ == b.d_; }
    friend bool operator!=(const BigInt& a, const BigInt& b) { return !(a == b); }
    friend bool operator<(const BigInt& a, const BigInt& b) { return compare(a, b) < 0; }

    static BigInt add(const BigInt& a, const BigInt& b);
    // Requires a >= b (this type has no sign).
    static BigInt sub(const BigInt& a, const BigInt& b);
    static BigInt mul(const BigInt& a, const BigInt& b);
    // q = a / b, r = a % b. Throws FormatError when b is zero.
    static void divmod(const BigInt& a, const BigInt& b, BigInt& q, BigInt& r);
    BigInt mod(const BigInt& m) const;
    BigInt shl(size_t bits) const;
    BigInt shr(size_t bits) const;

    // base^exp mod m. m must be non-zero. Uses Montgomery multiplication
    // for odd moduli (every RSA modulus and prime factor), plain
    // square-and-multiply otherwise.
    static BigInt mod_exp(const BigInt& base, const BigInt& exp, const BigInt& m);

private:
    void trim();
    std::vector<uint32_t> d_;  // little-endian limbs, no most-significant zero limbs
};

// -n^-1 mod 2^32 for an odd n: the Montgomery constant, and the `n0inv` field
// of an AVB public key.
uint32_t neg_inverse_mod32(uint32_t odd);

}  // namespace abr
