// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::hash -- self-contained SHA-1/SHA-256/SHA-512 (FIPS 180-4). abr links
// no crypto library: this is what the boot `id`, the AVB digests and the
// RSA signatures (src/rsa.cpp, over src/bigint.cpp) are all built on, the
// same on Linux, Windows and Android. OpenSSL, avbtool and boot_signer are
// used by the test suite only, as independent oracles.
//
// Implemented from the FIPS 180-4 specification; round constants
// cross-checked against multiple independent public-domain reference
// implementations (see PROGRESS.md) and verified against the standard
// NIST test vectors for "abc" in sha_selftest().
#pragma once

#include <cstdint>
#include <cstddef>

#include "abr/byte_io.hpp"

namespace abr::hash {

class Sha1 {
public:
    Sha1();
    void update(const uint8_t* data, size_t len);
    void update(const Bytes& data) { update(data.data(), data.size()); }
    Bytes finish();  // 20 bytes

private:
    void process_block(const uint8_t block[64]);
    uint32_t h_[5];
    uint8_t buffer_[64];
    size_t buffer_len_ = 0;
    uint64_t total_bits_ = 0;
};

class Sha256 {
public:
    Sha256();
    void update(const uint8_t* data, size_t len);
    void update(const Bytes& data) { update(data.data(), data.size()); }
    Bytes finish();  // 32 bytes

private:
    void process_block(const uint8_t block[64]);
    uint32_t h_[8];
    uint8_t buffer_[64];
    size_t buffer_len_ = 0;
    uint64_t total_bits_ = 0;
};

class Sha512 {
public:
    Sha512();
    void update(const uint8_t* data, size_t len);
    void update(const Bytes& data) { update(data.data(), data.size()); }
    Bytes finish();  // 64 bytes

private:
    void process_block(const uint8_t block[128]);
    uint64_t h_[8];
    uint8_t buffer_[128];
    size_t buffer_len_ = 0;
    uint64_t total_bits_lo_ = 0, total_bits_hi_ = 0;
};

Bytes sha1(const Bytes& data);
Bytes sha256(const Bytes& data);
Bytes sha512(const Bytes& data);

// Hashes the FIPS 180-4 / NIST test vector "abc" with all three
// algorithms and returns true iff every digest matches the published
// known-answer value. Called once from main() at startup (cheap) so a
// broken build fails loudly instead of silently mis-hashing images.
bool sha_selftest();

}  // namespace abr::hash
