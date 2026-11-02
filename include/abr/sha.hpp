// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::hash -- self-contained SHA-1/SHA-256/SHA-384/SHA-512 (FIPS 180-4) and MD5 (RFC 1321). abr links
// no crypto library: this is what the boot `id`, the AVB digests and the
// RSA signatures (src/rsa.cpp, over src/bigint.cpp) are all built on, the
// same on Linux, Windows and Android. OpenSSL, avbtool and boot_signer are
// used by the test suite only, as independent oracles.
//
// Hashing is where an unpack spends most of its time (every component is
// hashed several times: boot id, replay check, envelope, AVB digest, signature
// verification), so SHA-1 and SHA-256 use the CPU's own instructions when it
// has them -- x86-64 SHA-NI, ARMv8 SHA1/SHA2 -- chosen at run time, with a
// portable implementation (and the same results) everywhere else. The
// binary stays a single file that runs on any CPU of its architecture.
//
// Implemented from the FIPS 180-4 specification; round constants
// cross-checked against multiple independent public-domain reference
// implementations (see PROGRESS.md) and verified against the standard
// NIST test vectors for "abc" in sha_selftest(). tests/run_tests.sh compares
// every implementation with Python's hashlib on inputs of all awkward lengths.
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
    uint32_t h_[8];
    uint8_t buffer_[64];
    size_t buffer_len_ = 0;
    uint64_t total_bits_ = 0;
};

class Sha512 {
public:
    // SHA-384 is SHA-512 with other start values and a digest of the first 48 bytes (FIPS 180-4, 5.3.4 and 6.5).
    enum class Variant { SHA512, SHA384 };
    explicit Sha512(Variant variant = Variant::SHA512);
    void update(const uint8_t* data, size_t len);
    void update(const Bytes& data) { update(data.data(), data.size()); }
    Bytes finish();  // 64 bytes (48 for SHA-384)

private:
    void process_block(const uint8_t block[128]);
    uint64_t h_[8];
    uint8_t buffer_[128];
    size_t buffer_len_ = 0;
    uint64_t total_bits_lo_ = 0, total_bits_hi_ = 0;
    size_t digest_size_ = 64;
};

class Sha384 : public Sha512 {
public:
    Sha384() : Sha512(Variant::SHA384) {}
};

// MD5 (RFC 1321). It is here for the `hash` nodes of a FIT image (U-Boot's mkimage writes "md5" ones); nothing abr signs or
// verifies is made with it.
class Md5 {
public:
    Md5();
    void update(const uint8_t* data, size_t len);
    void update(const Bytes& data) { update(data.data(), data.size()); }
    Bytes finish();  // 16 bytes

private:
    void process_block(const uint8_t block[64]);
    uint32_t h_[4];
    uint8_t buffer_[64];
    size_t buffer_len_ = 0;
    uint64_t total_bits_ = 0;
};

Bytes sha1(const Bytes& data);
Bytes sha256(const Bytes& data);
Bytes sha384(const Bytes& data);
Bytes sha512(const Bytes& data);
Bytes md5(const Bytes& data);
Bytes sha1(const uint8_t* data, size_t len);
Bytes sha256(const uint8_t* data, size_t len);
Bytes sha384(const uint8_t* data, size_t len);
Bytes sha512(const uint8_t* data, size_t len);
Bytes md5(const uint8_t* data, size_t len);

// What computes SHA-1 / SHA-256 in this process: "portable", "x86 SHA-NI",
// "ARMv8 SHA1/SHA2" (or a mix, e.g. "ARMv8 SHA2 + portable SHA-1"). Decided
// once from the CPU; setting the environment variable ABR_SHA_IMPL=portable
// forces the portable code.
const char* implementation_name();

// For tests: true switches to the portable code, false back to what the CPU
// offers. Not thread-safe against concurrent hashing.
void force_portable(bool on);

// Hashes the FIPS 180-4 / NIST test vector "abc" with all the
// algorithms and returns true iff every digest matches the published
// known-answer value. Called once from main() at startup (cheap) so a
// broken build fails loudly instead of silently mis-hashing images.
bool sha_selftest();

}  // namespace abr::hash
