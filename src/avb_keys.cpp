// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/avb_keys.hpp"

#include <cstring>
#include <mutex>
#include <optional>
#include <vector>

#include "abr/rsa.hpp"
#include "abr/sha.hpp"
#include "abr/vbmeta.hpp"

namespace abr {

namespace {

// The public key of the key at `index` in the form a vbmeta stores it. Made when it is first asked for and kept: the R^2 of a key of
// 8192 bits is not free, and most asks are about a key of one size only.
Bytes public_blob_of(size_t index) {
    static std::mutex mu;
    static std::vector<std::optional<Bytes>> cache(detail::kAvbTestKeyCount);
    std::lock_guard<std::mutex> lock(mu);
    if (!cache[index]) {
        const char* pem = detail::kAvbTestKeys[index].pem;
        const RsaPrivateKey key = rsa_parse_private_key(Bytes(reinterpret_cast<const uint8_t*>(pem), reinterpret_cast<const uint8_t*>(pem) + std::strlen(pem)));
        cache[index] = avb_encode_public_key(key.public_key());
    }
    return *cache[index];
}

// What a vbmeta's public key of `bits` bits takes: AvbRSAPublicKeyHeader (num_bits, n0inv), the modulus and R^2 mod n.
size_t blob_size(unsigned bits) { return 8 + 2 * static_cast<size_t>(bits / 8); }

}  // namespace

std::span<const AvbTestKey> avb_test_keys() { return {detail::kAvbTestKeys, detail::kAvbTestKeyCount}; }

const AvbTestKey* find_avb_test_key(const Bytes& public_key_blob) {
    if (public_key_blob.size() < 8) return nullptr;
    const uint32_t bits = (uint32_t(public_key_blob[0]) << 24) | (uint32_t(public_key_blob[1]) << 16) | (uint32_t(public_key_blob[2]) << 8) |
                          uint32_t(public_key_blob[3]);
    const std::span<const AvbTestKey> keys = avb_test_keys();
    for (size_t i = 0; i < keys.size(); ++i) {
        if (keys[i].bits != bits || public_key_blob.size() != blob_size(bits)) continue;
        if (public_blob_of(i) == public_key_blob) return &keys[i];
    }
    return nullptr;
}

std::string describe_avb_public_key(const Bytes& blob) {
    if (blob.empty()) return "none";
    std::string out;
    if (blob.size() >= 8) {
        const uint32_t bits = (uint32_t(blob[0]) << 24) | (uint32_t(blob[1]) << 16) | (uint32_t(blob[2]) << 8) | uint32_t(blob[3]);
        if (bits >= 8 && bits % 8 == 0 && bits <= 65536 && blob.size() == blob_size(bits)) out = std::to_string(bits) + "-bit RSA";
    }
    if (out.empty()) out = std::to_string(blob.size()) + " bytes";
    static const char* digits = "0123456789abcdef";
    out += ", sha1 ";
    for (const uint8_t b : hash::sha1(blob)) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 15]);
    }
    if (const AvbTestKey* known = find_avb_test_key(blob)) out += std::string("; the public AVB test key ") + known->name;
    return out;
}

AvbKeyChoice choose_avb_test_key(uint32_t algorithm_type, const Bytes& image_public_key) {
    const unsigned bits = avb_algorithm_key_bits(algorithm_type);
    if (bits == 0) return {};
    if (const AvbTestKey* own = find_avb_test_key(image_public_key); own && own->bits == bits) return {own, true};
    for (const AvbTestKey& k : avb_test_keys())
        if (k.bits == bits) return {&k, false};
    return {};
}

}  // namespace abr
