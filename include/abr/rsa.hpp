// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::rsa -- RSASSA-PKCS1-v1_5 sign/verify and key parsing, self-contained
// (see bigint.hpp for why this does not use OpenSSL).
//
// Both signature schemes this tool deals with are PKCS#1 v1.5:
//   - AVB 2.0 vbmeta (avbtool): SHA-256/SHA-512 with RSA-2048/4096/8192;
//   - the pre-AVB boot signature (AOSP boot_signer): SHA-256 with RSA-2048.
// PKCS#1 v1.5 signing is deterministic, so a signature made here is
// byte-for-byte what OpenSSL (`openssl dgst -sha256 -sign`) produces for the
// same key and data, which is how tests/ checks it.
#pragma once

#include "abr/bigint.hpp"
#include "abr/byte_io.hpp"

namespace abr {

enum class HashAlg { SHA1, SHA256, SHA512 };

size_t hash_size(HashAlg alg);
Bytes hash_bytes(HashAlg alg, const Bytes& data);

struct RsaPublicKey {
    BigInt n, e;
    size_t size_bytes() const { return (n.bit_length() + 7) / 8; }
};

struct RsaPrivateKey {
    BigInt n, e, d;
    BigInt p, q, dp, dq, qinv;  // CRT parameters; zero when the key file lacks them
    size_t size_bytes() const { return (n.bit_length() + 7) / 8; }
    bool has_crt() const { return !p.is_zero() && !q.is_zero(); }
    RsaPublicKey public_key() const { return {n, e}; }
};

// Accepts a PEM file ("PRIVATE KEY" = PKCS#8, "RSA PRIVATE KEY" = PKCS#1) or
// the same structures as raw DER (Android's *.pk8 files are PKCS#8 DER).
// Passphrase-protected keys are rejected with an explanation.
RsaPrivateKey rsa_parse_private_key(const Bytes& file_contents);

// Accepts an X.509 certificate (PEM or DER), a SubjectPublicKeyInfo
// ("PUBLIC KEY") or a bare PKCS#1 RSAPublicKey ("RSA PUBLIC KEY").
RsaPublicKey rsa_parse_public_key(const Bytes& file_contents);

// `digest` is the hash of the message, computed with `alg`.
Bytes rsa_pkcs1_sign(const RsaPrivateKey& key, HashAlg alg, const Bytes& digest);
bool rsa_pkcs1_verify(const RsaPublicKey& key, HashAlg alg, const Bytes& digest,
                      const Bytes& signature);

// `AvbRSAPublicKeyHeader` + modulus + rr, the form libavb stores in a vbmeta
// image: be32 key_num_bits, be32 n0inv, then modulus and R^2 mod n, each
// key_num_bits/8 bytes, big-endian.
Bytes avb_encode_public_key(const RsaPublicKey& key);

}  // namespace abr
