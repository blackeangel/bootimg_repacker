// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/rsa.hpp"

#include "abr/asn1.hpp"
#include "abr/sha.hpp"

#include <algorithm>
#include <cstring>

namespace abr {

size_t hash_size(HashAlg alg) {
    switch (alg) {
        case HashAlg::SHA1: return 20;
        case HashAlg::SHA256: return 32;
        case HashAlg::SHA512: return 64;
    }
    return 0;
}

Bytes hash_bytes(HashAlg alg, const Bytes& data) {
    switch (alg) {
        case HashAlg::SHA1: return hash::sha1(data);
        case HashAlg::SHA256: return hash::sha256(data);
        case HashAlg::SHA512: return hash::sha512(data);
    }
    return {};
}

namespace {

// DER DigestInfo prefixes (RFC 8017, section 9.2 note 1).
Bytes digest_info_prefix(HashAlg alg) {
    switch (alg) {
        case HashAlg::SHA1:
            return {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
                    0x04, 0x14};
        case HashAlg::SHA256:
            return {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        case HashAlg::SHA512:
            return {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                    0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
    }
    return {};
}

// EMSA-PKCS1-v1_5: 00 01 FF..FF 00 DigestInfo, k bytes long.
Bytes emsa_pkcs1_v15(HashAlg alg, const Bytes& digest, size_t k) {
    if (digest.size() != hash_size(alg)) throw FormatError("RSA: digest has the wrong length");
    Bytes t = digest_info_prefix(alg);
    t.insert(t.end(), digest.begin(), digest.end());
    if (k < t.size() + 11) throw FormatError("RSA: key is too small for this hash algorithm");
    Bytes em(k, 0xff);
    em[0] = 0x00;
    em[1] = 0x01;
    em[k - t.size() - 1] = 0x00;
    std::copy(t.begin(), t.end(), em.end() - static_cast<long>(t.size()));
    return em;
}

BigInt public_op(const BigInt& m, const RsaPublicKey& key) {
    return BigInt::mod_exp(m, key.e, key.n);
}

BigInt private_op(const BigInt& c, const RsaPrivateKey& key) {
    if (key.has_crt()) {
        BigInt m1 = BigInt::mod_exp(c.mod(key.p), key.dp, key.p);
        BigInt m2 = BigInt::mod_exp(c.mod(key.q), key.dq, key.q);
        BigInt m2p = m2.mod(key.p);
        BigInt diff = BigInt::compare(m1, m2p) >= 0 ? BigInt::sub(m1, m2p)
                                                    : BigInt::sub(BigInt::add(m1, key.p), m2p);
        BigInt h = BigInt::mul(key.qinv, diff).mod(key.p);
        return BigInt::add(m2, BigInt::mul(h, key.q));
    }
    return BigInt::mod_exp(c, key.d, key.n);
}

// ---------------------------------------------------------- key parsing --

const char* kOidRsaEncryption = "1.2.840.113549.1.1.1";

RsaPrivateKey parse_pkcs1_private(const Bytes& der_bytes, size_t off, size_t end) {
    der::Tlv seq = der::read(der_bytes, off, end);
    if (seq.tag != der::kSequence) throw FormatError("RSA key: expected a SEQUENCE");
    auto f = der::children(der_bytes, seq);
    if (f.size() < 9) throw FormatError("RSA key: too few fields for an RSAPrivateKey");
    if (der::integer_value(der_bytes, f[0]) != BigInt(0))
        throw FormatError("RSA key: multi-prime RSA keys are not supported");
    RsaPrivateKey k;
    k.n = der::integer_value(der_bytes, f[1]);
    k.e = der::integer_value(der_bytes, f[2]);
    k.d = der::integer_value(der_bytes, f[3]);
    k.p = der::integer_value(der_bytes, f[4]);
    k.q = der::integer_value(der_bytes, f[5]);
    k.dp = der::integer_value(der_bytes, f[6]);
    k.dq = der::integer_value(der_bytes, f[7]);
    k.qinv = der::integer_value(der_bytes, f[8]);
    if (k.n.is_zero() || k.e.is_zero() || k.d.is_zero()) throw FormatError("RSA key: zero field");
    return k;
}

RsaPrivateKey parse_private_der(const Bytes& d) {
    der::Tlv seq = der::read(d, 0, d.size());
    if (seq.tag != der::kSequence) throw FormatError("RSA key: not a DER SEQUENCE");
    auto f = der::children(d, seq);
    // PKCS#8 PrivateKeyInfo: INTEGER 0, SEQUENCE {OID, NULL}, OCTET STRING {RSAPrivateKey}
    if (f.size() >= 3 && f[0].tag == der::kInteger && f[1].tag == der::kSequence &&
        f[2].tag == der::kOctetString) {
        auto alg = der::children(d, f[1]);
        if (alg.empty() || alg[0].tag != der::kOid ||
            der::oid_to_string(der::content(d, alg[0])) != kOidRsaEncryption)
            throw FormatError("private key is not an RSA key (PKCS#8 algorithm is not rsaEncryption)");
        return parse_pkcs1_private(d, f[2].content_offset(), f[2].content_offset() + f[2].content_len);
    }
    return parse_pkcs1_private(d, 0, d.size());
}

RsaPublicKey parse_rsa_public_key_struct(const Bytes& d, const der::Tlv& seq) {
    auto f = der::children(d, seq);
    if (f.size() != 2) throw FormatError("RSA public key: expected {modulus, exponent}");
    RsaPublicKey k;
    k.n = der::integer_value(d, f[0]);
    k.e = der::integer_value(d, f[1]);
    return k;
}

RsaPublicKey parse_spki(const Bytes& d, const der::Tlv& spki) {
    auto f = der::children(d, spki);
    if (f.size() != 2 || f[0].tag != der::kSequence || f[1].tag != der::kBitString)
        throw FormatError("SubjectPublicKeyInfo: unexpected layout");
    auto alg = der::children(d, f[0]);
    if (alg.empty() || alg[0].tag != der::kOid ||
        der::oid_to_string(der::content(d, alg[0])) != kOidRsaEncryption)
        throw FormatError("public key is not an RSA key");
    if (f[1].content_len < 2 || d[f[1].content_offset()] != 0)
        throw FormatError("SubjectPublicKeyInfo: bad BIT STRING");
    der::Tlv inner = der::read(d, f[1].content_offset() + 1, f[1].end());
    if (inner.tag != der::kSequence) throw FormatError("SubjectPublicKeyInfo: bad RSAPublicKey");
    return parse_rsa_public_key_struct(d, inner);
}

RsaPublicKey parse_public_der(const Bytes& d) {
    der::Tlv top = der::read(d, 0, d.size());
    if (top.tag != der::kSequence) throw FormatError("not a DER SEQUENCE");
    auto f = der::children(d, top);
    if (f.size() == 2 && f[0].tag == der::kInteger) return parse_rsa_public_key_struct(d, top);
    if (f.size() == 2 && f[0].tag == der::kSequence && f[1].tag == der::kBitString)
        return parse_spki(d, top);
    // X.509 Certificate: { tbsCertificate, signatureAlgorithm, signature }
    if (f.size() == 3 && f[0].tag == der::kSequence) {
        auto tbs = der::children(d, f[0]);
        size_t i = (!tbs.empty() && tbs[0].tag == 0xA0) ? 1 : 0;  // optional [0] version
        // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
        if (tbs.size() < i + 6) throw FormatError("X.509 certificate: too few fields");
        return parse_spki(d, tbs[i + 5]);
    }
    throw FormatError("unrecognised public key / certificate structure");
}

bool looks_like_pem(const Bytes& b) {
    static const char kMark[] = "-----BEGIN ";
    return std::search(b.begin(), b.end(), kMark, kMark + sizeof(kMark) - 1) != b.end();
}

}  // namespace

namespace {

// Low-level parse errors ("DER: element runs past the end of the data", "RSA
// key: not a DER SEQUENCE") mean little to someone who handed over the wrong
// file; say what was expected instead. Errors that already tell the person
// something useful (passphrase-protected, not an RSA key, ...) pass through.
[[noreturn]] void rethrow_key_error(const FormatError& e, const char* what_it_is) {
    static const char* const kExplanatory[] = {
        "passphrase", "no RSA private key found", "no certificate or public key found",
        "is not an RSA key", "RSA key is inconsistent", "multi-prime"};
    const std::string msg = e.what();
    for (const char* marker : kExplanatory)
        if (msg.find(marker) != std::string::npos) throw;
    throw FormatError(std::string("cannot read the file as ") + what_it_is + " (" + msg + ")");
}

}  // namespace

RsaPrivateKey rsa_parse_private_key(const Bytes& file) {
    RsaPrivateKey k;
    try {
        if (looks_like_pem(file)) {
            auto blocks = der::pem_decode(std::string(file.begin(), file.end()));
            bool found = false;
            for (auto& b : blocks) {
                if (b.label == "PRIVATE KEY" || b.label == "RSA PRIVATE KEY") {
                    k = parse_private_der(b.der);
                    found = true;
                    break;
                }
            }
            if (!found) throw FormatError("no RSA private key found in the PEM file");
        } else {
            k = parse_private_der(file);
        }
    } catch (const FormatError& e) {
        rethrow_key_error(e, "an RSA private key (PEM, or PKCS#8/PKCS#1 DER such as Android's .pk8)");
    }
    // Reject a key whose own numbers do not agree, instead of signing garbage.
    BigInt probe(0x1234567);
    if (public_op(BigInt::mod_exp(probe, k.d, k.n), k.public_key()) != probe)
        throw FormatError("RSA key is inconsistent (e*d != 1 mod phi(n))");
    return k;
}

RsaPublicKey rsa_parse_public_key(const Bytes& file) {
    try {
        if (looks_like_pem(file)) {
            auto blocks = der::pem_decode(std::string(file.begin(), file.end()));
            for (auto& b : blocks) {
                if (b.label == "CERTIFICATE" || b.label == "PUBLIC KEY" ||
                    b.label == "RSA PUBLIC KEY")
                    return parse_public_der(b.der);
            }
            throw FormatError("no certificate or public key found in the PEM file");
        }
        return parse_public_der(file);
    } catch (const FormatError& e) {
        rethrow_key_error(e, "an X.509 certificate or RSA public key (PEM or DER)");
    }
}

Bytes rsa_pkcs1_sign(const RsaPrivateKey& key, HashAlg alg, const Bytes& digest) {
    const size_t k = key.size_bytes();
    BigInt m = BigInt::from_bytes_be(emsa_pkcs1_v15(alg, digest, k));
    BigInt s = private_op(m, key);
    // Guard against a corrupt key or an arithmetic fault: never emit a
    // signature that does not verify.
    if (public_op(s, key.public_key()) != m) {
        s = BigInt::mod_exp(m, key.d, key.n);
        if (public_op(s, key.public_key()) != m)
            throw FormatError("RSA signing failed its own verification (corrupt key file?)");
    }
    return s.to_bytes_be(k);
}

bool rsa_pkcs1_verify(const RsaPublicKey& key, HashAlg alg, const Bytes& digest,
                      const Bytes& signature) {
    const size_t k = key.size_bytes();
    if (signature.size() != k || k < 11) return false;
    BigInt s = BigInt::from_bytes_be(signature);
    if (!(s < key.n)) return false;
    Bytes em = public_op(s, key).to_bytes_be(k);
    Bytes expected;
    try {
        expected = emsa_pkcs1_v15(alg, digest, k);
    } catch (const FormatError&) {
        return false;
    }
    return em == expected;
}

Bytes avb_encode_public_key(const RsaPublicKey& key) {
    const size_t bits = key.n.bit_length();
    if (bits % 8 != 0) throw FormatError("AVB public key: modulus bit length is not a multiple of 8");
    if (!key.n.is_odd()) throw FormatError("AVB public key: modulus is even");
    const size_t bytes = bits / 8;
    BigInt rr = BigInt(1).shl(2 * bits).mod(key.n);
    Bytes out;
    auto be32 = [&](uint32_t v) {
        for (int i = 3; i >= 0; --i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    be32(static_cast<uint32_t>(bits));
    be32(neg_inverse_mod32(key.n.low32()));
    Bytes n = key.n.to_bytes_be(bytes);
    Bytes r = rr.to_bytes_be(bytes);
    out.insert(out.end(), n.begin(), n.end());
    out.insert(out.end(), r.begin(), r.end());
    return out;
}

}  // namespace abr
