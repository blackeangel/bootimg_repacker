// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/avb1.hpp"

#include <algorithm>
#include <cstring>

#include "abr/asn1.hpp"
#include "abr/sha.hpp"

namespace abr::legacy {

namespace {

const char* const kOidSha1Rsa = "1.2.840.113549.1.1.5";
const char* const kOidSha256Rsa = "1.2.840.113549.1.1.11";
const char* const kOidSha512Rsa = "1.2.840.113549.1.1.13";
const char* const kOidEcdsaSha256 = "1.2.840.10045.4.3.2";
const char* const kOidEcdsaSha384 = "1.2.840.10045.4.3.3";
const char* const kOidEcdsaSha512 = "1.2.840.10045.4.3.4";

// AlgorithmIdentifier { sha256WithRSAEncryption } with the parameters left
// out, exactly what boot_signer writes for an RSA key.
const uint8_t kSha256WithRsa[] = {0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48,
                                  0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};

Bytes encode_attributes(const std::string& target, uint64_t length) {
    return der::encode_sequence(
        {der::encode(der::kPrintableString, Bytes(target.begin(), target.end())),
         der::encode_integer(length)});
}

// Hash of  image[0:length] || attributes.
Bytes digest_signed_data(HashAlg alg, const uint8_t* image, size_t length, const Bytes& attrs) {
    switch (alg) {
        case HashAlg::SHA1: {
            hash::Sha1 h;
            h.update(image, length);
            h.update(attrs);
            return h.finish();
        }
        case HashAlg::SHA256: {
            hash::Sha256 h;
            h.update(image, length);
            h.update(attrs);
            return h.finish();
        }
        case HashAlg::SHA512: {
            hash::Sha512 h;
            h.update(image, length);
            h.update(attrs);
            return h.finish();
        }
    }
    return {};
}

bool hash_for_oid(const std::string& oid, HashAlg& out) {
    if (oid == kOidSha1Rsa) out = HashAlg::SHA1;
    else if (oid == kOidSha256Rsa) out = HashAlg::SHA256;
    else if (oid == kOidSha512Rsa) out = HashAlg::SHA512;
    else return false;
    return true;
}

uint64_t small_integer(const Bytes& buf, const der::Tlv& t) {
    BigInt v = der::integer_value(buf, t);
    if (v.bit_length() > 63) throw FormatError("INTEGER too large");
    uint64_t out = 0;
    for (uint8_t b : v.to_bytes_be()) out = (out << 8) | b;
    return out;
}

// ----------------------------------------------------------- X.509 names --

const char* rdn_name(const std::string& oid) {
    if (oid == "2.5.4.3") return "CN";
    if (oid == "2.5.4.6") return "C";
    if (oid == "2.5.4.7") return "L";
    if (oid == "2.5.4.8") return "ST";
    if (oid == "2.5.4.10") return "O";
    if (oid == "2.5.4.11") return "OU";
    if (oid == "1.2.840.113549.1.9.1") return "emailAddress";
    return nullptr;
}

std::string string_value(const Bytes& buf, const der::Tlv& t) {
    Bytes c = der::content(buf, t);
    if (t.tag == 0x1e) {  // BMPString: UCS-2 big-endian; keep ASCII, mark the rest
        std::string out;
        for (size_t i = 0; i + 1 < c.size(); i += 2)
            out += (c[i] == 0 && c[i + 1] < 0x80) ? static_cast<char>(c[i + 1]) : '?';
        return out;
    }
    return std::string(c.begin(), c.end());
}

}  // namespace

std::string signature_algorithm_name(const std::string& oid) {
    if (oid == kOidSha1Rsa) return "sha1WithRSA";
    if (oid == kOidSha256Rsa) return "sha256WithRSA";
    if (oid == kOidSha512Rsa) return "sha512WithRSA";
    if (oid == kOidEcdsaSha256) return "ecdsa-with-SHA256";
    if (oid == kOidEcdsaSha384) return "ecdsa-with-SHA384";
    if (oid == kOidEcdsaSha512) return "ecdsa-with-SHA512";
    return "OID " + oid;
}

std::string certificate_subject(const Bytes& cert) {
    try {
        der::Tlv top = der::read(cert, 0, cert.size());
        auto f = der::children(cert, top);
        if (f.empty()) return "(unreadable certificate)";
        auto tbs = der::children(cert, f[0]);
        size_t i = (!tbs.empty() && tbs[0].tag == 0xA0) ? 1 : 0;
        if (tbs.size() < i + 5) return "(unreadable certificate)";
        const der::Tlv& subject = tbs[i + 4];  // serial, sigAlg, issuer, validity, subject
        std::string out;
        for (const der::Tlv& rdn : der::children(cert, subject)) {
            for (const der::Tlv& atv : der::children(cert, rdn)) {
                auto kv = der::children(cert, atv);
                if (kv.size() != 2 || kv[0].tag != der::kOid) continue;
                std::string oid = der::oid_to_string(der::content(cert, kv[0]));
                const char* name = rdn_name(oid);
                if (!out.empty()) out += ", ";
                out += (name ? std::string(name) : oid) + "=" + string_value(cert, kv[1]);
            }
        }
        return out.empty() ? "(empty subject)" : out;
    } catch (const FormatError&) {
        return "(unreadable certificate)";
    }
}

std::optional<BootSignature> parse_boot_signature(const Bytes& data, size_t offset) {
    // Cheap rejection first: this runs on every image's tail.
    if (offset >= data.size() || data[offset] != der::kSequence) return std::nullopt;
    try {
        der::Tlv seq = der::read(data, offset, data.size());
        auto f = der::children(data, seq);
        if (f.size() != 5) return std::nullopt;
        if (f[0].tag != der::kInteger || f[0].content_len != 1 ||
            data[f[0].content_offset()] != 1)
            return std::nullopt;
        if (f[1].tag != der::kSequence || f[2].tag != der::kSequence ||
            f[3].tag != der::kSequence || f[4].tag != der::kOctetString)
            return std::nullopt;
        auto alg = der::children(data, f[2]);
        if (alg.empty() || alg[0].tag != der::kOid) return std::nullopt;
        auto attrs = der::children(data, f[3]);
        if (attrs.size() != 2 || attrs[0].tag != der::kPrintableString ||
            attrs[1].tag != der::kInteger)
            return std::nullopt;

        BootSignature s;
        s.certificate = der::raw(data, f[1]);
        s.algorithm = der::raw(data, f[2]);
        s.algorithm_oid = der::oid_to_string(der::content(data, alg[0]));
        Bytes target = der::content(data, attrs[0]);
        s.target.assign(target.begin(), target.end());
        s.length = small_integer(data, attrs[1]);
        s.signature = der::content(data, f[4]);
        s.der_size = seq.total();
        return s;
    } catch (const FormatError&) {
        return std::nullopt;
    }
}

Verification verify_boot_signature(const BootSignature& sig, const uint8_t* image,
                                   size_t available) {
    Verification v;
    if (sig.length > available) {
        v.verdict = SignatureVerdict::Invalid;
        v.detail = "the signature covers " + std::to_string(sig.length) +
                   " bytes but the file has only " + std::to_string(available) + " from the image start";
        return v;
    }
    HashAlg alg;
    if (!hash_for_oid(sig.algorithm_oid, alg)) {
        v.detail = "signature algorithm " + signature_algorithm_name(sig.algorithm_oid) +
                   " is not supported (abr checks RSA signatures only)";
        return v;
    }
    RsaPublicKey pub;
    try {
        pub = rsa_parse_public_key(sig.certificate);
    } catch (const FormatError& e) {
        v.detail = std::string("the certificate has no RSA key abr can read (") + e.what() + ")";
        return v;
    }
    Bytes attrs = encode_attributes(sig.target, sig.length);
    Bytes digest = digest_signed_data(alg, image, static_cast<size_t>(sig.length), attrs);
    if (rsa_pkcs1_verify(pub, alg, digest, sig.signature)) {
        v.verdict = SignatureVerdict::Valid;
        v.detail = "the signature matches the image";
    } else {
        v.verdict = SignatureVerdict::Invalid;
        v.detail = "the signature does not match the image (modified after signing?)";
    }
    return v;
}

// --------------------------------------------------------------- signers --

bool is_aosp_test_certificate(const Bytes& certificate_der) {
    return certificate_der.size() == detail::kAospVerityCertDerSize &&
           std::memcmp(certificate_der.data(), detail::kAospVerityCertDer,
                       detail::kAospVerityCertDerSize) == 0;
}

Signer aosp_test_signer() {
    Signer s;
    s.key = rsa_parse_private_key(
        Bytes(detail::kAospVerityPk8, detail::kAospVerityPk8 + detail::kAospVerityPk8Size));
    s.certificate = Bytes(detail::kAospVerityCertDer,
                          detail::kAospVerityCertDer + detail::kAospVerityCertDerSize);
    s.subject = certificate_subject(s.certificate);
    s.is_aosp_test_key = true;
    return s;
}

namespace {

bool looks_like_pem(const Bytes& file) {
    static const char kMark[] = "-----BEGIN ";
    return std::search(file.begin(), file.end(), kMark, kMark + sizeof(kMark) - 1) != file.end();
}

// The DER of the first CERTIFICATE block of a PEM file, or empty.
Bytes pem_certificate(const Bytes& file) {
    if (!looks_like_pem(file)) return {};
    for (auto& b : der::pem_decode(std::string(file.begin(), file.end())))
        if (b.label == "CERTIFICATE") return b.der;
    return {};
}

}  // namespace

Signer make_signer(const Bytes& key_file, const Bytes& certificate_file) {
    Signer s;
    s.key = rsa_parse_private_key(key_file);

    Bytes cert;
    if (!certificate_file.empty()) {
        cert = looks_like_pem(certificate_file) ? pem_certificate(certificate_file) : certificate_file;
        if (cert.empty()) throw FormatError("no CERTIFICATE found in the certificate file");
    } else {
        cert = pem_certificate(key_file);  // a key and its certificate in one PEM file
    }
    if (cert.empty())
        throw FormatError(
            "a boot signature carries the signer's X.509 certificate, and none was found: pass it "
            "with --avb1-cert <cert.pem|cert.der>, or name the key like Android Image Kitchen "
            "does (--avb1-key <name> with <name>.pk8 and <name>.x509.pem next to each other)");

    RsaPublicKey pub;
    try {
        pub = rsa_parse_public_key(cert);
    } catch (const FormatError& e) {
        throw FormatError(std::string("cannot read the certificate: ") + e.what());
    }
    if (pub.n != s.key.n || pub.e != s.key.e)
        throw FormatError(
            "the certificate does not belong to this private key (different RSA modulus); a "
            "boot signature made with them would never verify");

    s.certificate = std::move(cert);
    s.subject = certificate_subject(s.certificate);
    s.is_aosp_test_key = is_aosp_test_certificate(s.certificate);
    return s;
}

Bytes build_boot_signature(const Bytes& image, const std::string& target, const Signer& signer) {
    const uint64_t length = image.size();
    Bytes attrs = encode_attributes(target, length);
    Bytes digest = digest_signed_data(HashAlg::SHA256, image.data(), image.size(), attrs);
    Bytes sig = rsa_pkcs1_sign(signer.key, HashAlg::SHA256, digest);
    return der::encode_sequence({der::encode_integer(1), signer.certificate,
                                 Bytes(kSha256WithRsa, kSha256WithRsa + sizeof(kSha256WithRsa)),
                                 attrs, der::encode(der::kOctetString, sig)});
}

}  // namespace abr::legacy
