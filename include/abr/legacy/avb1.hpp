// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy -- the pre-AVB-2.0 "boot signature" that AOSP's boot_signer
// (system/extras/verity/BootSignature.java) appends to a boot image, and that
// bootloaders such as LK check at the page-aligned end of the image
// ("verified boot 1.0", dm-verity era; Android Image Kitchen calls it AVBv1).
//
//   BootSignature ::= SEQUENCE {
//       formatVersion  INTEGER (1),
//       certificate    Certificate,           -- X.509, DER, the signer's
//       algorithm      AlgorithmIdentifier,   -- sha256WithRSAEncryption, no parameters
//       attributes     SEQUENCE { target PrintableString, length INTEGER },
//       signature      OCTET STRING }
//
// The signature is PKCS#1 v1.5 over  image[0 : length] || DER(attributes),
// where `image` starts at the "ANDROID!" magic, `length` is the page-aligned
// size of the whole image, and `target` is "/boot" or "/recovery".
//
// PKCS#1 v1.5 is deterministic, so re-signing an unmodified image with the
// key it was signed with reproduces the original blob byte for byte -- which
// is how tests/ checks this against the real boot_signer.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "abr/byte_io.hpp"
#include "abr/rsa.hpp"

namespace abr::legacy {

struct BootSignature {
    Bytes certificate;           // DER X.509, the whole element
    Bytes algorithm;             // DER AlgorithmIdentifier, the whole element, as found
    std::string algorithm_oid;   // dotted form of the algorithm, e.g. 1.2.840.113549.1.1.11
    std::string target;          // "/boot"
    uint64_t length = 0;         // bytes of the image the signature covers
    Bytes signature;             // contents of the OCTET STRING
    size_t der_size = 0;         // size of the whole BootSignature element in the source
};

// Parses a BootSignature that starts exactly at data[offset]. Returns nothing
// when the bytes there are not one (so it is safe to try on any tail).
std::optional<BootSignature> parse_boot_signature(const Bytes& data, size_t offset = 0);

enum class SignatureVerdict {
    Valid,        // the signature checks out against the certificate's key
    Invalid,      // it does not (image modified after signing, wrong length, ...)
    Unsupported,  // abr cannot judge it (ECDSA, unknown algorithm, unreadable certificate)
};

struct Verification {
    SignatureVerdict verdict = SignatureVerdict::Unsupported;
    std::string detail;  // why, in a sentence
};

// `image` points at the "ANDROID!" magic; `available` is how many bytes of the
// file follow from there (the signature needs sig.length of them).
Verification verify_boot_signature(const BootSignature& sig, const uint8_t* image, size_t available);
inline Verification verify_boot_signature(const BootSignature& sig, const Bytes& image) {
    return verify_boot_signature(sig, image.data(), image.size());
}

// A private key together with the certificate that goes into the signature.
struct Signer {
    RsaPrivateKey key;
    Bytes certificate;     // DER
    std::string subject;   // for messages
    bool is_aosp_test_key = false;
};

// Builds a Signer from key and certificate file contents (PEM or DER each).
// `certificate_file` may be empty if `key_file` is a PEM that also contains the
// CERTIFICATE. Throws FormatError, with a message that says what to do, when
// the key is unreadable, the certificate is missing, or the two do not match.
Signer make_signer(const Bytes& key_file, const Bytes& certificate_file);

// AOSP's public dev key pair (build/target/product/security/verity.*), the
// default signer of Android Image Kitchen. Not a secret.
Signer aosp_test_signer();
bool is_aosp_test_certificate(const Bytes& certificate_der);

// "C=US, ST=California, ..., CN=Android" -- the certificate's subject, for
// display. Never throws; returns "(unreadable certificate)" if it must.
std::string certificate_subject(const Bytes& certificate_der);

// The DER BootSignature for `image` (exactly the bytes to be covered, i.e.
// the whole page-aligned image). Always sha256WithRSAEncryption, like boot_signer.
Bytes build_boot_signature(const Bytes& image, const std::string& target, const Signer& signer);

// Human-readable algorithm name for messages ("sha256WithRSA", or the OID).
std::string signature_algorithm_name(const std::string& oid);

namespace detail {
// The embedded AOSP dev key pair; generated, see tools/gen_aosp_verity_key.py.
extern const uint8_t kAospVerityPk8[];
extern const size_t kAospVerityPk8Size;
extern const uint8_t kAospVerityCertDer[];
extern const size_t kAospVerityCertDerSize;
}  // namespace detail

}  // namespace abr::legacy
