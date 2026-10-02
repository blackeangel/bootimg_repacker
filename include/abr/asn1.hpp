// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::der -- a small DER (ITU-T X.690) reader/writer plus PEM/base64, just
// enough for RSA keys, X.509 certificates and the AOSP boot signature.
//
// Input is parsed leniently (non-minimal lengths and integers are accepted)
// but every length is bounds-checked against the buffer, indefinite lengths
// and tag numbers above 30 are rejected. Output is always proper DER:
// minimal lengths, minimal INTEGERs.
#pragma once

#include "abr/bigint.hpp"
#include "abr/byte_io.hpp"

#include <string>
#include <vector>

namespace abr::der {

constexpr uint8_t kInteger = 0x02;
constexpr uint8_t kBitString = 0x03;
constexpr uint8_t kOctetString = 0x04;
constexpr uint8_t kNull = 0x05;
constexpr uint8_t kOid = 0x06;
constexpr uint8_t kPrintableString = 0x13;
constexpr uint8_t kSequence = 0x30;
constexpr uint8_t kSet = 0x31;

struct Tlv {
    uint8_t tag = 0;
    size_t offset = 0;       // of the tag byte in the buffer
    size_t header_len = 0;   // tag byte + length bytes
    size_t content_len = 0;

    size_t content_offset() const { return offset + header_len; }
    size_t total() const { return header_len + content_len; }
    size_t end() const { return offset + total(); }
};

// Reads one TLV starting at `offset`, which must lie completely inside
// [offset, limit). Throws FormatError on anything truncated or malformed.
Tlv read(const Bytes& buf, size_t offset, size_t limit);
inline Tlv read(const Bytes& buf, size_t offset = 0) { return read(buf, offset, buf.size()); }

Bytes content(const Bytes& buf, const Tlv& t);
// The whole element, header included.
Bytes raw(const Bytes& buf, const Tlv& t);
// Direct children of a constructed element.
std::vector<Tlv> children(const Bytes& buf, const Tlv& t);

Bytes encode(uint8_t tag, const Bytes& content);
Bytes encode_integer(const BigInt& unsigned_value);  // adds the 0x00 sign byte when needed
Bytes encode_integer(uint64_t value);
Bytes encode_sequence(const std::vector<Bytes>& elements);

// The unsigned magnitude of an INTEGER's content (rejects negatives).
BigInt integer_value(const Bytes& buf, const Tlv& t);

// OID content bytes -> "1.2.840.113549.1.1.11".
std::string oid_to_string(const Bytes& content_bytes);

// ---- PEM / base64 -------------------------------------------------------

Bytes base64_decode(const std::string& text);  // whitespace ignored
std::string base64_encode(const Bytes& data);

struct PemBlock {
    std::string label;  // e.g. "PRIVATE KEY", "CERTIFICATE"
    Bytes der;
};
// All "-----BEGIN x-----" blocks in `text`, in order. A passphrase-protected
// block is reported as an error (abr has no password prompt or KDF).
std::vector<PemBlock> pem_decode(const std::string& text);

}  // namespace abr::der
