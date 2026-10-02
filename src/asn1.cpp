// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/asn1.hpp"

#include <algorithm>
#include <cstring>

namespace abr::der {

Tlv read(const Bytes& buf, size_t offset, size_t limit) {
    limit = std::min(limit, buf.size());
    if (offset >= limit) throw FormatError("DER: element starts past the end of the data");
    Tlv t;
    t.offset = offset;
    t.tag = buf[offset];
    if ((t.tag & 0x1f) == 0x1f) throw FormatError("DER: multi-byte tags are not supported");
    size_t pos = offset + 1;
    if (pos >= limit) throw FormatError("DER: truncated length");
    uint8_t first = buf[pos++];
    size_t len = 0;
    if (first < 0x80) {
        len = first;
    } else {
        size_t n = first & 0x7f;
        if (n == 0) throw FormatError("DER: indefinite lengths are not supported");
        if (n > 4) throw FormatError("DER: length does not fit in 32 bits");
        if (pos + n > limit) throw FormatError("DER: truncated length");
        for (size_t i = 0; i < n; ++i) len = (len << 8) | buf[pos++];
    }
    t.header_len = pos - offset;
    t.content_len = len;
    if (len > limit - pos) throw FormatError("DER: element runs past the end of the data");
    return t;
}

Bytes content(const Bytes& buf, const Tlv& t) {
    return Bytes(buf.begin() + static_cast<long>(t.content_offset()),
                 buf.begin() + static_cast<long>(t.content_offset() + t.content_len));
}

Bytes raw(const Bytes& buf, const Tlv& t) {
    return Bytes(buf.begin() + static_cast<long>(t.offset),
                 buf.begin() + static_cast<long>(t.end()));
}

std::vector<Tlv> children(const Bytes& buf, const Tlv& t) {
    std::vector<Tlv> out;
    size_t pos = t.content_offset();
    const size_t end = t.content_offset() + t.content_len;
    while (pos < end) {
        Tlv c = read(buf, pos, end);
        out.push_back(c);
        pos = c.end();
    }
    return out;
}

Bytes encode(uint8_t tag, const Bytes& body) {
    Bytes out;
    out.push_back(tag);
    size_t n = body.size();
    if (n < 0x80) {
        out.push_back(static_cast<uint8_t>(n));
    } else {
        uint8_t tmp[8];
        size_t cnt = 0;
        for (size_t v = n; v; v >>= 8) tmp[cnt++] = static_cast<uint8_t>(v);
        out.push_back(static_cast<uint8_t>(0x80 | cnt));
        while (cnt) out.push_back(tmp[--cnt]);
    }
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

Bytes encode_integer(const BigInt& v) {
    Bytes mag = v.to_bytes_be();  // at least one byte
    if (mag[0] & 0x80) mag.insert(mag.begin(), 0x00);
    return encode(kInteger, mag);
}

Bytes encode_integer(uint64_t value) { return encode_integer(BigInt(value)); }

Bytes encode_sequence(const std::vector<Bytes>& elements) {
    Bytes body;
    for (auto& e : elements) body.insert(body.end(), e.begin(), e.end());
    return encode(kSequence, body);
}

BigInt integer_value(const Bytes& buf, const Tlv& t) {
    if (t.tag != kInteger) throw FormatError("DER: expected an INTEGER");
    if (t.content_len == 0) throw FormatError("DER: empty INTEGER");
    if (buf[t.content_offset()] & 0x80) throw FormatError("DER: negative INTEGER where a key value was expected");
    return BigInt::from_bytes_be(buf.data() + t.content_offset(), t.content_len);
}

std::string oid_to_string(const Bytes& c) {
    if (c.empty()) return "";
    std::string out = std::to_string(c[0] / 40) + "." + std::to_string(c[0] % 40);
    uint64_t v = 0;
    for (size_t i = 1; i < c.size(); ++i) {
        v = (v << 7) | (c[i] & 0x7f);
        if (!(c[i] & 0x80)) {
            out += "." + std::to_string(v);
            v = 0;
        }
    }
    return out;
}

// ----------------------------------------------------------------- base64 --

Bytes base64_decode(const std::string& text) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    Bytes out;
    uint32_t acc = 0;
    int bits = 0;
    size_t pad = 0;
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c == '=') {
            ++pad;
            continue;
        }
        if (pad) throw FormatError("base64: data after padding");
        int v = value(c);
        if (v < 0) throw FormatError(std::string("base64: invalid character '") + c + "'");
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>(acc >> bits));
        }
    }
    return out;
}

std::string base64_encode(const Bytes& data) {
    static const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out += kAlphabet[v >> 18];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += kAlphabet[v & 63];
    }
    if (i + 1 == data.size()) {
        uint32_t v = uint32_t(data[i]) << 16;
        out += kAlphabet[v >> 18];
        out += kAlphabet[(v >> 12) & 63];
        out += "==";
    } else if (i + 2 == data.size()) {
        uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out += kAlphabet[v >> 18];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += '=';
    }
    return out;
}

std::vector<PemBlock> pem_decode(const std::string& text) {
    std::vector<PemBlock> out;
    static const std::string kBegin = "-----BEGIN ";
    static const std::string kEnd = "-----END ";
    size_t pos = 0;
    while (true) {
        size_t b = text.find(kBegin, pos);
        if (b == std::string::npos) break;
        size_t label_start = b + kBegin.size();
        size_t label_end = text.find("-----", label_start);
        if (label_end == std::string::npos) throw FormatError("PEM: unterminated BEGIN line");
        std::string label = text.substr(label_start, label_end - label_start);
        size_t body_start = label_end + 5;
        size_t e = text.find(kEnd + label + "-----", body_start);
        if (e == std::string::npos) throw FormatError("PEM: no matching END line for " + label);
        std::string body = text.substr(body_start, e - body_start);
        if (label.find("ENCRYPTED") != std::string::npos ||
            body.find("Proc-Type:") != std::string::npos)
            throw FormatError(
                "the key is passphrase-protected, which abr cannot read; decrypt it first, e.g. "
                "`openssl pkey -in key.pem -out key_plain.pem`");
        out.push_back({label, base64_decode(body)});
        pos = e + kEnd.size() + label.size() + 5;
    }
    return out;
}

}  // namespace abr::der
