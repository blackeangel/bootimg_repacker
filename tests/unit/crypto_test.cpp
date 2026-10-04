// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit-test driver for abr's self-contained crypto (BigInt, DER, RSA).
// Everything it checks is compared against an independent implementation by
// tests/run_tests.sh: Python's integers for the arithmetic, and OpenSSL's
// command line for the RSA signatures.
//
//   abr_unit_tests bigint                    < vectors from gen_bigint_vectors.py
//   abr_unit_tests rsa-sign <key> <sha1|sha256|sha512> <file>   -> hex signature
//   abr_unit_tests rsa-verify <key|cert> <alg> <file> <sig>     -> exit 0 if valid
//   abr_unit_tests avb-pubkey <key|cert>     -> hex of the AVB public key blob
//   abr_unit_tests der-dump <file>           -> one line per top-level child
//   abr_unit_tests sha-impl                  -> which SHA implementation runs here
//   abr_unit_tests sha-check <blob> <expect> -> "alg len chunk hex" lines vs the
//                                               first len bytes of blob, fed in
//                                               chunk-sized update() calls
//   abr_unit_tests sha-bench [MiB]           -> MB/s of every implementation
#include "abr/asn1.hpp"
#include "abr/bigint.hpp"
#include "abr/rsa.hpp"
#include "abr/sha.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace abr;

namespace {

BigInt from_hex(const std::string& s) {
    std::string h = s;
    if (h.size() % 2) h = "0" + h;
    Bytes b;
    for (size_t i = 0; i < h.size(); i += 2) b.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return BigInt::from_bytes_be(b);
}

std::string to_hex(const BigInt& v) {
    if (v.is_zero()) return "0";
    Bytes b = v.to_bytes_be();
    std::string out;
    char buf[3];
    for (uint8_t x : b) {
        std::snprintf(buf, sizeof(buf), "%02x", x);
        out += buf;
    }
    size_t nz = out.find_first_not_of('0');
    return nz == std::string::npos ? "0" : out.substr(nz);
}

std::string hex_bytes(const Bytes& b) {
    std::string out;
    char buf[3];
    for (uint8_t x : b) {
        std::snprintf(buf, sizeof(buf), "%02x", x);
        out += buf;
    }
    return out;
}

HashAlg alg_from(const std::string& s) {
    if (s == "sha1") return HashAlg::SHA1;
    if (s == "sha256") return HashAlg::SHA256;
    if (s == "sha512") return HashAlg::SHA512;
    throw FormatError("unknown hash algorithm " + s);
}

int run_bigint() {
    std::string line;
    size_t n = 0, bad = 0;
    auto check = [&](bool ok, const std::string& what) {
        ++n;
        if (!ok && bad++ < 5) std::cerr << "MISMATCH (vector " << n << "): " << what << "\n";
    };
    while (std::getline(std::cin, line)) {
        std::istringstream is(line);
        std::string op;
        is >> op;
        if (op.empty()) continue;
        std::vector<std::string> a;
        for (std::string t; is >> t;) a.push_back(t);
        BigInt x = from_hex(a[0]);
        if (op == "add") check(BigInt::add(x, from_hex(a[1])) == from_hex(a[2]), line.substr(0, 120));
        else if (op == "sub") check(BigInt::sub(x, from_hex(a[1])) == from_hex(a[2]), line.substr(0, 120));
        else if (op == "mul") check(BigInt::mul(x, from_hex(a[1])) == from_hex(a[2]), line.substr(0, 120));
        else if (op == "divmod") {
            BigInt q, r;
            BigInt::divmod(x, from_hex(a[1]), q, r);
            check(q == from_hex(a[2]) && r == from_hex(a[3]), line.substr(0, 120));
        } else if (op == "modexp")
            check(BigInt::mod_exp(x, from_hex(a[1]), from_hex(a[2])) == from_hex(a[3]), line.substr(0, 120));
        else if (op == "shl") check(x.shl(std::stoul(a[1])) == from_hex(a[2]), line.substr(0, 120));
        else if (op == "shr") check(x.shr(std::stoul(a[1])) == from_hex(a[2]), line.substr(0, 120));
        else if (op == "bytes") check(BigInt::from_bytes_be(x.to_bytes_be()) == x && to_hex(x) == a[0], line.substr(0, 120));
        else {
            std::cerr << "unknown vector op: " << op << "\n";
            return 2;
        }
    }
    std::cout << "bigint: " << n << " vectors, " << bad << " mismatches\n";
    return bad ? 1 : 0;
}

// Feeds p[0..len) to the hash in `chunk`-sized update() calls (0 = one call).
template <class H>
Bytes hash_chunked(const uint8_t* p, size_t len, size_t chunk) {
    H h;
    if (chunk == 0) {
        h.update(p, len);
    } else {
        for (size_t pos = 0; pos < len;) {
            size_t k = std::min(chunk, len - pos);
            h.update(p + pos, k);
            pos += k;
        }
    }
    return h.finish();
}

int run_sha_check(const char* blob_path, const char* expect_path) {
    const Bytes blob = read_file(blob_path);
    std::ifstream in(expect_path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open " << expect_path << "\n";
        return 2;
    }
    std::string line;
    size_t n = 0, bad = 0;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        std::istringstream is(line);
        std::string alg, hex;
        size_t len = 0, chunk = 0;
        is >> alg >> len >> chunk >> hex;
        if (!is || len > blob.size()) {
            std::cerr << "bad expectation line: " << line << "\n";
            return 2;
        }
        Bytes got;
        if (alg == "sha1")
            got = hash_chunked<hash::Sha1>(blob.data(), len, chunk);
        else if (alg == "sha256")
            got = hash_chunked<hash::Sha256>(blob.data(), len, chunk);
        else if (alg == "sha512")
            got = hash_chunked<hash::Sha512>(blob.data(), len, chunk);
        else {
            std::cerr << "bad algorithm in: " << line << "\n";
            return 2;
        }
        ++n;
        if (hex_bytes(got) != hex && bad++ < 5) std::cerr << "MISMATCH " << line << "\n   got " << hex_bytes(got) << "\n";
    }
    std::cout << "sha-check: " << n << " vectors, " << bad << " mismatches (" << hash::implementation_name() << ")\n";
    return bad ? 1 : 0;
}

int run_sha_bench(size_t mib) {
    Bytes buf(mib << 20);
    uint64_t x = 0x9E3779B97F4A7C15ULL;
    for (auto& b : buf) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        b = static_cast<uint8_t>(x >> 24);
    }
    auto bench = [&](const char* label, auto&& fn) {
        double best = 1e30;
        for (int rep = 0; rep < 3; ++rep) {
            auto t0 = std::chrono::steady_clock::now();
            Bytes d = fn();
            auto t1 = std::chrono::steady_clock::now();
            best = std::min(best, std::chrono::duration<double>(t1 - t0).count());
            if (d.empty()) return;
        }
        std::printf("  %-8s %8.0f MB/s\n", label, double(buf.size()) / (1 << 20) / best);
    };
    const char* auto_name = hash::implementation_name();
    for (int pass = 0; pass < 2; ++pass) {
        hash::force_portable(pass == 1);
        if (pass == 1 && std::string(hash::implementation_name()) == auto_name) break;  // nothing to compare
        std::printf("%s:\n", hash::implementation_name());
        bench("sha1", [&] { return hash::sha1(buf); });
        bench("sha256", [&] { return hash::sha256(buf); });
        bench("sha512", [&] { return hash::sha512(buf); });
    }
    hash::force_portable(false);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    set_binary_stdio();
    try {
        if (argc < 2) return 2;
        std::string cmd = argv[1];
        if (cmd == "bigint") return run_bigint();
        if (cmd == "sha-impl") {
            std::cout << hash::implementation_name() << "\n";
            return hash::sha_selftest() ? 0 : 1;
        }
        if (cmd == "sha-check" && argc == 4) return run_sha_check(argv[2], argv[3]);
        if (cmd == "sha-bench") return run_sha_bench(argc > 2 ? std::stoul(argv[2]) : 64);
        if (cmd == "rsa-sign" && argc == 5) {
            RsaPrivateKey key = rsa_parse_private_key(read_file(argv[2]));
            HashAlg alg = alg_from(argv[3]);
            Bytes sig = rsa_pkcs1_sign(key, alg, hash_bytes(alg, read_file(argv[4])));
            std::cout << hex_bytes(sig) << "\n";
            return 0;
        }
        if (cmd == "rsa-verify" && argc == 6) {
            RsaPublicKey key = rsa_parse_public_key(read_file(argv[2]));
            HashAlg alg = alg_from(argv[3]);
            Bytes sig = read_file(argv[5]);
            bool ok = rsa_pkcs1_verify(key, alg, hash_bytes(alg, read_file(argv[4])), sig);
            std::cout << (ok ? "valid" : "INVALID") << "\n";
            return ok ? 0 : 1;
        }
        if (cmd == "avb-pubkey" && argc == 3) {
            Bytes f = read_file(argv[2]);
            RsaPublicKey pub;
            try {
                pub = rsa_parse_private_key(f).public_key();
            } catch (const FormatError&) {
                pub = rsa_parse_public_key(f);
            }
            std::cout << hex_bytes(avb_encode_public_key(pub)) << "\n";
            return 0;
        }
        if (cmd == "der-dump" && argc == 3) {
            Bytes f = read_file(argv[2]);
            der::Tlv top = der::read(f);
            for (auto& c : der::children(f, top))
                std::printf("tag=0x%02x off=%zu len=%zu\n", c.tag, c.offset, c.content_len);
            return 0;
        }
        std::cerr << "usage error\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
