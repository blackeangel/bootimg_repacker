// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr/mbn.hpp, the images of Qualcomm's secure boot (sbl1/xbl, tz, hyp, aboot ...). Run by tests/run_tests.sh as `abr_unit_tests mbn`.
// The images here are made by hand, in the layout that coreboot's mbn_tools.py and qtestsign write (no image from a device was at hand), with
// the hashes made by abr::hash in these tests and, in the live checks of the script, by Python's hashlib:
//
//   * the names (algorithms, segment and access types of p_flags, the words of the headers), the sizes of the five headers;
//   * the structure, for every version (3, 5, 6, 7) and the SBL header, with and without signature, chain and metadata: read, built back to the
//     same bytes, the sizes made again when a part changes, the pointers where they were address + size, the rounding of the total to four bytes;
//   * what is not a structure: a version that does not exist, sizes that do not add up, parts that do not fit, every cut of a good image;
//   * flat images: found by the structure alone, and not found in files that are other things;
//   * the certificate chain: the subjects and the OU attributes of hand-made certificates, a chain that is filled up, bytes that are no certificate;
//   * an ELF with a hash segment, 32 and 64 bits: the table of hashes (SHA-1, SHA-256, SHA-384) is recognised only where abr makes exactly that
//     table, made again when a segment is edited (the same size, a bigger one that pushes the next one on, a smaller one), the hash segment growing,
//     a paged segment, a segment of a kind the loader does not check, one with no data, a table that is not abr's (kept as it is);
//   * the layouts that are not tidy (a section header table, data between the segments, an e_phoff that is not the end of the ELF header) are kept
//     as they are and a segment may not change its size there;
//   * ELFs that are not images of this kind (no hash segment, a Sony boot image, a segment outside the file, big-endian) and every cut of one;
//   * whatever parse_elf() accepts of a damaged image is built again to the same bytes (a few thousand flipped bytes).
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "abr/asn1.hpp"
#include "abr/mbn.hpp"
#include "abr/sha.hpp"

using namespace abr;
using namespace abr::mbn;

namespace {

int g_failures = 0;
int g_checks = 0;

#define EXPECT(cond)                                                      \
    do {                                                                  \
        ++g_checks;                                                       \
        if (!(cond)) {                                                    \
            ++g_failures;                                                 \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                 \
    } while (0)

template <typename F>
bool throws(F&& f) {
    try {
        f();
    } catch (const FormatError&) {
        return true;
    }
    return false;
}

Bytes pattern(size_t n, uint8_t seed) {
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>(seed + i * 13 + (i >> 7));
    return b;
}

void put(Bytes& b, uint64_t v, int width) {
    for (int i = 0; i < width; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void put_at(Bytes& b, size_t at, uint64_t v, int width) {
    for (int i = 0; i < width; ++i) b[at + i] = static_cast<uint8_t>(v >> (8 * i));
}
uint32_t get32(const Bytes& b, size_t at) { return uint32_t{b[at]} | (uint32_t{b[at + 1]} << 8) | (uint32_t{b[at + 2]} << 16) | (uint32_t{b[at + 3]} << 24); }
void append(Bytes& a, const Bytes& b) { a.insert(a.end(), b.begin(), b.end()); }

Bytes cat(std::initializer_list<const Bytes*> parts) {
    Bytes out;
    for (const Bytes* p : parts) append(out, *p);
    return out;
}

// ------------------------------------------------------------------------------------------------------------ the structure, by hand --

struct BlockSpec {
    int version = 3;        // 3, 5, 6, 7; 0 for the SBL header
    uint32_t image_id = 5;
    Bytes code, sig, cert, sig_qti, cert_qti, meta, meta_qti;
    uint32_t dest = 0x0F900000;
    bool pointers = true;   // the signature and the chain at dest + code size ..., else 0xFFFFFFFF
    size_t slack = 0;       // bytes between the parts and image_size (versions 3, 5, 6 and the SBL header)
};

// The bytes of a structure, written word by word from the layouts in the tools: nothing of abr's code is used.
Bytes make_block(const BlockSpec& s) {
    Bytes out;
    const uint64_t sum = s.meta_qti.size() + s.meta.size() + s.code.size() + s.sig_qti.size() + s.cert_qti.size() + s.sig.size() + s.cert.size();
    const uint32_t image_size = static_cast<uint32_t>(sum + s.slack);
    const uint32_t sig_ptr = s.pointers ? static_cast<uint32_t>(s.dest + s.code.size()) : 0xFFFFFFFFu;
    const uint32_t cert_ptr = s.pointers ? static_cast<uint32_t>(sig_ptr + s.sig.size()) : 0xFFFFFFFFu;
    std::vector<uint32_t> w;
    if (s.version == 0) {
        w = {0x844BDCD1, 0x73D71034, s.image_id, 0xFFFFFFFF, 0xFFFFFFFF, 80, s.dest, image_size, static_cast<uint32_t>(s.code.size()), sig_ptr,
             static_cast<uint32_t>(s.sig.size()), cert_ptr, static_cast<uint32_t>(s.cert.size()), 0, 1, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    } else if (s.version == 3) {
        w = {s.image_id, 3, 0, s.dest, image_size, static_cast<uint32_t>(s.code.size()), sig_ptr, static_cast<uint32_t>(s.sig.size()), cert_ptr, static_cast<uint32_t>(s.cert.size())};
    } else if (s.version == 5 || s.version == 6) {
        w = {s.image_id, static_cast<uint32_t>(s.version), static_cast<uint32_t>(s.sig_qti.size()), static_cast<uint32_t>(s.cert_qti.size()), image_size,
             static_cast<uint32_t>(s.code.size()), sig_ptr, static_cast<uint32_t>(s.sig.size()), cert_ptr, static_cast<uint32_t>(s.cert.size())};
        if (s.version == 6) {
            w.push_back(static_cast<uint32_t>(s.meta_qti.size()));
            w.push_back(static_cast<uint32_t>(s.meta.size()));
        }
    } else {
        w = {0, 7, 24, static_cast<uint32_t>(s.meta_qti.size()), static_cast<uint32_t>(s.meta.size()), static_cast<uint32_t>(s.code.size()),
             static_cast<uint32_t>(s.sig_qti.size()), static_cast<uint32_t>(s.cert_qti.size()), static_cast<uint32_t>(s.sig.size()), static_cast<uint32_t>(s.cert.size()),
             0, 0, 0x7B, 0, 3, 0};
    }
    for (uint32_t v : w) put(out, v, 4);
    append(out, s.meta_qti);
    append(out, s.meta);
    append(out, s.code);
    append(out, s.sig_qti);
    append(out, s.cert_qti);
    append(out, s.sig);
    append(out, s.cert);
    if (s.version != 7) out.insert(out.end(), s.slack, 0xA5);
    return out;
}

BlockSpec secure_spec(int version) {
    BlockSpec s;
    s.version = version;
    s.code = pattern(200, 1);
    s.sig = pattern(256, 7);
    s.cert = pattern(300, 9);
    if (version == 5 || version == 6 || version == 7) {
        s.sig_qti = pattern(64, 11);
        s.cert_qti = pattern(96, 13);
    }
    if (version == 6) {
        s.meta_qti = pattern(8, 3);
        s.meta = pattern(120, 5);
    }
    if (version == 7) {
        s.meta_qti = pattern(16, 3);
        s.meta = pattern(224, 5);
    }
    if (version == 5 || version == 6) s.pointers = false;
    return s;
}

void test_names() {
    EXPECT(std::string(algo_name(Algo::Sha1)) == "SHA-1" && std::string(algo_name(Algo::Sha256)) == "SHA-256" && std::string(algo_name(Algo::Sha384)) == "SHA-384");
    EXPECT(std::string(algo_key(Algo::Sha256)) == "sha256" && std::string(algo_key(Algo::None)) == "none");
    EXPECT(algo_from_key("sha1") == Algo::Sha1 && algo_from_key("sha384") == Algo::Sha384 && algo_from_key("none") == Algo::None);
    EXPECT(!algo_from_key("SHA256") && !algo_from_key("md5") && !algo_from_key(""));
    EXPECT(digest_size(Algo::Sha1) == 20 && digest_size(Algo::Sha256) == 32 && digest_size(Algo::Sha384) == 48 && digest_size(Algo::None) == 0);
    const Bytes x = {'a', 'b', 'c'};
    EXPECT(digest(Algo::Sha256, x.data(), x.size()) == hash::sha256(x));
    EXPECT(digest(Algo::Sha1, x.data(), x.size()) == hash::sha1(x));
    EXPECT(digest(Algo::Sha384, x.data(), x.size()) == hash::sha384(x));
    EXPECT(digest(Algo::None, x.data(), x.size()).empty());

    EXPECT(header_size(Kind::Boot, 3) == 40 && header_size(Kind::Boot, 5) == 40 && header_size(Kind::Boot, 6) == 48 && header_size(Kind::Boot, 7) == 64);
    EXPECT(header_size(Kind::Sbl, 0) == 80 && header_size(Kind::Boot, 4) == 0 && header_size(Kind::Boot, 0) == 0);
    EXPECT(fields(Kind::Boot, 3).size() == 10 && fields(Kind::Boot, 5).size() == 10 && fields(Kind::Boot, 6).size() == 12 && fields(Kind::Boot, 7).size() == 16);
    EXPECT(fields(Kind::Sbl, 0).size() == 20 && fields(Kind::Boot, 4).empty());
    for (int v : {3, 5, 6, 7}) {
        const std::vector<Field>& f = fields(Kind::Boot, static_cast<uint32_t>(v));
        for (size_t i = 0; i < f.size(); ++i) EXPECT(f[i].index == i);  // the words are in order
        EXPECT(std::string(f[1].name) == "version" && f[1].use == Field::Use::Fixed);
    }

    EXPECT(segment_type_name(2) == "HASH" && segment_type_name(7) == "PHDR" && segment_type_name(1) == "AMSS" && segment_type_name(0).empty());
    EXPECT(access_type_name(1) == "RO" && access_type_name(3) == "NOTUSED" && access_type_name(4) == "SHARED" && access_type_name(0).empty());
    EXPECT(describe_flags(0x02200000) == "---, HASH, RO");
    EXPECT(describe_flags(0x07000000) == "---, PHDR");
    EXPECT(describe_flags(0x01300005) == "r-x, AMSS, RO, paged");
    EXPECT(describe_flags(0x6) == "rw-");
    EXPECT(segment_type(0x02200000) == 2 && access_type(0x02200000) == 1 && segment_type(0x80000000) == 0);
}

void test_blocks() {
    for (int v : {0, 3, 5, 6, 7}) {
        BlockSpec s = secure_spec(v);
        if (v == 0) s.pointers = true;
        const Bytes d = make_block(s);
        EXPECT(block_problem(d, 0, d.size()).empty());
        const Block b = parse_block(d, 0, d.size());
        EXPECT(b.kind == (v == 0 ? Kind::Sbl : Kind::Boot) && (v == 0 || b.version == static_cast<uint32_t>(v)));
        EXPECT(b.code == s.code && b.sig == s.sig && b.cert == s.cert && b.sig_qti == s.sig_qti && b.cert_qti == s.cert_qti && b.metadata == s.meta && b.metadata_qti == s.meta_qti);
        EXPECT(b.consumed == d.size() && b.header_bytes() == (v == 0 ? 80u : v == 6 ? 48u : v == 7 ? 64u : 40u));
        EXPECT(b.slack.empty());
        EXPECT(b.derived_ptrs == (v == 3 || v == 0));
        EXPECT(build_block(b) == d);
        EXPECT(describe_header(b) == (v == 0 ? "SBL header (80 bytes)" : "header version " + std::to_string(v) + " (" + std::to_string(b.header_bytes()) + " bytes)"));
        // The structure inside a bigger buffer, at an offset.
        Bytes padded(37, 0xEE);
        append(padded, d);
        padded.insert(padded.end(), 50, 0xDD);
        EXPECT(block_problem(padded, 37, padded.size()).empty());
        const Block at = parse_block(padded, 37, padded.size());
        EXPECT(at.consumed == d.size() && build_block(at) == d);
        // Every cut of it is a problem, and the cut at its end is none.
        for (size_t n = 0; n < d.size(); ++n) EXPECT(!block_problem(d, 0, n).empty());
        EXPECT(block_problem(d, 0, d.size() + 10).empty());

        // Words by name.
        EXPECT(b.word("code_size") == s.code.size() && b.word("sig_size") == s.sig.size() && b.word("cert_size") == s.cert.size());
        EXPECT(b.word("no_such_word") == 0);
        Block c = b;
        EXPECT(c.set_word(v == 7 ? "software_id" : "image_id", 0x1234) && c.word(v == 7 ? "software_id" : "image_id") == 0x1234);
        EXPECT(!c.set_word("no_such_word", 1));
        EXPECT(build_block(c) != d);
    }

    // Sizes made again: the code grows by 100 bytes. Where the pointers followed the sizes, they follow the new ones.
    {
        const BlockSpec s = secure_spec(3);
        Block b = parse_block(make_block(s), 0, 1 << 20);
        EXPECT(b.derived_ptrs && b.ptr_base == s.dest);
        b.code = pattern(300, 1);
        const Bytes g = build_block(b);
        BlockSpec t = s;
        t.code = b.code;
        EXPECT(g == make_block(t));
        EXPECT(get32(g, 6 * 4) == s.dest + 300 && get32(g, 8 * 4) == s.dest + 300 + 256 && get32(g, 4 * 4) == 300 + 256 + 300);
    }
    // Pointers that were not address + size (0xFFFFFFFF) stay as they are.
    {
        BlockSpec s = secure_spec(5);
        const Block b0 = parse_block(make_block(s), 0, 1 << 20);
        EXPECT(!b0.derived_ptrs);
        Block b = b0;
        b.sig = pattern(100, 2);
        const Bytes g = build_block(b);
        EXPECT(get32(g, 6 * 4) == 0xFFFFFFFFu && get32(g, 8 * 4) == 0xFFFFFFFFu && get32(g, 7 * 4) == 100);
        // An unsigned image has the same pointer twice: that is no relation to follow when it is 0 or all ones.
        BlockSpec u;
        u.version = 3;
        u.code = pattern(64, 1);
        u.dest = 0;
        u.pointers = false;
        EXPECT(!parse_block(make_block(u), 0, 1 << 20).derived_ptrs);
    }
    // The rounding of the total to a multiple of four.
    {
        BlockSpec s;
        s.version = 3;
        s.code = pattern(10, 1);
        s.sig = pattern(1, 2);
        s.slack = 1;  // 11 bytes of parts, image_size 12
        const Bytes d = make_block(s);
        const Block b = parse_block(d, 0, d.size());
        EXPECT(b.slack.size() == 1 && b.align4 && get32(d, 4 * 4) == 12);
        EXPECT(build_block(b) == d);
        Block g = b;
        g.code = pattern(11, 1);  // 12 bytes: no slack now
        const Bytes e = build_block(g);
        EXPECT(e.size() == 40 + 12 && get32(e, 4 * 4) == 12);
        g.code = pattern(12, 1);  // 13 bytes: three bytes of rounding
        const Bytes f = build_block(g);
        EXPECT(f.size() == 40 + 16 && get32(f, 4 * 4) == 16 && f[40 + 13] == 0xA5 && f[40 + 14] == 0 && f[40 + 15] == 0);
        // Slack that is not the rounding is kept as it is.
        BlockSpec t = s;
        t.slack = 3;  // 11 + 3 = 14, not a multiple of four
        const Bytes h = make_block(t);
        const Block hb = parse_block(h, 0, h.size());
        EXPECT(hb.slack.size() == 3 && !hb.align4 && build_block(hb) == h);
        Block hg = hb;
        hg.code = pattern(20, 1);
        EXPECT(build_block(hg).size() == 40 + 20 + 1 + 3);
    }
    // The version 7 header has no image_size and no slack.
    {
        const Bytes d = make_block(secure_spec(7));
        const Block b = parse_block(d, 0, d.size());
        EXPECT(b.slack.empty() && !b.derived_ptrs && b.word("software_id") == 0x7B && b.word("hash_table_algorithm") == 3);
        EXPECT(b.word("common_metadata_size") == 24);
    }
    // make_block() of the library.
    for (int v : {3, 5, 6, 7}) {
        Block b = abr::mbn::make_block(Kind::Boot, static_cast<uint32_t>(v));
        b.code = pattern(16, 1);
        const Bytes d = build_block(b);
        EXPECT(block_problem(d, 0, d.size()).empty() && get32(d, 4) == static_cast<uint32_t>(v) && d.size() == b.header_bytes() + 16);
    }
    {
        Block b = abr::mbn::make_block(Kind::Sbl, 0);
        b.code = pattern(16, 1);
        const Bytes d = build_block(b);
        EXPECT(block_problem(d, 0, d.size()).empty() && get32(d, 0) == kSblCodeword && get32(d, 4) == kSblMagic && get32(d, 5 * 4) == 80);
    }
}

void test_block_problems() {
    const Bytes good = make_block(secure_spec(3));
    EXPECT(block_problem({}, 0, 0).find("fewer than 8") != std::string::npos);
    EXPECT(block_problem(good, good.size(), good.size()).find("fewer than 8") != std::string::npos);
    EXPECT(block_problem(good, 5, 3).find("fewer than 8") != std::string::npos);
    Bytes b = good;
    put_at(b, 4, 4, 4);
    EXPECT(block_problem(b, 0, b.size()).find("version 4") != std::string::npos);
    EXPECT(throws([&] { parse_block(b, 0, b.size()); }));
    b = good;
    put_at(b, 4, 8, 4);
    EXPECT(!block_problem(b, 0, b.size()).empty());
    // image_size that is not the sum of the parts.
    b = good;
    put_at(b, 16, get32(good, 16) + 4, 4);
    EXPECT(block_problem(b, 0, b.size()).find("image_size") != std::string::npos);
    b = good;
    put_at(b, 16, get32(good, 16) - 1, 4);
    EXPECT(block_problem(b, 0, b.size()).find("image_size") != std::string::npos);
    // A size that makes the parts overrun the buffer.
    b = good;
    put_at(b, 5 * 4, 0x7FFFFFFF, 4);
    EXPECT(!block_problem(b, 0, b.size()).empty());
    // 32-bit sizes that wrap when they are added up in a narrow type.
    b = good;
    put_at(b, 5 * 4, 0xFFFFFFFF, 4);
    put_at(b, 7 * 4, 0xFFFFFFFF, 4);
    put_at(b, 9 * 4, 0xFFFFFFFF, 4);
    put_at(b, 4 * 4, 0xFFFFFFFF, 4);
    EXPECT(!block_problem(b, 0, b.size()).empty());
    // Version 7 with a common metadata size that is not 24.
    Bytes v7 = make_block(secure_spec(7));
    put_at(v7, 8, 32, 4);
    EXPECT(block_problem(v7, 0, v7.size()).find("common_metadata_size") != std::string::npos);
    // SBL: the code is not behind the header.
    BlockSpec s = secure_spec(0);
    Bytes sbl = make_block(s);
    put_at(sbl, 5 * 4, 0x800, 4);
    EXPECT(block_problem(sbl, 0, sbl.size()).find("image_src") != std::string::npos);
}

// ------------------------------------------------------------------------------------------------------------------------------ flat images --

void test_flat() {
    for (int v : {0, 3, 5, 6, 7}) {
        const Bytes d = make_block(secure_spec(v));
        EXPECT(flat_looks_like(d));
        Bytes padded = d;
        padded.insert(padded.end(), 4096, 0xFF);  // the fill up to the partition size
        EXPECT(flat_looks_like(padded));
        Bytes cut(d.begin(), d.end() - 1);
        EXPECT(!flat_looks_like(cut));
        EXPECT(flat_problem(d).empty());
    }
    // An unsigned image: the structure is the header and the code.
    BlockSpec u;
    u.version = 3;
    u.code = pattern(1000, 4);
    EXPECT(flat_looks_like(make_block(u)));
    // An image id that is not small, no code: not taken for one.
    u.image_id = 0x1000;
    EXPECT(!flat_looks_like(make_block(u)));
    u.image_id = 5;
    u.code.clear();
    EXPECT(!flat_looks_like(make_block(u)));
    // Other things.
    EXPECT(!flat_looks_like({}));
    EXPECT(!flat_looks_like(Bytes(100, 0)));
    EXPECT(!flat_looks_like(Bytes(100, 0xFF)));
    EXPECT(!flat_looks_like(pattern(4096, 1)));
    Bytes android = {'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'};
    android.resize(4096, 0);
    EXPECT(!flat_looks_like(android));
    Bytes elf = {0x7F, 'E', 'L', 'F', 1, 1, 1};
    elf.resize(4096, 0);
    EXPECT(!flat_looks_like(elf));
    // An image whose version is right and the sizes are not.
    Bytes b = make_block(secure_spec(3));
    put_at(b, 7 * 4, 5, 4);
    EXPECT(!flat_looks_like(b));

    // The SBL header with the NAND preamble in front (the page-size magic as the third word).
    Bytes pre;
    put(pre, kSblCodeword, 4);
    put(pre, kSblMagic, 4);
    put(pre, kSblPreambleMagic, 4);
    pre.resize(4096, 0xFF);
    EXPECT(!flat_looks_like(pre));
    EXPECT(flat_problem(pre).find("preamble") != std::string::npos);
    Bytes sbl = make_block(secure_spec(0));
    put_at(sbl, 5 * 4, 0x1000, 4);
    EXPECT(!flat_looks_like(sbl));
    EXPECT(flat_problem(sbl).find("image_src") != std::string::npos);
    EXPECT(flat_problem(android).empty());
}

// ----------------------------------------------------------------------------------------------------------------------------------- chain --

Bytes oid(std::initializer_list<uint8_t> v) { return der::encode(der::kOid, Bytes(v)); }

Bytes atv(const Bytes& type, uint8_t string_tag, const std::string& text) {
    return der::encode(der::kSet, der::encode_sequence({type, der::encode(string_tag, Bytes(text.begin(), text.end()))}));
}

Bytes name(const std::vector<std::pair<char, std::string>>& entries) {
    Bytes content;
    for (const auto& [k, v] : entries) {
        Bytes type;
        switch (k) {
            case 'C': type = oid({0x55, 0x04, 0x06}); break;
            case 'O': type = oid({0x55, 0x04, 0x0A}); break;
            case 'U': type = oid({0x55, 0x04, 0x0B}); break;
            case 'N': type = oid({0x55, 0x04, 0x03}); break;
            default: type = oid({0x55, 0x04, 0x07}); break;
        }
        append(content, atv(type, k == 'C' ? der::kPrintableString : 0x0C, v));
    }
    return der::encode(der::kSequence, content);
}

Bytes certificate(const Bytes& issuer, const Bytes& subject) {
    const Bytes alg = der::encode_sequence({oid({0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}), der::encode(der::kNull, {})});
    const Bytes validity = der::encode_sequence({der::encode(0x17, Bytes{'2', '1', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'}),
                                                der::encode(0x17, Bytes{'3', '1', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'})});
    const Bytes spki = der::encode_sequence({alg, der::encode(der::kBitString, Bytes{0, 1, 2, 3})});
    const Bytes tbs = der::encode_sequence({der::encode(0xA0, der::encode_integer(uint64_t{2})), der::encode_integer(uint64_t{1234}), alg, issuer, validity, subject, spki});
    return der::encode_sequence({tbs, alg, der::encode(der::kBitString, Bytes{0, 9, 9, 9})});
}

void test_chain() {
    const Bytes root = name({{'C', "US"}, {'O', "Example Root"}, {'N', "Root CA"}});
    const Bytes mid = name({{'C', "US"}, {'O', "Example"}, {'N', "Attestation CA"}});
    const Bytes leaf = name({{'C', "US"}, {'L', "San Diego"}, {'U', "01 0000000000000003 SW_ID"}, {'U', "02 0000000000000000 HW_ID"},
                             {'U', "03 0000000000000002 DEBUG"}, {'U', "07 0001 SHA256"}, {'N', "Attestation"}});
    const Bytes c1 = certificate(root, leaf), c2 = certificate(root, mid), c3 = certificate(root, root);
    Bytes chain = cat({&c1, &c2, &c3});
    const size_t used = chain.size();
    chain.insert(chain.end(), 100, 0xFF);
    size_t rest = 0;
    const std::vector<Cert> certs = read_chain(chain, &rest);
    EXPECT(certs.size() == 3 && rest == 100);
    if (certs.size() == 3) {
        EXPECT(certs[0].offset == 0 && certs[0].size == c1.size() && certs[1].offset == c1.size() && certs[2].offset == c1.size() + c2.size());
        EXPECT(certs[0].subject == "C=US, L=San Diego, OU=01 0000000000000003 SW_ID, OU=02 0000000000000000 HW_ID, OU=03 0000000000000002 DEBUG, OU=07 0001 SHA256, CN=Attestation");
        EXPECT(certs[0].issuer == "C=US, O=Example Root, CN=Root CA");
        EXPECT(certs[0].attributes.size() == 4 && certs[0].attributes[0] == "01 0000000000000003 SW_ID" && certs[0].attributes[3] == "07 0001 SHA256");
        EXPECT(certs[1].subject == "C=US, O=Example, CN=Attestation CA" && certs[1].attributes.empty());
        EXPECT(certs[2].subject == certs[2].issuer);
        EXPECT(certs[0].size + certs[1].size + certs[2].size == used);
    }
    // Without the count of the rest.
    EXPECT(read_chain(chain).size() == 3);
    // A chain that is only fill, empty, or bytes that are no certificate.
    rest = 0;
    EXPECT(read_chain(Bytes(64, 0xFF), &rest).empty() && rest == 64);
    EXPECT(read_chain({}, &rest).empty() && rest == 0);
    EXPECT(read_chain(Bytes(64, 0), &rest).empty() && rest == 64);
    EXPECT(read_chain(pattern(300, 1), &rest).empty());
    // A SEQUENCE that is cut short, or that is no certificate (a sequence of two integers), ends the chain where it starts.
    Bytes cut(c1.begin(), c1.end() - 5);
    EXPECT(read_chain(cut, &rest).empty() && rest == cut.size());
    const Bytes seq = der::encode_sequence({der::encode_integer(uint64_t{1}), der::encode_integer(uint64_t{2})});
    Bytes mixed = cat({&c1, &seq});
    EXPECT(read_chain(mixed, &rest).size() == 1 && rest == seq.size());
    // Strings that are not printable come out in hex.
    const Bytes odd = der::encode(der::kSequence, atv(oid({0x55, 0x04, 0x03}), 0x0C, std::string("a\x01z", 3)));
    const Bytes c4 = certificate(odd, odd);
    EXPECT(read_chain(c4).size() == 1 && read_chain(c4)[0].subject == "CN=#61017a");

    EXPECT(attribute_text("01 0000000000000003 SW_ID") == "SW_ID 0x0000000000000003");
    EXPECT(attribute_text("07 0001 SHA256") == "SHA256 0x0001");
    EXPECT(attribute_text("04 0000 OEM_ID") == "OEM_ID 0x0000");
    EXPECT(attribute_text("Qualcomm").empty() && attribute_text("").empty() && attribute_text("1 2 3").empty());
    EXPECT(attribute_text("01 00zz SW_ID").empty() && attribute_text("01 0003 sw_id").empty() && attribute_text("01 0003 SW ID").empty());
}

// ----------------------------------------------------------------------------------------------------------------------------- the ELF, by hand --

struct SegSpec {
    uint32_t type = 1;        // PT_LOAD
    uint32_t flags = 0x5;
    uint64_t offset = 0;      // where the data is in the file (the data's size is what the data has)
    uint64_t vaddr = 0;
    uint64_t memsz = 0;       // 0: as big as the data
    uint64_t align = 0x1000;
    Bytes data;
};

struct ElfSpec {
    bool is64 = false;
    int version = 3;                 // of the header of the hash segment
    Algo algo = Algo::Sha256;
    Bytes sig, cert;
    uint64_t hash_offset = 0x1000;
    uint64_t hash_vaddr = 0x87000000;
    std::vector<SegSpec> segs;       // behind the placeholder and the hash segment
    uint8_t fill = 0;
    bool phdr_placeholder = true;
    uint64_t trailing = 0;           // bytes after the last segment
    uint64_t hash_pad = 0;           // bytes of the hash segment behind its parts
};

constexpr uint32_t kPlaceholderFlags = 0x07000000, kHashFlags = 0x02200000;

Bytes phdr_bytes(bool is64, uint32_t type, uint32_t flags, uint64_t off, uint64_t vaddr, uint64_t filesz, uint64_t memsz, uint64_t align) {
    Bytes out;
    put(out, type, 4);
    if (is64) {
        put(out, flags, 4), put(out, off, 8), put(out, vaddr, 8), put(out, vaddr, 8), put(out, filesz, 8), put(out, memsz, 8), put(out, align, 8);
    } else {
        put(out, off, 4), put(out, vaddr, 4), put(out, vaddr, 4), put(out, filesz, 4), put(out, memsz, 4), put(out, flags, 4), put(out, align, 4);
    }
    return out;
}

Bytes ehdr_bytes(bool is64, size_t phnum, uint64_t entry, uint64_t phoff = 0, uint64_t shoff = 0, size_t shnum = 0) {
    Bytes out = {0x7F, 'E', 'L', 'F', static_cast<uint8_t>(is64 ? 2 : 1), 1, 1};
    out.resize(16, 0);
    put(out, 2, 2);
    put(out, is64 ? 0xB7 : 0x28, 2);
    put(out, 1, 4);
    const int a = is64 ? 8 : 4;
    const uint64_t ehsize = is64 ? 64 : 52;
    put(out, entry, a);
    put(out, phoff ? phoff : ehsize, a);
    put(out, shoff, a);
    put(out, 0, 4);
    put(out, ehsize, 2);
    put(out, is64 ? 56 : 32, 2);
    put(out, phnum, 2);
    put(out, is64 ? 64 : 40, 2);
    put(out, shnum, 2);
    put(out, 0, 2);
    return out;
}

// Whether a segment's hash is made, in the words of the tool.
bool checked(uint32_t flags) {
    const unsigned t = (flags >> 24) & 7, a = (flags >> 21) & 7;
    return t != 2 && a != 3 && a != 4;
}

// The expected table, written out by hand: one entry per program header, in order.
Bytes expected_table(const ElfSpec& s, const Bytes& headers, Algo algo) {
    Bytes out;
    const size_t ds = digest_size(algo);
    const auto h = [&](const uint8_t* p, size_t n) { return digest(algo, p, n); };
    if (s.phdr_placeholder) append(out, h(headers.data(), headers.size()));
    out.insert(out.end(), ds, 0);  // the hash segment itself
    for (const SegSpec& g : s.segs) {
        if ((g.flags & 0x00100000) && !g.data.empty()) {  // paged: an entry for every page (the segments in the tests are made of whole pages at a page boundary)
            for (size_t pos = 0; pos < g.data.size(); pos += 0x1000)
                append(out, checked(g.flags) ? h(g.data.data() + pos, std::min<size_t>(0x1000, g.data.size() - pos)) : Bytes(ds, 0));
        } else if (checked(g.flags) && !g.data.empty()) {
            append(out, h(g.data.data(), g.data.size()));
        } else {
            out.insert(out.end(), ds, 0);
        }
    }
    return out;
}

// The whole file. The table is made with `algo`; the header of the hash segment is the one of the version, written by hand.
Bytes make_elf(const ElfSpec& s) {
    const size_t phnum = s.segs.size() + 1 + (s.phdr_placeholder ? 1 : 0);
    const uint64_t ehsize = s.is64 ? 64 : 52, phsize = s.is64 ? 56 : 32;
    const uint64_t header_size = ehsize + phnum * phsize;

    // The headers, with the sizes of the hash segment not yet known: they depend on the table only through its length, so make the headers first
    // with a guess, then again.
    const auto build_headers = [&](uint64_t hash_filesz, uint64_t hash_memsz) {
        Bytes h = ehdr_bytes(s.is64, phnum, s.segs.empty() ? 0 : s.segs[0].vaddr);
        if (s.phdr_placeholder) append(h, phdr_bytes(s.is64, 0, kPlaceholderFlags, 0, 0, header_size, 0, 0));
        append(h, phdr_bytes(s.is64, 0, kHashFlags, s.hash_offset, s.hash_vaddr, hash_filesz, hash_memsz, 0x1000));
        for (const SegSpec& g : s.segs)
            append(h, phdr_bytes(s.is64, g.type, g.flags, g.offset, g.vaddr, g.data.size(), g.memsz ? g.memsz : g.data.size(), g.align));
        return h;
    };
    const size_t digest = digest_size(s.algo);
    const size_t entries = expected_table(s, Bytes(), s.algo).size() / digest;
    const uint64_t code = entries * digest;
    const size_t hdr_len = s.version == 6 ? 48 : s.version == 7 ? 64 : 40;
    const uint64_t meta = s.version == 6 ? 120 : s.version == 7 ? 224 : 0;
    const uint64_t parts = meta + code + s.sig.size() + s.cert.size();
    const uint64_t hash_filesz = hdr_len + parts + s.hash_pad;
    const Bytes headers = build_headers(hash_filesz, (hash_filesz + 0xFFF) & ~uint64_t{0xFFF});
    const Bytes table = expected_table(s, headers, s.algo);

    Bytes block;
    const uint32_t dest = static_cast<uint32_t>(s.hash_vaddr + hdr_len);
    const uint32_t sig_ptr = dest + static_cast<uint32_t>(code), cert_ptr = sig_ptr + static_cast<uint32_t>(s.sig.size());
    std::vector<uint32_t> w;
    if (s.version == 3) {
        w = {0x17, 3, 0, dest, static_cast<uint32_t>(parts), static_cast<uint32_t>(code), sig_ptr, static_cast<uint32_t>(s.sig.size()), cert_ptr, static_cast<uint32_t>(s.cert.size())};
    } else if (s.version == 5) {
        w = {0x17, 5, 0, 0, static_cast<uint32_t>(parts), static_cast<uint32_t>(code), 0xFFFFFFFF, static_cast<uint32_t>(s.sig.size()), 0xFFFFFFFF, static_cast<uint32_t>(s.cert.size())};
    } else if (s.version == 6) {
        w = {0x17, 6, 0, 0, static_cast<uint32_t>(parts), static_cast<uint32_t>(code), 0xFFFFFFFF, static_cast<uint32_t>(s.sig.size()), 0xFFFFFFFF, static_cast<uint32_t>(s.cert.size()), 0, 120};
    } else {
        w = {0, 7, 24, 0, 224, static_cast<uint32_t>(code), 0, 0, static_cast<uint32_t>(s.sig.size()), static_cast<uint32_t>(s.cert.size()), 0, 0, 0x7B, 0, 3, 0};
    }
    for (uint32_t v : w) put(block, v, 4);
    block.insert(block.end(), meta, 0x3C);
    append(block, table);
    append(block, s.sig);
    append(block, s.cert);
    block.insert(block.end(), s.hash_pad, 0);

    Bytes out = headers;
    out.resize(s.hash_offset, s.fill);
    append(out, block);
    for (const SegSpec& g : s.segs) {
        if (g.data.empty()) continue;  // a segment without data has an offset and no bytes
        out.resize(g.offset, s.fill);
        append(out, g.data);
    }
    out.insert(out.end(), s.trailing, 0xFF);
    return out;
}

// A typical firmware: a code segment, a data segment, a segment that is not hashed (NOTUSED) and one that has no data (bss).
ElfSpec typical(bool is64, int version = 3, Algo algo = Algo::Sha256) {
    ElfSpec s;
    s.is64 = is64;
    s.version = version;
    s.algo = algo;
    s.sig = pattern(256, 21);
    s.cert = pattern(512, 22);
    SegSpec code, data, unused, bss;
    code.flags = 0x01200005;  // AMSS, RO, r-x
    code.offset = 0x3000;
    code.vaddr = 0x86000000;
    code.data = pattern(0x1400, 31);
    code.memsz = 0x1400;
    data.flags = 0x01000006;  // AMSS, RW
    data.offset = 0x5000;
    data.vaddr = 0x86100000;
    data.data = pattern(0x700, 32);
    data.memsz = 0x2000;  // bss behind it
    unused.flags = 0x01600004;  // NOTUSED
    unused.offset = 0x6000;
    unused.vaddr = 0x86200000;
    unused.data = pattern(0x300, 33);
    bss.flags = 0x01000006;
    bss.offset = 0x6400;
    bss.vaddr = 0x86300000;
    bss.memsz = 0x1000;
    s.segs = {code, data, unused, bss};
    return s;
}

void expect_round_trip(const Bytes& file, const char* what) {
    try {
        const Elf e = parse_elf(file);
        const Bytes back = build_elf(e);
        if (back != Bytes(file.begin(), file.begin() + static_cast<std::ptrdiff_t>(e.consumed))) {
            ++g_failures;
            ++g_checks;
            std::printf("  FAIL %s: the rebuilt image differs (%s)\n", what, e.tidy ? "tidy" : "not tidy");
        } else {
            ++g_checks;
        }
    } catch (const std::exception& ex) {
        ++g_failures;
        ++g_checks;
        std::printf("  FAIL %s: %s\n", what, ex.what());
    }
}

void test_elf_basic() {
    for (bool is64 : {false, true}) {
        for (int version : {3, 5, 6, 7}) {
            const Algo algo = version >= 6 ? Algo::Sha384 : Algo::Sha256;
            const ElfSpec spec = typical(is64, version, algo);
            const Bytes file = make_elf(spec);
            EXPECT(elf_looks_like(file));
            EXPECT(elf_problem(file).empty());
            const Elf e = parse_elf(file);
            EXPECT(e.is64 == is64 && e.seg.size() == 6 && e.hash_index == 1);
            EXPECT(e.seg[0].role == Role::Headers && e.seg[1].role == Role::Hash && e.seg[2].role == Role::Plain && e.seg[5].role == Role::Plain);
            EXPECT(e.seg[2].data == spec.segs[0].data && e.seg[3].data == spec.segs[1].data && e.seg[4].data == spec.segs[2].data && e.seg[5].data.empty());
            EXPECT(e.block.kind == Kind::Boot && e.block.version == static_cast<uint32_t>(version));
            EXPECT(e.block.sig == spec.sig && e.block.cert == spec.cert);
            EXPECT(e.algo == algo);
            EXPECT(e.tidy && e.fill == 0 && e.skeleton.empty());
            EXPECT(e.consumed == file.size());
            EXPECT(e.block.code == expected_table(spec, Bytes(file.begin(), file.begin() + static_cast<std::ptrdiff_t>(e.header_size())), algo));
            EXPECT(build_elf(e) == file);
            EXPECT(e.machine == (is64 ? 0xB7 : 0x28) && e.entry == spec.segs[0].vaddr);
            // The table: entry 0 is the hash of the headers, entry 1 is zeros, the NOTUSED segment and the empty one are zeros.
            const size_t ds = digest_size(algo);
            EXPECT(Bytes(e.block.code.begin() + static_cast<std::ptrdiff_t>(ds), e.block.code.begin() + static_cast<std::ptrdiff_t>(2 * ds)) == Bytes(ds, 0));
            EXPECT(Bytes(e.block.code.begin() + static_cast<std::ptrdiff_t>(4 * ds), e.block.code.begin() + static_cast<std::ptrdiff_t>(5 * ds)) == Bytes(ds, 0));
            EXPECT(Bytes(e.block.code.begin() + static_cast<std::ptrdiff_t>(5 * ds), e.block.code.end()) == Bytes(ds, 0));
            EXPECT(e.block.code.size() == 6 * ds);
            EXPECT(table_entries(e) == 6u);
            const std::optional<Bytes> t = make_table(e, algo, elf_header_bytes(e));
            EXPECT(t && *t == e.block.code);
            EXPECT(!make_table(e, Algo::None, {}));
            EXPECT(elf_header_bytes(e).size() == e.header_size() && Bytes(file.begin(), file.begin() + static_cast<std::ptrdiff_t>(e.header_size())) == elf_header_bytes(e));
        }
    }
    // SHA-1 (older images).
    {
        const Bytes file = make_elf(typical(false, 3, Algo::Sha1));
        const Elf e = parse_elf(file);
        EXPECT(e.algo == Algo::Sha1 && e.block.code.size() == 6 * 20 && build_elf(e) == file);
    }
    // Without a placeholder (an ELF whose first header is the hash segment), with 0xFF between the parts, with bytes after the last segment.
    {
        ElfSpec s = typical(false);
        s.phdr_placeholder = false;
        s.fill = 0xFF;
        s.trailing = 777;
        const Bytes file = make_elf(s);
        const Elf e = parse_elf(file);
        EXPECT(e.seg.size() == 5 && e.hash_index == 0 && e.algo == Algo::Sha256 && e.tidy && e.fill == 0xFF);
        EXPECT(e.consumed == file.size() - 777);
        EXPECT(build_elf(e) == Bytes(file.begin(), file.end() - 777));
    }
    // Bytes in the hash segment behind its parts.
    {
        ElfSpec s = typical(true);
        s.hash_pad = 100;
        const Bytes file = make_elf(s);
        const Elf e = parse_elf(file);
        EXPECT(e.hash_pad == Bytes(100, 0) && e.algo == Algo::Sha256 && build_elf(e) == file);
    }
    // The hash segment's header says its code, signature and chain pointers follow each other: so they do.
    {
        const Bytes file = make_elf(typical(false, 3));
        const Elf e = parse_elf(file);
        EXPECT(e.block.derived_ptrs && e.block.ptr_base == e.block.word("image_dest"));
    }
}

// The segments of a parsed ELF with `file` as the source: replaced data, built again, parsed again.
Elf edit(const Bytes& file, size_t seg, const Bytes& data) {
    Elf e = parse_elf(file);
    e.seg[seg].data = data;
    return e;
}

void test_elf_edits() {
    const ElfSpec spec = typical(false);
    const Bytes file = make_elf(spec);

    // The same size: only the segment and its entry in the table change.
    {
        const Bytes data = pattern(spec.segs[0].data.size(), 99);
        const Bytes out = build_elf(edit(file, 2, data));
        EXPECT(out.size() == file.size());
        ElfSpec t = spec;
        t.segs[0].data = data;
        EXPECT(out == make_elf(t));
        const Elf again = parse_elf(out);
        EXPECT(again.algo == Algo::Sha256 && again.seg[2].data == data && again.tidy);
        // The bytes that differ are those of the segment, the entry of the table (and the hash of the headers has not moved: same sizes).
        size_t differing = 0;
        for (size_t i = 0; i < file.size(); ++i) differing += out[i] != file[i];
        EXPECT(differing > 0);
        EXPECT(Bytes(out.begin(), out.begin() + 0x1000) == Bytes(file.begin(), file.begin() + 0x1000));
    }
    // A segment that grows into the next one pushes it on, to the next multiple of the alignment its place had; what follows it keeps its place
    // while that is behind the end of the one before.
    {
        const Bytes data = pattern(0x2200, 98);  // 0x3000 + 0x2200 = 0x5200 > 0x5000
        std::string note;
        const Bytes out = build_elf(edit(file, 2, data), &note);
        const Elf again = parse_elf(out);
        EXPECT(again.tidy && again.algo == Algo::Sha256);
        EXPECT(again.seg[2].ph.offset == 0x3000 && again.seg[2].ph.filesz == 0x2200);
        EXPECT(again.seg[3].ph.offset == 0x6000);  // 0x5200, up to the next multiple of p_align (0x1000) from where it was
        EXPECT(again.seg[4].ph.offset == 0x7000);  // 0x6000 + 0x700 = 0x6700 -> 0x7000
        EXPECT(again.seg[2].data == data && again.seg[3].data == spec.segs[1].data && again.seg[4].data == spec.segs[2].data);
        EXPECT(note.find("program header 3 0x5000 -> 0x6000") != std::string::npos);
        // The table is the one that the tool would make for what the file holds now.
        ElfSpec t = spec;
        t.segs[0].data = data;
        t.segs[0].memsz = 0x2200;  // p_memsz grew with the data: it was as big as the data
        t.segs[1].offset = 0x6000;
        t.segs[2].offset = 0x7000;  // (the segment without data keeps its p_offset, 0x6400)
        EXPECT(out == make_elf(t));
        // p_memsz of the grown segment grew with it (it was as big as its data); the one with a bss kept its own.
        EXPECT(again.seg[2].ph.memsz == 0x2200 && again.seg[3].ph.memsz == 0x2000);
    }
    // A segment that shrinks stays where it is, and the fill widens.
    {
        const Bytes data = pattern(0x100, 97);
        const Bytes out = build_elf(edit(file, 3, data));
        const Elf again = parse_elf(out);
        EXPECT(again.seg[3].ph.offset == 0x5000 && again.seg[3].ph.filesz == 0x100 && again.seg[4].ph.offset == 0x6000);
        EXPECT(again.seg[3].ph.memsz == 0x2000);  // a bss stays what it is; abr does not guess at it
        EXPECT(out[0x5100] == 0 && out[0x5FFF] == 0);
        EXPECT(again.tidy && again.algo == Algo::Sha256);
    }
    // A segment that is emptied has no data and keeps its p_offset.
    {
        const Elf e = edit(file, 4, {});
        const Bytes out = build_elf(e);
        const Elf again = parse_elf(out);
        EXPECT(again.seg[4].ph.filesz == 0 && again.seg[4].ph.offset == 0x6000 && again.algo == Algo::Sha256);
        EXPECT(again.seg[4].data.empty());
    }
    // Where the hash segment grows (a longer chain), the data behind it moves on if it must.
    {
        Elf e = parse_elf(file);
        e.block.cert = pattern(0x2100, 5);  // 0x1000 + 40 + table + 256 + 0x2100 > 0x3000
        std::string note;
        const Bytes out = build_elf(e, &note);
        const Elf again = parse_elf(out);
        EXPECT(again.tidy && again.algo == Algo::Sha256 && again.block.cert == e.block.cert);
        EXPECT(again.seg[2].ph.offset > 0x3000 && again.seg[2].ph.offset % 0x1000 == 0);
        EXPECT(again.seg[1].ph.filesz == again.block.consumed + again.hash_pad.size());
        EXPECT(again.seg[1].ph.memsz >= again.seg[1].ph.filesz);
        EXPECT(again.seg[2].data == spec.segs[0].data);
        // The pointers of the version 3 header follow the sizes.
        EXPECT(again.block.derived_ptrs && again.block.word("cert_size") == 0x2100);
        EXPECT(again.block.word("cert_ptr") == again.block.word("sig_ptr") + 256);
    }
    // A header of the table changes, so the hash of the headers does: a segment that moves changes it.
    {
        const Bytes data = pattern(0x2200, 98);
        const Elf moved = parse_elf(build_elf(edit(file, 2, data)));
        const Elf orig = parse_elf(file);
        EXPECT(Bytes(moved.block.code.begin(), moved.block.code.begin() + 32) != Bytes(orig.block.code.begin(), orig.block.code.begin() + 32));
    }
    // 32-bit ELF: an offset that does not fit.
    {
        const Elf e = edit(file, 2, Bytes(10, 1));
        Elf big = e;
        big.seg[3].ph.offset = 0x1'0000'0000ull;
        EXPECT(throws([&] { build_elf(big); }));
    }
    // A segment with a bss that is edited so that its data is longer than its p_memsz: p_memsz is raised.
    {
        const Bytes data = pattern(0x2100, 96);
        const Elf again = parse_elf(build_elf(edit(file, 3, data)));
        EXPECT(again.seg[3].ph.filesz == 0x2100 && again.seg[3].ph.memsz == 0x2100);  // p_memsz is never below p_filesz
    }
}

void test_elf_tables() {
    // A table that is not the one abr makes (an entry changed) is kept as it is, edits or not.
    {
        const ElfSpec spec = typical(false);
        Bytes file = make_elf(spec);
        file[0x1000 + 40 + 2 * 32 + 5] ^= 0x55;  // an entry of the table: the hash of the first segment
        const Elf e = parse_elf(file);
        EXPECT(e.algo == Algo::None && e.tidy);
        EXPECT(build_elf(e) == file);
        Elf edited = e;
        edited.seg[2].data = pattern(spec.segs[0].data.size(), 77);
        const Bytes out = build_elf(edited);
        EXPECT(Bytes(out.begin() + 0x1000, out.begin() + 0x1000 + 40 + 6 * 32) == Bytes(file.begin() + 0x1000, file.begin() + 0x1000 + 40 + 6 * 32));
        EXPECT(parse_elf(out).algo == Algo::None);
    }
    // A table of a length that fits no algorithm (7 bytes per entry) is kept as it is too.
    {
        ElfSpec spec = typical(false);
        Bytes file = make_elf(spec);
        Elf e = parse_elf(file);
        e.block.code.resize(e.block.code.size() - 4);
        e.algo = Algo::None;
        const Bytes odd = build_elf(e);
        const Elf again = parse_elf(odd);
        EXPECT(again.algo == Algo::None && again.block.code.size() == e.block.code.size() && build_elf(again) == odd);
    }
    // A PT_PHDR program header: the tool takes them out, so abr does not make a table for an ELF that has one.
    {
        ElfSpec spec = typical(false);
        spec.segs[3].type = 6;  // the bss segment becomes a PT_PHDR
        spec.segs[3].flags = 0x4;
        const Bytes file = make_elf(spec);
        const Elf e = parse_elf(file);
        EXPECT(e.algo == Algo::None);
        EXPECT(build_elf(e) == file);
    }
    // A paged segment: an entry for every page of it.
    {
        ElfSpec spec = typical(false);
        SegSpec paged;
        paged.flags = 0x01300005;  // AMSS, RO, paged
        paged.offset = 0x7000;
        paged.vaddr = 0x87000000;
        paged.data = pattern(0x3000, 41);
        spec.segs.push_back(paged);
        const Bytes file = make_elf(spec);
        const Elf e = parse_elf(file);
        EXPECT(e.algo == Algo::Sha256 && e.block.code.size() == (7 + 2) * 32);  // the paged segment has 3 entries instead of 1
        EXPECT(table_entries(e) == 9u);
        EXPECT(build_elf(e) == file);
        // The same segment with a size that is not made of whole pages: abr does not make that table.
        ElfSpec bad = spec;
        bad.segs.back().data = pattern(0x2F00, 41);
        const Elf f = parse_elf(make_elf(bad));
        EXPECT(f.algo == Algo::None);
        // A paged segment of a kind that is not hashed has zero entries, one per page.
        ElfSpec zero = spec;
        zero.segs.back().flags = 0x01700005;  // AMSS... NOTUSED (3 << 21), paged
        const Elf z = parse_elf(make_elf(zero));
        EXPECT(z.algo == Algo::Sha256 && z.block.code.size() == 9 * 32);
    }
    // A segment that is the hash segment's twin (segment type HASH) is never hashed, and only the first one is the hash segment.
    {
        ElfSpec spec = typical(false);
        spec.segs[2].flags = 0x02200000;  // a second hash segment's flags on the third data segment
        const Bytes file = make_elf(spec);
        const Elf e = parse_elf(file);
        EXPECT(e.hash_index == 1 && e.seg[4].role == Role::Plain && e.algo == Algo::Sha256);
        EXPECT(build_elf(e) == file);
    }
}

void test_elf_not_tidy() {
    const ElfSpec spec = typical(true);
    const Bytes tidy = make_elf(spec);

    // Section headers behind the last segment are outside the core; between the segments they are data in the gap.
    {
        Bytes file = tidy;
        put_at(file, 0x6000 - 0x100 + 0, 0xDEADBEEF, 4);  // not fill in a gap before the NOTUSED segment? (0x5700..0x6000 is a gap)
        const Elf e = parse_elf(file);
        EXPECT(!e.tidy && !e.skeleton.empty() && e.algo == Algo::Sha256);
        EXPECT(build_elf(e) == file);
        // The same size is fine, and the table follows an edit; another size is refused.
        Elf same = e;
        same.seg[2].data = pattern(spec.segs[0].data.size(), 55);
        const Bytes out = build_elf(same);
        EXPECT(out.size() == file.size() && parse_elf(out).algo == Algo::Sha256 && !parse_elf(out).tidy);
        EXPECT(out[0x6000 - 0x100] == 0xEF);  // the bytes between the segments are still there
        Elf longer = e;
        longer.seg[2].data.push_back(1);
        EXPECT(throws([&] { build_elf(longer); }));
        Elf cert = e;
        cert.block.cert.push_back(1);
        EXPECT(throws([&] { build_elf(cert); }));
        // elf_shell(): the same ELF from its skeleton.
        Elf shell = elf_shell(e.skeleton);
        EXPECT(!shell.tidy && shell.seg.size() == e.seg.size() && shell.hash_index == e.hash_index && shell.consumed == e.consumed);
        for (size_t i = 0; i < e.seg.size(); ++i) {
            EXPECT(shell.seg[i].role == e.seg[i].role && shell.seg[i].ph.offset == e.seg[i].ph.offset && shell.seg[i].ph.filesz == e.seg[i].ph.filesz);
            shell.seg[i].data = e.seg[i].data;
        }
        shell.block = e.block;
        shell.hash_pad = e.hash_pad;
        shell.algo = e.algo;
        EXPECT(build_elf(shell) == file);
    }
    // Two kinds of fill between the segments.
    {
        Bytes file = tidy;
        file[0x2800] = 0xFF;  // in the gap between the hash segment and the first segment
        const Elf e = parse_elf(file);
        EXPECT(!e.tidy);
        EXPECT(build_elf(e) == file);
    }
    // A section header table (e_shoff and e_shnum) in front of the data: not a layout abr makes.
    {
        Bytes file = tidy;
        put_at(file, 40, 0x2400, 8);  // e_shoff
        put_at(file, 60, 3, 2);       // e_shnum
        const Elf e = parse_elf(file);
        EXPECT(!e.tidy && build_elf(e) == file);
    }
    // e_phoff that is not the end of the ELF header (the table is further on, with the hole before it): kept.
    {
        const size_t phnum = 6;
        Bytes file = ehdr_bytes(true, phnum, 0x86000000, 0x100);
        file.resize(0x100, 0);
        const Bytes headers = tidy;  // the program headers of `tidy`, copied from its table
        file.insert(file.end(), headers.begin() + 64, headers.begin() + 64 + phnum * 56);
        file.resize(0x1000, 0);
        file.insert(file.end(), tidy.begin() + 0x1000, tidy.end());
        // The offsets are those of `tidy` (the table is only moved), and the hash of the headers is not the one in the table now: abr keeps it.
        const Elf e = parse_elf(file);
        EXPECT(!e.tidy && build_elf(e) == file);
    }
    // An ELF header that is not the standard one (OS/ABI byte): kept.
    {
        Bytes file = tidy;
        file[7] = 0x61;
        const Elf e = parse_elf(file);
        EXPECT(!e.tidy && build_elf(e) == file);
    }
    // The data of two segments that overlap, or one that overlaps the headers: not an image abr takes apart.
    {
        Bytes over = tidy;  // ELF64: the table is at 64, an entry is 56 bytes, p_offset is at +8
        put_at(over, 64 + 3 * 56 + 8, 0x3100, 8);  // the data segment's data begins inside the code segment's
        EXPECT(throws([&] { parse_elf(over); }));
        Bytes inside = tidy;
        put_at(inside, 64 + 2 * 56 + 8, 0x40, 8);  // the code segment's data begins inside the ELF header
        EXPECT(throws([&] { parse_elf(inside); }));
    }
}

void test_elf_not_images() {
    const Bytes tidy = make_elf(typical(false));
    // No hash segment: an ordinary ELF, a Sony boot image (flags of its own), a header with no segments.
    {
        Bytes plain = ehdr_bytes(false, 1, 0x8000);
        append(plain, phdr_bytes(false, 1, 5, 0x1000, 0x8000, 0x100, 0x100, 0x1000));
        plain.resize(0x1100, 0);
        EXPECT(!elf_looks_like(plain) && elf_problem(plain).empty());
        EXPECT(throws([&] { parse_elf(plain); }));
        Bytes sony = ehdr_bytes(false, 2, 0x8000);
        append(sony, phdr_bytes(false, 1, 0, 0x1000, 0x8000, 0x100, 0x100, 0x1000));
        append(sony, phdr_bytes(false, 1, 0x80000000, 0x1100, 0x9000, 0x100, 0x100, 0x1000));
        sony.resize(0x1200, 0);
        EXPECT(!elf_looks_like(sony));
        Bytes none = ehdr_bytes(false, 0, 0);
        none.resize(200, 0);
        EXPECT(!elf_looks_like(none));
    }
    // Not an ELF, big-endian, class that is neither.
    EXPECT(!elf_looks_like({}) && !elf_looks_like(Bytes(100, 0)) && !elf_looks_like(pattern(500, 3)));
    Bytes be = tidy;
    be[5] = 2;
    EXPECT(!elf_looks_like(be) && elf_problem(be).empty());
    Bytes cls = tidy;
    cls[4] = 3;
    EXPECT(!elf_looks_like(cls));
    // The hash segment that holds nothing like a header.
    {
        Bytes file = tidy;
        put_at(file, 0x1000 + 4, 9, 4);  // the version
        EXPECT(!elf_looks_like(file));
        EXPECT(elf_problem(file).find("MBN header") != std::string::npos);
        EXPECT(throws([&] { parse_elf(file); }));
    }
    // A segment outside the file: the .mdt of a split firmware keeps the headers and the hash segment, the data is in files of its own.
    {
        const Bytes mdt(tidy.begin(), tidy.begin() + 0x3000);
        EXPECT(!elf_looks_like(mdt));
        EXPECT(elf_problem(mdt).find(".mdt") != std::string::npos);
        EXPECT(throws([&] { parse_elf(mdt); }));
        const Bytes cut(tidy.begin(), tidy.begin() + 0x1010);
        EXPECT(!elf_looks_like(cut) && elf_problem(cut).find("hash segment") != std::string::npos);
    }
    // The hash segment holds an SBL header: not read in an ELF.
    {
        ElfSpec s = typical(false);
        Bytes file = make_elf(s);
        const Bytes sbl = make_block(secure_spec(0));
        std::copy(sbl.begin(), sbl.begin() + 80, file.begin() + 0x1000);
        EXPECT(!elf_looks_like(file));
    }
    // Every cut of an image: what is not an image is refused cleanly; what is one is built again.
    for (size_t n = 0; n < tidy.size(); n += (n < 0x1200 ? 1 : 0x77)) {
        const Bytes cut(tidy.begin(), tidy.begin() + static_cast<std::ptrdiff_t>(n));
        const bool like = elf_looks_like(cut);
        bool parsed = true;
        try {
            const Elf e = parse_elf(cut);
            (void)build_elf(e);
        } catch (const FormatError&) {
            parsed = false;
        }
        EXPECT(like == parsed);
    }
    EXPECT(elf_looks_like(tidy));
}

uint32_t next_random(uint32_t& state) {
    state = state * 1664525u + 1013904223u;
    return state >> 8;
}

// What parse_elf() accepts of a damaged image comes back to the same bytes (tidy or not), and whatever else it is refuses with a FormatError.
void test_elf_damaged() {
    uint32_t state = 12345;
    int accepted = 0, refused = 0;
    for (bool is64 : {false, true}) {
        const Bytes good = make_elf(typical(is64, is64 ? 6 : 3, is64 ? Algo::Sha384 : Algo::Sha256));
        for (int round = 0; round < 1500; ++round) {
            Bytes d = good;
            const int flips = 1 + static_cast<int>(next_random(state) % 3);
            for (int f = 0; f < flips; ++f) {
                // Most of the damage goes where the headers are: the ELF header, the program headers, the header of the hash segment.
                const size_t span = (next_random(state) % 4 == 0) ? d.size() : static_cast<size_t>(0x1000 + 40 + 64);
                const size_t at = next_random(state) % span;
                d[at] = static_cast<uint8_t>(next_random(state));
            }
            try {
                const Elf e = parse_elf(d);
                const Bytes back = build_elf(e);
                const Bytes core(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(e.consumed));
                ++g_checks;
                if (back != core) {
                    ++g_failures;
                    std::printf("  FAIL damaged image (round %d, %s) was accepted and not built back\n", round, is64 ? "ELF64" : "ELF32");
                }
                ++accepted;
            } catch (const FormatError&) {
                ++refused;
            } catch (const std::exception& ex) {
                ++g_checks;
                ++g_failures;
                std::printf("  FAIL damaged image (round %d): %s\n", round, ex.what());
            }
        }
    }
    EXPECT(accepted > 100 && refused > 100);  // both happen: the damage is not all in the data
}

}  // namespace

int run_mbn_tests() {
    test_names();
    test_blocks();
    test_block_problems();
    test_flat();
    test_chain();
    test_elf_basic();
    test_elf_edits();
    test_elf_tables();
    test_elf_not_tidy();
    test_elf_not_images();
    test_elf_damaged();
    if (g_failures == 0) std::printf("mbn: ok (%d checks)\n", g_checks);
    else std::printf("mbn: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
