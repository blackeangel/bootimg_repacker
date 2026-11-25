// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr::kallsyms (include/abr/kallsyms.hpp) and abr::kernelinfo (include/abr/kernelinfo.hpp): what abr learns from a kernel and writes to
// kernel_info/. Run by tests/run_tests.sh as `abr_unit_tests kinfo`.
//
//   * kallsyms: the table is written here again from scripts/kallsyms.c (the arrays, each one aligned; the names as tokens whose first is the type;
//     a marker for every 256th name; the 256 tokens with their index) -- for the three layouts that kernels have (absolute addresses, offsets from a
//     base, offsets with the per-CPU symbols absolute), both byte orders, 4 and 8 bytes for the pointers, for the number of symbols and for the markers,
//     names with one byte of length and with two (Linux 6.x), and the alignments 4, 8, 16 and 256 -- and find() has to give back every symbol, the
//     base, and the place of every array. What it must not find (zeros, random bytes, a table with a marker, an index or an order that is wrong, a
//     table that is cut) it does not find, and it never throws;
//   * kernelinfo: kernels are put together here from pieces that are written again from their formats (a banner and a vermagic, IKCFG_ST + gzip +
//     IKCFG_ED, a cpio archive written by hand, certificates in DER and in PEM built from the ASN.1 of RFC 5280, an ELF, a device tree, streams of
//     every codec) behind the headers of an arm64 Image, a zImage and a bzImage, and analyze() has to find every piece at its place, with what it says
//     about it, and nothing else (a stream that is cut or has a wrong checksum, a certificate that is not one, an archive that is not one);
//   * the files that write() makes, what is_ours() says, and that analyze() is the same on any number of threads and never throws, whatever the bytes.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "abr/asn1.hpp"
#include "abr/byte_io.hpp"
#include "abr/compression.hpp"
#include "abr/cpio.hpp"
#include "abr/kallsyms.hpp"
#include "abr/kernelinfo.hpp"
#include "abr/parallel.hpp"
#include "abr/sha.hpp"

using namespace abr;
namespace fs = std::filesystem;

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

// `msg` (a std::string or a text) says which case it was; it is only made when the check fails.
#define EXPECT_MSG(cond, msg)                                                                    \
    do {                                                                                         \
        ++g_checks;                                                                              \
        if (!(cond)) {                                                                           \
            ++g_failures;                                                                        \
            std::printf("  FAIL %s:%d: %s -- %s\n", __FILE__, __LINE__, #cond, std::string(msg).c_str()); \
        }                                                                                        \
    } while (0)

std::string hx(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

void put_int(Bytes& b, uint64_t v, unsigned width, bool be) {
    for (unsigned i = 0; i < width; ++i) b.push_back(static_cast<uint8_t>(v >> (be ? 8 * (width - 1 - i) : 8 * i)));
}

Bytes noise(std::mt19937_64& rng, size_t n) {
    Bytes b(n);
    for (uint8_t& c : b) c = static_cast<uint8_t>(rng());
    return b;
}

Bytes text_bytes(std::string_view s) { return Bytes(s.begin(), s.end()); }

void append(Bytes& to, const Bytes& from) { to.insert(to.end(), from.begin(), from.end()); }

// ---------------------------------------------------------------------------------------------------------- scripts/kallsyms.c, again --

struct Sym {
    uint64_t addr = 0;
    char type = 't';
    std::string name;
};

enum class Lay { Absolute, Relative, Percpu };

struct Spec {
    Lay layout = Lay::Relative;
    bool be = false;
    unsigned ptr = 8;      // the size of a pointer: an address (Absolute), kallsyms_relative_base (the others)
    unsigned count = 4;    // kallsyms_num_syms
    unsigned marker = 4;   // one number of kallsyms_markers
    bool long_names = false;
    unsigned align = 8;    // every array begins at a multiple of this
    unsigned pairs = 40;   // the most tokens that stand for two others
};

// What write_table() puts where (absolute: offsets into the image).
struct Placed {
    Bytes bytes;
    size_t at = 0;
    size_t addresses_at = 0, relative_base_at = 0, count_at = 0, names_at = 0, names_end = 0, markers_at = 0, token_table_at = 0, token_table_end = 0,
           token_index_at = 0;
    uint64_t relative_base = 0;
};

struct Tokens {
    std::vector<Bytes> names;            // every symbol as the tokens it is written in
    std::array<std::string, 256> table;  // what each token stands for; empty for one that is not used
};

// optimize_result(): the bytes that the names use stand for themselves; the other bytes, from 255 down, for the pair of tokens that is the most often
// together (the names are written again with the pair as one token, and the next round counts the new tokens too).
Tokens compress_names(const std::vector<Sym>& syms, unsigned pairs) {
    Tokens t;
    std::array<bool, 256> taken{};
    for (const Sym& s : syms) {
        Bytes seq;
        seq.push_back(static_cast<uint8_t>(s.type));
        for (const char c : s.name) seq.push_back(static_cast<uint8_t>(c));
        for (const uint8_t c : seq) taken[c] = true;
        t.names.push_back(std::move(seq));
    }
    for (unsigned c = 0; c < 256; ++c)
        if (taken[c]) t.table[c] = std::string(1, static_cast<char>(c));
    int slot = 255;
    for (unsigned k = 0; k < pairs; ++k) {
        while (slot >= 0 && taken[static_cast<size_t>(slot)]) --slot;
        if (slot < 0) break;
        std::map<unsigned, size_t> count;
        for (const Bytes& n : t.names)
            for (size_t i = 0; i + 1 < n.size(); ++i) ++count[static_cast<unsigned>(n[i]) << 8 | n[i + 1]];
        unsigned best = 0;
        size_t best_count = 0;
        for (const auto& [pair, c] : count)
            if (c > best_count) best = pair, best_count = c;
        if (best_count < 3) break;
        const auto a = static_cast<uint8_t>(best >> 8), b = static_cast<uint8_t>(best & 0xff);
        for (Bytes& n : t.names) {
            Bytes out;
            for (size_t i = 0; i < n.size(); ++i) {
                if (i + 1 < n.size() && n[i] == a && n[i + 1] == b) {
                    out.push_back(static_cast<uint8_t>(slot));
                    ++i;
                } else {
                    out.push_back(n[i]);
                }
            }
            n = std::move(out);
        }
        t.table[static_cast<size_t>(slot)] = t.table[a] + t.table[b];
        taken[static_cast<size_t>(slot)] = true;
    }
    return t;
}

// write_src(): the arrays one after the other, each one at the alignment (output_label() has `.balign` before the label). `at` is where in the image
// the first byte goes: the alignment is the image's, not the table's.
Placed write_table(const std::vector<Sym>& syms, const Spec& s, size_t at) {
    Placed p;
    p.at = at;
    Bytes& o = p.bytes;
    const auto here = [&] { return at + o.size(); };
    const auto align = [&] {
        while (here() % s.align != 0) o.push_back(0);
    };
    const Tokens t = compress_names(syms, s.pairs);

    uint64_t base = 0;
    if (s.layout != Lay::Absolute) {
        base = ~uint64_t{0};
        for (const Sym& y : syms)
            if (y.type != 'A') base = std::min(base, y.addr);  // the first that is not absolute: the table is in the order of the addresses
    }
    p.relative_base = base;

    align();
    p.addresses_at = here();
    for (const Sym& y : syms) {
        switch (s.layout) {
            case Lay::Absolute: put_int(o, y.addr, s.ptr, s.be); break;
            case Lay::Relative: put_int(o, y.addr - base, 4, s.be); break;
            case Lay::Percpu: put_int(o, y.type == 'A' ? y.addr : base - y.addr - 1, 4, s.be); break;  // the low 32 bits of a negative number
        }
    }
    if (s.layout != Lay::Absolute) {
        align();
        p.relative_base_at = here();
        put_int(o, base, s.ptr, s.be);
    }
    align();
    p.count_at = here();
    put_int(o, syms.size(), s.count, s.be);

    align();
    p.names_at = here();
    std::vector<uint64_t> markers;
    uint64_t off = 0;
    for (size_t i = 0; i < t.names.size(); ++i) {
        if (i % 256 == 0) markers.push_back(off);
        const Bytes& n = t.names[i];
        if (s.long_names && n.size() > 0x7f) {  // ULEB128 of up to two bytes
            o.push_back(static_cast<uint8_t>((n.size() & 0x7f) | 0x80));
            o.push_back(static_cast<uint8_t>((n.size() >> 7) & 0x7f));
            off += 2;
        } else {
            o.push_back(static_cast<uint8_t>(n.size()));
            off += 1;
        }
        append(o, n);
        off += n.size();
    }
    p.names_end = here();

    align();
    p.markers_at = here();
    for (const uint64_t m : markers) put_int(o, m, s.marker, s.be);

    align();
    p.token_table_at = here();
    std::vector<uint16_t> index;
    uint16_t pos = 0;
    for (unsigned i = 0; i < 256; ++i) {
        index.push_back(pos);
        o.insert(o.end(), t.table[i].begin(), t.table[i].end());
        o.push_back(0);
        pos = static_cast<uint16_t>(pos + t.table[i].size() + 1);
    }
    p.token_table_end = here();

    align();
    p.token_index_at = here();
    for (const uint16_t v : index) put_int(o, v, 2, s.be);
    return p;
}

// Symbols of a kernel's kind, in the order of their addresses: the type letters nm writes, names made of the words of a kernel (so that there are pairs
// to make tokens of), the ten digits somewhere (the table is found by its tokens of 0 to 9, which a kernel always uses), and for Linux 6.x a few names
// that are longer than 127 tokens.
std::vector<Sym> make_symbols(std::mt19937_64& rng, size_t n, const Spec& s) {
    static const char* const words[] = {"sys",   "read",    "write",  "open",  "close", "init",  "exit",  "probe", "remove", "show",  "store", "handler", "alloc", "free",
                                        "irq",   "dma",     "clk",    "reg",   "pm",    "suspend", "resume", "tty",  "net",    "dev",   "ioctl", "kmem",    "cache", "lock",
                                        "mutex", "timer",   "work",   "queue", "thread", "sched", "vm",     "page", "mmap",   "file",  "inode", "dentry",  "buf",   "msg"};
    const auto word = [&] { return std::string(words[rng() % (sizeof words / sizeof *words)]); };
    std::vector<Sym> v;
    uint64_t addr = s.layout == Lay::Percpu ? 0xffffffff81000000ull : s.ptr == 8 ? (s.layout == Lay::Absolute ? 0xffffffc000080000ull : 0xffffff8008080000ull) : 0xc0008000ull;
    if (s.layout == Lay::Percpu) {  // the per-CPU symbols come first: their addresses are small
        uint64_t a = 0;
        for (size_t i = 0; i < n / 10; ++i) {
            v.push_back({a, 'A', "percpu_" + word() + "_" + std::to_string(i)});
            a += 8 * (1 + rng() % 64);
        }
    }
    v.push_back({addr, 'T', "_text"});
    v.push_back({addr + 4, 't', "digits_0123456789"});
    addr += 8;
    static const char types[] = "TtDdRrBbWw";
    while (v.size() < n) {
        addr += 4 * (1 + rng() % 100);
        std::string name = (rng() % 4 == 0 ? "__" : "") + word() + "_" + word();
        if (rng() % 2) name += "_" + word();
        if (rng() % 5 == 0) name += "." + std::string(rng() % 2 ? "constprop." : "isra.") + std::to_string(rng() % 20);
        if (rng() % 7 == 0) name += "_" + std::to_string(rng() % 100000);
        v.push_back({addr, types[rng() % (sizeof types - 1)], std::move(name)});
    }
    if (s.long_names) {
        for (const size_t i : {n / 3, n / 2, 2 * n / 3}) {
            std::string name = "long_";
            const size_t len = 200 + rng() % 400;
            while (name.size() < len) name.push_back(static_cast<char>('a' + rng() % 26));
            v[i].name = std::move(name);
        }
    }
    return v;
}

// The bytes around a table: what the kernel has before and after it (noise).
Bytes image_of(const Placed& p, std::mt19937_64& rng) {
    Bytes img = noise(rng, p.at);
    append(img, p.bytes);
    append(img, noise(rng, 1000 + rng() % 3000));
    return img;
}

std::string label(const Spec& s, size_t n) {
    static const char* const lay[] = {"absolute", "relative", "percpu"};
    return std::string(lay[static_cast<int>(s.layout)]) + (s.be ? " BE" : " LE") + " ptr" + std::to_string(s.ptr) + " count" + std::to_string(s.count) + " marker" +
           std::to_string(s.marker) + (s.long_names ? " long" : "") + " align" + std::to_string(s.align) + " pairs" + std::to_string(s.pairs) + " n=" + std::to_string(n);
}

std::string expected_listing(const std::vector<Sym>& syms, unsigned address_size) {
    std::string out;
    char b[32];
    for (const Sym& y : syms) {
        std::snprintf(b, sizeof b, address_size == 8 ? "%016llx " : "%08llx ", static_cast<unsigned long long>(y.addr));
        out += b;
        out += y.type;
        out += ' ';
        out += y.name;
        out += '\n';
    }
    return out;
}

// One table: written, put among noise, found. `exact_markers`: the places of the markers are not ambiguous (see test_kallsyms_matrix).
void check_table(const Spec& s, size_t n, uint64_t seed, bool exact_markers = true) {
    std::mt19937_64 rng(seed);
    const std::vector<Sym> syms = make_symbols(rng, n, s);
    const size_t at = 0x1000 * (1 + rng() % 3);  // a multiple of 4096: the alignments of the table hold in the image
    const Placed p = write_table(syms, s, at);
    const Bytes img = image_of(p, rng);
    const std::string what = label(s, n);

    const std::optional<kallsyms::Table> t = kallsyms::find(img);
    EXPECT_MSG(t.has_value(), what);
    if (!t) return;
    bool same = t->symbols.size() == syms.size();
    size_t bad = 0;
    for (size_t i = 0; same && i < syms.size(); ++i)
        if (t->symbols[i].address != syms[i].addr || t->symbols[i].type != syms[i].type || t->symbols[i].name != syms[i].name) same = false, bad = i;
    EXPECT_MSG(same, what + ": the first symbol that is not the same: " + std::to_string(bad) + " of " + std::to_string(t->symbols.size()));

    const kallsyms::Layout layout = s.layout == Lay::Absolute ? kallsyms::Layout::Absolute : s.layout == Lay::Relative ? kallsyms::Layout::Relative : kallsyms::Layout::RelativePercpu;
    EXPECT_MSG(t->layout == layout, what);
    EXPECT_MSG(t->big_endian == s.be, what);
    EXPECT_MSG(t->address_size == s.ptr, what + ": address_size " + std::to_string(t->address_size));
    EXPECT_MSG(t->long_names == s.long_names, what);
    EXPECT_MSG(t->relative_base == p.relative_base, what + ": base " + hx(t->relative_base) + " not " + hx(p.relative_base));
    EXPECT_MSG(t->addresses_at == p.addresses_at, what + ": addresses_at " + hx(t->addresses_at) + " not " + hx(p.addresses_at));
    if (s.layout != Lay::Absolute) EXPECT_MSG(t->relative_base_at == p.relative_base_at, what + ": relative_base_at " + hx(t->relative_base_at) + " not " + hx(p.relative_base_at));
    // the number of symbols is found as the 4 bytes that hold the value: the low ones, which are the later in a big-endian number of 8 bytes
    EXPECT_MSG(t->count_at == p.count_at + (s.be && s.count == 8 ? 4 : 0), what + ": count_at " + hx(t->count_at) + " not " + hx(p.count_at));
    EXPECT_MSG(t->names_at == p.names_at, what + ": names_at " + hx(t->names_at) + " not " + hx(p.names_at));
    EXPECT_MSG(t->names_end == p.names_end, what + ": names_end " + hx(t->names_end) + " not " + hx(p.names_end));
    if (exact_markers) {
        EXPECT_MSG(t->marker_size == s.marker, what + ": marker_size " + std::to_string(t->marker_size));
        EXPECT_MSG(t->markers_at == p.markers_at, what + ": markers_at " + hx(t->markers_at) + " not " + hx(p.markers_at));
    }
    EXPECT_MSG(t->token_table_at == p.token_table_at, what + ": token_table_at " + hx(t->token_table_at) + " not " + hx(p.token_table_at));
    EXPECT_MSG(t->token_table_end == p.token_table_end, what);
    EXPECT_MSG(t->token_index_at == p.token_index_at, what + ": token_index_at " + hx(t->token_index_at) + " not " + hx(p.token_index_at));
    EXPECT_MSG(kallsyms::format(*t) == expected_listing(syms, s.ptr), what + ": the listing");
}

// ------------------------------------------------------------------------------------------------------------------------ kallsyms --

void test_kallsyms_matrix() {
    uint64_t seed = 1000;
    struct Kind {
        Lay layout;
        unsigned ptr;
    };
    // the kernels there are: arm64 3.x (absolute, 8 bytes), arm64 4.x and later and arm 4.6 and later (offsets), x86-64 (offsets, per-CPU symbols absolute),
    // arm 3.x (absolute, 4 bytes) and mips/ppc/arm-be
    const Kind kinds[] = {{Lay::Absolute, 8}, {Lay::Absolute, 4}, {Lay::Relative, 8}, {Lay::Relative, 4}, {Lay::Percpu, 8}};
    size_t cases = 0;
    for (const Kind& k : kinds)
        for (const bool be : {false, true})
            for (const unsigned count : k.ptr == 8 ? std::vector<unsigned>{4, 8} : std::vector<unsigned>{4})
                for (const unsigned marker : k.ptr == 8 ? std::vector<unsigned>{4, 8} : std::vector<unsigned>{4})
                    for (const bool long_names : {false, true})
                        for (const unsigned align : k.ptr == 8 ? std::vector<unsigned>{8, 16, 256} : std::vector<unsigned>{4, 8, 16, 256}) {
                            Spec s;
                            s.layout = k.layout;
                            s.ptr = k.ptr;
                            s.be = be;
                            s.count = count;
                            s.marker = marker;
                            s.long_names = long_names;
                            s.align = align;
                            // 513 symbols and more: with 2 markers of 8 bytes the 4-byte reading of the same bytes is the same table (the symbols are
                            // the same, the markers begin 4 bytes later), which is no matter, and no reason to give up the check of the places
                            check_table(s, 600 + (seed % 5), ++seed);
                            ++cases;
                        }
    EXPECT(cases == 176);
}

void test_kallsyms_sizes() {
    uint64_t seed = 5000;
    for (const size_t n : {257u, 300u, 512u, 513u, 700u, 1000u, 4096u, 5000u, 12345u}) {
        Spec s;
        s.layout = Lay::Relative;
        check_table(s, n, ++seed, n > 512);
        s.be = true;
        s.layout = Lay::Absolute;
        check_table(s, n, ++seed, n > 512);
    }
    // the tokens: none that stand for two (every name as it is), the most the free bytes allow
    for (const unsigned pairs : {0u, 1u, 40u, 250u}) {
        Spec s;
        s.pairs = pairs;
        check_table(s, 1500, 6000 + pairs);
        s.layout = Lay::Percpu;
        check_table(s, 1500, 6100 + pairs);
    }
    // a table of 256 names or fewer has the one marker, 0, which is the padding too: it is not found, and what is found is never wrong
    for (const size_t n : {10u, 100u, 256u}) {
        std::mt19937_64 rng(7000 + n);
        Spec s;
        const std::vector<Sym> syms = make_symbols(rng, n, s);
        const Placed p = write_table(syms, s, 0x1000);
        const Bytes img = image_of(p, rng);
        const auto t = kallsyms::find(img);
        if (t) {
            bool same = t->symbols.size() == syms.size();
            for (size_t i = 0; same && i < syms.size(); ++i) same = t->symbols[i].address == syms[i].addr && t->symbols[i].name == syms[i].name;
            EXPECT_MSG(same, "a small table that is found is the one that was written, n=" + std::to_string(n));
        }
    }
}

// A table that has nothing but zeros in front of it (the padding of a kernel): addresses of 4 bytes are in order when they are read as numbers of 8
// bytes too (the first half of those numbers are zero, the others are pairs of the addresses), and the reading of 4 bytes is the one that is right. A
// table of 8-byte addresses is not in order when it is read as words of 4, so the narrow reading is tried first without a cost.
void test_kallsyms_zero_prefix() {
    uint64_t seed = 8000;
    for (const Lay layout : {Lay::Absolute, Lay::Relative})
        for (const unsigned ptr : {4u, 8u})
            for (const bool be : {false, true})
                for (const size_t n : {300u, 700u, 1500u}) {
                    Spec s;
                    s.layout = layout;
                    s.ptr = ptr;
                    s.be = be;
                    std::mt19937_64 rng(++seed);
                    const std::vector<Sym> syms = make_symbols(rng, n, s);
                    const Placed p = write_table(syms, s, 0x4000);
                    Bytes img(0x4000, 0);
                    append(img, p.bytes);
                    append(img, noise(rng, 1000 + rng() % 3000));
                    const std::string what = "zeros in front: " + label(s, n);
                    const std::optional<kallsyms::Table> t = kallsyms::find(img);
                    EXPECT_MSG(t.has_value(), what);
                    if (!t) continue;
                    EXPECT_MSG(t->address_size == ptr, what + ": address_size " + std::to_string(t->address_size));
                    EXPECT_MSG(t->addresses_at == p.addresses_at, what + ": addresses_at " + hx(t->addresses_at) + " not " + hx(p.addresses_at));
                    EXPECT_MSG(kallsyms::format(*t) == expected_listing(syms, ptr), what + ": the listing");
                }
}

void test_kallsyms_absent() {
    EXPECT(!kallsyms::find(nullptr, 0).has_value());
    EXPECT(!kallsyms::find(Bytes{}).has_value());
    EXPECT(!kallsyms::find(Bytes(100, 0)).has_value());
    EXPECT(!kallsyms::find(Bytes(1 << 20, 0)).has_value());
    EXPECT(!kallsyms::find(Bytes(1 << 20, 0xff)).has_value());
    std::mt19937_64 rng(31337);
    for (int i = 0; i < 20; ++i) EXPECT(!kallsyms::find(noise(rng, 100000 + rng() % 400000)).has_value());
    // the ten digits and the 256 strings of a token table, without the markers, the names and the numbers of a symbol table
    Bytes tokens;
    for (unsigned c = 0; c < 256; ++c) {
        if (c >= '0' && c <= '9') tokens.push_back(static_cast<uint8_t>(c));
        tokens.push_back(0);
    }
    Bytes img = noise(rng, 4000);
    append(img, tokens);
    append(img, noise(rng, 4000));
    EXPECT(!kallsyms::find(img).has_value());
}

// A table that is damaged in one place is not a table: the markers, the index and the order of the addresses are what proves one.
void test_kallsyms_damage() {
    for (const Lay layout : {Lay::Absolute, Lay::Relative, Lay::Percpu}) {
        std::mt19937_64 rng(900 + static_cast<unsigned>(layout));
        Spec s;
        s.layout = layout;
        const std::vector<Sym> syms = make_symbols(rng, 800, s);
        const Placed p = write_table(syms, s, 0x2000);
        const Bytes good = image_of(p, rng);
        const std::string what = label(s, 800);
        EXPECT_MSG(kallsyms::find(good).has_value(), what);

        for (size_t k = 0; k < 4; ++k) {  // each of the 4 markers
            Bytes m = good;
            m[p.markers_at + 4 * k] ^= 1;
            EXPECT_MSG(!kallsyms::find(m).has_value(), what + ": marker " + std::to_string(k) + " changed");
        }
        for (const size_t k : {0u, 1u, 100u, 255u}) {  // one number of the index
            Bytes m = good;
            m[p.token_index_at + 2 * k] ^= 0x10;
            EXPECT_MSG(!kallsyms::find(m).has_value(), what + ": token index " + std::to_string(k) + " changed");
        }
        {  // two addresses (or two offsets) the wrong way round
            Bytes m = good;
            const size_t w = layout == Lay::Absolute ? 8 : 4;
            for (size_t i = 0; i < w; ++i) std::swap(m[p.addresses_at + 300 * w + i], m[p.addresses_at + 301 * w + i]);
            EXPECT_MSG(!kallsyms::find(m).has_value(), what + ": two addresses swapped");
        }
        {  // the length of the first name is one less: every name behind it is out of its place, and the marker of the 257th is not where it says
            Bytes m = good;
            m[p.names_at] = static_cast<uint8_t>(m[p.names_at] - 1);
            EXPECT_MSG(!kallsyms::find(m).has_value(), what + ": a length changed");
        }
        // cut anywhere before the end of the index: no table (the index is the proof); with the whole index it is there
        for (const size_t cut : {p.names_end, p.markers_at, p.token_table_at, p.token_table_end, p.token_index_at, p.token_index_at + 100, p.token_index_at + 511}) {
            const Bytes m(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(cut));
            EXPECT_MSG(!kallsyms::find(m).has_value(), what + ": cut at " + hx(cut));
        }
        EXPECT_MSG(kallsyms::find(Bytes(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(p.token_index_at + 512))).has_value(), what + ": cut behind the index");

        // never throws, and what is found is a list of symbols
        for (int i = 0; i < 150; ++i) {
            Bytes m = good;
            const size_t pos = p.at + rng() % p.bytes.size();
            m[pos] = static_cast<uint8_t>(rng());
            if (i % 3 == 0) m.resize(p.at + rng() % (p.bytes.size() + 2000));
            try {
                const auto t = kallsyms::find(m);
                EXPECT(!t || !t->symbols.empty());
            } catch (...) {
                EXPECT_MSG(false, what + ": find() threw");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------- the pieces of a kernel --

std::string hex_of(const Bytes& b) {
    static const char d[] = "0123456789abcdef";
    std::string s;
    for (const uint8_t c : b) s += d[c >> 4], s += d[c & 15];
    return s;
}

void set_le(Bytes& b, size_t at, uint64_t v, unsigned width) {
    for (unsigned i = 0; i < width; ++i) b[at + i] = static_cast<uint8_t>(v >> (8 * i));
}

// Bytes that none of the pieces is found in: the values 0x80 to 0xfe (the magics that are looked for have 7f, 1f, 37, 28, 'B', 04, 4c, 5d, 0d, '0', 30 or
// '-' in them, and each begins with one of those or has one of them next to a byte that is in this range).
Bytes filler(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    Bytes b(n);
    for (uint8_t& c : b) c = static_cast<uint8_t>(0x80 + rng() % 0x7f);
    return b;
}

// A kernel, put together piece by piece: put() returns where a piece went.
struct Img {
    Bytes b;
    uint64_t seed = 1;
    size_t put(const Bytes& d, size_t align = 1) {
        while (b.size() % align != 0) b.push_back(0);
        const size_t at = b.size();
        append(b, d);
        return at;
    }
    size_t put(std::string_view s, size_t align = 1) { return put(text_bytes(s), align); }
    size_t cstr(std::string_view s) {  // a string between two NULs, as a kernel keeps its strings
        b.push_back(0);
        const size_t at = b.size();
        append(b, text_bytes(s));
        b.push_back(0);
        return at;
    }
    void fill(size_t n) { append(b, filler(n, ++seed)); }
};

Bytes arm64_header(uint64_t text_offset, uint64_t image_size, uint64_t flags, bool efi = false) {
    Bytes h(64, 0);
    if (efi) h[0] = 'M', h[1] = 'Z', h[2] = 0x40, h[3] = 0xfa;
    else h[0] = 0x10, h[3] = 0x14;  // b .+0x40
    set_le(h, 8, text_offset, 8);
    set_le(h, 0x10, image_size, 8);
    set_le(h, 0x18, flags, 8);
    std::memcpy(&h[0x38], "ARM\x64", 4);
    if (efi) h[0x3c] = 0x40;
    return h;
}

Bytes riscv_header(uint64_t image_size) {
    Bytes h(64, 0);
    h[0] = 'M', h[1] = 'Z';
    set_le(h, 8, 0x200000, 8);
    set_le(h, 0x10, image_size, 8);
    set_le(h, 0x20, 0x00020000, 4);  // version 2.0
    std::memcpy(&h[0x30], "RISCV\0\0\0", 8);
    std::memcpy(&h[0x38], "RSC\x05", 4);
    return h;
}

// The first 0x30 bytes of arch/arm/boot/zImage: `mov r0, r0`, the magic, the start and the end (the size, as the start is 0).
Bytes zimage_header(size_t total, bool be) {
    Bytes h(0x30, 0);
    for (size_t i = 0; i < 0x24; i += 4) set_le(h, i, 0xe1a00000, 4);
    const auto put32 = [&](size_t at, uint32_t v) {
        for (unsigned i = 0; i < 4; ++i) h[at + i] = static_cast<uint8_t>(v >> (be ? 8 * (3 - i) : 8 * i));
    };
    put32(0x24, 0x016f2818);
    put32(0x28, 0);
    put32(0x2c, static_cast<uint32_t>(total));
    return h;
}

// arch/x86/boot/bzImage: the boot sector and `setup_sects` sectors of setup code, the protected-mode code behind them (`off` bytes of it, then the
// payload: the compressed kernel).
Bytes bzimage(const Bytes& payload, unsigned setup_sects, uint32_t off, uint32_t declared_length) {
    Bytes img((setup_sects + 1) * 512, 0);
    img[0x1f1] = static_cast<uint8_t>(setup_sects);
    std::memcpy(&img[0x202], "HdrS", 4);
    set_le(img, 0x206, 0x020f, 2);
    set_le(img, 0x20e, 0x100, 2);  // the version string is at 0x200 + 0x100
    img[0x211] = 1;
    set_le(img, 0x214, 0x100000, 4);
    set_le(img, 0x230, 0x200000, 4);
    img[0x234] = 1;
    set_le(img, 0x236, 0x7f, 2);
    set_le(img, 0x238, 2047, 4);
    set_le(img, 0x248, off, 4);
    set_le(img, 0x24c, declared_length, 4);
    set_le(img, 0x258, 0x1000000, 8);
    set_le(img, 0x260, 0x1c3000, 4);
    set_le(img, 0x264, 0x190, 4);
    const std::string version = "5.4.125-test (builder@host) #1 SMP";
    std::memcpy(&img[0x300], version.c_str(), version.size() + 1);
    append(img, filler(off, 7));
    append(img, payload);
    append(img, filler(300, 9));
    return img;
}

// ------------------------------------------------------------------------------------------------ ASN.1 and PEM, as RFC 5280 has them --

Bytes tlv(uint8_t tag, const Bytes& content) {
    Bytes b{tag};
    const size_t n = content.size();
    if (n < 0x80) {
        b.push_back(static_cast<uint8_t>(n));
    } else if (n < 0x100) {
        b.push_back(0x81);
        b.push_back(static_cast<uint8_t>(n));
    } else {
        b.push_back(0x82);
        b.push_back(static_cast<uint8_t>(n >> 8));
        b.push_back(static_cast<uint8_t>(n));
    }
    append(b, content);
    return b;
}

Bytes seq(const std::vector<Bytes>& parts) {
    Bytes c;
    for (const Bytes& p : parts) append(c, p);
    return tlv(0x30, c);
}

Bytes oid_tlv(std::initializer_list<uint32_t> arcs) {
    Bytes c;
    auto it = arcs.begin();
    const uint32_t first = *it++, second = *it++;
    c.push_back(static_cast<uint8_t>(first * 40 + second));
    for (; it != arcs.end(); ++it) {
        uint32_t v = *it;
        Bytes t{static_cast<uint8_t>(v & 0x7f)};
        for (v >>= 7; v != 0; v >>= 7) t.push_back(static_cast<uint8_t>(0x80 | (v & 0x7f)));
        c.insert(c.end(), t.rbegin(), t.rend());
    }
    return tlv(0x06, c);
}

Bytes integer_tlv(Bytes magnitude) {  // an unsigned number: a leading zero keeps the sign bit clear
    while (magnitude.size() > 1 && magnitude[0] == 0) magnitude.erase(magnitude.begin());
    if (magnitude.empty() || (magnitude[0] & 0x80) != 0) magnitude.insert(magnitude.begin(), 0);
    return tlv(0x02, magnitude);
}

Bytes rdn(const Bytes& oid, uint8_t tag, std::string_view value) { return tlv(0x31, seq({oid, tlv(tag, text_bytes(value))})); }

// The name of the Android test keys: C=US, ST=California, L=Mountain View, O=Android, OU=Android, CN=<cn>, emailAddress=android@android.com
Bytes aosp_name(const std::string& cn) {
    return seq({rdn(oid_tlv({2, 5, 4, 6}), 0x13, "US"), rdn(oid_tlv({2, 5, 4, 8}), 0x13, "California"), rdn(oid_tlv({2, 5, 4, 7}), 0x13, "Mountain View"),
                rdn(oid_tlv({2, 5, 4, 10}), 0x13, "Android"), rdn(oid_tlv({2, 5, 4, 11}), 0x13, "Android"), rdn(oid_tlv({2, 5, 4, 3}), 0x13, cn),
                rdn(oid_tlv({1, 2, 840, 113549, 1, 9, 1}), 0x16, "android@android.com")});
}
std::string aosp_name_text(const std::string& cn) { return "C=US, ST=California, L=Mountain View, O=Android, OU=Android, CN=" + cn + ", emailAddress=android@android.com"; }

struct Cert {
    Bytes der;
    std::string subject, issuer, serial, not_before, not_after, algorithm, key;
};

// An RSA certificate with a modulus of `modulus_bytes` bytes (the top bit set), exponent 65537. `general_time`: GeneralizedTime (years 2050 and on),
// else UTCTime. `high_serial`: a serial number whose first byte has the high bit set (it is written with a zero in front). `mismatch`: the algorithm
// of the signature is not the same in the two places RFC 5280 names it.
Cert make_cert(const std::string& subject_cn, const std::string& issuer_cn, size_t modulus_bytes, uint64_t seed, bool general_time, bool high_serial,
               bool mismatch = false) {
    std::mt19937_64 rng(seed);
    Bytes n = noise(rng, modulus_bytes);
    n[0] |= 0x80;
    Bytes sig = noise(rng, modulus_bytes);
    Bytes serial = noise(rng, 8);
    serial[0] = high_serial ? static_cast<uint8_t>(serial[0] | 0x80) : static_cast<uint8_t>((serial[0] & 0x7f) | 1);
    const Bytes sha256_rsa = oid_tlv({1, 2, 840, 113549, 1, 1, 11}), sha1_rsa = oid_tlv({1, 2, 840, 113549, 1, 1, 5});
    const Bytes algid = seq({sha256_rsa, tlv(0x05, {})});
    const Bytes outer_algid = seq({mismatch ? sha1_rsa : sha256_rsa, tlv(0x05, {})});
    Bytes key_bits{0};
    append(key_bits, seq({integer_tlv(n), integer_tlv(Bytes{1, 0, 1})}));
    const Bytes spki = seq({seq({oid_tlv({1, 2, 840, 113549, 1, 1, 1}), tlv(0x05, {})}), tlv(0x03, key_bits)});
    const uint8_t time_tag = general_time ? 0x18 : 0x17;
    const Bytes validity = seq({tlv(time_tag, text_bytes(general_time ? "20500101000000Z" : "110101000000Z")),
                                tlv(time_tag, text_bytes(general_time ? "20990101120000Z" : "380101000000Z"))});
    const Bytes tbs = seq({tlv(0xa0, tlv(0x02, Bytes{2})), integer_tlv(serial), algid, aosp_name(issuer_cn), validity, aosp_name(subject_cn), spki});
    Bytes sig_bits{0};
    append(sig_bits, sig);
    Cert c;
    c.der = seq({tbs, outer_algid, tlv(0x03, sig_bits)});
    c.subject = aosp_name_text(subject_cn);
    c.issuer = aosp_name_text(issuer_cn);
    c.serial = hex_of(serial);
    c.not_before = general_time ? "2050-01-01 00:00:00 UTC" : "2011-01-01 00:00:00 UTC";
    c.not_after = general_time ? "2099-01-01 12:00:00 UTC" : "2038-01-01 00:00:00 UTC";
    c.algorithm = "sha256WithRSAEncryption";
    c.key = "RSA " + std::to_string(modulus_bytes * 8) + " bits, exponent 65537";
    return c;
}

std::string b64(const Bytes& d) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s;
    for (size_t i = 0; i < d.size(); i += 3) {
        const uint32_t v = static_cast<uint32_t>(d[i]) << 16 | (i + 1 < d.size() ? static_cast<uint32_t>(d[i + 1]) << 8 : 0) | (i + 2 < d.size() ? d[i + 2] : 0);
        s += t[(v >> 18) & 63];
        s += t[(v >> 12) & 63];
        s += i + 1 < d.size() ? t[(v >> 6) & 63] : '=';
        s += i + 2 < d.size() ? t[v & 63] : '=';
    }
    return s;
}

std::string pem_of(const std::string& label, const Bytes& der) {
    const std::string body = b64(der);
    std::string s = "-----BEGIN " + label + "-----\n";
    for (size_t i = 0; i < body.size(); i += 64) s += body.substr(i, 64) + "\n";
    return s + "-----END " + label + "-----";
}

// -------------------------------------------------------------------------------------------------------- cpio, ELF, FDT, written by hand --

struct CItem {
    std::string name;
    uint32_t mode = 0100644;
    Bytes data;
    uint32_t rdev_major = 0, rdev_minor = 0;
};

// The newc format: a 110-byte header of the magic and 13 fields of 8 hexadecimal digits, the name and its NUL, the data, each padded to 4 bytes.
Bytes newc_archive(const std::vector<CItem>& items, bool upper = false, bool crc = false) {
    Bytes out;
    uint32_t ino = 300000;
    const auto record = [&](const std::string& name, uint32_t mode, uint32_t nlink, const Bytes& data, uint32_t rmaj, uint32_t rmin, uint32_t inode) {
        uint32_t check = 0;
        if (crc && (mode & 0170000) == 0100000)
            for (const uint8_t c : data) check += c;
        char h[128];
        std::snprintf(h, sizeof h, upper ? "%s%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X" : "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
                      crc ? "070702" : "070701", inode, mode, 0u, 0u, nlink, 0u, static_cast<unsigned>(data.size()), 0u, 0u, rmaj, rmin,
                      static_cast<unsigned>(name.size() + 1), check);
        out.insert(out.end(), h, h + 110);
        append(out, text_bytes(name));
        out.push_back(0);
        while (out.size() % 4 != 0) out.push_back(0);
        append(out, data);
        while (out.size() % 4 != 0) out.push_back(0);
    };
    for (const CItem& i : items) record(i.name, i.mode, (i.mode & 0170000) == 040000 ? 2 : 1, i.data, i.rdev_major, i.rdev_minor, ino++);
    record("TRAILER!!!", 0, 1, {}, 0, 0, 0);
    return out;
}

std::vector<CItem> sample_items() {
    std::string text;
    for (int i = 0; i < 300; ++i) text += "line " + std::to_string(i) + " of the file\n";
    return {{"dev", 040755, {}},
            {"dev/console", 020600, {}, 5, 1},
            {"etc", 040755, {}},
            {"etc/hostname", 0100644, text_bytes("abr\n")},
            {"init", 0100755, text_bytes("#!/bin/sh\necho hello\n")},
            {"sbin", 040755, {}},
            {"sbin/sh", 0120777, text_bytes("../init")},
            {"usr", 040755, {}},
            {"usr/data.txt", 0100644, text_bytes(text)}};
}
constexpr size_t kSampleEntries = 9;

// An ELF64 little-endian file with one PT_LOAD of `body` bytes behind the headers (120 bytes). `vdso`: the body has the names the vDSO exports.
Bytes elf64(size_t body, bool vdso, uint16_t type = 3) {
    Bytes e(120, 0);
    std::memcpy(e.data(), "\x7f" "ELF", 4);
    e[4] = 2, e[5] = 1, e[6] = 1;
    set_le(e, 16, type, 2);
    set_le(e, 18, 183, 2);
    set_le(e, 20, 1, 4);
    set_le(e, 24, 0x1000, 8);
    set_le(e, 32, 64, 8);  // e_phoff
    set_le(e, 52, 64, 2);
    set_le(e, 54, 56, 2);
    set_le(e, 56, 1, 2);
    set_le(e, 58, 64, 2);
    set_le(e, 64, 1, 4);  // PT_LOAD
    set_le(e, 68, 5, 4);
    set_le(e, 72, 120, 8);  // p_offset
    set_le(e, 96, body, 8);  // p_filesz
    set_le(e, 104, body, 8);
    Bytes data = filler(body, 31);
    if (vdso) {
        const std::string names("LINUX_2.6\0__kernel_rt_sigreturn\0__kernel_gettimeofday\0", 51);
        std::memcpy(data.data() + 16, names.data(), names.size());
    }
    append(e, data);
    return e;
}

// An ELF32 big-endian executable for MIPS with one segment of `body` bytes behind the headers (84 bytes).
Bytes elf32_be(size_t body) {
    Bytes e(84, 0);
    std::memcpy(e.data(), "\x7f" "ELF", 4);
    e[4] = 1, e[5] = 2, e[6] = 1;
    const auto put = [&](size_t at, uint32_t v, unsigned w) {
        for (unsigned i = 0; i < w; ++i) e[at + i] = static_cast<uint8_t>(v >> (8 * (w - 1 - i)));
    };
    put(16, 2, 2);
    put(18, 8, 2);
    put(20, 1, 4);
    put(24, 0x80100000, 4);
    put(28, 52, 4);  // e_phoff
    put(40, 52, 2);
    put(42, 32, 2);
    put(44, 1, 2);
    put(46, 40, 2);
    put(52, 1, 4);   // PT_LOAD
    put(56, 84, 4);  // p_offset
    put(68, static_cast<uint32_t>(body), 4);  // p_filesz
    put(72, static_cast<uint32_t>(body), 4);
    append(e, filler(body, 32));
    return e;
}

// A flattened device tree (version 17): the root with `model` and `compatible`, and a node `chosen` with `bootargs`.
Bytes dtb_of(const std::string& model) {
    const std::string strings("model\0compatible\0bootargs\0", 26);
    Bytes st;
    const auto be32 = [&](uint32_t v) { put_int(st, v, 4, true); };
    const auto pad = [&] {
        while (st.size() % 4 != 0) st.push_back(0);
    };
    const auto prop = [&](uint32_t name_off, const std::string& value) {
        be32(3);
        be32(static_cast<uint32_t>(value.size() + 1));
        be32(name_off);
        append(st, text_bytes(value));
        st.push_back(0);
        pad();
    };
    be32(1);  // FDT_BEGIN_NODE, the root: an empty name
    st.push_back(0);
    pad();
    prop(0, model);
    prop(6, "vendor,test");
    be32(1);
    append(st, text_bytes("chosen"));
    st.push_back(0);
    pad();
    prop(17, "console=ttyS0");
    be32(2);  // FDT_END_NODE
    be32(2);
    be32(9);  // FDT_END
    const uint32_t off_struct = 56, off_strings = static_cast<uint32_t>(56 + st.size());
    size_t total = off_strings + strings.size();
    total += (4 - total % 4) % 4;
    Bytes b;
    for (const uint32_t v : {0xd00dfeedu, static_cast<uint32_t>(total), off_struct, off_strings, 40u, 17u, 16u, 0u, static_cast<uint32_t>(strings.size()), static_cast<uint32_t>(st.size())})
        put_int(b, v, 4, true);
    b.resize(56, 0);  // the memory reservation map: its end (two zero words) is at 40
    append(b, st);
    append(b, text_bytes(strings));
    b.resize(total, 0);
    return b;
}

// ----------------------------------------------------------------------------------------------------------------- the headers --

std::string field(const kernelinfo::Report& r, const std::string& name) {
    for (const kernelinfo::Field& f : r.header)
        if (f.name == name) return f.value;
    return "<missing>";
}

void test_headers() {
    using kernelinfo::Kind;
    {  // arm64: the fields, and the tail behind image_size
        Img k;
        k.put(arm64_header(0x80000, 0x2000, 0xa));
        k.fill(0x2000 - 64 + 300);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        EXPECT(r.kind == Kind::Arm64Image);
        EXPECT(std::string(kernelinfo::kind_name(r.kind)) == "arm64 Image");
        EXPECT(r.size == k.b.size());
        EXPECT(field(r, "text_offset") == "0x80000");
        EXPECT(field(r, "image_size") == "0x2000 (8192 bytes)");
        EXPECT(field(r, "flags") == "0xa: little endian, 4 KiB pages, placed anywhere in memory");
        EXPECT(field(r, "efi_stub") == "<missing>");
        EXPECT(r.tail && r.tail->offset == 0x2000 && r.tail->size == 300);
    }
    for (const auto& [flags, text] : std::vector<std::pair<uint64_t, std::string>>{
             {0x3, "big endian, 4 KiB pages, placed as near the start of memory as possible"},
             {0x4, "little endian, 16 KiB pages, placed as near the start of memory as possible"},
             {0x6, "little endian, 64 KiB pages, placed as near the start of memory as possible"},
             {0x0, "little endian, page size not stated, placed as near the start of memory as possible"}}) {
        Img k;
        k.put(arm64_header(0x80000, 0, flags));
        k.fill(5000);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        EXPECT(field(r, "image_size") == "0 (not stated)");
        EXPECT_MSG(field(r, "flags") == hx(flags) + ": " + text, field(r, "flags"));
        EXPECT(!r.tail);
    }
    {  // arm64 with the EFI stub
        Img k;
        k.put(arm64_header(0, 0, 0xa, true));
        k.fill(5000);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        EXPECT(r.kind == Kind::Arm64Image);
        EXPECT(field(r, "efi_stub") == "yes: it is a PE/COFF file too, the PE header is at 0x40");
    }
    for (const bool be : {false, true}) {  // zImage
        Img z;
        z.put(zimage_header(0, be));
        z.fill(5000);
        for (unsigned i = 0; i < 4; ++i) z.b[0x2c + i] = static_cast<uint8_t>(z.b.size() >> (be ? 8 * (3 - i) : 8 * i));
        const size_t total = z.b.size();
        const kernelinfo::Report r = kernelinfo::analyze(z.b);
        EXPECT(r.kind == Kind::ArmZImage);
        EXPECT(field(r, "byte_order") == (be ? "big endian" : "little endian"));
        EXPECT(field(r, "start") == "0x0");
        EXPECT(field(r, "end") == hx(total) + " (the zImage is " + std::to_string(total) + " bytes)");
        EXPECT(!r.tail);
        z.put(Bytes(100, 0));
        const kernelinfo::Report t = kernelinfo::analyze(z.b);
        EXPECT(t.tail && t.tail->offset == total && t.tail->size == 100 && t.tail->what == "all zeros");
    }
    {  // bzImage
        const Bytes img = bzimage(filler(2000, 5), 4, 0x1000, 2000);
        const kernelinfo::Report r = kernelinfo::analyze(img);
        EXPECT(r.kind == Kind::X86BzImage);
        EXPECT(field(r, "boot_protocol") == "2.15");
        EXPECT(field(r, "setup_sects") == "4");
        EXPECT(field(r, "kernel_version") == "5.4.125-test (builder@host) #1 SMP");
        EXPECT(field(r, "loadflags") == "0x1");
        EXPECT(field(r, "code32_start") == "0x100000");
        EXPECT(field(r, "kernel_alignment") == "0x200000");
        EXPECT(field(r, "relocatable_kernel") == "yes");
        {  // the labels are in a column, and a label as long as the longest is still followed by a blank
            const std::string sum = kernelinfo::summary(r);
            EXPECT(sum.find("\n  kernel_alignment    0x200000\n") != std::string::npos);
            EXPECT(sum.find("\n  relocatable_kernel  yes\n") != std::string::npos);
            EXPECT(sum.find("\n  boot_protocol       2.15\n") != std::string::npos);
        }
        EXPECT(field(r, "xloadflags") == "0x7f");
        EXPECT(field(r, "cmdline_size") == "2047");
        EXPECT(field(r, "pref_address") == "0x1000000");
        EXPECT(field(r, "init_size") == "0x1c3000");
        EXPECT(field(r, "handover_offset") == "0x190");
        EXPECT(field(r, "payload_offset") == "0x1000 (from the protected-mode code)");
        EXPECT(field(r, "payload_length") == "0x7d0 (2000 bytes)");
        EXPECT(!r.payload);  // 2000 bytes of noise are no stream
    }
    {  // riscv
        Img k;
        k.put(riscv_header(0x4000));
        k.fill(0x4000 - 64);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        EXPECT(r.kind == Kind::RiscvImage);
        EXPECT(field(r, "text_offset") == "0x200000");
        EXPECT(field(r, "image_size") == "0x4000");
        EXPECT(field(r, "version") == "2.0");
        EXPECT(!r.tail);
    }
    {  // vmlinux
        const kernelinfo::Report r = kernelinfo::analyze(elf64(5000, false, 2));
        EXPECT(r.kind == Kind::Elf);
        EXPECT(field(r, "class") == "ELF 64-bit");
        EXPECT(field(r, "byte_order") == "little endian");
        EXPECT(field(r, "type") == "2");
        EXPECT(field(r, "machine") == "183");
        EXPECT(field(r, "entry") == "0x1000");
    }
    {  // no header
        Img k;
        k.fill(5000);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        EXPECT(r.kind == Kind::Unknown);
        EXPECT(r.header.empty() && !r.tail && !r.payload);
        EXPECT(std::string(kernelinfo::kind_name(r.kind)) == "kernel (no header that abr knows)");
    }
}

// ---------------------------------------------------------------------------------------------------------- the kernel in a zImage --

Bytes inner_kernel(const std::string& banner, bool with_header) {
    Img k;
    if (with_header) k.put(arm64_header(0x80000, 0, 0xa));
    k.fill(2000);
    k.put(banner + "\n", 8);
    k.b.push_back(0);
    k.fill(70000);
    return k.b;
}

void test_payloads() {
    const std::string banner = "Linux version 3.18.71-test (builder@host) (gcc version 4.9.x (GCC) ) #1 SMP PREEMPT Wed Dec 6 15:44:11 CST 2017";
    const Bytes inner = inner_kernel(banner, false);
    const Bytes inner_arm64 = inner_kernel(banner, true);
    const std::vector<Codec> codecs = {Codec::GZIP, Codec::XZ, Codec::LZMA, Codec::LZ4_LEGACY, Codec::LZ4, Codec::ZSTD, Codec::BZIP2, Codec::LZO};
    for (const Codec codec : codecs) {
        const std::string what = std::string(codec_name(codec));
        Bytes stream;
        try {
            stream = compress(codec, inner);
        } catch (const std::exception& e) {
            EXPECT_MSG(false, what + ": compress threw " + e.what());
            continue;
        }
        // arm zImage: the stub, then the stream somewhere in the first 128 KiB
        Img z;
        z.put(zimage_header(0, false));
        z.fill(0x400 - 0x30);
        const size_t at = z.put(stream, 4);
        z.fill(100);
        set_le(z.b, 0x2c, z.b.size(), 4);
        const kernelinfo::Report r = kernelinfo::analyze(z.b);
        EXPECT_MSG(r.kind == kernelinfo::Kind::ArmZImage, what);
        EXPECT_MSG(r.payload.has_value(), what + ": zImage");
        if (r.payload) {
            EXPECT_MSG(r.payload->codec == codec && r.payload->offset == at && r.payload->stored == stream.size(), what + ": zImage payload");
            EXPECT_MSG(r.payload->plain == inner, what + ": zImage payload bytes");
            EXPECT_MSG(r.banners.size() == 1 && r.banners[0].text == banner, what + ": banner of the payload");
            EXPECT_MSG(r.banners.size() == 1 && inner[r.banners[0].offset] == 'L', what + ": the offset of a banner is the payload's");
        }
        EXPECT_MSG(!r.tail, what);
        // x86 bzImage: the payload where the header says
        const Bytes bz = bzimage(stream, 4, 0x1000, static_cast<uint32_t>(stream.size()));
        const kernelinfo::Report b = kernelinfo::analyze(bz);
        EXPECT_MSG(b.kind == kernelinfo::Kind::X86BzImage, what);
        EXPECT_MSG(b.payload.has_value(), what + ": bzImage");
        if (b.payload) {
            EXPECT_MSG(b.payload->codec == codec && b.payload->offset == 5 * 512 + 0x1000 && b.payload->stored == stream.size(), what + ": bzImage payload");
            EXPECT_MSG(b.payload->plain == inner, what + ": bzImage payload bytes");
        }
    }
    {  // an Image inside says what it is
        const Bytes stream = compress(Codec::GZIP, inner_arm64);
        Img z;
        z.put(zimage_header(0, false));
        z.fill(0x200);
        z.put(stream, 4);
        z.fill(64);
        set_le(z.b, 0x2c, z.b.size(), 4);
        const kernelinfo::Report r = kernelinfo::analyze(z.b);
        EXPECT(r.payload && r.payload->plain == inner_arm64);
        EXPECT(field(r, "payload_kind") == "arm64 Image");
        EXPECT(field(r, "payload_kind") != field(kernelinfo::analyze(inner), "payload_kind"));
    }
    {  // what is not a kernel: a stream of less than 64 KiB; a payload that the header puts outside the file
        const Bytes small = compress(Codec::GZIP, filler(10000, 3));
        Img z;
        z.put(zimage_header(0, false));
        z.fill(0x200);
        z.put(small, 4);
        z.fill(64);
        set_le(z.b, 0x2c, z.b.size(), 4);
        EXPECT(!kernelinfo::analyze(z.b).payload);
        const Bytes stream = compress(Codec::GZIP, inner);
        EXPECT(!kernelinfo::analyze(bzimage(stream, 4, 0x1000, static_cast<uint32_t>(stream.size() + 100000))).payload);
        EXPECT(!kernelinfo::analyze(bzimage(small, 4, 0x1000, static_cast<uint32_t>(small.size()))).payload);
        Bytes cut = stream;
        cut.resize(cut.size() / 2);
        EXPECT(!kernelinfo::analyze(bzimage(cut, 4, 0x1000, static_cast<uint32_t>(cut.size()))).payload);
    }
}

// -------------------------------------------------------------------------------------------------------------------------- the tail --

void test_tail() {
    const std::string seandroid = "SEANDROIDENFORCE";
    Bytes zeros16(16, 0);
    std::vector<std::pair<Bytes, std::string>> tails;
    tails.push_back({Bytes(100, 0), "all zeros"});
    tails.push_back({Bytes(100, 0xff), "all 0xFF"});
    tails.push_back({text_bytes(seandroid), "the text SEANDROIDENFORCE (Samsung's mark of a kernel that enforces SELinux)"});
    {
        Bytes t = text_bytes(seandroid);
        append(t, zeros16);
        tails.push_back({t, "the text SEANDROIDENFORCE (Samsung's mark of a kernel that enforces SELinux) and more"});
    }
    tails.push_back({dtb_of("tail"), "a device tree"});
    tails.push_back({text_bytes("ANDROID!0123456789"), "an Android boot image"});
    tails.push_back({text_bytes(std::string("\x1f\x8b\x08\x00", 4) + "junk junk junk"), "a gzip stream"});
    tails.push_back({text_bytes(std::string("\xfd" "7zXZ\x00", 6) + "junk junk"), "an xz stream"});
    tails.push_back({text_bytes(std::string("\x28\xb5\x2f\xfd", 4) + "junk junk"), "a zstd frame"});
    tails.push_back({text_bytes(std::string("\x30\x82\x01\x02", 4) + "junk junk"), "DER data (a signature or a certificate)"});
    {
        const Bytes t = filler(40, 77);
        tails.push_back({t, "40 bytes of data, beginning " + hex_of(Bytes(t.begin(), t.begin() + 16))});
    }
    for (const auto& [tail, what] : tails) {
        Img k;
        k.put(arm64_header(0x80000, 0x3000, 0xa));
        k.fill(0x3000 - 64);
        k.put(tail);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        EXPECT_MSG(r.tail.has_value(), what);
        if (!r.tail) continue;
        EXPECT_MSG(r.tail->offset == 0x3000 && r.tail->size == tail.size(), what);
        EXPECT_MSG(r.tail->what == what, r.tail->what + " is not " + what);
    }
    {  // image_size that is more than the file, and the whole of it: no tail
        Img k;
        k.put(arm64_header(0x80000, 0x9000, 0xa));
        k.fill(0x3000 - 64);
        EXPECT(!kernelinfo::analyze(k.b).tail);
        Img j;
        j.put(arm64_header(0x80000, 0x3000, 0xa));
        j.fill(0x3000 - 64);
        EXPECT(!kernelinfo::analyze(j.b).tail);
    }
}

// ----------------------------------------------------------------------------------------------------- the banner and the other texts --

void test_text() {
    const std::string clang =
        "Android (6443078 based on r383902) clang version 11.0.1 (https://android.googlesource.com/toolchain/llvm-project b397f81060ce6d701042b782172ed13bee898b79), LLD "
        "11.0.1 (/buildbot/tmp/tmp6_m7QH b397f81060ce6d701042b782172ed13bee898b79)";
    const std::string b1 = "Linux version 5.4.125-perf+ (builder@host) (" + clang + ") #1 SMP PREEMPT Fri Aug 6 11:22:29 UTC 2021";
    const std::string b2 = "Linux version 5.4.125-perf+ (other@box) (clang version 12) #2 SMP Mon Sep 6 12:00:00 UTC 2021";
    const std::string vermagic = "5.4.125-perf+ SMP preempt mod_unload modversions aarch64";
    Img k;
    k.put(arm64_header(0x80000, 0, 0xa));
    k.fill(3000);
    const size_t at1 = k.put(b1 + "\n", 8);
    k.b.push_back(0);
    k.fill(400);
    k.cstr("Linux version %s (%s) (%s) %s\n");  // the format of the banner: no digit behind "version "
    k.cstr("Linux version 5");                   // too short for a banner
    const size_t at2 = k.put(b2 + "\n", 8);
    k.b.push_back(0);
    k.fill(300);
    k.put(b1 + "\n");  // the same text again: one banner
    k.b.push_back(0);
    k.fill(200);
    k.cstr(vermagic + "  ");  // the blanks at the end are not part of it
    k.cstr("GCC: (GNU) 4.9.x 20150123 (prerelease)");
    k.cstr("GCC: (Linaro GCC 4.9-2014.09) 4.9.2 20140904 (prerelease)");
    k.cstr("GCC: (GNU) 4.9.x 20150123 (prerelease)");
    k.cstr("xGCC: (is not a compiler string of its own)");
    k.cstr("console=ttyMSM0 androidboot.hardware=qcom androidboot.slot_suffix=_a androidboot.mode=\"x\" androidboot.");
    k.fill(300);
    const kernelinfo::Report r = kernelinfo::analyze(k.b);
    EXPECT(r.kind == kernelinfo::Kind::Arm64Image);
    EXPECT(r.banners.size() == 2);
    if (r.banners.size() == 2) {
        const kernelinfo::Banner& a = r.banners[0];
        EXPECT(a.offset == at1 && a.text == b1 && a.release == "5.4.125-perf+" && a.builder == "builder@host" && a.compiler == clang);
        EXPECT(a.build == "#1 SMP PREEMPT Fri Aug 6 11:22:29 UTC 2021");
        const kernelinfo::Banner& b = r.banners[1];
        EXPECT(b.offset == at2 && b.text == b2 && b.release == "5.4.125-perf+" && b.builder == "other@box" && b.compiler == "clang version 12");
        EXPECT(b.build == "#2 SMP Mon Sep 6 12:00:00 UTC 2021");
    }
    EXPECT_MSG(r.vermagic == vermagic, r.vermagic);
    EXPECT((r.compilers == std::vector<std::string>{"GCC: (GNU) 4.9.x 20150123 (prerelease)", "GCC: (Linaro GCC 4.9-2014.09) 4.9.2 20140904 (prerelease)"}));
    EXPECT((r.androidboot == std::vector<std::string>{"androidboot.hardware=qcom", "androidboot.mode=", "androidboot.slot_suffix=_a"}));
    EXPECT(!r.config && !r.kallsyms && r.initramfs.empty() && r.certificates.empty() && r.embedded.empty());

    {  // the vermagic is a string of its own: the release inside the banner, and a string that does not go on with the flags, are not it
        Img j;
        j.fill(100);
        j.put(b2 + "\n");
        j.b.push_back(0);
        j.cstr("5.4.125-perf+ is the release but these are no flags");
        j.cstr("5.4.125-perf+ mod_unloadx");
        const kernelinfo::Report t = kernelinfo::analyze(j.b);
        EXPECT_MSG(t.vermagic.empty(), t.vermagic);
        j.cstr("5.4.125-perf+ mod_unload");
        EXPECT(kernelinfo::analyze(j.b).vermagic == "5.4.125-perf+ mod_unload");
    }
    {  // an old banner: the compiler is "gcc version ... (GCC) " with a blank before the bracket
        Img j;
        j.fill(100);
        j.put("Linux version 3.10.49-g1234 (user@host) (gcc version 4.9.x 20150123 (prerelease) (GCC) ) #1 SMP PREEMPT Wed Dec 6 15:44:11 CST 2017\n");
        j.b.push_back(0);
        j.fill(100);
        const kernelinfo::Report t = kernelinfo::analyze(j.b);
        EXPECT(t.kind == kernelinfo::Kind::Unknown && t.banners.size() == 1);
        if (!t.banners.empty()) {
            EXPECT(t.banners[0].release == "3.10.49-g1234" && t.banners[0].builder == "user@host");
            EXPECT_MSG(t.banners[0].compiler == "gcc version 4.9.x 20150123 (prerelease) (GCC)", t.banners[0].compiler);
            EXPECT(t.banners[0].build == "#1 SMP PREEMPT Wed Dec 6 15:44:11 CST 2017");
        }
    }
    {  // a banner that is cut: what there is
        Img j;
        j.fill(100);
        j.put("Linux version 4.4.0-generic-extra\n");
        const kernelinfo::Report t = kernelinfo::analyze(j.b);
        EXPECT(t.banners.size() == 1);
        if (!t.banners.empty()) EXPECT(t.banners[0].release == "4.4.0-generic-extra" && t.banners[0].builder.empty() && t.banners[0].compiler.empty() && t.banners[0].build.empty());
        EXPECT(t.vermagic.empty());
        Img h;
        h.fill(100);
        h.put("Linux version 4.4.0 (a@b) (c) ");  // 30 bytes: nothing behind the compiler
        const kernelinfo::Report u = kernelinfo::analyze(h.b);
        EXPECT(u.banners.size() == 1 && u.banners[0].build.empty() && u.banners[0].compiler == "c");
    }
}

// ----------------------------------------------------------------------------------------------------------------------- IKCONFIG --

const char kConfig[] =
    "#\n# Automatically generated file; DO NOT EDIT.\n# Linux/arm64 5.4.125 Kernel Configuration\n#\n"
    "CONFIG_CC_IS_CLANG=y\nCONFIG_CLANG_VERSION=110001\nCONFIG_LOCALVERSION=\"-perf\"\nCONFIG_MODULES=y\nCONFIG_KALLSYMS=y\n"
    "# CONFIG_KASAN is not set\n# CONFIG_DEBUG_INFO is not set\nCONFIG_SND=m\nCONFIG_NR_CPUS=8\nCONFIG_CMDLINE=\"console=ttyMSM0\"\n"
    "CONFIG_ARM64_VA_BITS=39\n# a comment\n";

void test_config() {
    const std::string cfg = kConfig;
    const Bytes gz = compress(Codec::GZIP, text_bytes(cfg));
    Img k;
    k.put(arm64_header(0x80000, 0, 0xa));
    k.fill(2000);
    const size_t st = k.put("IKCFG_ST");
    k.put(gz);
    k.put("IKCFG_ED");
    k.fill(1000);
    const kernelinfo::Report r = kernelinfo::analyze(k.b);
    EXPECT(r.config.has_value());
    if (r.config) {
        const kernelinfo::Config& c = *r.config;
        EXPECT(c.offset == st + 8 && c.stored == gz.size() && c.text == cfg);
        EXPECT(c.yes == 3 && c.modules == 1 && c.no == 2 && c.value == 5);
        EXPECT(c.title == "# Linux/arm64 5.4.125 Kernel Configuration");
        const std::vector<std::pair<std::string, std::string>> want = {{"CONFIG_CC_IS_CLANG", "y"},           {"CONFIG_CLANG_VERSION", "110001"},
                                                                       {"CONFIG_LOCALVERSION", "\"-perf\""}, {"CONFIG_MODULES", "y"},
                                                                       {"CONFIG_KALLSYMS", "y"},             {"CONFIG_CMDLINE", "\"console=ttyMSM0\""},
                                                                       {"CONFIG_ARM64_VA_BITS", "39"}};
        EXPECT(c.notable.size() == want.size());
        for (size_t i = 0; i < want.size() && i < c.notable.size(); ++i) EXPECT(c.notable[i].name == want[i].first && c.notable[i].value == want[i].second);
    }
    EXPECT(r.embedded.empty());  // the stream of the configuration is the configuration, not a file of its own

    // what is not a configuration
    const Bytes no_config = compress(Codec::GZIP, text_bytes("this text has no options in it, and it is long enough to be a text\n"));
    Bytes bad_crc = gz;
    bad_crc[bad_crc.size() - 6] ^= 0x55;
    const std::vector<std::pair<Bytes, std::string>> bad = {{filler(500, 1), "not a stream"},
                                                            {no_config, "a stream with no options"},
                                                            {bad_crc, "a stream with a wrong checksum"},
                                                            {Bytes(gz.begin(), gz.begin() + static_cast<std::ptrdiff_t>(gz.size() / 2)), "a stream that is cut"}};
    for (const auto& [stream, what] : bad) {
        Img j;
        j.fill(500);
        j.put("IKCFG_ST");
        j.put(stream);
        const kernelinfo::Report t = kernelinfo::analyze(j.b);
        EXPECT_MSG(!t.config, what);
        EXPECT_MSG(t.embedded.empty(), what + ": embedded");
    }
    {  // a gzip stream that is not behind IKCFG_ST is a file in the kernel, not the configuration
        Img j;
        j.fill(500);
        j.put(gz);
        j.fill(100);
        const kernelinfo::Report t = kernelinfo::analyze(j.b);
        EXPECT(!t.config);
        EXPECT(t.embedded.size() == 1 && t.embedded[0].kind == "text");
    }
}

// ------------------------------------------------------------------------------------------------------------------------ initramfs --

void test_initramfs() {
    const Bytes ar = newc_archive(sample_items());
    EXPECT(ar.size() % 4 == 0);
    {  // linked in as it is
        Img k;
        k.put(arm64_header(0x80000, 0, 0xa));
        k.fill(4000);
        const size_t at = k.put(ar, 4);
        k.fill(2000);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        EXPECT(r.initramfs.size() == 1);
        if (!r.initramfs.empty()) {
            const kernelinfo::Initramfs& x = r.initramfs[0];
            EXPECT(x.offset == at && x.stored == ar.size() && x.codec == Codec::NONE && x.plain == ar && x.entries == kSampleEntries);
        }
        EXPECT(r.embedded.empty());
    }
    for (const Codec codec : {Codec::GZIP, Codec::XZ, Codec::LZMA, Codec::LZ4_LEGACY, Codec::LZ4, Codec::ZSTD, Codec::BZIP2, Codec::LZO}) {  // compressed
        const std::string what = std::string(codec_name(codec));
        const Bytes stream = compress(codec, ar);
        Img k;
        k.put(arm64_header(0x80000, 0, 0xa));
        k.fill(4000);
        const size_t at = k.put(stream, 4);
        k.fill(2000);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        EXPECT_MSG(r.initramfs.size() == 1, what);
        if (!r.initramfs.empty()) {
            const kernelinfo::Initramfs& x = r.initramfs[0];
            EXPECT_MSG(x.codec == codec && x.offset == at && x.stored == stream.size(), what + ": " + hx(x.offset) + " " + std::to_string(x.stored));
            EXPECT_MSG(x.plain == ar && x.entries == kSampleEntries, what + ": the archive");
        }
        EXPECT_MSG(r.embedded.empty(), what + ": embedded");
    }
    {  // upper-case digits (GNU cpio) and the crc magic
        for (const auto& [upper, crc] : std::vector<std::pair<bool, bool>>{{true, false}, {false, true}, {true, true}}) {
            const Bytes a = newc_archive(sample_items(), upper, crc);
            Img k;
            k.fill(3000);
            const size_t at = k.put(a, 4);
            k.fill(100);
            const kernelinfo::Report r = kernelinfo::analyze(k.b);
            EXPECT_MSG(r.initramfs.size() == 1 && r.initramfs[0].offset == at && r.initramfs[0].plain == a, std::string(upper ? "upper" : "lower") + (crc ? " crc" : " newc"));
        }
    }
    {  // two archives, one plain and one compressed, and what only looks like one; the order is that of the offsets
        const Bytes gz = compress(Codec::GZIP, newc_archive({{"only", 0100644, text_bytes("x")}}));
        Bytes cut = ar;
        cut.resize(ar.size() - 120);  // the trailer is gone
        Img k;
        k.fill(1000);
        const size_t first = k.put(gz, 4);
        k.fill(300);
        k.put(cut, 4);  // no trailer: not an archive
        k.fill(300);
        k.cstr("070701" + std::string(104, 'z'));  // the magic and nothing that is a header
        k.fill(300);
        const size_t second = k.put(ar, 4);
        k.fill(300);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        EXPECT_MSG(r.initramfs.size() == 2, std::to_string(r.initramfs.size()));
        if (r.initramfs.size() == 2) {
            EXPECT(r.initramfs[0].offset == first && r.initramfs[0].codec == Codec::GZIP && r.initramfs[0].entries == 1);
            EXPECT(r.initramfs[1].offset == second && r.initramfs[1].codec == Codec::NONE && r.initramfs[1].entries == kSampleEntries);
        }
    }
}

// ------------------------------------------------------------------------------------------------------------------- certificates --

void test_certificates() {
    const Cert c1 = make_cert("Android", "Android", 256, 11, false, false);
    const Cert c2 = make_cert("Dev Key", "Android Root", 64, 12, true, true);
    const Cert c3 = make_cert("a", "a", 20, 13, false, false);
    EXPECT(c1.der[1] == 0x82 && c2.der[1] == 0x82);
    EXPECT_MSG(c3.der[1] == 0x82 || c3.der[1] == 0x81, "the length form");
    const std::string pem_cert = pem_of("CERTIFICATE", c2.der);
    const Bytes key_der = filler(300, 55);
    const std::string pem_key = pem_of("RSA PRIVATE KEY", key_der);
    const Bytes pub_der = filler(100, 56);
    const std::string pem_pub = pem_of("PUBLIC KEY", pub_der);
    const Cert bad = make_cert("Mismatch", "Mismatch", 64, 14, false, false, true);

    Img k;
    k.put(arm64_header(0x80000, 0, 0xa));
    k.fill(1000);
    const size_t d1 = k.put(c1.der, 4);
    k.fill(200);
    const size_t d2 = k.put(c3.der, 1);
    k.fill(200);
    k.put(bad.der, 4);  // the algorithm is not the same in both places: not a certificate
    k.fill(200);
    const size_t p1 = k.cstr(pem_cert + "\n");
    const size_t p2 = k.cstr(pem_key + "\n");
    const size_t p3 = k.cstr(pem_pub + "\n");
    k.cstr("-----BEGIN CERTIFICATE-----\nMIIB\n");  // no end
    k.cstr("-----BEGIN CERTIFICATE-----\n\x01\x02\x03\n-----END CERTIFICATE-----");  // not text
    k.cstr("-----BEGIN " + std::string(80, 'X') + "-----\nAAAA\n-----END " + std::string(80, 'X') + "-----");  // a label that is no label
    {  // a SEQUENCE that has the look and not the structure
        Bytes junk = tlv(0x30, filler(300, 9));
        k.put(junk, 4);
    }
    k.fill(300);
    const kernelinfo::Report r = kernelinfo::analyze(k.b);
    EXPECT_MSG(r.certificates.size() == 5, std::to_string(r.certificates.size()));
    if (r.certificates.size() == 5) {
        const auto check = [&](const kernelinfo::Certificate& c, const Cert& want, size_t at, bool pem, const std::string& label) {
            EXPECT_MSG(c.offset == at && c.pem == pem && c.label == label, label + " at " + hx(c.offset));
            EXPECT_MSG(c.der == want.der, label + ": der");
            EXPECT_MSG(c.subject == want.subject && c.issuer == want.issuer, c.subject + " / " + c.issuer);
            EXPECT_MSG(c.serial == want.serial, c.serial + " is not " + want.serial);
            EXPECT_MSG(c.not_before == want.not_before && c.not_after == want.not_after, c.not_before + " - " + c.not_after);
            EXPECT_MSG(c.signature_algorithm == want.algorithm, c.signature_algorithm);
            EXPECT_MSG(c.public_key == want.key, c.public_key);
            EXPECT_MSG(c.sha256 == hex_of(hash::sha256(want.der)), "sha256");
        };
        check(r.certificates[0], c1, d1, false, "CERTIFICATE");
        EXPECT(r.certificates[0].size == c1.der.size() && !r.certificates[0].describe().empty());
        EXPECT(r.certificates[0].describe().find("(self-signed)") != std::string::npos);
        check(r.certificates[1], c3, d2, false, "CERTIFICATE");
        check(r.certificates[2], c2, p1, true, "CERTIFICATE");
        EXPECT(r.certificates[2].pem_text == pem_cert && r.certificates[2].size == pem_cert.size());
        EXPECT(r.certificates[2].describe().find("(self-signed)") == std::string::npos);
        const kernelinfo::Certificate& key = r.certificates[3];
        EXPECT(key.pem && key.label == "RSA PRIVATE KEY" && key.offset == p2 && key.der == key_der && key.pem_text == pem_key && key.subject.empty());
        EXPECT(key.describe().find("this is a private key") != std::string::npos);
        const kernelinfo::Certificate& pub = r.certificates[4];
        EXPECT(pub.pem && pub.label == "PUBLIC KEY" && pub.offset == p3 && pub.der == pub_der && pub.pem_text == pem_pub);
        EXPECT(pub.describe().find("private") == std::string::npos);
    }
    {  // nothing in the DER of a key or a signature is taken for a certificate
        Img j;
        j.fill(500);
        j.put(tlv(0x30, filler(500, 7)));
        j.put(seq({integer_tlv(filler(200, 8)), integer_tlv(Bytes{1, 0, 1})}));  // an RSA public key
        j.fill(500);
        EXPECT(kernelinfo::analyze(j.b).certificates.empty());
    }
}

// ----------------------------------------------------------------------------------------------------- files inside the kernel --

void test_embedded() {
    const Bytes elf1 = elf64(900, true), elf2 = elf32_be(500);
    const Bytes tree = dtb_of("Test Board");
    std::string text;
    for (int i = 0; i < 40; ++i) text += "a line of text number " + std::to_string(i) + "\n";
    std::mt19937_64 data_rng(5);
    const Bytes data = noise(data_rng, 3000);
    const Bytes gz_elf = compress(Codec::GZIP, elf2), xz_tree = compress(Codec::XZ, tree), zst_text = compress(Codec::ZSTD, text_bytes(text));
    const Bytes bz_data = compress(Codec::BZIP2, data), lz4_text = compress(Codec::LZ4, text_bytes(text));

    // what is not a file: an ELF whose program headers are outside the file, a tree that is a header and nothing else, streams that are cut or have a
    // wrong checksum
    Bytes elf_bad = elf1;
    set_le(elf_bad, 32, 0x100000, 8);
    Bytes tree_bad = tree;
    tree_bad[8] ^= 0xff;  // off_dt_struct
    Bytes gz_cut = compress(Codec::GZIP, text_bytes(text));
    gz_cut.resize(gz_cut.size() / 2);
    Bytes gz_crc = compress(Codec::GZIP, text_bytes(text));
    gz_crc[gz_crc.size() - 6] ^= 0x55;

    Img k;
    k.put(arm64_header(0x80000, 0, 0xa));
    k.fill(1000);
    const size_t e1 = k.put(elf1, 8);
    k.fill(100);
    const size_t e2 = k.put(elf2, 8);
    k.fill(100);
    const size_t t1 = k.put(tree, 8);
    k.fill(100);
    const size_t s1 = k.put(gz_elf, 4);
    k.fill(100);
    const size_t s2 = k.put(xz_tree, 4);
    k.fill(100);
    const size_t s3 = k.put(zst_text, 4);
    k.fill(100);
    const size_t s4 = k.put(bz_data, 4);
    k.fill(100);
    const size_t s5 = k.put(lz4_text, 4);
    k.fill(100);
    k.put(elf_bad, 8);
    k.fill(100);
    k.put(tree_bad, 8);
    k.fill(100);
    k.put(gz_cut, 4);
    k.fill(100);
    k.put(gz_crc, 4);
    k.fill(100);
    k.put(std::string("\xfd" "7zXZ\x00\x00\x04junk junk junk junk", 28));
    k.fill(500);
    const kernelinfo::Report r = kernelinfo::analyze(k.b);
    EXPECT_MSG(r.embedded.size() == 8, std::to_string(r.embedded.size()));
    if (r.embedded.size() != 8) return;
    const auto holds = [](const std::string& kind) {
        return kind == "elf" ? "an ELF file" : kind == "dtb" ? "a device tree" : kind == "text" ? "text" : "data";
    };
    const auto stream = [&](const kernelinfo::Embedded& e, Codec codec, size_t at, size_t stored, const std::string& kind, const Bytes& plain) {
        EXPECT_MSG(e.offset == at && e.stored == stored && e.codec == codec && e.kind == kind, kind + " at " + hx(e.offset));
        EXPECT_MSG(e.data == plain, kind + ": data");
        EXPECT_MSG(e.what == std::string(codec_name(codec)) + " stream of " + std::to_string(stored) + " bytes that holds " + holds(kind) + " (" + std::to_string(plain.size()) + " bytes)", e.what);
    };
    EXPECT(r.embedded[0].kind == "elf" && r.embedded[0].offset == e1 && r.embedded[0].stored == elf1.size() && r.embedded[0].data == elf1 && r.embedded[0].codec == Codec::NONE);
    EXPECT_MSG(r.embedded[0].what == "ELF 64-bit little endian shared object, AArch64, the vDSO", r.embedded[0].what);
    EXPECT(r.embedded[1].kind == "elf" && r.embedded[1].offset == e2 && r.embedded[1].stored == elf2.size() && r.embedded[1].data == elf2);
    EXPECT_MSG(r.embedded[1].what == "ELF 32-bit big endian executable, MIPS", r.embedded[1].what);
    EXPECT(r.embedded[2].kind == "dtb" && r.embedded[2].offset == t1 && r.embedded[2].stored == tree.size() && r.embedded[2].data == tree);
    EXPECT_MSG(r.embedded[2].what == "device tree, model \"Test Board\"", r.embedded[2].what);
    EXPECT_MSG(r.embedded[2].text.find("model = \"Test Board\";") != std::string::npos && r.embedded[2].text.find("/dts-v1/;") != std::string::npos, r.embedded[2].text);
    EXPECT(r.embedded[2].text.find("bootargs = \"console=ttyS0\";") != std::string::npos);
    stream(r.embedded[3], Codec::GZIP, s1, gz_elf.size(), "elf", elf2);
    stream(r.embedded[4], Codec::XZ, s2, xz_tree.size(), "dtb", tree);
    EXPECT(r.embedded[4].text.find("model = \"Test Board\";") != std::string::npos);
    stream(r.embedded[5], Codec::ZSTD, s3, zst_text.size(), "text", text_bytes(text));
    stream(r.embedded[6], Codec::BZIP2, s4, bz_data.size(), "data", data);
    stream(r.embedded[7], Codec::LZ4, s5, lz4_text.size(), "text", text_bytes(text));
    EXPECT(r.initramfs.empty() && !r.config);
}

// ------------------------------------------------------------------------------------------------------- a kernel with all of it, and its folder --

struct Full {
    Bytes bytes;
    Bytes archive, cfg_gz, elf, tree, gz_stream;
    std::string cfg, text, banner, pem_cert;
    Cert cert1, cert2;
    std::vector<Sym> syms;
    Placed table;
    size_t banner_at = 0, cfg_at = 0, cpio_at = 0, der_at = 0, pem_at = 0, elf_at = 0, tree_at = 0, gz_at = 0;
};

Full make_full() {
    Full f;
    f.cfg = kConfig;
    f.cfg_gz = compress(Codec::GZIP, text_bytes(f.cfg));
    f.archive = newc_archive(sample_items());
    f.cert1 = make_cert("Android", "Android", 256, 11, false, false);
    f.cert2 = make_cert("Dev Key", "Android Root", 64, 12, true, true);
    f.pem_cert = pem_of("CERTIFICATE", f.cert2.der);
    f.elf = elf64(600, true);
    f.tree = dtb_of("Test Board");
    for (int i = 0; i < 40; ++i) f.text += "a line of text number " + std::to_string(i) + "\n";
    f.gz_stream = compress(Codec::GZIP, text_bytes(f.text));
    f.banner = "Linux version 5.4.125-perf+ (builder@host) (clang version 11.0.1) #1 SMP PREEMPT Fri Aug 6 11:22:29 UTC 2021";
    Img k;
    k.put(arm64_header(0x80000, 0, 0xa));
    k.fill(3000);
    f.banner_at = k.put(f.banner + "\n", 8);
    k.b.push_back(0);
    k.cstr("5.4.125-perf+ SMP preempt mod_unload modversions aarch64");
    k.cstr("GCC: (GNU) 4.9.x 20150123 (prerelease)");
    k.cstr("androidboot.hardware=qcom androidboot.slot_suffix=_a");
    k.put("IKCFG_ST");
    f.cfg_at = k.put(f.cfg_gz);
    k.put("IKCFG_ED");
    k.fill(500);
    const Spec spec;  // what arm64 5.x has: offsets from a base
    std::mt19937_64 rng(77);
    f.syms = make_symbols(rng, 700, spec);
    const size_t at = k.put(Bytes{}, 4096);
    f.table = write_table(f.syms, spec, at);
    k.put(f.table.bytes);
    k.fill(1000);
    f.cpio_at = k.put(f.archive, 4);
    k.fill(500);
    f.der_at = k.put(f.cert1.der, 4);
    k.fill(200);
    f.pem_at = k.cstr(f.pem_cert + "\n");
    k.fill(300);
    f.elf_at = k.put(f.elf, 8);
    k.fill(100);
    f.tree_at = k.put(f.tree, 8);
    k.fill(100);
    f.gz_at = k.put(f.gz_stream, 4);
    k.fill(2000);
    f.bytes = k.b;
    return f;
}

struct TempDir {
    fs::path path;
    TempDir() {
        static int counter = 0;
        path = fs::temp_directory_path() / ("abr_kinfo_test_" + std::to_string(std::random_device{}()) + "_" + std::to_string(++counter));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

std::string str_of(const Bytes& b) { return std::string(b.begin(), b.end()); }
std::string slurp(const fs::path& p) { return str_of(read_file(p)); }
std::string hex_bare(size_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "%zx", v);
    return b;
}
std::string label_of(const std::string& name) {  // "release" as the summary writes it: 2 blanks in front, a column of 20
    std::string s = "  " + name;
    while (s.size() < 22) s += ' ';
    return s;
}

void test_full_and_write(const Full& f) {
    const kernelinfo::Report r = kernelinfo::analyze(f.bytes);
    EXPECT(r.kind == kernelinfo::Kind::Arm64Image);
    EXPECT(r.size == f.bytes.size());
    EXPECT(r.banners.size() == 1 && r.banners[0].offset == f.banner_at && r.banners[0].text == f.banner);
    EXPECT(r.vermagic == "5.4.125-perf+ SMP preempt mod_unload modversions aarch64");
    EXPECT(r.config && r.config->offset == f.cfg_at && r.config->text == f.cfg);
    EXPECT(r.kallsyms.has_value());
    if (r.kallsyms) {
        EXPECT(r.kallsyms->symbols.size() == 700);
        EXPECT(r.kallsyms->names_at == f.table.names_at && r.kallsyms->token_index_at == f.table.token_index_at && r.kallsyms->relative_base == f.table.relative_base);
        EXPECT(kallsyms::format(*r.kallsyms) == expected_listing(f.syms, 8));
    }
    EXPECT(r.initramfs.size() == 1 && r.initramfs[0].offset == f.cpio_at && r.initramfs[0].plain == f.archive);
    EXPECT(r.certificates.size() == 2);
    if (r.certificates.size() == 2) EXPECT(r.certificates[0].offset == f.der_at && !r.certificates[0].pem && r.certificates[1].offset == f.pem_at && r.certificates[1].pem);
    EXPECT(r.embedded.size() == 3);
    if (r.embedded.size() == 3) EXPECT(r.embedded[0].offset == f.elf_at && r.embedded[1].offset == f.tree_at && r.embedded[2].offset == f.gz_at && r.embedded[2].codec == Codec::GZIP);
    EXPECT(!r.tail && !r.payload);
    EXPECT_MSG(kernelinfo::one_line(r) == "Linux 5.4.125-perf+ (arm64 Image): config of 11 options, 700 symbols, 1 initramfs, 2 certificates, 3 embedded files", kernelinfo::one_line(r));

    // summary.txt: what it says, and in what order
    const std::string sum = kernelinfo::summary(r), readme = kernelinfo::readme();
    EXPECT(sum.substr(0, sum.find('\n')) == readme.substr(0, readme.find('\n')));
    const auto after = [&](const std::string& what, size_t from) {
        const size_t at = sum.find(what, from);
        EXPECT_MSG(at != std::string::npos, "summary: " + what);
        return at == std::string::npos ? from : at;
    };
    size_t at = after("(offsets are those of the kernel file)", 0);
    at = after("\nIMAGE\n", at);
    at = after(label_of("kind") + "arm64 Image, ", at);
    at = after(label_of("text_offset") + "0x80000\n", at);
    at = after("\nVERSION\n", at);
    at = after(label_of("release") + "5.4.125-perf+\n", at);
    at = after(label_of("built by") + "builder@host\n", at);
    at = after(label_of("compiler") + "clang version 11.0.1\n", at);
    at = after(label_of("vermagic") + "5.4.125-perf+ SMP preempt mod_unload modversions aarch64", at);
    at = after(label_of("banner") + "at " + hx(f.banner_at) + ": " + f.banner + "\n", at);
    at = after(label_of("androidboot"), at);
    at = after("\nCONFIGURATION (config)\n  # Linux/arm64 5.4.125 Kernel Configuration\n", at);
    at = after("11 options: 3 =y, 1 =m, 5 with a value, 2 not set\n", at);
    at = after("\nSYMBOLS (kallsyms.txt)\n  700 symbols; little endian, 64-bit addresses; offsets from the base " + hx(f.table.relative_base) + " (kallsyms_offsets)\n", at);
    at = after("\nINITRAMFS\n  at " + hx(f.cpio_at) + ": cpio archive, ", at);
    at = after(" 9 entries -> initramfs.cpio\n", at);
    at = after("\nCERTIFICATES AND KEYS (certs/)\n  at " + hx(f.der_at) + ": DER CERTIFICATE, " + std::to_string(f.cert1.der.size()) + " bytes -> certs/00-Android.der\n", at);
    at = after("      subject:    " + f.cert1.subject + "\n", at);
    at = after("  at " + hx(f.pem_at) + ": PEM CERTIFICATE, ", at);
    at = after(" bytes -> certs/01-Dev_Key.pem\n", at);
    at = after("\nFILES INSIDE THE KERNEL (binaries/)\n  at " + hx(f.elf_at) + ", ", at);
    at = after(": ELF 64-bit little endian shared object, AArch64, the vDSO -> binaries/00_elf_" + hex_bare(f.elf_at) + ".elf\n", at);
    at = after(" -> binaries/02_text_" + hex_bare(f.gz_at) + "_from_gzip.txt\n", at);
    EXPECT(sum.find("BEHIND THE END") == std::string::npos);

    // the folder
    TempDir tmp;
    const fs::path dir = tmp.path / "kernel_info";
    const std::vector<std::string> names = kernelinfo::write(r, dir);
    const std::string eoff = hex_bare(f.elf_at), toff = hex_bare(f.tree_at), goff = hex_bare(f.gz_at);
    const std::vector<std::string> want = {"README.txt",
                                           "summary.txt",
                                           "config",
                                           "kallsyms.txt",
                                           "initramfs.cpio",
                                           "initramfs/",
                                           "initramfs.meta",
                                           "certs/00-Android.der",
                                           "certs/00-Android.txt",
                                           "certs/01-Dev_Key.pem",
                                           "certs/01-Dev_Key.txt",
                                           "binaries/00_elf_" + eoff + ".elf",
                                           "binaries/01_dtb_" + toff + ".dtb",
                                           "binaries/01_dtb_" + toff + ".dts",
                                           "binaries/02_text_" + goff + "_from_gzip.txt"};
    EXPECT(names == want);
    for (const std::string& n : want) {
        const bool folder = n.back() == '/';
        EXPECT_MSG(folder ? fs::is_directory(dir / n.substr(0, n.size() - 1)) : fs::is_regular_file(dir / n), n);
    }
    EXPECT(slurp(dir / "README.txt") == readme);
    EXPECT(slurp(dir / "summary.txt") == sum);
    EXPECT(slurp(dir / "config") == f.cfg);
    EXPECT(slurp(dir / "kallsyms.txt") == expected_listing(f.syms, 8));
    EXPECT(read_file(dir / "initramfs.cpio") == f.archive);
    EXPECT(slurp(dir / "initramfs" / "init") == "#!/bin/sh\necho hello\n");
    EXPECT(slurp(dir / "initramfs" / "etc" / "hostname") == "abr\n");
    EXPECT(fs::is_regular_file(dir / "initramfs.meta"));
    EXPECT(read_file(dir / "certs" / "00-Android.der") == f.cert1.der);
    EXPECT(slurp(dir / "certs" / "01-Dev_Key.pem") == f.pem_cert + "\n");
    const std::string t0 = slurp(dir / "certs" / "00-Android.txt");
    EXPECT(t0.rfind("offset " + hx(f.der_at) + ", " + std::to_string(f.cert1.der.size()) + " bytes\n", 0) == 0);
    EXPECT(t0.find("subject:    " + f.cert1.subject + "\n") != std::string::npos && t0.find("(self-signed)") != std::string::npos);
    EXPECT(t0.find("sha256:     " + hex_of(hash::sha256(f.cert1.der)) + "\n") != std::string::npos);
    const std::string t1 = slurp(dir / "certs" / "01-Dev_Key.txt");
    EXPECT(t1.find("issuer:     " + f.cert2.issuer + "\n") != std::string::npos && t1.find("self-signed") == std::string::npos);
    EXPECT(read_file(dir / want[11]) == f.elf);
    EXPECT(read_file(dir / want[12]) == f.tree);
    EXPECT(slurp(dir / want[13]).find("model = \"Test Board\";") != std::string::npos);
    EXPECT(slurp(dir / want[14]) == f.text);

    // the folder is ours, and the names of the folders that are not are not taken
    EXPECT(kernelinfo::is_ours(dir));
    EXPECT(!kernelinfo::is_ours(tmp.path));
    EXPECT(!kernelinfo::is_ours(tmp.path / "missing"));
    fs::create_directories(tmp.path / "foreign");
    write_file(tmp.path / "foreign" / "README.txt", text_bytes("My own notes\nabout this folder\n"));
    EXPECT(!kernelinfo::is_ours(tmp.path / "foreign"));
    write_file(tmp.path / "foreign" / "README.txt", Bytes{});
    EXPECT(!kernelinfo::is_ours(tmp.path / "foreign"));
    write_file(tmp.path / "foreign" / "README.txt", text_bytes(readme));
    EXPECT(kernelinfo::is_ours(tmp.path / "foreign"));

    // written again over the same folder (what is in it stays, as the caller is the one who removes an earlier folder): nothing throws, and the files that
    // are written are the same; and into the folder once it is removed: the same list
    try {
        std::string joined;
        for (const std::string& n : kernelinfo::write(r, dir)) joined += n + " ";
        EXPECT_MSG(!joined.empty() && slurp(dir / "summary.txt") == sum && read_file(dir / "initramfs.cpio") == f.archive && slurp(dir / "initramfs" / "init") == "#!/bin/sh\necho hello\n", joined);
        fs::remove_all(dir);
        EXPECT(kernelinfo::write(r, dir) == want);
    } catch (const std::exception& e) {
        EXPECT_MSG(false, std::string("the second write threw: ") + e.what());
    }
}

void test_write_small() {
    {  // a kernel with nothing in it: the two texts
        Img k;
        k.fill(5000);
        const kernelinfo::Report r = kernelinfo::analyze(k.b);
        TempDir tmp;
        const std::vector<std::string> names = kernelinfo::write(r, tmp.path / "kernel_info");
        EXPECT((names == std::vector<std::string>{"README.txt", "summary.txt"}));
        const std::string sum = kernelinfo::summary(r);
        EXPECT(sum.find("no \"Linux version\" banner found") != std::string::npos);
        EXPECT(sum.find("none found: no \"IKCFG_ST\" and gzip stream") != std::string::npos);
        EXPECT(sum.find("none found: no symbol table") != std::string::npos);
        EXPECT(sum.find("\nINITRAMFS\n  none found\n") != std::string::npos);
        EXPECT(sum.find("\nCERTIFICATES AND KEYS (certs/)\n  none found\n") != std::string::npos);
        EXPECT(sum.find("\nFILES INSIDE THE KERNEL (binaries/)\n  none found\n") != std::string::npos);
        EXPECT(kernelinfo::one_line(r) == "kernel (no header that abr knows)");
    }
    {  // a zImage: the kernel inside is payload.bin, and the offsets are its
        const Bytes inner = inner_kernel("Linux version 3.18.71-test (builder@host) (gcc version 4.9.x (GCC) ) #1 SMP PREEMPT Wed Dec 6 15:44:11 CST 2017", false);
        const Bytes stream = compress(Codec::GZIP, inner);
        Img z;
        z.put(zimage_header(0, false));
        z.fill(0x400 - 0x30);
        const size_t at = z.put(stream, 4);
        z.fill(100);
        set_le(z.b, 0x2c, z.b.size(), 4);
        const kernelinfo::Report r = kernelinfo::analyze(z.b);
        TempDir tmp;
        const std::vector<std::string> names = kernelinfo::write(r, tmp.path / "kernel_info");
        EXPECT((names == std::vector<std::string>{"README.txt", "summary.txt", "payload.bin"}));
        EXPECT(read_file(tmp.path / "kernel_info" / "payload.bin") == inner);
        const std::string sum = kernelinfo::summary(r);
        EXPECT(sum.find("(offsets are those of payload.bin, the kernel inside the image)") != std::string::npos);
        EXPECT(sum.find(label_of("kernel inside") + "gzip stream at " + hx(at) + ", ") != std::string::npos);
        EXPECT(kernelinfo::one_line(r) == "Linux 3.18.71-test (arm zImage)");
        EXPECT(r.container.empty());
        kernelinfo::Report c = r;
        c.container = {"gzip stream at 0x800, 1234 bytes"};
        EXPECT(kernelinfo::summary(c).find(label_of("in the image") + "gzip stream at 0x800, 1234 bytes\n") != std::string::npos);
    }
    {  // the behind-the-end part
        Img k;
        k.put(arm64_header(0x80000, 0x3000, 0xa));
        k.fill(0x3000 - 64);
        k.put(Bytes(100, 0));
        const std::string sum = kernelinfo::summary(kernelinfo::analyze(k.b));
        EXPECT(sum.find("\nBEHIND THE END OF THE IMAGE\n  at 0x3000: 100 bytes, all zeros\n") != std::string::npos);
    }
}

// ------------------------------------------------------------------------------------------------- bytes that are not what they should be --

std::string fingerprint(const kernelinfo::Report& r) {
    std::string s = kernelinfo::summary(r) + "\n";
    if (r.config) s += r.config->text;
    if (r.kallsyms) s += kallsyms::format(*r.kallsyms);
    for (const auto& x : r.initramfs) s += hex_of(hash::sha256(x.plain));
    for (const auto& c : r.certificates) s += hex_of(hash::sha256(c.der)) + c.pem_text;
    for (const auto& e : r.embedded) s += hex_of(hash::sha256(e.data)) + e.text;
    if (r.payload) s += hex_of(hash::sha256(r.payload->plain));
    return s;
}

// Run first: the number of threads is changed between runs (and never while one is running).
void test_threads(const Full& f) {
    par::set_max_threads(1);
    const std::string one = fingerprint(kernelinfo::analyze(f.bytes));
    par::set_max_threads(4);
    const std::string four = fingerprint(kernelinfo::analyze(f.bytes));
    par::set_max_threads(0);
    const std::string automatic = fingerprint(kernelinfo::analyze(f.bytes));
    EXPECT(!one.empty() && one == four && one == automatic);
    // twice the same
    EXPECT(fingerprint(kernelinfo::analyze(f.bytes)) == one);
}

void check_report_inside(const kernelinfo::Report& r, size_t size, const std::string& what) {
    for (const auto& c : r.certificates)  // (the text of a PEM block whose body is damaged is still a block: it has no DER)
        EXPECT_MSG(c.offset + c.size <= size && (c.pem || !c.der.empty()), what + ": a certificate outside: " + hx(c.offset) + " " + std::to_string(c.size) + (c.pem ? " pem" : " der"));
    for (const auto& e : r.embedded) EXPECT_MSG(e.offset + e.stored <= size && !e.data.empty(), what + ": a file outside");
    for (const auto& x : r.initramfs) EXPECT_MSG(x.offset + x.stored <= size && !x.plain.empty(), what + ": an initramfs outside");
    for (const auto& b : r.banners) EXPECT_MSG(b.offset < size, what + ": a banner outside");
    if (r.config) EXPECT_MSG(r.config->offset + r.config->stored <= size, what + ": a configuration outside");
    if (r.kallsyms) EXPECT_MSG(r.kallsyms->token_index_at + 512 <= size && !r.kallsyms->symbols.empty(), what + ": a symbol table outside");
    if (r.tail) EXPECT_MSG(r.tail->offset + r.tail->size <= size, what + ": a tail outside");
}

void test_robust(const Full& f) {
    std::mt19937_64 rng(2024);
    const auto run = [&](const Bytes& m, const std::string& what) {
        try {
            const kernelinfo::Report r = kernelinfo::analyze(m);
            (void)kernelinfo::summary(r);
            (void)kernelinfo::one_line(r);
            check_report_inside(r, m.size(), what);
        } catch (...) {
            EXPECT_MSG(false, what + ": analyze threw");
        }
    };
    for (int i = 0; i < 80; ++i) {  // cut anywhere
        Bytes m = f.bytes;
        m.resize(rng() % (m.size() + 1));
        run(m, "cut at " + std::to_string(m.size()));
    }
    for (int i = 0; i < 150; ++i) {  // a few bytes changed anywhere
        Bytes m = f.bytes;
        const unsigned n = 1 + static_cast<unsigned>(rng() % 6);
        for (unsigned j = 0; j < n; ++j) m[rng() % m.size()] = static_cast<uint8_t>(rng());
        run(m, "changed " + std::to_string(n) + " bytes (" + std::to_string(i) + ")");
    }
    for (int i = 0; i < 40; ++i) {  // a piece of it wiped, or filled with noise
        Bytes m = f.bytes;
        const size_t from = rng() % m.size(), len = std::min<size_t>(m.size() - from, 1 + rng() % 4000);
        for (size_t j = 0; j < len; ++j) m[from + j] = i % 2 ? static_cast<uint8_t>(rng()) : uint8_t{0};
        run(m, "a piece at " + hx(from) + " of " + std::to_string(len) + " bytes");
    }
    run(Bytes{}, "empty");
    run(Bytes(1, 0x41), "one byte");
    run(Bytes(100, 0), "zeros");
    run(Bytes(100, 0xff), "ones");
}

void test_noise() {
    std::mt19937_64 rng(99);
    const auto nothing = [](const kernelinfo::Report& r) {
        return r.banners.empty() && r.vermagic.empty() && r.compilers.empty() && r.androidboot.empty() && !r.config && !r.kallsyms && r.initramfs.empty() &&
               r.certificates.empty() && r.embedded.empty() && !r.tail && !r.payload && r.header.empty() && r.kind == kernelinfo::Kind::Unknown;
    };
    for (int i = 0; i < 6; ++i) {
        const Bytes b = noise(rng, (size_t{1} << 18) + rng() % (size_t{1} << 20));
        EXPECT_MSG(nothing(kernelinfo::analyze(b)), "noise " + std::to_string(i));
    }
    EXPECT(nothing(kernelinfo::analyze(Bytes(1 << 20, 0))));
    EXPECT(nothing(kernelinfo::analyze(Bytes(1 << 20, 0xff))));
    {  // text that is not a kernel's
        Bytes t;
        const char* words[] = {"the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "version", "linux", "config", "certificate", "begin", "end"};
        while (t.size() < (size_t{1} << 19)) {
            append(t, text_bytes(words[rng() % 14]));
            t.push_back(rng() % 9 == 0 ? '\n' : ' ');
        }
        EXPECT(nothing(kernelinfo::analyze(t)));
    }
    const kernelinfo::Report empty = kernelinfo::analyze(Bytes{});
    EXPECT(nothing(empty) && empty.size == 0);
}

}  // namespace

int run_kinfo_tests() {
    const Full full = make_full();
    test_threads(full);  // first: it changes the number of threads, which is only safe when no work is running
    test_kallsyms_matrix();
    test_kallsyms_sizes();
    test_kallsyms_zero_prefix();
    test_kallsyms_absent();
    test_kallsyms_damage();
    test_headers();
    test_payloads();
    test_tail();
    test_text();
    test_config();
    test_initramfs();
    test_certificates();
    test_embedded();
    test_full_and_write(full);
    test_write_small();
    test_robust(full);
    test_noise();
    std::printf("kinfo: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
