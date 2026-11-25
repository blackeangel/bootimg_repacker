// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::kallsyms: see include/abr/kallsyms.hpp for what is looked for and why it can be told from other bytes.
#include "abr/kallsyms.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace abr::kallsyms {
namespace {

// The integers of the image, in the byte order of the kernel. The callers check with has() first.
struct Reader {
    const uint8_t* d = nullptr;
    size_t n = 0;
    bool be = false;

    bool has(size_t at, size_t len) const { return at <= n && len <= n - at; }
    uint64_t u(size_t at, unsigned width) const {
        uint64_t v = 0;
        if (be) {
            for (unsigned i = 0; i < width; ++i) v = (v << 8) | d[at + i];
        } else {
            for (unsigned i = width; i-- > 0;) v = (v << 8) | d[at + i];
        }
        return v;
    }
};

// The most symbols a table may have: the kernels of today have a few hundred thousand, and the markers and names that make a table
// real take at least a byte each, so no file can hold more than it is long -- the limit is for a file of a gigabyte.
constexpr uint64_t kMaxSymbols = 8u << 20;

// A symbol is a type letter and a name of at most this many characters once the tokens are put back (the kernel's KSYM_NAME_LEN is 128, 512 in
// Linux 6.x; a name that is longer than that does not come from a kernel).
constexpr size_t kMaxName = 1024;

// ---- the token table -------------------------------------------------------------------------------------------------------------

struct Tokens {
    size_t start = 0;  // the first token (the one for the byte 0x00)
    size_t end = 0;    // behind the NUL of the last token
    size_t index = 0;  // kallsyms_token_index
    uint32_t off[256] = {};
};

constexpr uint8_t kDigits[20] = {'0', 0, '1', 0, '2', 0, '3', 0, '4', 0, '5', 0, '6', 0, '7', 0, '8', 0, '9', 0};

// How far behind the table its index may be: the alignment of a section is a few hundred bytes at most.
constexpr size_t kIndexSlack = 2048;

// The token table that has the digits at `anchor` (the tokens of the bytes 0x30 to 0x39 stand for themselves, whatever else a kernel
// compresses), or false.
//
// The strings from the token 0x30 on are read forwards from the anchor (a string ends at its NUL) and give the end of the table. Going back
// from the anchor for the 48 before it would run into the bytes in front of the table -- the last marker, which in a big-endian kernel ends in a
// byte that is not zero and is not padded when the arrays are aligned to what they are -- so the start is what the index says. The index, 256
// 16-bit numbers behind the table, is the proof: from the token 0x30 on each number is the distance of its string from the anchor plus the same
// constant, the 48 before start at 0 and rise to that constant, and every one of them is where a string of the table really begins. The constant
// is where the anchor is in the table, so it says where the table starts.
bool read_tokens(const Reader& r, size_t anchor, Tokens& t) {
    const uint8_t* d = r.d;
    uint32_t rel[256] = {};  // the distance from the anchor of the string of every token from 0x30 on
    size_t q = anchor;
    for (int i = 0x30; i < 256; ++i) {
        rel[i] = static_cast<uint32_t>(q - anchor);
        size_t e = q;
        while (e < r.n && d[e] != 0) {
            if (e - q > 256) return false;
            ++e;
        }
        if (e >= r.n) return false;
        q = e + 1;
    }
    t.end = q;
    const size_t span = t.end - anchor;  // the strings of 0x30 to 0xff
    if (span >= 0x10000 || r.n < 512) return false;
    const size_t last = std::min(r.n - 512, t.end + kIndexSlack);
    for (size_t at = t.end; at <= last; ++at) {
        const size_t c = static_cast<size_t>(r.u(at + 2 * 0x30, 2));  // the index of the token 0x30: where the anchor is in the table
        if (c < 0x30 || c > anchor || c + span >= 0x10000) continue;
        bool ok = true;
        for (int i = 0x30; i < 256 && ok; ++i) ok = r.u(at + 2 * static_cast<size_t>(i), 2) == c + rel[i];
        if (!ok) continue;
        const size_t start = anchor - c;
        size_t prev = static_cast<size_t>(r.u(at, 2));
        if (prev != 0) continue;
        t.off[0] = 0;
        for (int i = 1; i <= 0x30 && ok; ++i) {  // the token i-1 is [prev, cur - 1), and its NUL is at cur - 1
            const size_t cur = static_cast<size_t>(r.u(at + 2 * static_cast<size_t>(i), 2));
            if (cur <= prev || cur > c || d[start + cur - 1] != 0) {
                ok = false;
                break;
            }
            for (size_t k = start + prev; k + 1 < start + cur; ++k)
                if (d[k] == 0) ok = false;
            if (i < 0x30) t.off[i] = static_cast<uint32_t>(cur);
            prev = cur;
        }
        if (!ok) continue;
        for (int i = 0x30; i < 256; ++i) t.off[i] = static_cast<uint32_t>(c + rel[i]);
        t.start = start;
        t.index = at;
        return true;
    }
    return false;
}

// ---- the markers -----------------------------------------------------------------------------------------------------------------

struct Markers {
    size_t at = 0;
    unsigned width = 4;
    std::vector<uint64_t> value;
};

// kallsyms_markers, which ends just before the token table (up to the alignment: zeros). Its numbers grow, from 0, and the array begins
// at the 0: a table of 256 symbols or fewer has the one marker 0, which cannot be told from the padding, so it is not found.
bool read_markers(const Reader& r, size_t table_start, unsigned width, Markers& m) {
    size_t q = table_start;
    while (q > 0 && r.d[q - 1] == 0) --q;
    if (q == 0) return false;
    const size_t end = ((q - 1) / width) * width + width;
    if (end > table_start || end < 2 * width) return false;
    size_t pos = end - width;
    uint64_t prev = r.u(pos, width);
    if (prev == 0) return false;
    size_t count = 1;
    for (;;) {
        if (pos < width) return false;
        pos -= width;
        const uint64_t v = r.u(pos, width);
        ++count;
        if (v >= prev) return false;
        prev = v;
        if (v == 0) break;
        if (count > kMaxSymbols / 256 + 1) return false;
    }
    m.at = pos;
    m.width = width;
    m.value.resize(count);
    for (size_t i = 0; i < count; ++i) m.value[i] = r.u(pos + i * width, width);
    return true;
}

// ---- the names -------------------------------------------------------------------------------------------------------------------

struct Name {
    uint32_t at;   // the first byte of the symbol's tokens
    uint32_t len;  // how many
};

// Walks `n` names from `at` the way the kernel does, and requires every 256th to be where the markers say and the end to be within the
// alignment (zeros) of `limit`. `limit` is where the markers begin.
bool parse_names(const Reader& r, size_t at, uint64_t n, const std::vector<uint64_t>& markers, bool long_names, size_t limit,
                 std::vector<Name>& names, size_t& end) {
    names.clear();
    names.reserve(static_cast<size_t>(n));
    size_t pos = at;
    for (uint64_t i = 0; i < n; ++i) {
        if (i % 256 == 0) {
            const uint64_t k = i / 256;
            if (k >= markers.size() || pos - at != markers[k]) return false;
        }
        if (pos >= limit) return false;
        size_t len = r.d[pos++];
        if (long_names && (len & 0x80) != 0) {
            if (pos >= limit) return false;
            len = (len & 0x7f) | (static_cast<size_t>(r.d[pos++]) << 7);
        }
        if (len == 0 || len > limit - pos) return false;
        names.push_back({static_cast<uint32_t>(pos), static_cast<uint32_t>(len)});
        pos += len;
    }
    if (pos > limit) return false;
    for (size_t i = pos; i < limit; ++i)
        if (r.d[i] != 0) return false;
    if (limit - pos >= 256 + 16) return false;
    end = pos;
    return true;
}

// ---- the addresses ---------------------------------------------------------------------------------------------------------------

struct Addresses {
    Layout layout = Layout::Absolute;
    unsigned width = 8;
    size_t at = 0;
    size_t base_at = 0;
    uint64_t base = 0;
    std::vector<uint64_t> value;
};

// The index of the byte behind the last byte that is not zero before `pos`, or 0.
size_t skip_zeros_back(const Reader& r, size_t pos) {
    while (pos > 0 && r.d[pos - 1] == 0) --pos;
    return pos;
}

bool sorted(const std::vector<uint64_t>& v) {
    for (size_t i = 1; i < v.size(); ++i)
        if (v[i - 1] > v[i]) return false;
    return true;
}

// The size of a pointer of the kernel that a relative base of `slot` bytes says: a base that is in the low 4 GiB is one of a kernel with 4-byte
// pointers, when the slot is of 8 bytes because the alignment (16 bytes on ARM) put zeros behind it.
unsigned width_of(unsigned slot, uint64_t base) { return slot == 8 && base <= 0xffffffffull ? 4u : slot; }

// The addresses that go with the names: `count_at` is where kallsyms_num_syms is (the array and the base are in front of it).
// The one that is found has to hold n numbers that are in order. As a relative table the offsets also have to be in the range of a
// kernel (an absolute table of 32-bit addresses is in order too when it is read as offsets, with its last address for a base), and the base, the
// lowest address of the kernel, has to be at a page (a kernel that starts anywhere else is looked for in a second round, after the
// absolute reading: a base of 8 bytes that is really two words of 4, or a base of 4 bytes that is the half of one of 8, is not at a page).
bool read_addresses(const Reader& r, size_t count_at, size_t n, Addresses& out) {
    const size_t q = skip_zeros_back(r, count_at);
    if (q == 0) return false;
    // relative: [offsets][zeros][relative_base][zeros]count
    auto relative = [&](bool strict) {
        for (const unsigned bw : {8u, 4u}) {
            const size_t bend = ((q - 1) / bw) * bw + bw;
            if (bend < bw || bend > count_at) continue;
            const size_t bstart = bend - bw;
            const uint64_t base = r.u(bstart, bw);
            // big endian: a base of 4 bytes with the zeros of the alignment behind it reads as a base of 8 bytes that has nothing in its low half
            // (a little-endian one reads as a number that is 32 bits wide: width_of() below). The reading of 4 bytes is the one that is right.
            if (bw == 8 && r.be && base != 0 && (base & 0xffffffffull) == 0) continue;
            if (strict && (base % 4096) != 0) continue;
            const size_t q2 = skip_zeros_back(r, bstart);
            if (q2 == 0) continue;
            const size_t oend = ((q2 - 1) / 4) * 4 + 4;
            if (oend > bstart || oend < 4 * n) continue;
            const size_t ostart = oend - 4 * n;
            std::vector<uint64_t> v(n);
            bool in_range = true, any_negative = false;
            for (size_t i = 0; i < n; ++i) {
                const uint64_t o = r.u(ostart + 4 * i, 4);
                v[i] = o;
                if (o >= 0x80000000u) any_negative = true;
                if (o >= (1u << 28)) in_range = false;
            }
            const uint64_t mask = bw == 8 ? ~0ull : 0xffffffffull;
            if (in_range) {
                std::vector<uint64_t> a(n);
                for (size_t i = 0; i < n; ++i) a[i] = (base + v[i]) & mask;
                if (sorted(a)) {
                    out = {Layout::Relative, width_of(bw, base), ostart, bstart, base, std::move(a)};
                    return true;
                }
            }
            if (any_negative) {
                std::vector<uint64_t> a(n);
                for (size_t i = 0; i < n; ++i) {
                    const int32_t o = static_cast<int32_t>(static_cast<uint32_t>(v[i]));
                    a[i] = (o >= 0 ? static_cast<uint64_t>(o) : base - 1 - static_cast<uint64_t>(static_cast<int64_t>(o))) & mask;
                }
                if (sorted(a)) {
                    out = {Layout::RelativePercpu, width_of(bw, base), ostart, bstart, base, std::move(a)};
                    return true;
                }
            }
        }
        return false;
    };
    if (relative(true)) return true;
    // absolute: [addresses][zeros]count. The narrow reading goes first: a table of 8-byte addresses is not in order when it is read as words of 4 (the
    // words alternate between the low half and the high half), but a table of 4-byte addresses is in order when it is read as words of 8 as soon as
    // the bytes in front of it are zeros (the first half of the numbers are zero, the others are pairs of its addresses).
    for (const unsigned aw : {4u, 8u}) {
        const size_t aend = ((q - 1) / aw) * aw + aw;
        if (aend > count_at || aend < aw * n) continue;
        const size_t astart = aend - aw * n;
        std::vector<uint64_t> a(n);
        for (size_t i = 0; i < n; ++i) a[i] = r.u(astart + aw * i, aw);
        if (sorted(a)) {
            out = {Layout::Absolute, aw, astart, 0, 0, std::move(a)};
            return true;
        }
    }
    return relative(false);
}

// ---- putting it together ---------------------------------------------------------------------------------------------------------

bool printable_name(const std::string& s) {
    for (const char c : s)
        if (c < 0x20 || c > 0x7e) return false;
    return true;
}

std::optional<Table> find_with(const uint8_t* data, size_t size, bool be) {
    Reader r;
    r.d = data;
    r.n = size;
    r.be = be;
    size_t from = 0;
    while (from + sizeof kDigits <= size) {
        const void* hit = std::memchr(data + from, '0', size - from - sizeof kDigits + 1);
        if (!hit) break;
        const size_t anchor = static_cast<size_t>(static_cast<const uint8_t*>(hit) - data);
        from = anchor + 1;
        if (std::memcmp(data + anchor, kDigits, sizeof kDigits) != 0) continue;
        Tokens tokens;
        if (!read_tokens(r, anchor, tokens)) continue;
        for (const unsigned mw : {4u, 8u}) {
            Markers markers;
            if (!read_markers(r, tokens.start, mw, markers)) continue;
            const uint64_t lo = 256 * (markers.value.size() - 1) + 1, hi = 256 * markers.value.size();
            if (hi > kMaxSymbols) continue;
            // kallsyms_num_syms is in front of the names, and the names are at least two bytes a symbol and at most a few dozen on average
            const size_t reach = static_cast<size_t>(hi) * 140 + 4096;
            const size_t low_limit = markers.at > reach ? markers.at - reach : 0;
            for (size_t p = markers.at & ~size_t{3}; p >= low_limit + 4 + 4;) {
                p -= 4;
                const uint64_t v = r.u(p, 4);
                if (v < lo || v > hi) continue;
                // the first name follows the number and the alignment (zeros); a name is never empty
                size_t nstart = p + 4;
                while (nstart < markers.at && nstart < p + 4 + 260 && data[nstart] == 0) ++nstart;
                if (nstart >= markers.at) continue;
                for (const bool long_names : {false, true}) {
                    std::vector<Name> names;
                    size_t nend = 0;
                    if (!parse_names(r, nstart, v, markers.value, long_names, markers.at, names, nend)) continue;
                    Addresses addr;
                    if (!read_addresses(r, p, static_cast<size_t>(v), addr)) continue;

                    Table t;
                    t.layout = addr.layout;
                    t.big_endian = be;
                    t.address_size = addr.width;
                    t.marker_size = mw;
                    t.long_names = long_names;
                    t.relative_base = addr.base;
                    t.addresses_at = addr.at;
                    t.relative_base_at = addr.base_at;
                    t.count_at = p;
                    t.names_at = nstart;
                    t.names_end = nend;
                    t.markers_at = markers.at;
                    t.token_table_at = tokens.start;
                    t.token_table_end = tokens.end;
                    t.token_index_at = tokens.index;
                    t.symbols.reserve(names.size());
                    size_t good = 0;
                    for (size_t i = 0; i < names.size(); ++i) {
                        std::string text;
                        for (uint32_t k = 0; k < names[i].len && text.size() <= kMaxName; ++k) {
                            const uint8_t b = data[names[i].at + k];
                            text.append(reinterpret_cast<const char*>(data + tokens.start + tokens.off[b]));
                        }
                        Symbol s;
                        s.address = addr.value[i];
                        if (!text.empty()) {
                            s.type = text[0];
                            s.name = text.substr(1);
                        }
                        const bool letter = (s.type >= 'A' && s.type <= 'Z') || (s.type >= 'a' && s.type <= 'z');
                        if (letter && printable_name(s.name) && !s.name.empty() && s.name.size() < kMaxName) ++good;
                        t.symbols.push_back(std::move(s));
                    }
                    // a table that the names do not read as is not one
                    if (good * 20 < t.symbols.size() * 19) {
                        t.symbols.clear();
                        continue;
                    }
                    return t;
                }
            }
        }
    }
    return std::nullopt;
}

}  // namespace

std::optional<Table> find(const uint8_t* data, size_t size) {
    if (!data || size < 1024) return std::nullopt;
    try {
        if (auto t = find_with(data, size, false)) return t;
        return find_with(data, size, true);
    } catch (const std::exception&) {  // an allocation that a made-up count asked for, say
        return std::nullopt;
    }
}

std::string format(const Table& t) {
    const unsigned digits = t.address_size * 2;
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(t.symbols.size() * (digits + 24));
    for (const Symbol& s : t.symbols) {
        for (unsigned i = digits; i-- > 0;) out.push_back(hex[(s.address >> (4 * i)) & 15]);
        out.push_back(' ');
        out.push_back(s.type);
        out.push_back(' ');
        out += s.name;
        out.push_back('\n');
    }
    return out;
}

}  // namespace abr::kallsyms
