// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/aml.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <numeric>
#include <optional>

#include "abr/dtb.hpp"
#include "abr/manifest.hpp"
#include "abr/pages.hpp"
#include "abr/textquote.hpp"

namespace abr::aml {

namespace {

using pages::padded;
using textquote::escape_for_terminal;

std::string num(uint64_t v) { return std::to_string(v); }

std::string hex(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

uint32_t le32_at(const Bytes& d, size_t at) {
    return uint32_t(d[at]) | (uint32_t(d[at + 1]) << 8) | (uint32_t(d[at + 2]) << 16) | (uint32_t(d[at + 3]) << 24);
}

uint32_t be32_at(const Bytes& d, size_t at) {
    return (uint32_t(d[at]) << 24) | (uint32_t(d[at + 1]) << 16) | (uint32_t(d[at + 2]) << 8) | uint32_t(d[at + 3]);
}

void put_le32(Bytes& out, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) out.push_back(uint8_t(v >> (8 * i)));
}

constexpr const char* kIdNames[3] = {"soc", "platform", "variant"};

// An id as the bytes of the container have it: the text and spaces up to `length`, every word of four characters reversed.
Bytes encode_id(const std::string& text, size_t length) {
    Bytes out(length, ' ');
    for (size_t i = 0; i < text.size(); ++i) out[i] = static_cast<uint8_t>(text[i]);
    for (size_t w = 0; w + 4 <= length; w += 4) std::reverse(out.begin() + static_cast<std::ptrdiff_t>(w), out.begin() + static_cast<std::ptrdiff_t>(w + 4));
    return out;
}

// Why `text` is not an id that abr writes (empty: it is), for an id of `length` bytes.
std::string id_problem(const std::string& text, size_t length) {
    if (text.size() > length) return "it is " + num(text.size()) + " characters, and an id of this version has " + num(length);
    for (const char c : text) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u <= 0x20 || u >= 0x7f)
            return std::string(u == 0x20 ? "it has a space in it" : "it has a byte (" + hex(u) + ") that is no printable character") +
                   "; u-boot turns every space of an id into the end of the text, and abr writes only ids that it reads whole";
    }
    return {};
}

// The text an id of the container holds (the bytes at `at`, `length` of them), or nullopt, with `why` saying what is wrong, for bytes that
// are not an id that abr writes again byte for byte: the padding is spaces, and the text is printable characters without any.
std::optional<std::string> decode_id(const Bytes& data, size_t at, size_t length, std::string* why) {
    std::string chars(length, ' ');
    for (size_t w = 0; w + 4 <= length; w += 4)
        for (size_t j = 0; j < 4; ++j) chars[w + j] = static_cast<char>(data[at + w + 3 - j]);
    size_t end = length;
    while (end > 0 && chars[end - 1] == ' ') --end;
    std::string text = chars.substr(0, end);
    if (const std::string problem = id_problem(text, length); !problem.empty()) {
        *why = problem;
        return std::nullopt;
    }
    return text;
}

// Where everything is for one page size: the first tree behind the table of entries and the trees one behind the other.
struct Layout {
    uint64_t table_end = 0;  // the end of the entries
    uint64_t first = 0;      // where the first tree is
    std::vector<uint64_t> offsets;
    std::vector<uint64_t> sizes;
    uint64_t end = 0;        // where the last tree and its padding end
};

Layout lay_out(uint32_t version, uint64_t page, size_t entries, const std::vector<uint64_t>& lengths) {
    Layout l;
    l.table_end = kHeaderSize + uint64_t(entry_size(version)) * entries;
    l.first = padded(l.table_end, page);
    uint64_t at = l.first;
    for (const uint64_t length : lengths) {
        l.offsets.push_back(at);
        l.sizes.push_back(padded(length, page));
        at += l.sizes.back();
    }
    l.end = at;
    return l;
}

// A tree that stands as one in a container: it starts with the magic, has its header, and is as long as that header says -- the length of a tree
// is found from its header (the zeros behind it are padding), so a file with bytes behind the tree, or cut short, cannot be one.
void check_tree(const Bytes& blob, const std::string& what) {
    if (blob.size() < 4 || be32_at(blob, 0) != kFdtMagic)
        throw FormatError(what + " is not a flattened device tree (it does not start with d0 0d fe ed)");
    if (blob.size() < kFdtHeaderSize)
        throw FormatError(what + " is cut short: the header of a flattened device tree is " + num(kFdtHeaderSize) + " bytes and it has " + num(blob.size()));
    const uint32_t total = be32_at(blob, 4);
    if (total != blob.size())
        throw FormatError(what + " is " + num(blob.size()) + " bytes, and the totalsize in its header is " + num(total) +
                          "; the length of a tree in the container is found from that header (what follows it is padding), so the two have to agree");
}

}  // namespace

void check_device_tree(const Bytes& blob, const std::string& what) { check_tree(blob, what); }

bool looks_like(const Bytes& data) {
    return data.size() >= kHeaderSize && std::memcmp(data.data(), "AML_", 4) == 0 && id_size(le32_at(data, 4)) != 0;
}

Bytes build(const Table& t) {
    if (entry_size(t.version) == 0) throw FormatError("an AML_ container has version 1 or 2, not " + num(t.version));
    if (t.page_size == 0 || t.page_size > kMaxPageSize)
        throw FormatError("the page size of an AML_ container is from 1 byte to 1 MiB, not " + num(t.page_size));
    if (t.entries.empty()) throw FormatError("an AML_ container has at least one entry");
    if (t.entries.size() > kMaxEntries)
        throw FormatError("an AML_ container of " + num(t.entries.size()) + " entries is more than abr makes (" + num(kMaxEntries) + ")");
    if (t.dtbs.empty()) throw FormatError("an AML_ container has at least one device tree");

    const size_t idlen = id_size(t.version);
    std::vector<bool> used(t.dtbs.size(), false);
    for (size_t i = 0; i < t.entries.size(); ++i) {
        const Entry& e = t.entries[i];
        if (e.dtb >= t.dtbs.size())
            throw FormatError("entry " + num(i) + " is for device tree " + num(e.dtb) + ", and the container has " + num(t.dtbs.size()));
        used[e.dtb] = true;
        const std::string* texts[3] = {&e.soc, &e.platform, &e.variant};
        for (size_t k = 0; k < 3; ++k)
            if (const std::string problem = id_problem(*texts[k], idlen); !problem.empty())
                throw FormatError("entry " + num(i) + ": the " + kIdNames[k] + " \"" + escape_for_terminal(*texts[k]) + "\" is not an id of a version " +
                                  num(t.version) + " container: " + problem);
    }
    for (size_t j = 0; j < t.dtbs.size(); ++j)
        if (!used[j]) throw FormatError("device tree " + num(j) + " is for no entry; nothing in the container would find it");
    for (size_t j = 0; j < t.dtbs.size(); ++j) check_tree(t.dtbs[j], "device tree " + num(j));

    std::vector<uint64_t> lengths;
    lengths.reserve(t.dtbs.size());
    for (const Bytes& b : t.dtbs) lengths.push_back(b.size());
    const Layout l = lay_out(t.version, t.page_size, t.entries.size(), lengths);
    if (l.end > 0xFFFFFFFFull) throw FormatError("the container would be " + num(l.end) + " bytes; an offset in it is a 32-bit word");

    Bytes out;
    out.reserve(static_cast<size_t>(l.end));
    out.insert(out.end(), {'A', 'M', 'L', '_'});
    put_le32(out, t.version);
    put_le32(out, static_cast<uint32_t>(t.entries.size()));
    for (const Entry& e : t.entries) {
        for (const std::string* text : {&e.soc, &e.platform, &e.variant}) {
            const Bytes id = encode_id(*text, idlen);
            out.insert(out.end(), id.begin(), id.end());
        }
        put_le32(out, static_cast<uint32_t>(l.offsets[e.dtb]));
        put_le32(out, static_cast<uint32_t>(l.sizes[e.dtb]));
    }
    out.resize(static_cast<size_t>(l.first), 0);  // the zeros up to the first tree
    for (size_t j = 0; j < t.dtbs.size(); ++j) {
        out.insert(out.end(), t.dtbs[j].begin(), t.dtbs[j].end());
        out.resize(static_cast<size_t>(l.offsets[j] + l.sizes[j]), 0);
    }
    return out;
}

Table parse(const Bytes& data, uint32_t page_hint) {
    if (!looks_like(data))
        throw FormatError("not an AML_ container: it does not start with \"AML_\", a version of 1 or 2 and a count");
    const uint32_t version = le32_at(data, 4);
    const size_t es = entry_size(version), idlen = id_size(version);
    const uint32_t count = le32_at(data, 8);
    if (count == 0) throw FormatError("the AML_ container has no entries");
    if (count > kMaxEntries)
        throw FormatError("the AML_ container says it has " + num(count) + " entries (abr takes " + num(kMaxEntries) + " at most)");
    const uint64_t table_end = kHeaderSize + uint64_t(es) * count;
    if (table_end > data.size())
        throw FormatError("the AML_ container says it has " + num(count) + " entries of " + num(es) + " bytes, and the file is " + num(data.size()) +
                          " bytes");

    struct Raw {
        Entry entry;
        uint64_t offset = 0;
        uint64_t size = 0;
    };
    std::vector<Raw> raw(count);
    for (size_t i = 0; i < raw.size(); ++i) {
        const size_t at = kHeaderSize + es * i;
        std::string* texts[3] = {&raw[i].entry.soc, &raw[i].entry.platform, &raw[i].entry.variant};
        for (size_t k = 0; k < 3; ++k) {
            std::string why;
            const std::optional<std::string> text = decode_id(data, at + k * idlen, idlen, &why);
            if (!text) throw FormatError("entry " + num(i) + ": its " + kIdNames[k] + " id is not one that abr writes again: " + why);
            *texts[k] = *text;
        }
        raw[i].offset = le32_at(data, at + 3 * idlen);
        raw[i].size = le32_at(data, at + 3 * idlen + 4);
    }

    // The trees, in the order they are in the file (an entry says where; several may say the same).
    std::map<uint64_t, uint64_t> trees;  // offset -> size
    for (const Raw& r : raw) {
        const auto [it, fresh] = trees.emplace(r.offset, r.size);
        if (!fresh && it->second != r.size)
            throw FormatError("entries are for the tree at offset " + hex(r.offset) + " and give it two sizes (" + num(it->second) + " and " + num(r.size) +
                              " bytes)");
    }
    std::vector<uint64_t> offsets, sizes, lengths;
    uint64_t common = 0;
    uint64_t previous_end = 0;
    for (const auto& [offset, size] : trees) {
        const std::string where = "the tree at offset " + hex(offset);
        if (size == 0) throw FormatError(where + " has size 0");
        if (offset < table_end) throw FormatError(where + " is inside the table of entries, which ends at " + hex(table_end));
        if (offset + size > data.size())
            throw FormatError(where + " and its " + num(size) + " bytes run past the end of the file (" + num(data.size()) + " bytes)");
        if (!offsets.empty() && offset < previous_end) throw FormatError(where + " overlaps the one before it, which ends at " + hex(previous_end));
        previous_end = offset + size;
        if (size < kFdtHeaderSize || be32_at(data, static_cast<size_t>(offset)) != kFdtMagic)
            throw FormatError("there is no device tree at offset " + hex(offset) + " (it does not start with d0 0d fe ed)");
        const uint32_t total = be32_at(data, static_cast<size_t>(offset) + 4);
        if (total < kFdtHeaderSize || total > size)
            throw FormatError(where + " says in its own header that it is " + num(total) + " bytes, and the container gives it " + num(size));
        offsets.push_back(offset);
        sizes.push_back(size);
        lengths.push_back(total);
        common = std::gcd(std::gcd(common, offset), size);
    }

    // The page size is not in the container; the layout is what tells it.
    for (const uint32_t page : pages::candidates(common, page_hint, kMaxPageSize)) {
        const Layout l = lay_out(version, page, count, lengths);
        if (l.offsets != offsets || l.sizes != sizes) continue;
        Table t;
        t.version = version;
        t.page_size = page;
        t.consumed = static_cast<size_t>(l.end);
        std::map<uint64_t, size_t> index;
        for (size_t i = 0; i < offsets.size(); ++i) {
            index[offsets[i]] = i;
            const auto from = data.begin() + static_cast<std::ptrdiff_t>(offsets[i]);
            t.dtbs.emplace_back(from, from + static_cast<std::ptrdiff_t>(lengths[i]));
        }
        for (const Raw& r : raw) {
            Entry e = r.entry;
            e.dtb = index.at(r.offset);
            t.entries.push_back(std::move(e));
        }
        // What is left of what the tool writes is the zeros: the fill up to the first tree, the padding of every tree.
        const Bytes again = build(t);
        for (size_t i = 0; i < again.size(); ++i) {
            if (again[i] == data[i]) continue;
            if (i >= table_end && i < l.first)
                throw FormatError("the end of the table of entries (the zeros up to the first tree, at offset " + hex(l.first) + ") is not zeros: offset " +
                                  hex(i) + " holds " + hex(data[i]) + "; the tool that makes the container does not write that");
            size_t tree = 0;
            while (tree + 1 < offsets.size() && i >= offsets[tree + 1]) ++tree;
            throw FormatError("the padding behind the tree at offset " + hex(offsets[tree]) + " is not zeros: offset " + hex(i) + " holds " + hex(data[i]) +
                              "; the tool that makes the container does not write that");
        }
        return t;
    }
    throw FormatError("the trees are not laid out as the tool lays them out (one behind the other, the first at the next page behind the table of entries, "
                      "each followed by zeros up to the next page -- a whole page when it ends on one): no page size up to 1 MiB gives these offsets and sizes");
}

}  // namespace abr::aml
