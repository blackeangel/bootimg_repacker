// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/qcdt.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <numeric>
#include <tuple>

#include "abr/dtb.hpp"
#include "abr/manifest.hpp"
#include "abr/textquote.hpp"

namespace abr::qcdt {

namespace {

using textquote::quote_shown;

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

// What dtbTool pads with: up to the next multiple of the page size, and a whole page when the length already is one.
uint64_t padded(uint64_t length, uint64_t page) { return length + (page - length % page); }

// Where everything is for one page size: the first tree behind the table (its entries, the word that ends it) and the trees one
// behind the other.
struct Layout {
    uint64_t table_end = 0;  // the end of the entries and of the word of zeros behind them
    uint64_t first = 0;      // where the first tree is
    std::vector<uint64_t> offsets;
    std::vector<uint64_t> sizes;
    uint64_t end = 0;        // where the last tree and its padding end
};

Layout lay_out(uint32_t version, uint64_t page, size_t entries, const std::vector<uint64_t>& lengths) {
    Layout l;
    l.table_end = kHeaderSize + uint64_t(entry_size(version)) * entries + 4;
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

// A tree that stands as one in a table: it starts with the magic, has its header, and is as long as that header says -- in a table
// the length of a tree is found from its header (the zeros behind it are padding), so a file with bytes behind the tree, or cut
// short, cannot be one.
void check_tree(const Bytes& blob, const std::string& what) {
    if (blob.size() < 4 || be32_at(blob, 0) != kFdtMagic)
        throw FormatError(what + " is not a flattened device tree (it does not start with d0 0d fe ed)");
    if (blob.size() < kFdtHeaderSize)
        throw FormatError(what + " is cut short: the header of a flattened device tree is " + num(kFdtHeaderSize) + " bytes and it has " + num(blob.size()));
    const uint32_t total = be32_at(blob, 4);
    if (total != blob.size())
        throw FormatError(what + " is " + num(blob.size()) + " bytes, and the totalsize in its header is " + num(total) +
                          "; the length of a tree in a table is found from that header (what follows it is padding), so the two have to agree");
}

bool any_pmic(const Chip& c) { return c.pmic[0] != 0 || c.pmic[1] != 0 || c.pmic[2] != 0 || c.pmic[3] != 0; }

// The cells of a property (what a tree holds, big-endian words), or FormatError for a value that is not whole cells.
std::vector<uint32_t> cells_of(const fdt::Property& p) {
    if (p.value.size() % 4 != 0)
        throw FormatError(p.name + " is " + num(p.value.size()) + " bytes, and a property of cells is a multiple of 4");
    std::vector<uint32_t> out;
    out.reserve(p.value.size() / 4);
    for (size_t i = 0; i < p.value.size(); i += 4) out.push_back(be32_at(p.value, i));
    return out;
}

// `p` as groups of `width` cells (at least one group).
std::vector<std::vector<uint32_t>> groups_of(const fdt::Property& p, size_t width, const std::string& meaning) {
    const std::vector<uint32_t> cells = cells_of(p);
    if (cells.empty()) throw FormatError(p.name + " is empty; it holds groups of " + meaning);
    if (cells.size() % width != 0)
        throw FormatError(p.name + " has " + num(cells.size()) + " cells, and it holds groups of " + num(width) + " (" + meaning + ")");
    std::vector<std::vector<uint32_t>> out;
    for (size_t i = 0; i < cells.size(); i += width) out.emplace_back(cells.begin() + static_cast<std::ptrdiff_t>(i),
                                                                       cells.begin() + static_cast<std::ptrdiff_t>(i + width));
    return out;
}

// The order in which dtbTool has the things of a list: the first, then the others from the last to the second (it links each new one in
// behind the first). It decides where equal boards -- a tree for one chipset, platform, subtype and revision with several PMIC ids -- are
// in the table, since dtbTool sorts by those four only; and the table is meant to be dtbTool's byte for byte.
template <typename T>
std::vector<T> dtbtool_order(const std::vector<T>& list) {
    std::vector<T> out;
    out.reserve(list.size());
    if (list.empty()) return out;
    out.push_back(list.front());
    for (size_t i = list.size(); i-- > 1;) out.push_back(list[i]);
    return out;
}

std::string board_text(const Chip& c, uint32_t version) {
    std::string s = "chipset " + hex(c.chipset) + ", platform " + hex(c.platform);
    if (version >= 2) s += ", subtype " + hex(c.subtype);
    s += ", revision " + hex(c.revision);
    if (version >= 3)
        s += ", pmic " + hex(c.pmic[0]) + " " + hex(c.pmic[1]) + " " + hex(c.pmic[2]) + " " + hex(c.pmic[3]);
    return s;
}

// The page sizes that the offsets and sizes of the trees allow (every one divides all of them), the one asked for first, then the
// usual ones, then the rest from the smallest.
std::vector<uint32_t> page_candidates(uint64_t common, uint32_t hint) {
    std::vector<uint32_t> divisors;
    for (uint64_t d = 1; d * d <= common; ++d) {
        if (common % d != 0) continue;
        if (d <= kMaxPageSize) divisors.push_back(static_cast<uint32_t>(d));
        const uint64_t other = common / d;
        if (other != d && other <= kMaxPageSize) divisors.push_back(static_cast<uint32_t>(other));
    }
    std::sort(divisors.begin(), divisors.end());
    std::vector<uint32_t> order;
    const auto take = [&](uint32_t p) {
        if (p != 0 && std::binary_search(divisors.begin(), divisors.end(), p) && std::find(order.begin(), order.end(), p) == order.end())
            order.push_back(p);
    };
    take(hint);
    for (const uint32_t p : {2048u, 4096u, 8192u, 16384u, 1024u, 512u, 32768u, 65536u, 131072u, 262144u, 524288u, 1048576u}) take(p);
    for (const uint32_t d : divisors) take(d);
    return order;
}

}  // namespace

bool looks_like(const Bytes& data) { return data.size() >= 4 && std::memcmp(data.data(), "QCDT", 4) == 0; }

Bytes build(const Table& t) {
    if (entry_size(t.version) == 0)
        throw FormatError("a QCDT table has version 1, 2 or 3, not " + num(t.version));
    if (t.page_size == 0 || t.page_size > kMaxPageSize)
        throw FormatError("the page size of a QCDT table is from 1 byte to 1 MiB (what dtbTool takes), not " + num(t.page_size));
    if (t.entries.empty()) throw FormatError("a QCDT table has at least one entry");
    if (t.entries.size() > kMaxEntries)
        throw FormatError("a QCDT table of " + num(t.entries.size()) + " entries is more than abr makes (" + num(kMaxEntries) + ")");
    if (t.dtbs.empty()) throw FormatError("a QCDT table has at least one device tree");

    std::vector<bool> used(t.dtbs.size(), false);
    for (size_t i = 0; i < t.entries.size(); ++i) {
        const Entry& e = t.entries[i];
        if (e.dtb >= t.dtbs.size())
            throw FormatError("entry " + num(i) + " is for device tree " + num(e.dtb) + ", and the table has " + num(t.dtbs.size()));
        used[e.dtb] = true;
        if (t.version < 2 && e.subtype != 0)
            throw FormatError("entry " + num(i) + " has a subtype (" + hex(e.subtype) + "), and an entry of a version 1 table has no word for it");
        if (t.version < 3 && any_pmic(e))
            throw FormatError("entry " + num(i) + " has a PMIC id, and an entry of a version " + num(t.version) + " table has no word for it");
    }
    for (size_t j = 0; j < t.dtbs.size(); ++j)
        if (!used[j])
            throw FormatError("device tree " + num(j) + " is for no entry; nothing in the table would find it");
    for (size_t j = 0; j < t.dtbs.size(); ++j) check_tree(t.dtbs[j], "device tree " + num(j));

    std::vector<uint64_t> lengths;
    lengths.reserve(t.dtbs.size());
    for (const Bytes& b : t.dtbs) lengths.push_back(b.size());
    const Layout l = lay_out(t.version, t.page_size, t.entries.size(), lengths);
    if (l.end > 0xFFFFFFFFull)
        throw FormatError("the table would be " + num(l.end) + " bytes; an offset in it is a 32-bit word");

    Bytes out;
    out.reserve(static_cast<size_t>(l.end));
    out.insert(out.end(), {'Q', 'C', 'D', 'T'});
    put_le32(out, t.version);
    put_le32(out, static_cast<uint32_t>(t.entries.size()));
    for (const Entry& e : t.entries) {
        put_le32(out, e.chipset);
        put_le32(out, e.platform);
        if (t.version >= 2) put_le32(out, e.subtype);
        put_le32(out, e.revision);
        if (t.version >= 3)
            for (const uint32_t p : e.pmic) put_le32(out, p);
        put_le32(out, static_cast<uint32_t>(l.offsets[e.dtb]));
        put_le32(out, static_cast<uint32_t>(l.sizes[e.dtb]));
    }
    out.resize(static_cast<size_t>(l.first), 0);  // the word that ends the table, and the zeros up to the first tree
    for (size_t j = 0; j < t.dtbs.size(); ++j) {
        out.insert(out.end(), t.dtbs[j].begin(), t.dtbs[j].end());
        out.resize(static_cast<size_t>(l.offsets[j] + l.sizes[j]), 0);
    }
    return out;
}

Table parse(const Bytes& data, uint32_t page_hint) {
    if (!looks_like(data) || data.size() < kHeaderSize) throw FormatError("not a QCDT table: it does not start with \"QCDT\", a version and a count");
    const uint32_t version = le32_at(data, 4);
    const size_t es = entry_size(version);
    if (es == 0) throw FormatError("this QCDT table has version " + num(version) + "; abr knows versions 1, 2 and 3");
    const uint32_t count = le32_at(data, 8);
    if (count == 0) throw FormatError("the QCDT table has no entries");
    if (count > kMaxEntries) throw FormatError("the QCDT table says it has " + num(count) + " entries (abr takes " + num(kMaxEntries) + " at most)");
    const uint64_t table_end = kHeaderSize + uint64_t(es) * count + 4;
    if (table_end > data.size())
        throw FormatError("the QCDT table says it has " + num(count) + " entries of " + num(es) + " bytes, and the file is " + num(data.size()) +
                          " bytes");

    struct Raw {
        Chip chip;
        uint64_t offset = 0;
        uint64_t size = 0;
    };
    std::vector<Raw> raw(count);
    size_t at = kHeaderSize;
    const auto word = [&] {
        const uint32_t v = le32_at(data, at);
        at += 4;
        return v;
    };
    for (Raw& r : raw) {
        r.chip.chipset = word();
        r.chip.platform = word();
        if (version >= 2) r.chip.subtype = word();
        r.chip.revision = word();
        if (version >= 3)
            for (uint32_t& p : r.chip.pmic) p = word();
        r.offset = word();
        r.size = word();
    }

    // The trees, in the order they are in the file (an entry says where; several may say the same).
    std::map<uint64_t, uint64_t> trees;  // offset -> size
    for (size_t i = 0; i < raw.size(); ++i) {
        const auto [it, fresh] = trees.emplace(raw[i].offset, raw[i].size);
        if (!fresh && it->second != raw[i].size)
            throw FormatError("entries are for the tree at offset " + hex(raw[i].offset) + " and give it two sizes (" + num(it->second) + " and " +
                              num(raw[i].size) + " bytes)");
    }
    std::vector<uint64_t> offsets, sizes, lengths;
    uint64_t common = 0;
    uint64_t previous_end = 0;
    for (const auto& [offset, size] : trees) {
        const std::string where = "the tree at offset " + hex(offset);
        if (size == 0) throw FormatError(where + " has size 0");
        if (offset < table_end) throw FormatError(where + " is inside the table, which ends at " + hex(table_end));
        if (offset + size > data.size())
            throw FormatError(where + " and its " + num(size) + " bytes run past the end of the file (" + num(data.size()) + " bytes)");
        if (!offsets.empty() && offset < previous_end)
            throw FormatError(where + " overlaps the one before it, which ends at " + hex(previous_end));
        previous_end = offset + size;
        if (size < kFdtHeaderSize || be32_at(data, static_cast<size_t>(offset)) != kFdtMagic)
            throw FormatError("there is no device tree at offset " + hex(offset) + " (it does not start with d0 0d fe ed)");
        const uint32_t total = be32_at(data, static_cast<size_t>(offset) + 4);
        if (total < kFdtHeaderSize || total > size)
            throw FormatError(where + " says in its own header that it is " + num(total) + " bytes, and the table gives it " + num(size));
        offsets.push_back(offset);
        sizes.push_back(size);
        lengths.push_back(total);
        common = std::gcd(std::gcd(common, offset), size);
    }

    // The page size is not in the table; the layout is what tells it.
    for (const uint32_t page : page_candidates(common, page_hint)) {
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
            Entry e;
            static_cast<Chip&>(e) = r.chip;
            e.dtb = index.at(r.offset);
            t.entries.push_back(e);
        }
        // What is left of what dtbTool writes is the zeros: the word that ends the table and its fill, the padding of every tree.
        const Bytes again = build(t);
        for (size_t i = 0; i < again.size(); ++i) {
            if (again[i] == data[i]) continue;
            if (i >= table_end - 4 && i < l.first)
                throw FormatError("the end of the table (the word of zeros and the zeros up to the first tree, at offset " + hex(l.first) +
                                  ") is not zeros: offset " + hex(i) + " holds " + hex(data[i]) + "; dtbTool does not write that");
            size_t tree = 0;
            while (tree + 1 < offsets.size() && i >= offsets[tree + 1]) ++tree;
            throw FormatError("the padding behind the tree at offset " + hex(offsets[tree]) + " is not zeros: offset " + hex(i) + " holds " +
                              hex(data[i]) + "; dtbTool does not write that");
        }
        return t;
    }
    throw FormatError("the trees are not laid out as dtbTool lays them out (one behind the other, the first at the next page behind the table, each "
                      "followed by zeros up to the next page -- a whole page when it ends on one): no page size up to 1 MiB gives these offsets and sizes");
}

std::optional<Tags> chips_of(const fdt::Tree& tree) {
    const fdt::Property* msm = tree.root.find_prop("qcom,msm-id");
    if (msm == nullptr) return std::nullopt;
    const fdt::Property* board = tree.root.find_prop("qcom,board-id");
    const fdt::Property* pmic = tree.root.find_prop("qcom,pmic-id");
    if (pmic != nullptr && board == nullptr)
        throw FormatError("it has qcom,pmic-id and no qcom,board-id (an entry of version 3 is made of the three)");
    Tags tags;
    tags.version = pmic != nullptr ? 3 : board != nullptr ? 2 : 1;
    if (tags.version == 1) {
        std::vector<Chip> made;
        for (const auto& g : groups_of(*msm, 3, "a chipset, a platform and a revision, as there is no qcom,board-id")) {
            Chip c;
            c.chipset = g[0];
            c.platform = g[1];
            c.revision = g[2];
            made.push_back(c);
        }
        tags.chips = dtbtool_order(made);
        return tags;
    }
    const auto ids = dtbtool_order(groups_of(*msm, 2, "a chipset and a revision"));
    const auto boards = dtbtool_order(groups_of(*board, 2, "a platform and a subtype"));
    std::vector<std::vector<uint32_t>> pmic_groups;
    if (pmic != nullptr) pmic_groups = groups_of(*pmic, 4, "four PMIC ids");
    else pmic_groups.push_back({0, 0, 0, 0});
    const auto pmics = dtbtool_order(pmic_groups);
    std::vector<Chip> made;
    for (const auto& id : ids)
        for (const auto& b : boards)
            for (const auto& p : pmics) {
                Chip c;
                c.chipset = id[0];
                c.revision = id[1];
                c.platform = b[0];
                c.subtype = b[1];
                for (size_t k = 0; k < 4; ++k) c.pmic[k] = p[k];
                made.push_back(c);
            }
    tags.chips = dtbtool_order(made);
    return tags;
}

Made make(const std::vector<Source>& sources, const MakeOptions& options) {
    if (options.page_size == 0 || options.page_size > kMaxPageSize)
        throw FormatError("the page size of a QCDT table is from 1 byte to 1 MiB (what dtbTool takes), not " + num(options.page_size));
    if (options.version > 3) throw FormatError("a QCDT table has version 1, 2 or 3, not " + num(options.version));

    struct Item {
        Chip chip;
        size_t source = 0;
    };
    Made made;
    std::vector<Item> items;
    uint32_t need = 1;
    for (size_t s = 0; s < sources.size(); ++s) {
        const std::string what = "the device tree " + quote_shown(sources[s].name);
        check_tree(sources[s].dtb, what);
        std::optional<Tags> tags;
        try {
            tags = chips_of(fdt::parse(sources[s].dtb));
        } catch (const FormatError& e) {
            throw FormatError(what + ": " + e.what());
        }
        if (!tags) {
            made.notes.push_back(quote_shown(sources[s].name) + " is left out: its root node has no qcom,msm-id, so it is not for a board");
            continue;
        }
        need = std::max(need, tags->version);
        for (const Chip& c : tags->chips) items.push_back({c, s});
    }
    if (items.empty())
        throw FormatError(sources.empty() ? "there is no device tree to make a table of"
                                          : "none of the " + num(sources.size()) + " device trees has a qcom,msm-id in its root node, so none is for a board");
    if (items.size() > kMaxEntries)
        throw FormatError("the device trees are for " + num(items.size()) + " boards; a table of more than " + num(kMaxEntries) + " entries is not made");

    const uint32_t version = options.version != 0 ? options.version : need;
    // dtbTool keeps the order of equal boards as the file system lists the files; the order here is the one of the sources.
    std::stable_sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        return std::tie(a.chip.chipset, a.chip.platform, a.chip.subtype, a.chip.revision) <
               std::tie(b.chip.chipset, b.chip.platform, b.chip.subtype, b.chip.revision);
    });
    {
        // The same board twice is the same chip: found by sorting a copy of the places (equal ones come out next to each other).
        std::vector<size_t> by_chip(items.size());
        std::iota(by_chip.begin(), by_chip.end(), size_t{0});
        const auto key = [&](size_t k) {
            const Chip& c = items[k].chip;
            return std::tie(c.chipset, c.platform, c.subtype, c.revision, c.pmic);
        };
        std::sort(by_chip.begin(), by_chip.end(), [&](size_t a, size_t b) { return key(a) != key(b) ? key(a) < key(b) : a < b; });
        for (size_t k = 1; k < by_chip.size(); ++k) {
            const Item& first = items[by_chip[k - 1]];
            const Item& again = items[by_chip[k]];
            if (first.chip != again.chip) continue;
            const std::string a = quote_shown(sources[first.source].name), b = quote_shown(sources[again.source].name);
            throw FormatError((first.source == again.source ? "the device tree " + a + " is for the same board twice"
                                                            : "the device trees " + a + " and " + b + " are for the same board") +
                              " (" + board_text(again.chip, 3) + "); a table has one entry for a board");
        }
    }

    size_t left_subtype = 0, left_pmic = 0;
    std::vector<size_t> index(sources.size(), sources.size());  // the place of a source's tree in the table
    for (const Item& item : items) {
        if (index[item.source] == sources.size()) {
            index[item.source] = made.table.dtbs.size();
            made.table.dtbs.push_back(sources[item.source].dtb);
        }
        Entry e;
        static_cast<Chip&>(e) = item.chip;
        e.dtb = index[item.source];
        if (version < 3 && any_pmic(e)) ++left_pmic;
        if (version < 2 && e.subtype != 0) ++left_subtype;
        if (version < 3) e.pmic = {};
        if (version < 2) e.subtype = 0;
        made.table.entries.push_back(e);
    }
    made.table.version = version;
    made.table.page_size = options.page_size;
    if (left_pmic != 0)
        made.notes.push_back("version " + num(version) + " has no word for the PMIC ids: those of " + num(left_pmic) + " entries are left out");
    if (left_subtype != 0)
        made.notes.push_back("version " + num(version) + " has no word for the subtype: those of " + num(left_subtype) + " entries are left out");
    return made;
}

}  // namespace abr::qcdt
