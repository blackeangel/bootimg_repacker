// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr::qcdt (include/abr/qcdt.hpp), the Qualcomm device tree table. Run by tests/run_tests.sh as `abr_unit_tests qcdt`.
//
//   * the bytes of a table of version 1, 2 and 3, written here again from the description of the format (the words of the header and of the
//     entries, the word of zeros that ends the table, every tree at the next page and padded to the next page -- a whole page when it ends on one)
//     for page sizes from 1 byte to 4096, trees that end on a page and a table that ends on one;
//   * parse() of what build() wrote is the table: random tables (entries that share a tree, every version), the page size found alone, from a right
//     hint and from a wrong one, bytes behind the table left alone;
//   * what parse() and build() refuse, and say (a header that is cut, a version, entries that run past the file, trees that overlap, a tree that is
//     none, a size that is not the tree's own, padding that is not zeros, a layout that is not dtbTool's, an entry for no tree, a subtype or a PMIC id
//     where there is no word for it);
//   * a table that is cut anywhere or has a byte changed anywhere is a FormatError or a table that build() writes again byte for byte;
//   * chips_of(): the version a tree needs, the groups of each property and the order dtbTool has their combinations in, what it refuses;
//   * make(): the entries sorted as dtbTool sorts them, a tree for several boards stored once, a version that is forced, a tree that is not for a
//     board left out and told, the same board twice refused.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/fdt.hpp"
#include "abr/manifest.hpp"
#include "abr/qcdt.hpp"

using namespace abr;

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

// `call` throws a FormatError whose text says `needle`.
#define EXPECT_REFUSES(call, needle)                                                                                                      \
    do {                                                                                                                                  \
        ++g_checks;                                                                                                                       \
        try {                                                                                                                             \
            (void)(call);                                                                                                                 \
            ++g_failures;                                                                                                                 \
            std::printf("  FAIL %s:%d: not refused: %s\n", __FILE__, __LINE__, #call);                                                  \
        } catch (const FormatError& e_) {                                                                                                 \
            if (std::string(e_.what()).find(needle) == std::string::npos) {                                                              \
                ++g_failures;                                                                                                             \
                std::printf("  FAIL %s:%d: %s: refused with \"%s\", which does not say \"%s\"\n", __FILE__, __LINE__, #call, e_.what(), needle); \
            }                                                                                                                             \
        }                                                                                                                                 \
    } while (0)

bool contains(const std::string& text, const std::string& what) { return text.find(what) != std::string::npos; }

uint32_t le32(const Bytes& d, size_t at) {
    return uint32_t{d[at]} | (uint32_t{d[at + 1]} << 8) | (uint32_t{d[at + 2]} << 16) | (uint32_t{d[at + 3]} << 24);
}

// ------------------------------------------------------------------------------------------------------------------------------ trees --

fdt::Property prop(const std::string& name, const Bytes& value) {
    fdt::Property p;
    p.name = name;
    p.value = value;
    return p;
}

Bytes cells(const std::vector<uint32_t>& words) {
    Bytes b;
    for (const uint32_t w : words)
        for (int i = 3; i >= 0; --i) b.push_back(static_cast<uint8_t>(w >> (8 * i)));
    return b;
}

// A tree whose root has the properties of a board (an empty list: the property is not there).
fdt::Tree tree_of(const std::vector<uint32_t>& msm, const std::vector<uint32_t>& board = {}, const std::vector<uint32_t>& pmic = {}) {
    fdt::Tree t;
    t.root.props.push_back(prop("model", {'t', 'e', 's', 't', 0}));
    if (!msm.empty()) t.root.props.push_back(prop("qcom,msm-id", cells(msm)));
    if (!board.empty()) t.root.props.push_back(prop("qcom,board-id", cells(board)));
    if (!pmic.empty()) t.root.props.push_back(prop("qcom,pmic-id", cells(pmic)));
    return t;
}

Bytes blob(const fdt::Tree& t) { return fdt::build(t); }

// The blob of `t`, `size` bytes long (free space behind the strings makes up the difference: it is part of `totalsize`).
Bytes blob_of_size(const fdt::Tree& t, size_t size) {
    const size_t base = fdt::build(t).size();
    return fdt::build(t, size > base ? size - base : 0);
}

// ----------------------------------------------------------------------------------------------------------- the format, written again --

struct Item {
    uint32_t chipset = 0, platform = 0, subtype = 0, revision = 0;
    std::array<uint32_t, 4> pmic{};
    size_t tree = 0;
};

// The next multiple of `page` -- a whole page further when `v` is one already.
uint64_t next_page(uint64_t v, uint64_t page) { return (v / page + 1) * page; }

Bytes expected(uint32_t version, uint32_t page, const std::vector<Item>& items, const std::vector<Bytes>& trees) {
    Bytes out;
    const auto word = [&](uint64_t v) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    const size_t words = version == 1 ? 5 : version == 2 ? 6 : 10;
    const uint64_t table_end = 12 + 4 * words * items.size() + 4;
    std::vector<uint64_t> at, size;
    uint64_t cursor = next_page(table_end, page);
    for (const Bytes& t : trees) {
        at.push_back(cursor);
        size.push_back(next_page(t.size(), page));
        cursor += size.back();
    }
    for (const char c : std::string("QCDT")) out.push_back(static_cast<uint8_t>(c));
    word(version);
    word(items.size());
    for (const Item& e : items) {
        word(e.chipset);
        word(e.platform);
        if (version >= 2) word(e.subtype);
        word(e.revision);
        if (version >= 3)
            for (const uint32_t p : e.pmic) word(p);
        word(at[e.tree]);
        word(size[e.tree]);
    }
    out.resize(static_cast<size_t>(next_page(table_end, page)), 0);
    for (size_t j = 0; j < trees.size(); ++j) {
        out.insert(out.end(), trees[j].begin(), trees[j].end());
        out.resize(static_cast<size_t>(at[j] + size[j]), 0);
    }
    return out;
}

qcdt::Table table_of(uint32_t version, uint32_t page, const std::vector<Item>& items, const std::vector<Bytes>& trees) {
    qcdt::Table t;
    t.version = version;
    t.page_size = page;
    t.dtbs = trees;
    for (const Item& i : items) {
        qcdt::Entry e;
        e.chipset = i.chipset;
        e.platform = i.platform;
        e.subtype = i.subtype;
        e.revision = i.revision;
        e.pmic = i.pmic;
        e.dtb = i.tree;
        t.entries.push_back(e);
    }
    return t;
}

bool same_table(const qcdt::Table& a, const qcdt::Table& b, bool with_page = true) {
    if (a.version != b.version || (with_page && a.page_size != b.page_size) || a.dtbs != b.dtbs || a.entries.size() != b.entries.size()) return false;
    for (size_t i = 0; i < a.entries.size(); ++i)
        if (!(a.entries[i] == b.entries[i])) return false;
    return true;
}

// Items for a table of `version` (the words a version has no place for stay zero).
std::vector<Item> items_for(uint32_t version, size_t n, size_t trees, uint32_t seed) {
    std::mt19937 rnd(seed);
    std::vector<Item> items(n);
    for (size_t i = 0; i < n; ++i) {
        Item& e = items[i];
        e.chipset = 0x100 + static_cast<uint32_t>(rnd() % 0x300);
        e.platform = static_cast<uint32_t>(rnd() % 20);
        if (version >= 2) e.subtype = static_cast<uint32_t>(rnd() % 8);
        e.revision = static_cast<uint32_t>(rnd() % 4) << 16;
        if (version >= 3)
            for (uint32_t& p : e.pmic) p = static_cast<uint32_t>(rnd() % 100);
        e.tree = i < trees ? i : rnd() % trees;  // every tree has an entry
    }
    return items;
}

std::vector<Bytes> trees_for(size_t n, uint32_t seed, size_t smallest = 150, size_t span = 700) {
    std::mt19937 rnd(seed);
    std::vector<Bytes> out;
    for (size_t j = 0; j < n; ++j) out.push_back(blob_of_size(tree_of({0x100 + static_cast<uint32_t>(j), 8, 0x10000}), smallest + rnd() % span));
    return out;
}

// ------------------------------------------------------------------------------------------------------------------------------ layout --

void test_layout() {
    // numbers worked out by hand: version 2, two entries, the page of 2048
    {
        const std::vector<Bytes> trees = {blob_of_size(tree_of({0x100, 0x10000}), 300), blob_of_size(tree_of({0x101, 0x10000}), 2048)};
        std::vector<Item> items(2);
        items[0] = {0x100, 8, 1, 0x10000, {}, 0};
        items[1] = {0x101, 9, 0, 0x10000, {}, 1};
        const Bytes built = qcdt::build(table_of(2, 2048, items, trees));
        // the table is 12 + 2 * 24 + 4 = 64 bytes; the first tree is at 2048, 2048 bytes with its padding; the second ends on a page and gets a whole one more
        EXPECT(built.size() == 2048 + 2048 + 4096);
        EXPECT(built[0] == 'Q' && built[1] == 'C' && built[2] == 'D' && built[3] == 'T');
        EXPECT(le32(built, 4) == 2 && le32(built, 8) == 2);
        EXPECT(le32(built, 12 + 4 * 4) == 2048 && le32(built, 12 + 5 * 4) == 2048);       // entry 0: offset, size
        EXPECT(le32(built, 12 + 6 * 4 + 4 * 4) == 4096 && le32(built, 12 + 6 * 4 + 5 * 4) == 4096);  // entry 1
        EXPECT(le32(built, 60) == 0);                                                       // the word that ends the table
        EXPECT(std::equal(trees[0].begin(), trees[0].end(), built.begin() + 2048));
        EXPECT(std::equal(trees[1].begin(), trees[1].end(), built.begin() + 4096));
        EXPECT(built == expected(2, 2048, items, trees));
    }
    // every version, several page sizes
    for (uint32_t version = 1; version <= 3; ++version) {
        for (const uint32_t page : {1u, 36u, 512u, 1000u, 2048u, 4096u}) {
            const std::vector<Bytes> trees = trees_for(3, 7 + version + page);
            const std::vector<Item> items = items_for(version, 5, 3, 11 + version);
            const qcdt::Table t = table_of(version, page, items, trees);
            const Bytes built = qcdt::build(t);
            EXPECT(built == expected(version, page, items, trees));
            const qcdt::Table back = qcdt::parse(built, page);
            EXPECT(same_table(back, t));
            EXPECT(back.consumed == built.size());
        }
    }
    // a tree that ends on a page gets a whole page of zeros behind it (dtbTool does), at several page sizes
    for (const uint32_t page : {512u, 1024u, 4096u}) {
        const std::vector<Bytes> trees = {blob_of_size(tree_of({0x100, 8, 0x10000}), page), blob_of_size(tree_of({0x101, 8, 0x10000}), 2 * page)};
        const std::vector<Item> items = items_for(1, 2, 2, 5);
        const Bytes built = qcdt::build(table_of(1, page, items, trees));
        EXPECT(built == expected(1, page, items, trees));
        EXPECT(built.size() == next_page(12 + 2 * 20 + 4, page) + 2 * page + 3 * page);
        EXPECT(same_table(qcdt::parse(built, page), table_of(1, page, items, trees)));
    }
    // a table that ends on a page gets a whole page of zeros behind it, too
    for (uint32_t version = 1; version <= 3; ++version) {
        const std::vector<Item> items = items_for(version, 3, 1, 9);
        const uint32_t page = static_cast<uint32_t>(12 + qcdt::entry_size(version) * 3 + 4);
        const std::vector<Bytes> trees = trees_for(1, 3);
        const Bytes built = qcdt::build(table_of(version, page, items, trees));
        EXPECT(built == expected(version, page, items, trees));
        EXPECT(le32(built, 12 + 3 * qcdt::entry_size(version) - 8) == 2 * page);  // the offset in the last entry: two pages in
        EXPECT(same_table(qcdt::parse(built, page), table_of(version, page, items, trees)));
    }
    EXPECT(qcdt::entry_size(0) == 0 && qcdt::entry_size(1) == 20 && qcdt::entry_size(2) == 24 && qcdt::entry_size(3) == 40 && qcdt::entry_size(4) == 0);
}

// ------------------------------------------------------------------------------------------------------------------------ round trips --

void test_roundtrip() {
    std::mt19937 rnd(20261112);
    const uint32_t pages[] = {512, 1024, 2048, 4096, 8192, 16384, 100, 36, 1};
    for (int round = 0; round < 300; ++round) {
        const uint32_t version = 1 + static_cast<uint32_t>(rnd() % 3);
        const uint32_t page = pages[rnd() % (sizeof pages / sizeof pages[0])];
        const size_t ntrees = 1 + rnd() % 4;
        const size_t nitems = ntrees + rnd() % 6;
        const std::vector<Bytes> trees = trees_for(ntrees, static_cast<uint32_t>(rnd()), 130, 900);
        const std::vector<Item> items = items_for(version, nitems, ntrees, static_cast<uint32_t>(rnd()));
        const qcdt::Table t = table_of(version, page, items, trees);
        const Bytes built = qcdt::build(t);
        EXPECT(built == expected(version, page, items, trees));

        const qcdt::Table with_hint = qcdt::parse(built, page);
        EXPECT(same_table(with_hint, t));
        EXPECT(with_hint.consumed == built.size());
        // with no hint, or a wrong one, the table that comes out is one that builds the same bytes (another page size gives the same layout now and then)
        for (const uint32_t hint : {0u, page + 7u, 3u}) {
            const qcdt::Table other = qcdt::parse(built, hint);
            EXPECT(same_table(other, t, false));
            EXPECT(qcdt::build(other) == built);
        }
        // what follows the table is the caller's
        Bytes longer = built;
        for (int k = 0; k < 100; ++k) longer.push_back(static_cast<uint8_t>(0xA0 + k));
        const qcdt::Table with_tail = qcdt::parse(longer, page);
        EXPECT(with_tail.consumed == built.size());
        EXPECT(same_table(with_tail, t));
    }
}

// -------------------------------------------------------------------------------------------------------------------------- refusals --

void put_word(Bytes& b, size_t at, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) b[at + i] = static_cast<uint8_t>(v >> (8 * i));
}

void test_parse_refusals() {
    // a good table: version 2, two entries for two trees (padded to one page and to two), the page of 2048
    const std::vector<Bytes> trees = {blob_of_size(tree_of({0x100, 0x10000}), 300), blob_of_size(tree_of({0x101, 0x10000}), 2500)};
    std::vector<Item> items(2);
    items[0] = {0x100, 8, 1, 0x10000, {}, 0};
    items[1] = {0x101, 9, 0, 0x10000, {}, 1};
    const Bytes good = qcdt::build(table_of(2, 2048, items, trees));
    EXPECT(qcdt::looks_like(good));
    EXPECT(qcdt::parse(good).entries.size() == 2);

    const size_t e0 = 12, e1 = 12 + 24;  // the entries; in each the offset is the 5th word and the size the 6th
    EXPECT(!qcdt::looks_like(Bytes()));
    EXPECT(!qcdt::looks_like(Bytes(100, 0)));
    EXPECT_REFUSES(qcdt::parse(Bytes()), "not a QCDT table");
    EXPECT_REFUSES(qcdt::parse(Bytes(100, 0)), "not a QCDT table");
    EXPECT_REFUSES(qcdt::parse(Bytes{'Q', 'C', 'D', 'T', 2, 0}), "not a QCDT table");

    Bytes b = good;
    put_word(b, 4, 0);
    EXPECT_REFUSES(qcdt::parse(b), "version 0");
    put_word(b, 4, 4);
    EXPECT_REFUSES(qcdt::parse(b), "version 4");
    b = good;
    put_word(b, 8, 0);
    EXPECT_REFUSES(qcdt::parse(b), "no entries");
    put_word(b, 8, 1u << 20);
    EXPECT_REFUSES(qcdt::parse(b), "at most");
    put_word(b, 8, 3);  // three entries, the table has two: what follows them is read as the third, and it is all zeros -- a tree of size 0
    EXPECT_REFUSES(qcdt::parse(b), "has size 0");
    b = good;
    b.resize(40);
    EXPECT_REFUSES(qcdt::parse(b), "says it has 2 entries");

    b = good;
    put_word(b, e0 + 16, 20);  // a tree inside the table
    EXPECT_REFUSES(qcdt::parse(b), "inside the table");
    b = good;
    put_word(b, e0 + 20, static_cast<uint32_t>(good.size()));  // a size that runs past the file
    EXPECT_REFUSES(qcdt::parse(b), "run past the end of the file");
    b = good;
    put_word(b, e0 + 20, 0);
    EXPECT_REFUSES(qcdt::parse(b), "size 0");
    b = good;
    b[2048] ^= 0xFF;  // the magic of the first tree
    EXPECT_REFUSES(qcdt::parse(b), "there is no device tree at offset 0x800");
    b = good;
    put_word(b, e0 + 20, 100);  // smaller than the totalsize in the header of the tree
    EXPECT_REFUSES(qcdt::parse(b), "says in its own header");
    b = good;
    put_word(b, e1 + 16, le32(good, e0 + 16));  // two entries, one tree, two sizes
    EXPECT_REFUSES(qcdt::parse(b), "two sizes");
    b = good;
    put_word(b, e1 + 16, le32(good, e0 + 16) + 512);  // the second tree starts inside the first
    EXPECT_REFUSES(qcdt::parse(b), "overlaps");

    b = good;
    b[60 + 1] = 1;  // the zeros that end the table
    EXPECT_REFUSES(qcdt::parse(b), "is not zeros");
    b = good;
    b[1000] = 1;    // between the word that ends the table and the first tree
    EXPECT_REFUSES(qcdt::parse(b), "is not zeros");
    b = good;
    b[2048 + trees[0].size() + 3] = 1;  // the padding behind the first tree
    EXPECT_REFUSES(qcdt::parse(b), "padding behind the tree at offset 0x800");
    b = good;
    b[good.size() - 1] = 1;
    EXPECT_REFUSES(qcdt::parse(b), "padding behind the tree");

    // trees that are not one behind the other: a gap of a page between them, entries and sizes made to fit
    b = good;
    b.insert(b.begin() + 2048 + 2048, 2048, 0);
    put_word(b, e1 + 16, 2048 + 2048 + 2048);
    EXPECT_REFUSES(qcdt::parse(b), "not laid out as dtbTool lays them out");
    // a size that is not a multiple of any page that fits the offsets
    b = good;
    put_word(b, e0 + 20, le32(good, e0 + 20) + 1);
    EXPECT_REFUSES(qcdt::parse(b), "overlaps");
}

void test_build_refusals() {
    const Bytes tree1 = blob_of_size(tree_of({0x100, 0x10000}), 300), tree2 = blob_of_size(tree_of({0x101, 0x10000}), 300);
    const std::vector<Item> one = items_for(1, 1, 1, 3);
    qcdt::Table t = table_of(1, 2048, one, {tree1});
    EXPECT(qcdt::build(t).size() == 4096);

    qcdt::Table bad = t;
    bad.version = 0;
    EXPECT_REFUSES(qcdt::build(bad), "version 1, 2 or 3, not 0");
    bad.version = 4;
    EXPECT_REFUSES(qcdt::build(bad), "version 1, 2 or 3, not 4");
    bad = t;
    bad.page_size = 0;
    EXPECT_REFUSES(qcdt::build(bad), "from 1 byte to 1 MiB");
    bad.page_size = qcdt::kMaxPageSize + 1;
    EXPECT_REFUSES(qcdt::build(bad), "from 1 byte to 1 MiB");
    bad = t;
    bad.page_size = qcdt::kMaxPageSize;
    EXPECT(qcdt::build(bad).size() == 2 * size_t{qcdt::kMaxPageSize});  // (a page for the table, a page for the tree: the page size at the top of what is allowed)
    bad = t;
    bad.entries.clear();
    EXPECT_REFUSES(qcdt::build(bad), "at least one entry");
    bad = t;
    bad.dtbs.clear();
    EXPECT_REFUSES(qcdt::build(bad), "at least one device tree");
    bad = t;
    bad.entries[0].dtb = 1;
    EXPECT_REFUSES(qcdt::build(bad), "entry 0 is for device tree 1, and the table has 1");
    bad = t;
    bad.dtbs.push_back(tree2);  // no entry for the second tree
    EXPECT_REFUSES(qcdt::build(bad), "device tree 1 is for no entry");
    bad = t;
    bad.entries[0].subtype = 3;  // version 1 has no word for it
    EXPECT_REFUSES(qcdt::build(bad), "no word for it");
    bad = t;
    bad.version = 2;
    bad.entries[0].pmic[2] = 9;
    EXPECT_REFUSES(qcdt::build(bad), "PMIC id");
    bad.version = 3;
    EXPECT(qcdt::build(bad).size() == 4096);  // a version 3 table has the word

    bad = t;
    bad.dtbs[0][0] ^= 0xFF;
    EXPECT_REFUSES(qcdt::build(bad), "not a flattened device tree");
    bad = t;
    bad.dtbs[0].resize(30);
    EXPECT_REFUSES(qcdt::build(bad), "cut short");
    bad = t;
    bad.dtbs[0].push_back(0);  // a byte behind the tree: the size of the file is not the totalsize
    EXPECT_REFUSES(qcdt::build(bad), "totalsize");
    bad = t;
    bad.dtbs[0].resize(bad.dtbs[0].size() - 1);
    EXPECT_REFUSES(qcdt::build(bad), "totalsize");

    // too many entries
    bad = t;
    bad.entries.assign(size_t{kMaxEntries} + 1, t.entries[0]);
    EXPECT_REFUSES(qcdt::build(bad), "more than abr makes");
}

// ------------------------------------------------------------------------------------------------------------------------------ damage --

void test_damage() {
    const std::vector<Bytes> trees = trees_for(2, 77, 120, 200);
    const std::vector<Item> items = items_for(3, 4, 2, 5);
    const Bytes good = qcdt::build(table_of(3, 512, items, trees));
    const auto judge = [&](const Bytes& data) {
        try {
            const qcdt::Table t = qcdt::parse(data);
            EXPECT(t.consumed <= data.size());
            EXPECT(qcdt::build(t) == Bytes(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(t.consumed)));
        } catch (const FormatError&) {
            ++g_checks;  // a refusal is as good
        }
    };
    for (size_t at = 0; at < good.size(); ++at) {
        for (const uint8_t flip : {uint8_t{0x01}, uint8_t{0x80}, uint8_t{0xFF}}) {
            Bytes bad = good;
            bad[at] ^= flip;
            judge(bad);
        }
    }
    for (size_t cut = 0; cut < good.size(); cut += 3) judge(Bytes(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(cut)));
}

// ---------------------------------------------------------------------------------------------------------------------------- chips_of --

// The order dtbTool has a list of n things in: the first, then the others from the last to the second.
std::vector<size_t> dtbtool_order(size_t n) {
    std::vector<size_t> out;
    if (n == 0) return out;
    out.push_back(0);
    for (size_t i = n - 1; i >= 1; --i) out.push_back(i);
    return out;
}

void test_chips() {
    // not for a board
    EXPECT(!qcdt::chips_of(tree_of({})).has_value());
    {  // version 1: qcom,msm-id = <chipset platform revision>
        const auto tags = qcdt::chips_of(tree_of({0x100, 8, 0x10000}));
        EXPECT(tags && tags->version == 1 && tags->chips.size() == 1);
        EXPECT(tags && tags->chips[0].chipset == 0x100 && tags->chips[0].platform == 8 && tags->chips[0].revision == 0x10000 && tags->chips[0].subtype == 0);
        // three groups: the first, then the last, then the second
        const auto t3 = qcdt::chips_of(tree_of({1, 10, 100, 2, 20, 200, 3, 30, 300}));
        EXPECT(t3 && t3->chips.size() == 3);
        if (t3 && t3->chips.size() == 3) {
            EXPECT(t3->chips[0].chipset == 1 && t3->chips[1].chipset == 3 && t3->chips[2].chipset == 2);
            EXPECT(t3->chips[1].platform == 30 && t3->chips[1].revision == 300);
        }
    }
    {  // version 2: qcom,msm-id = <chipset revision>, qcom,board-id = <platform subtype>
        const auto tags = qcdt::chips_of(tree_of({0x100, 0x10000}, {8, 1}));
        EXPECT(tags && tags->version == 2 && tags->chips.size() == 1);
        EXPECT(tags && tags->chips[0].chipset == 0x100 && tags->chips[0].revision == 0x10000 && tags->chips[0].platform == 8 && tags->chips[0].subtype == 1);
        // two ids, two boards: four boards; the groups in dtbTool's order, the msm-id outermost, then the same order for the whole list
        const auto four = qcdt::chips_of(tree_of({1, 0xA, 2, 0xB}, {7, 70, 8, 80}));
        EXPECT(four && four->chips.size() == 4);
        if (four && four->chips.size() == 4) {
            const std::array<uint32_t, 2> ids[2] = {{1, 0xA}, {2, 0xB}};
            const std::array<uint32_t, 2> boards[2] = {{7, 70}, {8, 80}};
            std::vector<std::array<uint32_t, 4>> made;  // chipset, revision, platform, subtype
            for (const size_t i : dtbtool_order(2))
                for (const size_t j : dtbtool_order(2)) made.push_back({ids[i][0], ids[i][1], boards[j][0], boards[j][1]});
            const std::vector<size_t> order = dtbtool_order(made.size());
            for (size_t k = 0; k < 4; ++k) {
                const auto& want = made[order[k]];
                const qcdt::Chip& got = four->chips[k];
                EXPECT(got.chipset == want[0] && got.revision == want[1] && got.platform == want[2] && got.subtype == want[3]);
            }
        }
    }
    {  // version 3: and qcom,pmic-id = <four ids>
        const auto tags = qcdt::chips_of(tree_of({0x100, 0x10000}, {8, 1}, {0x10, 0x20, 0x30, 0x40}));
        EXPECT(tags && tags->version == 3 && tags->chips.size() == 1);
        EXPECT((tags && tags->chips[0].pmic == std::array<uint32_t, 4>{0x10, 0x20, 0x30, 0x40}));
        // three PMIC groups for one board: three boards that differ in the PMIC ids, in dtbTool's order (twice: the list, then the whole)
        const auto three = qcdt::chips_of(tree_of({0x100, 0x10000}, {8, 1}, {1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3}));
        EXPECT(three && three->chips.size() == 3);
        if (three && three->chips.size() == 3) {
            std::vector<uint32_t> pm;
            for (const size_t i : dtbtool_order(3)) pm.push_back(static_cast<uint32_t>(i + 1));  // the order of the list: 1, 3, 2
            std::vector<uint32_t> second;
            for (const size_t i : dtbtool_order(3)) second.push_back(pm[i]);                    // and again for the whole list: 1, 2, 3
            for (size_t k = 0; k < 3; ++k) EXPECT(three->chips[k].pmic[0] == second[k]);
        }
        // the number of boards is the product of the groups
        const auto many = qcdt::chips_of(tree_of({1, 1, 2, 2, 3, 3}, {4, 4, 5, 5}, {1, 2, 3, 4, 5, 6, 7, 8}));
        EXPECT(many && many->version == 3 && many->chips.size() == 3 * 2 * 2);
    }
    // what is refused, and what it says
    EXPECT_REFUSES(qcdt::chips_of(tree_of({0x100, 0x10000}, {}, {1, 2, 3, 4})), "qcom,pmic-id and no qcom,board-id");
    {
        fdt::Tree t = tree_of({});
        t.root.props.push_back(prop("qcom,msm-id", Bytes{0, 0, 1}));  // not whole cells
        EXPECT_REFUSES(qcdt::chips_of(t), "multiple of 4");
        t = tree_of({});
        t.root.props.push_back(prop("qcom,msm-id", Bytes()));  // no group
        EXPECT_REFUSES(qcdt::chips_of(t), "is empty");
    }
    EXPECT_REFUSES(qcdt::chips_of(tree_of({1, 2, 3, 4})), "groups of 3");
    EXPECT_REFUSES(qcdt::chips_of(tree_of({1, 2, 3}, {5, 6, 7})), "groups of 2");
}

// ------------------------------------------------------------------------------------------------------------------------------ make --

qcdt::Source source(const std::string& name, const fdt::Tree& t) { return {name, blob(t)}; }

void test_make() {
    {  // three trees; entries sorted by chipset, platform, subtype, revision; the trees in the order of the first entry that has them
        const std::vector<qcdt::Source> sources = {
            source("c.dtb", tree_of({0x300, 0x10000}, {9, 0})),
            source("a.dtb", tree_of({0x100, 0x10000, 0x100, 0x20000}, {8, 1})),  // two ids: two boards, one tree
            source("b.dtb", tree_of({0x200, 0x10000}, {1, 5})),
        };
        const qcdt::Made m = qcdt::make(sources);
        EXPECT(m.table.version == 2 && m.table.page_size == 2048);
        EXPECT(m.notes.empty());
        EXPECT(m.table.entries.size() == 4);
        EXPECT(m.table.dtbs.size() == 3);  // the tree for two boards is there once
        if (m.table.entries.size() == 4 && m.table.dtbs.size() == 3) {
            const uint32_t want_chipsets[4] = {0x100, 0x100, 0x200, 0x300};
            for (size_t i = 0; i < 4; ++i) EXPECT(m.table.entries[i].chipset == want_chipsets[i]);
            EXPECT(m.table.entries[0].revision == 0x10000 && m.table.entries[1].revision == 0x20000);  // (equal but for the revision: sorted by it)
            EXPECT(m.table.entries[0].dtb == m.table.entries[1].dtb);
            EXPECT(m.table.dtbs[0] == sources[1].dtb && m.table.dtbs[1] == sources[2].dtb && m.table.dtbs[2] == sources[0].dtb);
            EXPECT(m.table.entries[0].dtb == 0 && m.table.entries[2].dtb == 1 && m.table.entries[3].dtb == 2);
            EXPECT(m.table.entries[0].platform == 8 && m.table.entries[0].subtype == 1);
        }
        // what comes out is a table that parses and builds again
        const Bytes built = qcdt::build(m.table);
        EXPECT(same_table(qcdt::parse(built, m.table.page_size), m.table));
    }
    {  // the version is the highest the trees need; a forced version leaves out what it has no word for, and says so
        const std::vector<qcdt::Source> sources = {source("a", tree_of({0x100, 0x10000}, {8, 1}, {1, 2, 3, 4})), source("b", tree_of({0x200, 0x10000}, {8, 2}))};
        const qcdt::Made m = qcdt::make(sources);
        EXPECT(m.table.version == 3);
        qcdt::MakeOptions two;
        two.version = 2;
        const qcdt::Made m2 = qcdt::make(sources, two);
        EXPECT(m2.table.version == 2);
        EXPECT((m2.table.entries.size() == 2 && m2.table.entries[0].pmic == std::array<uint32_t, 4>{}));
        EXPECT(m2.notes.size() == 1 && contains(m2.notes[0], "PMIC"));
        qcdt::MakeOptions one;
        one.version = 1;
        const qcdt::Made m1 = qcdt::make(sources, one);
        EXPECT(m1.table.version == 1 && m1.notes.size() == 2);
        EXPECT(m1.table.entries.size() == 2 && m1.table.entries[0].subtype == 0);
        EXPECT(qcdt::build(m1.table).size() > 0);
        // the page size
        qcdt::MakeOptions page;
        page.page_size = 4096;
        EXPECT(qcdt::make(sources, page).table.page_size == 4096);
        const Bytes built = qcdt::build(qcdt::make(sources, page).table);
        EXPECT(built.size() % 4096 == 0);
    }
    {  // a tree that is not for a board is left out and told; one for a board that is there only is enough
        const std::vector<qcdt::Source> sources = {source("plain.dtb", tree_of({})), source("board.dtb", tree_of({0x100, 8, 0x10000}))};
        const qcdt::Made m = qcdt::make(sources);
        EXPECT(m.table.entries.size() == 1 && m.table.dtbs.size() == 1 && m.table.version == 1);
        EXPECT(m.notes.size() == 1 && contains(m.notes[0], "plain.dtb") && contains(m.notes[0], "qcom,msm-id"));
    }
    // what is refused
    EXPECT_REFUSES(qcdt::make({}), "no device tree");
    EXPECT_REFUSES(qcdt::make({source("plain.dtb", tree_of({}))}), "none of the 1 device trees has a qcom,msm-id");
    {
        qcdt::MakeOptions bad;
        bad.page_size = 0;
        EXPECT_REFUSES(qcdt::make({source("a", tree_of({1, 2, 3}))}, bad), "from 1 byte to 1 MiB");
        bad.page_size = 2048;
        bad.version = 4;
        EXPECT_REFUSES(qcdt::make({source("a", tree_of({1, 2, 3}))}, bad), "version 1, 2 or 3");
    }
    {  // the same board twice: in one tree, in two
        EXPECT_REFUSES(qcdt::make({source("twice.dtb", tree_of({1, 2, 3, 1, 2, 3}))}), "is for the same board twice");
        EXPECT_REFUSES(qcdt::make({source("a.dtb", tree_of({1, 2, 3})), source("b.dtb", tree_of({1, 2, 3}))}), "are for the same board");
        // boards that differ in the PMIC ids only are two boards
        const qcdt::Made m = qcdt::make({source("a.dtb", tree_of({1, 2}, {3, 4}, {1, 1, 1, 1})), source("b.dtb", tree_of({1, 2}, {3, 4}, {2, 2, 2, 2}))});
        EXPECT(m.table.entries.size() == 2 && m.table.version == 3);
    }
    {  // a tree that is not one, or is not the size its header says, is refused by name: a board that is missing is worse than a refusal
        Bytes junk(200, 0x42);
        EXPECT_REFUSES(qcdt::make({{"junk.dtb", junk}}), "junk.dtb");
        Bytes longer = blob(tree_of({1, 2, 3}));
        longer.push_back(0);
        EXPECT_REFUSES(qcdt::make({{"long.dtb", longer}}), "totalsize");
        EXPECT_REFUSES(qcdt::make({source("bad.dtb", [] {
                                       fdt::Tree t = tree_of({});
                                       t.root.props.push_back(prop("qcom,msm-id", cells({1, 2, 3, 4})));
                                       return t;
                                   }())}),
                       "bad.dtb");
    }
}

}  // namespace

int run_qcdt_tests() {
    test_layout();
    test_roundtrip();
    test_parse_refusals();
    test_build_refusals();
    test_damage();
    test_chips();
    test_make();
    if (g_failures == 0) std::printf("qcdt: ok (%d checks)\n", g_checks);
    else std::printf("qcdt: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
