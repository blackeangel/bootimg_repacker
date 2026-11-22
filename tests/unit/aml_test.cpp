// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr::aml (include/abr/aml.hpp), the multi-tree container of Amlogic. Run by tests/run_tests.sh as `abr_unit_tests aml`.
//
//   * the header of a real container (the first 124 bytes of the `second` of a TWRP image for an S905X box: two entries, version 2, the boards
//     gxl_p212_1g and gxl_p212_2g, trees of 36670 and 37224 bytes at the page of 2048) is what build() writes for that table, byte for byte, and
//     parse() of a container of those sizes reads the table back;
//   * the bytes of a container of version 1 and 2, written here again from the description of the format (an id is its text and spaces, every word
//     of four characters reversed; the entries; every tree at the next page and padded to the next page) for page sizes from 1 byte to 4096, ids of
//     every length from 0 to the most the version has, trees that end on a page and a table of entries that ends on one;
//   * parse() of what build() wrote is the table: random containers (entries that share a tree, both versions), the page size found alone, from a
//     right hint and from a wrong one, bytes behind the container left alone;
//   * what parse() and build() refuse, and say (a header that is cut, a version, entries that run past the file, an id with a space, a NUL or a
//     byte that is no character in it, trees that overlap, a tree that is none, a size that is not the tree's own, padding that is not zeros, a layout
//     that is not the tool's, an entry for no tree, a tree for no entry);
//   * a container that is cut anywhere or has a byte changed anywhere is a FormatError or a container that build() writes again byte for byte.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

#include "abr/aml.hpp"
#include "abr/byte_io.hpp"
#include "abr/fdt.hpp"

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

uint32_t le32(const Bytes& d, size_t at) {
    return uint32_t{d[at]} | (uint32_t{d[at + 1]} << 8) | (uint32_t{d[at + 2]} << 16) | (uint32_t{d[at + 3]} << 24);
}

void put_word(Bytes& b, size_t at, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) b[at + i] = static_cast<uint8_t>(v >> (8 * i));
}

// ------------------------------------------------------------------------------------------------------------------------------ trees --

// A tree with a model in it, `size` bytes long (free space behind the strings makes up the difference: it is part of `totalsize`).
Bytes blob_of_size(const std::string& model, size_t size) {
    fdt::Tree t;
    fdt::Property p;
    p.name = "model";
    p.value = Bytes(model.begin(), model.end());
    p.value.push_back(0);
    t.root.props.push_back(p);
    const size_t base = fdt::build(t).size();
    return fdt::build(t, size > base ? size - base : 0);
}

// ----------------------------------------------------------------------------------------------------------- the format, written again --

struct Item {
    std::string soc, platform, variant;
    size_t tree = 0;
};

// The next multiple of `page` -- a whole page further when `v` is one already.
uint64_t next_page(uint64_t v, uint64_t page) { return (v / page + 1) * page; }

// An id: the text and spaces up to `length`, the character i of which is at the place that mirrors it inside its word of four (0 3, 1 2, 2 1, 3 0).
void put_id(Bytes& out, const std::string& text, size_t length) {
    std::string chars = text;
    chars.resize(length, ' ');
    for (size_t w = 0; w < length; w += 4)
        for (size_t j = 0; j < 4; ++j) out.push_back(static_cast<uint8_t>(chars[w + 3 - j]));
}

Bytes expected(uint32_t version, uint32_t page, const std::vector<Item>& items, const std::vector<Bytes>& trees) {
    Bytes out;
    const auto word = [&](uint64_t v) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    const size_t idlen = version == 1 ? 4 : 16;
    const uint64_t table_end = 12 + (3 * idlen + 8) * items.size();
    std::vector<uint64_t> at, size;
    uint64_t cursor = next_page(table_end, page);
    for (const Bytes& t : trees) {
        at.push_back(cursor);
        size.push_back(next_page(t.size(), page));
        cursor += size.back();
    }
    for (const char c : std::string("AML_")) out.push_back(static_cast<uint8_t>(c));
    word(version);
    word(items.size());
    for (const Item& e : items) {
        put_id(out, e.soc, idlen);
        put_id(out, e.platform, idlen);
        put_id(out, e.variant, idlen);
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

aml::Table table_of(uint32_t version, uint32_t page, const std::vector<Item>& items, const std::vector<Bytes>& trees) {
    aml::Table t;
    t.version = version;
    t.page_size = page;
    t.dtbs = trees;
    for (const Item& i : items) {
        aml::Entry e;
        e.soc = i.soc;
        e.platform = i.platform;
        e.variant = i.variant;
        e.dtb = i.tree;
        t.entries.push_back(e);
    }
    return t;
}

bool same_table(const aml::Table& a, const aml::Table& b, bool with_page = true) {
    if (a.version != b.version || (with_page && a.page_size != b.page_size) || a.dtbs != b.dtbs || a.entries.size() != b.entries.size()) return false;
    for (size_t i = 0; i < a.entries.size(); ++i)
        if (!(a.entries[i] == b.entries[i])) return false;
    return true;
}

// A text of `n` printable characters that are not spaces.
std::string random_text(std::mt19937& rnd, size_t n) {
    static const char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789_-.ABCXYZ~!";
    std::string s;
    for (size_t i = 0; i < n; ++i) s += kAlphabet[rnd() % (sizeof kAlphabet - 1)];
    return s;
}

std::vector<Item> items_for(uint32_t version, size_t n, size_t trees, uint32_t seed) {
    std::mt19937 rnd(seed);
    const size_t idlen = version == 1 ? 4 : 16;
    std::vector<Item> items(n);
    for (size_t i = 0; i < n; ++i) {
        Item& e = items[i];
        e.soc = random_text(rnd, rnd() % (idlen + 1));
        e.platform = random_text(rnd, rnd() % (idlen + 1));
        e.variant = random_text(rnd, rnd() % (idlen + 1));
        e.tree = i < trees ? i : rnd() % trees;  // every tree has an entry
    }
    return items;
}

std::vector<Bytes> trees_for(size_t n, uint32_t seed, size_t smallest = 150, size_t span = 700) {
    std::mt19937 rnd(seed);
    std::vector<Bytes> out;
    for (size_t j = 0; j < n; ++j) out.push_back(blob_of_size("tree " + std::to_string(j), smallest + rnd() % span));
    return out;
}

// -------------------------------------------------------------------------------------------------------------------- a real container --

void test_real_header() {
    // the first 124 bytes of a real container: the header, and two entries of 56 bytes
    static const uint8_t kReal[124] = {
        0x41, 0x4d, 0x4c, 0x5f, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20, 0x6c, 0x78, 0x67, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x32, 0x31, 0x32, 0x70, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x67, 0x31,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x20, 0x6c, 0x78, 0x67,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x32, 0x31, 0x32, 0x70, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x67, 0x32, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x98, 0x00, 0x00,
        0x00, 0x98, 0x00, 0x00};
    const Bytes real(kReal, kReal + sizeof kReal);
    const std::vector<Bytes> trees = {blob_of_size("p212 1g", 36670), blob_of_size("p212 2g", 37224)};
    EXPECT(trees[0].size() == 36670 && trees[1].size() == 37224);
    const std::vector<Item> items = {{"gxl", "p212", "1g", 0}, {"gxl", "p212", "2g", 1}};
    const Bytes built = aml::build(table_of(2, 2048, items, trees));
    EXPECT(built.size() == 77824);  // 2048 for the table, 18 pages and 19 pages of trees: the size of the `second` of that image
    EXPECT(Bytes(built.begin(), built.begin() + 124) == real);
    EXPECT(std::all_of(built.begin() + 124, built.begin() + 2048, [](uint8_t b) { return b == 0; }));
    EXPECT(std::equal(trees[0].begin(), trees[0].end(), built.begin() + 0x800));
    EXPECT(std::equal(trees[1].begin(), trees[1].end(), built.begin() + 0x9800));
    EXPECT(built == expected(2, 2048, items, trees));

    const aml::Table back = aml::parse(built, 2048);
    EXPECT(back.version == 2 && back.page_size == 2048 && back.consumed == built.size());
    EXPECT(back.entries.size() == 2 && back.dtbs.size() == 2);
    EXPECT(back.entries[0].soc == "gxl" && back.entries[0].platform == "p212" && back.entries[0].variant == "1g" && back.entries[0].dtb == 0);
    EXPECT(back.entries[1].soc == "gxl" && back.entries[1].platform == "p212" && back.entries[1].variant == "2g" && back.entries[1].dtb == 1);
    EXPECT(same_table(back, table_of(2, 2048, items, trees)));
    // with no hint the page size comes out the same: 2048 divides every offset and size, and is the first that the usual sizes try
    EXPECT(aml::parse(built).page_size == 2048);
}

// ------------------------------------------------------------------------------------------------------------------------------ layout --

void test_layout() {
    // numbers worked out by hand: version 1, three entries (20 bytes each), the page of 512
    {
        const std::vector<Bytes> trees = {blob_of_size("a", 300), blob_of_size("b", 512)};
        const std::vector<Item> items = {{"gxl", "p20", "1g", 0}, {"gxm", "q20", "2g", 1}, {"gxl", "p20", "2g", 0}};
        const Bytes built = aml::build(table_of(1, 512, items, trees));
        // the table is 12 + 3 * 20 = 72 bytes; the first tree is at 512 and takes one page; the second ends on a page and gets a whole one more
        EXPECT(built.size() == 512 + 512 + 1024);
        EXPECT(built[0] == 'A' && built[1] == 'M' && built[2] == 'L' && built[3] == '_');
        EXPECT(le32(built, 4) == 1 && le32(built, 8) == 3);
        // an id of version 1 is one word: "gxl" is 20 6c 78 67, "p20" 20 30 32 70, "1g" 20 20 67 31
        EXPECT(built[12] == 0x20 && built[13] == 'l' && built[14] == 'x' && built[15] == 'g');
        EXPECT(built[16] == 0x20 && built[17] == '0' && built[18] == '2' && built[19] == 'p');
        EXPECT(built[20] == 0x20 && built[21] == 0x20 && built[22] == 'g' && built[23] == '1');
        EXPECT(le32(built, 24) == 512 && le32(built, 28) == 512);    // entry 0: offset, size
        EXPECT(le32(built, 32 + 12) == 1024 && le32(built, 32 + 16) == 1024);  // entry 1
        EXPECT(le32(built, 52 + 12) == 512 && le32(built, 52 + 16) == 512);    // entry 2: the tree of entry 0 again
        EXPECT(built == expected(1, 512, items, trees));
        EXPECT(same_table(aml::parse(built, 512), table_of(1, 512, items, trees)));
    }
    // every version, several page sizes, ids of every length
    for (uint32_t version = 1; version <= 2; ++version) {
        for (const uint32_t page : {1u, 36u, 512u, 1000u, 2048u, 4096u}) {
            const std::vector<Bytes> trees = trees_for(3, 7 + version + page);
            const std::vector<Item> items = items_for(version, 6, 3, 11 + version);
            const aml::Table t = table_of(version, page, items, trees);
            const Bytes built = aml::build(t);
            EXPECT(built == expected(version, page, items, trees));
            const aml::Table back = aml::parse(built, page);
            EXPECT(same_table(back, t));
            EXPECT(back.consumed == built.size());
        }
    }
    // the longest ids a version has (no space behind the text), and none (all spaces)
    for (uint32_t version = 1; version <= 2; ++version) {
        const size_t idlen = version == 1 ? 4 : 16;
        const std::vector<Bytes> trees = trees_for(2, 5);
        const std::vector<Item> items = {{std::string(idlen, 'x'), std::string(idlen, 'Y'), std::string(idlen, '~'), 0}, {"", "", "", 1}};
        const Bytes built = aml::build(table_of(version, 2048, items, trees));
        EXPECT(built == expected(version, 2048, items, trees));
        EXPECT(same_table(aml::parse(built, 2048), table_of(version, 2048, items, trees)));
    }
    // a tree that ends on a page gets a whole page of zeros behind it, at several page sizes
    for (const uint32_t page : {512u, 1024u, 4096u}) {
        const std::vector<Bytes> trees = {blob_of_size("a", page), blob_of_size("b", 2 * page)};
        const std::vector<Item> items = items_for(2, 2, 2, 5);
        const Bytes built = aml::build(table_of(2, page, items, trees));
        EXPECT(built == expected(2, page, items, trees));
        EXPECT(built.size() == next_page(12 + 2 * 56, page) + 2 * page + 3 * page);
        EXPECT(same_table(aml::parse(built, page), table_of(2, page, items, trees)));
    }
    // a table of entries that ends on a page gets a whole page of zeros behind it, too
    for (uint32_t version = 1; version <= 2; ++version) {
        const std::vector<Item> items = items_for(version, 3, 1, 9);
        const uint32_t page = static_cast<uint32_t>(12 + aml::entry_size(version) * 3);
        const std::vector<Bytes> trees = trees_for(1, 3);
        const Bytes built = aml::build(table_of(version, page, items, trees));
        EXPECT(built == expected(version, page, items, trees));
        EXPECT(le32(built, 12 + 3 * aml::entry_size(version) - 8) == 2 * page);  // the offset in the last entry: two pages in
        EXPECT(same_table(aml::parse(built, page), table_of(version, page, items, trees)));
    }
    EXPECT(aml::id_size(0) == 0 && aml::id_size(1) == 4 && aml::id_size(2) == 16 && aml::id_size(3) == 0);
    EXPECT(aml::entry_size(0) == 0 && aml::entry_size(1) == 20 && aml::entry_size(2) == 56 && aml::entry_size(3) == 0);
}

// ------------------------------------------------------------------------------------------------------------------------ round trips --

void test_roundtrip() {
    std::mt19937 rnd(20261122);
    const uint32_t pages[] = {512, 1024, 2048, 4096, 8192, 16384, 100, 36, 1};
    for (int round = 0; round < 300; ++round) {
        const uint32_t version = 1 + static_cast<uint32_t>(rnd() % 2);
        const uint32_t page = pages[rnd() % (sizeof pages / sizeof pages[0])];
        const size_t ntrees = 1 + rnd() % 4;
        const size_t nitems = ntrees + rnd() % 6;
        const std::vector<Bytes> trees = trees_for(ntrees, static_cast<uint32_t>(rnd()), 130, 900);
        const std::vector<Item> items = items_for(version, nitems, ntrees, static_cast<uint32_t>(rnd()));
        const aml::Table t = table_of(version, page, items, trees);
        const Bytes built = aml::build(t);
        EXPECT(built == expected(version, page, items, trees));

        const aml::Table with_hint = aml::parse(built, page);
        EXPECT(same_table(with_hint, t));
        EXPECT(with_hint.consumed == built.size());
        // with no hint, or a wrong one, the table that comes out is one that builds the same bytes (another page size gives the same layout now and then)
        for (const uint32_t hint : {0u, page + 7u, 3u}) {
            const aml::Table other = aml::parse(built, hint);
            EXPECT(same_table(other, t, false));
            EXPECT(aml::build(other) == built);
        }
        // what follows the container is the caller's
        Bytes longer = built;
        for (int k = 0; k < 100; ++k) longer.push_back(static_cast<uint8_t>(0xA0 + k));
        const aml::Table with_tail = aml::parse(longer, page);
        EXPECT(with_tail.consumed == built.size());
        EXPECT(same_table(with_tail, t));
    }
}

// -------------------------------------------------------------------------------------------------------------------------- refusals --

// Overwrites the id of a version 2 container at `at` with `chars` (in the order of the text, spaces added up to 16), every word of four reversed as
// the container has it -- bytes that build() would never write.
void set_id(Bytes& b, size_t at, std::string chars) {
    chars.resize(16, ' ');
    for (size_t w = 0; w < 16; w += 4)
        for (size_t j = 0; j < 4; ++j) b[at + w + j] = static_cast<uint8_t>(chars[w + 3 - j]);
}

void test_parse_refusals() {
    // a good container: version 2, two entries for two trees (padded to one page and to two), the page of 2048
    const std::vector<Bytes> trees = {blob_of_size("a", 300), blob_of_size("b", 2500)};
    const std::vector<Item> items = {{"gxl", "p212", "1g", 0}, {"gxm", "q200", "2g", 1}};
    const Bytes good = aml::build(table_of(2, 2048, items, trees));
    EXPECT(good.size() == 2048 + 2048 + 4096);
    EXPECT(aml::looks_like(good));
    EXPECT(aml::parse(good).entries.size() == 2);

    // in each entry of 56 bytes the three ids are at 0, 16 and 32, the offset at 48 and the size at 52
    const size_t e0 = 12, e1 = 12 + 56;

    // not a container, or one with a header that is wrong
    EXPECT(!aml::looks_like(Bytes()));
    EXPECT(!aml::looks_like(Bytes(100, 0)));
    EXPECT(!aml::looks_like(Bytes{'A', 'M', 'L', '_', 2, 0}));
    EXPECT_REFUSES(aml::parse(Bytes()), "not an AML_ container");
    EXPECT_REFUSES(aml::parse(Bytes(100, 0)), "not an AML_ container");
    EXPECT_REFUSES(aml::parse(Bytes{'A', 'M', 'L', '_', 2, 0}), "not an AML_ container");
    Bytes b = good;
    for (const uint32_t version : {0u, 3u, 0x01000000u}) {
        put_word(b, 4, version);
        EXPECT(!aml::looks_like(b));
        EXPECT_REFUSES(aml::parse(b), "not an AML_ container");
    }
    b = good;
    put_word(b, 8, 0);
    EXPECT_REFUSES(aml::parse(b), "no entries");
    put_word(b, 8, 1u << 20);
    EXPECT_REFUSES(aml::parse(b), "at most");
    // three entries where the file has two: what follows the table is read as the third, and zeros are no id
    b = good;
    put_word(b, 8, 3);
    EXPECT_REFUSES(aml::parse(b), "entry 2");
    // entries that run past the end of the file
    b = good;
    b.resize(40);
    EXPECT_REFUSES(aml::parse(b), "says it has 2 entries of 56 bytes");

    // ids: a space inside the text, a space in front of it, a NUL, a byte above 0x7e, padding of zeros where the spaces belong
    b = good;
    set_id(b, e0, "a b");
    EXPECT_REFUSES(aml::parse(b), "entry 0: its soc id");
    EXPECT_REFUSES(aml::parse(b), "space");
    b = good;
    set_id(b, e0 + 16, " ab");
    EXPECT_REFUSES(aml::parse(b), "its platform id");
    EXPECT_REFUSES(aml::parse(b), "space");
    b = good;
    set_id(b, e1 + 32, std::string("a\0b", 3));
    EXPECT_REFUSES(aml::parse(b), "entry 1: its variant id");
    EXPECT_REFUSES(aml::parse(b), "printable");
    b = good;
    set_id(b, e0, "\x80xy");
    EXPECT_REFUSES(aml::parse(b), "printable");
    b = good;
    set_id(b, e0, "ab\x7f");
    EXPECT_REFUSES(aml::parse(b), "printable");
    b = good;
    set_id(b, e0, std::string("xyz") + std::string(13, '\0'));
    EXPECT_REFUSES(aml::parse(b), "printable");
    // what a tool that pads with spaces writes is taken, and what holds characters in the last word of the id too
    b = good;
    set_id(b, e0, std::string(16, 'q'));
    EXPECT(aml::parse(b).entries[0].soc == std::string(16, 'q'));

    // trees: where they are, how big, and whether there is one
    b = good;
    put_word(b, e0 + 48, 20);  // a tree inside the table
    EXPECT_REFUSES(aml::parse(b), "inside the table of entries");
    b = good;
    put_word(b, e0 + 52, static_cast<uint32_t>(good.size()));  // a size that runs past the end of the file
    EXPECT_REFUSES(aml::parse(b), "run past the end of the file");
    b = good;
    put_word(b, e0 + 52, 0);
    EXPECT_REFUSES(aml::parse(b), "has size 0");
    b = good;
    b[2048] ^= 0xFF;  // the magic of the first tree
    EXPECT_REFUSES(aml::parse(b), "there is no device tree at offset 0x800");
    b = good;
    put_word(b, e0 + 52, 100);  // smaller than the totalsize in the header of the tree
    EXPECT_REFUSES(aml::parse(b), "says in its own header that it is 300 bytes");
    b = good;
    put_word(b, e1 + 48, le32(good, e0 + 48));  // two entries for one offset, with two sizes
    EXPECT_REFUSES(aml::parse(b), "give it two sizes");
    b = good;
    put_word(b, e1 + 48, le32(good, e0 + 48) + 512);  // the second tree starts inside the first
    EXPECT_REFUSES(aml::parse(b), "overlaps the one before it");

    // padding that is not zeros: between the table and the first tree, and behind a tree
    b = good;
    b[1000] = 1;
    EXPECT_REFUSES(aml::parse(b), "the end of the table of entries");
    EXPECT_REFUSES(aml::parse(b), "is not zeros");
    b = good;
    b[2048 + 1500] = 1;  // behind the 300 bytes of the first tree, in its page
    EXPECT_REFUSES(aml::parse(b), "the padding behind the tree at offset 0x800 is not zeros");
    b = good;
    b[2048 + 2048 + 3000] = 1;  // behind the 2500 bytes of the second tree
    EXPECT_REFUSES(aml::parse(b), "the padding behind the tree at offset 0x1000 is not zeros");

    // a layout that is not the tool's: the trees where no page size puts them (a page too late for the first, and the second right behind it)
    {
        Bytes moved(2048, 0);
        std::copy(good.begin(), good.begin() + 124, moved.begin());
        moved.resize(4096, 0);  // zeros where the first tree should have been
        moved.insert(moved.end(), trees[0].begin(), trees[0].end());
        moved.resize(6144, 0);
        moved.insert(moved.end(), trees[1].begin(), trees[1].end());
        moved.resize(6144 + 4096, 0);
        put_word(moved, e0 + 48, 4096);
        put_word(moved, e0 + 52, 2048);
        put_word(moved, e1 + 48, 6144);
        put_word(moved, e1 + 52, 4096);
        EXPECT_REFUSES(aml::parse(moved), "not laid out as the tool lays them out");
        EXPECT_REFUSES(aml::parse(moved, 2048), "not laid out as the tool lays them out");
    }
    // sizes that are not the padded ones (the size is the tree and its zeros up to the next page, a whole page when it ends on one)
    b = good;
    put_word(b, e0 + 52, 300);
    EXPECT_REFUSES(aml::parse(b), "not laid out as the tool lays them out");
}

void test_build_refusals() {
    const std::vector<Bytes> trees = {blob_of_size("a", 300), blob_of_size("b", 700)};
    const std::vector<Item> items = {{"gxl", "p212", "1g", 0}, {"gxm", "q200", "2g", 1}};
    aml::Table t = table_of(2, 2048, items, trees);
    EXPECT(!aml::build(t).empty());

    aml::Table bad = t;
    bad.version = 3;
    EXPECT_REFUSES(aml::build(bad), "version 1 or 2");
    bad.version = 0;
    EXPECT_REFUSES(aml::build(bad), "version 1 or 2");
    bad = t;
    bad.page_size = 0;
    EXPECT_REFUSES(aml::build(bad), "page size");
    bad.page_size = aml::kMaxPageSize + 1;
    EXPECT_REFUSES(aml::build(bad), "page size");
    bad = t;
    bad.entries.clear();
    EXPECT_REFUSES(aml::build(bad), "at least one entry");
    bad = t;
    bad.dtbs.clear();
    EXPECT_REFUSES(aml::build(bad), "at least one device tree");
    bad = t;
    bad.entries[1].dtb = 2;
    EXPECT_REFUSES(aml::build(bad), "is for device tree 2");
    bad = t;
    bad.entries[1].dtb = 0;  // tree 1 is for no entry
    EXPECT_REFUSES(aml::build(bad), "for no entry");

    // ids
    bad = t;
    bad.entries[0].soc = "gx l";
    EXPECT_REFUSES(aml::build(bad), "space");
    bad = t;
    bad.entries[0].platform = std::string("p2\0 12", 6);
    EXPECT_REFUSES(aml::build(bad), "printable");
    bad = t;
    bad.entries[0].variant = "\xc3\xa9";
    EXPECT_REFUSES(aml::build(bad), "printable");
    bad = t;
    bad.entries[0].soc = std::string(17, 'x');
    EXPECT_REFUSES(aml::build(bad), "17 characters");
    bad = t;
    bad.version = 1;  // four characters are the most of an id of version 1, and "gxl", "p212", "1g", "gxm", "q200" and "2g" are that or shorter
    EXPECT(!aml::build(bad).empty());
    bad.entries[0].variant = "abcde";
    EXPECT_REFUSES(aml::build(bad), "5 characters");
    EXPECT_REFUSES(aml::build(bad), "the variant \"abcde\"");

    // trees
    bad = t;
    bad.dtbs[0][0] ^= 0xFF;
    EXPECT_REFUSES(aml::build(bad), "not a flattened device tree");
    bad = t;
    bad.dtbs[1].resize(20);
    EXPECT_REFUSES(aml::build(bad), "cut short");
    bad = t;
    bad.dtbs[0].push_back(0);  // a byte more than the totalsize in the header
    EXPECT_REFUSES(aml::build(bad), "totalsize");
    EXPECT_REFUSES(aml::check_device_tree(Bytes{1, 2, 3}, "the file x"), "the file x is not a flattened device tree");
    aml::check_device_tree(trees[0], "the file");  // a good one
}

// ------------------------------------------------------------------------------------------------------------------------- mutations --

// A container that is cut anywhere, or has any byte changed, is refused or is one that build() writes again byte for byte.
void check_mutant(const Bytes& m, uint32_t hint) {
    try {
        const aml::Table t = aml::parse(m, hint);
        ++g_checks;
        const Bytes again = aml::build(t);
        if (t.consumed > m.size() || again != Bytes(m.begin(), m.begin() + static_cast<std::ptrdiff_t>(t.consumed))) {
            ++g_failures;
            std::printf("  FAIL %s:%d: a changed container was taken, and build() does not write it again\n", __FILE__, __LINE__);
        }
    } catch (const FormatError&) {
        ++g_checks;  // refused: fine
    }
}

void test_mutations() {
    const std::vector<Bytes> trees = {blob_of_size("a", 200), blob_of_size("b", 260)};
    const std::vector<Item> items = {{"gxl", "p212", "1g", 0}, {"gxm", "q200", "2g", 1}, {"gxl", "p212", "2g", 1}};
    for (const uint32_t version : {1u, 2u}) {
        const Bytes good = aml::build(table_of(version, 512, items, trees));
        for (size_t n = 0; n < good.size(); ++n) check_mutant(Bytes(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(n)), 512);
        for (size_t i = 0; i < good.size(); ++i) {
            for (const uint8_t mask : {0x01, 0x20, 0x80, 0xFF}) {
                Bytes m = good;
                m[i] ^= mask;
                check_mutant(m, 512);
            }
        }
    }
    // random containers, one random byte of the first 200 and of the zeros changed
    std::mt19937 rnd(77);
    for (int round = 0; round < 100; ++round) {
        const uint32_t version = 1 + static_cast<uint32_t>(rnd() % 2);
        const size_t ntrees = 1 + rnd() % 3;
        const Bytes good = aml::build(table_of(version, 256, items_for(version, ntrees + 2, ntrees, rnd()), trees_for(ntrees, rnd(), 100, 300)));
        for (int k = 0; k < 40; ++k) {
            Bytes m = good;
            m[rnd() % std::min<size_t>(m.size(), 300)] ^= static_cast<uint8_t>(1 + rnd() % 255);
            check_mutant(m, 256);
        }
    }
}

}  // namespace

int run_aml_tests() {
    test_real_header();
    test_layout();
    test_roundtrip();
    test_parse_refusals();
    test_build_refusals();
    test_mutations();
    std::printf("aml: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
