// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of the device tree reader and writer (include/abr/fdt.hpp) and of the text of a tree (include/abr/dts.hpp). Run by
// tests/run_tests.sh as `abr_unit_tests fdt`; `abr_unit_tests fdt-files FILE...` is the check of blobs that another tool made
// (dtc, mkimage): every blob that abr takes for laid out as dtc and libfdt lay one out must come back from build() byte for byte,
// and the text of its tree must read back as the tree.
//
//   * a tree of random nodes, properties of every length (the padding of a value to 4 bytes), a reservation map, free space behind
//     the strings: build() then parse() is the tree, the layout is canonical, and build() of what parse() found is the blob again;
//   * what is not laid out the way abr writes it (a NOP token, a property behind a subnode, padding that is not zero, free space
//     that is not zero, blocks in another order, version 16) parses and says why it is not canonical;
//   * a blob that is cut anywhere, or has a byte changed anywhere, is a FormatError or a tree -- and when it is a tree whose layout
//     is canonical, build() gives the blob (8000 damaged blobs);
//   * names are found in the strings block as libfdt finds them (the end of a longer name is a name), a name that is not there is
//     added, and a tree that was made from text (no strings block yet) gets its names in the order of their use;
//   * the text: every kind of value, comments, escapes, /bits/, octal and character numbers; what is not read says so with the
//     line (labels, references, expressions, a node twice, a property twice, a property after a subnode, a second root, nesting
//     above the limit, a number that does not fit); parse(print(tree)) is the tree, for 3000 random trees and for damaged text.
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/dts.hpp"
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

bool contains(const std::string& haystack, std::string_view needle) { return haystack.find(needle) != std::string::npos; }

#define EXPECT_HAS(text, needle)                                                                       \
    do {                                                                                               \
        const std::string t_ = (text);                                                                 \
        ++g_checks;                                                                                    \
        if (!contains(t_, (needle))) {                                                                 \
            ++g_failures;                                                                              \
            std::printf("  FAIL %s:%d: \"%s\" does not say \"%s\"\n", __FILE__, __LINE__, t_.c_str(), \
                        std::string(needle).c_str());                                                  \
        }                                                                                              \
    } while (0)

template <typename F>
std::string refusal_of(F&& f) {
    try {
        f();
    } catch (const FormatError& e) {
        return e.what();
    } catch (const std::exception& e) {
        return std::string("NOT A FormatError: ") + e.what();
    }
    return "";
}

bool same_node(const fdt::Node& a, const fdt::Node& b) {
    if (a.name != b.name || a.props.size() != b.props.size() || a.children.size() != b.children.size()) return false;
    for (size_t i = 0; i < a.props.size(); ++i)
        if (a.props[i].name != b.props[i].name || a.props[i].value != b.props[i].value || a.props[i].incbin != b.props[i].incbin) return false;
    for (size_t i = 0; i < a.children.size(); ++i)
        if (!same_node(a.children[i], b.children[i])) return false;
    return true;
}

bool same_tree(const fdt::Tree& a, const fdt::Tree& b) {
    return a.version == b.version && a.last_comp_version == b.last_comp_version && a.boot_cpuid_phys == b.boot_cpuid_phys &&
           a.reserve == b.reserve && same_node(a.root, b.root);
}

const char kNameChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,._+-@#?*";

std::string random_name(std::mt19937_64& rng, size_t max_len) {
    std::string s;
    const size_t n = 1 + rng() % max_len;
    for (size_t i = 0; i < n; ++i) s += kNameChars[rng() % (sizeof kNameChars - 1)];
    return s;
}

Bytes random_value(std::mt19937_64& rng) {
    Bytes v;
    switch (rng() % 6) {
        case 0:  // nothing
            break;
        case 1: {  // strings
            const size_t n = 1 + rng() % 3;
            for (size_t k = 0; k < n; ++k) {
                const size_t len = 1 + rng() % 12;
                for (size_t i = 0; i < len; ++i) v.push_back(static_cast<uint8_t>(0x20 + rng() % 95));
                v.push_back(0);
            }
            break;
        }
        case 2: {  // cells
            const size_t n = 1 + rng() % 6;
            for (size_t k = 0; k < n * 4; ++k) v.push_back(static_cast<uint8_t>(rng()));
            break;
        }
        default: {  // anything, every length
            const size_t n = rng() % 41;
            for (size_t k = 0; k < n; ++k) v.push_back(static_cast<uint8_t>(rng()));
        }
    }
    return v;
}

void random_children(std::mt19937_64& rng, fdt::Node& n, size_t depth, size_t& budget) {
    const size_t props = rng() % 6;
    for (size_t i = 0; i < props && budget > 0; ++i, --budget) {
        fdt::Property p;
        do p.name = random_name(rng, 14);
        while (n.find_prop(p.name));
        p.value = random_value(rng);
        n.props.push_back(std::move(p));
    }
    if (depth >= 5) return;
    const size_t kids = rng() % 4;
    for (size_t i = 0; i < kids && budget > 0; ++i, --budget) {
        fdt::Node c;
        do c.name = random_name(rng, 12);
        while (n.find_child(c.name));
        random_children(rng, c, depth + 1, budget);
        n.children.push_back(std::move(c));
    }
}

fdt::Tree random_tree(std::mt19937_64& rng) {
    fdt::Tree t;
    t.last_comp_version = 16;
    t.boot_cpuid_phys = static_cast<uint32_t>(rng() % 3 == 0 ? rng() : 0);
    const size_t rsv = rng() % 4 == 0 ? rng() % 4 : 0;
    for (size_t i = 0; i < rsv; ++i) t.reserve.emplace_back(rng() | 1, rng() % 5 == 0 ? 0 : rng());
    size_t budget = 40;
    random_children(rng, t.root, 0, budget);
    return t;
}

void test_fdt_roundtrip() {
    std::puts("fdt: build() then parse() is the tree; build() of what parse() found is the blob");
    std::mt19937_64 rng(0x46445431ull);
    int bad_shape = 0;
    for (int round = 0; round < 3000; ++round) {
        const fdt::Tree t = random_tree(rng);
        const size_t slack = rng() % 3 == 0 ? rng() % 300 : 0;
        const Bytes blob = fdt::build(t, slack);
        fdt::Layout lay;
        fdt::Tree back;
        try {
            back = fdt::parse(blob, &lay);
        } catch (const FormatError& e) {
            ++g_checks;
            if (++bad_shape <= 3) {
                ++g_failures;
                std::printf("  FAIL: round %d: a blob that build() made does not parse: %s\n", round, e.what());
            }
            continue;
        }
        ++g_checks;
        if (!same_tree(t, back) || !lay.canonical || lay.slack != slack || lay.total_size != blob.size()) {
            if (++bad_shape <= 3) {
                ++g_failures;
                std::printf("  FAIL: round %d: the tree does not come back (canonical=%d slack %zu/%zu: %s)\n", round, lay.canonical, lay.slack, slack,
                            lay.why.c_str());
            }
            continue;
        }
        ++g_checks;
        const Bytes again = fdt::build(back, lay.slack);
        if (again != blob && ++bad_shape <= 3) {
            ++g_failures;
            std::printf("  FAIL: round %d: build() of what parse() found is not the blob\n", round);
        }
    }
    EXPECT(bad_shape == 0);
    // a blob is a prefix of a longer file: the rest is not its business
    {
        fdt::Tree t;
        t.root.props.push_back({"p", {1, 2, 3}, ""});
        Bytes blob = fdt::build(t, 4);
        const size_t size = blob.size();
        blob.insert(blob.end(), 100, 0xAB);
        fdt::Layout lay;
        const fdt::Tree back = fdt::parse(blob, &lay);
        EXPECT(lay.total_size == size && lay.canonical && same_tree(t, back));
    }
}

// A blob by hand, in any layout. `struct_words` is the structure block (tokens), `strings` the strings block.
struct Hand {
    uint32_t version = 17, last_comp = 16;
    Bytes rsv;             // the reservation map as bytes (with its end)
    Bytes structure;       // the structure block
    Bytes strings;
    size_t pad_before_struct = 0;
    bool strings_first = false;
    size_t slack = 0;
    uint8_t slack_byte = 0;
    int size_struct_delta = 0;
    Bytes build() const {
        BinaryWriter w;
        const size_t header = version >= 17 ? 40 : 36;
        const size_t off_rsv = 40;
        const size_t off_struct = off_rsv + rsv.size() + pad_before_struct;
        size_t off_strings = off_struct + structure.size();
        size_t off_struct_real = off_struct;
        if (strings_first) {
            off_strings = off_struct;
            off_struct_real = off_struct + strings.size();
        }
        (void)header;
        const size_t total = (strings_first ? off_struct_real + structure.size() : off_strings + strings.size()) + slack;
        w.be32(0xd00dfeed);
        w.be32(static_cast<uint32_t>(total));
        w.be32(static_cast<uint32_t>(off_struct_real));
        w.be32(static_cast<uint32_t>(off_strings));
        w.be32(static_cast<uint32_t>(off_rsv));
        w.be32(version);
        w.be32(last_comp);
        w.be32(0);
        w.be32(static_cast<uint32_t>(strings.size()));
        if (version >= 17) w.be32(static_cast<uint32_t>(static_cast<int>(structure.size()) + size_struct_delta));
        while (w.size() < off_rsv) w.u8(0);
        w.bytes(rsv);
        w.zeros(pad_before_struct);
        if (strings_first) {
            w.bytes(strings);
            w.bytes(structure);
        } else {
            w.bytes(structure);
            w.bytes(strings);
        }
        for (size_t i = 0; i < slack; ++i) w.u8(slack_byte);
        return w.take();
    }
};

void put32(Bytes& b, uint32_t v) {
    for (int k = 3; k >= 0; --k) b.push_back(static_cast<uint8_t>(v >> (8 * k)));
}

Bytes minimal_structure(bool nop, bool prop_after_child, bool bad_pad) {
    Bytes s;
    put32(s, 1);  // BEGIN_NODE, ""
    put32(s, 0);
    if (nop) put32(s, 4);
    if (!prop_after_child) {
        put32(s, 3);  // PROP len 3, nameoff 0
        put32(s, 3);
        put32(s, 0);
        s.push_back(1);
        s.push_back(2);
        s.push_back(3);
        s.push_back(bad_pad ? 0x55 : 0);
    }
    put32(s, 1);  // BEGIN_NODE "a"
    s.push_back('a');
    s.push_back(0);
    s.push_back(0);
    s.push_back(0);
    put32(s, 2);
    if (prop_after_child) {
        put32(s, 3);
        put32(s, 0);
        put32(s, 0);
    }
    put32(s, 2);
    put32(s, 9);
    return s;
}

void test_fdt_layouts() {
    std::puts("fdt: a blob that is not laid out as abr writes it parses and says why");
    Hand ok;
    ok.rsv.assign(16, 0);
    ok.structure = minimal_structure(false, false, false);
    ok.strings = {'p', 0};
    {
        fdt::Layout lay;
        const fdt::Tree t = fdt::parse(ok.build(), &lay);
        EXPECT(lay.canonical);
        EXPECT(t.root.props.size() == 1 && t.root.props[0].name == "p" && t.root.props[0].value == (Bytes{1, 2, 3}));
        EXPECT(t.root.children.size() == 1 && t.root.children[0].name == "a");
    }
    {
        Hand h = ok;
        h.structure = minimal_structure(true, false, false);
        fdt::Layout lay;
        fdt::parse(h.build(), &lay);
        EXPECT(!lay.canonical);
        EXPECT_HAS(lay.why, "NOP");
    }
    {
        Hand h = ok;
        h.structure = minimal_structure(false, true, false);
        fdt::Layout lay;
        const fdt::Tree t = fdt::parse(h.build(), &lay);
        EXPECT(!lay.canonical);
        EXPECT_HAS(lay.why, "after a subnode");
        EXPECT(t.root.props.size() == 1);
    }
    {
        Hand h = ok;
        h.structure = minimal_structure(false, false, true);
        fdt::Layout lay;
        fdt::parse(h.build(), &lay);
        EXPECT(!lay.canonical);
        EXPECT_HAS(lay.why, "padding that is not zero");
    }
    {
        Hand h = ok;
        h.slack = 12;
        h.slack_byte = 0xEE;
        fdt::Layout lay;
        fdt::parse(h.build(), &lay);
        EXPECT(!lay.canonical);
        EXPECT_HAS(lay.why, "not zero behind the strings");
    }
    {
        Hand h = ok;
        h.pad_before_struct = 8;
        fdt::Layout lay;
        fdt::parse(h.build(), &lay);
        EXPECT(!lay.canonical);
        EXPECT_HAS(lay.why, "one behind the other");
    }
    {
        Hand h = ok;
        h.strings = {'p', 0, 0, 0};
        h.strings_first = true;
        fdt::Layout lay;
        const fdt::Tree t = fdt::parse(h.build(), &lay);
        EXPECT(!lay.canonical && t.root.props.size() == 1);
    }
    {
        Hand h = ok;
        h.version = 16;
        fdt::Layout lay;
        fdt::parse(h.build(), &lay);
        EXPECT(!lay.canonical);
        EXPECT_HAS(lay.why, "version 16");
    }
    {
        Hand h = ok;
        h.size_struct_delta = 8;
        h.slack = 0;
        // the structure block is declared 8 bytes longer than it is: it runs out of the blob
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "is not inside the blob");
        // ... or into the strings block, when there is free space for it to run into
        h.slack = 16;
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "overlap");
    }
    {
        Hand h = ok;
        h.version = 15;
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "older than 16");
        h.version = 17;
        h.last_comp = 18;
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "newer than");
    }
    // refusals
    {
        Bytes blob = ok.build();
        Bytes b = blob;
        b[0] ^= 1;
        EXPECT_HAS(refusal_of([&] { fdt::parse(b); }), "d0 0d fe ed");
        EXPECT_HAS(refusal_of([&] { fdt::parse(Bytes(blob.begin(), blob.begin() + 20)); }), "cut short");
        // every prefix of a blob is refused
        int accepted = 0;
        for (size_t n = 0; n < blob.size(); ++n) {
            try {
                fdt::parse(Bytes(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(n)));
                ++accepted;
            } catch (const FormatError&) {
            }
        }
        EXPECT(accepted == 0);
        // a property whose name is not in the strings block
        Hand h = ok;
        h.strings = {'p'};  // no NUL
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "name of the property");
        // a root node with a name, a second root, a property outside a node, no node, unclosed
        h = ok;
        h.structure.clear();
        put32(h.structure, 1);
        h.structure.insert(h.structure.end(), {'x', 0, 0, 0});
        put32(h.structure, 2);
        put32(h.structure, 9);
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "root node has a name");
        h.structure.clear();
        put32(h.structure, 1), put32(h.structure, 0), put32(h.structure, 2), put32(h.structure, 1), put32(h.structure, 0), put32(h.structure, 2), put32(h.structure, 9);
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "second node at the top level");
        h.structure.clear();
        put32(h.structure, 3), put32(h.structure, 0), put32(h.structure, 0), put32(h.structure, 9);
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "outside any node");
        h.structure.clear();
        put32(h.structure, 9);
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "no node");
        h.structure.clear();
        put32(h.structure, 1), put32(h.structure, 0), put32(h.structure, 9);
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "still open");
        h.structure.clear();
        put32(h.structure, 1), put32(h.structure, 0), put32(h.structure, 77), put32(h.structure, 9);
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "which is none");
        h.structure.clear();
        put32(h.structure, 1), put32(h.structure, 0), put32(h.structure, 3), put32(h.structure, 0x7FFFFFF0), put32(h.structure, 0), put32(h.structure, 2), put32(h.structure, 9);
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "more than the structure block has left");
    }
    // nesting
    {
        fdt::Tree t;
        fdt::Node* n = &t.root;
        for (size_t i = 1; i < fdt::kMaxDepth; ++i) {
            n->children.emplace_back();
            n->children.back().name = "n";
            n = &n->children.back();
        }
        const Bytes blob = fdt::build(t);  // kMaxDepth levels, the root among them
        EXPECT(same_tree(t, fdt::parse(blob)));
        n->children.emplace_back();
        n->children.back().name = "n";
        EXPECT_HAS(refusal_of([&] { fdt::build(t); }), "nested more than");
        // the same in a blob that was not made by build()
        Bytes s;
        for (size_t i = 0; i <= fdt::kMaxDepth; ++i) put32(s, 1), put32(s, i == 0 ? 0 : 0x6e000000);
        for (size_t i = 0; i <= fdt::kMaxDepth; ++i) put32(s, 2);
        put32(s, 9);
        Hand h;
        h.rsv.assign(16, 0);
        h.structure = s;
        h.strings = {0};
        EXPECT_HAS(refusal_of([&] { fdt::parse(h.build()); }), "nested more than");
    }
    // the writer's refusals
    {
        fdt::Tree t;
        t.root.props.push_back({"p", {}, "file"});
        EXPECT_HAS(refusal_of([&] { fdt::build(t); }), "still names a file");
        fdt::Tree u;
        u.root.props.push_back({std::string("a\0b", 3), {}, ""});
        EXPECT_HAS(refusal_of([&] { fdt::build(u); }), "NUL");
        fdt::Tree v;
        v.root.name = "x";
        EXPECT_HAS(refusal_of([&] { fdt::build(v); }), "root node has a name");
        fdt::Tree w;
        w.version = 16;
        EXPECT_HAS(refusal_of([&] { fdt::build(w); }), "version 17");
    }
}

void test_fdt_damaged() {
    std::puts("fdt: a blob that is cut or has a byte changed is refused or is a tree, and a canonical one builds back");
    std::mt19937_64 rng(0x44414d47ull);
    int violations = 0;
    int parsed = 0, refused = 0;
    for (int round = 0; round < 8000; ++round) {
        const fdt::Tree t = random_tree(rng);
        Bytes blob = fdt::build(t, rng() % 4 == 0 ? rng() % 40 : 0);
        const size_t flips = 1 + rng() % 3;
        for (size_t k = 0; k < flips; ++k) {
            const size_t at = rng() % blob.size();
            blob[at] = (rng() % 3 == 0) ? static_cast<uint8_t>(blob[at] ^ (1u << (rng() % 8))) : static_cast<uint8_t>(rng());
        }
        if (rng() % 5 == 0) blob.resize(rng() % (blob.size() + 1));
        fdt::Layout lay;
        try {
            const fdt::Tree back = fdt::parse(blob, &lay);
            ++parsed;
            if (lay.canonical) {
                const Bytes again = fdt::build(back, lay.slack);
                ++g_checks;
                if (again.size() != lay.total_size || !std::equal(again.begin(), again.end(), blob.begin())) {
                    if (++violations <= 3) {
                        ++g_failures;
                        std::printf("  FAIL: round %d: a blob that parsed as canonical does not build back\n", round);
                    }
                }
            }
        } catch (const FormatError&) {
            ++refused;
        }
    }
    EXPECT(violations == 0);
    EXPECT(refused > 0 && parsed > 0);
}

void test_fdt_name_places() {
    std::puts("fdt: a name that is not at the first place of its text in the strings block is not canonical");
    Hand h;
    h.rsv.assign(16, 0);
    // two properties, both called "ab": one at 0, one at 3 (a blob that a tool could write; build() would use 0 for both)
    h.strings = {'a', 'b', 0, 'a', 'b', 0, 0, 0};
    Bytes s;
    put32(s, 1);
    put32(s, 0);
    put32(s, 3), put32(s, 0), put32(s, 0);
    put32(s, 3), put32(s, 0), put32(s, 3);
    put32(s, 2);
    put32(s, 9);
    h.structure = s;
    fdt::Layout lay;
    const fdt::Tree t = fdt::parse(h.build(), &lay);
    EXPECT(t.root.props.size() == 2 && t.root.props[1].name == "ab");
    EXPECT(!lay.canonical);
    EXPECT_HAS(lay.why, "first place its text has");
    // ... and a name that points into the middle of a longer one is canonical when that is the first place
    h.strings = {'x', 'a', 'b', 0};
    h.structure.clear();
    put32(h.structure, 1), put32(h.structure, 0);
    put32(h.structure, 3), put32(h.structure, 0), put32(h.structure, 1);
    put32(h.structure, 2), put32(h.structure, 9);
    const fdt::Tree u = fdt::parse(h.build(), &lay);
    EXPECT(u.root.props.size() == 1 && u.root.props[0].name == "ab" && lay.canonical);
}

void test_fdt_strings() {
    std::puts("fdt: names are found in the strings block as libfdt finds them");
    // "xyz-reg" holds "reg" at 4; "compatible" is found where it starts; a name that is not there is added at the end
    fdt::Tree t;
    t.strings = {'x', 'y', 'z', '-', 'r', 'e', 'g', 0, 'c', 'o', 'm', 'p', 'a', 't', 'i', 'b', 'l', 'e', 0};
    t.root.props.push_back({"reg", {0, 0, 0, 1}, ""});
    t.root.props.push_back({"compatible", {'a', 0}, ""});
    t.root.props.push_back({"xyz-reg", {0, 0, 0, 2}, ""});
    t.root.props.push_back({"new", {}, ""});
    t.root.props.push_back({"new", {}, ""});  // (a name twice: the same place)
    const Bytes blob = fdt::build(t);
    const fdt::Tree back = fdt::parse(blob);
    EXPECT(back.strings.size() == t.strings.size() + 4);
    EXPECT(std::string(back.strings.begin() + static_cast<std::ptrdiff_t>(t.strings.size()), back.strings.end() - 1) == "new");
    EXPECT(back.root.props.size() == 5 && back.root.props[0].name == "reg" && back.root.props[2].name == "xyz-reg");
    // string_offset() does the same lookup
    Bytes strings = t.strings;
    EXPECT(fdt::string_offset(strings, "reg") == 4);
    EXPECT(fdt::string_offset(strings, "xyz-reg") == 0);
    EXPECT(fdt::string_offset(strings, "compatible") == 8);
    EXPECT(strings == t.strings);
    EXPECT(fdt::string_offset(strings, "x") == strings.size() - 2);  // added
    // a tree from text has no strings: the names come in the order they are used
    fdt::Tree u;
    u.root.props.push_back({"b", {}, ""});
    u.root.props.push_back({"a", {}, ""});
    u.root.props.push_back({"b", {}, ""});
    const fdt::Tree ub = fdt::parse(fdt::build(u));
    EXPECT((ub.strings == Bytes{'b', 0, 'a', 0}));
    // the finders
    fdt::Node n;
    n.props.push_back({"s", {'h', 'i', 0}, ""});
    n.props.push_back({"two", {'a', 0, 'b', 0}, ""});
    n.props.push_back({"c4", {0, 0, 0, 7}, ""});
    n.props.push_back({"c8", {0, 0, 0, 1, 0, 0, 0, 2}, ""});
    std::string s;
    uint64_t v = 0;
    EXPECT(n.get_string("s", s) && s == "hi");
    EXPECT(!n.get_string("two", s) && !n.get_string("c4", s) && !n.get_string("none", s));
    EXPECT(n.get_u64("c4", v) && v == 7);
    EXPECT(n.get_u64("c8", v) && v == 0x100000002ull);
    EXPECT(!n.get_u64("s", v));
}

// ------------------------------------------------------------------------------------------------ the text

fdt::Tree must_parse(const std::string& text) {
    try {
        return dts::parse(text, "t.dts");
    } catch (const std::exception& e) {
        ++g_checks;
        ++g_failures;
        std::printf("  FAIL: a text that has to be read: %s\n  %s\n", e.what(), text.c_str());
        return {};
    }
}

void test_dts_syntax() {
    std::puts("dts: what is read, and what is not");
    const fdt::Tree t = must_parse(R"(/dts-v1/;
/memreserve/ 0x1000 0x2000;
/memreserve/ 4096 010;
// a comment
/ {
    /* another */ s = "one", "two\n\"q\"\\ \x41\101";
    c = <0x1 2 010 'a'>, <0xffffffff>;
    b = [00 11 2233 aB];
    e;
    q = /bits/ 8 <0xff 1>, /bits/ 16 <0x1234>, /bits/ 64 <0x1122334455667788>;
    empty = "";
    node@1 { x = <1>; };
    other,name+x { sub { }; };
};
)");
    EXPECT((t.reserve.size() == 2 && t.reserve[0] == std::pair<uint64_t, uint64_t>(0x1000, 0x2000) &&
            t.reserve[1] == std::pair<uint64_t, uint64_t>(4096, 8)));
    const fdt::Node& r = t.root;
    EXPECT(r.props.size() == 6);
    EXPECT((r.find_prop("s")->value == Bytes{'o', 'n', 'e', 0, 't', 'w', 'o', '\n', '"', 'q', '"', '\\', ' ', 'A', 'A', 0}));
    EXPECT((r.find_prop("c")->value == Bytes{0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 8, 0, 0, 0, 'a', 0xff, 0xff, 0xff, 0xff}));
    EXPECT((r.find_prop("b")->value == Bytes{0x00, 0x11, 0x22, 0x33, 0xab}));
    EXPECT(r.find_prop("e")->value.empty());
    EXPECT((r.find_prop("q")->value == Bytes{0xff, 1, 0x12, 0x34, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}));
    EXPECT((r.find_prop("empty")->value == Bytes{0}));
    EXPECT(r.children.size() == 2 && r.children[0].name == "node@1" && r.children[1].children.size() == 1);
    // an incbin
    const fdt::Tree i = must_parse("/dts-v1/; / { n { data = /incbin/(\"a b.bin\"); }; };");
    EXPECT(i.root.children[0].props[0].incbin == "a b.bin" && i.root.children[0].props[0].value.empty());
    // what is refused, with the line
    struct Bad {
        const char* text;
        const char* says;
    };
    const Bad bad[] = {
        {"/ { };", "starts with /dts-v1/"},
        {"/dts-v1/ / { };", "expected ';'"},
        {"/dts-v1/;\n/ {\n  l: n { };\n};", "labels are not read"},
        {"/dts-v1/;\n/ {\n  a = <&ref>;\n};", "reference"},
        {"/dts-v1/;\n/ {\n  a = <(1+2)>;\n};", "expression"},
        {"/dts-v1/;\n/ {\n  a = <MACRO>;\n};", "no macros"},
        {"/dts-v1/;\n/ {\n  a = <0x100000000>;\n};", "does not fit 32 bits"},
        {"/dts-v1/;\n/ {\n  a = /bits/ 8 <256>;\n};", "does not fit 8 bits"},
        {"/dts-v1/;\n/ {\n  a = /bits/ 12 <1>;\n};", "has to be 8, 16, 32 or 64"},
        {"/dts-v1/;\n/ {\n  a = <1>;\n  a = <2>;\n};", "is there twice"},
        {"/dts-v1/;\n/ {\n  n { };\n  n { };\n};", "is there twice"},
        {"/dts-v1/;\n/ {\n  n { };\n  a = <1>;\n};", "comes after a subnode"},
        {"/dts-v1/;\n/ { };\n/ { };", "something behind the root node"},
        {"/dts-v1/;\n/ {\n  a = \"open;\n};", "not closed"},
        {"/dts-v1/;\n/ {\n  /* open\n};", "not closed"},
        {"/dts-v1/;\n/ {\n  a = [123];\n};", "odd number"},
        {"/dts-v1/;\n/ {\n  a = [zz];\n};", "hexadecimal digit"},
        {"/dts-v1/;\n/ {\n  /delete-node/ x;\n};", "not read"},
        {"/dts-v1/;\n/ {\n  a = /incbin/(\"f\", 1, 2);\n};", "skip and a length"},
        {"/dts-v1/;\n/ {\n  a = <1>, /incbin/(\"f\");\n};", "only value"},
        {"/dts-v1/;\n/ {\n  a = \"x\\q\";\n};", "none that abr reads"},
        {"/dts-v1/;\n/ {\n  a = 5;\n};", "expected a value"},
        {"/dts-v1/;\n/ {\n  a = <1>\n};", "expected ';'"},
        {"/dts-v1/;\n/ {\n  a = <0x>;\n};", "no digits"},
        {"/dts-v1/;\n/ {\n  a = <12ab>;\n};", "followed by letters"},
        {"/dts-v1/;\n/ {\n", "ends inside a node"},
        {"/dts-v1/;\n", "root node"},
    };
    for (const Bad& b : bad) {
        const std::string said = refusal_of([&] { dts::parse(b.text, "t.dts"); });
        ++g_checks;
        if (!contains(said, b.says) || !contains(said, "t.dts: line ")) {
            ++g_failures;
            std::printf("  FAIL: \"%s\" gave: \"%s\" (wanted \"%s\")\n", b.text, said.c_str(), b.says);
        }
    }
    // the line is the right one
    EXPECT_HAS(refusal_of([&] { dts::parse("/dts-v1/;\n\n/ {\n  a = <1>;\n  b = <&x>;\n};", "t.dts"); }), "t.dts: line 5:");
    // depth
    std::string deep = "/dts-v1/;\n/ {\n";
    for (size_t k = 1; k < fdt::kMaxDepth; ++k) deep += "n {\n";
    for (size_t k = 1; k < fdt::kMaxDepth; ++k) deep += "};\n";
    deep += "};\n";
    EXPECT(refusal_of([&] { dts::parse(deep); }).empty());
    std::string deeper = "/dts-v1/;\n/ {\n";
    for (size_t k = 0; k < fdt::kMaxDepth; ++k) deeper += "n {\n";
    for (size_t k = 0; k < fdt::kMaxDepth; ++k) deeper += "};\n";
    deeper += "};\n";
    EXPECT_HAS(refusal_of([&] { dts::parse(deeper); }), "nested more than");
    // the printer's refusals
    fdt::Tree p;
    p.root.props.push_back({"a b", {}, ""});
    EXPECT_HAS(refusal_of([&] { dts::print(p); }), "cannot be written as text");
    fdt::Tree q;
    q.root.children.emplace_back();
    q.root.children[0].name = "x/y";
    EXPECT_HAS(refusal_of([&] { dts::print(q); }), "cannot be written as text");
}

fdt::Tree random_text_tree(std::mt19937_64& rng) {
    fdt::Tree t = random_tree(rng);
    // the text carries the memory map and the nodes; the rest of the header is not text
    t.version = 17;
    t.last_comp_version = 16;
    t.boot_cpuid_phys = 0;
    return t;
}

void test_dts_roundtrip() {
    std::puts("dts: parse(print(tree)) is the tree");
    std::mt19937_64 rng(0x44545331ull);
    int bad_round = 0;
    for (int round = 0; round < 3000; ++round) {
        const fdt::Tree t = random_text_tree(rng);
        const std::string text = dts::print(t);
        ++g_checks;
        try {
            const fdt::Tree back = dts::parse(text, "t.dts");
            if (!same_tree(t, back) && ++bad_round <= 3) {
                ++g_failures;
                std::printf("  FAIL: round %d: the tree does not come back from its text:\n%s\n", round, text.c_str());
            }
        } catch (const FormatError& e) {
            if (++bad_round <= 3) {
                ++g_failures;
                std::printf("  FAIL: round %d: the text of a tree is not read: %s\n%s\n", round, e.what(), text.c_str());
            }
        }
    }
    EXPECT(bad_round == 0);
    // every kind of value, as the printer writes it
    {
        fdt::Tree t;
        t.root.props.push_back({"str", {'a', 0, 'b', 'c', 0}, ""});
        t.root.props.push_back({"empty_str", {0}, ""});
        t.root.props.push_back({"zeros", {0, 0, 0, 0}, ""});
        t.root.props.push_back({"cells", {0, 0, 0x10, 0, 0xff, 0xff, 0xff, 0xff}, ""});
        t.root.props.push_back({"odd", {1, 2, 3}, ""});
        t.root.props.push_back({"quote", {'"', '\\', 'x', 0}, ""});
        t.root.props.push_back({"flag", {}, ""});
        t.root.props.push_back({"hi", {0xc3, 0xa9, 0}, ""});
        t.root.props.push_back({"file", {}, "kernel.bin"});
        const std::string text = dts::print(t);
        EXPECT_HAS(text, "str = \"a\", \"bc\";");
        EXPECT_HAS(text, "empty_str = \"\";");
        EXPECT_HAS(text, "zeros = <0x0>;");
        EXPECT_HAS(text, "cells = <0x1000 0xffffffff>;");
        EXPECT_HAS(text, "odd = [01 02 03];");
        EXPECT_HAS(text, "quote = \"\\\"\\\\x\";");
        EXPECT_HAS(text, "flag;");
        EXPECT_HAS(text, "hi = [c3 a9 00];");  // (bytes above 0x7e are not text, and 3 bytes are not cells)
        EXPECT_HAS(text, "file = /incbin/(\"kernel.bin\");");
        EXPECT(same_tree(t, dts::parse(text)));
    }
    // damaged text: refused or a tree that prints and reads back
    int violations = 0, read = 0, refused = 0;
    for (int round = 0; round < 3000; ++round) {
        std::string text = dts::print(random_text_tree(rng));
        const size_t flips = 1 + rng() % 3;
        for (size_t k = 0; k < flips && !text.empty(); ++k) text[rng() % text.size()] = static_cast<char>(rng() % 3 == 0 ? rng() : "{};=<>[]\"/ ,\n&:0x"[rng() % 18]);
        if (rng() % 6 == 0) text.resize(rng() % (text.size() + 1));
        try {
            const fdt::Tree t = dts::parse(text);
            ++read;
            ++g_checks;
            try {
                if (!same_tree(t, dts::parse(dts::print(t))) && ++violations <= 3) {
                    ++g_failures;
                    std::printf("  FAIL: a text that was read does not print and read back\n");
                }
            } catch (const FormatError&) {  // (a name that the damage made and the printer will not write)
            }
        } catch (const FormatError&) {
            ++refused;
        }
    }
    EXPECT(violations == 0 && read > 0 && refused > 0);
}

}  // namespace

int run_fdt_tests() {
    test_fdt_roundtrip();
    test_fdt_layouts();
    test_fdt_damaged();
    test_fdt_name_places();
    test_fdt_strings();
    test_dts_syntax();
    test_dts_roundtrip();
    if (g_failures == 0) std::printf("fdt: ok (%d checks)\n", g_checks);
    else std::printf("fdt: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}

// The blobs that another tool made: `abr_unit_tests fdt-files FILE...`. A blob that abr takes for laid out as dtc and libfdt do
// has to build back to the same bytes; the text of its tree has to read back as the tree. One line a file.
int run_fdt_files(int argc, char** argv) {
    int bad = 0;
    for (int i = 2; i < argc; ++i) {
        try {
            const Bytes blob = read_file(argv[i]);
            fdt::Layout lay;
            const fdt::Tree t = fdt::parse(blob, &lay);
            std::string verdict;
            if (lay.canonical) {
                const Bytes again = fdt::build(t, lay.slack);
                const bool same = again.size() == lay.total_size && std::equal(again.begin(), again.end(), blob.begin());
                verdict = same ? "canonical, built back byte for byte" : "canonical, BUT BUILT BACK DIFFERENTLY";
                if (!same) ++bad;
            } else {
                verdict = "not canonical: " + lay.why;
            }
            bool text_ok = true;
            try {
                text_ok = same_node(dts::parse(dts::print(t), "text").root, t.root);
            } catch (const FormatError& e) {
                verdict += std::string(" (no text: ") + e.what() + ")";
            }
            if (!text_ok) {
                verdict += " (THE TEXT DOES NOT READ BACK)";
                ++bad;
            }
            std::printf("%s: %s\n", argv[i], verdict.c_str());
        } catch (const std::exception& e) {
            std::printf("%s: refused: %s\n", argv[i], e.what());
        }
    }
    return bad == 0 ? 0 : 1;
}
