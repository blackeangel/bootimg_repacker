// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of what a kernel field holds besides the kernel (include/abr/kernel.hpp). Run by tests/run_tests.sh as `abr_unit_tests kernel`.
//
//   * plausible_tree(): a tree that dtc or abr wrote is one, whatever its size; a header that does not hold together (the magic, the
//     total size, the offsets of the blocks, the root node, FDT_END, a version that no tree has) is not;
//   * find_appended_trees(): one tree, several, with zero bytes between them where they are put at multiples of 4, 8, 16, 4096; a tail of a
//     few bytes, of zeros of any size; a tail of code and data is not the end of a kernel with trees: the trees that a kernel carries inside
//     itself are not glued trees, and the ones that end it are found behind them; data that begins with a tree is a dtb, not a kernel;
//   * random layouts of junk, gaps, trees and a tail: the start, the number of trees and where they end are the ones the layout had.
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/dtb.hpp"
#include "abr/dts.hpp"
#include "abr/fdt.hpp"
#include "abr/kernel.hpp"

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

// A tree of some size (`n` properties) that is not the same as the one of any other `salt`.
Bytes tree(size_t n, uint32_t salt) {
    std::string text = "/dts-v1/;\n/ {\n\tmodel = \"board " + std::to_string(salt) + "\";\n\tcompatible = \"vendor,soc-" + std::to_string(salt) + "\";\n";
    for (size_t i = 0; i < n; ++i) text += "\tprop" + std::to_string(i) + " = <" + std::to_string(salt * 7919 + i) + ">;\n";
    text += "\tchild { reg = <" + std::to_string(salt) + ">; };\n};\n";
    return fdt::build(dts::parse(text, "t"));
}

Bytes junk(size_t n, std::mt19937& rng) {
    Bytes b(n);
    for (uint8_t& x : b) x = static_cast<uint8_t>(rng());
    return b;
}

void append(Bytes& to, const Bytes& more) { to.insert(to.end(), more.begin(), more.end()); }

void test_plausible() {
    const Bytes t = tree(3, 1);
    EXPECT(kernel::plausible_tree(t, 0));
    for (size_t n : {0u, 1u, 5u, 20u, 40u}) EXPECT(kernel::plausible_tree(tree(n, 2), 0));
    // In the middle of other data, at any alignment.
    for (size_t pad : {1u, 2u, 3u, 4u, 5u, 7u}) {
        Bytes d(pad, 0x55);
        append(d, t);
        EXPECT(kernel::plausible_tree(d, pad));
        EXPECT(!kernel::plausible_tree(d, pad + 1));
    }
    // A blob cut short, or too long for the data it is in.
    EXPECT(!kernel::plausible_tree(Bytes(t.begin(), t.end() - 1), 0));
    EXPECT(!kernel::plausible_tree(Bytes(t.begin(), t.begin() + 39), 0));
    EXPECT(!kernel::plausible_tree(Bytes{}, 0));
    EXPECT(!kernel::plausible_tree(t, t.size()));
    EXPECT(!kernel::plausible_tree(t, t.size() + 100));

    auto be32_at = [](Bytes& b, size_t o, uint32_t v) {
        b[o] = static_cast<uint8_t>(v >> 24), b[o + 1] = static_cast<uint8_t>(v >> 16), b[o + 2] = static_cast<uint8_t>(v >> 8), b[o + 3] = static_cast<uint8_t>(v);
    };
    auto be32_of = [](const Bytes& b, size_t o) { return (uint32_t{b[o]} << 24) | (uint32_t{b[o + 1]} << 16) | (uint32_t{b[o + 2]} << 8) | uint32_t{b[o + 3]}; };
    struct Case {
        const char* what;
        size_t offset;
        uint32_t value;
    };
    const uint32_t total = be32_of(t, 4), off_struct = be32_of(t, 8), size_struct = be32_of(t, 36);
    const Case bad[] = {
        {"magic", 0, 0xd00dfeee},
        {"totalsize below the header", 4, 39},
        {"totalsize above the data", 4, total + 1},
        {"version 2", 20, 2},
        {"version 18", 20, 18},
        {"last_comp_version above the version", 24, 18},
        {"memory reservation map before the header's end", 16, 32},
        {"memory reservation map not at a multiple of 8", 16, 44},
        {"memory reservation map at the end of the blob", 16, total - 8},
        {"structure block before the header's end", 8, 36},
        {"structure block not at a multiple of 4", 8, off_struct + 2},
        {"structure block at the end of the blob", 8, total - 4},
        {"structure size odd", 36, size_struct - 1},
        {"structure size above the blob", 36, total},
        {"structure size too small", 36, 8},
        {"first token is not the root node", off_struct, 2},
        {"the root has a name", off_struct + 4, 0x61000000},
        {"no FDT_END at the end of the structure", off_struct + size_struct - 4, 3},
        {"the strings block is out of the blob", 12, total + 4},
        {"the strings size is out of the blob", 32, total},
    };
    for (const Case& c : bad) {
        Bytes m = t;
        be32_at(m, c.offset, c.value);
        if (kernel::plausible_tree(m, 0)) {
            ++g_failures;
            std::printf("  FAIL plausible_tree took a tree with %s\n", c.what);
        }
        ++g_checks;
    }
    // What the header may say otherwise: the boot cpu, the version 16 blob (no size of the structure block).
    Bytes cpu = t;
    be32_at(cpu, 28, 3);
    EXPECT(kernel::plausible_tree(cpu, 0));
    Bytes v16 = t;
    be32_at(v16, 20, 16);
    be32_at(v16, 24, 16);
    EXPECT(kernel::plausible_tree(v16, 0));
}

void test_find() {
    std::mt19937 rng(7);
    const Bytes kernel_bytes = junk(20000, rng);

    // Nothing there.
    EXPECT(!kernel::find_appended_trees(Bytes{}));
    EXPECT(!kernel::find_appended_trees(kernel_bytes));
    EXPECT(!kernel::find_appended_trees(tree(2, 1)));  // a dtb: there is nothing in front of the tree

    // One tree, several, contiguous.
    {
        Bytes d = kernel_bytes;
        append(d, tree(4, 1));
        const auto a = kernel::find_appended_trees(d);
        EXPECT(a && a->start == 20000 && a->trees == 1 && a->consumed == d.size());
    }
    {
        Bytes d = kernel_bytes;
        const Bytes a1 = tree(4, 1), a2 = tree(9, 2), a3 = tree(0, 3);
        append(d, a1), append(d, a2), append(d, a3);
        const auto a = kernel::find_appended_trees(d);
        EXPECT(a && a->start == 20000 && a->trees == 3 && a->consumed == d.size());
    }
    // The tree starts at a place that is not a multiple of anything (the end of a stream).
    for (size_t at : {20001u, 20002u, 20003u, 20007u, 20013u}) {
        Bytes d(kernel_bytes.begin(), kernel_bytes.begin() + static_cast<std::ptrdiff_t>(at));
        append(d, tree(5, 4));
        const auto a = kernel::find_appended_trees(d);
        EXPECT(a && a->start == at && a->trees == 1 && a->consumed == d.size());
    }
    // Trees put at multiples of 4, 8, 16, 4096: zeros between them, and the end of the last is where the trees end.
    for (size_t align : {4u, 8u, 16u, 4096u}) {
        Bytes d = kernel_bytes;  // 20000 is a multiple of 16, not of 4096
        const size_t first = d.size();
        std::vector<Bytes> blobs = {tree(3, 1), tree(8, 2), tree(1, 3), tree(12, 4)};
        for (size_t i = 0; i < blobs.size(); ++i) {
            if (i > 0) d.insert(d.end(), (align - d.size() % align) % align, 0);
            append(d, blobs[i]);
        }
        const auto a = kernel::find_appended_trees(d);
        EXPECT(a && a->start == first && a->trees == 4 && a->consumed == d.size());
    }
    // A tail: zeros of any size, a few bytes of anything, a marker; not a lot of anything.
    {
        Bytes base = kernel_bytes;
        append(base, tree(3, 1));
        append(base, tree(5, 2));
        const size_t end = base.size();
        for (size_t zeros : {1u, 3u, 100u, 5000u, 70000u, 1000000u}) {
            Bytes d = base;
            d.insert(d.end(), zeros, 0);
            const auto a = kernel::find_appended_trees(d);
            EXPECT(a && a->start == 20000 && a->trees == 2 && a->consumed == end);
        }
        for (size_t other : std::vector<size_t>{1, 16, 100, 4096, kernel::kMaxTailBehindTrees}) {
            Bytes d = base;
            Bytes t = junk(other, rng);
            t[0] = 0x41;  // (not a tree, not zero)
            append(d, t);
            const auto a = kernel::find_appended_trees(d);
            EXPECT(a && a->start == 20000 && a->trees == 2 && a->consumed == end);
        }
        for (size_t other : std::vector<size_t>{kernel::kMaxTailBehindTrees + 1, 100000}) {
            Bytes d = base;
            Bytes t = junk(other, rng);
            t[0] = 0x41;
            append(d, t);
            EXPECT(!kernel::find_appended_trees(d));  // code and data: the trees are the kernel's own
        }
        // Zeros first, then the marker: that is not zeros only, and a short one at that.
        Bytes d = base;
        d.insert(d.end(), 100, 0);
        append(d, Bytes{'S', 'E', 'A', 'N', 'D', 'R', 'O', 'I', 'D'});
        const auto a = kernel::find_appended_trees(d);
        EXPECT(a && a->trees == 2 && a->consumed == end);
    }
    // A tree inside the kernel with a lot of kernel behind it is not glued; the trees that end the data are, and are found behind it.
    {
        Bytes inner = kernel_bytes;
        append(inner, tree(6, 9));
        const size_t embedded_at = kernel_bytes.size();
        append(inner, junk(200000, rng));
        EXPECT(!kernel::find_appended_trees(inner));
        const size_t glued_at = inner.size();
        append(inner, tree(2, 1));
        append(inner, tree(7, 2));
        const auto a = kernel::find_appended_trees(inner);
        EXPECT(a && a->start == glued_at && a->trees == 2 && a->consumed == inner.size());
        EXPECT(a && a->start != embedded_at);
        // (a tree inside the data right behind which little follows is the end of the kernel: that is the rule, small tails are tails)
        Bytes near_end = kernel_bytes;
        append(near_end, tree(6, 9));
        append(near_end, junk(1000, rng));
        const auto b = kernel::find_appended_trees(near_end);
        EXPECT(b && b->start == embedded_at && b->trees == 1);
    }
    // The magic where no tree is: in a stream of random bytes, in a header that does not hold together, as the last bytes.
    {
        Bytes d = kernel_bytes;
        for (size_t at : {100u, 5001u, 19990u}) {
            d[at] = 0xd0, d[at + 1] = 0x0d, d[at + 2] = 0xfe, d[at + 3] = 0xed;
        }
        EXPECT(!kernel::find_appended_trees(d));
        append(d, tree(3, 5));
        const auto a = kernel::find_appended_trees(d);
        EXPECT(a && a->start == 20000 && a->trees == 1);
        Bytes cut = kernel_bytes;
        const Bytes t = tree(3, 5);
        cut.insert(cut.end(), t.begin(), t.end() - 3);  // the last tree is cut short
        EXPECT(!kernel::find_appended_trees(cut));
        Bytes magic_only = kernel_bytes;
        append(magic_only, Bytes{0xd0, 0x0d, 0xfe, 0xed});
        EXPECT(!kernel::find_appended_trees(magic_only));
    }
    // A tree behind the stream and then a second one that is cut short: the cut is what split_fdt_blobs() refuses to cut at (a damaged
    // image, not a kernel with trees), so the kernel is left as it is -- nothing is taken out of it that cannot be put back.
    {
        Bytes d = kernel_bytes;
        append(d, tree(3, 1));
        const Bytes second = tree(3, 2);
        d.insert(d.end(), second.begin(), second.begin() + 60);
        EXPECT(!kernel::find_appended_trees(d));
        // ... and the same two whole: both are glued.
        Bytes both = kernel_bytes;
        append(both, tree(3, 1));
        append(both, second);
        const auto a = kernel::find_appended_trees(both);
        EXPECT(a && a->start == 20000 && a->trees == 2 && a->consumed == both.size());
    }
}

void test_random_layouts() {
    std::mt19937 rng(20261121);
    for (int round = 0; round < 3000; ++round) {
        const size_t head = 1 + rng() % 5000;
        Bytes d = junk(head, rng);
        // keep the junk from being a tree by accident (it cannot be: the header has to hold together), and from ending in zeros that
        // would count as a gap in front of the first tree -- they do not: the first tree is the first thing that is one
        const size_t count = 1 + rng() % 5;
        const size_t aligns[] = {1, 1, 4, 8, 16, 64, 4096};
        const size_t align = aligns[rng() % 7];
        const size_t first = d.size();
        size_t end = 0;
        for (size_t i = 0; i < count; ++i) {
            if (i > 0 && align > 1) d.insert(d.end(), (align - d.size() % align) % align, 0);
            append(d, tree(rng() % 20, static_cast<uint32_t>(rng() % 1000)));
            end = d.size();
        }
        const size_t tail_kind = rng() % 4;
        if (tail_kind == 1) d.insert(d.end(), rng() % 70000, 0);
        if (tail_kind == 2) {
            Bytes t = junk(1 + rng() % 200, rng);
            t[0] = 0x41;
            append(d, t);
        }
        const auto a = kernel::find_appended_trees(d);
        const bool ok = a && a->start == first && a->trees == count && a->consumed == end;
        ++g_checks;
        if (!ok) {
            ++g_failures;
            std::printf("  FAIL round %d: head %zu, %zu trees, align %zu, tail kind %zu: %s\n", round, head, count, align, tail_kind,
                        a ? ("start " + std::to_string(a->start) + " trees " + std::to_string(a->trees) + " consumed " + std::to_string(a->consumed)).c_str() : "none");
        }
    }
}

}  // namespace

int run_kernel_tests() {
    test_plausible();
    test_find();
    test_random_layouts();
    if (g_failures == 0) std::printf("kernel: ok (%d checks)\n", g_checks);
    else std::printf("kernel: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
