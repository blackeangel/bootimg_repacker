// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of the FIT layer (include/abr/fit.hpp). Run by tests/run_tests.sh as `abr_unit_tests fit`; `abr_unit_tests fit-files FILE...`
// is the check of files that mkimage made: every file that open() takes must come back from build() byte for byte, and a file it
// does not take says why.
//
//   * a FIT of random images (data of every length, in any place of the node, hash nodes of every algorithm, configurations) built
//     in every place -- inline, offset, position -- with every alignment and free space: open() takes it, finds the images, and what
//     it gives back builds to the file again; bytes behind the FIT are not taken;
//   * the layout of the images that are behind the tree: an image that grows moves the ones behind it (to the next multiple of the
//     alignment), an image that does not change size stays where it is, a new one goes last, a place that is changed is written in
//     the other properties, and a tree that grows into the first image of a position FIT, images that overlap, a number that does not
//     fit in 32 bits are refused;
//   * what open() says no to, with the reason: two images of one name, `data` and `data-offset` in one node, images inline and behind
//     the tree, offsets and positions, a size that is not a cell, an image behind the end of the file, bytes that are not zero between
//     the images, images that overlap, no /images, a tree that dtc does not lay out like that;
//   * the hash nodes: the digest of every algorithm (crc32, md5, sha1, sha256, sha384, sha512) against the known answers, a node
//     without a value gets one first in the node, an algorithm that is not known is named and left; wrong_hashes() finds the nodes
//     whose value is not the digest;
//   * the end of the tree: mkimage -E pads it to a multiple of its -B so that the first image is aligned, and a tree that grows keeps
//     that; a layout that has `slack` bytes keeps them; an alignment that is not a power of two is refused;
//   * the signature nodes of images and configurations: all of them, and the ones an image that changed makes wrong;
//   * what mkimage leaves behind the `hashed-nodes` of a signature (bytes that are not zero behind a value): the FIT is taken in every
//     place, comes back byte for byte through the text, and the text says it; behind the data of an image in the tree it is refused;
//   * a file that is cut anywhere or has bytes changed (3000 of them): open() never throws, and what it takes comes back.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/dts.hpp"
#include "abr/fdt.hpp"
#include "abr/fit.hpp"
#include "abr/sha.hpp"

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

// ------------------------------------------------------------------ trees --

fdt::Property text_prop(const std::string& name, const std::string& text) {
    fdt::Property p;
    p.name = name;
    p.value.assign(text.begin(), text.end());
    p.value.push_back(0);
    return p;
}

fdt::Property cells_prop(const std::string& name, std::initializer_list<uint32_t> cells) {
    fdt::Property p;
    p.name = name;
    for (uint32_t c : cells)
        for (int s = 24; s >= 0; s -= 8) p.value.push_back(static_cast<uint8_t>(c >> s));
    return p;
}

fdt::Property bytes_prop(const std::string& name, const Bytes& value) {
    fdt::Property p;
    p.name = name;
    p.value = value;
    return p;
}

Bytes random_bytes(std::mt19937_64& rng, size_t n, bool nonzero_first = false) {
    Bytes b(n);
    for (uint8_t& c : b) c = static_cast<uint8_t>(rng());
    if (nonzero_first && n && b[0] == 0) b[0] = 1;
    return b;
}

fdt::Node* images_of(fdt::Tree& t) { return t.root.find_child("images"); }

// A FIT of `count` images with random data (the data is in the `data` property of every node, wherever the node has the place for it).
fdt::Tree random_fit(std::mt19937_64& rng, size_t count, std::vector<Bytes>* data_out = nullptr) {
    static const size_t sizes[] = {0, 1, 3, 4, 5, 7, 8, 13, 16, 100, 700, 1000, 3000, 4097};
    static const char* types[] = {"kernel", "flat_dt", "ramdisk", "script", "firmware"};
    static const char* algos[] = {"crc32", "md5", "sha1", "sha256", "sha384", "sha512"};
    fdt::Tree t;
    t.root.props.push_back(text_prop("description", "random FIT"));
    t.root.props.push_back(cells_prop("timestamp", {static_cast<uint32_t>(rng())}));
    fdt::Node images;
    images.name = "images";
    for (size_t i = 0; i < count; ++i) {
        fdt::Node n;
        n.name = std::string(types[i % 5]) + "-" + std::to_string(i + 1);
        n.props.push_back(text_prop("description", "image " + std::to_string(i)));
        n.props.push_back(text_prop("type", types[i % 5]));
        n.props.push_back(text_prop("arch", "arm64"));
        n.props.push_back(text_prop("compression", "none"));
        n.props.push_back(cells_prop("load", {0x0, static_cast<uint32_t>(0x80000 * (i + 1))}));
        const Bytes data = random_bytes(rng, sizes[rng() % (sizeof sizes / sizeof sizes[0])]);
        if (data_out) data_out->push_back(data);
        n.props.insert(n.props.begin() + static_cast<std::ptrdiff_t>(rng() % (n.props.size() + 1)), bytes_prop("data", data));
        const size_t hashes = rng() % 3;
        for (size_t h = 0; h < hashes; ++h) {
            fdt::Node hash;
            hash.name = "hash-" + std::to_string(h + 1);
            const std::string algo = algos[rng() % 6];
            hash.props.push_back(bytes_prop("value", *fit::hash_value(algo, data)));
            hash.props.push_back(text_prop("algo", algo));
            n.children.push_back(std::move(hash));
        }
        images.children.push_back(std::move(n));
    }
    t.root.children.push_back(std::move(images));
    fdt::Node configs;
    configs.name = "configurations";
    configs.props.push_back(text_prop("default", "conf-1"));
    fdt::Node conf;
    conf.name = "conf-1";
    conf.props.push_back(text_prop("description", "first"));
    if (count) conf.props.push_back(text_prop("kernel", t.root.children[0].children[0].name));
    configs.children.push_back(std::move(conf));
    t.root.children.push_back(std::move(configs));
    return t;
}

// What a repack of the unpacked files does with the text of the tree and the data of the images, in memory.
Bytes assemble(const fit::Opened& o, const std::vector<Bytes>& data) {
    fdt::Tree named = o.tree;
    fdt::Node* images = images_of(named);
    for (size_t k = 0; k < o.images.size(); ++k)
        if (!data[k].empty()) images->children[o.images[k].index].find_prop("data")->incbin = "x";
    fdt::Tree back = dts::parse(dts::print(named), "the text");
    back.version = o.tree.version;
    back.last_comp_version = o.tree.last_comp_version;
    back.boot_cpuid_phys = o.tree.boot_cpuid_phys;
    back.strings = o.tree.strings;
    fdt::Node* back_images = images_of(back);
    for (size_t k = 0; k < o.images.size(); ++k) {
        fdt::Property* p = back_images->children[o.images[k].index].find_prop("data");
        p->value = data[k];
        p->incbin.clear();
    }
    return fit::build(std::move(back), o.layout);
}

std::vector<Bytes> data_of(const fit::Opened& o) {
    std::vector<Bytes> out;
    for (const fit::Image& im : o.images) out.push_back(im.data);
    return out;
}

uint32_t cell(const fdt::Node& n, const char* name) {
    const fdt::Property* p = n.find_prop(name);
    if (!p || p->value.size() != 4) return 0xdeadbeef;
    return (uint32_t(p->value[0]) << 24) | (uint32_t(p->value[1]) << 16) | (uint32_t(p->value[2]) << 8) | p->value[3];
}

// ------------------------------------------------------------------ tests --

void test_fit_hash_values() {
    const Bytes abc = {'a', 'b', 'c'};
    auto hex = [](const std::optional<Bytes>& b) {
        std::string s;
        if (!b) return std::string("(none)");
        for (uint8_t c : *b) {
            static const char* d = "0123456789abcdef";
            s += d[c >> 4];
            s += d[c & 15];
        }
        return s;
    };
    EXPECT(hex(fit::hash_value("crc32", abc)) == "352441c2");  // crc32("abc")
    EXPECT(hex(fit::hash_value("crc32", {})) == "00000000");
    EXPECT(hex(fit::hash_value("md5", abc)) == "900150983cd24fb0d6963f7d28e17f72");
    EXPECT(hex(fit::hash_value("md5", {})) == "d41d8cd98f00b204e9800998ecf8427e");
    EXPECT(hex(fit::hash_value("sha1", abc)) == "a9993e364706816aba3e25717850c26c9cd0d89d");
    EXPECT(hex(fit::hash_value("sha256", abc)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT(hex(fit::hash_value("sha384", abc)) ==
           "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    EXPECT(hex(fit::hash_value("sha512", abc)) ==
           "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    EXPECT(!fit::hash_value("sha3-256", abc));
    EXPECT(!fit::hash_value("SHA256", abc));
    EXPECT(!fit::hash_value("", abc));
    // The RFC 1321 test suite
    EXPECT(hex(hash::md5(Bytes{'a'})) == "0cc175b9c0f1b6a831c399e269772661");
    const std::string digits = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    EXPECT(hex(hash::md5(Bytes(digits.begin(), digits.end()))) == "57edf4a22be3c955ac49da2e2107b67a");
}

void test_fit_roundtrip() {
    std::mt19937_64 rng(20261101);
    static const fit::Place places[] = {fit::Place::INLINE, fit::Place::OFFSET, fit::Place::POSITION};
    static const size_t aligns[] = {4, 8, 16, 64, 0x100, 0x800};
    static const size_t ends[] = {1, 4, 8, 0x40};
    static const size_t slacks[] = {0, 2, 4, 7, 64};
    int taken = 0;
    for (int round = 0; round < 1500; ++round) {
        std::vector<Bytes> data;
        const size_t count = rng() % 6;
        fdt::Tree tree = random_fit(rng, count, &data);
        fit::Layout layout;
        layout.place = places[rng() % 3];
        layout.align = aligns[rng() % 6];
        layout.end_align = layout.place == fit::Place::INLINE ? 1 : ends[rng() % 4];
        layout.slack = slacks[rng() % 5];
        const Bytes file = fit::build(tree, layout);
        std::string why;
        const std::optional<fit::Opened> o = fit::open(file, why);
        if (!o) {
            // (an inline FIT of no images with data is a plain tree, and every other one comes back)
            ++g_checks;
            ++g_failures;
            std::printf("  FAIL %s:%d: round %d (place %s, %zu images, align %zu, end %zu, slack %zu) is not taken: %s\n", __FILE__, __LINE__, round,
                        fit::place_name(layout.place), count, layout.align, layout.end_align, layout.slack, why.c_str());
            continue;
        }
        ++taken;
        EXPECT(o->layout.place == (count ? layout.place : fit::Place::INLINE));
        EXPECT(o->layout.slack == layout.slack);
        EXPECT(o->images.size() == count);
        for (size_t k = 0; k < o->images.size() && k < count; ++k) {
            EXPECT(o->images[k].index == k);
            EXPECT(o->images[k].data == data[k]);
        }
        EXPECT(o->consumed <= file.size());
        for (size_t b = o->consumed; b < file.size(); ++b)
            if (file[b] != 0) {
                EXPECT(false);
                break;
            }
        const Bytes again = assemble(*o, data_of(*o));
        EXPECT(again.size() == o->consumed && std::equal(again.begin(), again.end(), file.begin()));
        // What is behind the FIT is not the FIT's.
        Bytes longer = file;
        const Bytes junk = random_bytes(rng, 1 + rng() % 300, true);
        longer.insert(longer.end(), junk.begin(), junk.end());
        std::string why2;
        const std::optional<fit::Opened> o2 = fit::open(longer, why2);
        EXPECT(o2.has_value());
        if (o2) {
            EXPECT(o2->consumed == o->consumed);
            EXPECT(data_of(*o2) == data_of(*o));
        }
    }
    EXPECT(taken == 1500);
}

void test_fit_layout() {
    std::mt19937_64 rng(77);
    // Three images of 3000, 700 and 14 bytes in the offset place, as mkimage -E lays them out.
    auto make = [&](fit::Place place, size_t align, const std::vector<size_t>& sizes, std::vector<Bytes>& data) {
        fdt::Tree tree = random_fit(rng, sizes.size());
        data.clear();
        for (size_t i = 0; i < sizes.size(); ++i) {
            data.push_back(random_bytes(rng, sizes[i], true));
            images_of(tree)->children[i].find_prop("data")->value = data.back();
            images_of(tree)->children[i].children.clear();  // (hashes are not what this is about)
        }
        fit::Layout layout;
        layout.place = place;
        layout.align = align;
        layout.end_align = 4;
        return std::make_pair(std::move(tree), layout);
    };
    std::vector<Bytes> data;
    {
        auto [tree, layout] = make(fit::Place::OFFSET, 4, {3000, 700, 14}, data);
        const Bytes file = fit::build(tree, layout);
        std::string why;
        std::optional<fit::Opened> o = fit::open(file, why);
        EXPECT(o.has_value());
        if (o) {
            const fdt::Node* images = images_of(o->tree);
            EXPECT(cell(images->children[0], "data-offset") == 0);
            EXPECT(cell(images->children[0], "data-size") == 3000);
            EXPECT(cell(images->children[1], "data-offset") == 3000);
            EXPECT(cell(images->children[2], "data-offset") == 3700);
            EXPECT(o->layout.align == 4);
            EXPECT(o->layout.end_align == 4);
            EXPECT(o->consumed == file.size());
            // new properties are first in their node (libfdt puts a property there), as mkimage -E has them: data-size, data-offset
            const fdt::Tree raw = fdt::parse(file);
            const fdt::Node& raw_first = raw.root.find_child("images")->children[0];
            EXPECT(raw_first.props.size() >= 2 && raw_first.props[0].name == "data-size" && raw_first.props[1].name == "data-offset");
            EXPECT(raw_first.find_prop("data") == nullptr);
            // open() puts a `data` where they are: the data of the image is there when it is packed again
            EXPECT(images->children[0].props.size() >= 3 && images->children[0].props[0].name == "data" &&
                   images->children[0].props[1].name == "data-size");

            // The first image grows by five bytes: the others move, to the next multiple of four.
            std::vector<Bytes> grown = data_of(*o);
            grown[0] = random_bytes(rng, 3005, true);
            const Bytes edited = assemble(*o, grown);
            std::string why2;
            std::optional<fit::Opened> o2 = fit::open(edited, why2);
            EXPECT(o2.has_value());
            if (o2) {
                const fdt::Node* im = images_of(o2->tree);
                EXPECT(cell(im->children[0], "data-size") == 3005);
                EXPECT(cell(im->children[1], "data-offset") == 3008);
                EXPECT(cell(im->children[2], "data-offset") == 3708);
                EXPECT(data_of(*o2) == grown);
            }
            // A second image gets smaller: the third follows it
            grown = data_of(*o);
            grown[1] = random_bytes(rng, 5, true);
            std::string why3;
            std::optional<fit::Opened> o3 = fit::open(assemble(*o, grown), why3);
            EXPECT(o3.has_value());
            if (o3) {
                const fdt::Node* im = images_of(o3->tree);
                EXPECT(cell(im->children[0], "data-offset") == 0);
                EXPECT(cell(im->children[1], "data-offset") == 3000);
                EXPECT(cell(im->children[2], "data-offset") == 3008);
                EXPECT(data_of(*o3) == grown);
            }
            // The same sizes with other bytes: nothing moves
            grown = data_of(*o);
            grown[2] = random_bytes(rng, 14, true);
            const Bytes same_size = assemble(*o, grown);
            EXPECT(same_size.size() == file.size());
            const size_t base = file.size() - 3716;  // (3000 + 700 + 14 bytes of images, up to a multiple of four)
            EXPECT(same_size.size() == file.size() &&
                   std::equal(same_size.begin(), same_size.begin() + static_cast<std::ptrdiff_t>(base + 3700), file.begin()));
            EXPECT(std::equal(same_size.begin() + static_cast<std::ptrdiff_t>(base + 3700), same_size.begin() + static_cast<std::ptrdiff_t>(base + 3714),
                              grown[2].begin()));

            // The place changes: the properties of the other place go, and the images are where they were counted from the start
            std::vector<Bytes> same = data_of(*o);
            fit::Opened copy = *o;
            copy.layout.place = fit::Place::POSITION;
            const Bytes as_position = assemble(copy, same);
            fdt::Layout lay4;
            (void)fdt::parse(as_position, &lay4);
            std::string why4;
            std::optional<fit::Opened> o4 = fit::open(as_position, why4);
            EXPECT(o4.has_value());
            if (o4) {
                EXPECT(o4->layout.place == fit::Place::POSITION);
                const fdt::Node* im = images_of(o4->tree);
                EXPECT(im->children[0].find_prop("data-offset") == nullptr);
                EXPECT(im->children[0].find_prop("data-position") != nullptr);
                // the images follow the tree, one behind the other, each at a multiple of four
                const uint32_t p0 = cell(im->children[0], "data-position");
                EXPECT(p0 == (lay4.total_size + 3) / 4 * 4);
                EXPECT(cell(im->children[1], "data-position") == p0 + 3000);
                EXPECT(cell(im->children[2], "data-position") == p0 + 3700);
                EXPECT(data_of(*o4) == same);
            }
        }
    }
    {
        // Positions: 0x800 is where the first image is, and it stays there when images change size
        auto [tree, layout] = make(fit::Place::POSITION, 0x800, {3000, 700, 14}, data);
        const Bytes file = fit::build(tree, layout);
        std::string why;
        std::optional<fit::Opened> o = fit::open(file, why);
        EXPECT(o.has_value());
        if (o) {
            const fdt::Node* images = images_of(o->tree);
            EXPECT(cell(images->children[0], "data-position") == 0x800);
            EXPECT(cell(images->children[1], "data-position") == 0x800 + 0x1000);  // 3000 up to a multiple of 0x800
            EXPECT(o->layout.align == 0x800);
            std::vector<Bytes> grown = data_of(*o);
            grown[0] = random_bytes(rng, 0x801, true);
            std::string why2;
            std::optional<fit::Opened> o2 = fit::open(assemble(*o, grown), why2);
            EXPECT(o2.has_value());
            if (o2) {
                const fdt::Node* im = images_of(o2->tree);
                EXPECT(cell(im->children[0], "data-position") == 0x800);
                EXPECT(cell(im->children[1], "data-position") == 0x800 + 0x1000);
                EXPECT(cell(im->children[2], "data-position") == 0x800 + 0x1000 + 0x800);
            }
            // A tree that grows into the first image
            fit::Opened big = *o;
            fdt::Tree& t = big.tree;
            t.root.props.push_back(text_prop("description-long", std::string(0x900, 'x')));
            const std::string refusal = refusal_of([&] { assemble(big, data_of(*o)); });
            EXPECT_HAS(refusal, "reaches the image");
            EXPECT_HAS(refusal, "data-position");
        }
    }
    {
        // A new image goes last, an image taken away leaves the others where they are
        auto [tree, layout] = make(fit::Place::OFFSET, 4, {100, 200}, data);
        const Bytes file = fit::build(tree, layout);
        std::string why;
        std::optional<fit::Opened> o = fit::open(file, why);
        EXPECT(o.has_value());
        if (o) {
            fit::Opened plus = *o;
            fdt::Node added;
            added.name = "script-9";
            added.props.push_back(text_prop("type", "script"));
            fdt::Property d;
            d.name = "data";
            added.props.push_back(d);
            images_of(plus.tree)->children.push_back(added);
            fit::Image im;
            im.index = 2;
            im.name = "script-9";
            im.data = random_bytes(rng, 30, true);
            plus.images.push_back(im);
            std::string why2;
            std::optional<fit::Opened> o2 = fit::open(assemble(plus, data_of(plus)), why2);
            EXPECT(o2.has_value());
            if (o2) {
                const fdt::Node* n = images_of(o2->tree);
                EXPECT(cell(n->children[0], "data-offset") == 0);
                EXPECT(cell(n->children[1], "data-offset") == 100);
                EXPECT(cell(n->children[2], "data-offset") == 300);
                EXPECT(o2->images.size() == 3 && o2->images[2].data == im.data);
            }
            // The first of two is taken away: the second is where the tree says (its size has not changed)
            fit::Opened less = *o;
            images_of(less.tree)->children.erase(images_of(less.tree)->children.begin());
            less.images.erase(less.images.begin());
            less.images[0].index = 0;
            std::string why3;
            std::optional<fit::Opened> o3 = fit::open(assemble(less, data_of(less)), why3);
            EXPECT(o3.has_value());
            if (o3) EXPECT(cell(images_of(o3->tree)->children[0], "data-offset") == 100);
        }
    }
    {
        // Images that overlap are refused (the numbers in the tree are kept while the sizes are what they were)
        auto [tree, layout] = make(fit::Place::OFFSET, 4, {100, 200}, data);
        const Bytes file = fit::build(tree, layout);
        std::string why;
        std::optional<fit::Opened> o = fit::open(file, why);
        EXPECT(o.has_value());
        if (o) {
            fit::Opened bad = *o;
            images_of(bad.tree)->children[1].find_prop("data-offset")->value = {0, 0, 0, 50};
            EXPECT_HAS(refusal_of([&] { assemble(bad, data_of(*o)); }), "overlap");
            fit::Opened wide = *o;
            images_of(wide.tree)->children[1].find_prop("data-offset")->value = {0xff, 0xff, 0xff, 0xf0};
            images_of(wide.tree)->children[0].find_prop("data-offset")->value = {0xff, 0xff, 0xff, 0xff};
            EXPECT(!refusal_of([&] { assemble(wide, data_of(*o)); }).empty());
            fit::Opened align = *o;
            align.layout.align = 6;
            images_of(align.tree)->children[0].find_prop("data-size")->value = {0, 0, 0, 1};  // (not the size: the layout is made again)
            EXPECT_HAS(refusal_of([&] { assemble(align, data_of(*o)); }), "power of two");
            fit::Opened ends = *o;
            ends.layout.end_align = 12;
            EXPECT_HAS(refusal_of([&] { assemble(ends, data_of(*o)); }), "power of two");
        }
    }
}

// A file whose tree is `tree` (laid out as build() does), with `after` behind it.
Bytes file_of(const fdt::Tree& tree, const Bytes& after = {}) {
    Bytes b = fdt::build(tree, 0);
    b.insert(b.end(), after.begin(), after.end());
    return b;
}

void test_fit_tree_end() {
    std::mt19937_64 rng(0x54524545ull);
    auto total_of = [](const Bytes& file) { return (size_t{file[4]} << 24) | (size_t{file[5]} << 16) | (size_t{file[6]} << 8) | file[7]; };
    static const size_t aligns[] = {4, 8, 16, 0x100, 0x1000};
    for (const fit::Place place : {fit::Place::OFFSET, fit::Place::POSITION}) {
        for (const size_t t : aligns) {
            // the tree ends at a multiple of t, whatever its size, and `slack` is not used
            size_t checked = 0;
            for (size_t grow = 0; grow < 41; ++grow) {
                std::vector<Bytes> data;
                fdt::Tree tree = random_fit(rng, 3, &data);
                tree.root.props.push_back(bytes_prop("filler", Bytes(grow, 0x41)));
                fit::Layout layout;
                layout.place = place;
                layout.align = 4;
                layout.tree_align = t;
                layout.slack = 99;
                Bytes file;
                try {
                    file = fit::build(tree, layout);
                } catch (const FormatError& e) {
                    EXPECT(false);
                    std::printf("  place %s, tree_align %zu, filler %zu: %s\n", fit::place_name(place), t, grow, e.what());
                    continue;
                }
                EXPECT(total_of(file) % t == 0);
                std::string why;
                const std::optional<fit::Opened> o = fit::open(file, why);
                EXPECT(o.has_value());
                if (!o) continue;
                fdt::Layout lay;
                fdt::parse(file, &lay);
                // (the smallest alignment that makes the blob end where it does: no more is known of the -B it was made with)
                const size_t derived = o->layout.tree_align;
                EXPECT(derived >= 4 && (derived & (derived - 1)) == 0 && derived <= t);
                EXPECT(derived && (lay.used + derived - 1) / derived * derived == lay.total_size);
                EXPECT(derived == 4 || (lay.total_size - lay.used) >= derived / 2);
                // and it comes back as it is
                try {
                    const Bytes again = assemble(*o, data_of(*o));
                    EXPECT(again.size() == o->consumed && std::equal(again.begin(), again.end(), file.begin()));
                } catch (const FormatError& e) {
                    EXPECT(false);
                    std::printf("  place %s, tree_align %zu (derived %zu), filler %zu, used %zu, total %zu: %s\n", fit::place_name(place), t, derived, grow,
                                lay.used, lay.total_size, e.what());
                }
                ++checked;
            }
            EXPECT(checked == 41);
        }
    }
    {
        // a tree that grows keeps the alignment of its end (the offsets of the images count from it, so they move with it; a position
        // is where the file has it, and a tree that grows into the first image is refused, which the other tests have)
        for (const fit::Place place : {fit::Place::OFFSET}) {
            size_t known = 0;
            for (size_t len = 0; len < 24; ++len) {
                std::vector<Bytes> data;
                fdt::Tree tree = random_fit(rng, 2, &data);
                tree.root.props.push_back(bytes_prop("filler", Bytes(len, 0x42)));
                fit::Layout layout;
                layout.place = place;
                layout.align = 4;
                layout.tree_align = 16;
                const Bytes file = fit::build(tree, layout);
                std::string why;
                std::optional<fit::Opened> o = fit::open(file, why);
                if (!o) continue;
                fdt::Layout lay;
                fdt::parse(file, &lay);
                if (o->layout.tree_align != 16) continue;  // (a padding of less than 8 bytes could be the end of a tree aligned to 8, or to 4)
                ++known;
                for (size_t more = 1; more < 40; more += 3) {
                    fit::Opened grown = *o;
                    grown.tree.root.props.push_back(bytes_prop("more", Bytes(more, 0x43)));
                    const Bytes edited = assemble(grown, data_of(grown));
                    EXPECT(total_of(edited) % 16 == 0);
                    std::string why2;
                    EXPECT(fit::open(edited, why2).has_value());
                }
            }
            EXPECT(known > 0);
        }
    }
    {
        // an alignment of 0 or 1 is no alignment: the `slack` bytes are what is behind the strings, whatever the size of the tree
        std::vector<Bytes> data;
        fdt::Tree tree = random_fit(rng, 2, &data);
        fit::Layout layout;
        layout.place = fit::Place::OFFSET;
        layout.slack = 37;
        for (const size_t ta : {size_t{0}, size_t{1}}) {
            layout.tree_align = ta;
            const Bytes file = fit::build(tree, layout);
            fdt::Layout lay;
            fdt::parse(file, &lay);
            EXPECT(lay.total_size - lay.used == 37);
        }
        layout.tree_align = 6;
        EXPECT_HAS(refusal_of([&] { fit::build(tree, layout); }), "fit_tree_align) is 6, not a power of two");
        // inline: the tree is the file, with its slack
        layout.place = fit::Place::INLINE;
        layout.tree_align = 16;
        const Bytes file = fit::build(tree, layout);
        fdt::Layout lay;
        fdt::parse(file, &lay);
        EXPECT(lay.total_size - lay.used == 37);
    }
}

void test_fit_refusals() {
    std::mt19937_64 rng(5);
    auto refused = [&](const Bytes& file) {
        std::string why;
        const std::optional<fit::Opened> o = fit::open(file, why);
        EXPECT(!o.has_value());
        return why;
    };
    {
        fdt::Tree t = random_fit(rng, 2);
        images_of(t)->children[1].name = images_of(t)->children[0].name;
        EXPECT_HAS(refused(file_of(t)), "two images are called");
    }
    {
        fdt::Tree t = random_fit(rng, 1);
        images_of(t)->children[0].props.push_back(cells_prop("data-offset", {0}));
        EXPECT_HAS(refused(file_of(t)), "has `data` and also");
    }
    {
        // one inline, one behind the tree
        fdt::Tree t = random_fit(rng, 2);
        fdt::Node& second = images_of(t)->children[1];
        second.props.erase(std::remove_if(second.props.begin(), second.props.end(), [](const fdt::Property& p) { return p.name == "data"; }), second.props.end());
        second.props.push_back(cells_prop("data-size", {4}));
        second.props.push_back(cells_prop("data-offset", {0}));
        EXPECT_HAS(refused(file_of(t, Bytes(16, 0))), "in the tree and some behind it");
    }
    {
        // an offset and a position
        fdt::Tree t = random_fit(rng, 2);
        for (size_t i = 0; i < 2; ++i) {
            fdt::Node& n = images_of(t)->children[i];
            n.props.erase(std::remove_if(n.props.begin(), n.props.end(), [](const fdt::Property& p) { return p.name == "data"; }), n.props.end());
            n.props.push_back(cells_prop("data-size", {4}));
            n.props.push_back(cells_prop(i == 0 ? "data-offset" : "data-position", {0}));
        }
        EXPECT_HAS(refused(file_of(t, Bytes(16, 0))), "a data-offset and some a data-position");
    }
    auto external = [&](const char* start_name, std::initializer_list<std::pair<uint32_t, uint32_t>> places) {
        fdt::Tree t = random_fit(rng, static_cast<size_t>(places.size()));
        size_t i = 0;
        for (const auto& pl : places) {
            fdt::Node& n = images_of(t)->children[i++];
            n.props.erase(std::remove_if(n.props.begin(), n.props.end(), [](const fdt::Property& p) { return p.name == "data"; }), n.props.end());
            n.props.push_back(cells_prop("data-size", {pl.second}));
            n.props.push_back(cells_prop(start_name, {pl.first}));
        }
        return t;
    };
    {
        fdt::Tree t = external("data-offset", {{0, 10}});
        images_of(t)->children[0].find_prop("data-size")->value = {0, 0, 0, 0, 0, 0, 0, 10};
        EXPECT_HAS(refused(file_of(t, Bytes(64, 0))), "not what an image behind the tree has");
        fdt::Tree u = external("data-offset", {{0, 10}});
        fdt::Node& un = u.root.find_child("images")->children[0];
        un.props.erase(std::remove_if(un.props.begin(), un.props.end(), [](const fdt::Property& p) { return p.name == "data-offset"; }), un.props.end());
        EXPECT_HAS(refused(file_of(u, Bytes(64, 0))), "not what an image behind the tree has");
    }
    {
        fdt::Tree t = external("data-offset", {{0, 100}});
        EXPECT_HAS(refused(file_of(t, Bytes(50, 0))), "behind the end of the file");
    }
    {
        // a gap that is not zero, then images on top of each other, then an image on the tree
        fdt::Tree t = external("data-offset", {{0, 8}, {16, 8}});
        Bytes file = file_of(t, Bytes(40, 0));
        const size_t base = (fdt::build(t, 0).size() + 3) / 4 * 4;
        file[base + 10] = 0x55;
        EXPECT_HAS(refused(file), "bytes that are not zero");
        file[base + 10] = 0;
        std::string why;
        EXPECT(fit::open(file, why).has_value());
        fdt::Tree over = external("data-offset", {{0, 12}, {8, 8}});
        EXPECT_HAS(refused(file_of(over, Bytes(64, 0))), "where the tree or another image is");
        fdt::Tree position = external("data-position", {{4, 8}});
        EXPECT_HAS(refused(file_of(position, Bytes(64, 0))), "where the tree or another image is");
    }
    {
        fdt::Tree t;
        t.root.props.push_back(text_prop("description", "no images"));
        EXPECT_HAS(refused(file_of(t)), "no /images");
        EXPECT(!fit::looks_like(file_of(t)));
        fdt::Node empty;
        empty.name = "images";
        t.root.children.push_back(empty);
        EXPECT(!fit::looks_like(file_of(t)));  // (an /images without a node in it is a tree that has a node of that name)
        fdt::Tree fine = random_fit(rng, 1);
        EXPECT(fit::looks_like(file_of(fine)));
        EXPECT(!fit::looks_like(Bytes()));
        EXPECT(!fit::looks_like(Bytes(100, 0)));
        EXPECT(!fit::looks_like(Bytes{0xd0, 0x0d, 0xfe, 0xed}));
    }
    {
        // a tree that is not laid out as dtc lays one out: the version word (at 20) says 16, the blocks are those of version 17
        fdt::Tree t = random_fit(rng, 1);
        Bytes file = file_of(t);
        file[23] = 16;
        EXPECT(!refused(file).empty());
    }
    {
        // the whole of an offset FIT and a cut of it anywhere before the last image is not a FIT that comes back
        fdt::Tree t = random_fit(rng, 3);
        fit::Layout layout;
        layout.place = fit::Place::OFFSET;
        layout.end_align = 4;
        for (fdt::Node& n : images_of(t)->children) n.find_prop("data")->value = random_bytes(rng, 50, true);
        const Bytes file = fit::build(t, layout);
        std::string why;
        EXPECT(fit::open(file, why).has_value());
        Bytes cut(file.begin(), file.end() - 20);
        EXPECT_HAS(refused(cut), "behind the end of the file");
    }
}

void test_fit_hash_nodes() {
    std::mt19937_64 rng(11);
    fdt::Tree t = random_fit(rng, 2);
    fdt::Node& first = images_of(t)->children[0];
    first.props.erase(std::remove_if(first.props.begin(), first.props.end(), [](const fdt::Property& p) { return p.name == "data"; }), first.props.end());
    first.props.push_back(bytes_prop("data", Bytes{'a', 'b', 'c'}));
    first.children.clear();
    const char* algos[] = {"crc32", "md5", "sha1", "sha256", "sha384", "sha512"};
    for (size_t i = 0; i < 6; ++i) {
        fdt::Node h;
        h.name = "hash-" + std::to_string(i + 1);
        h.props.push_back(text_prop("algo", algos[i]));
        if (i % 2) h.props.push_back(bytes_prop("value", Bytes(3, 0xee)));  // a wrong value, or none
        first.children.push_back(h);
    }
    fdt::Node unknown;
    unknown.name = "hash-7";
    unknown.props.push_back(text_prop("algo", "sha3-256"));
    unknown.props.push_back(bytes_prop("value", Bytes{1, 2, 3}));
    first.children.push_back(unknown);
    fdt::Node noalgo;
    noalgo.name = "hash@8";
    first.children.push_back(noalgo);
    fdt::Node other;  // not a hash node
    other.name = "cipher";
    first.children.push_back(other);
    std::vector<std::string> notes;
    const size_t count = fit::refresh_hashes(t, {0}, notes);
    EXPECT(count == 6);
    EXPECT(notes.size() == 2);
    if (notes.size() == 2) {
        EXPECT_HAS(notes[0], "sha3-256");
        EXPECT_HAS(notes[1], "no algo");
    }
    for (size_t i = 0; i < 6; ++i) {
        const fdt::Node& h = first.children[i];
        const fdt::Property* v = h.find_prop("value");
        EXPECT(v && v->value == *fit::hash_value(algos[i], Bytes{'a', 'b', 'c'}));
        if (i % 2 == 0) EXPECT(h.props.size() == 2 && h.props[0].name == "value");  // first in the node, as libfdt puts it
    }
    EXPECT(first.children[6].find_prop("value")->value == (Bytes{1, 2, 3}));  // left as it was
    EXPECT(first.children[7].props.empty() && first.children[8].props.empty());
    // the second image was not asked for
    EXPECT(fit::refresh_hashes(t, {5}, notes) == 0);

    // wrong_hashes
    fit::Image im;
    im.index = 0;
    im.name = first.name;
    im.data = Bytes{'a', 'b', 'c'};
    EXPECT(fit::wrong_hashes(t, {im}).empty());
    im.data = Bytes{'a', 'b', 'd'};
    const std::vector<std::string> wrong = fit::wrong_hashes(t, {im});
    EXPECT(wrong.size() == 6);  // the unknown algorithm and the node without one are not judged
    if (!wrong.empty()) EXPECT_HAS(wrong[0], "crc32");
}

void test_fit_signatures() {
    std::mt19937_64 rng(3);
    fdt::Tree t = random_fit(rng, 3);
    fdt::Node* images = images_of(t);
    fdt::Node sig;
    sig.name = "signature-1";
    images->children[0].children.push_back(sig);
    fdt::Node* configs = t.root.find_child("configurations");
    fdt::Node conf2;
    conf2.name = "conf-2";
    conf2.props.push_back(text_prop("description", images->children[1].name));  // (a description is not a reference)
    conf2.props.push_back(text_prop("kernel", images->children[1].name));
    fdt::Property loadables;
    loadables.name = "loadables";
    for (const char c : images->children[2].name) loadables.value.push_back(static_cast<uint8_t>(c));
    loadables.value.push_back(0);
    conf2.props.push_back(loadables);
    conf2.children.push_back(sig);
    configs->children.push_back(conf2);
    fdt::Node conf3 = conf2;
    conf3.name = "conf-3";
    conf3.props.erase(conf3.props.begin() + 1, conf3.props.end());  // only the description
    configs->children.push_back(conf3);

    const std::vector<std::string> all = fit::signatures(t);
    EXPECT(all.size() == 3);
    std::set<std::string> changed = {images->children[1].name};
    std::vector<std::string> stale = fit::stale_signatures(t, changed);
    EXPECT(stale.size() == 1 && stale[0] == "/configurations/conf-2/signature-1");
    changed = {images->children[0].name};
    stale = fit::stale_signatures(t, changed);
    EXPECT(stale.size() == 1 && stale[0] == "/images/" + images->children[0].name + "/signature-1");
    changed = {images->children[2].name, images->children[0].name};
    EXPECT(fit::stale_signatures(t, changed).size() == 2);
    EXPECT(fit::stale_signatures(t, {}).empty());
    changed = {"nothing"};
    EXPECT(fit::stale_signatures(t, changed).empty());

    // the words of `info`
    const std::string line = fit::describe_image(images->children[0]);
    EXPECT_HAS(line, "type kernel");
    EXPECT_HAS(line, "arch arm64");
    EXPECT_HAS(line, "1 signature");
    const std::vector<std::string> configs_text = fit::describe_configurations(t);
    EXPECT(configs_text.size() == 3);
    if (!configs_text.empty()) EXPECT_HAS(configs_text[0], "(the default)");
}

void test_fit_padding() {
    // What mkimage leaves behind the `hashed-nodes` of a signature (the room it makes is not cleared) is the property's: the FIT is
    // taken, comes back byte for byte through the text, and the text has the bytes. Behind the data of an image they are nobody's.
    std::mt19937_64 rng(0x50414431ull);
    static const fit::Place places[] = {fit::Place::INLINE, fit::Place::OFFSET, fit::Place::POSITION};
    static const uint8_t junk[3] = {0x98, 0x3e, 0xb2};
    for (const fit::Place place : places) {
        for (size_t pad_len = 1; pad_len <= 3; ++pad_len) {
            std::vector<Bytes> data;
            fdt::Tree tree = random_fit(rng, 2, &data);
            fdt::Node* conf = tree.root.find_child("configurations")->find_child("conf-1");
            fdt::Node sig;
            sig.name = "signature-1";
            sig.props.push_back(text_prop("algo", "sha256,rsa2048"));
            fdt::Property nodes;
            nodes.name = "hashed-nodes";
            for (const char* path : {"/", "/configurations/conf-1", "/images/kernel-1", "/images/kernel-1/hash-1"}) {
                nodes.value.insert(nodes.value.end(), path, path + std::strlen(path));
                nodes.value.push_back(0);
            }
            while (fdt::padding_size(nodes.value.size()) != pad_len) {  // (the last path gets longer until the value has the padding)
                nodes.value.pop_back();
                nodes.value.push_back('x');
                nodes.value.push_back(0);
            }
            nodes.pad.assign(junk, junk + pad_len);
            sig.props.push_back(nodes);
            sig.props.push_back(bytes_prop("value", random_bytes(rng, 256)));
            conf->children.push_back(sig);

            fit::Layout layout;
            layout.place = place;
            layout.align = 8;
            layout.end_align = place == fit::Place::INLINE ? 1 : 8;
            const Bytes file = fit::build(tree, layout);
            // (the blob has them behind the value)
            const auto at = std::search(file.begin(), file.end(), nodes.value.begin(), nodes.value.end());
            EXPECT(at != file.end());
            if (at != file.end()) EXPECT(std::equal(nodes.pad.begin(), nodes.pad.end(), at + static_cast<std::ptrdiff_t>(nodes.value.size())));

            std::string why;
            const std::optional<fit::Opened> o = fit::open(file, why);
            EXPECT(o.has_value());
            if (!o) {
                std::printf("  place %s, %zu bytes of padding: %s\n", fit::place_name(place), pad_len, why.c_str());
                continue;
            }
            EXPECT(o->layout.place == place);
            const fdt::Node* s = o->tree.root.find_child("configurations")->find_child("conf-1")->find_child("signature-1");
            const fdt::Property* found = s ? s->find_prop("hashed-nodes") : nullptr;
            EXPECT(found && found->value == nodes.value && found->pad == nodes.pad);
            EXPECT_HAS(dts::print(o->tree), "/* abr: padding");
            const Bytes again = assemble(*o, data_of(*o));
            EXPECT(again.size() == o->consumed && std::equal(again.begin(), again.end(), file.begin()));
        }
    }
    {
        // the bytes behind the data of an image in the tree are not the image's, and not the property's either
        std::vector<Bytes> data;
        fdt::Tree tree = random_fit(rng, 1, &data);
        const Bytes image = random_bytes(rng, 13, true);
        images_of(tree)->children[0].find_prop("data")->value = image;
        fit::Layout layout;
        Bytes file = fit::build(tree, layout);
        std::string why;
        EXPECT(fit::open(file, why).has_value());
        const auto at = std::search(file.begin(), file.end(), image.begin(), image.end());
        EXPECT(at != file.end());
        if (at != file.end()) {
            *(at + 13) = 0x55;
            const std::optional<fit::Opened> o = fit::open(file, why);
            EXPECT(!o.has_value());
            EXPECT_HAS(why, "are not zero");
            EXPECT_HAS(why, "behind the data of the image");
        }
    }
}

void test_fit_damaged() {
    std::mt19937_64 rng(424242);
    static const fit::Place places[] = {fit::Place::INLINE, fit::Place::OFFSET, fit::Place::POSITION};
    int taken = 0, refused = 0;
    for (int round = 0; round < 3000; ++round) {
        fdt::Tree tree = random_fit(rng, 1 + rng() % 4);
        fit::Layout layout;
        layout.place = places[rng() % 3];
        layout.align = 4u << (rng() % 4);
        layout.end_align = layout.place == fit::Place::INLINE ? 1 : 4;
        Bytes file = fit::build(tree, layout);
        const size_t kind = rng() % 4;
        if (kind == 0) {
            file.resize(rng() % (file.size() + 1));
        } else {
            const size_t flips = 1 + rng() % 4;
            for (size_t f = 0; f < flips; ++f) file[rng() % file.size()] = static_cast<uint8_t>(rng());
        }
        try {
            std::string why;
            const std::optional<fit::Opened> o = fit::open(file, why);
            if (!o) {
                ++refused;
                EXPECT(!why.empty());
                continue;
            }
            ++taken;
            const Bytes again = assemble(*o, data_of(*o));
            EXPECT(again.size() == o->consumed && o->consumed <= file.size() && std::equal(again.begin(), again.end(), file.begin()));
        } catch (const std::exception& e) {
            ++g_failures;
            ++g_checks;
            std::printf("  FAIL %s:%d: round %d threw: %s\n", __FILE__, __LINE__, round, e.what());
        }
    }
    EXPECT(taken > 100 && refused > 100);
}

}  // namespace

int run_fit_tests() {
    test_fit_hash_values();
    test_fit_roundtrip();
    test_fit_layout();
    test_fit_tree_end();
    test_fit_refusals();
    test_fit_hash_nodes();
    test_fit_signatures();
    test_fit_padding();
    test_fit_damaged();
    if (g_failures == 0) std::printf("fit: ok (%d checks)\n", g_checks);
    else std::printf("fit: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}

int run_fit_files(int argc, char** argv) {
    int bad = 0;
    for (int i = 2; i < argc; ++i) {
        try {
            const Bytes file = read_file(argv[i]);
            if (!fit::looks_like(file)) {
                std::printf("%s: not a FIT (no /images node with a node in it)\n", argv[i]);
                continue;
            }
            std::string why;
            const std::optional<fit::Opened> o = fit::open(file, why);
            if (!o) {
                std::printf("%s: a FIT that is not unpacked as one: %s\n", argv[i], why.c_str());
                continue;
            }
            const Bytes again = assemble(*o, data_of(*o));
            const bool same = again.size() == o->consumed && std::equal(again.begin(), again.end(), file.begin());
            if (!same) ++bad;
            std::printf("%s: FIT, data %s, %zu images, align %zu, end align %zu, %zu of %zu bytes, %s\n", argv[i], fit::place_name(o->layout.place),
                        o->images.size(), o->layout.align, o->layout.end_align, o->consumed, file.size(),
                        same ? "built back byte for byte" : "BUILT BACK DIFFERENTLY");
            for (const std::string& w : fit::wrong_hashes(o->tree, o->images)) std::printf("  %s\n", w.c_str());
        } catch (const std::exception& e) {
            ++bad;
            std::printf("%s: THREW %s\n", argv[i], e.what());
        }
    }
    return bad == 0 ? 0 : 1;
}
