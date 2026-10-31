// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::fdt -- a flattened device tree (the "dtb": Devicetree Specification, chapter 5) as a tree, and back to the bytes it
// was.
//
// dtb.hpp splits a file into FDT blobs by their `totalsize` and never looks inside. This looks inside: a U-Boot FIT image
// (fit.hpp) is a flattened device tree whose nodes hold the kernel, the ramdisk and the device trees, and the Qualcomm
// device tree table (qcdt.hpp) names its entries by properties of the trees it holds.
//
// The model keeps what a tool made of the blob, so that a tree that nobody touched comes back byte for byte:
//   * the nodes and properties in the order the structure block has them, a property's value as the bytes it holds;
//   * the strings block as it was. A property name is looked up in it (the first place any tool puts a name, the same way
//     libfdt and dtc find one: a name may share the end of a longer one), and one that is not there is added at the end;
//     nothing is ever taken out, so a name that is no longer used stays;
//   * the memory reservation map and the three header words that are not sizes (version, last_comp_version,
//     boot_cpuid_phys);
//   * how much free space the blob has behind its strings (libfdt, which mkimage uses, leaves some).
//
// The layout is the one dtc and libfdt write: header (40 bytes), the reservation map, the structure block, the strings
// block, free space. A blob that is laid out in another way (the blocks in another order, with gaps, an older version,
// bytes that are not zero in the free space or in the padding of a name or a value, NOP tokens, a structure block with
// something behind its END) still parses, but `Layout::canonical` says it is not what build() writes; the caller that needs
// the bytes back (fit.cpp) says no to it.
//
// Everything a blob says is checked against the bytes that there are: offsets, sizes, the NUL that ends a name, the nesting
// (at most kMaxDepth), the number of nodes and properties (at most kMaxItems -- a blob of empty nodes is a thousand times
// its size in memory otherwise).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::fdt {

inline constexpr size_t kMaxDepth = 64;
inline constexpr size_t kMaxItems = 1u << 20;  // nodes and properties together

struct Property {
    std::string name;
    Bytes value;
    // Text only (dts.hpp): the value is not here but in the file this names (`data = /incbin/("file")`). Empty for a property
    // that has its bytes. A tree with a property that has an `incbin` cannot be built until the caller has put the bytes
    // in `value` and cleared it.
    std::string incbin;
};

struct Node {
    std::string name;  // "" for the root
    std::vector<Property> props;
    std::vector<Node> children;

    const Property* find_prop(std::string_view name) const;
    Property* find_prop(std::string_view name);
    const Node* find_child(std::string_view name) const;
    Node* find_child(std::string_view name);
    // The value of a property that is a string (or nullopt: not there, or not one string).
    bool get_string(std::string_view name, std::string& out) const;
    // The value of a property that is one 32-bit cell, or two (a 64-bit number).
    bool get_u64(std::string_view name, uint64_t& out) const;
};

struct Tree {
    uint32_t version = 17;
    uint32_t last_comp_version = 16;
    uint32_t boot_cpuid_phys = 0;
    std::vector<std::pair<uint64_t, uint64_t>> reserve;  // the memory reservation map, without the entry that ends it
    Node root;
    Bytes strings;  // the strings block as it was (or empty, for a tree made from text)
};

// How a blob is laid out, as far as build() can write it again.
struct Layout {
    size_t total_size = 0;       // the header's `totalsize`: what the blob takes of its file
    size_t used = 0;             // where the strings block ends
    size_t slack = 0;            // total_size - used, when all of it is zero
    bool canonical = true;       // build(tree, slack) gives the blob
    std::string why;             // when it is not: the first thing that makes build() write another blob
};

// Reads the blob at the start of `data` (which may be longer: a FIT has its data behind it). FormatError, saying what and
// where, for a blob that is not one: a header that is cut short or has another magic, a version below 16, an offset or size
// that does not fit in `totalsize`, a block that is not aligned, a token that is none, a name or a string without its NUL,
// a node that is never closed, more nesting or more items than the limits.
Tree parse(const Bytes& data, Layout* layout = nullptr);

// The blob of the tree: header, reservation map, structure block, strings block and `slack` bytes of zeros. FormatError
// for a property that still has an `incbin`, a name with a NUL in it, a blob that would be 4 GiB or more.
Bytes build(const Tree& tree, size_t slack = 0);

// Where a name is in the strings block (the place libfdt and dtc find it: a name may be the end of a longer one), or the end of
// the block after the name has been added.
uint32_t string_offset(Bytes& strings, const std::string& name);

}  // namespace abr::fdt
