// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::aml -- the multi-tree container of Amlogic ("AML_"): the device trees of the boards one family of SoCs runs on, in one file, and what the
// u-boot of such a board searches for the tree of the board it runs on (common/aml_dt.c of the Amlogic u-boot). It is the `second` of the boot image
// of an Amlogic TV box (the TWRP recoveries for the S905, S912 and the like put it there), and a partition of its own on others (`dtb`).
//
//   "AML_"  version  number of entries                              (12 bytes, 32-bit little-endian words)
//   the entries, one for each board a tree is for:
//       soc  platform  variant  offset  size                        (the three ids are 4 bytes each in version 1, 16 bytes in version 2)
//   zeros, up to the next multiple of the page size
//   the trees, each followed by zeros up to the next multiple of the page size
//
// The offset of an entry is from the start of the container, its size is the size of the tree with the zeros behind it (u-boot does not read it).
// Several entries may point at one tree. The page size is not in the container: the tool that makes it (a dtbTool of the family of the one that
// makes the QCDT tables, see qcdt.hpp) is told it, and pads with it.
//
// An id is a piece of the name of a board: u-boot is given "gxl_p212_2g" by the hardware and cuts it at its underscores, "gxl" the SoC, "p212" the
// platform (the reference design), "2g" the variant. In the container it is the text with spaces behind it up to the length of the id, in words of
// four characters of which each is stored reversed (what u-boot reads as a little-endian word, takes the characters of from the top byte down,
// and turns the spaces of into NULs): "gxl" is 20 6c 78 67 and twelve spaces, "2g" is 20 20 67 32 and twelve spaces. A text with a space in it, or
// with a byte that is no printable character, is not one that the reader takes whole, and is not one abr writes.
//
// This is written against the code of u-boot that reads the container and against the file of one real device (the `second` of a TWRP image for
// an S905X box), which the tests compare with; none of it is in abr. What abr takes as a container is what build() writes again byte for byte
// (parse() writes it again, to see that it does: one that another tool made in another way is not taken, and parse() says what is different). The
// trees are stored as they are, and a tree whose size is not the `totalsize` of its own header is not one.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::aml {

inline constexpr size_t kHeaderSize = 12;
inline constexpr uint32_t kDefaultPageSize = 2048;  // that of the boot images the container is in
inline constexpr uint32_t kMaxPageSize = 1u << 20;

// The length of an id of this version (4 or 16 bytes), 0 for a version that there is not.
constexpr size_t id_size(uint32_t version) { return version == 1 ? 4 : version == 2 ? 16 : 0; }
// The size of an entry of this version (20 or 56 bytes: the three ids, the offset and the size), 0 for a version that there is not.
constexpr size_t entry_size(uint32_t version) { return id_size(version) == 0 ? 0 : 3 * id_size(version) + 8; }

// "AML_" and a version that is 1 or 2: what a container starts with.
bool looks_like(const Bytes& data);

// The board a tree is for, by the three pieces of its name.
struct Entry {
    std::string soc;       // "gxl"
    std::string platform;  // "p212"
    std::string variant;   // "2g"
    size_t dtb = 0;        // which of Table::dtbs
    bool operator==(const Entry&) const = default;
};

struct Table {
    uint32_t version = 2;  // 1 or 2: the length of an id
    uint32_t page_size = kDefaultPageSize;
    std::vector<Entry> entries;  // in the order of the container
    std::vector<Bytes> dtbs;     // the trees, each as long as its header says, in the order they are in the container
    size_t consumed = 0;         // set by parse(): where the last tree ends, with its padding
};

// The container at the start of `data` (which may be longer: what follows `consumed` is the caller's). `page_hint` is the page size to try first
// when the container fits several (the page size of the boot image it is in; 0: none): it is not in the container, and what the trees' sizes and
// offsets allow is a number that divides all of them. FormatError, saying what, for a container abr cannot write again byte for byte: a header that
// is cut short or has a version other than 1 and 2, no entries, entries that run past the file, an id that is not a text of printable characters
// without spaces, an offset where no tree is, two trees that overlap, a layout that is not the tool's for any page size, padding that is not zeros.
Table parse(const Bytes& data, uint32_t page_hint = 0);

// The container, laid out as its tool lays it out: the entries in the order given, the trees in the order of `dtbs`, each at the next multiple of
// the page size. FormatError for a table that contradicts itself: a version or a page size that is not allowed, no entries or no trees, an entry for a
// tree there is not, a tree that no entry is for, an id that is not a text of printable characters without spaces or is longer than the version
// allows, a tree that is not a flattened device tree of the size its header gives, a container of 4 GiB or more (an offset is a 32-bit word).
Bytes build(const Table& table);

// FormatError, with `what` named as the culprit, for bytes that cannot stand as a tree of a container: not a flattened device tree, cut short, or not as
// long as its header says. build() checks every tree the same way and names it "device tree N"; a caller that knows the file a tree came from checks it
// first with the name of the file.
void check_device_tree(const Bytes& blob, const std::string& what);

}  // namespace abr::aml
