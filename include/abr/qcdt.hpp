// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::qcdt -- the Qualcomm device tree table ("QCDT"): what dtbTool makes of the device trees of a kernel, and what the
// bootloader of a Qualcomm phone (LK, aboot) searches for the tree of the board it runs on. It is the `dt` of a boot image
// with a version 0 header (the word that holds the version in later headers is its `dt_size`), and a partition of its own on
// some devices.
//
//   "QCDT"  version  number of entries                                     (12 bytes, 32-bit little-endian words)
//   the entries, one for each board a tree is for:
//       version 1:  chipset platform revision                     offset size     (5 words)
//       version 2:  chipset platform subtype revision             offset size     (6 words)
//       version 3:  chipset platform subtype revision pmic0..pmic3 offset size    (10 words)
//   a word of zeros                                                        (the end of the table)
//   zeros, up to the next multiple of the page size
//   the trees, each followed by zeros up to the next multiple of the page size
//
// The offset of an entry is from the start of the table, its size is the size of the tree with the zeros behind it. Several
// entries may point at one tree (a tree for several boards), which is then in the table once. The page size is not in the
// table: dtbTool is told it (`-s`, the page size of the boot image) and pads with it. Two things are as dtbTool does them and
// not what one would guess: a table or a tree that ends on a page already gets a whole page of zeros behind it, and the size an
// entry gives is the size with the padding.
//
// What the words are are the cells of the properties of the root node of the tree (devicetree.org has no binding for them; the
// kernels of Qualcomm do):
//       version 1:  qcom,msm-id = <chipset platform revision>
//       version 2:  qcom,msm-id = <chipset revision>,  qcom,board-id = <platform subtype>
//       version 3:  as version 2, and qcom,pmic-id = <pmic0 pmic1 pmic2 pmic3>
// Each property may hold several groups; an entry is made of every combination of them (dtbTool does the same).
//
// This is written against the sources of dtbTool of the Code Aurora Forum (the one of LineageOS, version 3) and against the table
// of a real device, which the tests compare with; none of it is in abr. What abr takes as a table is what build() writes again
// byte for byte (parse() writes the table again, to see that it does: a table that another tool made in another way is not
// taken, and parse() says what is different). The trees are stored as they are, and a tree whose size is not the `totalsize` of
// its own header is not one (dtbTool takes the size of the file, and the size in the table is all there is to find the file's
// length by: the zeros after the tree cannot be told from bytes that belong to it).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/fdt.hpp"

namespace abr::qcdt {

inline constexpr size_t kHeaderSize = 12;
inline constexpr uint32_t kDefaultPageSize = 2048;  // dtbTool's
inline constexpr uint32_t kMaxPageSize = 1u << 20;  // dtbTool refuses more

// The size of an entry of this version (20, 24 or 40 bytes), 0 for a version that there is not.
constexpr size_t entry_size(uint32_t version) { return version == 1 ? 20 : version == 2 ? 24 : version == 3 ? 40 : 0; }

// "QCDT" and a version that is 1, 2 or 3: what a table starts with.
bool looks_like(const Bytes& data);

// The board (and the revision of it) a tree is for.
struct Chip {
    uint32_t chipset = 0;
    uint32_t platform = 0;
    uint32_t subtype = 0;   // versions 2 and 3
    uint32_t revision = 0;
    std::array<uint32_t, 4> pmic{};  // version 3
    bool operator==(const Chip&) const = default;
};

struct Entry : Chip {
    size_t dtb = 0;  // which of Table::dtbs
    bool operator==(const Entry&) const = default;
};

struct Table {
    uint32_t version = 1;  // 1, 2 or 3: the width of an entry
    uint32_t page_size = kDefaultPageSize;
    std::vector<Entry> entries;  // in the order of the table
    std::vector<Bytes> dtbs;     // the trees, each as long as its header says, in the order they are in the table
    size_t consumed = 0;         // set by parse(): where the last tree ends, with its padding
};

// The table at the start of `data` (which may be longer: what follows `consumed` is the caller's). `page_hint` is the page size to
// try first when the table fits several (the page size of the boot image the table is in; 0: none): the table does not say it, and
// what the trees' sizes and offsets allow is a number that divides all of them. FormatError, saying what, for a table abr cannot
// write again byte for byte: a header that is cut short or has a version other than 1 to 3, no entries, entries that run past the
// file, an offset where no tree is, two trees that overlap, a layout that is not dtbTool's for any page size, padding that is not
// zeros.
Table parse(const Bytes& data, uint32_t page_hint = 0);

// The table, laid out as dtbTool lays it out: the entries in the order given, the trees in the order of `dtbs`, each at the next
// multiple of the page size. FormatError for a table that contradicts itself: a version or a page size that is not allowed, no
// entries or no trees, an entry that points at a tree there is not, a tree that no entry points at, a subtype in a version 1 table
// or a PMIC id in a version 1 or 2 table (the entry has no word for it), a tree that is not a flattened device tree of the size its
// header gives, a table of 4 GiB or more (an offset is a 32-bit word).
Bytes build(const Table& table);

// What the root node of a tree says about the boards it is for, or nullopt when it has no qcom,msm-id (the tree is not for a
// Qualcomm board). `version` is the lowest that has a word for everything: 1 with just qcom,msm-id, 2 with a qcom,board-id, 3 with
// a qcom,pmic-id. FormatError for a property that is not in the form of its version: a size that is not whole cells, the wrong number
// of cells, a qcom,pmic-id without a qcom,board-id, none of the groups (an empty property).
struct Tags {
    uint32_t version = 1;
    // Every combination, in the order dtbTool has them: it goes through the groups of each property as the first, then the last to the second,
    // takes the combinations with the groups of qcom,msm-id outermost and those of qcom,pmic-id innermost, and puts the first of those first and the
    // others after it from the last to the second. It is the order of the boards that differ only in their PMIC ids, which is all it decides.
    std::vector<Chip> chips;
};
std::optional<Tags> chips_of(const fdt::Tree& tree);

// The device trees dtbTool is given, by name (what messages call each).
struct Source {
    std::string name;
    Bytes dtb;
};

struct MakeOptions {
    uint32_t page_size = kDefaultPageSize;
    // 0: the highest of what the trees need (as dtbTool). 1, 2 or 3: that version, whatever the trees need; what it has no word for is
    // left out (a version 2 table has no PMIC ids), as `dtbTool -2` does.
    uint32_t version = 0;
};

struct Made {
    Table table;
    // The trees that are not in it, and why (no qcom,msm-id, ...), and what a forced version left out.
    std::vector<std::string> notes;
};

// What dtbTool makes of the trees: an entry for every board each is for, sorted by chipset, platform, subtype and revision (equal
// ones stay in the order of the sources), the trees in the order of the first entry that has them. FormatError for a tree that is
// not a flattened device tree of the size its header gives (dtbTool skips such a file, and a board that is missing from the table is
// worse than a refusal), for a property that is not in the form of its version, for two entries that are the same board (dtbTool
// keeps the one it came to first, and which that is depends on the order the file system lists the files in), for no tree that is for
// a board, and for a page size that is not from 1 byte to 1 MiB.
Made make(const std::vector<Source>& sources, const MakeOptions& options = {});

}  // namespace abr::qcdt
