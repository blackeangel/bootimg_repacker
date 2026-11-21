// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::kernel -- what the kernel of a boot-family image holds besides the kernel's own code.
//
// The kernel field of a boot image is rarely just a kernel. The build of an Android kernel glues device trees behind it (`Image.gz-dtb`:
// a gzip stream and, right behind its last byte, one to a few dozen flattened device trees that the bootloader picks from by the ids inside
// them; `zImage-dtb` and `Image-dtb` for a kernel that is not compressed) and an edit of the kernel that does not know of them drops them.
// find_appended_trees() finds them so that unpack can write them as sources and pack can put them back.
#pragma once

#include <cstddef>
#include <optional>

#include "abr/byte_io.hpp"

namespace abr::kernel {

// The most that may follow the last glued tree for them to be the end of the kernel field: a few bytes of padding, a marker, a signature. What is
// behind them and is not more than this, or is all zeros whatever its size (a field that is filled up), is kept as it is, behind the trees.
inline constexpr size_t kMaxTailBehindTrees = 64 * 1024;

// Device trees glued behind a kernel: from `start` to `consumed`, `trees` of them one behind the other (with zero bytes between two where
// they are put at multiples of 4, 8, 16, ... bytes), and what is left of the data behind the last one is the tail.
struct Appended {
    size_t start = 0;     // where the first tree begins: more than 0 (what is in front of it is the stream, or the kernel)
    size_t trees = 0;     // how many trees: at least 1
    size_t consumed = 0;  // where the last one ends; the tail is data.size() - consumed bytes
};

// Does a flattened device tree begin at `pos` of `data`, a header that says so and whose fields hold together -- the sizes, the offsets of
// the three blocks, the first token of the structure block (the root node), its last (FDT_END)? Not a reader of the tree: a header's worth of
// checks, enough to tell a tree from the bytes of a kernel that happen to be d0 0d fe ed.
bool plausible_tree(const Bytes& data, size_t pos);

// The device trees that end `data`, when it has some: the first place from which every byte is trees (and zeros between them) up to the end
// of the data, or to a tail (at most kMaxTailBehindTrees bytes, or zeros only). The trees that lie inside a kernel with code and data
// behind them -- the ones that a kernel carries for its own tests -- are not glued trees. None when there are no trees, and when the data
// begins with one (there is nothing in front of it: the data is a dtb, not a kernel with trees).
std::optional<Appended> find_appended_trees(const Bytes& data);

}  // namespace abr::kernel
