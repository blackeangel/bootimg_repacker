// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::dts -- a device tree (fdt.hpp) as text and back: the part of the device tree source language (Devicetree Specification,
// chapter 6; what dtc reads) that a tree of a binary blob needs, so that a FIT image (fit.hpp) can be a text people edit:
//
//     /dts-v1/;
//
//     /memreserve/ 0x1000 0x2000;
//
//     / {
//         description = "Test FIT";
//         images {
//             kernel-1 {
//                 data = /incbin/("kernel_1");
//                 load = <0x0 0x80080000>;
//                 hash-1 { algo = "sha256"; };
//             };
//         };
//     };
//
// A value is a list of strings ("a", "b"), of cells (<0x1 0x2>, 32 bits each, or /bits/ 8, 16 or 64), of bytes ([00 11]) or the
// bytes of a file (/incbin/("file"), the only value of its property). What is not read is named: labels and references (&x),
// expressions and macros, /delete-node/ and /delete-property/, /include/, /plugin/, a second root node, a node or a
// property twice. Every error has the line.
//
// print() writes a property as a list of strings when its bytes are one (printable characters, each string at least one long,
// the last NUL), as cells when its length is a multiple of 4, as bytes otherwise -- any of the three gives the same bytes back,
// whichever way the source had it. parse(print(tree)) is the tree.
#pragma once

#include <string>
#include <string_view>

#include "abr/fdt.hpp"

namespace abr::dts {

inline constexpr size_t kMaxText = 64u << 20;

// The text of the tree. FormatError for a name that the text cannot say (the characters of a name are letters, digits and
// , . _ + * # ? @ -). A property that has an `incbin` is written as /incbin/("file"); a property without a value as `name;`.
std::string print(const fdt::Tree& tree);

// The tree of a text. `what` names the text in the messages ("fit.its").
fdt::Tree parse(std::string_view text, const std::string& what = "device tree source");

}  // namespace abr::dts
