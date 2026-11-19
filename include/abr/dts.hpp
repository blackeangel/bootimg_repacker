// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::dts -- a device tree (fdt.hpp) as source text and back: abr's own device tree compiler and decompiler. It reads the language of
// dtc (the Devicetree Specification, chapter 6, and what dtc 1.7 reads beyond it) and writes the blob that dtc writes; it writes the
// source of a blob in the style that people edit.
//
//     /dts-v1/;
//
//     /memreserve/ 0x1000 0x2000;
//
//     / {
//         compatible = "vendor,board", "vendor,soc";
//         cpus {
//             cpu0: cpu@0 { reg = <0x0>; next-level-cache = <&l2>; };
//         };
//         l2: cache { phandle = <0x2>; };
//     };
//
//     &l2 { size = <0x80000>; };
//     /delete-node/ &unused;
//
// What is read (what dtc reads, with the same results -- tests/tools/dtc_live.py compares the blobs with dtc's):
//   * /dts-v1/; and /plugin/;, /memreserve/ (with labels), /include/ "file" (anywhere), the line markers that cpp writes (# 1 "file");
//   * nodes and properties with labels (label: name), a node written twice or reached by &label { } or &{/path} { } (the second
//     definition is merged into the first), /delete-node/ and /delete-property/ (by name, and /delete-node/ &label;),
//     /omit-if-no-ref/;
//   * values: "strings", <cells> (32 bits; /bits/ 8, 16, 32 or 64), [bytes], &label and &{/path} (as a string: the path of the node,
//     or inside <> as the phandle of the node), /incbin/("file") and /incbin/("file", skip, length), joined by commas, with labels;
//   * integers as numbers (decimal, 0x, octal, a U, L, UL, LL or ULL behind them), characters ('a', '\n') and C expressions in
//     parentheses (+ - * / % << >> < > <= >= == != & | ^ && || ! ~ ?:), on 64 bits;
//   * what dtc does to the tree before it writes it: the phandle of a node that is referenced and has none (the lowest one that is free,
//     in the order of the references, a `phandle` property behind the properties of the node), the paths of &label values, the `name`
//     property that says what the name of the node says (dropped), the nodes of /omit-if-no-ref/ that nobody refers to (dropped),
//     /plugin/: the fragments of &label { } blocks, __fixups__ and __local_fixups__, with -@ (Options::symbols) __symbols__;
//     the boot_cpuid_phys of the blob (the first cell of the reg of the first node of /cpus, or 0);
//   * the errors dtc makes of a tree: a node or a property twice, a name with a character it may not have, a label twice, a phandle that
//     is not valid or is used twice, a reference to a node that is not there (except in a /plugin/), a `name` that is not a string.
//   The warnings of dtc (the style checks) are not made. Every error has the file and the line.
//
// What is not read: the C preprocessor (#include <...>, #define, #if: run cpp first, as the kernel's build does, and abr reads its
// output), the other source formats of dtc (dts version 0, yaml, asm, filesystem trees), and the old versions of the blob format (abr
// writes version 17, last_comp_version 16). /include/ and a /incbin/ that is read need Options::read_file; without it an /incbin/ is a
// name (`data = /incbin/("file")`, the whole file, the only value of its property) that the caller -- fit.cpp -- resolves itself, and an
// /include/ is an error.
//
// print() writes the source of a tree: a property as a list of strings when its bytes are one (printable characters and the
// escapes of C, each string ending with its NUL), as cells when its length is a multiple of 4, as bytes otherwise -- any of the three
// gives the same bytes back, whichever way a source had it. A value that is long is broken into lines (8 cells, 16 bytes). The text
// has no labels and no references: a blob has none (phandles are numbers there), and parse(print(tree)) is the tree.
//
// The one thing that is not the language: the bytes behind a value that are not zero (fdt::Property::pad; mkimage leaves some behind
// the `hashed-nodes` of a signature) are in a comment right behind the property, `hashed-nodes = "/"; /* abr: padding 98 3e b2 */`.
// dtc reads it as the comment it is; parse() reads it back, and says no to one that is anywhere else or does not fit the value.
#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "abr/fdt.hpp"

namespace abr::dts {

inline constexpr size_t kMaxText = 64u << 20;  // a source, and all that it includes
inline constexpr size_t kMaxInclude = 16;      // /include/ inside /include/

struct Options {
    // Reads a file that the text names: `name` as it is written, `from` the file whose text names it ("" for the text itself, else
    // what an earlier call put in `resolved`). `resolved` is what a later name inside that file is relative to; `out` its bytes.
    // false when there is no such file or it may not be read (the error of the text then says which name). Not set: no /include/, and
    // an /incbin/ is a name (see above).
    std::function<bool(const std::string& name, const std::string& from, std::string& resolved, Bytes& out)> read_file;
    // dtc -@: a __symbols__ node with the path of every labelled node.
    bool symbols = false;
    // What dtc says on stderr and goes on (a value that does not fit its cell and is cut) is put here, one line each, when set.
    std::vector<std::string>* warnings = nullptr;
};

// The text of the tree. FormatError for a name that the text cannot say (the characters of a name are letters, digits and
// , . _ + * # ? @ -). A property that has an `incbin` is written as /incbin/("file"); a property without a value as `name;`.
std::string print(const fdt::Tree& tree);

// The tree of a text. `what` names the text in the messages ("fit.its").
fdt::Tree parse(std::string_view text, const std::string& what = "device tree source", const Options& options = {});

// A reader of files for Options::read_file that reads from a directory: a relative name without `..` (a text that is unpacked next to
// its files may not reach out of the folder: a copy of someone's project would put their files into your image), a regular file,
// at most kMaxText bytes. A name inside a file that this reader found is relative to the directory of that file.
std::function<bool(const std::string&, const std::string&, std::string&, Bytes&)> directory_reader(const std::string& directory);

}  // namespace abr::dts
