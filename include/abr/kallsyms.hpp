// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::kallsyms -- the symbol table that a Linux kernel carries in itself, read out of an image.
//
// A kernel built with CONFIG_KALLSYMS keeps the names of its functions (and, with CONFIG_KALLSYMS_ALL, of its data) so
// that /proc/kallsyms and the oops messages can print them. scripts/kallsyms.c writes the table into the last link of
// the kernel as six arrays, one after the other, each aligned (to 4 or 8 bytes on most machines, to 256 or 16 on ARM
// where `.align 8` counts in powers of two):
//
//     kallsyms_addresses[n]    the address of every symbol, as a pointer-sized number         (before Linux 4.6, or
//     kallsyms_offsets[n]      ... or its distance from kallsyms_relative_base, 32 bits        CONFIG_KALLSYMS_BASE_RELATIVE off)
//     kallsyms_relative_base   the pointer that the offsets count from (only with the offsets)
//     kallsyms_num_syms        n
//     kallsyms_names           for each symbol a length (one byte; two when the high bit of the first is set, Linux 6.x) and
//                              the symbol as that many "tokens": the first character is the type, as nm writes it
//     kallsyms_markers         the position in kallsyms_names of every 256th symbol (a number of 4 or of pointer size)
//     kallsyms_token_table     the 256 tokens, NUL-terminated strings: a byte that no name uses stands for a short string
//                              that the names use a lot ("arm", "_reg"), the others for themselves
//     kallsyms_token_index     256 16-bit offsets into the token table
//
// None of them has a name or a header in the image, so find() looks for the structure: the token table is the one run
// of strings that has the digits 0-9 one after the other, and it is proved by the index that follows it (every one of the 256
// offsets has to be where the string really starts). The markers are in front of it: numbers that grow from 0. The names are
// in front of them: walking the lengths from the first one has to reach every marker at the exact position it names and the end
// of the names where the markers begin. The number of symbols is just before the names (and must be one that the markers allow).
// And the addresses are just before that, with or without the relative base, and have to be in order. A table is only taken
// when all of it fits, so that the bytes of a kernel that has none (or other bytes that look a little like one) give nothing.
//
// The tables are in the byte order and the word size of the kernel; find() tries both orders and both sizes.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::kallsyms {

struct Symbol {
    uint64_t address = 0;
    char type = '?';   // as nm writes it: T t D d R r B b A W w ... (lower case: a local symbol)
    std::string name;
};

enum class Layout {
    Absolute,        // kallsyms_addresses: the address of every symbol
    Relative,        // kallsyms_offsets: relative_base plus a 32-bit number
    RelativePercpu,  // kallsyms_offsets with CONFIG_KALLSYMS_ABSOLUTE_PERCPU (x86-64): a number that is not negative is the address itself,
                     // a negative one is relative_base - 1 - the number
};

struct Table {
    Layout layout = Layout::Absolute;
    bool big_endian = false;
    unsigned address_size = 8;  // bytes of an address (Absolute) or of kallsyms_relative_base (Relative*)
    unsigned marker_size = 4;   // bytes of one kallsyms_markers number
    bool long_names = false;    // a name of more than 127 bytes has two bytes of length
    uint64_t relative_base = 0; // only for the relative layouts

    // Where the pieces are, as offsets into the data the table was found in.
    size_t addresses_at = 0;  // kallsyms_addresses or kallsyms_offsets
    size_t relative_base_at = 0;  // 0 for Absolute
    size_t count_at = 0;
    size_t names_at = 0;
    size_t names_end = 0;
    size_t markers_at = 0;
    size_t token_table_at = 0;
    size_t token_table_end = 0;
    size_t token_index_at = 0;

    std::vector<Symbol> symbols;  // in the order of the table, which is the order of the addresses
};

// The table in `data`, or nothing when there is none. Never throws, whatever the bytes are.
std::optional<Table> find(const uint8_t* data, size_t size);
inline std::optional<Table> find(const Bytes& data) { return find(data.data(), data.size()); }

// One line per symbol as /proc/kallsyms writes them: the address in lower case hexadecimal (16 digits, 8 when the addresses are
// 32 bits), a blank, the type, a blank, the name, a line feed.
std::string format(const Table& table);

}  // namespace abr::kallsyms
