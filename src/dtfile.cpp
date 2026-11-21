// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/dtfile.hpp"

#include <algorithm>
#include <cctype>

#include "abr/dtb.hpp"
#include "abr/dts.hpp"
#include "abr/fdt.hpp"
#include "abr/sha.hpp"
#include "abr/textquote.hpp"

namespace abr::dtfile {

namespace {

std::string shown(const std::string& s) { return textquote::quote_shown(s); }

Bytes bytes_of(const std::string& s) { return Bytes(s.begin(), s.end()); }

std::string raw_name(const std::string& file) { return ".abr_raw/" + file + ".raw"; }

std::string with_extension(const std::string& file, const char* extension) {
    return is_source_name(file) ? file.substr(0, file.size() - 4) + extension : file;
}

// A word of the header of a blob (the header is 40 bytes: abr/fdt.hpp checked it).
uint32_t header_word(const Bytes& blob, size_t index) {
    const size_t at = index * 4;
    return (uint32_t(blob[at]) << 24) | (uint32_t(blob[at + 1]) << 16) | (uint32_t(blob[at + 2]) << 8) | uint32_t(blob[at + 3]);
}

// What makes build(parse(source)) another blob than the one the source is of: the first thing that is found.
std::string why_not_exact(const fdt::Tree& tree, const fdt::Layout& layout, const fdt::Tree* compiled, const Bytes& blob, const Bytes& rebuilt) {
    if (compiled && compiled->boot_cpuid_phys != tree.boot_cpuid_phys)
        return "its boot_cpuid_phys is " + std::to_string(tree.boot_cpuid_phys) + ", and a source says it by the reg of the first cpu (" +
               std::to_string(compiled->boot_cpuid_phys) + ")";
    if (layout.slack) return std::to_string(layout.slack) + " bytes of free space are behind its strings, and dtc writes none";
    if (!layout.canonical) return layout.why;
    if (blob.size() >= 40 && rebuilt.size() >= 40) {
        // (words 8 and 9 of the header: the sizes of the strings and of the structure block)
        const uint32_t strings = header_word(blob, 8), strings_dtc = header_word(rebuilt, 8);
        const uint32_t structure = header_word(blob, 9), structure_dtc = header_word(rebuilt, 9);
        if (strings > strings_dtc)
            return "its strings block is " + std::to_string(strings - strings_dtc) +
                   " bytes longer than dtc writes it (a string that no property uses, or one that is there twice)";
        if (strings < strings_dtc)
            return "its strings block is " + std::to_string(strings_dtc - strings) +
                   " bytes shorter than dtc writes it (it shares strings that dtc does not)";
        if (structure != structure_dtc)
            return "its structure block is " + std::to_string(structure) + " bytes, and dtc writes " + std::to_string(structure_dtc);
    }
    return "dtc would not lay it out like this (the order of its strings or of its blocks)";
}

}  // namespace

bool is_source_name(const std::string& name) {
    if (name.size() < 5) return false;
    const std::string tail = name.substr(name.size() - 4);
    return std::tolower(static_cast<unsigned char>(tail[0])) == '.' && std::tolower(static_cast<unsigned char>(tail[1])) == 'd' &&
           std::tolower(static_cast<unsigned char>(tail[2])) == 't' && std::tolower(static_cast<unsigned char>(tail[3])) == 's';
}

std::string file_name(const std::string& file, const Prepared& p) { return p.text ? file : with_extension(file, ".dtb"); }

Prepared prepare(const Bytes& blob) {
    Prepared p;
    fdt::Layout layout;
    fdt::Tree tree;
    try {
        tree = fdt::parse(blob, &layout);
    } catch (const FormatError& e) {
        p.note = std::string("abr cannot read it as a device tree (") + e.what() + "): it is a file of the blob, not a source";
        return p;
    }
    try {
        p.source = dts::print(tree);
    } catch (const FormatError& e) {
        p.note = std::string("a source cannot say what it holds (") + e.what() + "): it is a file of the blob, not a source";
        return p;
    }
    p.text = true;
    // Does the source give the blob back? (What dtc writes of it is the same bytes: dts.hpp.)
    std::string why;
    try {
        const fdt::Tree compiled = dts::parse(p.source, "the source");
        const Bytes rebuilt = fdt::build(compiled);
        if (rebuilt != blob) {
            if (layout.slack && fdt::build(compiled, layout.slack) == blob) p.slack = layout.slack;  // the free space is all that dtc would not write
            else why = why_not_exact(tree, layout, &compiled, blob, rebuilt);
        }
    } catch (const FormatError& e) {
        why = std::string("dtc would refuse its source: ") + e.what();
    }
    if (!why.empty()) {
        p.keep_raw = true;
        p.note = "the source does not give the tree back byte for byte (" + why +
                 "). The bytes the image had are kept (in .abr_raw/) and go back while the source is as it is; once it is edited, the tree is "
                 "compiled from it the way dtc lays it out";
    }
    return p;
}

void commit(Manifest& m, const std::filesystem::path& dir, const std::string& prefix, const std::string& file, const Prepared& p,
            const Bytes& blob) {
    const std::string name = file_name(file, p);
    m.set(prefix + "_file", name);
    if (!p.text) {
        write_file(dir / name, blob);
        return;
    }
    const Bytes text = bytes_of(p.source);
    write_file(dir / name, text);
    if (p.slack) m.set_u64(prefix + "_slack", p.slack);
    m.set_hex(prefix + "_text_hash", hash::sha256(text));
    if (p.keep_raw) {
        write_file(dir / raw_name(name), blob);
        m.set_hex(prefix + "_raw_hash", hash::sha256(blob));
    }
}

Loaded load(const Manifest& m, const std::filesystem::path& dir, const std::string& prefix, bool must_be_tree) {
    const std::string key = prefix + "_file";
    const std::string name = m.get_path(key);
    if (name.empty()) throw FormatError("manifest.txt has no " + shown(key) + " (the file of the device tree)");
    Loaded out;
    if (!is_source_name(name)) {
        out.blob = read_file(dir / name);
        if (!must_be_tree) return out;
        try {
            check_fdt_blob(out.blob, key + " (" + shown(name) + ")");
        } catch (const FormatError& e) {
            throw FormatError(std::string(e.what()) + "; a source is a file whose name ends in .dts");
        }
        return out;
    }

    const Bytes text = read_file(dir / name);
    const bool as_unpacked = m.has(prefix + "_text_hash") && hash::sha256(text) == m.get_hex(prefix + "_text_hash");
    const std::filesystem::path raw_path = dir / raw_name(name);
    std::error_code ec;
    const bool has_raw = std::filesystem::is_regular_file(raw_path, ec);
    if (as_unpacked && has_raw) {
        out.blob = read_file(raw_path);
        if (!m.has(prefix + "_raw_hash") || hash::sha256(out.blob) != m.get_hex(prefix + "_raw_hash"))
            throw FormatError(shown(raw_name(name)) + " does not belong to " + shown(name) + " as it was unpacked (its hash is not " +
                              shown(prefix + "_raw_hash") + " of manifest.txt). Delete it to have " + shown(name) +
                              " compiled, or unpack the image again");
        check_fdt_blob(out.blob, shown(raw_name(name)));
        return out;
    }

    // The free space the tree had belongs to the source as it was unpacked (it is what makes that source give the blob back); an edited source is
    // compiled the way dtc lays a tree out.
    const size_t slack = as_unpacked ? static_cast<size_t>(m.get_size(prefix + "_slack", 0)) : 0;
    out.blob = compile(text, shown(name), (dir / name).parent_path(), slack, &out.warnings);
    out.edited = !as_unpacked;
    if (!as_unpacked && (has_raw || m.has(prefix + "_slack"))) {
        const std::string what = has_raw ? (m.has(prefix + "_slack") ? "the bytes the image had (kept in .abr_raw/) and the free space behind its strings"
                                                                      : "the bytes the image had (kept in .abr_raw/)")
                                         : "the free space behind its strings";
        out.note = shown(name) + " was edited: the tree is compiled from it, laid out the way dtc lays it out (" + what + " are not used)";
    }
    return out;
}

Bytes compile(const Bytes& text, const std::string& name, const std::filesystem::path& folder, size_t slack, std::vector<std::string>* warnings) {
    dts::Options options;
    options.warnings = warnings;
    options.read_file = dts::directory_reader(folder.string());
    const fdt::Tree tree = dts::parse(std::string_view(reinterpret_cast<const char*>(text.data()), text.size()), name, options);
    return fdt::build(tree, slack);
}

}  // namespace abr::dtfile
