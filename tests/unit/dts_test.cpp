// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr's device tree compiler (include/abr/dts.hpp, src/dts.cpp) judged by dtc 1.7.0, and the two helpers that tests/tools/dtc_live.py
// drives. The language itself, its refusals and the text that print() writes are checked by `abr_unit_tests fdt`; what is here is
// what only dtc can say: the bytes.
//
//   abr_unit_tests dts-golden DIR          every NAME.dts of DIR (tests/golden/dts) compiles to the bytes of NAME.dtb, which dtc wrote
//                                          (NAME.flags with -@: dtc -@), or, where NAME.fail is, is refused -- on the line and with the
//                                          words it says. For a blob dtc wrote: parse(blob) builds back to the blob, and print() then
//                                          parse() then build() gives the blob again. One line a file.
//   abr_unit_tests dts-compile SRC OUT [-@] [-d DIR]
//                                          the compiler on one file. What an /include/ or an /incbin/ names is read from DIR (by default
//                                          the folder of SRC). Exit 1, and the message on stderr, when it refuses.
//   abr_unit_tests dts-decompile BLOB OUT  the text of the tree of a blob.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/dts.hpp"
#include "abr/fdt.hpp"

using namespace abr;
namespace fs = std::filesystem;

namespace {

bool same_node(const fdt::Node& a, const fdt::Node& b) {
    if (a.name != b.name || a.props.size() != b.props.size() || a.children.size() != b.children.size()) return false;
    for (size_t i = 0; i < a.props.size(); ++i)
        if (a.props[i].name != b.props[i].name || a.props[i].value != b.props[i].value || a.props[i].incbin != b.props[i].incbin ||
            a.props[i].pad != b.props[i].pad)
            return false;
    for (size_t i = 0; i < a.children.size(); ++i)
        if (!same_node(a.children[i], b.children[i])) return false;
    return true;
}

bool same_tree(const fdt::Tree& a, const fdt::Tree& b) {
    return a.version == b.version && a.last_comp_version == b.last_comp_version && a.boot_cpuid_phys == b.boot_cpuid_phys &&
           a.reserve == b.reserve && same_node(a.root, b.root);
}

std::string text_of(const Bytes& b) { return std::string(b.begin(), b.end()); }

bool is_file(const fs::path& p) {
    std::error_code ec;
    return fs::is_regular_file(p, ec);
}

struct Compiled {
    Bytes blob;
    std::vector<std::string> warnings;
};

// What `dtc [-@] -I dts -O dtb` does to a file.
Compiled compile(const std::string& path, const std::string& dir, bool symbols) {
    Compiled c;
    dts::Options options;
    options.symbols = symbols;
    options.warnings = &c.warnings;
    options.read_file = dts::directory_reader(dir);
    const fdt::Tree tree = dts::parse(text_of(read_file(path)), path, options);
    c.blob = fdt::build(tree);
    return c;
}

std::string first_difference(const Bytes& got, const Bytes& want) {
    size_t i = 0;
    while (i < got.size() && i < want.size() && got[i] == want[i]) ++i;
    return "sizes " + std::to_string(got.size()) + " and " + std::to_string(want.size()) + ", the first difference at byte " + std::to_string(i);
}

int g_failures = 0;

void fail(const std::string& name, const std::string& what) {
    ++g_failures;
    std::printf("  FAIL %s: %s\n", name.c_str(), what.c_str());
}

// A blob that dtc wrote: abr reads it as laid out the way dtc lays it out, builds it back to the same bytes, and the text of its tree
// compiles to it again.
void check_blob_of_dtc(const std::string& name, const Bytes& blob) {
    try {
        fdt::Layout layout;
        const fdt::Tree tree = fdt::parse(blob, &layout);
        if (!layout.canonical) return fail(name, "the blob that dtc wrote is not canonical: " + layout.why);
        if (fdt::build(tree, layout.slack) != blob) return fail(name, "parse() then build() does not give the blob back");
        const std::string text = dts::print(tree);
        const fdt::Tree again = dts::parse(text, name + " (its text)");
        if (!same_tree(again, tree)) return fail(name, "the text of the blob does not read back as its tree");
        if (fdt::build(again) != blob) return fail(name, "the text of the blob does not compile to the blob: " + first_difference(fdt::build(again), blob));
        if (dts::print(again) != text) fail(name, "print() of the tree that was read from the text is another text");
    } catch (const std::exception& e) {
        fail(name, std::string("the blob of dtc is refused: ") + e.what());
    }
}

}  // namespace

int run_dts_golden(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: abr_unit_tests dts-golden DIR\n");
        return 2;
    }
    const fs::path dir = argv[2];
    std::vector<std::string> names;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec))
        if (entry.path().extension() == ".dts") names.push_back(entry.path().stem().string());
    std::sort(names.begin(), names.end());
    if (names.empty()) {
        std::printf("dts-golden: no .dts file in %s\n", argv[2]);
        return 1;
    }
    int compiled = 0, refused = 0;
    for (const std::string& name : names) {
        const std::string src = (dir / (name + ".dts")).string();
        const fs::path dtb = dir / (name + ".dtb"), fail_file = dir / (name + ".fail"), flags = dir / (name + ".flags");
        const bool symbols = is_file(flags) && text_of(read_file(flags.string())).find("-@") != std::string::npos;
        if (is_file(dtb)) {
            Compiled c;
            try {
                c = compile(src, dir.string(), symbols);
            } catch (const std::exception& e) {
                fail(name, std::string("refused, and dtc compiles it: ") + e.what());
                continue;
            }
            const Bytes want = read_file(dtb.string());
            if (c.blob != want) {
                fail(name, "not the blob that dtc wrote: " + first_difference(c.blob, want));
                continue;
            }
            ++compiled;
            check_blob_of_dtc(name, want);
        } else if (is_file(fail_file)) {
            std::string expect = text_of(read_file(fail_file.string()));  // "LINE WORDS"
            while (!expect.empty() && (expect.back() == '\n' || expect.back() == '\r')) expect.pop_back();
            const size_t blank = expect.find(' ');
            const std::string at = "line " + expect.substr(0, blank) + ": ", words = blank == std::string::npos ? std::string() : expect.substr(blank + 1);
            try {
                compile(src, dir.string(), symbols);
                fail(name, "compiled, and dtc refuses it");
            } catch (const FormatError& e) {
                const std::string what = e.what();
                if (what.find(at) == std::string::npos) fail(name, "refused, but not on " + at + "(" + what + ")");
                else if (what.find(words) == std::string::npos) fail(name, "refused, but it does not say \"" + words + "\" (" + what + ")");
                else ++refused;
            } catch (const std::exception& e) {
                fail(name, std::string("refused with something that is not a FormatError: ") + e.what());
            }
        } else {
            fail(name, "there is neither a .dtb (what dtc wrote) nor a .fail (dtc refuses it)");
        }
    }
    if (g_failures == 0) std::printf("dts-golden: ok (%d sources compile to the blobs of dtc, %d are refused as dtc refuses them)\n", compiled, refused);
    else std::printf("dts-golden: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}

int run_dts_compile(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: abr_unit_tests dts-compile SRC OUT [-@] [-d DIR]\n");
        return 2;
    }
    bool symbols = false;
    std::string dir = fs::path(argv[2]).parent_path().string();
    if (dir.empty()) dir = ".";
    for (int i = 4; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-@") symbols = true;
        else if (a == "-d" && i + 1 < argc) dir = argv[++i];
        else {
            std::fprintf(stderr, "dts-compile: what is %s?\n", a.c_str());
            return 2;
        }
    }
    try {
        const Compiled c = compile(argv[2], dir, symbols);
        write_file(argv[3], c.blob);
        for (const std::string& w : c.warnings) std::fprintf(stderr, "warning: %s\n", w.c_str());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}

int run_dts_decompile(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: abr_unit_tests dts-decompile BLOB OUT\n");
        return 2;
    }
    try {
        const std::string text = dts::print(fdt::parse(read_file(argv[2])));
        write_file(argv[3], Bytes(text.begin(), text.end()));
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
