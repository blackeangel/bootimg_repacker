// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of one device tree in the folder of an unpack (include/abr/dtfile.hpp). Run by tests/run_tests.sh as `abr_unit_tests dtfile`.
//
//   * a tree that dtc lays out is a source and nothing else: prepare() says it needs no raw copy and no free space, commit() writes NAME.dts,
//     load() gives the blob back; a tree with free space behind its strings (a FIT's, dtbTool's) keeps the size of it in the manifest and
//     needs no raw copy either;
//   * a tree that dtc would lay out another way (a string that no property uses, the strings in another order, bytes behind a value) keeps the
//     blob in .abr_raw/, which goes back while the source is as it was unpacked; an edited source is compiled, and the note says that the bytes
//     the image had are not used; a raw copy that is not the one the manifest has the hash of is refused, one that is missing is not an error;
//   * what has no source (not a tree, a tree with a name that a source cannot say) is a file of the blob, NAME.dtb, which has to be a tree;
//   * an edited source is compiled without the free space the tree had; the source as it was unpacked is compiled with it;
//   * an /include/ and an /incbin/ are read from the folder of the source and from nowhere else (no `..`);
//   * is_source_name(), the key names, and what load() refuses (no key, a file that is not there, an error in the source with the line).
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <random>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/dtfile.hpp"
#include "abr/dts.hpp"
#include "abr/fdt.hpp"
#include "abr/manifest.hpp"
#include "abr/sha.hpp"

using namespace abr;
namespace fs = std::filesystem;

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

struct TempDir {
    fs::path path;
    TempDir() {
        static unsigned counter = 0;
        path = fs::temp_directory_path() / ("abr_dtfile_test_" + std::to_string(static_cast<unsigned long>(std::random_device{}())) + "_" +
                                            std::to_string(counter++));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::string refusal_of(const std::function<void()>& f) {
    try {
        f();
    } catch (const FormatError& e) {
        return e.what();
    }
    return {};
}

void put_text(const fs::path& p, const std::string& text) { write_file(p, Bytes(text.begin(), text.end())); }

std::string read_text(const fs::path& p) {
    const Bytes b = read_file(p);
    return std::string(b.begin(), b.end());
}

Bytes blob_of(const std::string& text) { return fdt::build(dts::parse(text, "test")); }

const char* kTree = R"(/dts-v1/;
/ {
	model = "dtfile test";
	compatible = "test,board";
	#address-cells = <1>;
	#size-cells = <1>;
	soc {
		serial@1000 { reg = <0x1000 0x100>; status = "okay"; };
	};
};
)";

uint32_t word_of(const Bytes& b, size_t index) {
    return (uint32_t(b[index * 4]) << 24) | (uint32_t(b[index * 4 + 1]) << 16) | (uint32_t(b[index * 4 + 2]) << 8) | uint32_t(b[index * 4 + 3]);
}

void set_word(Bytes& b, size_t index, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[index * 4 + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (24 - 8 * i));
}

// The blob of kTree with a string at the end of the strings block that no property uses: laid out as no source says, and a tree all the same.
Bytes with_orphan_string(Bytes blob) {
    const std::string orphan = "orphan-string";
    blob.insert(blob.end(), orphan.begin(), orphan.end());
    blob.push_back(0);
    set_word(blob, 1, static_cast<uint32_t>(blob.size()));                                       // totalsize
    set_word(blob, 8, word_of(blob, 8) + static_cast<uint32_t>(orphan.size() + 1));              // size_dt_strings
    return blob;
}

// ---------------------------------------------------------------------------------------------------------------- a tree dtc lays out
void test_plain_tree() {
    const Bytes blob = blob_of(kTree);
    const dtfile::Prepared p = dtfile::prepare(blob);
    EXPECT(p.text);
    EXPECT(!p.keep_raw);
    EXPECT(p.slack == 0);
    EXPECT(p.note.empty());
    EXPECT_HAS(p.source, "model = \"dtfile test\";");

    TempDir d;
    Manifest m;
    dtfile::commit(m, d.path, "blob0", "dtb/entry0.dts", p, blob);
    EXPECT(m.get("blob0_file") == "dtb/entry0.dts");
    EXPECT(m.has("blob0_text_hash"));
    EXPECT(!m.has("blob0_raw_hash"));
    EXPECT(!m.has("blob0_slack"));
    EXPECT(fs::is_regular_file(d.path / "dtb" / "entry0.dts"));
    EXPECT(!fs::exists(d.path / ".abr_raw"));
    EXPECT(dtfile::file_name("dtb/entry0.dts", p) == "dtb/entry0.dts");

    const dtfile::Loaded l = dtfile::load(m, d.path, "blob0");
    EXPECT(l.blob == blob);
    EXPECT(l.warnings.empty());
    EXPECT(l.note.empty());
}

// --------------------------------------------------------------------------------------------------- free space behind the strings
void test_slack() {
    const fdt::Tree tree = dts::parse(kTree, "test");
    for (const size_t slack : {size_t(1), size_t(4), size_t(17), size_t(1000)}) {
        const Bytes blob = fdt::build(tree, slack);
        const dtfile::Prepared p = dtfile::prepare(blob);
        EXPECT(p.text);
        EXPECT(p.slack == slack);
        EXPECT(!p.keep_raw);

        TempDir d;
        Manifest m;
        dtfile::commit(m, d.path, "dtb0", "entry0.dts", p, blob);
        EXPECT(m.get_size("dtb0_slack", 0) == slack);
        EXPECT(!fs::exists(d.path / ".abr_raw"));
        const dtfile::Loaded l = dtfile::load(m, d.path, "dtb0");
        EXPECT(l.blob == blob);

        // an edited source is compiled the way dtc lays a tree out: the free space is the unpacked source's
        const std::string edited = read_text(d.path / "entry0.dts") + "/ { extra = <1>; };\n";
        put_text(d.path / "entry0.dts", edited);
        const dtfile::Loaded e = dtfile::load(m, d.path, "dtb0");
        EXPECT(e.blob == blob_of(edited));
        EXPECT_HAS(e.note, "was edited");
        EXPECT_HAS(e.note, "free space");
    }
}

// ------------------------------------------------------------------------------------------------------------ a tree dtc would not write
void test_raw_copy() {
    const Bytes blob = with_orphan_string(blob_of(kTree));
    const fdt::Tree tree = fdt::parse(blob);  // (a tree all the same)
    EXPECT(!tree.root.children.empty());
    const dtfile::Prepared p = dtfile::prepare(blob);
    EXPECT(p.text);
    EXPECT(p.keep_raw);
    EXPECT_HAS(p.note, "byte for byte");
    EXPECT_HAS(p.note, "strings block is 14 bytes longer");  // ("orphan-string" and its zero)
    EXPECT_HAS(p.note, ".abr_raw");

    TempDir d;
    Manifest m;
    dtfile::commit(m, d.path, "blob1", "entry1.dts", p, blob);
    EXPECT(fs::is_regular_file(d.path / "entry1.dts"));
    EXPECT(fs::is_regular_file(d.path / ".abr_raw" / "entry1.dts.raw"));
    EXPECT(m.has("blob1_raw_hash") && m.has("blob1_text_hash"));

    // as unpacked: the bytes the image had
    dtfile::Loaded l = dtfile::load(m, d.path, "blob1");
    EXPECT(l.blob == blob);
    EXPECT(l.note.empty());

    // edited: compiled, and the person is told
    const std::string edited = read_text(d.path / "entry1.dts") + "/ { more = \"text\"; };\n";
    put_text(d.path / "entry1.dts", edited);
    l = dtfile::load(m, d.path, "blob1");
    EXPECT(l.blob == blob_of(edited));
    EXPECT_HAS(l.note, "was edited");
    EXPECT_HAS(l.note, ".abr_raw");

    // back as it was unpacked (the same text): the bytes again
    put_text(d.path / "entry1.dts", p.source);
    EXPECT(dtfile::load(m, d.path, "blob1").blob == blob);

    // a raw copy that is not the one of the manifest is refused, with both names
    Bytes other = blob_of(kTree);
    write_file(d.path / ".abr_raw" / "entry1.dts.raw", other);
    const std::string said = refusal_of([&] { dtfile::load(m, d.path, "blob1"); });
    EXPECT_HAS(said, ".abr_raw/entry1.dts.raw");
    EXPECT_HAS(said, "blob1_raw_hash");
    // a raw copy with the right hash that is no tree is refused too (the hash is the manifest's, which may be edited as well)
    const Bytes junk(100, 0x41);
    write_file(d.path / ".abr_raw" / "entry1.dts.raw", junk);
    m.set_hex("blob1_raw_hash", hash::sha256(junk));
    EXPECT(!refusal_of([&] { dtfile::load(m, d.path, "blob1"); }).empty());

    // no raw copy at all: the source is compiled (a person deleted it, which is what the note says to do)
    std::error_code ec;
    fs::remove(d.path / ".abr_raw" / "entry1.dts.raw", ec);
    put_text(d.path / "entry1.dts", p.source);
    EXPECT(dtfile::load(m, d.path, "blob1").blob == blob_of(p.source));
}

// --------------------------------------------------------------------------------------------------------------------- no source
void test_no_source() {
    const Bytes junk(200, 0x5A);
    const dtfile::Prepared p = dtfile::prepare(junk);
    EXPECT(!p.text);
    EXPECT(!p.note.empty());
    EXPECT(dtfile::file_name("dtb/entry3.dts", p) == "dtb/entry3.dtb");
    EXPECT(dtfile::file_name("plain.bin", p) == "plain.bin");

    // (a file that is not a tree: it is the file of the slot and goes back as it is, where a slot may hold anything)
    TempDir d;
    Manifest m;
    dtfile::commit(m, d.path, "dtb5", "entry5.dts", p, junk);
    EXPECT(m.get("dtb5_file") == "entry5.dtb");
    EXPECT(read_file(d.path / "entry5.dtb") == junk);
    EXPECT(!m.has("dtb5_text_hash"));
    EXPECT(dtfile::load(m, d.path, "dtb5", false).blob == junk);
    const std::string said = refusal_of([&] { dtfile::load(m, d.path, "dtb5"); });
    EXPECT_HAS(said, "dtb5_file (entry5.dtb)");
    EXPECT_HAS(said, ".dts");

    // a blob that is a tree is a file of its own name, and has to be a tree as long as it is
    const Bytes blob = blob_of(kTree);
    write_file(d.path / "own.dtb", blob);
    m.set("dtb6_file", "own.dtb");
    EXPECT(dtfile::load(m, d.path, "dtb6").blob == blob);
    write_file(d.path / "own.dtb", Bytes(blob.begin(), blob.end() - 1));
    EXPECT_HAS(refusal_of([&] { dtfile::load(m, d.path, "dtb6"); }), "dtb6_file (own.dtb)");
}

// ------------------------------------------------------------------------------------------------------------------ what is refused
void test_refusals() {
    TempDir d;
    Manifest m;
    EXPECT_HAS(refusal_of([&] { dtfile::load(m, d.path, "blob0"); }), "blob0_file");  // no key
    m.set("blob0_file", "entry0.dts");
    EXPECT(!refusal_of([&] { dtfile::load(m, d.path, "blob0"); }).empty());  // no file
    m.set("blob0_file", "../entry0.dts");
    EXPECT(!refusal_of([&] { dtfile::load(m, d.path, "blob0"); }).empty());  // a name that leaves the folder
    m.set("blob0_file", "entry0.dts");
    put_text(d.path / "entry0.dts", "/dts-v1/;\n/ {\n\tmodel = \"x\"\n};\n");
    const std::string said = refusal_of([&] { dtfile::load(m, d.path, "blob0"); });
    EXPECT_HAS(said, "entry0.dts");  // the file and the line
    EXPECT_HAS(said, "line 4");
    put_text(d.path / "entry0.dts", "/dts-v1/;\n/ { a = <&nowhere>; };\n");
    EXPECT_HAS(refusal_of([&] { dtfile::load(m, d.path, "blob0"); }), "nowhere");
}

// ---------------------------------------------------------------------------------------------------- /include/ and /incbin/ stay inside
void test_includes() {
    TempDir d;
    fs::create_directories(d.path / "sub");
    put_text(d.path / "sub" / "part.dtsi", "model = \"from a part\";\n");
    write_file(d.path / "sub" / "data.bin", Bytes{1, 2, 3, 4});
    put_text(d.path / "sub" / "entry0.dts",
             "/dts-v1/;\n/ {\n/include/ \"part.dtsi\"\n\tblob = /incbin/(\"data.bin\");\n};\n");
    Manifest m;
    m.set("blob0_file", "sub/entry0.dts");
    const dtfile::Loaded l = dtfile::load(m, d.path, "blob0");
    const fdt::Tree tree = fdt::parse(l.blob);
    bool model = false, blob = false;
    for (const fdt::Property& pr : tree.root.props) {
        if (pr.name == "model") model = std::string(pr.value.begin(), pr.value.end()) == std::string("from a part\0", 12);
        if (pr.name == "blob") blob = pr.value == Bytes{1, 2, 3, 4};
    }
    EXPECT(model && blob);

    // a file outside the folder of the source is not read, whatever the name looks like
    put_text(d.path / "secret.txt", "model = \"secret\";\n");
    for (const char* name : {"../secret.txt", "../../secret.txt", "/etc/passwd", "sub/../../secret.txt"}) {
        put_text(d.path / "sub" / "entry0.dts", std::string("/dts-v1/;\n/ {\n/include/ \"") + name + "\"\n};\n");
        EXPECT_HAS(refusal_of([&] { dtfile::load(m, d.path, "blob0"); }), "may be read");
        put_text(d.path / "sub" / "entry0.dts", std::string("/dts-v1/;\n/ { x = /incbin/(\"") + name + "\"); };\n");
        EXPECT_HAS(refusal_of([&] { dtfile::load(m, d.path, "blob0"); }), "may be read");
    }
}

void test_names() {
    EXPECT(dtfile::is_source_name("a.dts"));
    EXPECT(dtfile::is_source_name("dtb/entry0.DTS"));
    EXPECT(dtfile::is_source_name("x.Dts"));
    EXPECT(!dtfile::is_source_name(".dts"));
    EXPECT(!dtfile::is_source_name("dts"));
    EXPECT(!dtfile::is_source_name("a.dtb"));
    EXPECT(!dtfile::is_source_name("a.dtsi"));
    EXPECT(!dtfile::is_source_name("a.dts.raw"));
    EXPECT(!dtfile::is_source_name(""));
}

// A tree with no property that a source cannot say is a source; a name that a source cannot say makes the file of the blob.
void test_unsayable_name() {
    fdt::Tree tree = dts::parse(kTree, "test");
    fdt::Node odd;
    odd.name = "bad name with spaces";
    tree.root.children.push_back(odd);
    const Bytes blob = fdt::build(tree);
    const dtfile::Prepared p = dtfile::prepare(blob);
    EXPECT(!p.text);
    EXPECT(!p.note.empty());
}

// Many random trees: whatever prepare() decides, commit() and load() give the blob back.
void test_random_round_trips() {
    std::mt19937 rng(20261121);
    for (int round = 0; round < 300; ++round) {
        std::string text = "/dts-v1/;\n/ {\n";
        const int props = static_cast<int>(rng() % 6);
        for (int i = 0; i < props; ++i) {
            text += "\tp" + std::to_string(i) + " = ";
            switch (rng() % 3) {
                case 0: text += "<" + std::to_string(rng() % 100000) + ">;\n"; break;
                case 1: text += "\"s" + std::to_string(rng() % 1000) + "\";\n"; break;
                default: text += "[" + std::string(2 * (rng() % 9), 'a') + "];\n"; break;
            }
        }
        const int kids = static_cast<int>(rng() % 4);
        for (int i = 0; i < kids; ++i) text += "\tn" + std::to_string(i) + " { q = <" + std::to_string(rng() % 99) + ">; };\n";
        text += "};\n";
        Bytes blob = blob_of(text);
        const size_t kind = rng() % 4;
        if (kind == 1) blob = fdt::build(dts::parse(text, "t"), rng() % 64 + 1);
        if (kind == 2) blob = with_orphan_string(blob);
        TempDir d;
        Manifest m;
        const dtfile::Prepared p = dtfile::prepare(blob);
        dtfile::commit(m, d.path, "t", "t.dts", p, blob);
        const dtfile::Loaded l = dtfile::load(m, d.path, "t");
        EXPECT(l.blob == blob);
        EXPECT(p.text);
        EXPECT(p.keep_raw == (kind == 2));
    }
}

}  // namespace

int run_dtfile_tests() {
    test_plain_tree();
    test_slack();
    test_raw_copy();
    test_no_source();
    test_refusals();
    test_includes();
    test_names();
    test_unsayable_name();
    test_random_round_trips();
    if (g_failures == 0) std::printf("dtfile: ok (%d checks)\n", g_checks);
    else std::printf("dtfile: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
