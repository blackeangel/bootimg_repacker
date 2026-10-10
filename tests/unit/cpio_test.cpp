// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr::cpio (include/abr/cpio.hpp) and of the ramdisk directory built on it
// (include/abr/ramdisk_tree.hpp). Run by tests/run_tests.sh as `abr_unit_tests cpio`.
//
//   * write() and parse() are each other's inverse, for both magics, and parse() is strict: every
//     way an archive can be damaged that it could only guess about is an error with a reason;
//   * an archive becomes a directory plus a metadata file and comes back byte for byte, including
//     names a text file needs quoting for, a non-canonical order, inode numbers and link counts that
//     follow no rule, a fill after the end record of any length, a root record "." with or without
//     "./" in front of the other names -- and several archives one after the other, each its own
//     directory;
//   * an edited directory (a file changed, added, deleted, a mode changed in the metadata, the
//     metadata gone, a volume deleted) builds the archive the edit says, new entries with the
//     documented defaults, and says which entries those were;
//   * symbolic links are links where the system has them and Cygwin link files where it does not, and
//     either is read back as a link, whichever system the tree has been carried to;
//   * what cannot be a directory (hard links, a name twice, '..', an absolute name, a missing
//     parent, junk after the end, odc, a damaged archive, names that are not UTF-8) is refused, with the
//     reason, and nothing is left behind;
//   * a few hundred random archives come back exact, and an edit changes only what it edits.
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "abr/byte_io.hpp"
#include "abr/cpio.hpp"
#include "abr/ramdisk_tree.hpp"
#include "abr/sha.hpp"

using namespace abr;
namespace fs = std::filesystem;

namespace {

int g_failures = 0;
int g_checks = 0;

#define EXPECT(cond)                                                              \
    do {                                                                          \
        ++g_checks;                                                               \
        if (!(cond)) {                                                            \
            ++g_failures;                                                         \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                         \
    } while (0)

bool contains(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

#define EXPECT_HAS(text, needle)                                                                  \
    do {                                                                                          \
        const std::string t_ = (text);                                                            \
        ++g_checks;                                                                               \
        if (!contains(t_, (needle))) {                                                            \
            ++g_failures;                                                                         \
            std::printf("  FAIL %s:%d: \"%s\" does not say \"%s\"\n", __FILE__, __LINE__, t_.c_str(), \
                        std::string(needle).c_str());                                             \
        }                                                                                         \
    } while (0)

Bytes bytes(std::string_view s) { return Bytes(s.begin(), s.end()); }

cpio::Entry entry(const std::string& name, uint32_t mode, std::string_view data = "", uint32_t ino = 0,
                  uint32_t nlink = 1) {
    cpio::Entry e;
    e.name = name;
    e.mode = mode;
    e.data = bytes(data);
    e.ino = ino;
    e.nlink = nlink;
    return e;
}

constexpr uint32_t DIR = cpio::kDirectory | 0755;
constexpr uint32_t REG = cpio::kRegular | 0644;
constexpr uint32_t EXE = cpio::kRegular | 0755;
constexpr uint32_t LNK = cpio::kSymlink | 0777;

// What Android's mkbootfs makes of a list of entries: inodes counted from 300000, the end record
// with mode 0755, zero fill up to a multiple of 256.
Bytes mkbootfs_like(std::vector<cpio::Entry> es, cpio::Magic magic = cpio::Magic::NEWC, size_t tail = 256,
                    bool upper = false) {
    cpio::Archive a;
    a.magic = magic;
    a.upper_hex = upper;
    for (size_t i = 0; i < es.size(); ++i) es[i].ino = 300000 + static_cast<uint32_t>(i);
    a.entries = std::move(es);
    a.trailer.mode = 0755;
    a.trailer.ino = 300000 + static_cast<uint32_t>(a.entries.size());
    Bytes out = cpio::write(a);
    out.resize(align_up(out.size(), tail), 0);
    return out;
}

Bytes concat(const std::vector<Bytes>& parts) {
    Bytes out;
    for (const Bytes& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

std::vector<cpio::Entry> sample_entries() {
    std::vector<cpio::Entry> es;
    es.push_back(entry("bin", DIR));
    es.push_back(entry("bin/sh", EXE, "#!/bin/sh\n"));
    es.push_back(entry("dev", DIR));
    {
        cpio::Entry c = entry("dev/console", cpio::kCharDev | 0600);
        c.rdevmajor = 5;
        c.rdevminor = 1;
        es.push_back(c);
    }
    es.push_back(entry("dev/fifo", cpio::kFifo | 0600));
    es.push_back(entry("empty", REG));
    es.push_back(entry("etc", LNK, "/system/etc"));
    es.push_back(entry("init", EXE, std::string_view("\x7f" "ELF\0\1\2\3 more bytes", 19)));
    es.push_back(entry("init.rc", cpio::kRegular | 0750, "on boot\n    start x\n"));
    es.push_back(entry("odd", REG, "12345"));  // 5 bytes: data padding
    es.push_back(entry("odd2", REG, "1234567"));
    return es;
}

// What Magisk puts after the ramdisk of an image: an archive of its own.
std::vector<cpio::Entry> overlay_entries() {
    std::vector<cpio::Entry> es;
    es.push_back(entry(".backup", DIR));
    es.push_back(entry(".backup/.magisk", REG, "KEEPVERITY=true\n"));
    es.push_back(entry("overlay.d", DIR));
    es.push_back(entry("overlay.d/sbin", DIR));
    es.push_back(entry("overlay.d/sbin/magisk", EXE, "#!/system/bin/sh\n"));
    return es;
}

std::optional<cpio::Parsed> must_parse(const Bytes& b) {
    std::string error;
    auto p = cpio::parse(b, error);
    ++g_checks;
    if (!p) {
        ++g_failures;
        std::printf("  FAIL: the archive does not parse: %s\n", error.c_str());
    }
    return p;
}

const cpio::Entry* find_entry(const cpio::Archive& a, std::string_view name) {
    for (const cpio::Entry& e : a.entries)
        if (e.name == name) return &e;
    return nullptr;
}

std::vector<std::string> names_of(const cpio::Archive& a) {
    std::vector<std::string> out;
    for (const cpio::Entry& e : a.entries) out.push_back(e.name);
    return out;
}

// ----------------------------------------------------------------------------- cpio

// The case of the hexadecimal digits of the headers of the first archive of `wire`: 'U' upper, 'l' lower,
// 'm' both, '-' no letters at all.
char digit_case(const Bytes& wire) {
    bool upper = false;
    bool lower = false;
    size_t pos = 0;
    while (pos + cpio::kHeaderSize <= wire.size() && std::memcmp(&wire[pos], "07070", 5) == 0) {
        for (size_t i = 6; i < cpio::kHeaderSize; ++i) {
            const uint8_t c = wire[pos + i];
            if (c >= 'A' && c <= 'F') upper = true;
            if (c >= 'a' && c <= 'f') lower = true;
        }
        auto field = [&](size_t n) {
            size_t v = 0;
            for (size_t i = 0; i < 8; ++i) {
                const uint8_t c = wire[pos + 6 + 8 * n + i];
                v = v * 16 + static_cast<size_t>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
            }
            return v;
        };
        const size_t namesize = field(11);
        const size_t filesize = field(6);
        const bool trailer = std::memcmp(&wire[pos + cpio::kHeaderSize], cpio::kTrailerName, 10) == 0;
        pos += align_up(cpio::kHeaderSize + namesize, 4) + align_up(filesize, 4);
        if (trailer) break;
    }
    return upper && lower ? 'm' : upper ? 'U' : lower ? 'l' : '-';
}

void test_write_parse(cpio::Magic magic, bool upper = false) {
    cpio::Archive a;
    a.magic = magic;
    a.upper_hex = upper;
    a.entries = sample_entries();
    for (size_t i = 0; i < a.entries.size(); ++i) {
        a.entries[i].ino = 100 + static_cast<uint32_t>(i) * 3;
        a.entries[i].uid = static_cast<uint32_t>(i);
        a.entries[i].gid = 2000 + static_cast<uint32_t>(i);
        a.entries[i].mtime = 1700000000u + static_cast<uint32_t>(i);
        a.entries[i].nlink = 1 + static_cast<uint32_t>(i % 3);
        a.entries[i].devmajor = 8;
        a.entries[i].devminor = static_cast<uint32_t>(i);
    }
    a.trailer.mode = 0644;
    a.trailer.nlink = 7;
    const Bytes wire = cpio::write(a);
    EXPECT(wire.size() % 4 == 0);
    EXPECT(cpio::looks_like_cpio(wire.data(), wire.size()));
    EXPECT(std::memcmp(wire.data(), magic == cpio::Magic::CRC ? "070702" : "070701", 6) == 0);
    EXPECT(digit_case(wire) == (upper ? 'U' : 'l'));

    Bytes padded = wire;
    padded.resize(wire.size() + 1000, 0);
    std::string error;
    const auto parsed = cpio::parse(padded, error);
    EXPECT(parsed.has_value());
    if (!parsed) {
        std::printf("    %s\n", error.c_str());
        return;
    }
    EXPECT(parsed->length == wire.size());
    EXPECT(parsed->archive.magic == magic);
    EXPECT(parsed->archive.upper_hex == upper);
    EXPECT(parsed->archive.entries.size() == a.entries.size());
    for (size_t i = 0; i < a.entries.size() && i < parsed->archive.entries.size(); ++i) {
        const cpio::Entry& x = a.entries[i];
        const cpio::Entry& y = parsed->archive.entries[i];
        EXPECT(x.name == y.name && x.mode == y.mode && x.data == y.data && x.ino == y.ino);
        EXPECT(x.uid == y.uid && x.gid == y.gid && x.mtime == y.mtime && x.nlink == y.nlink);
        EXPECT(x.devmajor == y.devmajor && x.devminor == y.devminor);
        EXPECT(x.rdevmajor == y.rdevmajor && x.rdevminor == y.rdevminor);
    }
    EXPECT(parsed->archive.trailer.mode == 0644 && parsed->archive.trailer.nlink == 7);
    EXPECT(cpio::write(parsed->archive) == wire);

    if (magic == cpio::Magic::CRC) {  // the check field is the byte sum, for regular files only
        const cpio::Entry& e = parsed->archive.entries[1];
        EXPECT(e.name == "bin/sh" && cpio::byte_sum(e.data) == cpio::byte_sum(bytes("#!/bin/sh\n")));
    }
}

// Damages `wire` with `mutate` and requires parse() to refuse it, with `why` in the reason.
void expect_refused(const char* what, const Bytes& wire, void (*mutate)(Bytes&), std::string_view why) {
    ++g_checks;
    Bytes b = wire;
    if (mutate) mutate(b);
    std::string error;
    const auto parsed = cpio::parse(b, error);
    if (parsed) {
        ++g_failures;
        std::printf("  FAIL: %s was accepted\n", what);
        return;
    }
    if (!contains(error, why)) {
        ++g_failures;
        std::printf("  FAIL: %s: the reason is \"%s\", not \"%s\"\n", what, error.c_str(), std::string(why).c_str());
    }
}

void test_parse_strictness() {
    cpio::Archive a;
    a.entries.push_back(entry("d", DIR));      // header 110 + name 2 = 112: no padding
    a.entries.push_back(entry("d/f", REG, "hello"));  // 110 + 4 = 114: 2 padding bytes; 5 data bytes: 3 padding
    a.entries.push_back(entry("l", LNK, "d/f"));
    a.trailer.mode = 0755;
    const Bytes wire = cpio::write(a);
    std::string error;
    EXPECT(cpio::parse(wire, error).has_value());

    // The second record starts at 112; its name at 112 + 110 = 222, its name padding at 226..227,
    // its data at 228..232, the data padding at 233..235.
    expect_refused("a field that is not hexadecimal", wire, [](Bytes& b) { b[10] = 'g'; }, "hexadecimal");
    expect_refused("a name without its NUL", wire, [](Bytes& b) { b[111] = 'x'; }, "NUL");
    expect_refused("a NUL inside a name", wire, [](Bytes& b) { b[223] = 0; }, "NUL inside");
    expect_refused("padding after a name that is not zero", wire, [](Bytes& b) { b[226] = 1; }, "padding");
    expect_refused("padding after data that is not zero", wire, [](Bytes& b) { b[234] = 1; }, "padding");
    expect_refused("a cut-short archive", wire, [](Bytes& b) { b.resize(b.size() / 2); }, "");
    expect_refused("an archive without its end record", wire, [](Bytes& b) { b.resize(b.size() - 124); }, "");
    expect_refused("a name size of zero", wire, [](Bytes& b) { std::fill_n(b.begin() + 94, 8, uint8_t('0')); }, "0 bytes");
    expect_refused("a huge name size", wire, [](Bytes& b) { std::fill_n(b.begin() + 94, 8, uint8_t('f')); }, "name of");
    expect_refused("a data size that runs past the end", wire, [](Bytes& b) { std::fill_n(b.begin() + 112 + 54, 8, uint8_t('f')); }, "past the end");
    expect_refused("a check value in a 070701 record", wire, [](Bytes& b) { b[110 - 1] = '1'; }, "checksum");
    expect_refused("two kinds of record in one archive", wire, [](Bytes& b) { b[112 + 5] = '2'; }, "mixed");
    expect_refused("no magic", wire, [](Bytes& b) { b[0] = 'X'; }, "no cpio record");
    expect_refused("nothing at all", Bytes(), nullptr, "cut short");

    cpio::Archive crc;
    crc.magic = cpio::Magic::CRC;
    crc.entries.push_back(entry("f", REG, "abcdef"));
    const Bytes crc_wire = cpio::write(crc);
    EXPECT(cpio::parse(crc_wire, error).has_value());
    // The data of "f" starts at 112 + 0: header 110 + name 2 = 112.
    expect_refused("a data byte that does not match its checksum", crc_wire, [](Bytes& b) { b[112] ^= 1; }, "checksum");

    // An end record that holds data.
    cpio::Archive with_data;
    with_data.entries.push_back(entry(cpio::kTrailerName, REG, "data"));
    const Bytes data_wire = cpio::write(with_data);
    const auto refused = cpio::parse(data_wire, error);
    EXPECT(!refused.has_value());
    EXPECT_HAS(error, "has data");
}

// ----------------------------------------------------------------------------- the Cygwin link file

void test_cygwin_format() {
    // What the tools of the user write for "ab": "!<symlink>", FF FE, each character and a zero byte,
    // two zero bytes. For ASCII that is UTF-16LE.
    const Bytes want = {0x21, 0x3C, 0x73, 0x79, 0x6D, 0x6C, 0x69, 0x6E, 0x6B, 0x3E, 0xFF, 0xFE, 'a', 0, 'b', 0, 0, 0};
    EXPECT(cygwin_link_file("ab") == want);

    std::string error;
    for (const std::string& target :
         {std::string("/system/bin/sh"), std::string("../a b/c"), std::string("caf\xc3\xa9"),
          std::string("\xf0\x9f\x98\x80 emoji"), std::string("\xe2\x82\xac\xd0\x9f\xd1\x80\xd0\xb8"), std::string(255, 'p'),
          std::string("x")}) {
        const Bytes file = cygwin_link_file(target);
        const auto back = read_cygwin_link_file(file, error);
        EXPECT(back.has_value() && *back == target);
        EXPECT(error.empty());
    }
    // The characters outside the first plane are two UTF-16 units: a surrogate pair.
    {
        const Bytes f = cygwin_link_file("\xf0\x9f\x98\x80");  // U+1F600
        const Bytes pair = {0x3D, 0xD8, 0x00, 0xDE};
        EXPECT(f.size() == 12 + 4 + 2);
        EXPECT(std::equal(pair.begin(), pair.end(), f.begin() + 12));
    }

    // The older form: UTF-8 up to a zero byte, no byte order mark.
    {
        const auto old = read_cygwin_link_file(bytes(std::string("!<symlink>old/style\0", 20)), error);
        EXPECT(old.has_value() && *old == "old/style");
        const auto unterminated = read_cygwin_link_file(bytes("!<symlink>no/zero"), error);
        EXPECT(unterminated.has_value() && *unterminated == "no/zero");
    }
    // Like Cygwin, it stops at the first zero unit; what follows is not looked at, a missing
    // terminator is not a fault.
    {
        Bytes f = cygwin_link_file("ab");
        f.push_back(0xFF);
        f.push_back(0xFF);
        const auto b = read_cygwin_link_file(f, error);
        EXPECT(b.has_value() && *b == "ab");
        Bytes no_end(f.begin(), f.begin() + 16);  // magic, BOM, "ab", no terminator
        const auto c = read_cygwin_link_file(no_end, error);
        EXPECT(c.has_value() && *c == "ab");
    }

    // Not a link file: nothing returned and no error.
    for (const std::string& other : {std::string(), std::string("hello"), std::string("!<symlin"), std::string("#!/bin/sh\n"),
                                     std::string("\xff\xfe!\0<\0s\0y\0m\0l\0i\0n\0k\0>\0", 22)}) {
        const auto none = read_cygwin_link_file(bytes(other), error);
        EXPECT(!none.has_value() && error.empty());
    }

    // A link file that cannot be read says why.
    auto broken = [&](const char* what, const Bytes& file, std::string_view why) {
        const auto none = read_cygwin_link_file(file, error);
        ++g_checks;
        if (none.has_value()) {
            ++g_failures;
            std::printf("  FAIL: %s was read as '%s'\n", what, none->c_str());
            return;
        }
        if (!contains(error, why)) {
            ++g_failures;
            std::printf("  FAIL: %s: the reason is \"%s\", not \"%s\"\n", what, error.c_str(), std::string(why).c_str());
        }
    };
    Bytes head(bytes("!<symlink>"));
    auto with = [&](std::initializer_list<uint8_t> tail) {
        Bytes b = head;
        b.insert(b.end(), tail.begin(), tail.end());
        return b;
    };
    broken("nothing after the magic", head, "no target");
    broken("an empty UTF-16 target", with({0xFF, 0xFE, 0, 0}), "no target");
    broken("an empty UTF-8 target", with({0}), "no target");
    broken("a low surrogate alone", with({0xFF, 0xFE, 0x00, 0xDC, 0, 0}), "low surrogate");
    broken("a high surrogate alone", with({0xFF, 0xFE, 0x3D, 0xD8, 0x41, 0x00, 0, 0}), "high surrogate");
    broken("a high surrogate at the end", with({0xFF, 0xFE, 0x3D, 0xD8}), "middle of a character");
    broken("an odd number of bytes", with({0xFF, 0xFE, 'a', 0, 'b'}), "middle of a character");
    broken("UTF-8 that is not", with({'a', 0xFF, 'b', 0}), "not UTF-8");

    // What cannot be written is refused.
    auto refuses = [&](const char* what, const std::string& target) {
        ++g_checks;
        try {
            (void)cygwin_link_file(target);
            ++g_failures;
            std::printf("  FAIL: a link file for %s was written\n", what);
        } catch (const FormatError&) {
        }
    };
    refuses("an empty target", "");
    refuses("a target with a zero byte", std::string("a\0b", 3));
    refuses("a target that is not UTF-8", "caf\xe9");
    refuses("an overlong UTF-8 form", "\xc0\xaf");
    refuses("a surrogate in UTF-8", "\xed\xa0\x80");
    refuses("a code point beyond Unicode", "\xf4\x90\x80\x80");
}

// ----------------------------------------------------------------------------- the directory

fs::path make_temp_dir() {
    static std::atomic<unsigned> counter{0};
    std::random_device rd;
    const fs::path base = fs::temp_directory_path();
    for (int i = 0; i < 100; ++i) {
        fs::path p = base / ("abr-cpio-test-" + std::to_string(rd()) + "-" + std::to_string(counter++));
        std::error_code ec;
        if (fs::create_directory(p, ec)) return p;
    }
    throw std::runtime_error("cannot make a temporary directory");
}

struct TempDir {
    fs::path path = make_temp_dir();
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::string slurp(const fs::path& p) {
    const Bytes b = read_file(p);
    return std::string(b.begin(), b.end());
}

void spit(const fs::path& p, const std::string& s) { write_file(p, reinterpret_cast<const uint8_t*>(s.data()), s.size()); }

bool exists_at_all(const fs::path& p) {
    std::error_code ec;
    return fs::exists(fs::symlink_status(p, ec));
}

// extract_ramdisk_tree + pack_ramdisk_tree reproduce `wire` exactly.
void expect_exact_tree(const char* what, const Bytes& wire, size_t expected_entries = 0, size_t expected_volumes = 1) {
    TempDir t;
    const RamdiskTree r = extract_ramdisk_tree(wire, t.path, "tree");
    if (!r.created) {
        ++g_failures;
        std::printf("  FAIL: %s: no tree (%s)\n", what, r.reason.c_str());
        return;
    }
    EXPECT(r.exact);
    if (!r.exact) std::printf("    %s: %s\n", what, r.difference.c_str());
    if (expected_entries) EXPECT(r.entries == expected_entries);
    EXPECT(r.volumes == expected_volumes);
    const Bytes again = pack_ramdisk_tree(t.path, "tree", r.volumes);
    if (again != wire) {
        ++g_failures;
        std::printf("  FAIL: %s: the tree does not build the archive back\n", what);
    }
    EXPECT(hash::sha256(again) == r.rebuilt_sha256);
}

void test_tree_roundtrip() {
    expect_exact_tree("mkbootfs style", mkbootfs_like(sample_entries()), 11);
    expect_exact_tree("crc", mkbootfs_like(sample_entries(), cpio::Magic::CRC), 11);
    expect_exact_tree("an empty archive", mkbootfs_like({}), 0);
    for (size_t tail : {1u, 4u, 256u, 512u, 4096u}) expect_exact_tree("tail", mkbootfs_like(sample_entries(), cpio::Magic::NEWC, tail));
    {  // a fill that is no multiple of anything usual
        Bytes b = mkbootfs_like(sample_entries(), cpio::Magic::NEWC, 4);
        b.resize(b.size() + 37, 0);
        expect_exact_tree("an odd fill", b);
        b.resize(b.size() + 100000, 0);
        expect_exact_tree("a long fill", b);
    }
    {  // `find . | cpio`: a root record, "./x" names, a file system's inodes and counts, not sorted
        cpio::Archive a;
        a.entries.push_back(entry(".", DIR, "", 500, 4));
        a.entries.push_back(entry("./zeta", REG, "z", 9001));
        a.entries.push_back(entry("./alpha", DIR, "", 77, 3));
        a.entries.push_back(entry("./alpha/inner", DIR, "", 78, 2));
        a.entries.push_back(entry("./alpha/file", EXE, "aaa", 4000));
        a.entries.push_back(entry("./beta", DIR, "", 12, 2));
        for (cpio::Entry& e : a.entries) {
            e.mtime = 1700000123;
            e.devmajor = 8;
            e.devminor = 1;
            e.uid = e.gid = 0;
        }
        a.trailer.mode = 0;
        Bytes b = cpio::write(a);
        b.resize(align_up(b.size(), 512), 0);
        expect_exact_tree("find | cpio", b, 5);
    }
    {  // inode numbers and link counts that follow no rule
        cpio::Archive a;
        uint32_t ino = 91;
        for (cpio::Entry e : sample_entries()) {
            e.ino = ino += 1000;
            e.nlink = e.type() == cpio::kDirectory ? 2 : 1;
            a.entries.push_back(e);
        }
        a.entries[2].nlink = 9;  // a directory with a count no layout explains
        a.trailer.mode = 0755;
        a.trailer.ino = 5;
        Bytes b = cpio::write(a);
        b.resize(align_up(b.size(), 256), 0);
        expect_exact_tree("explicit inodes and link counts", b);
    }
    {  // owners and the special permission bits
        std::vector<cpio::Entry> es = sample_entries();
        es[1].mode = cpio::kRegular | 04755;
        es[1].uid = 1000;
        es[1].gid = 2000;
        es[0].mode = cpio::kDirectory | 01777;
        es[2].mode = cpio::kDirectory | 02755;
        expect_exact_tree("owners and setuid/setgid/sticky", mkbootfs_like(es));
    }
    {  // files of more than 64 KiB, and of 4096 and 4097 bytes; the names sort behind the sample's
        std::vector<cpio::Entry> es = sample_entries();
        std::mt19937 rng(7);
        for (size_t n : {size_t(131072), size_t(4096), size_t(4097), size_t(65537)}) {
            cpio::Entry e = entry("zbig" + std::to_string(n), REG);
            for (size_t i = 0; i < n; ++i) e.data.push_back(static_cast<uint8_t>(rng()));
            es.push_back(e);
        }
        expect_exact_tree("large files", mkbootfs_like(es), 15);
    }
    {  // a regular file that happens to look like a Cygwin link stays a file: the metadata says what it is
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("zlook", REG));
        const Bytes link = cygwin_link_file("some/target");
        es.back().data = link;
        expect_exact_tree("a file that looks like a Cygwin link", mkbootfs_like(es), 12);
    }
#ifndef _WIN32
    {  // names that need quoting in the metadata file
        std::vector<cpio::Entry> es;
        es.push_back(entry("res", DIR));
        for (const std::string& n : {std::string("with space"), std::string("\"quoted\""), std::string("back\\slash"),
                                     std::string("tab\there"), std::string("new\nline"), std::string(" leading"),
                                     std::string("trailing "), std::string("#hash"), std::string("- dash"),
                                     std::string("caf\xc3\xa9"), std::string("ctl\x01\x7f"), std::string(200, 'n')})
            es.push_back(entry("res/" + n, REG, n));
        std::stable_sort(es.begin() + 1, es.end(), [](const cpio::Entry& x, const cpio::Entry& y) { return x.name < y.name; });
        expect_exact_tree("names that need quoting", mkbootfs_like(es), 13);
    }
#endif
}

// GNU cpio 2.15 writes the root as "." and everything else without "./"; older versions put "./" in
// front of the rest. Both are archives, and so is one with no root record at all.
void test_root_record() {
    auto plain_root = [](bool root, bool dotslash) {
        std::vector<cpio::Entry> es;
        const std::string p = dotslash ? "./" : "";
        if (root) es.push_back(entry(".", DIR));
        es.push_back(entry(p + "bin", DIR));
        es.push_back(entry(p + "bin/sh", EXE, "#!/bin/sh\n"));
        es.push_back(entry(p + "etc", DIR));
        es.push_back(entry(p + "etc/fstab", REG, "x"));
        es.push_back(entry(p + "init", EXE, "i"));
        return mkbootfs_like(es);
    };
    expect_exact_tree("a root and plain names (GNU cpio 2.15)", plain_root(true, false), 5);
    expect_exact_tree("a root and ./ names (older cpio)", plain_root(true, true), 5);
    expect_exact_tree("plain names, no root", plain_root(false, false), 5);
    expect_exact_tree("./ names, no root", plain_root(false, true), 5);
    expect_exact_tree("only the root", mkbootfs_like({entry(".", DIR)}), 0);

    {  // a file added to a tree whose names are plain stays plain, and the root stays
        TempDir t;
        const Bytes wire = plain_root(true, false);
        const RamdiskTree r = extract_ramdisk_tree(wire, t.path, "tree");
        EXPECT(r.created && r.exact);
        EXPECT_HAS(slurp(t.path / "tree.meta"), "names plain");
        EXPECT_HAS(slurp(t.path / "tree.meta"), "d 0755 0 0 0 - .\n");
        spit(t.path / "tree/new.txt", "n");
        const auto edited = must_parse(pack_ramdisk_tree(t.path, "tree"));
        if (edited) {
            EXPECT((names_of(edited->archive) ==
                    std::vector<std::string>{".", "bin", "bin/sh", "etc", "etc/fstab", "init", "new.txt"}));
        }
    }
    {  // and the other way: "./" names with a root
        TempDir t;
        const Bytes wire = plain_root(true, true);
        const RamdiskTree r = extract_ramdisk_tree(wire, t.path, "tree");
        EXPECT(r.created && r.exact);
        EXPECT_HAS(slurp(t.path / "tree.meta"), "names dotslash");
        spit(t.path / "tree/new.txt", "n");
        const auto edited = must_parse(pack_ramdisk_tree(t.path, "tree"));
        if (edited) {
            EXPECT((names_of(edited->archive) ==
                    std::vector<std::string>{".", "./bin", "./bin/sh", "./etc", "./etc/fstab", "./init", "./new.txt"}));
        }
    }
    {  // a root record taken out of the metadata is taken out of the archive
        TempDir t;
        const RamdiskTree r = extract_ramdisk_tree(plain_root(true, false), t.path, "tree");
        EXPECT(r.created);
        std::string meta = slurp(t.path / "tree.meta");
        const std::string root_line = "d 0755 0 0 0 - .\n";
        const size_t at = meta.find(root_line);
        EXPECT(at != std::string::npos);
        if (at != std::string::npos) {
            meta.erase(at, root_line.size());
            spit(t.path / "tree.meta", meta);
            const auto edited = must_parse(pack_ramdisk_tree(t.path, "tree"));
            if (edited) EXPECT(find_entry(edited->archive, ".") == nullptr);
        }
    }
}

// GNU cpio -- and so `find . | cpio -H newc`, as Android Image Kitchen packs a ramdisk -- writes the
// digits of the headers in upper case, Android's mkbootfs and Magisk in lower case. An archive comes back
// as it was, and an edited one is written the way the unedited one was.
void test_hex_case() {
    {
        const Bytes lower = mkbootfs_like(sample_entries());
        const Bytes upper = mkbootfs_like(sample_entries(), cpio::Magic::NEWC, 256, true);
        EXPECT(digit_case(lower) == 'l' && digit_case(upper) == 'U');
        EXPECT(lower != upper);
        const auto pl = must_parse(lower);
        const auto pu = must_parse(upper);
        EXPECT(pl && !pl->archive.upper_hex);
        EXPECT(pu && pu->archive.upper_hex);
        if (pu) EXPECT(cpio::write(pu->archive) == Bytes(upper.begin(), upper.begin() + static_cast<std::ptrdiff_t>(pu->length)));
    }
    expect_exact_tree("upper case digits", mkbootfs_like(sample_entries(), cpio::Magic::NEWC, 512, true), 11);
    expect_exact_tree("upper case digits, crc", mkbootfs_like(sample_entries(), cpio::Magic::CRC, 512, true), 11);
    expect_exact_tree("upper case digits, then lower case (two archives)",
                      concat({mkbootfs_like(sample_entries(), cpio::Magic::NEWC, 512, true), mkbootfs_like(overlay_entries())}), 16, 2);
    expect_exact_tree("lower case digits, then upper case (two archives)",
                      concat({mkbootfs_like(sample_entries()), mkbootfs_like(overlay_entries(), cpio::Magic::NEWC, 4, true)}), 16, 2);

    // Both cases in one archive is something no writer does: refused, with the reason.
    {
        Bytes b = mkbootfs_like(sample_entries(), cpio::Magic::NEWC, 256, true);
        const size_t second = align_up(cpio::kHeaderSize + 4, 4);  // "bin\0": the first record has no data
        size_t at = second + 6;
        while (at < second + cpio::kHeaderSize && !(b[at] >= 'A' && b[at] <= 'F')) ++at;
        EXPECT(at < second + cpio::kHeaderSize);
        b[at] = static_cast<uint8_t>(b[at] | 0x20);
        std::string error;
        EXPECT(!cpio::parse(b, error).has_value());
        EXPECT_HAS(error, "upper case in some records and lower case in others");
        TempDir t;
        const RamdiskTree r = extract_ramdisk_tree(b, t.path, "tree");
        EXPECT(!r.created);
        EXPECT_HAS(r.reason, "upper case in some records");
    }

    // The metadata says which, and an edit keeps it.
    for (const bool upper : {false, true}) {
        TempDir t;
        const Bytes wire = mkbootfs_like(sample_entries(), cpio::Magic::NEWC, 512, upper);
        EXPECT(extract_ramdisk_tree(wire, t.path, "tree").created);
        EXPECT_HAS(slurp(t.path / "tree.meta"), upper ? "\nhex upper\n" : "\nhex lower\n");
        spit(t.path / "tree/new.txt", "n");
        const Bytes edited = pack_ramdisk_tree(t.path, "tree");
        EXPECT(digit_case(edited) == (upper ? 'U' : 'l'));
        EXPECT(must_parse(edited).has_value());
        // The setting is one to change by hand.
        std::string meta = slurp(t.path / "tree.meta");
        const std::string was = upper ? "hex upper" : "hex lower";
        const size_t at = meta.find(was);
        EXPECT(at != std::string::npos);
        if (at != std::string::npos) {
            meta.replace(at, was.size(), upper ? "hex lower" : "hex upper");
            spit(t.path / "tree.meta", meta);
            EXPECT(digit_case(pack_ramdisk_tree(t.path, "tree")) == (upper ? 'l' : 'U'));
        }
    }

    // The fill after the archive: when 256 and 512 fit it alike, the digits tell who wrote it -- mkbootfs
    // and Magisk pad to 256, GNU cpio to 512 -- and an edit that grows the archive pads the same way.
    for (size_t pad = 0; pad < 600; pad += 20) {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("zpad", REG, std::string(pad, 'x')));
        for (const bool upper : {false, true}) {
            TempDir t;
            const Bytes wire = mkbootfs_like(es, cpio::Magic::NEWC, upper ? 512 : 256, upper);
            const RamdiskTree r = extract_ramdisk_tree(wire, t.path, "tree");
            EXPECT(r.created && r.exact);
            EXPECT_HAS(slurp(t.path / "tree.meta"), upper ? "\ntail align 512\n" : "\ntail align 256\n");
            spit(t.path / "tree/zpad", std::string(pad + 300, 'y'));
            EXPECT(pack_ramdisk_tree(t.path, "tree").size() % (upper ? 512 : 256) == 0);
        }
    }
}

void test_tree_edits() {
    TempDir t;
    const Bytes wire = mkbootfs_like(sample_entries());
    const RamdiskTree r = extract_ramdisk_tree(wire, t.path, "tree");
    EXPECT(r.created && r.exact && r.volumes == 1);

    // A file's contents, a new file, a new directory with a file, a deleted file, a deleted tree.
    spit(t.path / "tree/init.rc", "on boot\n    start y\n    start z\n");
    spit(t.path / "tree/newfile", "n");
    fs::create_directory(t.path / "tree/newdir");
    spit(t.path / "tree/newdir/inner", "i");
    fs::remove(t.path / "tree/odd");
    fs::remove_all(t.path / "tree/bin");

    PackReport report;
    const Bytes edited = pack_ramdisk_tree(t.path, "tree", 1, &report);
    EXPECT(report.warnings.empty());
    EXPECT(report.notes.size() == 2);
    if (report.notes.size() == 2) {
        EXPECT_HAS(report.notes[0], "tree/: 3 new entries not in tree.meta");
        EXPECT_HAS(report.notes[0], "newdir d 0755, newdir/inner f 0644, newfile f 0644");
        EXPECT_HAS(report.notes[1], "3 entries of tree.meta are not in the directory");
        EXPECT_HAS(report.notes[1], "bin, bin/sh, odd");
    }
    std::string error;
    const auto parsed = cpio::parse(edited, error);
    EXPECT(parsed.has_value());
    if (!parsed) return;
    const std::vector<std::string> want = {"dev", "dev/console", "dev/fifo", "empty", "etc", "init", "init.rc",
                                           "newdir", "newdir/inner", "newfile", "odd2"};
    EXPECT(names_of(parsed->archive) == want);
    for (size_t i = 0; i < parsed->archive.entries.size(); ++i) {
        const cpio::Entry& e = parsed->archive.entries[i];
        EXPECT(e.ino == 300000 + i);  // counted again, as mkbootfs does
        EXPECT(e.uid == 0 && e.gid == 0 && e.nlink == 1);
        if (e.name == "init.rc") {
            EXPECT(e.mode == (cpio::kRegular | 0750));  // kept from the metadata
            EXPECT(e.data == bytes("on boot\n    start y\n    start z\n"));
        }
        if (e.name == "newfile") EXPECT(e.mode == REG);                 // the default
        if (e.name == "newdir") EXPECT(e.mode == DIR);                  // the default
        if (e.name == "dev/console") {
            EXPECT(e.mode == (cpio::kCharDev | 0600) && e.rdevmajor == 5 && e.rdevminor == 1);
            EXPECT(e.data.empty());
        }
        if (e.name == "etc") EXPECT(e.mode == LNK && e.data == bytes("/system/etc"));
    }

    // The metadata: a mode and an owner changed by editing the line.
    std::string meta = slurp(t.path / "tree.meta");
    const std::string line = "f 0750 0 0 0 - init.rc";
    const size_t at = meta.find(line);
    EXPECT(at != std::string::npos);
    if (at != std::string::npos) {
        meta.replace(at, line.size(), "f 6755 1000 2000 0 - init.rc");
        spit(t.path / "tree.meta", meta);
        const auto changed = cpio::parse(pack_ramdisk_tree(t.path, "tree"), error);
        EXPECT(changed.has_value());
        if (changed)
            for (const cpio::Entry& e : changed->archive.entries)
                if (e.name == "init.rc") EXPECT(e.mode == (cpio::kRegular | 06755) && e.uid == 1000 && e.gid == 2000);
    }

    // A file that turns into a symbolic link by changing the type letter of its line, and holds the
    // target as text.
    {
        std::string m2 = slurp(t.path / "tree.meta");
        const std::string odd2 = "f 0644 0 0 0 - odd2";
        const size_t where = m2.find(odd2);
        EXPECT(where != std::string::npos);
        if (where != std::string::npos) {
            m2.replace(where, odd2.size(), "l 0777 0 0 0 - odd2");
            spit(t.path / "tree.meta", m2);
            spit(t.path / "tree/odd2", "target/path\r\n");
            const auto links = cpio::parse(pack_ramdisk_tree(t.path, "tree"), error);
            EXPECT(links.has_value());
            if (links) {
                const cpio::Entry* e = find_entry(links->archive, "odd2");
                EXPECT(e && e->mode == LNK && e->data == bytes("target/path"));
            }
            // and one with a byte order mark and no line break at all, as some editors save it
            spit(t.path / "tree/odd2", "\xEF\xBB\xBF" "second/target");
            const auto bom = cpio::parse(pack_ramdisk_tree(t.path, "tree"), error);
            if (bom) {
                const cpio::Entry* e = find_entry(bom->archive, "odd2");
                EXPECT(e && e->data == bytes("second/target"));
            }
            // a link whose file has nothing in it is a fault, not an empty link
            spit(t.path / "tree/odd2", "\r\n");
            try {
                (void)pack_ramdisk_tree(t.path, "tree");
                ++g_failures;
                std::printf("  FAIL: a link without a target was accepted\n");
            } catch (const FormatError& ex) {
                EXPECT_HAS(ex.what(), "odd2");
                EXPECT_HAS(ex.what(), "no target");
            }
            spit(t.path / "tree/odd2", "target/path");
        }
    }
    // The metadata gone: everything is made up the way mkbootfs would.
    fs::remove(t.path / "tree.meta");
    PackReport made_report;
    const Bytes made_up = pack_ramdisk_tree(t.path, "tree", 1, &made_report);
    EXPECT(made_report.warnings.size() == 1);
    if (!made_report.warnings.empty()) EXPECT_HAS(made_report.warnings[0], "there is no tree.meta");
    const auto made = cpio::parse(made_up, error);
    EXPECT(made.has_value());
    if (made)
        for (const cpio::Entry& e : made->archive.entries) {
            EXPECT(e.uid == 0 && e.gid == 0 && e.mtime == 0);
            if (e.name == "dev/console") EXPECT(e.mode == REG);  // a device is only a file without its metadata
            if (e.name == "init") EXPECT(e.mode == EXE);          // an ELF binary is executable
            if (e.name == "init.rc") EXPECT(e.mode == REG);
        }
}

void test_archive_order() {
    // The order is the archive's own (not sorted): what is new goes behind the last record of its directory.
    cpio::Archive a;
    a.entries.push_back(entry("z", DIR, "", 1));
    a.entries.push_back(entry("z/b", REG, "b", 2));
    a.entries.push_back(entry("z/a", REG, "a", 3));
    a.entries.push_back(entry("m", DIR, "", 4));
    a.entries.push_back(entry("m/q", REG, "q", 5));
    a.trailer.mode = 0755;
    a.trailer.ino = 6;
    Bytes wire = cpio::write(a);
    wire.resize(align_up(wire.size(), 256), 0);
    expect_exact_tree("an order that is not sorted", wire, 5);

    TempDir t;
    const RamdiskTree r = extract_ramdisk_tree(wire, t.path, "tree");
    EXPECT(r.created);
    EXPECT_HAS(slurp(t.path / "tree.meta"), "order archive");
    spit(t.path / "tree/z/c", "c");
    spit(t.path / "tree/zz", "zz");
    fs::create_directory(t.path / "tree/m/sub");
    spit(t.path / "tree/m/sub/s", "s");
    std::string error;
    const auto edited = cpio::parse(pack_ramdisk_tree(t.path, "tree"), error);
    EXPECT(edited.has_value());
    if (!edited) return;
    const std::vector<std::string> names = names_of(edited->archive);
    const std::vector<std::string> want = {"z", "z/b", "z/a", "z/c", "m", "m/q", "m/sub", "m/sub/s", "zz"};
    EXPECT(names == want);
    if (names != want) {
        for (const std::string& n : names) std::printf("    %s\n", n.c_str());
    }
}

// ----------------------------------------------------------------------------- permissions

// What a file, directory or link that is put into the tree gets when the metadata does not list it.
void test_new_entry_defaults() {
    TempDir t;
    const RamdiskTree r = extract_ramdisk_tree(mkbootfs_like(sample_entries()), t.path, "tree");
    EXPECT(r.created && r.exact);
    EXPECT_HAS(slurp(t.path / "tree.meta"), "newmode file=0644 exec=0755 dir=0755 link=0777\n");
    EXPECT_HAS(slurp(t.path / "tree.meta"), "default uid=0 gid=0 mtime=0 dev=0:0\n");

    const std::string elf("\x7f" "ELF\2\1\1\0 rest of a program", 25);
    spit(t.path / "tree/plain.txt", "text");
    spit(t.path / "tree/tool", elf);
    spit(t.path / "tree/script.sh", "#!/system/bin/sh\necho hi\n");
    spit(t.path / "tree/libfoo.so", elf);
    spit(t.path / "tree/libfoo.so.1", elf);
    spit(t.path / "tree/mod.ko", elf);
    spit(t.path / "tree/empty_new", "");
    spit(t.path / "tree/not_a_script", "# !/bin/sh\n");
    fs::create_directory(t.path / "tree/newdir");
    write_file(t.path / "tree/newlink", cygwin_link_file("tool"));
#ifndef _WIN32
    spit(t.path / "tree/runme", "x");
    fs::permissions(t.path / "tree/runme", fs::perms::owner_exec, fs::perm_options::add);
    // An executable bit on something the metadata lists changes nothing: the metadata is what counts.
    fs::permissions(t.path / "tree/init.rc", fs::perms::owner_all, fs::perm_options::replace);
    fs::permissions(t.path / "tree/init", fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
#endif
    PackReport report;
    const auto parsed = must_parse(pack_ramdisk_tree(t.path, "tree", 1, &report));
    if (!parsed) return;
    auto mode_of = [&](const char* name) -> int64_t {
        const cpio::Entry* e = find_entry(parsed->archive, name);
        return e ? static_cast<int64_t>(e->mode) : -1;
    };
    EXPECT(mode_of("plain.txt") == static_cast<int64_t>(REG));
    EXPECT(mode_of("tool") == static_cast<int64_t>(EXE));
    EXPECT(mode_of("script.sh") == static_cast<int64_t>(EXE));
    EXPECT(mode_of("libfoo.so") == static_cast<int64_t>(REG));
    EXPECT(mode_of("libfoo.so.1") == static_cast<int64_t>(REG));
    EXPECT(mode_of("mod.ko") == static_cast<int64_t>(REG));
    EXPECT(mode_of("empty_new") == static_cast<int64_t>(REG));
    EXPECT(mode_of("not_a_script") == static_cast<int64_t>(REG));
    EXPECT(mode_of("newdir") == static_cast<int64_t>(DIR));
    EXPECT(mode_of("newlink") == static_cast<int64_t>(LNK));
    EXPECT(mode_of("init.rc") == static_cast<int64_t>(cpio::kRegular | 0750));
    EXPECT(mode_of("init") == static_cast<int64_t>(EXE));
#ifndef _WIN32
    EXPECT(mode_of("runme") == static_cast<int64_t>(EXE));
#endif
    EXPECT(report.warnings.empty());
    EXPECT(!report.notes.empty());
    if (!report.notes.empty()) {
        EXPECT_HAS(report.notes[0], "new entries not in tree.meta");
        EXPECT_HAS(report.notes[0], "tool f 0755");
        EXPECT_HAS(report.notes[0], "libfoo.so f 0644");
        EXPECT_HAS(report.notes[0], "newdir d 0755");
        EXPECT_HAS(report.notes[0], "newlink l 0777");
        EXPECT_HAS(report.notes[0], "default owner 0:0");
    }

    // The defaults are the ones of the metadata, and can be changed there.
    std::string meta = slurp(t.path / "tree.meta");
    auto replace = [&](const std::string& from, const std::string& to) {
        const size_t at = meta.find(from);
        EXPECT(at != std::string::npos);
        if (at != std::string::npos) meta.replace(at, from.size(), to);
    };
    replace("newmode file=0644 exec=0755 dir=0755 link=0777", "newmode file=0640 exec=0750 dir=0700 link=0755");
    replace("default uid=0 gid=0", "default uid=1000 gid=1001");
    spit(t.path / "tree.meta", meta);
    PackReport second;
    const auto changed = must_parse(pack_ramdisk_tree(t.path, "tree", 1, &second));
    if (!changed) return;
    auto entry_of = [&](const char* name) { return find_entry(changed->archive, name); };
    EXPECT(entry_of("plain.txt") && entry_of("plain.txt")->mode == (cpio::kRegular | 0640));
    EXPECT(entry_of("tool") && entry_of("tool")->mode == (cpio::kRegular | 0750));
    EXPECT(entry_of("newdir") && entry_of("newdir")->mode == (cpio::kDirectory | 0700));
    EXPECT(entry_of("newlink") && entry_of("newlink")->mode == (cpio::kSymlink | 0755));
    EXPECT(entry_of("plain.txt") && entry_of("plain.txt")->uid == 1000 && entry_of("plain.txt")->gid == 1001);
    // what is listed keeps what the metadata says
    EXPECT(entry_of("init.rc") && entry_of("init.rc")->mode == (cpio::kRegular | 0750) && entry_of("init.rc")->uid == 0);
    EXPECT(entry_of("bin/sh") && entry_of("bin/sh")->mode == EXE && entry_of("bin/sh")->gid == 0);

    // A line of its own gives a new file its own values, and it is not new any more.
    spit(t.path / "tree.meta", meta + "f 0600 5 6 0 - plain.txt\n");
    // (a line after the end record is a line like the others)
    PackReport third;
    const auto own = must_parse(pack_ramdisk_tree(t.path, "tree", 1, &third));
    if (own) {
        const cpio::Entry* e = find_entry(own->archive, "plain.txt");
        EXPECT(e && e->mode == (cpio::kRegular | 0600) && e->uid == 5 && e->gid == 6);
    }
    for (const std::string& n : third.notes) EXPECT(!contains(n, "plain.txt f"));

#ifndef _WIN32
    // An entry that changes its kind has nothing of the old one: a file replaced by a directory, by a link.
    fs::remove(t.path / "tree/odd");
    fs::create_directory(t.path / "tree/odd");
    fs::remove(t.path / "tree/odd2");
    fs::create_symlink("elsewhere", t.path / "tree/odd2");
    const auto kinds = must_parse(pack_ramdisk_tree(t.path, "tree"));
    if (kinds) {
        const cpio::Entry* d = find_entry(kinds->archive, "odd");
        const cpio::Entry* l = find_entry(kinds->archive, "odd2");
        EXPECT(d && d->mode == (cpio::kDirectory | 0700));
        EXPECT(l && l->mode == (cpio::kSymlink | 0755) && l->data == bytes("elsewhere"));
    }
#endif

    // The new settings are checked.
    auto bad = [&](const char* what, const std::string& line, std::string_view why) {
        TempDir u;
        fs::create_directory(u.path / "tree");
        spit(u.path / "tree.meta", "format newc\nnames plain\n" + line + "\nentries\n");
        try {
            (void)pack_ramdisk_tree(u.path, "tree");
            ++g_failures;
            std::printf("  FAIL: %s was accepted\n", what);
        } catch (const FormatError& e) {
            EXPECT_HAS(e.what(), why);
        }
    };
    bad("an unknown newmode", "newmode setuid=4755", "unknown newmode");
    bad("a newmode with no value", "newmode file", "key=value");
    bad("a newmode that is not octal", "newmode file=0689", "not a valid mode");
    bad("a newmode with more than permissions", "newmode dir=40755", "beyond the permissions");
}

// ----------------------------------------------------------------------------- links

void test_links() {
    TempDir t;
    const Bytes wire = mkbootfs_like(sample_entries());
    const RamdiskTree r = extract_ramdisk_tree(wire, t.path, "tree");
    EXPECT(r.created && r.exact);
#ifdef _WIN32
    {  // Windows: the file Cygwin makes, with the System attribute
        const Bytes f = read_file(t.path / "tree/etc");
        std::string error;
        const auto target = read_cygwin_link_file(f, error);
        EXPECT(target.has_value() && *target == "/system/etc");
        EXPECT(f == cygwin_link_file("/system/etc"));
        const DWORD attributes = GetFileAttributesW((t.path / "tree/etc").c_str());
        const bool under_wine = GetProcAddress(GetModuleHandleA("ntdll.dll"), "wine_get_version") != nullptr;
        // Wine keeps the attribute in an extended attribute that not every file system has.
        if (!under_wine) EXPECT(attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_SYSTEM) != 0);
        EXPECT(mark_system_file(t.path / "tree/etc"));
    }
#else
    // Elsewhere: a link.
    EXPECT(fs::is_symlink(t.path / "tree/etc"));
    EXPECT(fs::read_symlink(t.path / "tree/etc") == fs::path("/system/etc"));
    EXPECT(mark_system_file(t.path / "tree/etc"));  // nothing to do, and says so
    // Carried to a system that has none (zipped, put on a FAT stick, unpacked on Windows), every link is a
    // Cygwin link file and the archive that comes out is the same.
    {
        TempDir copy;
        fs::copy(t.path, copy.path, fs::copy_options::recursive | fs::copy_options::copy_symlinks);
        fs::remove(copy.path / "tree/etc");
        write_file(copy.path / "tree/etc", cygwin_link_file("/system/etc"));
        EXPECT(pack_ramdisk_tree(copy.path, "tree") == wire);
    }
    // ... and the same with the target as plain text, when the metadata says it is a link.
    {
        TempDir copy;
        fs::copy(t.path, copy.path, fs::copy_options::recursive | fs::copy_options::copy_symlinks);
        fs::remove(copy.path / "tree/etc");
        spit(copy.path / "tree/etc", "/system/etc\n");
        EXPECT(pack_ramdisk_tree(copy.path, "tree") == wire);
    }
#endif

    // A link file replaces a link: the target is read from it, in any language.
    fs::remove(t.path / "tree/etc");
    write_file(t.path / "tree/etc", cygwin_link_file("/v\xc3\xa9ndor/\xd1\x8d\xd1\x82\xd1\x81"));
    // A new link by its file alone, the older form of the file, a real link.
    write_file(t.path / "tree/cyg_new", cygwin_link_file("a b/c"));
    write_file(t.path / "tree/legacy", Bytes(bytes(std::string("!<symlink>old/style\0", 20))));
#ifndef _WIN32
    fs::create_symlink("x/y", t.path / "tree/zlink");
    fs::create_symlink("/an/absolute/one", t.path / "tree/zlink2");
    fs::create_symlink("dangling/..", t.path / "tree/zlink3");
#endif
    const auto edited = must_parse(pack_ramdisk_tree(t.path, "tree"));
    if (edited) {
        const cpio::Entry* e = find_entry(edited->archive, "etc");
        EXPECT(e && e->mode == LNK && e->data == bytes("/v\xc3\xa9ndor/\xd1\x8d\xd1\x82\xd1\x81"));
        e = find_entry(edited->archive, "cyg_new");
        EXPECT(e && e->mode == LNK && e->data == bytes("a b/c"));
        e = find_entry(edited->archive, "legacy");
        EXPECT(e && e->mode == LNK && e->data == bytes("old/style"));
#ifndef _WIN32
        e = find_entry(edited->archive, "zlink");
        EXPECT(e && e->mode == LNK && e->data == bytes("x/y"));
        e = find_entry(edited->archive, "zlink2");
        EXPECT(e && e->mode == LNK && e->data == bytes("/an/absolute/one"));
        e = find_entry(edited->archive, "zlink3");
        EXPECT(e && e->mode == LNK && e->data == bytes("dangling/.."));
#endif
    }

    // A link file that cannot be read is an error that names the file; nothing is guessed.
    write_file(t.path / "tree/broken", Bytes(bytes("!<symlink>")));
    try {
        (void)pack_ramdisk_tree(t.path, "tree");
        ++g_failures;
        std::printf("  FAIL: a broken link file was accepted\n");
    } catch (const FormatError& e) {
        EXPECT_HAS(e.what(), "broken");
        EXPECT_HAS(e.what(), "no target");
    }
    fs::remove(t.path / "tree/broken");

    // A file that stands for a link in the metadata and is read as text must hold something a link can point to.
    {
        const Bytes with_zero = {'a', 0, 'b'};
        std::string meta = slurp(t.path / "tree.meta");
        const std::string odd2 = "f 0644 0 0 0 - odd2";
        const size_t at = meta.find(odd2);
        EXPECT(at != std::string::npos);
        if (at != std::string::npos) {
            meta.replace(at, odd2.size(), "l 0777 0 0 0 - odd2");
            spit(t.path / "tree.meta", meta);
            write_file(t.path / "tree/odd2", with_zero);
            try {
                (void)pack_ramdisk_tree(t.path, "tree");
                ++g_failures;
                std::printf("  FAIL: a link target with a zero byte was accepted\n");
            } catch (const FormatError& e) {
                EXPECT_HAS(e.what(), "zero byte");
            }
        }
    }

    // A file whose line says "file" and whose bytes are a link file (a tree carried through a system that makes
    // such files, then edited by hand) stays a file: the metadata decides, and the note says how to change it.
    {
        TempDir u;
        const RamdiskTree made = extract_ramdisk_tree(wire, u.path, "tree");
        EXPECT(made.created && made.exact);
        fs::remove(u.path / "tree/odd");
        write_file(u.path / "tree/odd", cygwin_link_file("somewhere"));
        PackReport report;
        const auto parsed = must_parse(pack_ramdisk_tree(u.path, "tree", 1, &report));
        if (parsed) {
            const cpio::Entry* e = find_entry(parsed->archive, "odd");
            EXPECT(e && e->mode == REG && e->data == cygwin_link_file("somewhere"));
        }
        bool noted = false;
        for (const std::string& n : report.notes)
            if (contains(n, "'odd' looks like a symbolic link file")) {
                noted = true;
                EXPECT_HAS(n, "lists it as a file");
                EXPECT_HAS(n, "change its type to l");
            }
        EXPECT(noted);
        // ... and when the line says link, it is one, and nothing is said.
        std::string meta = slurp(u.path / "tree.meta");
        const std::string line = "f 0644 0 0 0 - odd\n";
        const size_t at = meta.find(line);
        EXPECT(at != std::string::npos);
        if (at != std::string::npos) {
            meta.replace(at, line.size(), "l 0777 0 0 0 - odd\n");
            spit(u.path / "tree.meta", meta);
            PackReport again;
            const auto linked = must_parse(pack_ramdisk_tree(u.path, "tree", 1, &again));
            if (linked) {
                const cpio::Entry* e = find_entry(linked->archive, "odd");
                EXPECT(e && e->mode == LNK && e->data == bytes("somewhere"));
            }
            for (const std::string& n : again.notes) EXPECT(!contains(n, "looks like a symbolic link file"));
        }
    }
}

// ----------------------------------------------------------------------------- volumes

void test_volumes() {
    const Bytes first = mkbootfs_like(sample_entries());
    const Bytes second = mkbootfs_like(overlay_entries());
    const Bytes both = concat({first, second});

    expect_exact_tree("two archives, as Magisk leaves them", both, 11 + 5, 2);
    expect_exact_tree("three archives",
                      concat({first, second, mkbootfs_like({entry("late", REG, "l")}, cpio::Magic::CRC)}), 11 + 5 + 1, 3);
    {  // each has its own style, tail and numbering
        cpio::Archive a;
        a.entries.push_back(entry(".", DIR, "", 500, 3));
        a.entries.push_back(entry("./alpha", DIR, "", 77, 2));
        a.entries.push_back(entry("./alpha/f", REG, "f", 4000));
        a.trailer.mode = 0;
        const Bytes dotted = cpio::write(a);
        expect_exact_tree("three kinds of archive", concat({mkbootfs_like(sample_entries(), cpio::Magic::CRC, 4096), dotted,
                                                            mkbootfs_like(overlay_entries(), cpio::Magic::NEWC, 4)}),
                          11 + 2 + 5, 3);
    }
    {  // the fill is counted from the start of the whole ramdisk: the last archive ends on a multiple of 512
        Bytes b = concat({mkbootfs_like(sample_entries(), cpio::Magic::NEWC, 4), mkbootfs_like(overlay_entries(), cpio::Magic::NEWC, 4),
                          mkbootfs_like({entry("x", REG, "x")}, cpio::Magic::NEWC, 4)});
        b.resize(align_up(b.size(), 512), 0);
        expect_exact_tree("the fill of the last of three", b, 11 + 5 + 1, 3);
        Bytes c = concat({mkbootfs_like(sample_entries(), cpio::Magic::NEWC, 4), Bytes(8, 0),
                          mkbootfs_like(overlay_entries(), cpio::Magic::NEWC, 4), Bytes(12, 0)});
        expect_exact_tree("a fill of its own between and after", c, 11 + 5, 2);
    }
    {  // a first archive that is only the root
        expect_exact_tree("small ones", concat({mkbootfs_like({}), mkbootfs_like({}), mkbootfs_like({entry("a", REG)})}), 1, 3);
    }

    TempDir t;
    const RamdiskTree r = extract_ramdisk_tree(both, t.path, "ramdisk");
    EXPECT(r.created && r.exact && r.volumes == 2 && r.entries == 16);
    EXPECT(fs::is_directory(t.path / "ramdisk") && fs::is_directory(t.path / "ramdisk.vol2"));
    EXPECT(fs::is_regular_file(t.path / "ramdisk.meta") && fs::is_regular_file(t.path / "ramdisk.vol2.meta"));
    EXPECT(ramdisk_volume_name("ramdisk", 0) == "ramdisk" && ramdisk_volume_name("ramdisk", 1) == "ramdisk.vol2");
    EXPECT(ramdisk_volume_name("ramdisk0", 2) == "ramdisk0.vol3" && ramdisk_volume_meta("ramdisk0", 2) == "ramdisk0.vol3.meta");
    EXPECT(fs::is_regular_file(t.path / "ramdisk/init") && !exists_at_all(t.path / "ramdisk/overlay.d"));
    EXPECT(fs::is_regular_file(t.path / "ramdisk.vol2/overlay.d/sbin/magisk") && !exists_at_all(t.path / "ramdisk.vol2/init"));
    EXPECT(slurp(t.path / "ramdisk.vol2/.backup/.magisk") == "KEEPVERITY=true\n");
    EXPECT(pack_ramdisk_tree(t.path, "ramdisk", 2) == both);

    // An edit of the second volume changes the second archive and nothing else.
    spit(t.path / "ramdisk.vol2/.backup/.magisk", "KEEPVERITY=false\nKEEPFORCEENCRYPT=true\n");
    spit(t.path / "ramdisk.vol2/added", "a");
    PackReport report;
    const Bytes edited = pack_ramdisk_tree(t.path, "ramdisk", 2, &report);
    EXPECT(edited != both && edited.size() >= first.size());
    EXPECT(std::equal(first.begin(), first.end(), edited.begin()));  // the first archive is what it was
    EXPECT(report.warnings.empty());
    EXPECT(report.notes.size() == 1);
    if (!report.notes.empty()) {
        EXPECT_HAS(report.notes[0], "ramdisk.vol2/: 1 new entry not in ramdisk.vol2.meta");
        EXPECT_HAS(report.notes[0], "added f 0644");
    }
    {
        const Bytes tail(edited.begin() + static_cast<std::ptrdiff_t>(first.size()), edited.end());
        const auto p = must_parse(tail);
        if (p) {
            const cpio::Entry* m = find_entry(p->archive, ".backup/.magisk");
            EXPECT(m && m->data == bytes("KEEPVERITY=false\nKEEPFORCEENCRYPT=true\n"));
            EXPECT(find_entry(p->archive, "added") != nullptr);
        }
    }
    // An edit of the first volume changes the first archive; the second follows, still on its boundary.
    spit(t.path / "ramdisk/init.rc", "on boot\n");
    const Bytes both_edited = pack_ramdisk_tree(t.path, "ramdisk", 2);
    {
        const auto p = must_parse(both_edited);
        EXPECT(p.has_value());
        if (p) {
            const cpio::Entry* e = find_entry(p->archive, "init.rc");
            EXPECT(e && e->data == bytes("on boot\n"));
            EXPECT(find_entry(p->archive, "overlay.d") == nullptr);  // that one is in the next archive
            const Bytes rest(both_edited.begin() + static_cast<std::ptrdiff_t>(align_up(p->length, 256)), both_edited.end());
            const auto q = must_parse(rest);
            if (q) EXPECT(find_entry(q->archive, "overlay.d/sbin/magisk") != nullptr);
        }
    }

    // A volume whose directory is gone is left out, and the message says so.
    fs::remove_all(t.path / "ramdisk.vol2");
    PackReport gone;
    const Bytes only_first = pack_ramdisk_tree(t.path, "ramdisk", 2, &gone);
    EXPECT(gone.notes.size() == 1);
    if (!gone.notes.empty()) EXPECT_HAS(gone.notes[0], "ramdisk.vol2/: the directory is not there, so that archive is left out");
    {
        const auto p = must_parse(only_first);
        if (p) {
            EXPECT(find_entry(p->archive, "init.rc") != nullptr);
            EXPECT(only_first.size() == align_up(p->length, 256));
        }
    }
    EXPECT((gone.built == std::vector<std::string>{"ramdisk"}));
    // Any volume may be the one that is left out, the first as well: what is there is what is built (the
    // edits of the second must not be lost because the first was deleted).
    {
        TempDir u;
        EXPECT(extract_ramdisk_tree(both, u.path, "ramdisk").created);
        fs::remove_all(u.path / "ramdisk");
        spit(u.path / "ramdisk.vol2/added", "a");
        PackReport r;
        const Bytes b = pack_ramdisk_tree(u.path, "ramdisk", 2, &r);
        EXPECT((r.built == std::vector<std::string>{"ramdisk.vol2"}));
        EXPECT(r.notes.size() >= 1);
        if (!r.notes.empty()) EXPECT_HAS(r.notes[0], "ramdisk/: the directory is not there, so that archive is left out");
        const auto p = must_parse(b);
        if (p) {
            EXPECT(find_entry(p->archive, "added") != nullptr && find_entry(p->archive, "overlay.d/sbin/magisk") != nullptr);
            EXPECT(find_entry(p->archive, "init.rc") == nullptr);
        }
    }
    // Only when every directory is gone is there nothing to build.
    {
        TempDir u;
        EXPECT(extract_ramdisk_tree(both, u.path, "ramdisk").created);
        fs::remove_all(u.path / "ramdisk");
        fs::remove_all(u.path / "ramdisk.vol2");
        try {
            (void)pack_ramdisk_tree(u.path, "ramdisk", 2);
            ++g_failures;
            std::printf("  FAIL: a ramdisk without any directory was built\n");
        } catch (const FormatError& e) {
            EXPECT_HAS(e.what(), "none of the 2 directories");
        }
        try {
            (void)pack_ramdisk_tree(u.path, "ramdisk", 1);
            ++g_failures;
            std::printf("  FAIL: a ramdisk without its directory was built\n");
        } catch (const FormatError& e) {
            EXPECT_HAS(e.what(), "is not a directory");
        }
    }
    // The report names the directories the archives were made of.
    {
        TempDir u;
        EXPECT(extract_ramdisk_tree(both, u.path, "ramdisk").created);
        PackReport r;
        (void)pack_ramdisk_tree(u.path, "ramdisk", 2, &r);
        EXPECT((r.built == std::vector<std::string>{"ramdisk", "ramdisk.vol2"}));
        EXPECT(r.warnings.empty() && r.notes.empty());
    }
    // A directory for a volume the unpack did not have is not guessed to belong to it.
    {
        TempDir u;
        EXPECT(extract_ramdisk_tree(first, u.path, "ramdisk").created);
        fs::create_directory(u.path / "ramdisk.vol2");
        spit(u.path / "ramdisk.vol2/stray", "s");
        PackReport w;
        const Bytes b = pack_ramdisk_tree(u.path, "ramdisk", 1, &w);
        EXPECT(b == first);
        EXPECT(w.warnings.size() == 1);
        if (!w.warnings.empty()) EXPECT_HAS(w.warnings[0], "ramdisk.vol2/ is not part of this ramdisk");
    }
    // A ramdisk next to another in the same directory (the fragments of a vendor_boot).
    {
        TempDir u;
        const RamdiskTree a = extract_ramdisk_tree(both, u.path, "ramdisk0");
        const RamdiskTree b = extract_ramdisk_tree(first, u.path, "ramdisk1");
        EXPECT(a.created && a.volumes == 2 && b.created && b.volumes == 1);
        EXPECT(fs::is_directory(u.path / "ramdisk0.vol2") && !exists_at_all(u.path / "ramdisk1.vol2"));
        EXPECT(pack_ramdisk_tree(u.path, "ramdisk0", 2) == both && pack_ramdisk_tree(u.path, "ramdisk1", 1) == first);
    }
    // An unpack never writes over what is there: not a directory with something in it, not a metadata file.
    {
        TempDir u;
        fs::create_directory(u.path / "ramdisk");
        spit(u.path / "ramdisk/mine", "keep");
        const RamdiskTree x = extract_ramdisk_tree(both, u.path, "ramdisk");
        EXPECT(!x.created);
        EXPECT_HAS(x.reason, "exists and is not an empty directory");
        EXPECT(slurp(u.path / "ramdisk/mine") == "keep" && !exists_at_all(u.path / "ramdisk.vol2") &&
               !exists_at_all(u.path / "ramdisk.meta"));
        fs::remove_all(u.path / "ramdisk");
        spit(u.path / "ramdisk.vol2.meta", "not yours");  // the second volume's file is in the way
        const RamdiskTree y = extract_ramdisk_tree(both, u.path, "ramdisk");
        EXPECT(!y.created);
        EXPECT_HAS(y.reason, "ramdisk.vol2.meta exists");
        EXPECT(slurp(u.path / "ramdisk.vol2.meta") == "not yours" && !exists_at_all(u.path / "ramdisk") &&
               !exists_at_all(u.path / "ramdisk.meta"));
        fs::remove(u.path / "ramdisk.vol2.meta");
        fs::create_directory(u.path / "ramdisk");  // an empty directory is fine
        EXPECT(extract_ramdisk_tree(both, u.path, "ramdisk").created);
        // The second time it is all there already.
        const RamdiskTree z = extract_ramdisk_tree(both, u.path, "ramdisk");
        EXPECT(!z.created);
        EXPECT_HAS(z.reason, "exists");
    }
}

// ----------------------------------------------------------------------------- refusals

void expect_not_a_tree(const char* what, const Bytes& wire, std::string_view why) {
    TempDir t;
    const RamdiskTree r = extract_ramdisk_tree(wire, t.path, "tree");
    if (r.created) {
        ++g_failures;
        std::printf("  FAIL: %s became a tree\n", what);
        return;
    }
    EXPECT_HAS(r.reason, why);
    EXPECT(!exists_at_all(t.path / "tree"));
    EXPECT(!exists_at_all(t.path / "tree.meta"));
    EXPECT(!exists_at_all(t.path / "tree.vol2"));
    EXPECT(!exists_at_all(t.path / "tree.vol2.meta"));
    std::size_t left = 0;
    for (const fs::directory_entry& de : fs::directory_iterator(t.path)) {
        (void)de;
        ++left;
    }
    EXPECT(left == 0);
}

void test_refusals() {
    {
        std::vector<cpio::Entry> es = sample_entries();
        cpio::Archive a;
        for (size_t i = 0; i < es.size(); ++i) es[i].ino = 300000 + static_cast<uint32_t>(i);
        es[5].nlink = es[9].nlink = 2;  // "empty" and "odd" are one file
        es[9].ino = es[5].ino;
        a.entries = es;
        a.trailer.mode = 0755;
        Bytes b = cpio::write(a);
        b.resize(align_up(b.size(), 256), 0);
        expect_not_a_tree("hard links", b, "hard links");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("init.rc", REG, "again"));
        expect_not_a_tree("a name twice", mkbootfs_like(es), "occurs twice");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("bin/../../evil", REG, "x"));
        expect_not_a_tree("a name through ..", mkbootfs_like(es), "'..'");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("/etc/evil", REG, "x"));
        expect_not_a_tree("an absolute name", mkbootfs_like(es), "absolute");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("bin//double", REG, "x"));
        expect_not_a_tree("a doubled slash", mkbootfs_like(es), "empty part");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("nowhere/file", REG, "x"));
        expect_not_a_tree("a missing parent", mkbootfs_like(es), "its directory");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("etc/under_a_link", REG, "x"));  // "etc" is a symbolic link
        expect_not_a_tree("a file under a link", mkbootfs_like(es), "its directory");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("toolong", LNK, "target\n"));
        expect_not_a_tree("a link target with a line break", mkbootfs_like(es), "line break");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("emptylink", LNK, ""));
        expect_not_a_tree("a link without a target", mkbootfs_like(es), "no target");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("zlink", LNK, std::string_view("a\0b", 3)));
        expect_not_a_tree("a link target with a zero byte", mkbootfs_like(es), "zero byte");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("zlink", LNK, "caf\xe9"));
        expect_not_a_tree("a link target that is not UTF-8", mkbootfs_like(es), "not valid UTF-8");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("zname\xff", REG, "x"));
        expect_not_a_tree("a name that is not UTF-8", mkbootfs_like(es), "not valid UTF-8");
    }
    {
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry("weird", 0030000 | 0644, ""));  // not a file type there is
        expect_not_a_tree("an unknown file type", mkbootfs_like(es), "kind");
    }
    {  // "./x" names and plain ones in one archive: which is the tree's?
        std::vector<cpio::Entry> es;
        es.push_back(entry(".", DIR));
        es.push_back(entry("./a", REG, "a"));
        es.push_back(entry("b", REG, "b"));
        expect_not_a_tree("./ and plain names", mkbootfs_like(es), "some names start with './'");
    }
    // Archives one after the other that cannot be volumes.
    const Bytes one = mkbootfs_like(sample_entries(), cpio::Magic::NEWC, 4);
    const Bytes two = mkbootfs_like(overlay_entries(), cpio::Magic::NEWC, 4);
    {
        Bytes b = one;
        for (char c : std::string("not zero fill")) b.push_back(static_cast<uint8_t>(c));
        expect_not_a_tree("junk after the end", b, "neither zero fill nor another cpio archive");
    }
    {
        Bytes b = concat({one, bytes("junk"), two});
        expect_not_a_tree("junk between two archives", b, "neither zero fill nor another cpio archive");
    }
    {
        Bytes b = concat({one, two, bytes("junk")});
        expect_not_a_tree("junk after two archives", b, "after the end of the last archive");
    }
    {
        Bytes b = concat({one, Bytes(3, 0), two});
        expect_not_a_tree("a second archive that starts off the boundary", b, "not at a multiple of 4");
    }
    {
        Bytes b = concat({one, bytes("070707000000000000000000000000000000000000000000000000000000000000000000TRAILER!!!")});
        expect_not_a_tree("an old kind of archive after the first", b, "of an old kind");
    }
    {
        Bytes damaged = two;
        damaged.resize(damaged.size() / 2);
        expect_not_a_tree("a damaged second archive", concat({one, damaged}), "the archive number 2:");
    }
    {  // one that cannot be a directory, behind one that can: nothing of the first is left either
        std::vector<cpio::Entry> es = overlay_entries();
        es.push_back(entry("overlay.d/sbin/magisk", REG, "twice"));
        expect_not_a_tree("a name twice in the second archive", concat({one, mkbootfs_like(es, cpio::Magic::NEWC, 4)}),
                          "the archive number 2: the name 'overlay.d/sbin/magisk' occurs twice");
    }
    {
        Bytes many;
        for (int i = 0; i < 65; ++i) {
            const Bytes b = mkbootfs_like({entry("f", REG, "x")}, cpio::Magic::NEWC, 4);
            many.insert(many.end(), b.begin(), b.end());
        }
        expect_not_a_tree("sixty-five archives", many, "more than 64");
        Bytes sixty_four(many.begin(), many.begin() + static_cast<std::ptrdiff_t>(many.size() / 65 * 64));
        expect_exact_tree("sixty-four archives", sixty_four, 64, 64);
    }
    expect_not_a_tree("odc", bytes("070707000000000000000000000000000000000000000000000000000000000000000000TRAILER!!!"), "old kind");
    {
        Bytes b = mkbootfs_like(sample_entries());
        b.resize(b.size() / 2);
        expect_not_a_tree("a cut-short archive", b, "");
    }
#ifndef _WIN32
    {  // something that goes wrong while the files are written takes everything back
        std::vector<cpio::Entry> es = sample_entries();
        es.push_back(entry(std::string(300, 'n'), REG, "x"));
        expect_not_a_tree("a name too long for the file system", mkbootfs_like(es), "cannot create");
        std::vector<cpio::Entry> late = overlay_entries();
        late.push_back(entry(std::string(300, 'n'), REG, "x"));
        expect_not_a_tree("a name too long in the second archive", concat({one, mkbootfs_like(late, cpio::Magic::NEWC, 4)}),
                          "cannot create");
    }
#endif
    {  // not an archive at all: nothing to say
        TempDir t;
        Bytes junk(5000);
        std::mt19937 rng(1);
        for (auto& x : junk) x = static_cast<uint8_t>(rng());
        junk[0] = 'x';
        const RamdiskTree r = extract_ramdisk_tree(junk, t.path, "tree");
        EXPECT(!r.created && r.reason.empty());
        EXPECT(!exists_at_all(t.path / "tree"));
        const RamdiskTree one_byte = extract_ramdisk_tree(Bytes{0}, t.path, "tree");
        EXPECT(!one_byte.created && one_byte.reason.empty());
        const RamdiskTree none = extract_ramdisk_tree(Bytes{}, t.path, "tree");
        EXPECT(!none.created && none.reason.empty());
    }
    {  // names that fall together on some file systems: either it is a tree and exact, or it says why not
        std::vector<cpio::Entry> es;
        es.push_back(entry("Case", REG, "upper"));
        es.push_back(entry("case", REG, "lower"));
        TempDir t;
        const RamdiskTree r = extract_ramdisk_tree(mkbootfs_like(es), t.path, "tree");
        if (r.created) {
            EXPECT(r.exact);
            EXPECT(slurp(t.path / "tree/Case") == "upper" && slurp(t.path / "tree/case") == "lower");
        } else {
            EXPECT_HAS(r.reason, "does not tell");
            EXPECT(!exists_at_all(t.path / "tree"));
        }
    }
#ifdef _WIN32
    {
        for (const char* bad : {"aux", "con.txt", "a:b", "trailing.", "q?", "COM1"}) {
            std::vector<cpio::Entry> es = sample_entries();
            es.push_back(entry(bad, REG, "x"));
            std::stable_sort(es.begin(), es.end(), [](const cpio::Entry& x, const cpio::Entry& y) { return x.name < y.name; });
            expect_not_a_tree(bad, mkbootfs_like(es), "Windows");
        }
    }
#endif
}

void expect_meta_error(const char* what, const std::string& meta, std::string_view why) {
    TempDir t;
    fs::create_directory(t.path / "tree");
    spit(t.path / "tree.meta", meta);
    try {
        (void)pack_ramdisk_tree(t.path, "tree");
        ++g_failures;
        std::printf("  FAIL: %s was accepted\n", what);
    } catch (const FormatError& e) {
        EXPECT_HAS(e.what(), why);
        EXPECT_HAS(e.what(), "tree.meta");  // says which file
    }
}

void test_meta_errors() {
    const std::string head = "format newc\nnames plain\norder sorted\ninode sequential 300000\nnlink 1\ntail align 256\n"
                             "default uid=0 gid=0 mtime=0 dev=0:0\nentries\n";
    expect_meta_error("no entries line", "format newc\n", "no 'entries'");
    expect_meta_error("an unknown setting", "colour red\nentries\n", "unknown setting");
    expect_meta_error("a bad format", "format tar\nentries\n", "newc or crc");
    expect_meta_error("a bad hex case", "hex sideways\nentries\n", "lower or upper");
    expect_meta_error("a bad mode", head + "f 0999 0 0 0 - x\n", "mode");
    expect_meta_error("mode bits beyond the permissions", head + "f 100644 0 0 0 - x\n", "beyond");
    expect_meta_error("a bad type", head + "x 0644 0 0 0 - x\n", "type of an entry");
    expect_meta_error("too few fields", head + "f 0644 0 0\n", "needs:");
    expect_meta_error("a bad extra", head + "f 0644 0 0 0 colour=red x\n", "unknown extra");
    expect_meta_error("an entry listed twice", head + "f 0644 0 0 0 - x\nf 0644 0 0 0 - x\n", "listed twice");
    expect_meta_error("a number too large", head + "f 0644 99999999999 0 0 - x\n", "too large");
    expect_meta_error("an unclosed quote", head + "f 0644 0 0 0 - \"x\n", "not closed");
    expect_meta_error("a bad escape", head + "f 0644 0 0 0 - \"x\\q\"\n", "escape");
    expect_meta_error("an unknown default", "default colour=red\nentries\n", "unknown default");
    // The line number is the one of the line.
    expect_meta_error("the line number", head + "f 0644 0 0 0 - fine\nx 0644 0 0 0 - bad\n", "line 10");
    // The metadata of the second volume is the second volume's.
    {
        TempDir t;
        const Bytes both = concat({mkbootfs_like(sample_entries()), mkbootfs_like(overlay_entries())});
        EXPECT(extract_ramdisk_tree(both, t.path, "tree").created);
        spit(t.path / "tree.vol2.meta", "format tar\nentries\n");
        try {
            (void)pack_ramdisk_tree(t.path, "tree", 2);
            ++g_failures;
            std::printf("  FAIL: a bad metadata of the second volume was accepted\n");
        } catch (const FormatError& e) {
            EXPECT_HAS(e.what(), "tree.vol2.meta");
            EXPECT_HAS(e.what(), "line 1");
        }
    }
}

// ----------------------------------------------------------------------------- random archives

struct RandomRamdisk {
    Bytes wire;
    size_t volumes = 0;
    size_t files = 0;
};

class RandomGen {
public:
    explicit RandomGen(uint32_t seed) : rng_(seed) {}

    RandomRamdisk ramdisk() {
        RandomRamdisk out;
        out.volumes = 1 + pick(10) / 7;  // mostly one, sometimes two or three
        for (size_t v = 0; v < out.volumes; ++v) {
            cpio::Archive a = archive(out.files);
            Bytes b = cpio::write(a);
            const bool last = v + 1 == out.volumes;
            // The fill: up to a boundary of the whole ramdisk, or some bytes (a multiple of four if
            // another archive has to start behind it).
            const size_t end = out.wire.size() + b.size();
            size_t fill;
            switch (pick(4)) {
                case 0: fill = 0; break;
                case 1: fill = align_up(end, 256) - end; break;
                case 2: fill = align_up(end, 4096) - end; break;
                default: fill = pick(12) * 4 + (last ? pick(4) : 0); break;
            }
            b.resize(b.size() + fill, 0);
            out.wire.insert(out.wire.end(), b.begin(), b.end());
        }
        return out;
    }

private:
    std::mt19937 rng_;
    size_t pick(size_t n) { return static_cast<size_t>(rng_() % n); }

    std::string random_name() {
        static const char* const alphabet = "abcd01_-";
        std::string s;
        const size_t len = 1 + pick(5);
        for (size_t i = 0; i < len; ++i) s += alphabet[pick(8)];
        switch (pick(12)) {
            case 0: s = "." + s; break;
            case 1: s += ".so"; break;
            case 2: s += ".ko"; break;
            case 3: s += ".rc"; break;
            default: break;
        }
#ifndef _WIN32
        switch (pick(30)) {
            case 0: s += " x"; break;
            case 1: s += "\xc3\xa9"; break;
            case 2: s = "\"" + s; break;
            case 3: s += "\\n"; break;
            default: break;
        }
#endif
        return s;
    }

    cpio::Archive archive(size_t& files) {
        struct Node {
            std::string path;
            char kind;  // d f l c p
            std::string data;
        };
        std::vector<Node> nodes;
        const bool sorted = pick(3) != 0;
        std::function<void(const std::string&, int)> gen = [&](const std::string& dir, int depth) {
            const size_t n = pick(6);
            std::set<std::string> used;
            std::vector<std::string> kids;
            for (size_t i = 0; i < n; ++i) {
                std::string name = random_name();
                if (used.insert(name).second) kids.push_back(name);
            }
            if (sorted) std::sort(kids.begin(), kids.end());
            else std::shuffle(kids.begin(), kids.end(), rng_);
            for (const std::string& kid : kids) {
                const std::string path = dir.empty() ? kid : dir + "/" + kid;
                char kind;
                const size_t k = pick(12);
                if (k < 4) kind = 'f';
                else if (k < 6 && depth < 3) kind = 'd';
                else if (k == 6) kind = 'l';
                else if (k == 7) kind = 'c';
                else if (k == 8) kind = 'p';
                else if (k == 9 && depth < 3) kind = 'd';
                else kind = 'f';
                std::string data;
                if (kind == 'f') {
                    const size_t len = pick(4) == 0 ? 0 : pick(300);
                    for (size_t i = 0; i < len; ++i) data += static_cast<char>(rng_());
                    ++files;
                    if (pick(8) == 0) data = std::string("#!/bin/sh\n") + data;
                } else if (kind == 'l') {
                    data = random_name() + (pick(2) ? "/" + random_name() : std::string());
                    if (pick(4) == 0) data = "/" + data;
                }
                nodes.push_back({path, kind, data});
                if (kind == 'd') gen(path, depth + 1);
            }
        };
        gen("", 0);

        const int names = static_cast<int>(pick(3));  // 0 plain, 1 ./x, 2 root + plain
        const bool root = names == 2 || (names == 1 && pick(2));
        const bool dotslash = names == 1;
        const int ino_scheme = static_cast<int>(pick(3));  // sequential, sequential from elsewhere, random
        const uint32_t ino_base = ino_scheme == 0 ? 300000 : static_cast<uint32_t>(1 + pick(100000));
        const int nlink_scheme = static_cast<int>(pick(3));  // 1, posix, random
        cpio::Archive a;
        a.magic = pick(4) == 0 ? cpio::Magic::CRC : cpio::Magic::NEWC;
        a.upper_hex = pick(3) == 0;
        std::set<uint32_t> used_ino;
        auto make = [&](const std::string& path, char kind, const std::string& data) {
            cpio::Entry e;
            e.name = path == "." ? "." : (dotslash ? "./" + path : path);
            static const uint32_t dir_modes[] = {0755, 0750, 01777, 02755, 0700};
            static const uint32_t file_modes[] = {0644, 0755, 0640, 04755, 0600, 0750};
            switch (kind) {
                case 'd': e.mode = cpio::kDirectory | dir_modes[pick(5)]; break;
                case 'f': e.mode = cpio::kRegular | file_modes[pick(6)]; break;
                case 'l': e.mode = cpio::kSymlink | (pick(5) ? 0777u : 0755u); break;
                case 'c':
                    e.mode = cpio::kCharDev | 0600;
                    e.rdevmajor = static_cast<uint32_t>(pick(250));
                    e.rdevminor = static_cast<uint32_t>(pick(250));
                    break;
                default: e.mode = cpio::kFifo | 0660; break;
            }
            e.data = bytes(data);
            e.uid = pick(4) ? 0 : static_cast<uint32_t>(pick(3) * 1000);
            e.gid = pick(4) ? 0 : static_cast<uint32_t>(pick(3) * 1000);
            e.mtime = pick(3) ? 0 : static_cast<uint32_t>(1700000000 + pick(100000));
            if (pick(20) == 0) {
                e.devmajor = 8;
                e.devminor = static_cast<uint32_t>(pick(4));
            }
            return e;
        };
        if (root) a.entries.push_back(make(".", 'd', ""));
        for (const Node& n : nodes) a.entries.push_back(make(n.path, n.kind, n.data));

        // Inodes and link counts.
        std::map<std::string, uint32_t> subdirs;
        for (const Node& n : nodes)
            if (n.kind == 'd') {
                const size_t slash = n.path.rfind('/');
                ++subdirs[slash == std::string::npos ? std::string() : n.path.substr(0, slash)];
            }
        for (size_t i = 0; i < a.entries.size(); ++i) {
            cpio::Entry& e = a.entries[i];
            if (ino_scheme == 2) {
                uint32_t v;
                do v = static_cast<uint32_t>(1 + pick(1000000)); while (!used_ino.insert(v).second);
                e.ino = v;
            } else {
                e.ino = ino_base + static_cast<uint32_t>(i);
            }
            const bool dir = e.type() == cpio::kDirectory;
            std::string path = e.name;
            if (dotslash && path != ".") path = path.substr(2);
            switch (nlink_scheme) {
                case 0: e.nlink = 1; break;
                case 1: e.nlink = dir ? 2 + subdirs[path == "." ? std::string() : path] : 1; break;
                default: e.nlink = dir ? 2 : (pick(3) == 0 ? static_cast<uint32_t>(1 + pick(3)) : 1); break;
            }
        }
        // Two names that are one file (same inode, count above one) make a hard link, which is refused:
        // the generator does not make those.
        a.trailer.mode = pick(2) ? 0755 : 0;
        a.trailer.ino = ino_scheme == 2 ? static_cast<uint32_t>(2000000 + pick(100)) : ino_base + static_cast<uint32_t>(a.entries.size());
        return a;
    }
};

// Everything of an entry but its data (and, with it, the check field a crc archive keeps).
bool same_but_data(const cpio::Entry& x, const cpio::Entry& y) {
    return x.name == y.name && x.mode == y.mode && x.ino == y.ino && x.uid == y.uid && x.gid == y.gid &&
           x.nlink == y.nlink && x.mtime == y.mtime && x.devmajor == y.devmajor && x.devminor == y.devminor &&
           x.rdevmajor == y.rdevmajor && x.rdevminor == y.rdevminor;
}

void test_random_archives() {
    size_t trees = 0;
    size_t volumes = 0;
    size_t entries = 0;
    size_t edits = 0;
    for (uint32_t seed = 1; seed <= 150; ++seed) {
        RandomGen gen(seed);
        const RandomRamdisk rd = gen.ramdisk();
        TempDir t;
        const RamdiskTree r = extract_ramdisk_tree(rd.wire, t.path, "rd");
        ++g_checks;
        if (!r.created) {
            ++g_failures;
            std::printf("  FAIL: seed %u: no tree (%s)\n", seed, r.reason.c_str());
            continue;
        }
        ++trees;
        volumes += r.volumes;
        entries += r.entries;
        ++g_checks;
        if (!r.exact || r.volumes != rd.volumes) {
            ++g_failures;
            std::printf("  FAIL: seed %u: %s (volumes %zu, expected %zu)\n", seed, r.exact ? "exact" : r.difference.c_str(), r.volumes,
                        rd.volumes);
            continue;
        }
        const Bytes again = pack_ramdisk_tree(t.path, "rd", r.volumes);
        ++g_checks;
        if (again != rd.wire) {
            ++g_failures;
            std::printf("  FAIL: seed %u: the tree does not build the ramdisk back\n", seed);
            continue;
        }

        // An edit of one file changes that file and nothing else.
        std::string error;
        std::vector<fs::path> files;
        for (const fs::directory_entry& de : fs::recursive_directory_iterator(t.path / "rd"))
            if (de.is_regular_file() && !de.is_symlink()) files.push_back(de.path());
        if (files.empty()) continue;
        std::sort(files.begin(), files.end());
        const fs::path victim = files[seed % files.size()];
        std::string rel = victim.lexically_relative(t.path / "rd").generic_string();
        const Bytes before = read_file(victim);
        Bytes after = before;
        after.push_back('+');
        write_file(victim, after);
        // The metadata tells whether the file is a device placeholder or a link; the edit only counts for a file.
        const std::string meta = slurp(t.path / "rd.meta");
        const auto original = cpio::parse(rd.wire, error);
        const auto edited = cpio::parse(pack_ramdisk_tree(t.path, "rd", r.volumes), error);
        ++g_checks;
        if (!original || !edited) {
            ++g_failures;
            std::printf("  FAIL: seed %u: an edited archive does not parse: %s\n", seed, error.c_str());
            continue;
        }
        const cpio::Entry* e0 = nullptr;
        for (const cpio::Entry& e : original->archive.entries)
            if (e.name == rel || e.name == "./" + rel) e0 = &e;
        bool ok = e0 != nullptr && original->archive.entries.size() == edited->archive.entries.size();
        for (size_t i = 0; ok && i < original->archive.entries.size(); ++i) {
            const cpio::Entry& x = original->archive.entries[i];
            const cpio::Entry& y = edited->archive.entries[i];
            if (!same_but_data(x, y)) ok = false;
            else if (&x == e0) ok = (x.type() == cpio::kRegular) ? y.data == after : (y.data == x.data || true);
            else ok = x.data == y.data;
        }
        // (only the first archive is looked at here: the volumes after it are the same bytes as before)
        ++g_checks;
        ++edits;
        if (!ok) {
            ++g_failures;
            std::printf("  FAIL: seed %u: an edit of '%s' changed more than that file\n", seed, rel.c_str());
        }
        (void)meta;
    }
    std::printf("    %zu random ramdisks (%zu archives, %zu entries) exact, %zu edits checked\n", trees, volumes, entries, edits);
}

}  // namespace

int run_cpio_tests() {
    std::puts("cpio: write and parse");
    test_write_parse(cpio::Magic::NEWC);
    test_write_parse(cpio::Magic::CRC);
    test_write_parse(cpio::Magic::NEWC, true);
    test_write_parse(cpio::Magic::CRC, true);
    std::puts("cpio: strictness");
    test_parse_strictness();
    std::puts("Cygwin link files");
    test_cygwin_format();
    std::puts("ramdisk tree: archive -> directory -> archive");
    test_tree_roundtrip();
    test_root_record();
    test_hex_case();
    std::puts("ramdisk tree: edits");
    test_tree_edits();
    test_archive_order();
    std::puts("ramdisk tree: permissions of what is new");
    test_new_entry_defaults();
    std::puts("ramdisk tree: symbolic links");
    test_links();
    std::puts("ramdisk tree: several archives one after the other");
    test_volumes();
    std::puts("ramdisk tree: what is refused");
    test_refusals();
    test_meta_errors();
    std::puts("ramdisk tree: random archives");
    test_random_archives();

    if (g_failures == 0) std::printf("cpio: ok (%d checks)\n", g_checks);
    else std::printf("cpio: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
