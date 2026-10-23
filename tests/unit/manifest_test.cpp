// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of manifest.txt (include/abr/manifest.hpp) and of the quoting it shares with ramdisk.meta
// (include/abr/textquote.hpp). Run by tests/run_tests.sh as `abr_unit_tests manifest`.
//
//   * a value comes back from save() and load() as the very bytes it was -- whatever they are: a command line with a
//     space at its end (real images have them), a line break (an image could use it to add keys to the manifest that
//     unpack writes), quotes, backslashes, control bytes, bytes that are not UTF-8 -- and what is written has no line
//     break and no control byte but the end of its line;
//   * a manifest that was written by hand, or by an earlier abr, reads as it always did (white space around the key
//     and the value, CRLF line ends, comments, lines without '=');
//   * a quoted value that is wrong is an error that says which line;
//   * the name of a file a manifest asks repack to open has to lie in the directory of the manifest.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/manifest.hpp"
#include "abr/textquote.hpp"

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

#define EXPECT_HAS(text, needle)                                                                        \
    do {                                                                                                \
        const std::string t_ = (text);                                                                  \
        ++g_checks;                                                                                     \
        if (!contains(t_, (needle))) {                                                                  \
            ++g_failures;                                                                               \
            std::printf("  FAIL %s:%d: \"%s\" does not say \"%s\"\n", __FILE__, __LINE__, t_.c_str(), \
                        std::string(needle).c_str());                                                   \
        }                                                                                               \
    } while (0)

std::string printable(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (c >= 0x20 && c < 0x7F) out += static_cast<char>(c);
        else {
            char buf[8];
            std::snprintf(buf, sizeof buf, "<%02x>", c);
            out += buf;
        }
    }
    return out;
}

struct TempDir {
    fs::path path;
    TempDir() {
        static unsigned counter = 0;
        path = fs::temp_directory_path() /
               ("abr_manifest_test_" + std::to_string(static_cast<unsigned long>(std::random_device{}())) + "_" +
                std::to_string(counter++));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

void write_text(const fs::path& p, const std::string& text) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << text;
}

std::string read_text(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// quote() then unquote(): the same bytes, and a line of the file that is one line
bool quoted_roundtrip(const std::string& s, bool quote_empty) {
    const std::string q = textquote::quote(s, quote_empty);
    for (unsigned char c : q)
        if (c < 0x20 || c == 0x7F) return false;
    std::string back, why;
    if (!textquote::unquote(q, back, why)) return false;
    return back == s;
}

void test_quote_basics() {
    std::puts("quoting: what stays as it is, and what is put in quotes");
    EXPECT(textquote::quote("console=ttyS0 androidboot.hardware=qcom", false) == "console=ttyS0 androidboot.hardware=qcom");
    EXPECT(textquote::quote("a  b", false) == "a  b");  // white space inside is no problem
    EXPECT(textquote::quote("a\"b", false) == "a\"b");  // nor is a quote that does not open the value
    EXPECT(textquote::quote("x=y#z", false) == "x=y#z");
    EXPECT(textquote::quote("\xc3\xbc\xd0\x94", false) == "\xc3\xbc\xd0\x94");  // UTF-8 stays readable
    EXPECT(textquote::quote("", false).empty());
    EXPECT(textquote::quote("", true) == "\"\"");
    EXPECT(textquote::quote("end ", false) == "\"end \"");
    EXPECT(textquote::quote(" start", false) == "\" start\"");
    EXPECT(textquote::quote("end\t", false) == "\"end\\t\"");
    EXPECT(textquote::quote("   ", false) == "\"   \"");
    EXPECT(textquote::quote("\"x", false) == "\"\\\"x\"");
    EXPECT(textquote::quote("a\\b", false) == "\"a\\\\b\"");
    EXPECT(textquote::quote("a\nb", false) == "\"a\\nb\"");
    EXPECT(textquote::quote("a\rb", false) == "\"a\\rb\"");
    EXPECT(textquote::quote(std::string("a\0b", 3), false) == "\"a\\x00b\"");
    EXPECT(textquote::quote("a\x7f", false) == "\"a\\x7f\"");
    EXPECT(textquote::quote("a\x1b[31m", false) == "\"a\\x1b[31m\"");  // an escape sequence is not passed to a terminal

    std::puts("quoting: reading");
    std::string out, why;
    EXPECT(textquote::unquote("plain value  ", out, why) && out == "plain value");  // white space at the end goes
    EXPECT(textquote::unquote("plain\r", out, why) && out == "plain");
    EXPECT(textquote::unquote("", out, why) && out.empty());
    EXPECT(textquote::unquote("\"\"", out, why) && out.empty());
    EXPECT(textquote::unquote("\"  in  \"", out, why) && out == "  in  ");
    EXPECT(textquote::unquote("\"a\\\\b\\\"c\\n\\t\\r\\x41\\xFF\"", out, why) && out == std::string("a\\b\"c\n\t\rA\xff"));
    EXPECT(textquote::unquote("\"closed\"   ", out, why) && out == "closed");  // white space after the closing quote is nothing
    EXPECT(textquote::unquote("\"closed\"\r", out, why) && out == "closed");
    EXPECT(textquote::unquote("a\"b", out, why) && out == "a\"b");  // a quote that is not the first character is nothing special

    std::puts("quoting: what is wrong with a quoted string");
    EXPECT(!textquote::unquote("\"open", out, why));
    EXPECT_HAS(why, "not closed");
    EXPECT(!textquote::unquote("\"ends\\", out, why));
    EXPECT_HAS(why, "backslash");
    EXPECT(!textquote::unquote("\"a\\qb\"", out, why));
    EXPECT_HAS(why, "unknown escape");
    EXPECT(!textquote::unquote("\"a\\x4\"", out, why));
    EXPECT_HAS(why, "two hexadecimal digits");
    EXPECT(!textquote::unquote("\"a\\x", out, why));
    EXPECT_HAS(why, "two hexadecimal digits");
    EXPECT(!textquote::unquote("\"a\\x4", out, why));  // (the end of the text comes after one digit)
    EXPECT_HAS(why, "two hexadecimal digits");
    EXPECT(!textquote::unquote("\"a\\xZZ\"", out, why));
    EXPECT_HAS(why, "two hexadecimal digits");
    EXPECT(!textquote::unquote("\"a\" b", out, why));
    EXPECT_HAS(why, "after the closing quote");
    EXPECT(!textquote::unquote("\"a\"\"b\"", out, why));
    EXPECT_HAS(why, "after the closing quote");
}

void test_quote_every_byte() {
    std::puts("quoting: every byte, alone and at the edges of a text");
    size_t cases = 0;
    for (int b = 0; b < 256; ++b) {
        const std::string c(1, static_cast<char>(b));
        for (const std::string& s : {c, "x" + c, c + "x", "x" + c + "x", " " + c, c + " ", c + c, "\"" + c, c + "\"", "\\" + c, c + "\\",
                                     "a=" + c, c + "\n", "\t" + c + "\t"}) {
            EXPECT(quoted_roundtrip(s, false));
            EXPECT(quoted_roundtrip(s, true));
            // what is plain is itself; what is not is in quotes
            const std::string q = textquote::quote(s, false);
            EXPECT(q == s || (q.size() >= 2 && q.front() == '"' && q.back() == '"'));
            ++cases;
        }
    }
    std::printf("    %zu texts exact\n", cases);
}

void test_quote_random() {
    std::puts("quoting: random texts");
    std::mt19937 rng(20261020);
    std::string special = "\"\\ \t\r\n=#'x\x7f\x80\xff";
    special += '\0';
    size_t n = 0;
    for (; n < 20000; ++n) {
        std::string s;
        const size_t len = rng() % 40;
        for (size_t i = 0; i < len; ++i) {
            switch (rng() % 4) {
                case 0: s += special[rng() % special.size()]; break;
                case 1: s += static_cast<char>(rng() & 0xFF); break;
                default: s += static_cast<char>('a' + rng() % 26); break;
            }
        }
        if (!quoted_roundtrip(s, false) || !quoted_roundtrip(s, true)) {
            ++g_failures;
            std::printf("  FAIL: \"%s\" does not come back from quote() and unquote()\n", printable(s).c_str());
            break;
        }
        ++g_checks;
    }
    std::printf("    %zu random texts exact\n", n);
}

// What a terminal gets of quote_shown(): decoded by a validator of its own (the code point worked out, the range of each length
// checked), not the one in textquote.cpp. No control character, no C1 control, nothing that is not UTF-8.
bool terminal_safe(const std::string& out, bool layout = false) {
    for (size_t i = 0; i < out.size();) {
        const unsigned char c = static_cast<unsigned char>(out[i]);
        if ((c < 0x20 && !(layout && (c == '\n' || c == '\t'))) || c == 0x7F) return false;
        if (c < 0x80) { ++i; continue; }
        size_t n = 0;
        uint32_t cp = 0;
        uint32_t least = 0;
        if ((c & 0xE0) == 0xC0) { n = 2; cp = c & 0x1F; least = 0x80; }
        else if ((c & 0xF0) == 0xE0) { n = 3; cp = c & 0x0F; least = 0x800; }
        else if ((c & 0xF8) == 0xF0) { n = 4; cp = c & 0x07; least = 0x10000; }
        else return false;
        if (i + n > out.size()) return false;
        for (size_t k = 1; k < n; ++k) {
            const unsigned char d = static_cast<unsigned char>(out[i + k]);
            if ((d & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (d & 0x3F);
        }
        if (cp < least || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) || (cp >= 0x80 && cp <= 0x9F)) return false;
        i += n;
    }
    return true;
}

bool shown_roundtrip(const std::string& s) {
    const std::string q = textquote::quote_shown(s);
    std::string back, why;
    return terminal_safe(q) && textquote::unquote(q, back, why) && back == s;
}

void test_quote_shown() {
    std::puts("quoting for a terminal: C1 controls and what is not UTF-8 are escaped, UTF-8 is not");
    EXPECT(textquote::quote_shown("console=ttyS0 androidboot.hardware=qcom") == "console=ttyS0 androidboot.hardware=qcom");
    EXPECT(textquote::quote_shown("") == "");
    EXPECT(textquote::quote_shown("\xc3\xbc\xd0\x94 \xe2\x82\xac \xf0\x9f\x98\x80") == "\xc3\xbc\xd0\x94 \xe2\x82\xac \xf0\x9f\x98\x80");
    EXPECT(textquote::quote_shown("a\xc2\xa0z") == "a\xc2\xa0z");  // U+00A0, the first character after the C1 controls
    EXPECT(textquote::quote_shown("\xc2\x9b") == "\"\\xc2\\x9b\"");  // U+009B: CSI
    EXPECT(textquote::quote_shown("a\xc2\x80z") == "\"a\\xc2\\x80z\"");
    EXPECT(textquote::quote_shown("\xc2\x9f") == "\"\\xc2\\x9f\"");
    EXPECT(textquote::quote_shown("\x9b" "2J") == "\"\\x9b" "2J\"");  // CSI as a single byte
    EXPECT(textquote::quote_shown("\xff") == "\"\\xff\"");
    EXPECT(textquote::quote_shown("\xc0\xaf") == "\"\\xc0\\xaf\"");                  // an overlong "/"
    EXPECT(textquote::quote_shown("\xed\xa0\x80") == "\"\\xed\\xa0\\x80\"");         // a surrogate
    EXPECT(textquote::quote_shown("\xf4\x90\x80\x80") == "\"\\xf4\\x90\\x80\\x80\"");  // above U+10FFFF
    EXPECT(textquote::quote_shown("\xf4\x8f\xbf\xbf") == "\xf4\x8f\xbf\xbf");              // U+10FFFF itself is a character
    EXPECT(textquote::quote_shown("\xf0\x90\x80\x80") == "\xf0\x90\x80\x80");              // U+10000, the first of four bytes
    EXPECT(textquote::quote_shown("\xf0\x80\x80\x80") == "\"\\xf0\\x80\\x80\\x80\"");  // an overlong form of U+0000
    EXPECT(textquote::quote_shown("\xf0\x8f\xbf\xbf") == "\"\\xf0\\x8f\\xbf\\xbf\"");  // an overlong form of U+FFFF
    EXPECT(textquote::quote_shown("\xf5\x80\x80\x80") == "\"\\xf5\\x80\\x80\\x80\"");  // a lead byte that UTF-8 does not have
    EXPECT(textquote::quote_shown("\xe0\x9f\xbf") == "\"\\xe0\\x9f\\xbf\"");              // an overlong form of U+07FF
    EXPECT(textquote::quote_shown("\xe0\xa0\x80") == "\xe0\xa0\x80");                        // U+0800
    EXPECT(textquote::quote_shown("\xed\x9f\xbf") == "\xed\x9f\xbf");                        // U+D7FF, the last before the surrogates
    EXPECT(textquote::quote_shown("\xee\x80\x80") == "\xee\x80\x80");                        // U+E000, the first after them
    EXPECT(textquote::quote_shown("a\xe2\x82") == "\"a\\xe2\\x82\"");                // cut off at the end
    EXPECT(textquote::quote_shown("a\xe2z") == "\"a\\xe2z\"");                       // cut off by an ASCII character
    EXPECT(textquote::quote_shown("\x80") == "\"\\x80\"");                           // a continuation byte alone
    EXPECT(textquote::quote_shown("a\x1b[31m") == "\"a\\x1b[31m\"");                 // what quote() does stays
    EXPECT(textquote::quote_shown("end ") == "\"end \"");
    EXPECT(textquote::quote_shown("a\nb") == "\"a\\nb\"");
    EXPECT(textquote::quote_shown("\xc3\xbc\n") == "\"\xc3\xbc\\n\"");  // UTF-8 inside quotes stays
    EXPECT(textquote::quote_shown("\xc3\xbc") == textquote::quote("\xc3\xbc", false));

    size_t cases = 0;
    for (int b = 0; b < 256; ++b) {
        const std::string c(1, static_cast<char>(b));
        for (const std::string& s : {c, "x" + c, c + "x", "x" + c + "x", " " + c, c + " ", c + c, "\"" + c, c + "\"", "\\" + c,
                                     "\xc2" + c, "\xe2\x82" + c, c + "\x82", "\xc3" + c + "\xbc"}) {
            EXPECT(shown_roundtrip(s));
            ++cases;
        }
    }
    // every sequence of three bytes from the bytes at the edges of the ranges of UTF-8
    const unsigned char edge[] = {0x00, 0x09, 0x0A, 0x1B, 0x20, 0x22, 0x41, 0x5C, 0x7E, 0x7F, 0x80, 0x8F, 0x90, 0x9B, 0x9F, 0xA0,
                                  0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1, 0xEC, 0xED, 0xEF, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xFF};
    for (unsigned char x : edge)
        for (unsigned char y : edge)
            for (unsigned char z : edge) {
                const std::string s{static_cast<char>(x), static_cast<char>(y), static_cast<char>(z)};
                EXPECT(shown_roundtrip(s));
                // a text that is well-formed UTF-8 with no C1 control or control character, and that quote() leaves as it is, stays as it is
                if (terminal_safe(s) && textquote::quote(s, false) == s) EXPECT(textquote::quote_shown(s) == s);
                ++cases;
            }
    std::mt19937 rng(20261021);
    const std::vector<std::string> pieces = {"a", "Z", " ", "=", "\"", "\\", "\n", "\x1b", "\x07", "\x7f", "\xc2\x9b", "\xc2\xa0", "\xc3\xbc",
                                             "\xe2\x82\xac", "\xf0\x9f\x98\x80", "\xff", "\x9b", "\xc0", "\xed\xa0", "\xe2\x82", "\x80"};
    for (size_t n = 0; n < 20000; ++n) {
        std::string s;
        const size_t len = rng() % 12;
        for (size_t i = 0; i < len; ++i) s += pieces[rng() % pieces.size()];
        EXPECT(shown_roundtrip(s));
        ++cases;
    }
    std::printf("    %zu texts safe for a terminal and exact\n", cases);
}

// What the stream buffer passes on of what is written to it: `parts` one after the other, then a flush.
std::string through_filter(const std::vector<std::string>& parts, bool by_byte = false) {
    std::ostringstream target;
    textquote::TerminalSafeBuf buf(target.rdbuf());
    std::ostream os(&buf);
    for (const std::string& p : parts) {
        if (by_byte) for (char c : p) os.put(c);
        else os.write(p.data(), static_cast<std::streamsize>(p.size()));
    }
    os.flush();
    return target.str();
}

void test_terminal_filter() {
    std::puts("the stream buffer for a terminal: what a terminal would act on is written as escapes");
    EXPECT(through_filter({"plain text, 100% fine: a\\b \"c\"\n\tindented\n"}) == "plain text, 100% fine: a\\b \"c\"\n\tindented\n");
    EXPECT(through_filter({""}).empty());
    EXPECT(through_filter({"a\x1b[2Jb"}) == "a\\x1b[2Jb");
    EXPECT(through_filter({"\x1b]0;title\x07"}) == "\\x1b]0;title\\x07");
    EXPECT(through_filter({"a\rb\bc\x7f" "d\x01"}) == "a\\x0db\\x08c\\x7f" "d\\x01");
    EXPECT(through_filter({std::string("a\0b", 3)}) == "a\\x00b");
    EXPECT(through_filter({"\x0b\x0c"}) == "\\x0b\\x0c");  // vertical tab, form feed
    EXPECT(through_filter({"\xc3\xbc\xd0\x94 \xe2\x82\xac \xf0\x9f\x98\x80\n"}) == "\xc3\xbc\xd0\x94 \xe2\x82\xac \xf0\x9f\x98\x80\n");
    EXPECT(through_filter({"a\xc2\xa0z"}) == "a\xc2\xa0z");
    EXPECT(through_filter({"\xc2\x9b" "2J"}) == "\\xc2\\x9b" "2J");  // CSI in UTF-8
    EXPECT(through_filter({"\xc2\x80\xc2\x9f"}) == "\\xc2\\x80\\xc2\\x9f");
    EXPECT(through_filter({"\x9b" "2J"}) == "\\x9b" "2J");  // CSI as one byte
    EXPECT(through_filter({"\xff\xc0\xaf\xed\xa0\x80\xf4\x90\x80\x80"}) == "\\xff\\xc0\\xaf\\xed\\xa0\\x80\\xf4\\x90\\x80\\x80");
    EXPECT(through_filter({"a\xe2z"}) == "a\\xe2z");                                // cut off by an ASCII character
    EXPECT(through_filter({"a\xe2\x82"}) == "a\\xe2\\x82");                         // cut off by the end (the flush)
    EXPECT(through_filter({"\xe2\x82", "\xac"}) == "\xe2\x82\xac");                // a character in two writes
    EXPECT(through_filter({"\xe2", "\x82", "\xac"}) == "\xe2\x82\xac");            // and in three
    EXPECT(through_filter({"\xe2\x82\xac"}, true) == "\xe2\x82\xac");              // a byte at a time
    EXPECT(through_filter({"\xc2", "\x9b"}) == "\\xc2\\x9b");                       // a C1 control in two writes
    EXPECT(through_filter({"\xe2\x82", "z"}) == "\\xe2\\x82z");                     // a character that the next write does not go on with
    EXPECT(through_filter({"\xf0\x9f", "\x98", "\x80"}) == "\xf0\x9f\x98\x80");
    EXPECT(through_filter({"\xf0\x9f", "\x98"}) == "\\xf0\\x9f\\x98");              // never finished
    EXPECT(through_filter({"\xed", "\xa0\x80"}) == "\\xed\\xa0\\x80");              // a surrogate, cut and then not UTF-8
    EXPECT(through_filter({"\\x1b"}) == "\\x1b");                                   // an escape that is written out is text

    // the same text in any pieces comes out the same, and a terminal gets nothing it would act on
    std::mt19937 rng(20261021);
    const std::vector<std::string> pieces = {"a", "Z", " ", "\n", "\t", "\x1b", "\x07", "\r", "\x7f", "\x01", "\xc2\x9b", "\xc2\xa0", "\xc3\xbc",
                                             "\xe2\x82\xac", "\xf0\x9f\x98\x80", "\xff", "\x9b", "\xc0", "\xed\xa0", "\xe2\x82", "\x80", "\\x1b"};
    size_t cases = 0;
    for (size_t n = 0; n < 20000; ++n) {
        std::string text;
        for (size_t i = rng() % 14; i > 0; --i) text += pieces[rng() % pieces.size()];
        const std::string whole = through_filter({text});
        std::vector<std::string> cut;
        for (size_t at = 0; at < text.size();) {
            const size_t len = 1 + rng() % 4;
            cut.push_back(text.substr(at, len));
            at += len;
        }
        EXPECT(through_filter(cut) == whole);
        EXPECT(through_filter({text}, true) == whole);
        EXPECT(terminal_safe(whole, true));
        EXPECT(through_filter({whole}) == whole);  // (what comes out is not changed by the filter again)
        ++cases;
    }
    std::printf("    %zu random texts, in pieces and whole, come out the same and safe\n", cases);
}

void test_manifest_roundtrip() {
    std::puts("manifest.txt: values come back as the very bytes they were");
    TempDir dir;
    const fs::path file = dir.path / "manifest.txt";
    const std::vector<std::string> values = {
        "console=ttyS0,115200 androidboot.hardware=qcom",
        "console=ttyS0 ",                    // a space at the end: real images have it
        " console=ttyS0",                    // and at the start
        "a  b",                              // two inside
        "tab\there", "\t",
        "",                                  // nothing
        "   ",                               // only white space
        "\"quoted\"", "\"", "\"\"",
        "back\\slash", "\\", "ends with a backslash\\",
        "x=y", "=", "#not a comment", "# nor this",
        "line one\nline two",                // a line break
        "line one\r\nline two",
        "name\nramdisk_file=/etc/passwd\nkernel_file=../../.ssh/id_rsa",   // the way to add keys to a manifest
        "\nkernel_file=x", "trailing\n",
        std::string("zero\0byte", 9),
        "\x1b]0;title\x07 escape sequences", "\x7f",
        "\xc3\xbc\xd0\x94\xe4\xb8\xad",      // UTF-8
        "\xff\xfe latin and others \x80",    // not UTF-8
    };
    for (const std::string& v : values) {
        Manifest m;
        m.set("type", "boot");
        m.set("cmdline", v);
        m.set("after", "next");
        m.save(dir.path / "manifest.txt", "a comment");
        const std::string text = read_text(file);
        // no line break and no control byte in what is written but the ends of its lines
        size_t lines = 0;
        bool clean = true;
        for (unsigned char c : text) {
            if (c == '\n') ++lines;
            else if (c < 0x20 || c == 0x7F) clean = false;
        }
        Manifest back;
        std::string load_error;
        try {
            back = Manifest::load(file);
        } catch (const FormatError& e) {
            load_error = e.what();
        }
        const bool exact = back.get("cmdline", "?") == v && back.get("type") == "boot" && back.get("after") == "next";
        if (!load_error.empty() || !exact || !clean || lines != 4 || back.has("ramdisk_file") || back.has("kernel_file")) {
            ++g_failures;
            std::printf("  FAIL: \"%s\" -> %s (%zu lines, %s) -> \"%s\"\n", printable(v).c_str(), printable(text).c_str(), lines,
                        clean ? "clean" : "control bytes", printable(back.get("cmdline", "?")).c_str());
        }
        ++g_checks;
    }
    std::printf("    %zu values exact, none adds a key\n", values.size());

    // what is plain stays plain: the files stay what a person would write (and what earlier versions wrote)
    {
        Manifest m;
        m.set("type", "boot");
        m.set("empty", "");
        m.set("cmdline", "console=ttyS0 quiet");
        m.set("name", "a \"b\" c");
        m.save(file);
        const std::string text = read_text(file);
        EXPECT_HAS(text, "\nempty=\n");
        EXPECT_HAS(text, "\ncmdline=console=ttyS0 quiet\n");
        EXPECT_HAS(text, "\nname=a \"b\" c\n");
    }

    std::puts("manifest.txt: random values, several keys");
    std::mt19937 rng(7);
    const std::string special = "\"\\ \t\r\n=#x\x7f\x80\xff";
    size_t n = 0;
    for (; n < 1500; ++n) {
        Manifest m;
        std::vector<std::pair<std::string, std::string>> want;
        const size_t keys = 1 + rng() % 5;
        for (size_t k = 0; k < keys; ++k) {
            std::string v;
            const size_t len = rng() % 30;
            for (size_t i = 0; i < len; ++i) v += (rng() % 3 == 0) ? special[rng() % special.size()] : static_cast<char>('a' + rng() % 26);
            want.emplace_back("key" + std::to_string(k), v);
            m.set(want.back().first, v);
        }
        m.save(file);
        Manifest back;
        bool ok = true;
        try {
            back = Manifest::load(file);
        } catch (const FormatError&) {
            ok = false;
        }
        for (const auto& [k, v] : want) ok = ok && back.get(k, "?") == v;
        // ... and nothing else came with them
        ok = ok && !back.has("key" + std::to_string(keys));
        if (!ok) {
            ++g_failures;
            std::printf("  FAIL: random manifest %zu does not come back as it was written:\n%s\n", n, printable(read_text(file)).c_str());
            break;
        }
        ++g_checks;
    }
    std::printf("    %zu random manifests exact\n", n);
}

void test_manifest_reading() {
    std::puts("manifest.txt: what is written by hand reads as it always did");
    TempDir dir;
    const fs::path file = dir.path / "manifest.txt";
    write_text(file,
               "# a comment\r\n"
               "\r\n"
               "type = boot  \r\n"
               "  cmdline=console=ttyS0 quiet   \r\n"      // white space around is dropped, as it was
               "no equals sign on this line\r\n"
               "empty=\r\n"
               "  indented_key   =   spaced value  \n"
               "quoted = \"  kept  \"   \n"                  // a quoted value keeps what is inside
               "mid=a\"b\"c\n"                              // quotes that do not open the value are text
               "last=no newline at the end");
    const Manifest m = Manifest::load(file);
    EXPECT(m.get("type") == "boot");
    EXPECT(m.get("cmdline") == "console=ttyS0 quiet");
    EXPECT(m.has("empty") && m.get("empty", "?").empty());
    EXPECT(m.get("indented_key") == "spaced value");
    EXPECT(m.get("quoted") == "  kept  ");
    EXPECT(m.get("mid") == "a\"b\"c");
    EXPECT(m.get("last") == "no newline at the end");
    EXPECT(!m.has("no equals sign on this line"));

    std::puts("manifest.txt: a quoted value that is wrong is an error that says where");
    struct Bad {
        const char* line;
        const char* why;
    };
    const Bad bad[] = {
        {"cmdline=\"never closed", "not closed"},
        {"cmdline=\"ends in a backslash\\", "backslash"},
        {"cmdline=\"a\\qb\"", "unknown escape"},
        {"cmdline=\"a\\x4\"", "two hexadecimal digits"},
        {"cmdline=\"a\" and more", "after the closing quote"},
    };
    for (const Bad& b : bad) {
        write_text(file, std::string("type=boot\n# a comment\n") + b.line + "\n");
        std::string said;
        try {
            Manifest::load(file);
        } catch (const FormatError& e) {
            said = e.what();
        }
        EXPECT_HAS(said, b.why);
        EXPECT_HAS(said, "line 3");
        EXPECT_HAS(said, "manifest.txt");
    }
}

void test_manifest_paths() {
    std::puts("manifest.txt: file names have to lie in the directory");
    Manifest m;
    const char* fine[] = {"kernel", "ramdisk.cpio", "sub/dir/file.bin", "./kernel", "a.b", "name with space", ".hidden", "...", "a..b",
                          "\xc3\xbc\xd0\x94", "part0_MSM.bin", "ramdisk.vol2"};
    for (const char* v : fine) {
        m.set("kernel_file", v);
        std::string got;
        try {
            got = m.get_path("kernel_file");
        } catch (const FormatError& e) {
            ++g_failures;
            std::printf("  FAIL: \"%s\" was refused: %s\n", v, e.what());
        }
        EXPECT(got == v);
    }
    EXPECT(m.get_path("not_there").empty());
    EXPECT(m.get_path("not_there", "fallback.bin") == "fallback.bin");

    struct Bad {
        std::string value;
        const char* why;
    };
    const Bad bad[] = {
        {"..", "'..'"},
        {"../kernel", "'..'"},
        {"a/../b", "'..'"},
        {"a/b/..", "'..'"},
        {"/etc/passwd", "absolute"},
        {"/", "absolute"},
        {"\\windows\\system32", "absolute"},
        {"a\\b", "backslash"},
        {"..\\x", "backslash"},
        {"C:kernel", "colon"},
        {"C:/kernel", "colon"},
        {"kernel:stream", "colon"},
        {"a//b", "empty part"},
        {"kernel/", "empty part"},
        {"a\nb", "control character"},
        {std::string("a\0b", 3), "control character"},
        {"a\x7f", "control character"},
    };
    for (const Bad& b : bad) {
        m.set("kernel_file", b.value);
        std::string said;
        try {
            m.get_path("kernel_file");
        } catch (const FormatError& e) {
            said = e.what();
        }
        if (said.empty()) {
            ++g_failures;
            std::printf("  FAIL: \"%s\" was not refused\n", printable(b.value).c_str());
        } else {
            EXPECT_HAS(said, b.why);
            EXPECT_HAS(said, "kernel_file");
            EXPECT_HAS(said, "directory");
            EXPECT(said.find('\n') == std::string::npos);  // (what a hostile name says in the message is quoted)
        }
    }
    // the default is looked at as well
    std::string said;
    try {
        m.get_path("not_there", "../x");
    } catch (const FormatError& e) {
        said = e.what();
    }
    EXPECT_HAS(said, "'..'");
}

// ---- the bytes behind the NUL that ends the text of a header field ------------------------------------------------------

Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }

void test_text_field_tails() {
    std::puts("text fields of a header: what is behind the NUL that ends the text");

    // reading: the text, and the tail up to its last non-zero byte
    struct Read {
        std::string field;     // the N bytes of the field
        std::string text;
        std::string tail;
    };
    const std::vector<Read> reads = {
        {std::string("abc\0\0\0\0\0", 8), "abc", ""},
        {std::string("abc\0XY\0\0", 8), "abc", "XY"},
        {std::string("abc\0\0Z\0\0", 8), "abc", std::string("\0Z", 2)},     // a zero inside the tail stays
        {std::string("abc\0\0\0\0Z", 8), "abc", std::string("\0\0\0Z", 4)},   // a tail that reaches the end of the field
        {std::string("abc\0Z\0\0\0", 8), "abc", "Z"},
        {"abcdefgh", "abcdefgh", ""},                                   // no NUL at all: the text fills the field
        {std::string("abcdefg\0", 8), "abcdefg", ""},                   // a NUL at the very end: nothing behind it
        {std::string("\0\0\0\0\0\0\0\0", 8), "", ""},
        {std::string("\0junk\0\0\0", 8), "", "junk"},                  // no text, junk behind the first NUL
        {std::string("\0\0\0\0\0\0\0Z", 8), "", std::string("\0\0\0\0\0\0Z", 7)},
        {std::string("ab\0cdef", 7), "ab", "cdef"},
        {std::string("a\0", 2), "a", ""},
        {std::string("\0", 1), "", ""},
    };
    for (const Read& r : reads) {
        const Bytes field = bytes_of(r.field);
        Bytes framed = bytes_of("12");  // (something in front, and something behind: the field is exactly N bytes)
        framed.insert(framed.end(), field.begin(), field.end());
        framed.push_back('9');
        BinaryReader reader(framed);
        reader.skip(2);
        Bytes tail = bytes_of("stale");  // (a tail from an earlier field must not stay)
        const std::string text = reader.asciiz(field.size(), tail);
        EXPECT(text == r.text);
        EXPECT(tail == bytes_of(r.tail));
        EXPECT(reader.pos() == 2 + field.size());
        // and the old call, without a tail, says the same of the text
        BinaryReader again(framed);
        again.skip(2);
        EXPECT(again.asciiz(field.size()) == r.text);
        EXPECT(again.pos() == 2 + field.size());
    }

    // writing: always exactly N bytes; the text, its NUL, then as much of the tail as the field holds
    struct Write {
        std::string text;
        std::string tail;
        size_t size;
        std::string field;
    };
    const std::vector<Write> writes = {
        {"abc", "", 8, std::string("abc\0\0\0\0\0", 8)},
        {"abc", "XY", 8, std::string("abc\0XY\0\0", 8)},
        {"abc", std::string("\0Z", 2), 8, std::string("abc\0\0Z\0\0", 8)},
        {"abc", "123456789", 8, std::string("abc\0" "1234", 8)},        // too long for the field: cut
        {"abc", "1234", 8, std::string("abc\0" "1234", 8)},             // exactly what the field holds
        {"abcdefg", "XY", 8, std::string("abcdefg\0", 8)},              // text and NUL fill the field: no room
        {"abcdefgh", "XY", 8, "abcdefgh"},                              // the text fills it: no NUL, no tail
        {"abcdefghij", "XY", 8, "abcdefgh"},                            // a text that is too long is cut, as it was
        {"", "XY", 8, std::string("\0XY\0\0\0\0\0", 8)},
        {"", "", 8, std::string(8, '\0')},
        {"a", "XY", 2, std::string("a\0", 2)},
        {"", "XY", 1, std::string("\0", 1)},
        {"abc", "XY", 0, ""},                                           // (no field)
    };
    for (const Write& w : writes) {
        BinaryWriter out;
        out.asciiz(w.text, w.size, bytes_of(w.tail));
        EXPECT(out.size() == w.size);
        EXPECT(out.data() == bytes_of(w.field));
        if (w.tail.empty()) {  // the same as the call that has no tail
            BinaryWriter plain;
            plain.asciiz(w.text, w.size);
            EXPECT(plain.data() == out.data());
        }
    }

    {   // a tail very much longer than the field: what fits is written, and nothing past the end of the field
        BinaryWriter out;
        out.asciiz("abc", 8, Bytes(16u << 20, 'x'));
        EXPECT(out.data() == bytes_of(std::string("abc\0xxxx", 8)));
    }

    // any field is read and written back as it was: text, NUL, then whatever -- zeros, junk, the rest of an old text
    std::mt19937 rng(20261022);
    for (int round = 0; round < 20000; ++round) {
        const size_t n = 1 + rng() % 40;
        Bytes field(n, 0);
        const unsigned density = 1 + rng() % 4;  // how many of the bytes are zero: about 1/density
        const unsigned style = rng() % 3;
        for (auto& b : field) {
            if (rng() % density == 0 && style != 2) b = 0;
            else if (style == 0) b = static_cast<uint8_t>('a' + rng() % 26);
            else b = static_cast<uint8_t>(rng());
        }
        if (rng() % 3 == 0) field[rng() % n] = 0;  // a NUL somewhere
        if (rng() % 3 == 0) field.back() = 0;
        Bytes framed = field;
        BinaryReader reader(framed);
        Bytes tail;
        const std::string text = reader.asciiz(n, tail);
        EXPECT(reader.pos() == n);
        BinaryWriter out;
        out.asciiz(text, n, tail);
        EXPECT(out.data() == field);
        // a tail never ends in a zero (it is trimmed) and never starts in the text
        EXPECT(tail.empty() || tail.back() != 0);
        EXPECT(text.find('\0') == std::string::npos);
        EXPECT(text.size() + (tail.empty() ? 0 : 1 + tail.size()) <= n);
    }

    // the manifest: a printable tail is text, anything else is hex, nothing is nothing
    TempDir dir;
    const fs::path file = dir.path / "manifest.txt";
    struct InManifest {
        std::string tail;
        bool as_text;
    };
    const std::vector<InManifest> tails = {
        {"115200 androidboot.selinux=permissive", true},
        {" leading and trailing blanks ", true},          // (blanks at the ends are quoted, and come back)
        {"\"quoted\" and \\ and # and = and ' '", true},
        {"x", true},
        {std::string("\0", 1), false},
        {std::string("\0Z", 2), false},
        {"\xff\xff\xff", false},
        {"\xc3\xbc", false},                                // UTF-8 is not printable ASCII
        {"line one\nkernel_file=/etc/passwd", false},        // a line break would add a key to the manifest
        {"tab\there", false},
        {"\x1b]0;title\x07", false},
        {"\x7f", false},
        {"~", true},                                      // the last printable ASCII character,
        {"\x1f", false},                                  // the control character before the first,
        {"\x80", false},                                  // and the first byte above ASCII
    };
    for (const InManifest& t : tails) {
        Manifest m;
        m.set("type", "boot");
        m.set_tail("cmdline_tail", bytes_of(t.tail));
        m.set("after", "next");
        EXPECT(m.has("cmdline_tail") == t.as_text);
        EXPECT(m.has("cmdline_tail_hex") == !t.as_text);
        EXPECT(m.get_tail("cmdline_tail") == bytes_of(t.tail));
        m.save(file);
        const std::string written = read_text(file);
        // nothing a line of the file could be taken for but the lines the manifest wrote
        size_t lines = 0;
        for (char c : written) lines += c == '\n';
        EXPECT(lines == 3);  // type, the tail, after
        Manifest back = Manifest::load(file);
        EXPECT(back.get_tail("cmdline_tail") == bytes_of(t.tail));
        EXPECT(back.get("after") == "next");
        EXPECT(!back.has("kernel_file"));
    }
    {
        Manifest none;
        none.set_tail("cmdline_tail", Bytes());
        EXPECT(!none.has("cmdline_tail"));
        EXPECT(!none.has("cmdline_tail_hex"));
        EXPECT(none.get_tail("cmdline_tail").empty());
    }
    {   // both, from a manifest somebody edited: the hex one is read
        Manifest both;
        both.set("cmdline_tail", "text");
        both.set_hex("cmdline_tail_hex", bytes_of("hex"));
        EXPECT(both.get_tail("cmdline_tail") == bytes_of("hex"));
    }
    std::mt19937 rng2(7);
    for (int round = 0; round < 3000; ++round) {
        Bytes tail(1 + rng2() % 60);
        const bool printable_only = rng2() % 2;
        for (auto& b : tail) b = printable_only ? static_cast<uint8_t>(0x20 + rng2() % 95) : static_cast<uint8_t>(rng2());
        Manifest m;
        m.set_tail("t", tail);
        m.save(file);
        EXPECT(Manifest::load(file).get_tail("t") == tail);
    }
}

}  // namespace

int run_manifest_tests() {
    test_quote_basics();
    test_quote_every_byte();
    test_quote_random();
    test_quote_shown();
    test_terminal_filter();
    test_manifest_roundtrip();
    test_manifest_reading();
    test_manifest_paths();
    test_text_field_tails();
    if (g_failures == 0) std::printf("manifest: ok (%d checks)\n", g_checks);
    else std::printf("manifest: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
