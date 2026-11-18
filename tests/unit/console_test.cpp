// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr::console (include/abr/console.hpp) and abr::progress (include/abr/progress.hpp). Run by tests/run_tests.sh as
// `abr_unit_tests console`.
//
//   * progress: the weights of the stages that are done plus the part of the stage in progress that is done, never more than there is
//     (a stage that reports more than its work stops at its end, a stage that is not entered is done when the next one is, a command
//     that is not over never shows 100%), work that is added to a stage that is entered again, jobs named while they run;
//   * the bar: for every width, style, share and text that is thrown at it, one line that starts with a carriage return and ends with
//     the erasing of the rest of the line, that is not wider than the terminal, that holds no control character of its own (the text it
//     is given is cleaned) and no colour where there are none, nothing but ASCII where it is asked to be;
//   * the printer: what threads write comes out whole and in order, the two streams in the order they were written, text a terminal
//     would act on is escaped (unless it is asked not to), what is written without a line break at the end is not lost, and the bar is
//     drawn while a command is in progress and stays where it is: what is written meanwhile waits for the end of the command and comes
//     out behind the bar (a flood of lines does not wait), and is gone at the end;
//   * wrapping: lines broken at the blanks to the width of the screen, with the indent of the value of a `key: value` line, a long word
//     behind a `/`; never a line that is wider, never a character lost or cut in two; the printer wraps for ABR_COLUMNS (and for a
//     terminal), not for a pipe, not with the output unfiltered.
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "abr/console.hpp"
#include "abr/progress.hpp"

using namespace abr;
using namespace std::chrono_literals;

namespace {

int g_failures = 0;

#define EXPECT(cond)                                                              \
    do {                                                                          \
        if (!(cond)) {                                                            \
            ++g_failures;                                                         \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                         \
    } while (0)

void set_env(const char* name, const char* value) {
#ifdef _WIN32
    _putenv_s(name, value ? value : "");
#else
    if (value) setenv(name, value, 1);
    else unsetenv(name);
#endif
}

// ------------------------------------------------------------------ progress --

void test_progress() {
    // no command: nothing
    EXPECT(!progress::snapshot().active);
    progress::advance(5);  // (is nothing, and does no harm)
    progress::enter("x", 10);
    EXPECT(!progress::snapshot().active);

    progress::begin("unpack", {{"read", 1}, {"decode", 6}, {"verify", 3}});
    progress::Snapshot s = progress::snapshot();
    EXPECT(s.active && s.command == "unpack" && s.fraction == 0 && !s.determinate && s.stage.empty());

    progress::enter("read", 4);
    progress::advance(2);
    s = progress::snapshot();
    EXPECT(s.determinate && s.stage == "read" && std::abs(s.fraction - 0.05) < 1e-9);  // half of 1 of 10

    // "decode" is entered: "read" is done; and again, with more work: what is done stays done
    progress::enter("decode", 100);
    s = progress::snapshot();
    EXPECT(std::abs(s.fraction - 0.1) < 1e-9);
    progress::advance(50);
    EXPECT(std::abs(progress::snapshot().fraction - 0.4) < 1e-9);
    progress::enter("decode", 100);  // 200 in all, 50 done
    EXPECT(std::abs(progress::snapshot().fraction - 0.25) < 1e-9);
    // more than the work: the stage ends where it ends, and the command is not over
    progress::advance(100000);
    s = progress::snapshot();
    EXPECT(std::abs(s.fraction - 0.7) < 1e-9 && s.active);

    // a stage that is not in the plan changes nothing; one that was left out is done when the next is entered
    progress::enter("nonsense", 5);
    EXPECT(progress::snapshot().stage == "decode");
    progress::enter("verify");  // (no units: not known)
    s = progress::snapshot();
    EXPECT(!s.determinate && std::abs(s.fraction - 0.7) < 1e-9 && s.stage == "verify");
    // a stage that is behind is not entered again
    progress::enter("read", 10);
    EXPECT(progress::snapshot().stage == "verify");

    // jobs
    {
        const progress::Activity a("kernel");
        const progress::Activity b("ramdisk.cpio");
        const progress::Activity c("dt");
        EXPECT(progress::snapshot().activity == "kernel, ramdisk.cpio +1");
        {
            const progress::Activity d("x");
            EXPECT(progress::snapshot().activity == "kernel, ramdisk.cpio +2");
        }
    }
    EXPECT(progress::snapshot().activity.empty());

    progress::end();
    progress::end();
    EXPECT(!progress::snapshot().active);

    // advance() from many threads adds up
    progress::begin("t", {{"a", 1}});
    progress::enter("a", 8000);
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i)
        threads.emplace_back([] {
            for (int k = 0; k < 500; ++k) progress::advance(2);
        });
    for (auto& t : threads) t.join();
    EXPECT(std::abs(progress::snapshot().fraction - 0.99) < 1e-9);  // (all the work is done, and the command is not over)
    progress::end();
}

// ------------------------------------------------------------------- the bar --

// The bytes of a line that is not an escape sequence of ours; fails when one is not the kind the bar writes.
std::string strip_escapes(const std::string& line, bool* clean) {
    std::string out;
    *clean = true;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] != '\x1b') {
            out += line[i];
            continue;
        }
        if (i + 1 >= line.size() || line[i + 1] != '[') {
            *clean = false;
            return out;
        }
        size_t j = i + 2;
        while (j < line.size() && ((line[j] >= '0' && line[j] <= '9') || line[j] == ';')) ++j;
        if (j >= line.size() || (line[j] != 'm' && line[j] != 'K')) {
            *clean = false;
            return out;
        }
        i = j;
    }
    return out;
}

size_t characters(const std::string& s) {
    size_t n = 0;
    for (const char c : s) n += (static_cast<unsigned char>(c) & 0xc0) != 0x80;
    return n;
}

void test_bar() {
    const console::Colour colours[] = {console::Colour::TRUECOLOUR, console::Colour::ANSI256, console::Colour::ANSI16, console::Colour::NONE};
    const std::vector<std::string> texts = {
        "kernel",
        "ramdisk.cpio, vendor_ramdisk00 +3",
        std::string("a\x1b[31mred\x1b[0m\r\n\tb\x07\x7f"),  // what a terminal would act on
        std::string("\xc2\x9b" "31m"),                         // a C1 control (CSI)
        std::string("caf\xc3\xa9 \xe2\x80\xae" "evil"),       // text that is fine, and a bidirectional override
        std::string("bad \xff\xfe utf8 \xe2\x82"),            // not UTF-8
        std::string(300, 'x'),                                // longer than any terminal
        "",
    };
    const double fractions[] = {0.0, 0.004, 0.5, 0.995, 1.0};
    int lines = 0;
    for (const console::Colour colour : colours)
        for (const bool utf8 : {true, false})
            for (const int columns : {1, 20, 24, 30, 40, 41, 60, 80, 100, 200})
                for (const double fraction : fractions)
                    for (const bool determinate : {true, false})
                        for (const unsigned frame : {0u, 1u, 7u, 100u, 12345u})
                            for (const std::string& text : texts) {
                                progress::Snapshot s;
                                s.active = true;
                                s.command = text;
                                s.stage = "decode";
                                s.activity = text;
                                s.fraction = fraction;
                                s.determinate = determinate;
                                s.seconds = frame * 0.08 + 0.3;
                                console::BarStyle style;
                                style.colour = colour;
                                style.utf8 = utf8;
                                const std::string line = console::render_bar(s, style, columns, frame);
                                ++lines;
                                EXPECT(!line.empty() && line.front() == '\r');
                                EXPECT(line.size() >= 3 && line.compare(line.size() - 3, 3, "\x1b[K") == 0);
                                bool clean = false;
                                const std::string visible = strip_escapes(line.substr(1), &clean);
                                EXPECT(clean);
                                bool controls = false, high = false;
                                for (const char ch : visible) {
                                    const unsigned char c = static_cast<unsigned char>(ch);
                                    controls = controls || c < 0x20 || c == 0x7f;
                                    high = high || c >= 0x80;
                                }
                                EXPECT(!controls);
                                EXPECT(utf8 || !high);
                                // not wider than the terminal (the last column is left alone; below 20 columns the bar takes 20)
                                {
                                    static int shown = 0;
                                    const bool fits = characters(visible) <= static_cast<size_t>(std::max(columns, 20)) - 1;
                                    if (!fits && shown++ < 6)
                                        std::printf("  [columns %d, %zu characters, utf8 %d, share %.3f] %s\n", columns, characters(visible), utf8 ? 1 : 0,
                                                    fraction, visible.c_str());
                                    EXPECT(fits);
                                }
                                // no colour: the only escape in it is the one that clears the rest of the line (so that none came in with the text)
                                if (colour == console::Colour::NONE) EXPECT(std::count(line.begin(), line.end(), '\x1b') == 1);
                                // the share shown is what is done (a figure that is more than it is is a lie)
                                const int percent = fraction >= 1.0 ? 100 : static_cast<int>(fraction * 100);
                                EXPECT(visible.find(std::to_string(percent) + "%") != std::string::npos);
                            }
    EXPECT(lines > 10000);

    // nothing in progress: nothing to draw
    EXPECT(console::render_bar(progress::Snapshot{}, console::BarStyle{}, 80, 0).empty());

    // what it looks like, once (UTF-8, 100 columns, half done): the command, the bar with its edge, the share, the words, the time
    progress::Snapshot s;
    s.active = true;
    s.command = "unpack";
    s.stage = "decode";
    s.activity = "kernel";
    s.fraction = 0.5;
    s.determinate = true;
    s.seconds = 1.25;
    console::BarStyle plain;
    plain.colour = console::Colour::NONE;
    bool clean = false;
    const std::string text = strip_escapes(console::render_bar(s, plain, 100, 0).substr(1), &clean);
    EXPECT(text.find("unpack") != std::string::npos && text.find(" 50%") != std::string::npos &&
           text.find("decode \xc2\xb7 kernel") != std::string::npos && text.find("1.2 s") != std::string::npos);
    plain.utf8 = false;
    const std::string ascii = strip_escapes(console::render_bar(s, plain, 100, 0).substr(1), &clean);
    EXPECT(ascii.find("[#") != std::string::npos && ascii.find("-]") != std::string::npos && ascii.find("decode - kernel") != std::string::npos);
}

// ---------------------------------------------------------------- the printer --

// std::cout and std::cerr write into strings for as long as this lives.
struct Capture {
    std::stringbuf out, err;
    std::streambuf* old_out;
    std::streambuf* old_err;
    Capture() : old_out(std::cout.rdbuf(&out)), old_err(std::cerr.rdbuf(&err)) {}
    ~Capture() {
        std::cout.rdbuf(old_out);
        std::cerr.rdbuf(old_err);
    }
};

void test_printer() {
    set_env("ABR_PROGRESS", "never");
    set_env("ABR_UNFILTERED_OUTPUT", nullptr);

    // whole lines, in order, from many threads; both streams, in the order they were written
    {
        Capture cap;
        {
            console::Printer printer;
            std::vector<std::thread> threads;
            for (int t = 0; t < 8; ++t)
                threads.emplace_back([t] {
                    for (int i = 0; i < 400; ++i) {
                        // (written in pieces, as the code of abr does: `std::cerr` flushes after each of them)
                        std::ostream& os = (i % 2 == 0) ? std::cout : std::cerr;
                        os << "thread " << t << " line " << i << " " << std::string(static_cast<size_t>(i % 40), '.') << "\n";
                    }
                });
            for (auto& th : threads) th.join();
        }
        const std::string all_out = cap.out.str(), all_err = cap.err.str();
        std::vector<int> next_even(8, 0), next_odd(8, 1);
        for (const bool is_out : {true, false}) {
            std::istringstream in(is_out ? all_out : all_err);
            std::string line;
            int count = 0;
            while (std::getline(in, line)) {
                int t = -1, i = -1;
                char dots[64] = {};
                EXPECT(std::sscanf(line.c_str(), "thread %d line %d %63s", &t, &i, dots) >= 2);
                EXPECT(t >= 0 && t < 8 && i >= 0);
                if (t < 0 || t >= 8 || i < 0) continue;
                EXPECT(line == "thread " + std::to_string(t) + " line " + std::to_string(i) + " " + std::string(static_cast<size_t>(i % 40), '.'));
                int& next = is_out ? next_even[static_cast<size_t>(t)] : next_odd[static_cast<size_t>(t)];
                EXPECT(i == next);
                next += 2;
                ++count;
            }
            EXPECT(count == 8 * 200);
        }
    }

    // the order of the two streams, when one thread writes them
    {
        Capture cap;
        {
            console::Printer printer;
            std::cout << "a\n";
            std::cerr << "b\n";
            std::cout << "c\n";
        }
        EXPECT(cap.out.str() == "a\nc\n" && cap.err.str() == "b\n");
    }

    // a line that is not finished is not lost; a line that is finished a piece at a time comes out as one
    {
        Capture cap;
        {
            console::Printer printer;
            std::cout << "one " << 2 << " " << 3.5 << "\n" << "and no line break";
        }
        EXPECT(cap.out.str() == "one 2 3.5\nand no line break");
    }

    // what a terminal would act on is escaped, unless the output is asked to be left alone
    {
        Capture cap;
        {
            console::Printer printer;
            std::cout << "a\x1b[31mred\x1b[0m \x07 \xc2\x9b\n";
        }
        EXPECT(cap.out.str().find('\x1b') == std::string::npos);
        EXPECT(cap.out.str().find("red") != std::string::npos);
        EXPECT(cap.out.str().find('\x07') == std::string::npos);
    }
    set_env("ABR_UNFILTERED_OUTPUT", "1");
    {
        Capture cap;
        {
            console::Printer printer;
            std::cout << "a\x1b[31mred\n";
        }
        EXPECT(cap.out.str() == "a\x1b[31mred\n");
    }
    set_env("ABR_UNFILTERED_OUTPUT", nullptr);

    // no bar where it is switched off: a command in progress is not seen at all
    {
        Capture cap;
        {
            console::Printer printer;
            progress::begin("pack", {{"a", 1}});
            progress::enter("a", 10);
            progress::advance(5);
            std::this_thread::sleep_for(400ms);
            std::cout << "message\n";
            progress::end();
        }
        EXPECT(cap.out.str() == "message\n" && cap.err.str().empty());
    }

    // the bar, forced (the output is a string here): on stderr, in frames, away for a line and at the end
    set_env("ABR_PROGRESS", "always");
    set_env("ABR_COLUMNS", "60");
    set_env("NO_COLOR", "1");
    {
        Capture cap;
        {
            console::Printer printer;
            progress::begin("pack", {{"a", 1}});
            progress::enter("a", 10);
            progress::advance(5);
            std::this_thread::sleep_for(350ms);
            std::cout << "message\n";
            std::this_thread::sleep_for(250ms);
            progress::end();
            std::this_thread::sleep_for(200ms);
        }
        const std::string out = cap.out.str(), err = cap.err.str();
        EXPECT(out == "message\n");  // (on stdout: what a pipe would have got)
        EXPECT(err.find("pack") != std::string::npos && err.find(" 50%") != std::string::npos);
        EXPECT(err.find('\n') == std::string::npos);  // the bar has no line break of its own
        // (stdout is no terminal here, so the line does not touch the bar) the end takes the bar away: the last thing on the line
        EXPECT(err.size() >= 5 && err.compare(err.size() - 5, 5, "\r\x1b[2K") == 0);
    }
    set_env("NO_COLOR", nullptr);
    set_env("ABR_COLUMNS", nullptr);
    set_env("ABR_PROGRESS", "never");
    EXPECT(!progress::snapshot().active);
}

// ----------------------------------------------------------------- wrapping --

size_t chars_of(const std::string& s) {
    size_t n = 0;
    for (const char c : s) n += (static_cast<unsigned char>(c) & 0xc0) != 0x80;
    return n;
}

bool valid_utf8(const std::string& s) {
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        const size_t len = c < 0x80 ? 1 : c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : c >= 0xc2 ? 2 : 0;
        if (len == 0 || i + len > s.size()) return false;
        for (size_t k = 1; k < len; ++k)
            if ((static_cast<unsigned char>(s[i + k]) & 0xc0) != 0x80) return false;
        i += len;
    }
    return true;
}

std::string without_blanks(const std::vector<std::string>& lines) {
    std::string out;
    for (const std::string& l : lines)
        for (const char c : l)
            if (c != ' ') out += c;
    return out;
}

using Lines = std::vector<std::string>;

void test_wrap() {
    // what it does, by hand
    EXPECT(console::wrap("hello world", 20) == Lines{"hello world"});
    EXPECT(console::wrap("", 20) == Lines{""});
    EXPECT(console::wrap("   ", 20) == Lines{""});
    EXPECT(console::wrap("aaa bbb ccc ddd", 8) == (Lines{"aaa bbb", "ccc ddd"}));
    EXPECT(console::wrap("a    b", 20) == Lines{"a    b"});  // (the blanks inside a line stay)
    EXPECT(console::wrap("alpha beta gamma delta epsilon zeta eta theta iota", 24, 2, 4) ==
           (Lines{"  alpha beta gamma delta", "    epsilon zeta eta", "    theta iota"}));
    // a group in parentheses goes whole to the next line when it fits there (with `groups`), else it is words like the rest
    EXPECT(console::wrap("name (97479936 bytes) tail", 20, 0, 2, true) == (Lines{"name", "  (97479936 bytes)", "  tail"}));
    EXPECT(console::wrap("name (97479936 bytes) tail", 20, 0, 2) == (Lines{"name (97479936", "  bytes) tail"}));
    // a word that is longer than a line: behind a `/` in the second half of the room, else behind another separator, else cut
    EXPECT(console::wrap("/aaaa/bbbb/cccc/dddd/eeee/ffff", 16) == (Lines{"/aaaa/bbbb/cccc/", "dddd/eeee/ffff"}));
    EXPECT(console::wrap("aaaa-bbbb-cccc-dddd-eeee", 16) == (Lines{"aaaa-bbbb-cccc-", "dddd-eeee"}));
    EXPECT(console::wrap(std::string(40, 'x'), 16) == (Lines{std::string(16, 'x'), std::string(16, 'x'), std::string(8, 'x')}));
    // the word that follows a long one goes on, on the line where it ended
    EXPECT(console::wrap(std::string(20, 'x') + " yy", 16) == (Lines{std::string(16, 'x'), "xxxx yy"}));
    // a character is not cut in two
    {
        std::string euros;
        for (int i = 0; i < 40; ++i) euros += "\xe2\x82\xac";
        const Lines l = console::wrap(euros, 16);
        EXPECT(l.size() == 3 && chars_of(l[0]) == 16 && chars_of(l[1]) == 16 && chars_of(l[2]) == 8);
        for (const std::string& line : l) EXPECT(valid_utf8(line));
    }
    // an indent that leaves no room is made to: a narrow width keeps 16 characters beside it
    {
        const Lines l = console::wrap("one two three four", 20, 18, 18);
        for (const std::string& line : l) EXPECT(chars_of(line) <= 20);
        EXPECT(without_blanks(l) == "onetwothreefour");
    }

    // a message line: itself when it fits (byte for byte), else the indent of its value or two blanks more than its own
    EXPECT(console::wrap_message("  a   line  that   fits", 40) == Lines{"  a   line  that   fits"});
    EXPECT(console::wrap_message("cmdline:        bootopt=64S3,32N2,64N2 erofs.reserved_pages=64", 40) ==
           (Lines{"cmdline:        bootopt=64S3,32N2,64N2", "                erofs.reserved_pages=64"}));
    EXPECT(console::wrap_message("unpacked vendor_boot -> /data/local/AIK-mobile/vendor_boot_ofox/", 40) ==
           (Lines{"unpacked vendor_boot ->", "  /data/local/AIK-mobile/", "  vendor_boot_ofox/"}));
    EXPECT(console::wrap_message("warning: kernel (gzip) is cut short: the stream ends before its end", 40) ==
           (Lines{"warning: kernel (gzip) is cut short: the", "         stream ends before its end"}));
    // (a colon far into the line is no key: two blanks)
    EXPECT(console::wrap_message("a sentence that has its colon late: and a long tail of words after it", 30) ==
           (Lines{"a sentence that has its colon", "  late: and a long tail of", "  words after it"}));
    // (the arrow is no key either)
    EXPECT(console::wrap_message("ramdisk -> out/dir: x and a long tail of words that goes on and on", 30).at(1).rfind("  ", 0) == 0);

    // for every text, width and indent: never wider, never a character lost, cut in two or made up, the indents as asked
    std::mt19937 rng(12345);
    const char* const pieces[] = {"a", "bc", "def", "/", "-", ".", "(", ")", " ", " ", "  ", "\xc3\xa9", "\xe2\x82\xac", "word", "path/to/file", "x", ":"};
    int cases = 0;
    for (int iter = 0; iter < 6000; ++iter) {
        std::string text;
        const int n = static_cast<int>(rng() % 60);
        for (int i = 0; i < n; ++i) text += pieces[rng() % (sizeof pieces / sizeof *pieces)];
        if (rng() % 7 == 0) text += std::string(rng() % 90, 'q');  // (a word of any length)
        const size_t width = 1 + rng() % 120;
        const size_t first = rng() % 40, next = rng() % 40;
        const bool groups = rng() % 2 == 0;
        const Lines lines = console::wrap(text, width, first, next, groups);
        ++cases;
        EXPECT(!lines.empty());
        const size_t eff = std::max<size_t>(width, 8);
        const size_t most = eff > 16 ? eff - 16 : 0;
        std::string want;
        for (const char c : text)
            if (c != ' ') want += c;
        EXPECT(without_blanks(lines) == want);
        bool any_word = !want.empty();
        for (size_t i = 0; i < lines.size(); ++i) {
            EXPECT(chars_of(lines[i]) <= eff);
            EXPECT(valid_utf8(lines[i]));
            EXPECT(lines[i].empty() || lines[i].back() != ' ');
            EXPECT(!any_word || !lines[i].empty());
            if (any_word) {
                size_t lead = 0;
                while (lead < lines[i].size() && lines[i][lead] == ' ') ++lead;
                EXPECT(lead == std::min(i == 0 ? first : next, most));
            }
        }
    }
    EXPECT(cases == 6000);
}

// What a stream that is a terminal would be: one buffer for stdout and stderr, written by the printer thread and read by the test.
class LockedBuf final : public std::streambuf {
public:
    std::string text() {
        std::lock_guard<std::mutex> lock(mu_);
        return data_;
    }

protected:
    int_type overflow(int_type c) override {
        if (!traits_type::eq_int_type(c, traits_type::eof())) {
            std::lock_guard<std::mutex> lock(mu_);
            data_ += traits_type::to_char_type(c);
        }
        return traits_type::not_eof(c);
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        std::lock_guard<std::mutex> lock(mu_);
        data_.append(s, static_cast<size_t>(n));
        return n;
    }

private:
    std::mutex mu_;
    std::string data_;
};

struct CaptureOne {
    LockedBuf buf;
    std::streambuf* old_out;
    std::streambuf* old_err;
    CaptureOne() : old_out(std::cout.rdbuf(&buf)), old_err(std::cerr.rdbuf(&buf)) {}
    ~CaptureOne() {
        std::cout.rdbuf(old_out);
        std::cerr.rdbuf(old_err);
    }
};

size_t count_of(const std::string& s, const std::string& part) {
    size_t n = 0;
    for (size_t at = s.find(part); at != std::string::npos; at = s.find(part, at + part.size())) ++n;
    return n;
}

// Waits until `done()` holds, for 15 seconds at most: the printer is a thread of its own, and an emulator or a busy machine makes it late.
// (A test that sleeps a fixed time and then looks fails there, and says nothing about the printer.)
template <class F>
bool wait_for(F&& done) {
    const auto end = std::chrono::steady_clock::now() + 15s;
    while (!done()) {
        if (std::chrono::steady_clock::now() >= end) return false;
        std::this_thread::sleep_for(10ms);
    }
    return true;
}

void test_hold() {
    set_env("ABR_UNFILTERED_OUTPUT", nullptr);
    set_env("ABR_PROGRESS", "always");
    set_env("ABR_COLUMNS", "60");
    set_env("NO_COLOR", "1");

    // What a command says while the bar is on the screen waits for the end of the command: the bar frames come one over the other (no
    // line break among them), then the bar is taken away, then the lines, in the order they were written, the two streams together.
    {
        CaptureOne cap;
        {
            console::Printer printer;
            progress::begin("pack", {{"a", 1}});
            progress::enter("a", 10);
            progress::advance(5);
            EXPECT(wait_for([&] { return count_of(cap.buf.text(), "pack") >= 1; }));  // (the bar is on the screen)
            std::cout << "first\n";
            std::cerr << "second\n";
            EXPECT(wait_for([&] { return count_of(cap.buf.text(), "pack") >= 3; }));  // (and goes on being drawn)
            const std::string meanwhile = cap.buf.text();
            EXPECT(meanwhile.find("first") == std::string::npos && meanwhile.find("second") == std::string::npos);
            EXPECT(meanwhile.find('\n') == std::string::npos);
            EXPECT(count_of(meanwhile, "pack") >= 3);  // (frames of the bar, one over the other: it did not move)
            progress::end();
            EXPECT(wait_for([&] {
                const std::string s = cap.buf.text();
                return s.size() >= 7 && s.compare(s.size() - 7, 7, "second\n") == 0;
            }));
        }
        const std::string text = cap.buf.text();
        const size_t first = text.find("first");
        EXPECT(first != std::string::npos);
        if (first != std::string::npos) {
            EXPECT(first >= 5 && text.compare(first - 5, 5, "\r\x1b[2K") == 0);  // (the bar goes, then the line)
            EXPECT(text.substr(first) == "first\nsecond\n");                    // (nothing after them: no bar over again)
            EXPECT(text.substr(0, first).find('\n') == std::string::npos);
        }
    }

    // a line that is written when no command is in progress is written at once
    {
        CaptureOne cap;
        {
            console::Printer printer;
            std::cout << "alone\n";
            EXPECT(wait_for([&] { return !cap.buf.text().empty(); }));
            EXPECT(cap.buf.text() == "alone\n");
        }
    }

    // a flood does not wait for the end: past the limit the lines are let out, the bar away for them (it comes back under them)
    {
        CaptureOne cap;
        {
            console::Printer printer;
            progress::begin("pack", {{"a", 1}});
            progress::enter("a", 10);
            progress::advance(5);
            EXPECT(wait_for([&] { return count_of(cap.buf.text(), "pack") >= 1; }));  // (the bar is on the screen)
            const std::string line(900, 'f');
            size_t sent = 0;
            while (sent <= console::kHeldLimit + 4000) {
                std::cout << line << "\n";
                sent += line.size() + 1;
            }
            // (the lines come out, and the bar is drawn again under them; the printer may be late)
            const auto came_out = [&](const std::string& s) {
                const size_t last_line = s.rfind('\n');
                return s.size() > console::kHeldLimit && last_line != std::string::npos && s.find("pack", last_line) != std::string::npos;
            };
            EXPECT(wait_for([&] { return came_out(cap.buf.text()); }));
            const std::string meanwhile = cap.buf.text();
            EXPECT(meanwhile.size() > console::kHeldLimit);  // (it came out)
            EXPECT(meanwhile.find("\r\x1b[2K" + std::string(40, 'f')) != std::string::npos);
            // ... and the bar is on the line under it: the last thing written is a frame of the bar
            const size_t last_line = meanwhile.rfind('\n');
            EXPECT(last_line != std::string::npos && meanwhile.find("pack", last_line) != std::string::npos);
            progress::end();
        }
    }
    set_env("NO_COLOR", nullptr);
    set_env("ABR_COLUMNS", nullptr);
    set_env("ABR_PROGRESS", "never");
}

void test_printer_wrap() {
    set_env("ABR_PROGRESS", "never");
    set_env("ABR_UNFILTERED_OUTPUT", nullptr);

    // a pipe (no terminal, no ABR_COLUMNS): nothing is wrapped
    set_env("ABR_COLUMNS", nullptr);
    {
        Capture cap;
        {
            console::Printer printer;
            std::cout << "key:   " << std::string(100, 'v') << " tail\n";
        }
        EXPECT(cap.out.str() == "key:   " + std::string(100, 'v') + " tail\n");
    }

    // ABR_COLUMNS is the width of the screen: lines that do not fit are broken, the ones that fit are not touched
    set_env("ABR_COLUMNS", "30");
    {
        Capture cap;
        {
            console::Printer printer;
            std::cout << "short  line  stays\n";
            std::cout << "key:   " << std::string(20, 'v') << " and more words here\n";
            std::cerr << "warning: " << std::string(70, 'w') << "\n";
            std::cout << "a\x1b[31m" << " red text that is longer than the screen is wide\n";
            std::cout << "tab\there and a long rest of a line that wraps\n";
            std::cout << "no line break at the end of this one, however long it may be";
        }
        const std::string out = cap.out.str(), err = cap.err.str();
        EXPECT(out.rfind("short  line  stays\n", 0) == 0);
        std::istringstream in(out);
        std::string line, all;
        std::vector<std::string> lines;
        while (std::getline(in, line)) lines.push_back(line);
        // (the last, which has no line break, is as it was)
        EXPECT(lines.back() == "no line break at the end of this one, however long it may be");
        for (size_t i = 0; i + 1 < lines.size(); ++i) EXPECT(chars_of(lines[i]) <= 29);
        EXPECT(out.find("key:   vvvvvvvvvvvvvvvvvvvv\n       and more words here\n") != std::string::npos);
        EXPECT(out.find('\x1b') == std::string::npos && out.find("a\\x1b[31m") != std::string::npos);  // (counted as it is shown)
        EXPECT(out.find('\t') == std::string::npos && out.find("tab     here and a long rest\n") != std::string::npos);
        std::istringstream in_err(err);
        int n = 0;
        while (std::getline(in_err, line)) {
            EXPECT(chars_of(line) <= 29);
            ++n;
        }
        EXPECT(n >= 3);  // (a word of 70 characters on lines of 29)
        std::string w;
        for (const char c : err)
            if (c == 'w') w += c;
        EXPECT(w.size() == 70 + 1);  // ("warning" has one w)
    }
    // the output left alone is left alone
    set_env("ABR_UNFILTERED_OUTPUT", "1");
    {
        Capture cap;
        {
            console::Printer printer;
            std::cout << "key:   " << std::string(100, 'v') << " tail\n";
        }
        EXPECT(cap.out.str() == "key:   " + std::string(100, 'v') + " tail\n");
    }
    set_env("ABR_UNFILTERED_OUTPUT", nullptr);

    // the width: ABR_COLUMNS when it names a number, else the terminal's (not here: 0)
    set_env("ABR_COLUMNS", "77");
    EXPECT(console::columns(1) == 77 && console::columns(2) == 77);
    for (const char* bad : {"0", "abc", "-5", "123456", ""}) {
        set_env("ABR_COLUMNS", bad);
        EXPECT(console::columns(999) == 0);  // (a descriptor that is no terminal)
    }
    set_env("ABR_COLUMNS", nullptr);
    EXPECT(console::columns(999) == 0);
}

}  // namespace

int run_console_tests() {
    std::printf("console: progress\n");
    test_progress();
    std::printf("console: the bar\n");
    test_bar();
    std::printf("console: the printer\n");
    test_printer();
    std::printf("console: wrapping\n");
    test_wrap();
    test_printer_wrap();
    std::printf("console: what waits for the bar\n");
    test_hold();
    if (g_failures == 0) std::printf("console: all passed\n");
    else std::printf("console: %d FAILED\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
