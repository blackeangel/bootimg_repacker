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
//     drawn while a command is in progress and is gone before a line is written and at the end.
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iostream>
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

}  // namespace

int run_console_tests() {
    std::printf("console: progress\n");
    test_progress();
    std::printf("console: the bar\n");
    test_bar();
    std::printf("console: the printer\n");
    test_printer();
    if (g_failures == 0) std::printf("console: all passed\n");
    else std::printf("console: %d FAILED\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
