// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/console.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iostream>
#include <mutex>
#include <optional>
#include <streambuf>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "abr/textquote.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace abr::console {

// ---------------------------------------------------------------- the bar --

namespace {

struct Rgb {
    int r, g, b;
};

Rgb mix(Rgb a, Rgb b, double t) {
    t = std::clamp(t, 0.0, 1.0);
    const auto one = [&](int x, int y) { return static_cast<int>(std::lround(x + (y - x) * t)); };
    return {one(a.r, b.r), one(a.g, b.g), one(a.b, b.b)};
}

// Left to right: violet, sky, mint.
Rgb gradient(double t) {
    constexpr Rgb violet{127, 90, 240}, sky{44, 177, 255}, mint{45, 226, 166};
    t = std::clamp(t, 0.0, 1.0);
    return t < 0.5 ? mix(violet, sky, t * 2) : mix(sky, mint, (t - 0.5) * 2);
}

constexpr Rgb kSky{44, 177, 255};
constexpr Rgb kMint{45, 226, 166};
constexpr Rgb kWhite{255, 255, 255};
constexpr Rgb kEmpty{62, 68, 82};

int xterm_256(Rgb c) {
    const auto level = [](int v) { return static_cast<int>(std::lround(v / 255.0 * 5)); };
    return 16 + 36 * level(c.r) + 6 * level(c.g) + level(c.b);
}

// What is written to change the colour or the weight of the text that follows; nothing where there are no colours, and only when
// something changes.
class Painter {
public:
    explicit Painter(Colour colour) : colour_(colour) {}

    void rgb(Rgb c, bool bold = false) {
        switch (colour_) {
            case Colour::NONE: return;
            case Colour::TRUECOLOUR:
                set((bold ? "1;" : "") + std::string("38;2;") + std::to_string(c.r) + ";" + std::to_string(c.g) + ";" + std::to_string(c.b));
                return;
            case Colour::ANSI256: set((bold ? "1;" : "") + std::string("38;5;") + std::to_string(xterm_256(c))); return;
            case Colour::ANSI16:
                // (cyan for the cooler half of the gradient, green for the rest)
                set(std::string(bold ? "1;" : "") + (c.g > 200 && c.b < 190 ? "32" : "36"));
                return;
        }
    }
    void dim() {
        if (colour_ == Colour::NONE) return;
        set(colour_ == Colour::ANSI16 ? "90" : "2");
    }
    void grey() {
        switch (colour_) {
            case Colour::NONE: return;
            case Colour::TRUECOLOUR: set("38;2;" + std::to_string(kEmpty.r) + ";" + std::to_string(kEmpty.g) + ";" + std::to_string(kEmpty.b)); return;
            case Colour::ANSI256: set("38;5;238"); return;
            case Colour::ANSI16: set("90"); return;
        }
    }
    void plain() {
        if (colour_ == Colour::NONE) return;
        set("0");
    }
    void bold() {
        if (colour_ == Colour::NONE) return;
        set("1");
    }
    void text(std::string_view s) { out_.append(s); }
    std::string finish() {
        if (colour_ != Colour::NONE && !last_.empty() && last_ != "0") out_ += "\x1b[0m";
        return std::move(out_);
    }

private:
    void set(std::string code) {
        if (code == last_) return;
        // (every sequence starts from nothing: the one before is not a base to add to)
        out_ += "\x1b[0;" + code + "m";
        last_ = std::move(code);
    }
    Colour colour_;
    std::string out_;
    std::string last_;
};

// What a text is when a terminal is to be handed it: control characters, the C1 controls and what is not UTF-8 are a '?' -- and, for
// a terminal that is not known to take UTF-8 (`utf8` false), every character that is not ASCII.
std::string clean(std::string_view s, bool utf8) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        size_t len = 1;
        bool ok = true;
        if (c < 0x20 || c == 0x7f) ok = false;
        else if (c >= 0x80) {
            len = c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : c >= 0xc2 ? 2 : 0;
            if (len == 0 || i + len > s.size()) ok = false;
            for (size_t k = 1; ok && k < len; ++k) ok = (static_cast<unsigned char>(s[i + k]) & 0xc0) == 0x80;
            if (ok && len == 2 && c == 0xc2 && static_cast<unsigned char>(s[i + 1]) < 0xa0) ok = false;  // C1 controls
            if (ok && len == 3 && c == 0xe2 && static_cast<unsigned char>(s[i + 1]) == 0x80 &&
                static_cast<unsigned char>(s[i + 2]) >= 0xa8 && static_cast<unsigned char>(s[i + 2]) <= 0xae)
                ok = false;  // line/paragraph separators, bidirectional overrides
        }
        if (!ok) {
            out += '?';
            i += 1;
        } else if (!utf8 && len > 1) {
            out += '?';
            i += len;
        } else {
            out.append(s.substr(i, len));
            i += len;
        }
    }
    return out;
}

size_t width_of(std::string_view s) {
    size_t n = 0;
    for (const char c : s) n += (static_cast<unsigned char>(c) & 0xc0) != 0x80;
    return n;
}

// The first `n` characters of `s` (UTF-8 characters, not bytes); when that cuts, the last of them is the ellipsis.
std::string fit(std::string_view s, size_t n, bool utf8) {
    if (width_of(s) <= n) return std::string(s);
    const std::string_view mark = utf8 ? "\xe2\x80\xa6" : "~";
    if (n == 0) return {};
    size_t keep = n - 1, i = 0, seen = 0;
    while (i < s.size() && seen < keep) {
        ++i;
        while (i < s.size() && (static_cast<unsigned char>(s[i]) & 0xc0) == 0x80) ++i;
        ++seen;
    }
    return std::string(s.substr(0, i)) + std::string(mark);
}

std::string seconds_text(double s) {
    if (s < 10) {
        const int tenths = static_cast<int>(s * 10);
        return std::to_string(tenths / 10) + "." + std::to_string(tenths % 10) + " s";
    }
    const int whole = static_cast<int>(s);
    if (whole < 60) return std::to_string(whole) + " s";
    const int sec = whole % 60;
    return std::to_string(whole / 60) + "m " + (sec < 10 ? "0" : "") + std::to_string(sec) + "s";
}

}  // namespace

std::string render_bar(const progress::Snapshot& s, const BarStyle& style, int columns, unsigned frame) {
    if (!s.active) return {};
    const size_t usable = static_cast<size_t>(std::max(columns, 20)) - 1;
    Painter p(style.colour);

    const double fraction = std::clamp(s.fraction, 0.0, 1.0);
    const int percent = fraction >= 1.0 ? 100 : static_cast<int>(fraction * 100);
    std::string pct = std::to_string(percent) + "%";
    while (pct.size() < 4) pct.insert(pct.begin(), ' ');
    const std::string command = fit(clean(s.command, style.utf8), 10, style.utf8);
    const std::string elapsed = seconds_text(s.seconds);

    static const char* const kBraille[] = {"\xe2\xa0\x8b", "\xe2\xa0\x99", "\xe2\xa0\xb9", "\xe2\xa0\xb8", "\xe2\xa0\xbc",
                                           "\xe2\xa0\xb4", "\xe2\xa0\xa6", "\xe2\xa0\xa7", "\xe2\xa0\x87", "\xe2\xa0\x8f"};
    static const char kAscii[] = {'|', '/', '-', '\\'};
    const std::string spinner = style.utf8 ? std::string(kBraille[frame % 10]) : std::string(1, kAscii[frame % 4]);

    // The room: spinner and a space, the command and a space, [the bar, a space, the share,] [two spaces, the words, a space, the time].
    const size_t head = 2 + width_of(command) + 1;
    const size_t share = 1 + pct.size();
    size_t remaining = usable > head + share ? usable - head - share : 0;
    const size_t time_room = 2 + elapsed.size();
    size_t bar_w = 0, words_w = 0;
    bool with_time = false;
    if (remaining >= 8) {
        if (remaining >= 40) {
            with_time = true;
            remaining -= time_room;
            bar_w = std::clamp<size_t>(remaining / 2, 10, 34);
            words_w = remaining > bar_w + 2 ? remaining - bar_w - 2 : 0;
            if (words_w < 8) words_w = 0;
        } else {
            bar_w = std::min<size_t>(remaining, 34);
        }
    }

    // The head.
    p.rgb(gradient(0));
    p.text(spinner);
    p.plain();
    p.text(" ");
    p.rgb(kSky, true);
    p.text(command);
    p.plain();
    p.text(" ");

    // The bar.
    if (bar_w > 0) {
        const bool utf8 = style.utf8;
        const size_t cells = utf8 ? bar_w : bar_w - 2;  // (the brackets of the ASCII bar are in the width)
        const size_t halves = static_cast<size_t>(std::lround(fraction * static_cast<double>(cells) * 2));
        const size_t whole = std::min(halves / 2, cells);
        const bool half = utf8 && (halves % 2 == 1) && whole < cells;
        const double wave = std::fmod(frame * 0.8, static_cast<double>(cells) + 8) - 4;  // the brightness that runs along what is filled
        // What searches while the work is not known: three cells that go to and fro on what is not filled.
        long scan = -10;
        if (!s.determinate && fraction < 1.0 && cells > whole + 4) {
            const size_t room = cells - whole - 3;  // the places the first of the three can be at
            const size_t period = room * 2;
            const size_t k = frame % (period == 0 ? 1 : period);
            scan = static_cast<long>(whole + (k < room ? k : period - k));
        }
        if (!utf8) p.text("[");
        for (size_t i = 0; i < cells; ++i) {
            const double t = cells > 1 ? static_cast<double>(i) / static_cast<double>(cells - 1) : 0;
            const bool filled = i < whole;
            const bool edge = half && i == whole;
            const bool searching = static_cast<long>(i) >= scan && static_cast<long>(i) < scan + 3;
            if (filled || edge) {
                const double glow = std::max(0.0, 1.0 - std::fabs(static_cast<double>(i) - wave) / 3.0) * 0.45;
                p.rgb(mix(gradient(t), kWhite, glow));
                p.text(utf8 ? (edge ? "\xe2\x95\xb8" : "\xe2\x94\x81") : "#");
            } else if (searching) {
                p.rgb(mix(gradient(t), kWhite, 0.2));
                p.text(utf8 ? "\xe2\x94\x81" : "*");
            } else if (s.determinate && i == whole && fraction < 1.0) {
                // The cell the work is at breathes, so that a stage that is long about a step does not look stuck.
                const double breath = 0.5 + 0.5 * std::sin(frame * 0.6);
                p.rgb(mix(kEmpty, gradient(t), 0.25 + 0.6 * breath));
                p.text(utf8 ? "\xe2\x94\x81" : "-");
            } else {
                p.grey();
                p.text(utf8 ? "\xe2\x94\x81" : "-");
            }
        }
        p.plain();
        if (!utf8) p.text("]");
        p.text(" ");
    }

    // The share, the words, the time.
    p.bold();
    p.text(pct);
    p.plain();
    if (words_w > 0) {
        std::string words = clean(s.stage, style.utf8);
        if (!s.activity.empty()) words += std::string(words.empty() ? "" : (style.utf8 ? " \xc2\xb7 " : " - ")) + clean(s.activity, style.utf8);
        words = fit(words, words_w, style.utf8);
        p.text("  ");
        p.rgb(kMint);
        p.text(words);
        p.plain();
        p.text(std::string(words_w - width_of(words), ' '));
    }
    if (with_time) {
        p.text("  ");
        p.dim();
        p.text(elapsed);
    }
    return "\r" + p.finish() + "\x1b[K";
}

// ---------------------------------------------------------------- the terminal --

namespace {

#ifdef _WIN32
HANDLE handle_of(int fd) { return reinterpret_cast<HANDLE>(_get_osfhandle(fd)); }
bool is_terminal(int fd) {
    DWORD mode = 0;
    const HANDLE h = handle_of(fd);
    return h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode) != 0;
}
int terminal_width(int fd) {
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (GetConsoleScreenBufferInfo(handle_of(fd), &info)) return info.srWindow.Right - info.srWindow.Left + 1;
    return 0;
}
#else
bool is_terminal(int fd) { return ::isatty(fd) != 0; }
int terminal_width(int fd) {
    winsize ws{};
    if (::ioctl(fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
    return 0;
}
#endif

std::string env(const char* name) {
    const char* v = std::getenv(name);
    return v ? v : "";
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool contains(const std::string& s, const char* part) { return s.find(part) != std::string::npos; }

bool locale_is_utf8() {
#ifdef _WIN32
    return true;  // (the console is put in UTF-8: Utf8Console)
#else
    for (const char* name : {"LC_ALL", "LC_CTYPE", "LANG"}) {
        const std::string v = lower(env(name));
        if (!v.empty()) return contains(v, "utf-8") || contains(v, "utf8");
    }
    return false;
#endif
}

Colour colour_level() {
    if (!env("NO_COLOR").empty()) return Colour::NONE;
    const std::string colorterm = lower(env("COLORTERM"));
    if (contains(colorterm, "truecolor") || contains(colorterm, "24bit")) return Colour::TRUECOLOUR;
#ifdef _WIN32
    return Colour::TRUECOLOUR;
#else
    const std::string term = lower(env("TERM"));
    if (contains(term, "direct")) return Colour::TRUECOLOUR;
    if (contains(term, "256color")) return Colour::ANSI256;
    return Colour::ANSI16;
#endif
}

// What a signal that ends the process finds: whether there is a bar on the line to take away first.
std::atomic<bool> g_bar_on_screen{false};
int g_bar_fd = 2;

#ifndef _WIN32
void on_signal(int sig) {
    if (g_bar_on_screen.load()) {
        static const char erase[] = "\r\x1b[2K";
        const ssize_t ignored = ::write(g_bar_fd, erase, sizeof erase - 1);
        (void)ignored;
    }
    ::signal(sig, SIG_DFL);
    ::raise(sig);
}
#endif

}  // namespace

// ---------------------------------------------------------------- the printer --

struct Printer::Impl {
    struct Item {
        int stream;  // 0: std::cout, 1: std::cerr
        std::string text;
    };

    // std::cout and std::cerr write here: a line a thread has written goes to the queue as one piece.
    class Queue final : public std::streambuf {
    public:
        Queue(Impl& owner, int stream) : owner_(owner), stream_(stream) {}
        // Hands over what this thread has written of a line that is not finished (at the end: a message that has no line break).
        void hand_over_partial() {
            std::string& mine = partial();
            if (!mine.empty()) {
                owner_.push(stream_, std::move(mine));
                mine.clear();
            }
        }

    protected:
        int_type overflow(int_type c) override {
            if (traits_type::eq_int_type(c, traits_type::eof())) return traits_type::not_eof(c);
            const char ch = traits_type::to_char_type(c);
            put(&ch, 1);
            return c;
        }
        std::streamsize xsputn(const char* s, std::streamsize n) override {
            put(s, static_cast<size_t>(n));
            return n;
        }
        // (a flush does not hand over a line that is not finished: std::cerr flushes after each `<<`, and the pieces of one line
        // are not to be torn apart by what another thread writes between them)
        int sync() override { return 0; }

    private:
        std::string& partial() {
            thread_local std::string mine[2];
            return mine[stream_];
        }
        void put(const char* s, size_t n) {
            std::string& mine = partial();
            mine.append(s, n);
            const size_t last = mine.rfind('\n');
            if (last == std::string::npos) return;
            owner_.push(stream_, mine.substr(0, last + 1));
            mine.erase(0, last + 1);
        }
        Impl& owner_;
        int stream_;
    };

    Impl() : out_q(*this, 0), err_q(*this, 1) {}

    void push(int stream, std::string text) {
        {
            std::lock_guard<std::mutex> lock(mu);
            queue.push_back({stream, std::move(text)});
        }
        cv.notify_one();
    }

    int columns() const {
        if (forced_columns > 0) return forced_columns;
        if (const int w = terminal_width(bar_stream == 1 ? 2 : 1); w > 0) return w;
        if (const std::string c = env("COLUMNS"); !c.empty() && c.size() <= 4) {
            const int w = std::atoi(c.c_str());
            if (w > 0) return w;
        }
        return 80;
    }

    void erase_bar() {
        static const char erase[] = "\r\x1b[2K";
        real[bar_stream]->sputn(erase, sizeof erase - 1);
        real[bar_stream]->pubsync();
        bar_visible = false;
        g_bar_on_screen = false;
    }

    void write_item(const Item& it) {
        const int st = it.stream;
        // The bar is on the terminal the line goes to, or on the one beside it that is a terminal as well.
        if (bar_visible && (st == bar_stream || (is_tty[st] && is_tty[bar_stream]))) erase_bar();
        std::streambuf* out = safe[st] ? &*safe[st] : real[st];
        out->sputn(it.text.data(), static_cast<std::streamsize>(it.text.size()));
        out->pubsync();
        line_open[st] = !it.text.empty() && it.text.back() != '\n';
    }

    void draw_bar() {
        const progress::Snapshot s = progress::snapshot();
        if (!s.active) {
            if (bar_visible) erase_bar();
            return;
        }
        if (s.seconds * 1000 < show_after_ms || line_open[bar_stream]) return;
        const unsigned frame = static_cast<unsigned>(s.seconds * 12.5);
        const std::string line = render_bar(s, style, columns(), frame);
        real[bar_stream]->sputn(line.data(), static_cast<std::streamsize>(line.size()));
        real[bar_stream]->pubsync();
        bar_visible = true;
        g_bar_on_screen = true;
    }

    void run() {
        std::unique_lock<std::mutex> lock(mu);
        for (;;) {
            cv.wait_for(lock, bar_enabled ? std::chrono::milliseconds(80) : std::chrono::hours(1),
                        [&] { return stopping || !queue.empty(); });
            std::deque<Item> items;
            items.swap(queue);
            const bool last = stopping && items.empty();
            lock.unlock();
            for (const Item& it : items) write_item(it);
            if (bar_enabled) {
                if (last) {
                    if (bar_visible) erase_bar();
                } else if (items.empty()) {
                    // (the bar comes back on the tick after a line was written, not at once: the line that ends a command is not
                    // followed by one more drawing of a bar that is over)
                    draw_bar();
                }
            }
            lock.lock();
            if (last) break;
        }
    }

    Queue out_q, err_q;
    std::streambuf* before[2] = {nullptr, nullptr};  // what std::cout and std::cerr had
    std::streambuf* real[2] = {nullptr, nullptr};    // the same: where the printer writes to
    std::optional<textquote::TerminalSafeBuf> safe[2];
    bool is_tty[2] = {false, false};
    bool line_open[2] = {false, false};  // (printer thread only) the last thing written to the stream does not end a line

    bool bar_enabled = false;
    int bar_stream = 1;
    bool bar_visible = false;  // (printer thread only)
    BarStyle style;
    int forced_columns = 0;
    int show_after_ms = 250;

    std::mutex mu;
    std::condition_variable cv;
    std::deque<Item> queue;
    bool stopping = false;
    std::thread thread;

#ifdef _WIN32
    HANDLE console_handle = INVALID_HANDLE_VALUE;
    DWORD console_mode = 0;
    bool console_mode_changed = false;
#else
    struct sigaction old_int {};
    struct sigaction old_term {};
    bool signals_taken = false;
#endif
};

Printer::Printer() : impl_(std::make_unique<Impl>()) {
    Impl& m = *impl_;
    std::cout.flush();
    std::cerr.flush();
    m.before[0] = m.real[0] = std::cout.rdbuf();
    m.before[1] = m.real[1] = std::cerr.rdbuf();
    const std::string unfiltered = env("ABR_UNFILTERED_OUTPUT");
    if (unfiltered.empty() || unfiltered == "0") {
        m.safe[0].emplace(m.real[0]);
        m.safe[1].emplace(m.real[1]);
    }
    m.is_tty[0] = is_terminal(1);
    m.is_tty[1] = is_terminal(2);

    // The bar: on stderr when that is a terminal (stdout may be a pipe for what the person wants to keep), else on stdout when that is.
    const std::string mode = lower(env("ABR_PROGRESS"));
    const bool never = mode == "never" || mode == "0" || mode == "off" || mode == "no" || mode == "false";
    const bool always = mode == "always" || mode == "force";
    const std::string term = lower(env("TERM"));
    bool terminal_ok = m.is_tty[0] || m.is_tty[1];
    m.bar_stream = m.is_tty[1] ? 1 : 0;
#ifndef _WIN32
    if (term.empty() || term == "dumb") terminal_ok = false;
#else
    if (terminal_ok) {
        // (a console that is told to understand the escape sequences; where it will not, there is no bar)
        const int fd = m.bar_stream == 1 ? 2 : 1;
        m.console_handle = handle_of(fd);
        DWORD mode_now = 0;
        if (GetConsoleMode(m.console_handle, &mode_now) != 0) {
            m.console_mode = mode_now;
            if ((mode_now & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0) {
                // (already)
            } else if (SetConsoleMode(m.console_handle, mode_now | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0) {
                m.console_mode_changed = true;
            } else {
                terminal_ok = false;
            }
        } else {
            terminal_ok = false;
        }
    }
#endif
    m.bar_enabled = !never && (always || terminal_ok);
    if (always && !terminal_ok) {
        m.bar_stream = 1;
        m.show_after_ms = 0;
        if (const std::string c = env("ABR_COLUMNS"); !c.empty() && c.size() <= 4) m.forced_columns = std::atoi(c.c_str());
    }
    m.style.colour = colour_level();
    m.style.utf8 = locale_is_utf8();
    g_bar_fd = m.bar_stream == 1 ? 2 : 1;

    try {
        m.thread = std::thread([&m] { m.run(); });
    } catch (const std::system_error&) {
        impl_.reset();  // (no thread to be had: the output stays as it is, written by whoever writes it)
        return;
    }
    std::cout.rdbuf(&m.out_q);
    std::cerr.rdbuf(&m.err_q);
#ifndef _WIN32
    if (m.bar_enabled) {
        struct sigaction sa {};
        sa.sa_handler = on_signal;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        m.signals_taken = ::sigaction(SIGINT, &sa, &m.old_int) == 0 && ::sigaction(SIGTERM, &sa, &m.old_term) == 0;
    }
#endif
}

Printer::~Printer() {
    if (!impl_) return;
    Impl& m = *impl_;
    std::cout.flush();
    std::cerr.flush();
    m.out_q.hand_over_partial();
    m.err_q.hand_over_partial();
    {
        std::lock_guard<std::mutex> lock(m.mu);
        m.stopping = true;
    }
    m.cv.notify_all();
    if (m.thread.joinable()) m.thread.join();
    std::cout.rdbuf(m.before[0]);
    std::cerr.rdbuf(m.before[1]);
#ifdef _WIN32
    if (m.console_mode_changed) SetConsoleMode(m.console_handle, m.console_mode);
#else
    if (m.signals_taken) {
        ::sigaction(SIGINT, &m.old_int, nullptr);
        ::sigaction(SIGTERM, &m.old_term, nullptr);
    }
#endif
}

}  // namespace abr::console
