// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::console -- what the person at the terminal sees: a printer thread, and a progress bar.
//
// While a Printer lives, everything written to std::cout and std::cerr goes to a thread of its own, which is the only one that writes to
// the terminal (or file, or pipe) behind them: the threads that work never wait for a terminal, a line that a thread writes is never
// torn by another's, and the lines come out in the order they were written, the two streams together. Each stream's text is made safe
// first (abr/textquote.hpp: what a terminal would act on is written as an escape), the last defence for text that an image holds and a
// message forgot to quote; ABR_UNFILTERED_OUTPUT=1 turns that off (the fuzzer looks for such messages with it).
//
// When a command is in progress (abr/progress.hpp) that takes more than a moment and the output is a terminal, the printer draws a bar
// on the last line of it -- a gradient, the share that is done, the stage and the jobs in progress, the time -- and it stays where it
// is: what the command says while the bar is there is kept, and comes out, after the bar is gone, when the command is over (a bar that
// is taken away for every line and drawn again below it jumps about the screen; and what a pipe would have got is the same lines in the
// same order). A flood of lines does not wait for the end: past kHeldLimit bytes they are let out, the bar away for them. Where the
// output is not a terminal there is no bar and nothing but the lines.
//
// A line that is longer than the terminal is broken at its blanks, not in the middle of a word, and the next lines of it are indented
// -- under the value of a `key: value` line, else by two blanks -- so that a narrow terminal (a phone's: 56 columns) shows a column and
// not a mess (wrap_message). A path that is longer than the room is broken behind a `/`. Where the output is no terminal nothing is
// wrapped, and the tables (abr/layout.hpp) are the wide ones.
//
//   NO_COLOR=1            no colours (the bar is drawn in plain characters)
//   ABR_PROGRESS=never    no bar (always: draw it at once, also where the output is no terminal -- the tests of the bar do that --
//                         and treat stdout as being on the same screen as the bar)
//   ABR_COLUMNS=N         the width the output is made for, in place of the terminal's (and where there is no terminal: lines are
//                         wrapped to it, and tables are made for it)
//   TERM=dumb, or none    no bar (a terminal that cannot move the cursor back to the start of the line)
#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "abr/progress.hpp"

namespace abr::console {

// The width of the screen that stream `fd` (1: stdout, 2: stderr) goes to: ABR_COLUMNS when that names a number, else the width of
// the terminal (80 when it does not say, COLUMNS before that); 0 when there is no screen -- a pipe, a file -- and no ABR_COLUMNS.
// What is made for a width (a table, the help) is made for this, and is the same text everywhere when it is 0.
int columns(int fd);

// `text` broken at its blanks into lines of at most `width` characters (UTF-8 characters, not bytes). The first line is indented by
// `first` blanks, the others by `next`; the blanks between two words stay as they are, the blanks at a break are dropped. With `groups`,
// what is in parentheses is not broken when it fits on a line of its own ("(97479936 bytes)": for the cells of a table, not for
// prose, where it leaves the lines short). A word that does not fit on a line of its own
// is put on one, and broken there: behind a `/` or a `\` when there is one in the second half of the room, else behind another
// separator (- _ . , ; : = + @), else where the room ends. A width that leaves no room for 16 characters beside the indent is
// made to. Never an empty list (empty text is one empty line); no line ends in a blank.
std::vector<std::string> wrap(std::string_view text, size_t width, size_t first = 0, size_t next = 0, bool groups = false);

// One line of a message (`line` has no line break) for a terminal `width` characters wide: itself when it fits, else wrap() of it (with groups) with
// the indent it has, and for the lines after the first the indent of its value when it is a `key:   value` line (the key at most 24
// characters, the value starting before the middle of the line), else two blanks more than it has.
std::vector<std::string> wrap_message(std::string_view line, size_t width);

enum class Colour { NONE, ANSI16, ANSI256, TRUECOLOUR };

struct BarStyle {
    Colour colour = Colour::TRUECOLOUR;
    bool utf8 = true;  // false: the bar is made of ASCII characters
};

// The line the bar is, for a terminal `columns` wide (the last column is left alone: a line that fills it wraps in some terminals):
// it starts with a carriage return and ends with what clears the rest of the line, and holds no line break. `frame` moves what is
// animated (about 12 a second). Nothing but the text from `snapshot` (cleaned of whatever a terminal would act on) and the escape
// sequences of the colour that is asked for is in it.
std::string render_bar(const progress::Snapshot& snapshot, const BarStyle& style, int columns, unsigned frame);

// How many bytes of lines the printer keeps for the end of a command while the bar is on the screen; more than that comes out at once.
inline constexpr size_t kHeldLimit = 1 << 20;

class Printer {
public:
    Printer();
    ~Printer();  // what was written is all written, the bar is gone, std::cout and std::cerr are as they were
    Printer(const Printer&) = delete;
    Printer& operator=(const Printer&) = delete;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace abr::console
