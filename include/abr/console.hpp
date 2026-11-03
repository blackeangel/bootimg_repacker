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
// on the last line of it -- a gradient, the share that is done, the stage and the jobs in progress, the time -- and takes it away for
// the lines that are written and at the end, so that what is written is what a pipe would have got. Where the output is not a terminal
// there is no bar and nothing but the lines.
//
//   NO_COLOR=1            no colours (the bar is drawn in plain characters)
//   ABR_PROGRESS=never    no bar (always: draw it where the output is no terminal, at once -- the tests of the bar do that;
//                         ABR_COLUMNS=N is the width then)
//   TERM=dumb, or none    no bar (a terminal that cannot move the cursor back to the start of the line)
#pragma once

#include <memory>
#include <string>

#include "abr/progress.hpp"

namespace abr::console {

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
