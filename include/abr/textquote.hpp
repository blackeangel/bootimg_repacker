// SPDX-License-Identifier: GPL-3.0-or-later
//
// How a piece of text -- a command line, a name, a path -- goes into one line of a text file that people edit
// (manifest.txt, ramdisk.meta) and comes back as the same bytes.
//
// What a plain line cannot hold: a line break (what follows it would be taken for lines of the file: a command line
// in a damaged or a hostile image could add keys to a manifest that way), white space at either end (the readers
// drop it, so the next repack would build another image), a double quote at the start (it opens a quoted string),
// a backslash, and the other control bytes (a terminal that is shown them does what they say). Such a text is written
// in double quotes with the escapes of C. Anything else is written as it is, so that the files stay what a person
// would write.
#pragma once

#include <streambuf>
#include <string>
#include <string_view>

namespace abr::textquote {

// `s` for the end of a line: itself when a reader gets exactly that back, else in double quotes with \\ \" \n \t \r
// and \xNN for the other control bytes (0x00-0x1F, 0x7F). Bytes from 0x80 on are left as they are (UTF-8 stays
// readable, and any other byte survives). The empty string is written as "" only when `quote_empty` is set.
std::string quote(std::string_view s, bool quote_empty);

// `s` for a message that is shown on a terminal (`info`, a warning that names something an image holds): what `quote` makes of
// it, and also the bytes from 0x80 on that are not well-formed UTF-8, as \xNN, and the C1 controls (U+0080-U+009F, in UTF-8 the
// bytes C2 80 to C2 9F: a terminal in UTF-8 mode takes U+009B for the start of an escape sequence, as it takes ESC [) as \xC2\xNN.
// What is left is text that a terminal only shows. `unquote` reads it back as the bytes it was made of.
std::string quote_shown(std::string_view s);

// The reverse, for the rest of a line after any white space that leads it: a string in double quotes is unescaped,
// anything else is itself without the white space at its end. false, with `why` saying what is wrong, for a quoted
// string that is not closed, that ends in a backslash or in a \x without two hexadecimal digits, that has another
// escape, or that is followed by anything but white space.
bool unquote(std::string_view s, std::string& out, std::string& why);

// What a stream gets when it is given to a terminal: the buffer of std::cout or std::cerr behind this one. Text that is written to
// it goes on as it is, except what a terminal would act on, which is written as the \xNN of `quote`: the control characters but
// the line break and the tab, the C1 controls, and the bytes that are not well-formed UTF-8. It is the last line of defence for
// everything abr prints: a name or a command line out of an image is escaped where it is printed (`quote_shown`), and this
// keeps a place where that was forgotten from handing the control sequences of an image to a terminal. A character that is
// written in pieces (a byte at a time) is judged as a whole; what is left of one at sync() is escaped. Not for several threads at
// once (abr's messages are printed one at a time: see say() in main.cpp).
class TerminalSafeBuf final : public std::streambuf {
public:
    explicit TerminalSafeBuf(std::streambuf* target) : target_(target) {}
    ~TerminalSafeBuf() override;
    TerminalSafeBuf(const TerminalSafeBuf&) = delete;
    TerminalSafeBuf& operator=(const TerminalSafeBuf&) = delete;

protected:
    int_type overflow(int_type c) override;
    std::streamsize xsputn(const char* s, std::streamsize n) override;
    int sync() override;

private:
    bool write(const char* s, size_t n);
    bool flush_pending();
    std::streambuf* target_;
    std::string pending_;  // the beginning of a UTF-8 character whose end has not been written yet
};

}  // namespace abr::textquote
