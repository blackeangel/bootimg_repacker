// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/textquote.hpp"

#include <cstdio>

namespace abr::textquote {

namespace {
bool blank(char c) { return c == ' ' || c == '\t'; }

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

enum class Utf8 { Good, Bad, Cut };

// The character that starts `s` (not empty), by RFC 3629: no overlong form, no surrogate, nothing above U+10FFFF. Good, with
// its length in `n`; Cut when what there is of it is right so far and `s` ends (it may go on in what is written next); Bad
// when it is no UTF-8.
Utf8 utf8_scan(std::string_view s, size_t& n) {
    const unsigned char c = static_cast<unsigned char>(s[0]);
    unsigned lo = 0x80, hi = 0xBF;
    if (c < 0x80) {
        n = 1;
        return Utf8::Good;
    } else if (c >= 0xC2 && c <= 0xDF) {
        n = 2;
    } else if (c >= 0xE0 && c <= 0xEF) {
        n = 3;
        if (c == 0xE0) lo = 0xA0;  // (no overlong form)
        if (c == 0xED) hi = 0x9F;  // (no surrogate)
    } else if (c >= 0xF0 && c <= 0xF4) {
        n = 4;
        if (c == 0xF0) lo = 0x90;
        if (c == 0xF4) hi = 0x8F;  // (nothing above U+10FFFF)
    } else {
        return Utf8::Bad;
    }
    for (size_t i = 1; i < n; ++i) {
        if (i >= s.size()) return Utf8::Cut;
        const unsigned char d = static_cast<unsigned char>(s[i]);
        if (d < (i == 1 ? lo : 0x80u) || d > (i == 1 ? hi : 0xBFu)) return Utf8::Bad;
    }
    return Utf8::Good;
}

// The length of the well-formed character that starts `s`; 0 when there is none (or it is cut off).
size_t utf8_length(std::string_view s) {
    size_t n = 0;
    return utf8_scan(s, n) == Utf8::Good ? n : 0;
}

void escape_byte(std::string& out, unsigned char c) {
    char buf[8];
    std::snprintf(buf, sizeof buf, "\\x%02x", c);
    out += buf;
}

std::string quote_impl(std::string_view s, bool quote_empty, bool for_terminal) {
    bool plain = !s.empty() ? !blank(s.front()) && s.front() != '"' && !blank(s.back()) : !quote_empty;
    std::string body;
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c >= 0x80 && for_terminal) {
            const size_t n = utf8_length(s.substr(i));
            if (n == 0) {  // not UTF-8: a byte that a terminal may take for something of its own
                escape_byte(body, c);
                plain = false;
                ++i;
            } else if (c == 0xC2 && static_cast<unsigned char>(s[i + 1]) < 0xA0) {  // U+0080-U+009F, the C1 controls
                escape_byte(body, c);
                escape_byte(body, static_cast<unsigned char>(s[i + 1]));
                plain = false;
                i += 2;
            } else {
                body.append(s.substr(i, n));
                i += n;
            }
            continue;
        }
        ++i;
        switch (c) {
            case '\\': body += "\\\\"; plain = false; break;
            case '"': body += "\\\""; break;
            case '\n': body += "\\n"; plain = false; break;
            case '\t': body += "\\t"; plain = false; break;
            case '\r': body += "\\r"; plain = false; break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    escape_byte(body, c);
                    plain = false;
                } else {
                    body += static_cast<char>(c);
                }
        }
    }
    return plain ? std::string(s) : "\"" + body + "\"";
}
}  // namespace

std::string quote(std::string_view s, bool quote_empty) { return quote_impl(s, quote_empty, false); }

std::string quote_shown(std::string_view s) { return quote_impl(s, false, true); }

// ---- TerminalSafeBuf ---------------------------------------------------------------------------------------------------

namespace {
bool is_c1(std::string_view s) { return s.size() >= 2 && static_cast<unsigned char>(s[0]) == 0xC2 && static_cast<unsigned char>(s[1]) < 0xA0; }
}  // namespace

bool TerminalSafeBuf::write(const char* s, size_t n) {
    std::string in = std::move(pending_);
    pending_.clear();
    in.append(s, n);
    std::string out;
    out.reserve(in.size() + 8);
    for (size_t i = 0; i < in.size();) {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        if (c < 0x80) {
            if ((c < 0x20 && c != '\n' && c != '\t') || c == 0x7F) escape_byte(out, c);
            else out += static_cast<char>(c);
            ++i;
            continue;
        }
        const std::string_view rest(in.data() + i, in.size() - i);
        size_t len = 0;
        switch (utf8_scan(rest, len)) {
            case Utf8::Good:
                if (is_c1(rest)) {
                    escape_byte(out, c);
                    escape_byte(out, static_cast<unsigned char>(in[i + 1]));
                } else {
                    out.append(rest.substr(0, len));
                }
                i += len;
                break;
            case Utf8::Cut:  // the end of a character comes with what is written next (or sync() makes escapes of it)
                pending_.assign(rest);
                i = in.size();
                break;
            case Utf8::Bad:
                escape_byte(out, c);
                ++i;
                break;
        }
    }
    return out.empty() || target_->sputn(out.data(), static_cast<std::streamsize>(out.size())) == static_cast<std::streamsize>(out.size());
}

bool TerminalSafeBuf::flush_pending() {
    if (pending_.empty()) return true;
    std::string out;
    for (unsigned char c : pending_) escape_byte(out, c);
    pending_.clear();
    return target_->sputn(out.data(), static_cast<std::streamsize>(out.size())) == static_cast<std::streamsize>(out.size());
}

TerminalSafeBuf::~TerminalSafeBuf() { flush_pending(); }

TerminalSafeBuf::int_type TerminalSafeBuf::overflow(int_type c) {
    if (traits_type::eq_int_type(c, traits_type::eof())) return traits_type::not_eof(c);
    const char ch = traits_type::to_char_type(c);
    return write(&ch, 1) ? c : traits_type::eof();
}

std::streamsize TerminalSafeBuf::xsputn(const char* s, std::streamsize n) {
    return write(s, static_cast<size_t>(n)) ? n : 0;
}

int TerminalSafeBuf::sync() { return flush_pending() && target_->pubsync() == 0 ? 0 : -1; }

bool unquote(std::string_view s, std::string& out, std::string& why) {
    out.clear();
    if (s.empty() || s.front() != '"') {
        while (!s.empty() && (blank(s.back()) || s.back() == '\r' || s.back() == '\n')) s.remove_suffix(1);
        out.assign(s);
        return true;
    }
    size_t i = 1;
    for (; i < s.size() && s[i] != '"'; ++i) {
        if (s[i] != '\\') {
            out += s[i];
            continue;
        }
        if (++i >= s.size()) {
            why = "a quoted string ends in a backslash";
            return false;
        }
        switch (s[i]) {
            case '\\': out += '\\'; break;
            case '"': out += '"'; break;
            case 'n': out += '\n'; break;
            case 't': out += '\t'; break;
            case 'r': out += '\r'; break;
            case 'x': {
                const int hi = i + 1 < s.size() ? hex_digit(s[i + 1]) : -1;
                const int lo = i + 2 < s.size() ? hex_digit(s[i + 2]) : -1;
                if (hi < 0 || lo < 0) {
                    why = "a \\x escape in a quoted string has no two hexadecimal digits";
                    return false;
                }
                out += static_cast<char>(hi * 16 + lo);
                i += 2;
                break;
            }
            default:
                why = std::string("unknown escape \\") + s[i] + " in a quoted string";
                return false;
        }
    }
    if (i >= s.size()) {
        why = "a quoted string is not closed";
        return false;
    }
    for (++i; i < s.size(); ++i)
        if (!blank(s[i]) && s[i] != '\r' && s[i] != '\n') {
            why = "text after the closing quote of a quoted string";
            return false;
        }
    return true;
}

}  // namespace abr::textquote
