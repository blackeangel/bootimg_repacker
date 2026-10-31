// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/dts.hpp"

#include <cstdio>

#include "abr/textquote.hpp"

namespace abr::dts {

namespace {

bool name_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ',' || c == '.' || c == '_' || c == '+' ||
           c == '*' || c == '#' || c == '?' || c == '@' || c == '-';
}

bool plain_name(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s)
        if (!name_char(c)) return false;
    return true;
}

bool printable(unsigned char c) { return c >= 0x20 && c <= 0x7E; }

// The value as a list of strings, when it is one: the last byte is a NUL, no byte is a control or a byte above 0x7E, and no string is
// empty (but for a value that is a single empty string).
bool as_strings(const Bytes& v) {
    if (v.empty() || v.back() != 0) return false;
    if (v.size() == 1) return true;
    bool empty = true;  // the string being read has no character yet
    for (uint8_t c : v) {
        if (c == 0) {
            if (empty) return false;
            empty = true;
        } else {
            if (!printable(c)) return false;
            empty = false;
        }
    }
    return true;
}

void append_string_list(std::string& out, const Bytes& v) {
    size_t i = 0;
    bool first = true;
    while (i < v.size()) {
        if (!first) out += ", ";
        first = false;
        out += '"';
        for (; v[i] != 0; ++i) {
            if (v[i] == '"' || v[i] == '\\') out += '\\';
            out += static_cast<char>(v[i]);
        }
        out += '"';
        ++i;
    }
}

void print_node(std::string& out, const fdt::Node& n, size_t depth, bool root) {
    const std::string indent(depth, '\t');
    if (!root && !plain_name(n.name))
        throw FormatError("device tree source: the node name " + textquote::quote_shown(n.name.substr(0, 60)) +
                          " cannot be written as text (a name is letters, digits and , . _ + * # ? @ -)");
    out += indent;
    out += root ? "/" : n.name;
    out += " {\n";
    for (const fdt::Property& p : n.props) {
        if (!plain_name(p.name))
            throw FormatError("device tree source: the property name " + textquote::quote_shown(p.name.substr(0, 60)) +
                              " cannot be written as text (a name is letters, digits and , . _ + * # ? @ -)");
        out += indent;
        out += '\t';
        out += p.name;
        if (!p.incbin.empty()) {
            out += " = /incbin/(\"";
            for (char c : p.incbin) {
                if (c == '"' || c == '\\') out += '\\';
                out += c;
            }
            out += "\");\n";
            continue;
        }
        if (p.value.empty()) {
            out += ";\n";
            continue;
        }
        out += " = ";
        if (as_strings(p.value)) {
            append_string_list(out, p.value);
        } else if (p.value.size() % 4 == 0) {
            out += '<';
            for (size_t i = 0; i < p.value.size(); i += 4) {
                const uint32_t cell = (uint32_t(p.value[i]) << 24) | (uint32_t(p.value[i + 1]) << 16) | (uint32_t(p.value[i + 2]) << 8) | p.value[i + 3];
                char buf[16];
                std::snprintf(buf, sizeof buf, "%s0x%x", i ? " " : "", cell);
                out += buf;
            }
            out += '>';
        } else {
            out += '[';
            for (size_t i = 0; i < p.value.size(); ++i) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "%s%02x", i ? " " : "", p.value[i]);
                out += buf;
            }
            out += ']';
        }
        out += ";\n";
    }
    if (!n.props.empty() && !n.children.empty()) out += '\n';
    for (size_t i = 0; i < n.children.size(); ++i) {
        print_node(out, n.children[i], depth + 1, false);
        if (i + 1 < n.children.size()) out += '\n';
    }
    out += indent;
    out += "};\n";
}

// ------------------------------------------------------------------------------------------------ reading

class Reader {
public:
    Reader(std::string_view text, const std::string& what) : s_(text), what_(what) {}

    [[noreturn]] void fail(const std::string& why) const {
        throw FormatError(what_ + ": line " + std::to_string(line_) + ": " + why);
    }

    // White space and comments.
    void skip() {
        for (;;) {
            if (i_ >= s_.size()) return;
            const char c = s_[i_];
            if (c == '\n') {
                ++line_;
                ++i_;
            } else if (c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v') {
                ++i_;
            } else if (c == '/' && i_ + 1 < s_.size() && s_[i_ + 1] == '/') {
                while (i_ < s_.size() && s_[i_] != '\n') ++i_;
            } else if (c == '/' && i_ + 1 < s_.size() && s_[i_ + 1] == '*') {
                const size_t start_line = line_;
                i_ += 2;
                for (;;) {
                    if (i_ + 1 >= s_.size()) {
                        line_ = start_line;
                        fail("a comment that is not closed");
                    }
                    if (s_[i_] == '*' && s_[i_ + 1] == '/') {
                        i_ += 2;
                        break;
                    }
                    if (s_[i_] == '\n') ++line_;
                    ++i_;
                }
            } else {
                return;
            }
        }
    }

    bool eof() {
        skip();
        return i_ >= s_.size();
    }
    // The next character (after white space), or 0 at the end.
    char peek() {
        skip();
        return i_ < s_.size() ? s_[i_] : '\0';
    }
    bool take(char c) {
        if (peek() != c) return false;
        ++i_;
        return true;
    }
    void expect(char c, const char* where) {
        if (!take(c)) {
            std::string got = i_ < s_.size() ? "'" + textquote::quote_shown(std::string(1, s_[i_])) + "'" : "the end of the text";
            fail(std::string("expected '") + c + "' " + where + ", found " + got);
        }
    }
    bool starts_with(std::string_view lit) {
        skip();
        return s_.substr(i_, lit.size()) == lit;
    }
    void advance(size_t n) { i_ += n; }

    std::string name() {
        skip();
        const size_t from = i_;
        while (i_ < s_.size() && name_char(static_cast<unsigned char>(s_[i_]))) ++i_;
        if (i_ == from) {
            std::string got = i_ < s_.size() ? "'" + textquote::quote_shown(std::string(1, s_[i_])) + "'" : "the end of the text";
            fail("expected a name, found " + got);
        }
        return std::string(s_.substr(from, i_ - from));
    }

    // A string in double quotes, escapes read.
    std::string string() {
        skip();
        if (i_ >= s_.size() || s_[i_] != '"') fail("expected a string in double quotes");
        ++i_;
        std::string out;
        for (;;) {
            if (i_ >= s_.size() || s_[i_] == '\n') fail("a string that is not closed");
            const char c = s_[i_++];
            if (c == '"') break;
            if (c != '\\') {
                out += c;
                continue;
            }
            if (i_ >= s_.size()) fail("a string that is not closed");
            const char e = s_[i_++];
            switch (e) {
                case 'a': out += '\a'; break;
                case 'b': out += '\b'; break;
                case 't': out += '\t'; break;
                case 'n': out += '\n'; break;
                case 'v': out += '\v'; break;
                case 'f': out += '\f'; break;
                case 'r': out += '\r'; break;
                case '\\': out += '\\'; break;
                case '"': out += '"'; break;
                case 'x': {
                    unsigned v = 0;
                    int digits = 0;
                    while (digits < 2 && i_ < s_.size() && hex_value(s_[i_]) >= 0) {
                        v = v * 16 + static_cast<unsigned>(hex_value(s_[i_++]));
                        ++digits;
                    }
                    if (digits == 0) fail("\\x in a string without a hexadecimal digit");
                    out += static_cast<char>(v);
                    break;
                }
                default:
                    if (e >= '0' && e <= '7') {
                        unsigned v = static_cast<unsigned>(e - '0');
                        int digits = 1;
                        while (digits < 3 && i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '7') {
                            v = v * 8 + static_cast<unsigned>(s_[i_++] - '0');
                            ++digits;
                        }
                        if (v > 255) fail("an octal escape above \\377 in a string");
                        out += static_cast<char>(v);
                    } else {
                        fail(std::string("the escape \\") + e + " in a string is none that abr reads");
                    }
            }
        }
        return out;
    }

    // A number: decimal, 0x hexadecimal, 0 octal (as dtc reads them), or a character in single quotes.
    uint64_t number(unsigned bits) {
        skip();
        if (i_ >= s_.size()) fail("expected a number, found the end of the text");
        uint64_t v = 0;
        const char c = s_[i_];
        if (c == '\'') {
            ++i_;
            if (i_ + 1 >= s_.size()) fail("a character that is not closed");
            if (s_[i_] == '\\') fail("a character in single quotes with an escape is not read; write the number");
            v = static_cast<unsigned char>(s_[i_++]);
            if (i_ >= s_.size() || s_[i_] != '\'') fail("a character in single quotes has to be one character");
            ++i_;
        } else if (c >= '0' && c <= '9') {
            unsigned base = 10;
            if (c == '0' && i_ + 1 < s_.size() && (s_[i_ + 1] == 'x' || s_[i_ + 1] == 'X')) {
                base = 16;
                i_ += 2;
            } else if (c == '0' && i_ + 1 < s_.size() && s_[i_ + 1] >= '0' && s_[i_ + 1] <= '9') {
                base = 8;
                ++i_;
            }
            const size_t from = i_;
            for (; i_ < s_.size(); ++i_) {
                const int d = hex_value(s_[i_]);
                if (d < 0 || static_cast<unsigned>(d) >= base) break;
                if (v > (UINT64_MAX - static_cast<unsigned>(d)) / base) fail("a number that does not fit 64 bits");
                v = v * base + static_cast<unsigned>(d);
            }
            if (i_ == from) fail("a number with no digits");
            if (i_ < s_.size() && (name_char(static_cast<unsigned char>(s_[i_])) && s_[i_] != ',')) fail("a number that is followed by letters");
        } else if (c == '(' || c == '-' || c == '~' || c == '!') {
            fail("an expression where a number is expected (abr reads numbers only)");
        } else if (c == '&') {
            fail("a reference (&name): abr reads no labels or references");
        } else {
            fail("a name where a number is expected (abr reads no macros)");
        }
        if (bits < 64 && (v >> bits) != 0) fail("the number " + std::to_string(v) + " does not fit " + std::to_string(bits) + " bits");
        return v;
    }

    static int hex_value(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    size_t line() const { return line_; }
    char raw() const { return i_ < s_.size() ? s_[i_] : '\0'; }
    void raw_advance() { ++i_; }

private:
    std::string_view s_;
    std::string what_;
    size_t i_ = 0;
    size_t line_ = 1;
};

void put_be(Bytes& out, uint64_t v, unsigned bytes) {
    for (unsigned k = bytes; k-- > 0;) out.push_back(static_cast<uint8_t>(v >> (8 * k)));
}

void parse_value(Reader& r, fdt::Property& p) {
    bool first = true;
    for (;;) {
        const char c = r.peek();
        if (c == '"') {
            const std::string s = r.string();
            p.value.insert(p.value.end(), s.begin(), s.end());
            p.value.push_back(0);
        } else if (c == '<' || (c == '/' && r.starts_with("/bits/"))) {
            unsigned bits = 32;
            if (c == '/') {
                r.advance(6);
                const uint64_t b = r.number(64);
                if (b != 8 && b != 16 && b != 32 && b != 64) r.fail("/bits/ has to be 8, 16, 32 or 64");
                bits = static_cast<unsigned>(b);
                if (r.peek() != '<') r.fail("expected '<' after /bits/ and its width");
            }
            r.raw_advance();  // '<'
            for (;;) {
                if (r.peek() == '>') {
                    r.raw_advance();
                    break;
                }
                put_be(p.value, r.number(bits), bits / 8);
            }
        } else if (c == '[') {
            r.raw_advance();
            int high = -1;
            for (;;) {
                const char d = r.peek();
                if (d == ']') {
                    r.raw_advance();
                    break;
                }
                const int v = Reader::hex_value(d);
                if (v < 0) r.fail("expected a hexadecimal digit or ']' in a byte string");
                r.raw_advance();
                if (high < 0) {
                    high = v;
                } else {
                    p.value.push_back(static_cast<uint8_t>(high * 16 + v));
                    high = -1;
                }
            }
            if (high >= 0) r.fail("a byte string with an odd number of hexadecimal digits");
        } else if (c == '/' && r.starts_with("/incbin/")) {
            if (!first || !p.value.empty()) r.fail("/incbin/ has to be the only value of its property");
            r.advance(8);
            r.expect('(', "after /incbin/");
            p.incbin = r.string();
            if (p.incbin.empty()) r.fail("/incbin/ names no file");
            if (r.peek() == ',') r.fail("/incbin/ with a skip and a length is not read; the whole file is the value");
            r.expect(')', "after the file name of /incbin/");
        } else if (c == '&') {
            r.fail("a reference (&name): abr reads no labels or references");
        } else {
            r.fail("expected a value: a string, <cells>, [bytes] or /incbin/(\"file\")");
        }
        first = false;
        if (!p.incbin.empty()) {
            if (r.peek() == ',') r.fail("/incbin/ has to be the only value of its property");
            return;
        }
        if (r.peek() == ',') {
            r.raw_advance();
            continue;
        }
        return;
    }
}

void parse_body(Reader& r, fdt::Node& node, size_t depth, size_t& items) {
    for (;;) {
        const char c = r.peek();
        if (c == '}') return;
        if (c == '\0') r.fail("the text ends inside a node (a '}' is missing)");
        if (c == '/') {
            if (r.starts_with("/delete-node/") || r.starts_with("/delete-property/"))
                r.fail("/delete-node/ and /delete-property/ are not read; leave the node or the property out");
            if (r.starts_with("/omit-if-no-ref/")) r.fail("/omit-if-no-ref/ is not read");
            r.fail("a directive that abr does not read");
        }
        const std::string name = r.name();
        if (++items > fdt::kMaxItems) r.fail("more than " + std::to_string(fdt::kMaxItems) + " nodes and properties");
        const char next = r.peek();
        if (next == ':') r.fail("labels are not read (" + textquote::quote_shown(name) + ":)");
        if (next == '{') {
            if (depth >= fdt::kMaxDepth) r.fail("nodes nested more than " + std::to_string(fdt::kMaxDepth) + " deep");
            if (node.find_child(name)) r.fail("the node " + textquote::quote_shown(name) + " is there twice (abr does not merge nodes)");
            r.raw_advance();
            node.children.emplace_back();
            node.children.back().name = name;
            parse_body(r, node.children.back(), depth + 1, items);
            r.expect('}', "to close the node");
            r.expect(';', "behind the '}' of a node");
        } else {
            if (!node.children.empty()) r.fail("the property " + textquote::quote_shown(name) + " comes after a subnode; write the properties of a node first");
            if (node.find_prop(name)) r.fail("the property " + textquote::quote_shown(name) + " is there twice");
            fdt::Property p;
            p.name = name;
            if (next == '=') {
                r.raw_advance();
                parse_value(r, p);
            } else if (next != ';') {
                r.fail("expected '=', '{' or ';' after the name " + textquote::quote_shown(name));
            }
            r.expect(';', "at the end of the property");
            node.props.push_back(std::move(p));
        }
    }
}

}  // namespace

std::string print(const fdt::Tree& tree) {
    std::string out = "/dts-v1/;\n\n";
    for (const auto& [addr, size] : tree.reserve) {
        char buf[64];
        std::snprintf(buf, sizeof buf, "/memreserve/ 0x%llx 0x%llx;\n", static_cast<unsigned long long>(addr), static_cast<unsigned long long>(size));
        out += buf;
    }
    if (!tree.reserve.empty()) out += '\n';
    print_node(out, tree.root, 0, true);
    return out;
}

fdt::Tree parse(std::string_view text, const std::string& what) {
    if (text.size() > kMaxText) throw FormatError(what + " is " + std::to_string(text.size()) + " bytes; abr reads up to " + std::to_string(kMaxText));
    Reader r(text, what);
    fdt::Tree tree;
    if (!r.starts_with("/dts-v1/")) r.fail("a device tree source starts with /dts-v1/;");
    r.advance(8);
    r.expect(';', "behind /dts-v1/");
    while (r.starts_with("/memreserve/")) {
        r.advance(12);
        const uint64_t a = r.number(64);
        const uint64_t s = r.number(64);
        r.expect(';', "behind /memreserve/");
        if (tree.reserve.size() >= fdt::kMaxItems) r.fail("too many /memreserve/ entries");
        tree.reserve.emplace_back(a, s);
    }
    if (r.peek() != '/') r.fail("expected the root node ('/ {')");
    if (r.starts_with("/plugin/") || r.starts_with("/include/")) r.fail("/plugin/ and /include/ are not read");
    r.raw_advance();
    r.expect('{', "after the '/' of the root node");
    size_t items = 0;
    parse_body(r, tree.root, 1, items);
    r.expect('}', "to close the root node");
    r.expect(';', "behind the '}' of the root node");
    if (!r.eof()) r.fail("there is something behind the root node (abr reads one, and no second '/ {' that would add to it)");
    return tree;
}

}  // namespace abr::dts
