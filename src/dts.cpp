// SPDX-License-Identifier: GPL-3.0-or-later
//
// The device tree compiler and decompiler of abr (dts.hpp). The language and what is done to a tree before it is written are those of
// dtc 1.7 (dtc-lexer.l, dtc-parser.y, livetree.c, checks.c, flattree.c); the code is abr's own.
//
// The way it goes:
//   * Lex reads the text (and what /include/ brings in) a token at a time, and the parser says what it expects: a name is a name where
//     dtc's lexer is in its PROPNODENAME state (after `{` and `;`), a number where it is in its V1 state. There is no token stream.
//   * Parser makes a "live tree" (LNode, LProp): nodes and properties as they are written, with their labels, the references that a
//     value holds (Marker) and the flags that /delete-node/, /delete-property/ and /omit-if-no-ref/ set. A node that is written twice
//     is merged into the first as dtc merges it -- a deleted node or property stays in its place with a flag, and a later definition
//     of the same name takes that place again, which is what puts the properties of dtc's output in the order they are in.
//   * finish() does what dtc's checks do that changes the result or stops it, in dtc's order, and what main() of dtc does behind them
//     (the fixups of a /plugin/, the symbols).
//   * to_tree() makes the fdt::Tree of what is left.
#include "abr/dts.hpp"

#include <algorithm>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>

#include "abr/manifest.hpp"
#include "abr/textquote.hpp"

namespace abr::dts {

namespace {

using textquote::quote_shown;

// ------------------------------------------------------------------------------------------------------------ characters

constexpr bool is_digit(unsigned char c) { return c >= '0' && c <= '9'; }
constexpr bool is_alpha(unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

constexpr int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// What a name is made of for the lexer (dtc-lexer.l: PROPNODECHAR).
constexpr bool name_char(unsigned char c) {
    return is_alpha(c) || is_digit(c) || c == ',' || c == '.' || c == '_' || c == '+' || c == '*' || c == '#' || c == '?' || c == '@' || c == '-';
}
// What dtc's checks let a node name and a property name be made of (checks.c: NODECHARS, PROPCHARS).
constexpr bool node_name_char(unsigned char c) { return is_alpha(c) || is_digit(c) || c == ',' || c == '.' || c == '_' || c == '+' || c == '-' || c == '@'; }
constexpr bool prop_name_char(unsigned char c) { return is_alpha(c) || is_digit(c) || c == ',' || c == '.' || c == '_' || c == '+' || c == '*' || c == '#' || c == '?' || c == '-'; }
constexpr bool label_start(unsigned char c) { return is_alpha(c) || c == '_'; }
constexpr bool label_char(unsigned char c) { return is_alpha(c) || is_digit(c) || c == '_'; }
constexpr bool path_char(unsigned char c) { return name_char(c) || c == '/'; }

bool plain_name(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s)
        if (!name_char(c)) return false;
    return true;
}

void put_be(Bytes& out, uint64_t v, unsigned bytes) {
    for (unsigned k = bytes; k-- > 0;) out.push_back(static_cast<uint8_t>(v >> (8 * k)));
}

// ------------------------------------------------------------------------------------------------------------ printing

constexpr bool printable(unsigned char c) { return c >= 0x20 && c <= 0x7E; }
// \a \b \t \n \v \f \r: what dtc writes with a backslash and a letter.
constexpr bool escapable(unsigned char c) { return c >= 7 && c <= 13; }

constexpr size_t kCellsPerLine = 8;
constexpr size_t kBytesPerLine = 16;
constexpr size_t kStringsWidth = 80;  // columns, a tab counted as 8

// The value as a list of strings, when it is one: it ends with a NUL, no byte is one that a string cannot hold, and there are no more
// empty strings than a string can follow (dtc's own measure: no more NULs than the bytes that are not). A single NUL is `""`.
bool as_strings(const Bytes& v) {
    if (v.empty() || v.back() != 0) return false;
    if (v.size() == 1) return true;
    size_t nuls = 0;
    for (uint8_t c : v) {
        if (c == 0)
            ++nuls;
        else if (!printable(c) && !escapable(c))
            return false;
    }
    return nuls * 2 <= v.size();
}

std::string quoted(const uint8_t* s, size_t n) {
    std::string out = "\"";
    for (size_t i = 0; i < n; ++i) {
        const uint8_t c = s[i];
        switch (c) {
            case '\a': out += "\\a"; break;
            case '\b': out += "\\b"; break;
            case '\t': out += "\\t"; break;
            case '\n': out += "\\n"; break;
            case '\v': out += "\\v"; break;
            case '\f': out += "\\f"; break;
            case '\r': out += "\\r"; break;
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            default: out += static_cast<char>(c);
        }
    }
    out += '"';
    return out;
}

void print_property(std::string& out, const fdt::Property& p, const std::string& indent) {
    if (!plain_name(p.name))
        throw FormatError("device tree source: the property name " + quote_shown(p.name.substr(0, 60)) +
                          " cannot be written as text (a name is letters, digits and , . _ + * # ? @ -)");
    out += indent;
    out += p.name;
    if (!p.incbin.empty()) {
        out += " = /incbin/(\"";
        for (char c : p.incbin) {
            if (c == '"' || c == '\\') out += '\\';
            out += c;
        }
        out += "\");\n";
        return;
    }
    if (p.value.empty()) {
        out += ";\n";
        return;
    }
    out += " = ";
    const std::string continued = indent + '\t';
    if (as_strings(p.value)) {
        std::vector<std::string> parts;
        size_t total = 0;
        for (size_t i = 0; i < p.value.size();) {
            size_t end = i;
            while (p.value[end] != 0) ++end;
            parts.push_back(quoted(p.value.data() + i, end - i));
            total += parts.back().size() + 2;
            i = end + 1;
        }
        const bool broken = indent.size() * 8 + p.name.size() + 3 + total > kStringsWidth;
        for (size_t i = 0; i < parts.size(); ++i) {
            if (i) out += broken ? ",\n" + continued : std::string(", ");
            out += parts[i];
        }
    } else if (p.value.size() % 4 == 0) {
        out += '<';
        for (size_t i = 0; i < p.value.size(); i += 4) {
            if (i) out += (i / 4) % kCellsPerLine == 0 ? "\n" + continued : std::string(" ");
            const uint32_t cell = (uint32_t(p.value[i]) << 24) | (uint32_t(p.value[i + 1]) << 16) | (uint32_t(p.value[i + 2]) << 8) | p.value[i + 3];
            char buf[16];
            std::snprintf(buf, sizeof buf, "0x%x", cell);
            out += buf;
        }
        out += '>';
    } else {
        out += '[';
        for (size_t i = 0; i < p.value.size(); ++i) {
            if (i) out += i % kBytesPerLine == 0 ? "\n" + continued : std::string(" ");
            char buf[8];
            std::snprintf(buf, sizeof buf, "%02x", p.value[i]);
            out += buf;
        }
        out += ']';
    }
    out += ';';
    if (!p.pad.empty() && p.pad.size() == fdt::padding_size(p.value.size())) {
        out += " /* abr: padding";
        for (uint8_t b : p.pad) {
            char buf[8];
            std::snprintf(buf, sizeof buf, " %02x", b);
            out += buf;
        }
        out += " */";
    }
    out += '\n';
}

void print_node(std::string& out, const fdt::Node& n, size_t depth, bool root) {
    const std::string indent(depth, '\t');
    if (!root && !plain_name(n.name))
        throw FormatError("device tree source: the node name " + quote_shown(n.name.substr(0, 60)) +
                          " cannot be written as text (a name is letters, digits and , . _ + * # ? @ -)");
    out += indent;
    out += root ? "/" : n.name;
    out += " {\n";
    for (const fdt::Property& p : n.props) print_property(out, p, indent + '\t');
    if (!n.props.empty() && !n.children.empty()) out += '\n';
    for (size_t i = 0; i < n.children.size(); ++i) {
        print_node(out, n.children[i], depth + 1, false);
        if (i + 1 < n.children.size()) out += '\n';
    }
    out += indent;
    out += "};\n";
}

// ------------------------------------------------------------------------------------------------------------ the live tree

struct Pos {
    uint32_t file = 0;
    uint32_t line = 0;
};

struct Label {
    std::string name;
    bool deleted = false;
};

// A reference that a value holds: a phandle (the cell at `offset`, which holds 0xffffffff until it is known) or a path (a string that
// is put in at `offset`).
struct Marker {
    size_t offset = 0;
    std::string ref;
    bool path = false;
};

struct LProp {
    std::string name;
    Bytes value;
    std::vector<Marker> markers;
    std::vector<Label> labels;
    std::vector<std::string> data_labels;  // the labels inside the value: only checked for being used twice
    std::string incbin;
    Bytes pad;
    bool deleted = false;
    Pos pos;
};

struct LNode {
    std::string name;
    std::vector<LProp> props;
    std::vector<std::unique_ptr<LNode>> children;
    std::vector<Label> labels;
    LNode* parent = nullptr;
    bool deleted = false;
    bool omit_if_unused = false;
    bool referenced = false;
    uint32_t phandle = 0;
    std::string fullpath;
    Pos pos;
};

// The labels of a node or a property are a list that a new label joins at the head, as in dtc (what it makes of them -- the order of
// the properties of __symbols__ -- goes by that order).
void add_label(std::vector<Label>& labels, const std::string& name) {
    for (Label& l : labels)
        if (l.name == name) {
            l.deleted = false;
            return;
        }
    labels.insert(labels.begin(), Label{name, false});
}

void delete_labels(std::vector<Label>& labels) {
    for (Label& l : labels) l.deleted = true;
}

LProp* find_prop(LNode& n, const std::string& name) {
    for (LProp& p : n.props)
        if (!p.deleted && p.name == name) return &p;
    return nullptr;
}

void delete_node(LNode& n) {
    n.deleted = true;
    for (auto& c : n.children) delete_node(*c);
    for (LProp& p : n.props) {
        p.deleted = true;
        delete_labels(p.labels);
    }
    delete_labels(n.labels);
}

void add_child(LNode& parent, std::unique_ptr<LNode> child) {
    child->parent = &parent;
    parent.children.push_back(std::move(child));
}

// dtc's merge_nodes(): what `nn` holds goes into `old`. A property or a child of the same name -- a deleted one too -- takes the place of
// the old one; the others are added at the end.
void merge_nodes(LNode& old, LNode&& nn) {
    old.deleted = false;
    for (const Label& l : nn.labels) add_label(old.labels, l.name);
    for (LProp& np : nn.props) {
        if (np.deleted) {
            for (LProp& op : old.props)  // the first of that name, deleted already or not: that is what dtc does
                if (op.name == np.name) {
                    op.deleted = true;
                    delete_labels(op.labels);
                    break;
                }
            continue;
        }
        LProp* hit = nullptr;
        for (LProp& op : old.props)
            if (op.name == np.name) {
                hit = &op;
                break;
            }
        if (!hit) {
            old.props.push_back(std::move(np));
            continue;
        }
        for (const Label& l : np.labels) add_label(hit->labels, l.name);
        hit->value = std::move(np.value);
        hit->markers = std::move(np.markers);
        hit->data_labels = std::move(np.data_labels);
        hit->incbin = std::move(np.incbin);
        hit->pad = std::move(np.pad);
        hit->deleted = false;
        hit->pos = np.pos;
    }
    for (auto& nc : nn.children) {
        if (nc->deleted) {
            for (auto& oc : old.children)
                if (oc->name == nc->name) {
                    delete_node(*oc);
                    break;
                }
            continue;
        }
        LNode* hit = nullptr;
        for (auto& oc : old.children)
            if (oc->name == nc->name) {
                hit = oc.get();
                break;
            }
        if (hit)
            merge_nodes(*hit, std::move(*nc));
        else
            add_child(old, std::move(nc));
    }
}

LNode* find_by_label(LNode& tree, const std::string& label) {
    for (const Label& l : tree.labels)
        if (!l.deleted && l.name == label) return &tree;
    for (auto& c : tree.children) {
        if (c->deleted) continue;
        if (LNode* n = find_by_label(*c, label)) return n;
    }
    return nullptr;
}

LNode* find_by_path(LNode& tree, std::string_view path) {
    if (path.empty()) return tree.deleted ? nullptr : &tree;
    while (!path.empty() && path.front() == '/') path.remove_prefix(1);
    const size_t slash = path.find('/');
    for (auto& c : tree.children) {
        if (c->deleted) continue;
        if (slash != std::string_view::npos) {
            if (path.substr(0, slash) == c->name) return find_by_path(*c, path.substr(slash + 1));
        } else if (path == c->name) {
            return c.get();
        }
    }
    return nullptr;
}

// A label, a path, or a label and a path behind it (`label/sub/node`).
LNode* find_by_ref(LNode& tree, const std::string& ref) {
    if (ref.empty()) return nullptr;  // &{}: dtc stops on an assertion where it is looked up
    if (ref == "/") return &tree;
    LNode* target = &tree;
    std::string_view path;
    bool has_path = false;
    if (!ref.empty() && ref[0] == '/') {
        path = ref;
        has_path = true;
    } else {
        std::string_view label = ref;
        const size_t slash = label.find('/');
        if (slash != std::string_view::npos) {
            path = label.substr(slash + 1);
            label = label.substr(0, slash);
            has_path = true;
        }
        target = find_by_label(tree, std::string(label));
        if (!target) return nullptr;
    }
    return has_path ? find_by_path(*target, path) : target;
}

struct Doc {
    std::vector<std::string> files;  // the names the messages use; Pos::file is an index
    std::unique_ptr<LNode> root;
    std::vector<std::pair<uint64_t, uint64_t>> reserve;
    bool plugin = false;
    unsigned next_fragment = 0;
    uint32_t boot_cpuid = 0;
};

[[noreturn]] void fail_at(const Doc& d, Pos p, const std::string& why) {
    throw FormatError(d.files[p.file] + ": line " + std::to_string(p.line) + ": " + why);
}

// ------------------------------------------------------------------------------------------------------------ reading

class Lex {
public:
    Lex(Doc& doc, std::string_view text, const std::string& what, const Options& opt) : doc_(doc), opt_(opt) {
        if (text.size() > kMaxText) throw FormatError(what + " is " + std::to_string(text.size()) + " bytes; abr reads up to " + std::to_string(kMaxText));
        doc_.files.push_back(what);
        total_ = text.size();
        frames_.push_back({text, 0, 1, 0, std::string()});
        skip_bom(frames_.back());
    }

    Pos pos() const { return {frames_.back().file, static_cast<uint32_t>(frames_.back().line)}; }
    // What read_file made of the name of the text that is being read (what a name in it is relative to); "" for the text itself.
    const std::string& current_from() const { return frames_.back().from; }
    [[noreturn]] void fail(const std::string& why) const { fail_at(doc_, pos(), why); }

    // White space, comments, line markers of cpp and /include/. The end of an included text goes back to the text that included it.
    void skip() {
        for (;;) {
            Frame& f = frames_.back();
            if (f.pos >= f.text.size()) {
                if (frames_.size() == 1) return;
                frames_.pop_back();
                continue;
            }
            const char c = f.text[f.pos];
            if (c == '\n') {
                ++f.line;
                ++f.pos;
            } else if (c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v') {
                ++f.pos;
            } else if (c == '/' && f.pos + 1 < f.text.size() && f.text[f.pos + 1] == '/') {
                while (f.pos < f.text.size() && f.text[f.pos] != '\n') ++f.pos;
            } else if (c == '/' && f.pos + 1 < f.text.size() && f.text[f.pos + 1] == '*') {
                block_comment(f);
            } else if (c == '/' && f.text.substr(f.pos, 9) == "/include/") {
                include(f);
            } else if (c == '#' && (f.pos == 0 || f.text[f.pos - 1] == '\n') && line_marker(f)) {
                // a line that cpp left: `# 12 "file.dts"`
            } else {
                return;
            }
        }
    }

    bool at_end() {
        skip();
        return frames_.size() == 1 && frames_.back().pos >= frames_.back().text.size();
    }
    // The next character, or 0 at the end.
    char peek() {
        skip();
        const Frame& f = frames_.back();
        return f.pos < f.text.size() ? f.text[f.pos] : '\0';
    }
    // The character after the next one, 0 when there is none (it is not looked at through white space).
    char peek2() {
        skip();
        const Frame& f = frames_.back();
        return f.pos + 1 < f.text.size() ? f.text[f.pos + 1] : '\0';
    }
    bool eat(char c) {
        if (peek() != c) return false;
        ++frames_.back().pos;
        return true;
    }
    void expect(char c, const char* where) {
        if (!eat(c)) fail(std::string("expected '") + c + "' " + where + ", found " + found());
    }
    bool at_word(std::string_view w) {
        skip();
        const Frame& f = frames_.back();
        return f.text.substr(f.pos, w.size()) == w;
    }
    void advance(size_t n) { frames_.back().pos += n; }
    std::string found() {
        skip();
        const Frame& f = frames_.back();
        if (f.pos >= f.text.size()) return "the end of the text";
        return "'" + quote_shown(std::string(1, f.text[f.pos])) + "'";
    }

    // A name of a node or a property (a backslash in front of it is dropped).
    std::string name() {
        skip();
        Frame& f = frames_.back();
        size_t i = f.pos;
        if (i < f.text.size() && f.text[i] == '\\') ++i;
        const size_t from = i;
        while (i < f.text.size() && name_char(static_cast<unsigned char>(f.text[i]))) ++i;
        if (i == from) fail("expected a name, found " + found());
        f.pos = i;
        return std::string(f.text.substr(from, i - from));
    }

    // `label:` (the colon right behind the name), or nothing and nothing is read.
    std::optional<std::string> label() {
        skip();
        Frame& f = frames_.back();
        size_t i = f.pos;
        if (i >= f.text.size() || !label_start(static_cast<unsigned char>(f.text[i]))) return std::nullopt;
        size_t j = i + 1;
        while (j < f.text.size() && label_char(static_cast<unsigned char>(f.text[j]))) ++j;
        if (j >= f.text.size() || f.text[j] != ':') return std::nullopt;
        f.pos = j + 1;
        return std::string(f.text.substr(i, j - i));
    }

    struct Ref {
        std::string text;  // a label (maybe with a path behind it) or a path
        bool path = false;  // written &{...}
    };

    // `&label` or `&{path}`; a '&' that is neither is left (the operator of an expression).
    std::optional<Ref> ref() {
        skip();
        Frame& f = frames_.back();
        if (f.pos >= f.text.size() || f.text[f.pos] != '&') return std::nullopt;
        if (f.pos + 1 < f.text.size() && f.text[f.pos + 1] == '{') {
            size_t j = f.pos + 2;
            while (j < f.text.size() && path_char(static_cast<unsigned char>(f.text[j]))) ++j;
            if (j >= f.text.size() || f.text[j] != '}') fail("a reference &{...} names a path (letters, digits and , . _ + * # ? @ - /) and ends with '}'");
            Ref r{std::string(f.text.substr(f.pos + 2, j - f.pos - 2)), true};
            f.pos = j + 1;
            return r;
        }
        if (f.pos + 1 < f.text.size() && label_start(static_cast<unsigned char>(f.text[f.pos + 1]))) {
            size_t j = f.pos + 2;
            while (j < f.text.size() && label_char(static_cast<unsigned char>(f.text[j]))) ++j;
            Ref r{std::string(f.text.substr(f.pos + 1, j - f.pos - 1)), false};
            f.pos = j;
            return r;
        }
        return std::nullopt;
    }

    // A string in double quotes, its escapes read. A line break may be inside; a backslash may not be the last thing of a line.
    std::string string() {
        skip();
        Frame& f = frames_.back();
        if (f.pos >= f.text.size() || f.text[f.pos] != '"') fail("expected a string in double quotes, found " + found());
        size_t i = f.pos + 1;
        std::string out;
        for (;;) {
            if (i >= f.text.size()) fail("a string that is not closed");
            const char c = f.text[i++];
            if (c == '"') break;
            if (c != '\\') {
                if (c == '\n') ++f.line;
                out += c;
                continue;
            }
            if (i >= f.text.size() || f.text[i] == '\n') fail("a string that is not closed (a backslash is not the last character of a line)");
            escape(f, i, out);
        }
        f.pos = i;
        return out;
    }

    // A number: 123, 0x7b, 0173, a U, L, UL, LL or ULL behind it, or a character ('a'). Returns false when the text is none of them.
    bool number(uint64_t& v) {
        skip();
        Frame& f = frames_.back();
        if (f.pos >= f.text.size()) return false;
        const char c = f.text[f.pos];
        if (c == '\'') {
            size_t i = f.pos + 1;
            std::string chars;
            for (;;) {
                if (i >= f.text.size()) fail("a character that is not closed");
                const char d = f.text[i++];
                if (d == '\'') break;
                if (d != '\\') {
                    chars += d;
                    continue;
                }
                if (i >= f.text.size()) fail("a character that is not closed");
                escape(f, i, chars);
            }
            if (chars.empty()) fail("Empty character literal");
            if (chars.size() > 1) fail("Character literal has " + std::to_string(chars.size()) + " characters instead of 1");
            v = static_cast<unsigned char>(chars[0]);
            f.pos = i;
            return true;
        }
        if (!is_digit(static_cast<unsigned char>(c))) return false;
        const std::string_view t = f.text;
        size_t i = f.pos;
        unsigned base = 10;
        if (c == '0' && i + 2 < t.size() && (t[i + 1] == 'x' || t[i + 1] == 'X') && hex_value(t[i + 2]) >= 0) {
            base = 16;
            i += 2;
        } else if (c == '0' && i + 1 < t.size() && is_digit(static_cast<unsigned char>(t[i + 1]))) {
            base = 8;
        }
        v = 0;
        const size_t from = i;
        while (i < t.size()) {
            const int d = hex_value(t[i]);
            if (d < 0 || (base != 16 && d > 9)) break;  // a letter ends a number that is not hexadecimal
            if (static_cast<unsigned>(d) >= base) fail("Bad integer literal '" + std::string(t.substr(f.pos, i + 1 - f.pos)) + "'");
            if (v > (UINT64_MAX - static_cast<unsigned>(d)) / base) fail("Integer literal '" + std::string(t.substr(f.pos, 24)) + "' out of range");
            v = v * base + static_cast<unsigned>(d);
            ++i;
        }
        if (i == from) fail("a number with no digits");
        const std::string_view rest = t.substr(i);
        for (std::string_view suffix : {"ULL", "UL", "LL", "U", "L"})
            if (rest.substr(0, suffix.size()) == suffix) {
                i += suffix.size();
                break;
            }
        f.pos = i;
        return true;
    }

    // Raw access for the bytes of [ ].
    char raw() const {
        const Frame& f = frames_.back();
        return f.pos < f.text.size() ? f.text[f.pos] : '\0';
    }
    char raw_at(size_t ahead) const {
        const Frame& f = frames_.back();
        return f.pos + ahead < f.text.size() ? f.text[f.pos + ahead] : '\0';
    }

    // The comment `abr: padding 98 3e b2` that comes right behind the ';' that ends a property (print() writes it there): the bytes
    // behind the value that are not zeros (fdt::Property::pad). A comment of this kind anywhere else is an error: it would be lost.
    std::optional<Bytes> take_pad(Pos& at) {
        pad_allowed_ = true;
        skip();
        pad_allowed_ = false;
        std::optional<Bytes> r = std::move(pad_);
        pad_.reset();
        at = pad_pos_;
        return r;
    }

private:
    struct Frame {
        std::string_view text;
        size_t pos = 0;
        size_t line = 1;
        uint32_t file = 0;
        std::string from;  // what read_file made of the name of this text: the names inside are relative to it
    };

    static void skip_bom(Frame& f) {
        if (f.text.size() >= 3 && static_cast<unsigned char>(f.text[0]) == 0xEF && static_cast<unsigned char>(f.text[1]) == 0xBB &&
            static_cast<unsigned char>(f.text[2]) == 0xBF)
            f.pos = 3;
    }

    uint32_t file_index(const std::string& name) {
        for (size_t i = 0; i < doc_.files.size(); ++i)
            if (doc_.files[i] == name) return static_cast<uint32_t>(i);
        doc_.files.push_back(name);
        return static_cast<uint32_t>(doc_.files.size() - 1);
    }

    // The escape that starts at f.text[i] (right behind the backslash), appended to `out`; i is left behind it. As dtc reads it:
    // \a \b \t \n \v \f \r, one to three octal digits, \x and one or two hexadecimal digits, and any other character is itself.
    void escape(const Frame& f, size_t& i, std::string& out) const {
        const char e = f.text[i++];
        switch (e) {
            case 'a': out += '\a'; return;
            case 'b': out += '\b'; return;
            case 't': out += '\t'; return;
            case 'n': out += '\n'; return;
            case 'v': out += '\v'; return;
            case 'f': out += '\f'; return;
            case 'r': out += '\r'; return;
            case 'x': {
                unsigned v = 0;
                int digits = 0;
                while (digits < 2 && i < f.text.size() && hex_value(f.text[i]) >= 0) {
                    v = v * 16 + static_cast<unsigned>(hex_value(f.text[i++]));
                    ++digits;
                }
                if (digits == 0) fail("\\x used with no following hex digits");
                out += static_cast<char>(v);
                return;
            }
            default:
                if (e >= '0' && e <= '7') {
                    unsigned v = static_cast<unsigned>(e - '0');
                    int digits = 1;
                    while (digits < 3 && i < f.text.size() && f.text[i] >= '0' && f.text[i] <= '7') {
                        v = v * 8 + static_cast<unsigned>(f.text[i++] - '0');
                        ++digits;
                    }
                    out += static_cast<char>(v & 0xFF);
                    return;
                }
                out += e;
        }
    }

    void block_comment(Frame& f) {
        const size_t start_line = f.line;
        const size_t body = f.pos + 2;
        size_t i = body;
        for (;; ++i) {
            if (i + 1 >= f.text.size()) {
                f.line = start_line;
                fail("a comment that is not closed");
            }
            if (f.text[i] == '*' && f.text[i + 1] == '/') break;
            if (f.text[i] == '\n') ++f.line;
        }
        note_comment(f, f.text.substr(body, i - body), start_line);
        f.pos = i + 2;
    }

    // A block comment that has been read: one that starts with "abr: padding" is what take_pad() hands over.
    void note_comment(const Frame& f, std::string_view body, size_t start_line) {
        constexpr std::string_view kTag = "abr: padding";
        auto blank = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
        size_t a = 0, b = body.size();
        while (a < b && blank(body[a])) ++a;
        while (b > a && blank(body[b - 1])) --b;
        const std::string_view text = body.substr(a, b - a);
        if (text.substr(0, kTag.size()) != kTag) return;
        const Pos here{f.file, static_cast<uint32_t>(start_line)};
        if (!pad_allowed_) fail_at(doc_, here, "the comment \"abr: padding\" is not right behind a property (it tells what is behind the value of the one before it)");
        if (pad_) fail_at(doc_, here, "two comments \"abr: padding\" behind one property");
        const std::string_view rest = text.substr(kTag.size());
        Bytes bytes;
        for (size_t i = 0; i < rest.size();) {
            if (rest[i] == ' ' || rest[i] == '\t') {
                ++i;
                continue;
            }
            if (i + 2 > rest.size() || hex_value(rest[i]) < 0 || hex_value(rest[i + 1]) < 0 || (i + 2 < rest.size() && rest[i + 2] != ' ' && rest[i + 2] != '\t'))
                fail_at(doc_, here, "the comment \"abr: padding\" lists bytes, each as two hexadecimal digits");
            bytes.push_back(static_cast<uint8_t>(hex_value(rest[i]) * 16 + hex_value(rest[i + 1])));
            i += 2;
        }
        if (bytes.empty() || bytes.size() > 3)
            fail_at(doc_, here, "the comment \"abr: padding\" lists " + std::to_string(bytes.size()) + " bytes; the padding behind a value is 1 to 3");
        pad_ = std::move(bytes);
        pad_pos_ = here;
    }

    // `# 12 "file.dts" 1 3` (or `#line 12 ...`) at the start of a line: where the line that follows is. dtc's own rule: the numbers behind
    // the name are the flags of cpp, and what follows on the line is read as text. True when the text is one.
    bool line_marker(Frame& f) {
        const std::string_view t = f.text;
        size_t i = f.pos + 1;
        if (t.substr(i, 4) == "line") i += 4;
        size_t a = i;
        while (i < t.size() && (t[i] == ' ' || t[i] == '\t')) ++i;
        if (i == a) return false;
        const size_t digits = i;
        uint64_t n = 0;
        while (i < t.size() && is_digit(static_cast<unsigned char>(t[i]))) {
            if (i - digits < 9) n = n * 10 + static_cast<unsigned>(t[i] - '0');
            ++i;
        }
        if (i == digits) return false;
        a = i;
        while (i < t.size() && (t[i] == ' ' || t[i] == '\t')) ++i;
        if (i == a || i >= t.size() || t[i] != '"') return false;
        const size_t name_from = ++i;
        while (i < t.size() && t[i] != '"') {  // a line break may be inside the name (dtc's string is `"([^\\"]|\\.)*"`, and [^..] takes it)
            if (t[i] == '\\') {
                if (i + 1 >= t.size() || t[i + 1] == '\n') return false;
                ++i;
            }
            ++i;
        }
        if (i >= t.size()) return false;
        std::string name;
        for (size_t k = name_from; k < i;) {
            if (t[k] != '\\') {
                name += t[k++];
                continue;
            }
            ++k;
            escape(f, k, name);
        }
        ++i;
        for (;;) {  // the flags
            size_t j = i;
            while (j < t.size() && (t[j] == ' ' || t[j] == '\t')) ++j;
            const size_t d = j;
            while (j < t.size() && is_digit(static_cast<unsigned char>(t[j]))) ++j;
            if (j == d) break;
            i = j;
        }
        f.file = file_index(name);
        f.line = n == 0 ? 0 : static_cast<size_t>(n - 1);
        f.pos = i;
        return true;
    }

    void include(Frame& f) {
        const Pos at = pos();
        size_t i = f.pos + 9;
        size_t lines = 0;
        while (i < f.text.size() && (f.text[i] == ' ' || f.text[i] == '\t' || f.text[i] == '\r' || f.text[i] == '\n' || f.text[i] == '\f' || f.text[i] == '\v')) {
            if (f.text[i] == '\n') ++lines;
            ++i;
        }
        if (i >= f.text.size() || f.text[i] != '"') fail("/include/ is followed by the name of a file in double quotes");
        const size_t from = ++i;
        while (i < f.text.size() && f.text[i] != '"') {
            if (f.text[i] == '\\') ++i;
            ++i;
        }
        if (i >= f.text.size()) fail("the name of the file of /include/ is not closed");
        const std::string name(f.text.substr(from, i - from));
        f.pos = i + 1;
        f.line += lines;
        if (!opt_.read_file) fail_at(doc_, at, "/include/ " + quote_shown(name) + ": there is no directory to read the file from here");
        if (frames_.size() > kMaxInclude) fail_at(doc_, at, "/include/ inside /include/ more than " + std::to_string(kMaxInclude) + " deep (a file that includes itself?)");
        std::string resolved;
        Bytes data;
        if (!opt_.read_file(name, f.from, resolved, data))
            fail_at(doc_, at, "/include/ " + quote_shown(name) + ": that file is not there, or it is not one that may be read (a relative name without '..')");
        total_ += data.size();
        if (total_ > kMaxText) fail_at(doc_, at, "the texts that /include/ brings in are more than " + std::to_string(kMaxText) + " bytes");
        owned_.emplace_back(reinterpret_cast<const char*>(data.data()), data.size());
        const uint32_t file = file_index(resolved.empty() ? name : resolved);
        frames_.push_back({owned_.back(), 0, 1, file, resolved});
        skip_bom(frames_.back());
    }

    Doc& doc_;
    const Options& opt_;
    std::vector<Frame> frames_;
    std::deque<std::string> owned_;
    size_t total_ = 0;
    bool pad_allowed_ = false;
    std::optional<Bytes> pad_;
    Pos pad_pos_;
};

// A token of an expression that is in parentheses.
enum class Op { None, LParen, RParen, Plus, Minus, Star, Slash, Percent, Shl, Shr, Lt, Gt, Le, Ge, Eq, Ne, BitAnd, BitOr, BitXor, And, Or, Not, Tilde, Quest, Colon };

class Parser {
public:
    Parser(Doc& doc, std::string_view text, const std::string& what, const Options& opt) : doc_(doc), opt_(opt), lx_(doc, text, what, opt) {}

    void run() {
        if (!lx_.at_word("/dts-v1/")) lx_.fail("a device tree source starts with /dts-v1/;");
        bool first = true;
        while (lx_.at_word("/dts-v1/")) {
            lx_.advance(8);
            lx_.expect(';', "behind /dts-v1/");
            bool plugin = false;
            if (lx_.at_word("/plugin/")) {
                lx_.advance(8);
                lx_.expect(';', "behind /plugin/");
                plugin = true;
            }
            if (first)
                doc_.plugin = plugin;
            else if (plugin != doc_.plugin)
                lx_.fail("Header flags don't match earlier ones");
            first = false;
        }
        for (;;) {  // /memreserve/
            bool any_label = false;
            while (lx_.label()) any_label = true;
            if (!lx_.at_word("/memreserve/")) {
                if (any_label) lx_.fail("a label that is not in front of a /memreserve/ or a node (a label cannot be on the root node)");
                break;
            }
            lx_.advance(12);
            const uint64_t address = integer_prim();
            const uint64_t size = integer_prim();
            lx_.expect(';', "behind /memreserve/");
            if (doc_.reserve.size() >= fdt::kMaxItems) lx_.fail("too many /memreserve/ entries");
            doc_.reserve.emplace_back(address, size);
        }
        tree();
    }

private:
    // ---- numbers and expressions

    Op peek_op() {
        lx_.skip();
        const char c = lx_.raw();
        const char d = lx_.raw_at(1);
        switch (c) {
            case '(': return Op::LParen;
            case ')': return Op::RParen;
            case '+': return Op::Plus;
            case '-': return Op::Minus;
            case '*': return Op::Star;
            case '/': return Op::Slash;
            case '%': return Op::Percent;
            case '<': return d == '<' ? Op::Shl : d == '=' ? Op::Le : Op::Lt;
            case '>': return d == '>' ? Op::Shr : d == '=' ? Op::Ge : Op::Gt;
            case '=': return d == '=' ? Op::Eq : Op::None;
            case '!': return d == '=' ? Op::Ne : Op::Not;
            case '&':
                if (d == '&') return Op::And;
                if (label_start(static_cast<unsigned char>(d)) || d == '{') return Op::None;  // a reference
                return Op::BitAnd;
            case '|': return d == '|' ? Op::Or : Op::BitOr;
            case '^': return Op::BitXor;
            case '~': return Op::Tilde;
            case '?': return Op::Quest;
            case ':': return Op::Colon;
            default: return Op::None;
        }
    }
    static size_t op_size(Op op) {
        switch (op) {
            case Op::Shl: case Op::Shr: case Op::Le: case Op::Ge: case Op::Eq: case Op::Ne: case Op::And: case Op::Or: return 2;
            default: return 1;
        }
    }
    void take_op(Op op) { lx_.advance(op_size(op)); }

    // The levels of the binary operators, the loosest first (the grammar of dtc-parser.y: integer_or ... integer_mul).
    static int level_of(Op op) {
        switch (op) {
            case Op::Or: return 0;
            case Op::And: return 1;
            case Op::BitOr: return 2;
            case Op::BitXor: return 3;
            case Op::BitAnd: return 4;
            case Op::Eq: case Op::Ne: return 5;
            case Op::Lt: case Op::Gt: case Op::Le: case Op::Ge: return 6;
            case Op::Shl: case Op::Shr: return 7;
            case Op::Plus: case Op::Minus: return 8;
            case Op::Star: case Op::Slash: case Op::Percent: return 9;
            default: return -1;
        }
    }

    uint64_t apply(Op op, uint64_t a, uint64_t b) {
        switch (op) {
            case Op::Or: return a || b;
            case Op::And: return a && b;
            case Op::BitOr: return a | b;
            case Op::BitXor: return a ^ b;
            case Op::BitAnd: return a & b;
            case Op::Eq: return a == b;
            case Op::Ne: return a != b;
            case Op::Lt: return a < b;
            case Op::Gt: return a > b;
            case Op::Le: return a <= b;
            case Op::Ge: return a >= b;
            case Op::Shl: return b < 64 ? a << b : 0;
            case Op::Shr: return b < 64 ? a >> b : 0;
            case Op::Plus: return a + b;
            case Op::Minus: return a - b;
            case Op::Star: return a * b;
            case Op::Slash:
                if (b == 0) lx_.fail("Division by zero");
                return a / b;
            case Op::Percent:
                if (b == 0) lx_.fail("Division by zero");
                return a % b;
            default: return 0;
        }
    }

    uint64_t binary(int level, size_t depth) {
        if (level > 9) return unary(depth);
        uint64_t lhs = binary(level + 1, depth);
        for (;;) {
            const Op op = peek_op();
            if (level_of(op) != level) return lhs;
            take_op(op);
            lhs = apply(op, lhs, binary(level + 1, depth));
        }
    }

    uint64_t unary(size_t depth) {
        const Op op = peek_op();
        if (op == Op::Minus) {
            take_op(op);
            return 0 - unary(depth);
        }
        if (op == Op::Tilde) {
            take_op(op);
            return ~unary(depth);
        }
        if (op == Op::Not) {
            take_op(op);
            return !unary(depth);
        }
        return prim(depth);
    }

    uint64_t prim(size_t depth) {
        if (peek_op() == Op::LParen) {
            if (depth >= fdt::kMaxDepth) lx_.fail("expressions in parentheses nested more than " + std::to_string(fdt::kMaxDepth) + " deep");
            take_op(Op::LParen);
            const uint64_t v = expr(depth + 1);
            if (peek_op() != Op::RParen) lx_.fail("expected ')' to close the expression, found " + lx_.found());
            take_op(Op::RParen);
            return v;
        }
        uint64_t v = 0;
        if (!lx_.number(v)) lx_.fail("expected a number or an expression in parentheses, found " + lx_.found());
        return v;
    }

    // integer_expr: `a ? b : c` is read from the right (dtc-parser.y: integer_trinary).
    uint64_t expr(size_t depth) {
        const uint64_t cond = binary(0, depth);
        if (peek_op() != Op::Quest) return cond;
        take_op(Op::Quest);
        const uint64_t a = expr(depth);
        if (peek_op() != Op::Colon) lx_.fail("expected ':' in the expression (a ? b : c), found " + lx_.found());
        take_op(Op::Colon);
        const uint64_t b = expr(depth);
        return cond ? a : b;
    }

    // integer_prim: a number, a character, or an expression in parentheses.
    uint64_t integer_prim() { return prim(0); }

    // ---- values

    void warn(const std::string& why) {
        if (opt_.warnings) opt_.warnings->push_back(doc_.files[lx_.pos().file] + ": line " + std::to_string(lx_.pos().line) + ": " + why);
    }

    void parse_array(LProp& p, unsigned bits) {  // behind '<'
        for (;;) {
            if (lx_.eat('>')) return;
            if (std::optional<std::string> l = lx_.label()) {
                p.data_labels.push_back(*l);
                continue;
            }
            if (std::optional<Lex::Ref> r = lx_.ref()) {
                if (bits != 32) lx_.fail("References are only allowed in arrays with 32-bit elements.");
                p.markers.push_back({p.value.size(), r->text, false});
                put_be(p.value, 0xffffffffu, 4);
                continue;
            }
            const uint64_t v = integer_prim();
            if (bits < 64) {
                const uint64_t mask = (uint64_t{1} << bits) - 1;
                // Bits above the mask are all zero, or all one (a negative number, sign-extended): anything else is cut, and dtc says so.
                if (v > mask && (v | mask) != ~uint64_t{0}) {
                    char buf[160];
                    std::snprintf(buf, sizeof buf, "Value 0x%016llx truncated to 0x%0*llx", static_cast<unsigned long long>(v), static_cast<int>(bits / 4),
                                  static_cast<unsigned long long>(v & mask));
                    warn(buf);
                }
            }
            put_be(p.value, v, bits / 8);
        }
    }

    void parse_bytes(LProp& p) {  // behind '['
        for (;;) {
            lx_.skip();
            if (lx_.eat(']')) return;
            if (std::optional<std::string> l = lx_.label()) {
                p.data_labels.push_back(*l);
                continue;
            }
            const int hi = hex_value(lx_.raw());
            if (hi < 0) lx_.fail("expected two hexadecimal digits or ']' in a byte string, found " + lx_.found());
            const int lo = hex_value(lx_.raw_at(1));
            if (lo < 0) lx_.fail("a byte in a byte string is two hexadecimal digits");
            lx_.advance(2);
            p.value.push_back(static_cast<uint8_t>(hi * 16 + lo));
        }
    }

    void parse_incbin(LProp& p, bool only) {
        lx_.advance(8);
        lx_.expect('(', "after /incbin/");
        const Pos at = lx_.pos();
        const std::string file = lx_.string();
        uint64_t skip = 0;
        uint64_t length = UINT64_MAX;
        bool ranged = false;
        if (lx_.eat(',')) {
            skip = integer_prim();
            lx_.expect(',', "after the offset of /incbin/");
            length = integer_prim();
            ranged = true;
        }
        lx_.expect(')', "behind /incbin/");
        if (!opt_.read_file) {
            // A name: the caller reads the file (fit.cpp does). Only the whole file, and nothing beside it in the property.
            if (ranged) fail_at(doc_, at, "/incbin/ with an offset and a length is not read here; the whole file is the value");
            if (!only) fail_at(doc_, at, "/incbin/ has to be the only value of its property");
            if (file.empty()) fail_at(doc_, at, "/incbin/ names no file");
            p.incbin = file;
            return;
        }
        std::string resolved;
        Bytes data;
        if (!opt_.read_file(file, lx_.current_from(), resolved, data))
            fail_at(doc_, at, "/incbin/ " + quote_shown(file) + ": that file is not there, or it is not one that may be read (a relative name without '..')");
        if (skip > data.size()) skip = data.size();
        const uint64_t take = std::min<uint64_t>(length, data.size() - skip);
        p.value.insert(p.value.end(), data.begin() + static_cast<std::ptrdiff_t>(skip), data.begin() + static_cast<std::ptrdiff_t>(skip + take));
    }

    void parse_value(LProp& p) {
        bool first = true;
        for (;;) {
            while (std::optional<std::string> l = lx_.label()) p.data_labels.push_back(*l);
            const char c = lx_.peek();
            if (c == '"') {
                const std::string s = lx_.string();
                p.value.insert(p.value.end(), s.begin(), s.end());
                p.value.push_back(0);
            } else if (c == '<') {
                lx_.advance(1);
                parse_array(p, 32);
            } else if (lx_.at_word("/bits/")) {
                lx_.advance(6);
                uint64_t bits = 0;
                if (!lx_.number(bits)) lx_.fail("expected the width of the elements (8, 16, 32 or 64) after /bits/");
                if (bits != 8 && bits != 16 && bits != 32 && bits != 64) lx_.fail("Array elements must be 8, 16, 32 or 64-bits");
                if (!lx_.eat('<')) lx_.fail("expected '<' after /bits/ and its width, found " + lx_.found());
                parse_array(p, static_cast<unsigned>(bits));
            } else if (c == '[') {
                lx_.advance(1);
                parse_bytes(p);
            } else if (c == '&') {
                std::optional<Lex::Ref> r = lx_.ref();
                if (!r) lx_.fail("expected a reference (&label or &{/path}), found '&'");
                p.markers.push_back({p.value.size(), r->text, true});
            } else if (lx_.at_word("/incbin/")) {
                parse_incbin(p, first);
            } else {
                lx_.fail("expected a value (a string, <cells>, [bytes], a reference or /incbin/), found " + lx_.found());
            }
            first = false;
            while (std::optional<std::string> l = lx_.label()) p.data_labels.push_back(*l);
            if (!p.incbin.empty() && lx_.peek() == ',') lx_.fail("/incbin/ has to be the only value of its property");
            if (!lx_.eat(',')) return;
        }
    }

    // ---- nodes

    // The properties and the nodes of a node, behind its '{' and up to (not including) its '}'.
    void body(LNode& n, size_t depth, size_t& items) {
        bool child_seen = false;
        for (;;) {
            std::vector<std::string> labels;
            while (std::optional<std::string> l = lx_.label()) labels.push_back(*l);
            const char c = lx_.peek();
            if (c == '}') {
                if (!labels.empty()) lx_.fail("a label with nothing behind it");
                return;
            }
            if (c == '\0') lx_.fail("the text ends inside a node (a '}' is missing)");
            bool omit = false;
            if (lx_.at_word("/delete-property/")) {
                if (child_seen) lx_.fail("Properties must precede subnodes");
                lx_.advance(17);
                LProp d;
                d.pos = lx_.pos();
                d.name = lx_.name();
                d.deleted = true;
                lx_.expect(';', "behind /delete-property/ and the name");
                if (++items > fdt::kMaxItems) lx_.fail("more than " + std::to_string(fdt::kMaxItems) + " nodes and properties");
                n.props.push_back(std::move(d));
                continue;
            }
            if (lx_.at_word("/delete-node/")) {
                lx_.advance(13);
                auto d = std::make_unique<LNode>();
                d->pos = lx_.pos();
                d->name = lx_.name();
                d->deleted = true;
                lx_.expect(';', "behind /delete-node/ and the name");
                if (++items > fdt::kMaxItems) lx_.fail("more than " + std::to_string(fdt::kMaxItems) + " nodes and properties");
                add_child(n, std::move(d));
                child_seen = true;
                continue;
            }
            if (lx_.at_word("/omit-if-no-ref/")) {
                lx_.advance(16);
                omit = true;
                while (std::optional<std::string> l = lx_.label()) labels.push_back(*l);
            } else if (c == '/') {
                lx_.fail("a directive that abr does not read here: " + lx_.found());
            }
            const Pos at = lx_.pos();
            const std::string name = lx_.name();
            if (++items > fdt::kMaxItems) lx_.fail("more than " + std::to_string(fdt::kMaxItems) + " nodes and properties");
            if (lx_.peek() == '{') {
                if (depth >= fdt::kMaxDepth) lx_.fail("nodes nested more than " + std::to_string(fdt::kMaxDepth) + " deep");
                lx_.advance(1);
                auto child = std::make_unique<LNode>();
                child->name = name;
                child->pos = at;
                child->omit_if_unused = omit;
                for (size_t k = labels.size(); k-- > 0;) add_label(child->labels, labels[k]);
                body(*child, depth + 1, items);
                lx_.expect('}', "to close the node");
                lx_.expect(';', "behind the '}' of a node");
                add_child(n, std::move(child));
                child_seen = true;
                continue;
            }
            if (omit) lx_.fail("/omit-if-no-ref/ is for a node");
            if (child_seen) lx_.fail("Properties must precede subnodes");
            LProp p;
            p.name = name;
            p.pos = at;
            for (size_t k = labels.size(); k-- > 0;) add_label(p.labels, labels[k]);
            const char next = lx_.peek();
            if (next == '=') {
                lx_.advance(1);
                parse_value(p);
            } else if (next != ';') {
                lx_.fail("expected '=', '{' or ';' after the name " + quote_shown(name) + ", found " + lx_.found());
            }
            lx_.expect(';', "at the end of the property");
            Pos pad_at;
            if (std::optional<Bytes> pad = lx_.take_pad(pad_at)) {
                if (!p.incbin.empty())
                    fail_at(doc_, pad_at, "the comment \"abr: padding\" is behind the property " + quote_shown(name) + ", whose value is a file: its padding is the one of the bytes of the file");
                if (pad->size() != fdt::padding_size(p.value.size()))
                    fail_at(doc_, pad_at, "the comment \"abr: padding\" behind the property " + quote_shown(name) + " lists " + std::to_string(pad->size()) + " byte(s), and its value of " +
                                              std::to_string(p.value.size()) + " bytes has " + std::to_string(fdt::padding_size(p.value.size())) + " of padding");
                for (uint8_t b : *pad)
                    if (b != 0) {
                        p.pad = std::move(*pad);
                        break;
                    }
            }
            n.props.push_back(std::move(p));
        }
    }

    // `{ ... };`: a node of the given name, not yet put anywhere.
    std::unique_ptr<LNode> nodedef(const std::string& name, Pos at) {
        lx_.expect('{', "to open the node");
        auto n = std::make_unique<LNode>();
        n->name = name;
        n->pos = at;
        body(*n, 1, items_);
        lx_.expect('}', "to close the node");
        lx_.expect(';', "behind the '}' of a node");
        return n;
    }

    // dtc's add_orphan_node(): a /plugin/ that changes a node it does not have becomes a fragment, `target` or `target-path` and `__overlay__`.
    void add_orphan(const std::string& ref, std::unique_ptr<LNode> body_node) {
        LProp target;
        if (!ref.empty() && ref[0] == '/') {
            target.name = "target-path";
            target.value.assign(ref.begin(), ref.end());
            target.value.push_back(0);
        } else {
            target.name = "target";
            target.markers.push_back({0, ref, false});
            put_be(target.value, 0xffffffffu, 4);
        }
        body_node->name = "__overlay__";
        auto fragment = std::make_unique<LNode>();
        fragment->name = "fragment@" + std::to_string(doc_.next_fragment++);
        fragment->pos = body_node->pos;
        fragment->props.push_back(std::move(target));
        add_child(*fragment, std::move(body_node));
        add_child(*doc_.root, std::move(fragment));
    }

    static bool relative_ref(const std::string& ref) { return !ref.empty() && ref[0] != '/' && ref.find('/', 1) != std::string::npos; }

    void tree() {
        bool have_root = false;
        auto new_root = [&]() {
            doc_.root = std::make_unique<LNode>();
            have_root = true;
        };
        while (!lx_.at_end()) {
            std::vector<std::string> labels;
            while (std::optional<std::string> l = lx_.label()) labels.push_back(*l);
            const Pos at = lx_.pos();
            if (lx_.at_word("/delete-node/") || lx_.at_word("/omit-if-no-ref/")) {
                const bool del = lx_.at_word("/delete-node/");
                if (!labels.empty()) lx_.fail("a label in front of /delete-node/ or /omit-if-no-ref/");
                if (!have_root) lx_.fail("expected the root node ('/ {'), found a directive");
                lx_.advance(del ? 13 : 16);
                const std::optional<Lex::Ref> r = lx_.ref();
                if (!r) lx_.fail("expected a reference (&label or &{/path}), found " + lx_.found());
                lx_.expect(';', "behind the reference");
                LNode* target = find_by_ref(*doc_.root, r->text);
                if (!target) fail_at(doc_, at, "Label or path " + (r->text.empty() ? std::string("(empty: &{})") : r->text) + " not found");
                if (del)
                    delete_node(*target);
                else
                    target->omit_if_unused = true;
                continue;
            }
            if (!labels.empty() && !have_root) lx_.fail("a label in front of the first node (the root node has none)");
            if (lx_.at_word("/memreserve/")) lx_.fail("a /memreserve/ has to come before the root node");
            if (lx_.at_word("/dts-v1/")) lx_.fail("a second /dts-v1/ behind the tree");
            if (lx_.peek() == '/') {
                if (!labels.empty()) lx_.fail("a label cannot be on the root node");
                lx_.advance(1);
                std::unique_ptr<LNode> nn = nodedef("", at);
                if (!have_root) {
                    doc_.root = std::move(nn);
                    have_root = true;
                } else {
                    merge_nodes(*doc_.root, std::move(*nn));
                }
                continue;
            }
            const std::optional<Lex::Ref> r = lx_.ref();
            if (!r) lx_.fail("expected '/' (the root node), a reference (&label { }) or /delete-node/, found " + lx_.found());
            std::unique_ptr<LNode> nn = nodedef("", at);
            if (!have_root) {
                if (!doc_.plugin) fail_at(doc_, at, "Label or path " + (r->text.empty() ? std::string("(empty: &{})") : r->text) + " not found");
                if (relative_ref(r->text)) fail_at(doc_, at, "Label-relative reference " + r->text + " not supported in plugin");
                new_root();
                add_orphan(r->text, std::move(nn));
                continue;
            }
            if (!labels.empty()) {
                if (doc_.plugin && relative_ref(r->text)) fail_at(doc_, at, "Label-relative reference " + r->text + " not supported in plugin");
                LNode* target = find_by_ref(*doc_.root, r->text);
                if (!target) fail_at(doc_, at, "Label or path " + (r->text.empty() ? std::string("(empty: &{})") : r->text) + " not found");
                for (size_t k = labels.size(); k-- > 0;) add_label(target->labels, labels[k]);
                merge_nodes(*target, std::move(*nn));
            } else if (r->path && doc_.plugin) {
                if (relative_ref(r->text)) fail_at(doc_, at, "Label-relative reference " + r->text + " not supported in plugin");
                add_orphan(r->text, std::move(nn));
            } else {
                LNode* target = find_by_ref(*doc_.root, r->text);
                if (target)
                    merge_nodes(*target, std::move(*nn));
                else if (doc_.plugin)
                    add_orphan(r->text, std::move(nn));
                else
                    fail_at(doc_, at, "Label or path " + (r->text.empty() ? std::string("(empty: &{})") : r->text) + " not found");
            }
        }
        if (!have_root) lx_.fail("there is no root node ('/ { };')");
        doc_.root->name.clear();
    }

    Doc& doc_;
    const Options& opt_;
    Lex lx_;
    size_t items_ = 0;
};

// ------------------------------------------------------------------------------------------------------------ what dtc does to a tree

void walk(LNode& n, const std::function<void(LNode&)>& fn) {
    fn(n);
    for (size_t i = 0; i < n.children.size(); ++i)
        if (!n.children[i]->deleted) walk(*n.children[i], fn);
}

size_t basename_length(const LNode& n) {
    const size_t at = n.name.find('@');
    return at == std::string::npos ? n.name.size() : at;
}

// dtc's join_path(): the root is "/", a child of it "/name", a grandchild "/name/name".
void fill_fullpaths(LNode& n, const std::string& prefix) {
    n.fullpath = !prefix.empty() && prefix.back() == '/' ? prefix + n.name : prefix + "/" + n.name;
    for (auto& c : n.children)
        if (!c->deleted) fill_fullpaths(*c, n.fullpath);
}

bool is_one_string(const Bytes& v) {
    if (v.empty() || v.back() != 0) return false;
    for (size_t i = 0; i + 1 < v.size(); ++i)
        if (v[i] == 0) return false;
    return true;
}

constexpr bool phandle_valid(uint32_t p) { return p != 0 && p != 0xffffffffu; }

class Finisher {
public:
    Finisher(Doc& doc, const Options& opt) : doc_(doc), opt_(opt) {}

    void run() {
        LNode& root = *doc_.root;
        fill_fullpaths(root, "");
        walk(root, [&](LNode& n) { check_duplicate_nodes(n); });
        walk(root, [&](LNode& n) { check_duplicate_props(n); });
        walk(root, [&](LNode& n) { check_node_names(n); });
        walk(root, [&](LNode& n) { check_prop_names(n); });
        walk(root, [&](LNode& n) { check_name_props(n); });
        check_duplicate_labels();
        walk(root, [&](LNode& n) { explicit_phandles(n); });
        walk(root, [&](LNode& n) { phandle_references(n); });
        walk(root, [&](LNode& n) { path_references(n); });
        walk(root, [&](LNode& n) {
            if (n.omit_if_unused && !n.referenced && !(opt_.symbols && has_labels(n))) delete_node(n);
        });
        if (opt_.symbols) symbols();
        if (doc_.plugin) {
            fixups();
            local_fixups();
        }
    }

private:
    [[noreturn]] void fail_node(const LNode& n, const std::string& why) const { fail_at(doc_, n.pos, n.fullpath + ": " + why); }
    [[noreturn]] void fail_prop(const LNode& n, const LProp& p, const std::string& why) const { fail_at(doc_, p.pos, n.fullpath + ":" + p.name + ": " + why); }

    // dtc asks whether the list of labels is there, not whether a label in it is alive (a node whose labels were all deleted with it and that
    // came back keeps a phandle with -@, and is not dropped by /omit-if-no-ref/).
    static bool has_labels(const LNode& n) { return !n.labels.empty(); }

    void check_duplicate_nodes(LNode& n) {
        for (size_t i = 0; i < n.children.size(); ++i) {
            if (n.children[i]->deleted) continue;
            for (size_t j = i + 1; j < n.children.size(); ++j)
                if (n.children[i]->name == n.children[j]->name) fail_node(*n.children[j], "Duplicate node name");
        }
    }

    void check_duplicate_props(LNode& n) {
        for (size_t i = 0; i < n.props.size(); ++i) {
            if (n.props[i].deleted) continue;
            for (size_t j = i + 1; j < n.props.size(); ++j) {
                if (n.props[j].deleted) continue;
                if (n.props[i].name == n.props[j].name) fail_prop(n, n.props[i], "Duplicate property name");
            }
        }
    }

    void check_node_names(LNode& n) {
        for (unsigned char c : n.name)
            if (!node_name_char(c)) fail_node(n, std::string("Bad character '") + quote_shown(std::string(1, static_cast<char>(c))) + "' in node name");
        const size_t at = n.name.find('@');
        if (at != std::string::npos && n.name.find('@', at + 1) != std::string::npos) fail_node(n, "multiple '@' characters in node name");
    }

    void check_prop_names(LNode& n) {
        for (const LProp& p : n.props) {
            if (p.deleted) continue;
            for (unsigned char c : p.name)
                if (!prop_name_char(c)) fail_prop(n, p, std::string("Bad character '") + quote_shown(std::string(1, static_cast<char>(c))) + "' in property name");
        }
    }

    // A `name` property that says what the name of the node says is dropped; one that says something else, or is not a string, is an error.
    void check_name_props(LNode& n) {
        if (LProp* p = find_prop(n, "name"); p && !is_one_string(p->value)) fail_prop(n, *p, "property is not a string");
        for (size_t i = 0; i < n.props.size(); ++i) {
            if (n.props[i].name != "name") continue;
            const LProp& p = n.props[i];
            const size_t base = basename_length(n);
            if (p.value.size() != base + 1 || !std::equal(p.value.begin(), p.value.begin() + static_cast<std::ptrdiff_t>(base), n.name.begin()))
                fail_node(n, "\"name\" property is incorrect (\"" + quote_shown(std::string(p.value.begin(), p.value.end() - (p.value.empty() ? 0 : 1))) + "\" instead of base node name)");
            n.props.erase(n.props.begin() + static_cast<std::ptrdiff_t>(i));
            return;
        }
    }

    void check_duplicate_labels() {
        std::map<std::string, std::tuple<const LNode*, const LProp*, size_t>> seen;
        auto note = [&](const std::string& label, const LNode* n, const LProp* p, size_t index) {
            const auto key = std::make_tuple(n, p, index);
            const auto [it, added] = seen.emplace(label, key);
            if (!added && it->second != key) {
                const LNode* other = std::get<0>(it->second);
                fail_node(*n, "Duplicate label '" + label + "' on " + n->fullpath + (p ? ":" + p->name : std::string()) + " and " + other->fullpath);
            }
        };
        walk(*doc_.root, [&](LNode& n) {
            for (const Label& l : n.labels)
                if (!l.deleted) note(l.name, &n, nullptr, 0);
            for (const LProp& p : n.props) {
                if (p.deleted) continue;
                for (const Label& l : p.labels)
                    if (!l.deleted) note(l.name, &n, &p, 0);
                size_t index = 1;
                for (const std::string& l : p.data_labels) note(l, &n, &p, index++);
            }
        });
    }

    // The phandle that a `phandle` or a `linux,phandle` property holds, 0 for none -- and for a node that gives itself one to be made.
    uint32_t phandle_prop(LNode& n, const char* name) {
        LProp* p = find_prop(n, name);
        if (!p) return 0;
        if (p->value.size() != 4) fail_prop(n, *p, "bad length (" + std::to_string(p->value.size()) + ") " + name + " property");
        for (const Marker& m : p->markers) {
            if (m.path) continue;
            if (&n != find_by_ref(*doc_.root, m.ref)) fail_node(n, std::string(name) + " is a reference to another node");
            return 0;
        }
        const uint32_t v = (uint32_t(p->value[0]) << 24) | (uint32_t(p->value[1]) << 16) | (uint32_t(p->value[2]) << 8) | p->value[3];
        if (!phandle_valid(v)) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "bad value (0x%x) in %s property", v, name);
            fail_prop(n, *p, buf);
        }
        return v;
    }

    void explicit_phandles(LNode& n) {
        const uint32_t phandle = phandle_prop(n, "phandle");
        const uint32_t linux_phandle = phandle_prop(n, "linux,phandle");
        if (!phandle && !linux_phandle) return;
        if (linux_phandle && phandle && phandle != linux_phandle) fail_node(n, "mismatching 'phandle' and 'linux,phandle' properties");
        const uint32_t value = phandle ? phandle : linux_phandle;
        const auto it = by_phandle_.find(value);
        if (it != by_phandle_.end() && it->second != &n) {
            char buf[64];
            std::snprintf(buf, sizeof buf, "duplicated phandle 0x%x (seen before at ", value);
            fail_node(n, std::string(buf) + it->second->fullpath + ")");
        }
        n.phandle = value;
        by_phandle_[value] = &n;
    }

    // dtc's get_node_phandle(): the phandle of a node, the lowest one that is free if it has none yet; a `phandle` property is put behind the
    // others of a node that has none.
    uint32_t node_phandle(LNode& n) {
        if (phandle_valid(n.phandle)) return n.phandle;
        while (by_phandle_.count(next_phandle_)) ++next_phandle_;
        n.phandle = next_phandle_;
        by_phandle_[next_phandle_] = &n;
        if (!find_prop(n, "phandle")) {
            LProp p;
            p.name = "phandle";
            put_be(p.value, n.phandle, 4);
            n.props.push_back(std::move(p));
        }
        return n.phandle;
    }

    void phandle_references(LNode& n) {
        for (size_t i = 0; i < n.props.size(); ++i) {
            if (n.props[i].deleted) continue;
            const std::vector<Marker> markers = n.props[i].markers;  // node_phandle() may add a property to this very node
            for (const Marker& m : markers) {
                if (m.path) continue;
                LNode* target = find_by_ref(*doc_.root, m.ref);
                if (!target) {
                    if (!doc_.plugin) fail_prop(n, n.props[i], "Reference to non-existent node or label \"" + m.ref + "\"");
                    continue;  // stays 0xffffffff: __fixups__ says where
                }
                const uint32_t ph = node_phandle(*target);
                for (unsigned k = 0; k < 4; ++k) n.props[i].value[m.offset + k] = static_cast<uint8_t>(ph >> (24 - 8 * k));
                target->referenced = true;
            }
        }
    }

    void path_references(LNode& n) {
        for (LProp& p : n.props) {
            if (p.deleted) continue;
            for (size_t i = 0; i < p.markers.size(); ++i) {
                if (!p.markers[i].path) continue;
                LNode* target = find_by_ref(*doc_.root, p.markers[i].ref);
                if (!target) fail_prop(n, p, "Reference to non-existent node or label \"" + p.markers[i].ref + "\"");
                const std::string& path = target->fullpath;
                const size_t at = p.markers[i].offset;
                p.value.insert(p.value.begin() + static_cast<std::ptrdiff_t>(at), path.begin(), path.end());
                p.value.insert(p.value.begin() + static_cast<std::ptrdiff_t>(at + path.size()), uint8_t{0});
                for (size_t k = i + 1; k < p.markers.size(); ++k) p.markers[k].offset += path.size() + 1;
                target->referenced = true;
            }
        }
    }

    // ---- what dtc's main() does behind the checks

    LNode& root_child(const std::string& name) {
        for (auto& c : doc_.root->children)
            if (!c->deleted && c->name == name) return *c;
        auto c = std::make_unique<LNode>();
        c->name = name;
        LNode& ref = *c;
        add_child(*doc_.root, std::move(c));
        return ref;
    }

    static void append_to_property(LNode& n, const std::string& name, const uint8_t* data, size_t size) {
        if (LProp* p = find_prop(n, name)) {
            p->value.insert(p->value.end(), data, data + size);
            return;
        }
        LProp p;
        p.name = name;
        p.value.assign(data, data + size);
        n.props.push_back(std::move(p));
    }

    void symbols() {
        bool any = false;
        walk(*doc_.root, [&](LNode& n) { any = any || has_labels(n); });
        if (!any) return;
        LNode& an = root_child("__symbols__");
        walk(*doc_.root, [&](LNode& n) {
            if (!has_labels(n)) return;
            for (size_t i = 0; i < n.labels.size(); ++i) {
                if (n.labels[i].deleted) continue;
                if (find_prop(an, n.labels[i].name)) {
                    if (opt_.warnings) opt_.warnings->push_back("label " + n.labels[i].name + " already exists in /" + an.name);
                    continue;
                }
                LProp p;
                p.name = n.labels[i].name;
                p.value.assign(n.fullpath.begin(), n.fullpath.end());
                p.value.push_back(0);
                an.props.push_back(std::move(p));
            }
            node_phandle(n);
        });
    }

    void fixups() {
        bool any = false;
        walk(*doc_.root, [&](LNode& n) {
            for (const LProp& p : n.props)
                if (!p.deleted)
                    for (const Marker& m : p.markers)
                        if (!m.path && !find_by_ref(*doc_.root, m.ref)) any = true;
        });
        if (!any) return;
        LNode& fn = root_child("__fixups__");
        walk(*doc_.root, [&](LNode& n) {
            for (const LProp& p : n.props) {
                if (p.deleted) continue;
                for (const Marker& m : p.markers) {
                    if (m.path || find_by_ref(*doc_.root, m.ref)) continue;
                    if (m.ref.find('/') != std::string::npos) throw FormatError("Can't generate fixup for reference to path &{" + m.ref + "}");
                    if (n.fullpath.find(':') != std::string::npos || p.name.find(':') != std::string::npos) throw FormatError("arguments should not contain ':'");
                    const std::string entry = n.fullpath + ":" + p.name + ":" + std::to_string(m.offset);
                    append_to_property(fn, m.ref, reinterpret_cast<const uint8_t*>(entry.c_str()), entry.size() + 1);
                }
            }
        });
    }

    void local_fixups() {
        bool any = false;
        walk(*doc_.root, [&](LNode& n) {
            for (const LProp& p : n.props)
                if (!p.deleted)
                    for (const Marker& m : p.markers)
                        if (!m.path && find_by_ref(*doc_.root, m.ref)) any = true;
        });
        if (!any) return;
        LNode& lfn = root_child("__local_fixups__");
        // The nodes that hold a reference, found before any node is added (the tree that is walked is not the one that grows).
        struct Entry {
            LNode* node;
            std::string prop;
            size_t offset;
        };
        std::vector<Entry> entries;
        walk(*doc_.root, [&](LNode& n) {
            for (const LProp& p : n.props) {
                if (p.deleted) continue;
                for (const Marker& m : p.markers)
                    if (!m.path && find_by_ref(*doc_.root, m.ref)) entries.push_back({&n, p.name, m.offset});
            }
        });
        for (const Entry& e : entries) {
            std::vector<const LNode*> chain;
            for (const LNode* w = e.node; w; w = w->parent) chain.push_back(w);
            LNode* at = &lfn;
            for (size_t i = chain.size() - 1; i-- > 0;) {  // below the root
                LNode* next = nullptr;
                for (auto& c : at->children)
                    if (!c->deleted && c->name == chain[i]->name) next = c.get();
                if (!next) {
                    auto c = std::make_unique<LNode>();
                    c->name = chain[i]->name;
                    next = c.get();
                    add_child(*at, std::move(c));
                }
                at = next;
            }
            uint8_t be[4];
            for (unsigned k = 0; k < 4; ++k) be[k] = static_cast<uint8_t>(e.offset >> (24 - 8 * k));
            append_to_property(*at, e.prop, be, 4);
        }
    }

    Doc& doc_;
    const Options& opt_;
    std::map<uint32_t, LNode*> by_phandle_;
    uint32_t next_phandle_ = 1;
};

uint32_t guess_boot_cpuid(LNode& root) {
    LNode* cpus = find_by_path(root, "/cpus");
    if (!cpus || cpus->children.empty()) return 0;
    LProp* reg = find_prop(*cpus->children.front(), "reg");
    if (!reg || reg->value.size() != 4) return 0;
    return (uint32_t(reg->value[0]) << 24) | (uint32_t(reg->value[1]) << 16) | (uint32_t(reg->value[2]) << 8) | reg->value[3];
}

void to_node(const LNode& n, fdt::Node& out) {
    out.name = n.name;
    for (const LProp& p : n.props) {
        if (p.deleted) continue;
        fdt::Property q;
        q.name = p.name;
        q.value = p.value;
        q.incbin = p.incbin;
        if (p.pad.size() == fdt::padding_size(p.value.size())) q.pad = p.pad;
        out.props.push_back(std::move(q));
    }
    for (const auto& c : n.children) {
        if (c->deleted) continue;
        out.children.emplace_back();
        to_node(*c, out.children.back());
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

fdt::Tree parse(std::string_view text, const std::string& what, const Options& options) {
    Doc doc;
    Parser(doc, text, what, options).run();
    doc.boot_cpuid = guess_boot_cpuid(*doc.root);
    Finisher(doc, options).run();
    // dtc writes a blob without a node in it when the root is deleted (/delete-node/ &{/};) and says nothing; a blob nobody can read is no
    // result.
    if (doc.root->deleted) throw FormatError(what + ": the root node is deleted (/delete-node/ &{/};): there is nothing left of the tree");
    fdt::Tree tree;
    tree.boot_cpuid_phys = doc.boot_cpuid;
    tree.reserve = doc.reserve;
    to_node(*doc.root, tree.root);
    return tree;
}

std::function<bool(const std::string&, const std::string&, std::string&, Bytes&)> directory_reader(const std::string& directory) {
    return [dir = std::filesystem::path(directory)](const std::string& name, const std::string& from, std::string& resolved, Bytes& out) {
        if (name.empty() || *path_problem(name)) return false;
        std::filesystem::path rel(name);
        if (!from.empty()) rel = std::filesystem::path(from).parent_path() / name;
        const std::string shown = rel.generic_string();
        if (*path_problem(shown)) return false;
        std::error_code ec;
        const std::filesystem::path full = dir / rel;
        if (!std::filesystem::is_regular_file(full, ec)) return false;
        const auto size = std::filesystem::file_size(full, ec);
        if (ec || size > kMaxText) return false;
        try {
            out = read_file(full);
        } catch (const std::exception&) {
            return false;
        }
        resolved = shown;
        return true;
    };
}

}  // namespace abr::dts
