// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/ramdisk_tree.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <numeric>
#include <optional>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

#include "abr/cpio.hpp"
#include "abr/sha.hpp"

namespace abr {

namespace fs = std::filesystem;

namespace {

#ifdef _WIN32
constexpr bool kWindows = true;
#else
constexpr bool kWindows = false;
#endif

// More archives one after the other than this is not a ramdisk somebody made on purpose.
constexpr size_t kMaxVolumes = 64;

// ------------------------------------------------------------------ the metadata --

struct Extras {
    std::optional<uint32_t> ino;
    std::optional<uint32_t> nlink;
    std::optional<std::pair<uint32_t, uint32_t>> dev;
    std::optional<std::pair<uint32_t, uint32_t>> rdev;
};

struct MetaEntry {
    char type = 'f';  // d f l c b p s, and T for the end record of the archive
    uint32_t mode = 0;  // the permission bits; for T the whole mode word
    uint32_t uid = 0;
    uint32_t gid = 0;
    uint32_t mtime = 0;
    Extras x;
    std::string path;
};

enum class Order { SORTED, ARCHIVE };
enum class NlinkScheme { ONE, POSIX, EXPLICIT };

struct Meta {
    cpio::Magic magic = cpio::Magic::NEWC;
    bool hex_upper = false;  // the digits A-F of the headers are upper case (GNU cpio) rather than lower (mkbootfs)
    bool dotslash = false;  // the names start with "./" (what `find . | cpio` writes), but for the root "."
    Order order = Order::SORTED;
    bool ino_sequential = true;
    uint32_t ino_base = 300000;
    NlinkScheme nlink = NlinkScheme::ONE;
    bool tail_align = true;  // zero fill up to a multiple of tail_value (counted from the start of the
                             // whole ramdisk), else tail_value bytes of it
    uint32_t tail_value = 256;
    uint32_t default_uid = 0;
    uint32_t default_gid = 0;
    uint32_t default_mtime = 0;
    uint32_t default_devmajor = 0;
    uint32_t default_devminor = 0;
    // The permissions of an entry that is not listed.
    uint32_t new_file = 0644;
    uint32_t new_exec = 0755;
    uint32_t new_dir = 0755;
    uint32_t new_link = 0777;
    MetaEntry trailer;
    std::vector<MetaEntry> entries;

    Meta() {
        trailer.type = 'T';
        trailer.mode = 0755;  // what Android's mkbootfs writes
        trailer.path = cpio::kTrailerName;
    }
};

[[noreturn]] void meta_error(size_t line, const std::string& what) {
    throw FormatError("line " + std::to_string(line) + ": " + what);
}

uint32_t parse_u32(std::string_view s, int base, size_t line, const char* what) {
    if (s.empty()) meta_error(line, std::string("an empty ") + what);
    uint64_t v = 0;
    for (char c : s) {
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else d = 99;
        if (d >= base) meta_error(line, std::string("'") + std::string(s) + "' is not a valid " + what);
        v = v * static_cast<uint64_t>(base) + static_cast<uint64_t>(d);
        if (v > 0xFFFFFFFFull) meta_error(line, std::string("the ") + what + " '" + std::string(s) + "' is too large");
    }
    return static_cast<uint32_t>(v);
}

uint32_t parse_permissions(std::string_view s, size_t line, const char* what) {
    const uint32_t v = parse_u32(s, 8, line, what);
    if (v & ~07777u) meta_error(line, std::string("the ") + what + " '" + std::string(s) + "' has bits beyond the permissions");
    return v;
}

std::pair<uint32_t, uint32_t> parse_pair(std::string_view s, size_t line, const char* what) {
    const size_t colon = s.find(':');
    if (colon == std::string_view::npos) meta_error(line, std::string("'") + std::string(s) + "' should be MAJOR:MINOR");
    return {parse_u32(s.substr(0, colon), 10, line, what), parse_u32(s.substr(colon + 1), 10, line, what)};
}

std::string octal(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%04o", static_cast<unsigned>(v));
    return buf;
}

std::string format_extras(const Extras& x) {
    std::string out;
    auto add = [&](const std::string& s) {
        if (!out.empty()) out += ',';
        out += s;
    };
    if (x.ino) add("ino=" + std::to_string(*x.ino));
    if (x.nlink) add("nlink=" + std::to_string(*x.nlink));
    if (x.dev) add("dev=" + std::to_string(x.dev->first) + ":" + std::to_string(x.dev->second));
    if (x.rdev) add("rdev=" + std::to_string(x.rdev->first) + ":" + std::to_string(x.rdev->second));
    return out.empty() ? "-" : out;
}

Extras parse_extras(std::string_view s, size_t line) {
    Extras x;
    if (s == "-") return x;
    while (!s.empty()) {
        const size_t comma = s.find(',');
        const std::string_view item = s.substr(0, comma);
        s = comma == std::string_view::npos ? std::string_view() : s.substr(comma + 1);
        const size_t eq = item.find('=');
        if (eq == std::string_view::npos) meta_error(line, "'" + std::string(item) + "' should be key=value");
        const std::string_view key = item.substr(0, eq);
        const std::string_view value = item.substr(eq + 1);
        if (key == "ino") x.ino = parse_u32(value, 10, line, "inode number");
        else if (key == "nlink") x.nlink = parse_u32(value, 10, line, "link count");
        else if (key == "dev") x.dev = parse_pair(value, line, "device number");
        else if (key == "rdev") x.rdev = parse_pair(value, line, "device number");
        else meta_error(line, "unknown extra '" + std::string(key) + "'");
    }
    return x;
}

// A path is written as it is unless that would not read back the same: then in quotes, with the
// escapes of C.
std::string quote_path(const std::string& p) {
    bool plain = !p.empty() && p.front() != ' ' && p.front() != '\t' && p.front() != '"' && p.back() != ' ' &&
                 p.back() != '\t';
    for (unsigned char c : p)
        if (c < 0x20 || c == 0x7F || c == '\\') plain = false;
    if (plain) return p;
    std::string out = "\"";
    for (unsigned char c : p) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            case '\r': out += "\\r"; break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\x%02x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out + "\"";
}

std::string unquote_path(std::string_view s, size_t line) {
    if (s.empty() || s.front() != '"') {
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
        return std::string(s);
    }
    std::string out;
    size_t i = 1;
    for (; i < s.size() && s[i] != '"'; ++i) {
        if (s[i] != '\\') {
            out += s[i];
            continue;
        }
        if (++i >= s.size()) meta_error(line, "a quoted path ends in a backslash");
        switch (s[i]) {
            case '\\': out += '\\'; break;
            case '"': out += '"'; break;
            case 'n': out += '\n'; break;
            case 't': out += '\t'; break;
            case 'r': out += '\r'; break;
            case 'x':
                if (i + 2 >= s.size()) meta_error(line, "a quoted path ends in a \\x escape");
                out += static_cast<char>(parse_u32(s.substr(i + 1, 2), 16, line, "\\x escape"));
                i += 2;
                break;
            default: meta_error(line, std::string("unknown escape \\") + s[i] + " in a quoted path");
        }
    }
    if (i >= s.size()) meta_error(line, "a quoted path is not closed");
    return out;
}

std::string format_entry(const MetaEntry& e) {
    std::string out;
    out += e.type;
    out += ' ';
    out += octal(e.mode);
    out += ' ' + std::to_string(e.uid) + ' ' + std::to_string(e.gid) + ' ' + std::to_string(e.mtime);
    out += ' ' + format_extras(e.x) + ' ' + quote_path(e.path) + '\n';
    return out;
}

std::string format_meta(const Meta& m) {
    std::string out =
        "# abr ramdisk metadata -- what the directory next to this file cannot say.\n"
        "# One line per entry, in the order of the archive:  type mode uid gid mtime extras path\n"
        "#   type    d directory, f file, l symbolic link, c/b device node, p fifo, s socket\n"
        "#           (a device node, fifo or socket is an empty file in the directory; T ends the archive)\n"
        "#   mode    permission bits in octal (setuid/setgid/sticky included)\n"
        "#   extras  ino=N nlink=N dev=MAJOR:MINOR rdev=MAJOR:MINOR, comma separated, or - for none\n"
        "# Owners and modes are taken from here and never from the file system, so they come through\n"
        "# Windows, which has none. A path deleted from the directory is deleted from the ramdisk. A path in\n"
        "# the directory that is not listed here is new: it gets `default` for its owner and time and\n"
        "# `newmode` for its permissions (exec: an executable file -- the executable bit, or an ELF binary\n"
        "# or a #! script). To give a new file other values, add a line for it.\n";
    out += std::string("format ") + (m.magic == cpio::Magic::CRC ? "crc" : "newc") + '\n';
    out += std::string("hex ") + (m.hex_upper ? "upper" : "lower") + '\n';
    out += std::string("names ") + (m.dotslash ? "dotslash" : "plain") + '\n';
    out += std::string("order ") + (m.order == Order::SORTED ? "sorted" : "archive") + '\n';
    out += m.ino_sequential ? "inode sequential " + std::to_string(m.ino_base) + "\n" : std::string("inode explicit\n");
    out += std::string("nlink ") + (m.nlink == NlinkScheme::ONE ? "1" : m.nlink == NlinkScheme::POSIX ? "posix" : "explicit") + '\n';
    out += std::string("tail ") + (m.tail_align ? "align " : "size ") + std::to_string(m.tail_value) + '\n';
    out += "default uid=" + std::to_string(m.default_uid) + " gid=" + std::to_string(m.default_gid) +
           " mtime=" + std::to_string(m.default_mtime) + " dev=" + std::to_string(m.default_devmajor) + ":" +
           std::to_string(m.default_devminor) + '\n';
    out += "newmode file=" + octal(m.new_file) + " exec=" + octal(m.new_exec) + " dir=" + octal(m.new_dir) +
           " link=" + octal(m.new_link) + '\n';
    out += "entries\n";
    for (const MetaEntry& e : m.entries) out += format_entry(e);
    out += format_entry(m.trailer);
    return out;
}

std::string_view take_token(std::string_view& s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    size_t end = 0;
    while (end < s.size() && s[end] != ' ' && s[end] != '\t') ++end;
    const std::string_view token = s.substr(0, end);
    s.remove_prefix(end);
    return token;
}

// key=value, once per item of `args`; `handle` gets the key and the value.
template <class F>
void each_setting(const std::vector<std::string_view>& args, size_t line, F&& handle) {
    for (std::string_view item : args) {
        const size_t eq = item.find('=');
        if (eq == std::string_view::npos) meta_error(line, "'" + std::string(item) + "' should be key=value");
        handle(item.substr(0, eq), item.substr(eq + 1));
    }
}

Meta parse_meta(std::string_view text) {
    Meta m;
    bool in_entries = false;
    bool saw_trailer = false;
    size_t line_no = 0;
    while (!text.empty()) {
        const size_t nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view() : text.substr(nl + 1);
        ++line_no;
        while (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        std::string_view probe = line;
        while (!probe.empty() && (probe.front() == ' ' || probe.front() == '\t')) probe.remove_prefix(1);
        if (probe.empty() || probe.front() == '#') continue;

        if (!in_entries) {
            std::string_view rest = line;
            const std::string_view key = take_token(rest);
            std::vector<std::string_view> args;
            for (std::string_view t = take_token(rest); !t.empty(); t = take_token(rest)) args.push_back(t);
            const std::string_view a = args.size() > 0 ? args[0] : std::string_view();
            const std::string_view b = args.size() > 1 ? args[1] : std::string_view();
            if (key == "entries") {
                in_entries = true;
            } else if (key == "format") {
                if (a == "newc") m.magic = cpio::Magic::NEWC;
                else if (a == "crc") m.magic = cpio::Magic::CRC;
                else meta_error(line_no, "format must be newc or crc");
            } else if (key == "hex") {
                if (a == "lower") m.hex_upper = false;
                else if (a == "upper") m.hex_upper = true;
                else meta_error(line_no, "hex must be lower or upper");
            } else if (key == "names") {
                if (a == "plain") m.dotslash = false;
                else if (a == "dotslash") m.dotslash = true;
                else meta_error(line_no, "names must be plain or dotslash");
            } else if (key == "order") {
                if (a == "sorted") m.order = Order::SORTED;
                else if (a == "archive") m.order = Order::ARCHIVE;
                else meta_error(line_no, "order must be sorted or archive");
            } else if (key == "inode") {
                if (a == "sequential") {
                    m.ino_sequential = true;
                    m.ino_base = b.empty() ? 300000 : parse_u32(b, 10, line_no, "inode number");
                } else if (a == "explicit") {
                    m.ino_sequential = false;
                } else {
                    meta_error(line_no, "inode must be 'sequential N' or 'explicit'");
                }
            } else if (key == "nlink") {
                if (a == "1") m.nlink = NlinkScheme::ONE;
                else if (a == "posix") m.nlink = NlinkScheme::POSIX;
                else if (a == "explicit") m.nlink = NlinkScheme::EXPLICIT;
                else meta_error(line_no, "nlink must be 1, posix or explicit");
            } else if (key == "tail") {
                if (a == "align") m.tail_align = true;
                else if (a == "size") m.tail_align = false;
                else meta_error(line_no, "tail must be 'align N' or 'size N'");
                m.tail_value = parse_u32(b, 10, line_no, "tail length");
                if (m.tail_align && m.tail_value == 0) meta_error(line_no, "tail align 0");
            } else if (key == "default") {
                each_setting(args, line_no, [&](std::string_view k, std::string_view v) {
                    if (k == "uid") m.default_uid = parse_u32(v, 10, line_no, "uid");
                    else if (k == "gid") m.default_gid = parse_u32(v, 10, line_no, "gid");
                    else if (k == "mtime") m.default_mtime = parse_u32(v, 10, line_no, "mtime");
                    else if (k == "dev") std::tie(m.default_devmajor, m.default_devminor) = parse_pair(v, line_no, "device number");
                    else meta_error(line_no, "unknown default '" + std::string(k) + "'");
                });
            } else if (key == "newmode") {
                each_setting(args, line_no, [&](std::string_view k, std::string_view v) {
                    if (k == "file") m.new_file = parse_permissions(v, line_no, "mode");
                    else if (k == "exec") m.new_exec = parse_permissions(v, line_no, "mode");
                    else if (k == "dir") m.new_dir = parse_permissions(v, line_no, "mode");
                    else if (k == "link") m.new_link = parse_permissions(v, line_no, "mode");
                    else meta_error(line_no, "unknown newmode '" + std::string(k) + "' (file, exec, dir or link)");
                });
            } else {
                meta_error(line_no, "unknown setting '" + std::string(key) + "'");
            }
            continue;
        }

        std::string_view rest = line;
        const std::string_view type = take_token(rest);
        const std::string_view mode = take_token(rest);
        const std::string_view uid = take_token(rest);
        const std::string_view gid = take_token(rest);
        const std::string_view mtime = take_token(rest);
        const std::string_view extras = take_token(rest);
        while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) rest.remove_prefix(1);
        if (type.size() != 1 || std::strchr("dflcbpsT", type[0]) == nullptr)
            meta_error(line_no, "the type of an entry is one of d f l c b p s T");
        if (extras.empty() || rest.empty()) meta_error(line_no, "an entry needs: type mode uid gid mtime extras path");
        MetaEntry e;
        e.type = type[0];
        e.mode = parse_u32(mode, 8, line_no, "mode");
        e.uid = parse_u32(uid, 10, line_no, "uid");
        e.gid = parse_u32(gid, 10, line_no, "gid");
        e.mtime = parse_u32(mtime, 10, line_no, "mtime");
        e.x = parse_extras(extras, line_no);
        e.path = unquote_path(rest, line_no);
        if (e.type == 'T') {
            if (saw_trailer) meta_error(line_no, "more than one T entry");
            saw_trailer = true;
            m.trailer = e;
        } else {
            if (e.mode & ~07777u) meta_error(line_no, "a mode has bits beyond the permissions (the type is the first column)");
            m.entries.push_back(std::move(e));
        }
    }
    if (!in_entries) throw FormatError("no 'entries' line");
    return m;
}

// ------------------------------------------------------------------ small helpers --

std::string to_utf8(const fs::path& p) {
#ifdef _WIN32
    const std::u8string u = p.generic_u8string();
    return std::string(u.begin(), u.end());
#else
    return p.generic_string();
#endif
}

fs::path from_utf8(const std::string& s) {
#ifdef _WIN32
    return fs::path(std::u8string(s.begin(), s.end()));
#else
    return fs::path(s);
#endif
}

// "a/b/c" -> a, b, c; the root "." -> nothing.
std::vector<std::string_view> components(std::string_view path) {
    std::vector<std::string_view> out;
    if (path == ".") return out;
    size_t start = 0;
    for (;;) {
        const size_t slash = path.find('/', start);
        if (slash == std::string_view::npos) {
            out.push_back(path.substr(start));
            break;
        }
        out.push_back(path.substr(start, slash - start));
        start = slash + 1;
    }
    return out;
}

// The directory a path is in; empty for a top-level path.
std::string parent_of(std::string_view path) {
    const size_t slash = path.rfind('/');
    return slash == std::string_view::npos ? std::string() : std::string(path.substr(0, slash));
}

// The order Android's mkbootfs writes: depth first, the entries of a directory sorted by the bytes
// of their names, a directory in front of what it holds. That is exactly the order of the lists of
// path components.
struct CanonicalKey {
    std::vector<std::string_view> parts;
};
bool canonical_less(const CanonicalKey& a, const CanonicalKey& b) {
    return std::lexicographical_compare(a.parts.begin(), a.parts.end(), b.parts.begin(), b.parts.end());
}

char letter_for(uint32_t mode) {
    switch (mode & cpio::kTypeMask) {
        case cpio::kDirectory: return 'd';
        case cpio::kRegular: return 'f';
        case cpio::kSymlink: return 'l';
        case cpio::kCharDev: return 'c';
        case cpio::kBlockDev: return 'b';
        case cpio::kFifo: return 'p';
        case cpio::kSocket: return 's';
        default: return 0;
    }
}

uint32_t type_bits(char letter) {
    switch (letter) {
        case 'd': return cpio::kDirectory;
        case 'f': return cpio::kRegular;
        case 'l': return cpio::kSymlink;
        case 'c': return cpio::kCharDev;
        case 'b': return cpio::kBlockDev;
        case 'p': return cpio::kFifo;
        case 's': return cpio::kSocket;
        default: return 0;
    }
}

uint32_t most_common(const std::vector<uint32_t>& v, uint32_t fallback) {
    std::map<uint32_t, size_t> count;
    for (uint32_t x : v) ++count[x];
    uint32_t best = fallback;
    size_t best_n = 0;
    for (const auto& [value, n] : count)
        if (n > best_n) {
            best = value;
            best_n = n;
        }
    return best;
}

std::string squote(const std::string& s) { return "'" + s + "'"; }

// "a, b, c and 7 more" -- the first `cap` of them.
std::string list_some(const std::vector<std::string>& items, size_t cap) {
    std::string out;
    for (size_t i = 0; i < items.size() && i < cap; ++i) {
        if (i) out += ", ";
        out += items[i];
    }
    if (items.size() > cap) out += " and " + std::to_string(items.size() - cap) + " more";
    return out;
}

std::string plural(size_t n, const char* one, const char* many) {
    return std::to_string(n) + " " + (n == 1 ? one : many);
}

// What Windows would refuse about one component of a path ("" if nothing).
std::string windows_name_problem(std::string_view part) {
    for (unsigned char c : part)
        if (c < 0x20 || std::strchr("<>:\"|?*\\", c) != nullptr) return "has a character that Windows does not allow in a name";
    if (part.back() == '.' || part.back() == ' ') return "ends with a dot or a space, which Windows drops";
    std::string stem;
    for (char c : part) {
        if (c == '.') break;
        stem += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    while (!stem.empty() && stem.back() == ' ') stem.pop_back();
    static const char* const kReserved[] = {"CON", "PRN", "AUX", "NUL"};
    for (const char* r : kReserved)
        if (stem == r) return "is the name of a Windows device";
    if (stem.size() == 4 && (stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0) && stem[3] >= '1' && stem[3] <= '9')
        return "is the name of a Windows device";
    return {};
}

// ------------------------------------------------------------------ UTF and links --

// UTF-8 to code points. False when the bytes are not UTF-8: overlong forms, surrogates and anything
// beyond U+10FFFF are not.
bool utf8_decode(std::string_view s, std::u32string& out) {
    out.clear();
    size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        char32_t cp;
        size_t extra;
        if (c < 0x80) {
            cp = c;
            extra = 0;
        } else if (c >= 0xC2 && c <= 0xDF) {
            cp = c & 0x1Fu;
            extra = 1;
        } else if (c >= 0xE0 && c <= 0xEF) {
            cp = c & 0x0Fu;
            extra = 2;
        } else if (c >= 0xF0 && c <= 0xF4) {
            cp = c & 0x07u;
            extra = 3;
        } else {
            return false;
        }
        if (s.size() - i <= extra) return false;
        for (size_t k = 1; k <= extra; ++k) {
            const unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3Fu);
        }
        if ((extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000)) return false;
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        out.push_back(cp);
        i += extra + 1;
    }
    return true;
}

void utf8_append(std::string& out, char32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

void utf16le_append(Bytes& out, char32_t cp) {
    auto put = [&](uint32_t unit) {
        out.push_back(static_cast<uint8_t>(unit & 0xFF));
        out.push_back(static_cast<uint8_t>((unit >> 8) & 0xFF));
    };
    if (cp < 0x10000) {
        put(cp);
    } else {
        cp -= 0x10000;
        put(0xD800 + (cp >> 10));
        put(0xDC00 + (cp & 0x3FF));
    }
}

constexpr std::string_view kCygwinMagic = "!<symlink>";

// What a plain text file holding a link's target says: the text without a byte order mark and
// without the line break an editor adds. Empty (and `error` set) when that is nothing a link can point to.
std::string text_link_target(const Bytes& data, std::string& error) {
    size_t begin = 0;
    size_t end = data.size();
    if (end >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) begin = 3;
    while (end > begin && (data[end - 1] == '\n' || data[end - 1] == '\r')) --end;
    if (end == begin) {
        error = "it has no target";
        return {};
    }
    std::string target(reinterpret_cast<const char*>(data.data()) + begin, end - begin);
    if (target.find('\0') != std::string::npos) {
        error = "its target has a zero byte";
        return {};
    }
    return target;
}

// ------------------------------------------------------------------ executables --

// A file that is meant to be run: a #! script or an ELF program (a library or a kernel module is not).
bool looks_executable(const Bytes& data, const std::string& path) {
    if (data.size() >= 2 && data[0] == '#' && data[1] == '!') return true;
    if (data.size() < 4 || data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') return false;
    const size_t slash = path.rfind('/');
    const std::string_view base = std::string_view(path).substr(slash == std::string::npos ? 0 : slash + 1);
    auto ends_with = [&](std::string_view suffix) {
        return base.size() >= suffix.size() && base.substr(base.size() - suffix.size()) == suffix;
    };
    return !(ends_with(".so") || ends_with(".ko") || base.find(".so.") != std::string_view::npos);
}

// ------------------------------------------------------------------ archive -> tree --

// Works out how a tree and a metadata file can say everything the archive says. Returns why that
// is not possible, or an empty string; `paths[i]` is where entry i goes in the tree.
std::string analyze(const cpio::Archive& a, Meta& meta, std::vector<std::string>& paths) {
    const auto& es = a.entries;
    const size_t n = es.size();
    meta = Meta();
    meta.magic = a.magic;
    meta.hex_upper = a.upper_hex;

    // `find . | cpio` writes the root as "." and the rest as "./x" (older cpio) or as "x" (newer
    // one): the root is the same in both, the rest has to be one or the other.
    bool any_dotslash = false;
    bool any_plain = false;
    for (const cpio::Entry& e : es) {
        if (e.name == ".") continue;
        if (e.name.rfind("./", 0) == 0) any_dotslash = true;
        else any_plain = true;
    }
    if (any_dotslash && any_plain) return "some names start with './' and some do not";
    meta.dotslash = any_dotslash;

    std::unordered_set<std::string> seen;
    std::unordered_set<std::string> dirs;
    std::map<std::tuple<uint32_t, uint32_t, uint32_t>, size_t> links;
    std::u32string scratch;
    paths.clear();
    paths.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const cpio::Entry& e = es[i];
        std::string path = e.name == "." ? std::string(".") : (meta.dotslash ? e.name.substr(2) : e.name);
        if (path.empty()) return "an entry without a name";
        if (path != ".") {
            if (path.front() == '/') return "the name " + squote(e.name) + " is an absolute path";
            for (std::string_view part : components(path)) {
                if (part.empty()) return "the name " + squote(e.name) + " has an empty part (a doubled or a trailing slash)";
                if (part == "." || part == "..") return "the name " + squote(e.name) + " goes through '.' or '..'";
            }
            if (!utf8_decode(path, scratch)) return "the name " + squote(e.name) + " is not valid UTF-8";
            if (path.find('\0') != std::string::npos) return "the name " + squote(e.name) + " has a zero byte";
        }
        const char t = letter_for(e.mode);
        if (!t) return squote(e.name) + " is of a kind (mode " + octal(e.mode) + ") that a directory cannot hold";
        if (e.mode & ~(cpio::kTypeMask | 07777u)) return squote(e.name) + " has mode bits that are neither its kind nor its permissions";
        if (path == "." && t != 'd') return "'.' is not a directory";
        if (!seen.insert(path).second) return "the name " + squote(e.name) + " occurs twice";
        if (t != 'f' && t != 'l' && !e.data.empty()) return squote(e.name) + " is not a regular file but has data";
        if (t == 'l') {
            // The target travels as a link, or as a Cygwin link file (UTF-16), or as text: what all of
            // them can hold, and nothing else.
            if (e.data.empty()) return "the symbolic link " + squote(e.name) + " has no target";
            if (e.data.back() == '\n' || e.data.back() == '\r')
                return "the target of the link " + squote(e.name) + " ends in a line break, which a text file would lose";
            if (std::find(e.data.begin(), e.data.end(), uint8_t{0}) != e.data.end())
                return "the target of the link " + squote(e.name) + " has a zero byte";
            if (!utf8_decode(std::string_view(reinterpret_cast<const char*>(e.data.data()), e.data.size()), scratch))
                return "the target of the link " + squote(e.name) + " is not valid UTF-8";
        }
        if (path != ".") {
            const std::string parent = parent_of(path);
            if (!parent.empty() && !dirs.count(parent))
                return squote(e.name) + " comes without (or before) its directory " + squote(parent);
        }
        if (t == 'd') dirs.insert(path);
        if (t != 'd' && e.nlink >= 2) {
            const auto [it, fresh] = links.emplace(std::make_tuple(e.devmajor, e.devminor, e.ino), i);
            if (!fresh) return "hard links: " + squote(es[it->second].name) + " and " + squote(e.name) + " are one file";
        }
        paths.push_back(std::move(path));
    }

    // Link counts: all 1 (mkbootfs), or the real ones of a file system (a directory has 2 and one
    // more for each subdirectory), or whatever there is.
    if (std::all_of(es.begin(), es.end(), [](const cpio::Entry& e) { return e.nlink == 1; })) {
        meta.nlink = NlinkScheme::ONE;
    } else {
        std::unordered_map<std::string, uint32_t> subdirs;  // "" is the root
        for (size_t i = 0; i < n; ++i)
            if (letter_for(es[i].mode) == 'd' && paths[i] != ".") ++subdirs[parent_of(paths[i])];
        bool posix = true;
        for (size_t i = 0; i < n && posix; ++i) {
            const bool dir = letter_for(es[i].mode) == 'd';
            const uint32_t want = dir ? 2 + subdirs[paths[i] == "." ? std::string() : paths[i]] : 1;
            posix = es[i].nlink == want;
        }
        meta.nlink = posix ? NlinkScheme::POSIX : NlinkScheme::EXPLICIT;
    }

    // Inode numbers: counted up from some start (mkbootfs), or whatever they are.
    meta.ino_base = n ? es[0].ino : a.trailer.ino;
    meta.ino_sequential = a.trailer.ino == meta.ino_base + static_cast<uint32_t>(n);
    for (size_t i = 0; i < n && meta.ino_sequential; ++i) meta.ino_sequential = es[i].ino == meta.ino_base + static_cast<uint32_t>(i);

    // Defaults for entries that are added: what most of the archive has.
    {
        std::vector<uint32_t> uids, gids, mtimes;
        std::map<std::pair<uint32_t, uint32_t>, size_t> devs;
        for (const cpio::Entry& e : es) {
            uids.push_back(e.uid);
            gids.push_back(e.gid);
            mtimes.push_back(e.mtime);
            ++devs[{e.devmajor, e.devminor}];
        }
        meta.default_uid = most_common(uids, 0);
        meta.default_gid = most_common(gids, 0);
        meta.default_mtime = most_common(mtimes, 0);
        size_t best = 0;
        for (const auto& [dev, count] : devs)
            if (count > best) {
                best = count;
                meta.default_devmajor = dev.first;
                meta.default_devminor = dev.second;
            }
    }

    // The order: the canonical one, or the archive's own.
    {
        std::vector<CanonicalKey> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i].parts = components(paths[i]);
        std::vector<size_t> idx(n);
        std::iota(idx.begin(), idx.end(), size_t{0});
        std::stable_sort(idx.begin(), idx.end(), [&](size_t x, size_t y) { return canonical_less(keys[x], keys[y]); });
        bool same = true;
        for (size_t i = 0; i < n && same; ++i) same = idx[i] == i;
        meta.order = same ? Order::SORTED : Order::ARCHIVE;
    }

    meta.entries.clear();
    meta.entries.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const cpio::Entry& e = es[i];
        MetaEntry m;
        m.type = letter_for(e.mode);
        m.mode = e.mode & 07777u;
        m.uid = e.uid;
        m.gid = e.gid;
        m.mtime = e.mtime;
        m.path = paths[i];
        if (!meta.ino_sequential) m.x.ino = e.ino;
        if (meta.nlink == NlinkScheme::EXPLICIT && e.nlink != 1) m.x.nlink = e.nlink;
        if (e.devmajor != meta.default_devmajor || e.devminor != meta.default_devminor) m.x.dev = std::make_pair(e.devmajor, e.devminor);
        if (e.rdevmajor || e.rdevminor) m.x.rdev = std::make_pair(e.rdevmajor, e.rdevminor);
        meta.entries.push_back(std::move(m));
    }
    {
        const cpio::Entry& t = a.trailer;
        MetaEntry& m = meta.trailer;
        m = MetaEntry();
        m.type = 'T';
        m.mode = t.mode;
        m.uid = t.uid;
        m.gid = t.gid;
        m.mtime = t.mtime;
        m.path = cpio::kTrailerName;
        if (!meta.ino_sequential) m.x.ino = t.ino;
        if (t.nlink != 1) m.x.nlink = t.nlink;
        if (t.devmajor || t.devminor) m.x.dev = std::make_pair(t.devmajor, t.devminor);
        if (t.rdevmajor || t.rdevminor) m.x.rdev = std::make_pair(t.rdevmajor, t.rdevminor);
    }
    return {};
}

// Where the end of an archive falls: the zero fill after it makes the end a multiple of N (one of
// the usual block sizes), counted from the start of the whole ramdisk, or is just so many bytes.
// `end` is the offset of the archive's end in the ramdisk, `fill` the zeros after it. When the fill
// fits 256 and 512 alike, the writer decides: mkbootfs and Magisk (lower case digits) pad to 256,
// GNU cpio (upper case) to 512. An archive with no fill at all is "align 4": nothing is added.
void describe_tail(size_t end, size_t fill, Meta& meta) {
    const uint32_t first = meta.hex_upper ? 512u : 256u;
    const uint32_t second = meta.hex_upper ? 256u : 512u;
    for (uint32_t n : {first, second, 1024u, 4096u, 4u}) {
        if (align_up(end, n) - end == fill) {
            meta.tail_align = true;
            meta.tail_value = n;
            return;
        }
    }
    meta.tail_align = false;
    meta.tail_value = static_cast<uint32_t>(fill);
}

void write_entry_file(const fs::path& p, const Bytes& data, const std::string& name) {
    std::ofstream out(p, std::ios::binary);
    if (!out) throw FormatError("cannot create " + squote(name));
    if (!data.empty()) out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    out.close();
    if (!out) throw FormatError("cannot write " + squote(name));
}

// A symbolic link in the tree: a real one where the system has them for the asking, otherwise the
// file Cygwin and MSYS2 use (and Windows marks it as a system file, as they do).
void write_link(const fs::path& p, const Bytes& target_bytes, const std::string& name) {
    const std::string target(target_bytes.begin(), target_bytes.end());
    if (!kWindows) {
        std::error_code ec;
        fs::create_symlink(from_utf8(target), p, ec);
        if (!ec) return;
        // The file system cannot hold links (FAT, some network and phone storage): a file will do.
    }
    write_entry_file(p, cygwin_link_file(target), name);
    if (kWindows) mark_system_file(p);
}

std::string describe_difference(const Bytes& original, const Bytes& rebuilt) {
    size_t i = 0;
    const size_t common = std::min(original.size(), rebuilt.size());
    while (i < common && original[i] == rebuilt[i]) ++i;
    std::string out = "the tree builds " + std::to_string(rebuilt.size()) + " bytes, the ramdisk has " +
                      std::to_string(original.size());
    if (i < common || original.size() != rebuilt.size()) out += "; they first differ at byte " + std::to_string(i);
    return out;
}

// ------------------------------------------------------------------ tree -> archive --

struct Item {
    std::string path;
    fs::file_type type = fs::file_type::none;
    fs::path real;
};

void walk(const fs::path& dir, const std::string& rel, std::vector<Item>& out, std::vector<std::string>& leftovers) {
    std::vector<fs::directory_entry> kids;
    for (const fs::directory_entry& de : fs::directory_iterator(dir)) kids.push_back(de);
    std::sort(kids.begin(), kids.end(), [](const fs::directory_entry& x, const fs::directory_entry& y) {
        return to_utf8(x.path().filename()) < to_utf8(y.path().filename());
    });
    for (const fs::directory_entry& de : kids) {
        const std::string name = to_utf8(de.path().filename());
        const fs::file_type type = de.symlink_status().type();
        if (type == fs::file_type::regular &&
            (name == ".DS_Store" || name == "Thumbs.db" || name == "desktop.ini")) {
            leftovers.push_back(rel.empty() ? name : rel + "/" + name);
            continue;
        }
        Item item;
        item.path = rel.empty() ? name : rel + "/" + name;
        item.type = type;
        item.real = de.path();
        out.push_back(item);
        if (type == fs::file_type::directory) walk(de.path(), item.path, out, leftovers);
    }
}

std::string link_target(const fs::path& p) {
    const fs::path t = fs::read_symlink(p);
#ifdef _WIN32
    return to_utf8(t);
#else
    return t.native();
#endif
}

struct Built {
    std::string path;
    char type = 'f';
    const MetaEntry* meta = nullptr;  // its line in the metadata, if there is one for the same kind of entry
    bool exec = false;                // a file that is meant to be run (only looked at for a new one)
    cpio::Entry entry;
};

struct VolumeBuild {
    Bytes archive;  // the records and the end record, without the fill behind it
    bool tail_align = true;
    uint32_t tail_value = 256;
};

// One archive from one directory and its metadata. `label` ("ramdisk/") starts the messages.
VolumeBuild build_volume(const fs::path& tree_dir, const fs::path& meta_file, const std::string& label,
                         PackReport* report) {
    auto warning = [&](const std::string& s) {
        if (report) report->warnings.push_back(label + ": " + s);
    };
    auto note = [&](const std::string& s) {
        if (report) report->notes.push_back(label + ": " + s);
    };
    const std::string meta_name = to_utf8(meta_file.filename());

    Meta meta;
    const bool have_meta = fs::exists(meta_file);
    if (have_meta) {
        const Bytes raw = read_file(meta_file);
        try {
            meta = parse_meta(std::string_view(reinterpret_cast<const char*>(raw.data()), raw.size()));
        } catch (const FormatError& ex) {
            throw FormatError(meta_name + ": " + ex.what());
        }
    } else {
        warning("there is no " + meta_name + ": owners, modes and the order of the entries are made up (root, " +
                octal(meta.new_dir) + " / " + octal(meta.new_file) + ", sorted)");
    }
    std::unordered_map<std::string, size_t> meta_index;
    for (size_t i = 0; i < meta.entries.size(); ++i)
        if (!meta_index.emplace(meta.entries[i].path, i).second)
            throw FormatError(meta_name + ": " + squote(meta.entries[i].path) + " is listed twice");

    if (!fs::is_directory(tree_dir)) throw FormatError(squote(to_utf8(tree_dir)) + " is not a directory");
    std::vector<Item> items;
    std::vector<std::string> leftovers;
    walk(tree_dir, "", items, leftovers);
    for (const std::string& l : leftovers) note(squote(l) + " is a leftover of a file manager and is not put into the ramdisk");

    std::vector<Built> built;
    built.reserve(items.size() + 1);

    // What every entry has: its mode, owner, time and device numbers, from the metadata when it has a line.
    auto fill_common = [&](Built& b) {
        cpio::Entry& e = b.entry;
        uint32_t perm;
        if (b.meta) {
            perm = b.meta->mode & 07777u;
        } else {
            switch (b.type) {
                case 'd': perm = meta.new_dir; break;
                case 'l': perm = meta.new_link; break;
                case 'f': perm = b.exec ? meta.new_exec : meta.new_file; break;
                default: perm = 0600; break;
            }
        }
        e.mode = type_bits(b.type) | perm;
        e.uid = b.meta ? b.meta->uid : meta.default_uid;
        e.gid = b.meta ? b.meta->gid : meta.default_gid;
        e.mtime = b.meta ? b.meta->mtime : meta.default_mtime;
        e.devmajor = meta.default_devmajor;
        e.devminor = meta.default_devminor;
        if (b.meta) {
            if (b.meta->x.dev) std::tie(e.devmajor, e.devminor) = *b.meta->x.dev;
            if (b.meta->x.rdev) std::tie(e.rdevmajor, e.rdevminor) = *b.meta->x.rdev;
        }
    };

    // The root of a `find . | cpio` archive is an entry of its own.
    if (auto it = meta_index.find("."); it != meta_index.end() && meta.entries[it->second].type == 'd') {
        Built b;
        b.path = ".";
        b.type = 'd';
        b.meta = &meta.entries[it->second];
        fill_common(b);
        built.push_back(std::move(b));
    }

    for (const Item& item : items) {
        Built b;
        b.path = item.path;
        const auto found = meta_index.find(item.path);
        const MetaEntry* me = found == meta_index.end() ? nullptr : &meta.entries[found->second];
        cpio::Entry& e = b.entry;
        switch (item.type) {
            case fs::file_type::directory: b.type = 'd'; break;
            case fs::file_type::symlink: {
                b.type = 'l';
                const std::string t = link_target(item.real);
                e.data.assign(t.begin(), t.end());
                break;
            }
            case fs::file_type::regular: {
                if (me && std::strchr("cbps", me->type)) {  // a placeholder for something a directory cannot hold
                    b.type = me->type;
                    break;
                }
                Bytes data = read_file(item.real);
                std::string error;
                // A link is a file in the Cygwin format, or -- if the metadata says so -- just its target.
                std::optional<std::string> cyg;
                if (!(me && me->type == 'f')) {
                    cyg = read_cygwin_link_file(data, error);
                    if (!error.empty()) throw FormatError("the link file " + squote(item.path) + " cannot be read: " + error);
                }
                if (me && me->type == 'f') {
                    std::string ignored;
                    if (read_cygwin_link_file(data, ignored))
                        note(squote(item.path) + " looks like a symbolic link file, but " + meta_name +
                             " lists it as a file, and a file it stays (to make it a link, delete its line there or change its type to l)");
                }
                if (cyg) {
                    b.type = 'l';
                    e.data.assign(cyg->begin(), cyg->end());
                } else if (me && me->type == 'l') {
                    b.type = 'l';
                    const std::string t = text_link_target(data, error);
                    if (!error.empty()) throw FormatError("the symbolic link " + squote(item.path) + ": " + error);
                    e.data.assign(t.begin(), t.end());
                } else {
                    b.type = 'f';
                    e.data = std::move(data);
                }
                break;
            }
            case fs::file_type::character: b.type = 'c'; break;
            case fs::file_type::block: b.type = 'b'; break;
            case fs::file_type::fifo: b.type = 'p'; break;
            case fs::file_type::socket: b.type = 's'; break;
            default:
                note(squote(item.path) + " is not something a ramdisk can hold and is left out");
                continue;
        }
        if (b.type == 'l') {
            if (e.data.empty()) throw FormatError("the symbolic link " + squote(item.path) + " has no target");
            if (std::find(e.data.begin(), e.data.end(), uint8_t{0}) != e.data.end())
                throw FormatError("the target of the symbolic link " + squote(item.path) + " has a zero byte");
        }
        b.meta = (me && me->type == b.type) ? me : nullptr;
        if (!b.meta && b.type == 'f') {
            bool x = looks_executable(e.data, item.path);
#ifndef _WIN32
            x = x || (fs::status(item.real).permissions() & fs::perms::owner_exec) != fs::perms::none;
#endif
            b.exec = x;
        }
        fill_common(b);
        built.push_back(std::move(b));
    }

    // What the user added and what the user took away, for the message.
    if (have_meta) {
        std::vector<std::string> fresh;
        std::vector<std::string> gone;
        std::unordered_set<std::string> present;
        for (const Built& b : built) {
            present.insert(b.path);
            if (!b.meta) fresh.push_back(b.path + " " + b.type + " " + octal(b.entry.mode & 07777u));
        }
        for (const MetaEntry& me : meta.entries)
            if (!present.count(me.path)) gone.push_back(me.path);
        if (!fresh.empty())
            note(plural(fresh.size(), "new entry", "new entries") + " not in " + meta_name + ", with its default owner " +
                 std::to_string(meta.default_uid) + ":" + std::to_string(meta.default_gid) + " and these modes: " +
                 list_some(fresh, 12) + " (a line for a path in " + meta_name + " gives it its own)");
        if (!gone.empty())
            note(plural(gone.size(), "entry", "entries") + " of " + meta_name + " " + (gone.size() == 1 ? "is" : "are") +
                 " not in the directory and left out of the ramdisk: " + list_some(gone, 12));
    }

    // Order.
    std::vector<size_t> order;
    {
        std::vector<CanonicalKey> keys(built.size());
        for (size_t i = 0; i < built.size(); ++i) keys[i].parts = components(built[i].path);
        std::vector<size_t> canonical(built.size());
        std::iota(canonical.begin(), canonical.end(), size_t{0});
        std::stable_sort(canonical.begin(), canonical.end(), [&](size_t x, size_t y) { return canonical_less(keys[x], keys[y]); });
        if (meta.order == Order::SORTED) {
            order = canonical;
        } else {
            // What the archive had keeps its place; what is new goes behind the last record of the
            // directory it is in (parents first, so that a new directory is there before its files).
            std::unordered_map<std::string, size_t> by_path;
            for (size_t i = 0; i < built.size(); ++i) by_path[built[i].path] = i;
            std::vector<char> placed(built.size(), 0);
            for (const MetaEntry& me : meta.entries) {
                const auto it = by_path.find(me.path);
                if (it != by_path.end() && built[it->second].meta && !placed[it->second]) {
                    order.push_back(it->second);
                    placed[it->second] = 1;
                }
            }
            for (size_t i : canonical) {
                if (placed[i]) continue;
                const std::string parent = parent_of(built[i].path);
                size_t at = order.size();
                if (!parent.empty()) {
                    size_t last = std::string::npos;
                    for (size_t k = 0; k < order.size(); ++k) {
                        const std::string& p = built[order[k]].path;
                        if (p == parent || (p.size() > parent.size() && p.compare(0, parent.size(), parent) == 0 && p[parent.size()] == '/'))
                            last = k;
                    }
                    if (last != std::string::npos) at = last + 1;
                }
                order.insert(order.begin() + static_cast<std::ptrdiff_t>(at), i);
            }
        }
    }

    // Link counts and inode numbers.
    std::unordered_map<std::string, uint32_t> subdirs;
    for (const Built& b : built)
        if (b.type == 'd' && b.path != ".") ++subdirs[parent_of(b.path)];
    uint32_t next_ino = meta.ino_base;
    if (!meta.ino_sequential) {
        uint32_t highest = 0;
        for (const MetaEntry& me : meta.entries)
            if (me.x.ino && *me.x.ino > highest) highest = *me.x.ino;
        if (meta.trailer.x.ino && *meta.trailer.x.ino > highest) highest = *meta.trailer.x.ino;
        next_ino = highest + 1;
    }
    cpio::Archive archive;
    archive.magic = meta.magic;
    archive.upper_hex = meta.hex_upper;
    archive.entries.reserve(built.size());
    for (size_t position = 0; position < order.size(); ++position) {
        Built& b = built[order[position]];
        cpio::Entry e = std::move(b.entry);
        e.name = b.path == "." ? std::string(".") : (meta.dotslash ? "./" + b.path : b.path);
        if (meta.ino_sequential) {
            e.ino = meta.ino_base + static_cast<uint32_t>(position);
        } else if (b.meta && b.meta->x.ino) {
            e.ino = *b.meta->x.ino;
        } else {
            e.ino = next_ino++;
        }
        switch (meta.nlink) {
            case NlinkScheme::ONE: e.nlink = 1; break;
            case NlinkScheme::POSIX:
                e.nlink = b.type == 'd' ? 2 + subdirs[b.path == "." ? std::string() : b.path] : 1;
                break;
            case NlinkScheme::EXPLICIT:
                e.nlink = b.meta && b.meta->x.nlink ? *b.meta->x.nlink : (b.type == 'd' ? 2 : 1);
                break;
        }
        archive.entries.push_back(std::move(e));
    }
    {
        cpio::Entry& t = archive.trailer;
        const MetaEntry& m = meta.trailer;
        t.mode = m.mode;
        t.uid = m.uid;
        t.gid = m.gid;
        t.mtime = m.mtime;
        t.nlink = m.x.nlink.value_or(1);
        if (m.x.dev) std::tie(t.devmajor, t.devminor) = *m.x.dev;
        if (m.x.rdev) std::tie(t.rdevmajor, t.rdevminor) = *m.x.rdev;
        t.ino = meta.ino_sequential ? meta.ino_base + static_cast<uint32_t>(order.size()) : m.x.ino.value_or(next_ino);
    }

    VolumeBuild out;
    out.archive = cpio::write(archive);
    out.tail_align = meta.tail_align;
    out.tail_value = meta.tail_value;
    return out;
}

}  // namespace

// ------------------------------------------------------------------ links, public --

Bytes cygwin_link_file(const std::string& target) {
    std::u32string cps;
    if (target.empty()) throw FormatError("a link without a target");
    if (target.find('\0') != std::string::npos) throw FormatError("a link target with a zero byte");
    if (!utf8_decode(target, cps)) throw FormatError("the link target is not UTF-8");
    Bytes out(kCygwinMagic.begin(), kCygwinMagic.end());
    out.push_back(0xFF);
    out.push_back(0xFE);
    for (char32_t cp : cps) utf16le_append(out, cp);
    out.push_back(0);
    out.push_back(0);
    return out;
}

std::optional<std::string> read_cygwin_link_file(const Bytes& data, std::string& error) {
    error.clear();
    if (data.size() < kCygwinMagic.size() || std::memcmp(data.data(), kCygwinMagic.data(), kCygwinMagic.size()) != 0)
        return std::nullopt;
    const uint8_t* p = data.data() + kCygwinMagic.size();
    size_t n = data.size() - kCygwinMagic.size();
    std::string target;
    if (n >= 2 && p[0] == 0xFF && p[1] == 0xFE) {
        // UTF-16LE up to the first zero unit, which is where Cygwin stops too.
        p += 2;
        n -= 2;
        size_t i = 0;
        bool ended = false;
        while (i + 1 < n) {
            uint32_t unit = static_cast<uint32_t>(p[i]) | (static_cast<uint32_t>(p[i + 1]) << 8);
            i += 2;
            if (unit == 0) {
                ended = true;
                break;
            }
            if (unit >= 0xDC00 && unit <= 0xDFFF) {
                error = "the UTF-16 text has a low surrogate without a high one";
                return std::nullopt;
            }
            if (unit >= 0xD800 && unit <= 0xDBFF) {
                if (i + 1 >= n) {
                    error = "the UTF-16 text ends in the middle of a character";
                    return std::nullopt;
                }
                const uint32_t low = static_cast<uint32_t>(p[i]) | (static_cast<uint32_t>(p[i + 1]) << 8);
                if (low < 0xDC00 || low > 0xDFFF) {
                    error = "the UTF-16 text has a high surrogate without a low one";
                    return std::nullopt;
                }
                i += 2;
                unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
            }
            utf8_append(target, unit);
        }
        if (!ended && (n & 1)) {
            error = "the UTF-16 text ends in the middle of a character";
            return std::nullopt;
        }
    } else {
        // The older form: the target in UTF-8 up to a zero byte.
        size_t i = 0;
        while (i < n && p[i] != 0) ++i;
        target.assign(reinterpret_cast<const char*>(p), i);
        std::u32string scratch;
        if (!utf8_decode(target, scratch)) {
            error = "the target is not UTF-8";
            return std::nullopt;
        }
    }
    if (target.empty()) {
        error = "it has no target";
        return std::nullopt;
    }
    return target;
}

// ------------------------------------------------------------------ public --

std::string ramdisk_volume_name(const std::string& prefix, size_t index) {
    return index == 0 ? prefix : prefix + ".vol" + std::to_string(index + 1);
}

std::string ramdisk_volume_meta(const std::string& prefix, size_t index) {
    return ramdisk_volume_name(prefix, index) + ".meta";
}

namespace {

RamdiskTree extract_impl(const Bytes& plain, const fs::path& dir, const std::string& prefix) {
    RamdiskTree r;
    if (cpio::looks_like_other_cpio(plain.data(), plain.size())) {
        r.reason = "it is a cpio archive of an old kind (odc or binary), which no kernel takes as a ramdisk";
        return r;
    }
    if (!cpio::looks_like_cpio(plain.data(), plain.size())) return r;  // not an archive: nothing to say

    // The archives one after the other. The zeros after one are its fill, up to the next or to the end.
    struct Volume {
        cpio::Archive archive;
        size_t offset = 0;
        size_t length = 0;
        size_t fill = 0;
        Meta meta;
        std::vector<std::string> paths;
    };
    std::vector<Volume> vols;
    {
        size_t offset = 0;
        for (;;) {
            const std::string which = vols.empty() ? std::string() : "the archive number " + std::to_string(vols.size() + 1) + ": ";
            std::string error;
            auto parsed = cpio::parse(plain.data() + offset, plain.size() - offset, error);
            if (!parsed) {
                r.reason = which + error;
                return r;
            }
            const size_t end = offset + parsed->length;
            size_t next = end;
            while (next < plain.size() && plain[next] == 0) ++next;
            Volume v;
            v.archive = std::move(parsed->archive);
            v.offset = offset;
            v.length = parsed->length;
            v.fill = next - end;
            vols.push_back(std::move(v));
            if (next == plain.size()) break;
            if (cpio::looks_like_other_cpio(plain.data() + next, plain.size() - next)) {
                r.reason = "after the archive number " + std::to_string(vols.size()) +
                           " comes one of an old kind (odc or binary)";
                return r;
            }
            if (!cpio::looks_like_cpio(plain.data() + next, plain.size() - next)) {
                r.reason = "there is data after the end of the " + std::string(vols.size() == 1 ? "archive" : "last archive") +
                           " that is neither zero fill nor another cpio archive";
                return r;
            }
            if (next % 4 != 0) {
                r.reason = "the archive number " + std::to_string(vols.size() + 1) + " starts at byte " +
                           std::to_string(next) + ", not at a multiple of 4, where no kernel looks for it";
                return r;
            }
            if (vols.size() >= kMaxVolumes) {
                r.reason = "it is more than " + std::to_string(kMaxVolumes) + " cpio archives one after the other";
                return r;
            }
            offset = next;
        }
    }
    for (size_t i = 0; i < vols.size(); ++i) {
        if (const std::string why = analyze(vols[i].archive, vols[i].meta, vols[i].paths); !why.empty()) {
            r.reason = (vols.size() > 1 ? "the archive number " + std::to_string(i + 1) + ": " : std::string()) + why;
            return r;
        }
        describe_tail(vols[i].offset + vols[i].length, vols[i].fill, vols[i].meta);
    }

    // Nothing that is there already is touched.
    std::vector<fs::path> trees, metas;
    for (size_t i = 0; i < vols.size(); ++i) {
        trees.push_back(dir / ramdisk_volume_name(prefix, i));
        metas.push_back(dir / ramdisk_volume_meta(prefix, i));
        std::error_code ec;
        const fs::file_status st = fs::symlink_status(trees[i], ec);
        if (fs::exists(st) && !(fs::is_directory(st) && fs::is_empty(trees[i], ec))) {
            r.reason = to_utf8(trees[i]) + " exists and is not an empty directory (move it away to get the directory)";
            return r;
        }
        if (fs::exists(fs::symlink_status(metas[i], ec))) {
            r.reason = to_utf8(metas[i]) + " exists (move it away to get the directory)";
            return r;
        }
    }

    auto undo = [&] {
        std::error_code ec;
        for (size_t i = 0; i < trees.size(); ++i) {
            fs::remove_all(trees[i], ec);
            fs::remove(metas[i], ec);
        }
        r.entries = 0;
    };

    try {
        for (size_t v = 0; v < vols.size(); ++v) {
            fs::create_directories(trees[v]);
            const auto& es = vols[v].archive.entries;
            const auto& paths = vols[v].paths;
            for (size_t i = 0; i < es.size(); ++i) {
                const std::string& path = paths[i];
                if (path == ".") continue;
                if (kWindows) {
                    for (std::string_view part : components(path))
                        if (const std::string why = windows_name_problem(part); !why.empty())
                            throw FormatError("the name " + squote(path) + " " + why);
                }
                const fs::path p = trees[v] / from_utf8(path);
                const char t = letter_for(es[i].mode);
                // A name that is there already means the file system tells two names of the archive apart
                // less well than the archive does (case, a form of Unicode).
                std::error_code ec;
                const fs::file_status st = fs::symlink_status(p, ec);
                if (ec && st.type() == fs::file_type::none) throw FormatError("cannot create " + squote(path) + ": " + ec.message());
                if (fs::exists(st))
                    throw FormatError("this file system does not tell " + squote(path) + " from another name (it differs only in case, or in form)");
                if (t == 'd') {
                    fs::create_directory(p, ec);
                    if (ec) throw FormatError("cannot create " + squote(path) + ": " + ec.message());
                } else if (t == 'l') {
                    write_link(p, es[i].data, path);
                } else {
                    write_entry_file(p, t == 'f' ? es[i].data : Bytes(), path);
                }
                ++r.entries;
            }
        }
        for (size_t v = 0; v < vols.size(); ++v) {
            const std::string text = format_meta(vols[v].meta);
            write_file(metas[v], reinterpret_cast<const uint8_t*>(text.data()), text.size());
        }
    } catch (const std::exception& ex) {
        undo();
        r.reason = ex.what();
        return r;
    }
    r.created = true;
    r.volumes = vols.size();

    try {
        const Bytes rebuilt = pack_ramdisk_tree(dir, prefix, vols.size());
        r.rebuilt_sha256 = hash::sha256(rebuilt);
        r.exact = rebuilt == plain;
        if (!r.exact) r.difference = describe_difference(plain, rebuilt);
    } catch (const std::exception& ex) {
        undo();
        r.created = false;
        r.volumes = 0;
        r.reason = std::string("the tree could not be read back: ") + ex.what();
    }
    return r;
}

}  // namespace

RamdiskTree extract_ramdisk_tree(const Bytes& plain, const fs::path& dir, const std::string& prefix) {
    try {
        return extract_impl(plain, dir, prefix);
    } catch (const std::exception& ex) {  // out of memory, a file system that fails in an odd place
        RamdiskTree r;
        r.reason = ex.what();
        return r;
    }
}

Bytes pack_ramdisk_tree(const fs::path& dir, const std::string& prefix, size_t volumes, PackReport* report) {
    if (volumes == 0) volumes = 1;
    Bytes out;
    size_t built = 0;
    for (size_t i = 0; i < volumes; ++i) {
        const std::string name = ramdisk_volume_name(prefix, i);
        const fs::path tree = dir / name;
        if (!fs::is_directory(tree)) {
            if (report) report->notes.push_back(name + "/: the directory is not there, so that archive is left out of the ramdisk");
            continue;
        }
        const VolumeBuild v = build_volume(tree, dir / ramdisk_volume_meta(prefix, i), name + "/", report);
        out.insert(out.end(), v.archive.begin(), v.archive.end());
        const size_t end = out.size();
        out.resize(v.tail_align ? align_up(end, v.tail_value) : end + v.tail_value, 0);
        ++built;
        if (report) report->built.push_back(name);
    }
    if (built == 0)
        throw FormatError(volumes == 1 ? squote(to_utf8(dir / prefix)) + " is not a directory"
                                       : "none of the " + std::to_string(volumes) + " directories of the ramdisk '" + prefix +
                                             "' is there");
    if (report && fs::exists(dir / ramdisk_volume_name(prefix, volumes)))
        report->warnings.push_back(ramdisk_volume_name(prefix, volumes) + "/ is not part of this ramdisk (the unpack had " +
                                   plural(volumes, "archive", "archives") + ") and is ignored");
    return out;
}

}  // namespace abr
