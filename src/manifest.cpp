// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/manifest.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string_view>

#include "abr/textquote.hpp"

namespace abr {

namespace {
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
}  // namespace

Manifest Manifest::load(const std::filesystem::path& path) {
    // (read_file: only a regular file, of a size a manifest can have, and one of the files this run has read: the image that
    // `repack` makes is not written over it)
    const Bytes data = read_file(path);
    const std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
    Manifest m;
    size_t number = 0;
    for (size_t at = 0; at < text.size();) {  // (the lines as std::getline cuts them; CR before LF is trimmed below)
        const size_t nl = text.find('\n', at);
        const std::string line(text.substr(at, nl == std::string_view::npos ? std::string_view::npos : nl - at));
        at = nl == std::string_view::npos ? text.size() : nl + 1;
        ++number;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        // A value that would not read back the same as plain text is written in double quotes (save() below).
        std::string value, why;
        if (!textquote::unquote(trim(t.substr(eq + 1)), value, why))
            throw FormatError(textquote::quote_shown(path.string()) + ", line " + std::to_string(number) + ": " + why);
        m.set(trim(t.substr(0, eq)), value);
    }
    return m;
}

void Manifest::save(const std::filesystem::path& path, const std::string& header_comment) const {
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
    // Binary on purpose: the manifest has LF line ends on every platform (Windows text
    // mode would write CRLF), so unpacked directories are identical wherever they were made.
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw FormatError("cannot write manifest: " + path.string());
    if (!header_comment.empty()) f << "# " << header_comment << "\n";
    // (a value with a line break in it would be taken for more lines, and one with white space at an end would lose it)
    for (auto& [k, v] : entries_) f << k << "=" << textquote::quote(v, false) << "\n";
}

bool Manifest::has(const std::string& key) const { return index_.find(key) != index_.end(); }

void Manifest::set(const std::string& key, const std::string& value) {
    const auto it = index_.find(key);
    if (it != index_.end()) {
        entries_[it->second].second = value;
        return;
    }
    index_.emplace(key, entries_.size());
    entries_.emplace_back(key, value);
}

std::string Manifest::get(const std::string& key, const std::string& def) const {
    const auto it = index_.find(key);
    return it == index_.end() ? def : entries_[it->second].second;
}

// What a name that is to be found in the directory of the unpack must not be, or "" when it is fine.
static const char* path_problem(const std::string& v) {
    if (v.empty()) return "";
    for (unsigned char c : v)
        if (c < 0x20 || c == 0x7F) return "has a control character in it";
    if (v.front() == '/' || v.front() == '\\') return "is an absolute path";
    if (v.find('\\') != std::string::npos) return "has a backslash in it (the parts of a path are separated by '/')";
    if (v.find(':') != std::string::npos) return "has a colon in it (a drive, or a stream of a file on Windows)";
    size_t from = 0;
    while (true) {
        const size_t to = v.find('/', from);
        const std::string part = v.substr(from, to == std::string::npos ? std::string::npos : to - from);
        if (part.empty()) return "has an empty part (a doubled or a trailing slash)";
        if (part == "..") return "goes through '..'";
        if (to == std::string::npos) break;
        from = to + 1;
    }
    return "";
}

std::string Manifest::get_path(const std::string& key, const std::string& def) const {
    std::string v = get(key, def);
    if (const char* why = path_problem(v); *why)
        throw FormatError("manifest.txt: " + key + "=" + textquote::quote_shown(v) + " " + why +
                          ". A file the manifest names has to be in the directory it is in (a relative path "
                          "without '..'); copy it there");
    return v;
}

void Manifest::set_u32(const std::string& key, uint32_t v) { set(key, std::to_string(v)); }
void Manifest::set_u64(const std::string& key, uint64_t v) { set(key, std::to_string(v)); }

// The number in `text`: decimal digits, or 0x and hexadecimal digits. `key` and `shown` (the value as the manifest has it, `text`
// may be a part of it) are for the message.
static uint64_t parse_number(const std::string& key, const std::string& shown, std::string_view text, unsigned bits) {
    auto fail = [&](const std::string& why) {
        throw FormatError("manifest.txt: " + key + "=" + textquote::quote_shown(shown) + " " + why);
    };
    if (text.empty()) fail("is empty; a number is needed (decimal, or hexadecimal with 0x)");
    unsigned base = 10;
    size_t i = 0;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        i = 2;
    }
    uint64_t v = 0;
    for (; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        unsigned d = 99;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        if (d >= base) fail("is not a number (decimal digits, or 0x and hexadecimal digits)");
        if (v > (UINT64_MAX - d) / base) fail("is too large (it does not fit in 64 bits)");
        v = v * base + d;
    }
    if (bits < 64 && (v >> bits) != 0) fail("does not fit in " + std::to_string(bits) + " bits");
    return v;
}

uint64_t Manifest::get_bounded(const std::string& key, uint64_t def, unsigned bits) const {
    if (!has(key)) return def;
    const std::string text = get(key);
    return parse_number(key, text, text, bits);
}

uint32_t Manifest::get_u32(const std::string& key, uint32_t def) const {
    return static_cast<uint32_t>(get_bounded(key, def, 32));
}
uint64_t Manifest::get_u64(const std::string& key, uint64_t def) const { return get_bounded(key, def, 64); }

int64_t Manifest::get_int(const std::string& key, int64_t def, int64_t lo, int64_t hi) const {
    if (!has(key)) return def;
    std::string text = get(key);
    const bool negative = !text.empty() && text[0] == '-';
    const uint64_t magnitude = parse_number(key, text, negative ? std::string_view(text).substr(1) : std::string_view(text), 63);
    const int64_t v = negative ? -static_cast<int64_t>(magnitude) : static_cast<int64_t>(magnitude);
    if (v < lo || v > hi)
        throw FormatError("manifest.txt: " + key + "=" + textquote::quote_shown(text) + " is outside " + std::to_string(lo) + " .. " +
                          std::to_string(hi));
    return v;
}

uint32_t Manifest::get_count(const std::string& key, uint32_t def) const {
    return static_cast<uint32_t>(get_int(key, def, 0, kMaxEntries));
}

std::pair<uint32_t, uint32_t> Manifest::get_version(const std::string& key, uint32_t def_major, uint32_t def_minor) const {
    if (!has(key)) return {def_major, def_minor};
    const std::string text = get(key);
    const size_t dot = text.find('.');
    auto digits = [](std::string_view part) {
        return !part.empty() && part.find_first_not_of("0123456789") == std::string_view::npos;
    };
    const std::string_view major = std::string_view(text).substr(0, dot);
    const std::string_view minor = dot == std::string::npos ? std::string_view() : std::string_view(text).substr(dot + 1);
    if (dot == std::string::npos || !digits(major) || !digits(minor))
        throw FormatError("manifest.txt: " + key + "=" + textquote::quote_shown(text) +
                          " is not a version like 2.2 (two decimal numbers with a dot between them)");
    return {static_cast<uint32_t>(parse_number(key, text, major, 32)), static_cast<uint32_t>(parse_number(key, text, minor, 32))};
}

uint64_t Manifest::get_size(const std::string& key, uint64_t def) const {
    const uint64_t v = get_u64(key, def);
    if (v > kMaxImageSize)
        throw FormatError("manifest.txt: " + key + "=" + textquote::quote_shown(get(key)) + " is more than " + std::to_string(kMaxImageSize >> 20) +
                          " MiB, and no image of the family is that big");
    return v;
}

void Manifest::set_addr(const std::string& key, uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    set(key, buf);
}
uint64_t Manifest::get_addr(const std::string& key, uint64_t def) const { return get_bounded(key, def, 64); }
uint32_t Manifest::get_addr32(const std::string& key, uint32_t def) const {
    return static_cast<uint32_t>(get_bounded(key, def, 32));
}

void Manifest::set_bool(const std::string& key, bool v) { set(key, v ? "true" : "false"); }
bool Manifest::get_bool(const std::string& key, bool def) const {
    if (!has(key)) return def;
    std::string v = get(key);
    for (char& c : v) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (v == "true" || v == "1" || v == "yes") return true;
    if (v == "false" || v == "0" || v == "no") return false;
    throw FormatError("manifest.txt: " + key + "=" + textquote::quote_shown(get(key)) +
                      (v.empty() ? " is empty; it has to be true or false" : " is neither true nor false"));
}

void Manifest::set_hex(const std::string& key, const Bytes& data) {
    std::string s;
    s.reserve(data.size() * 2);
    static const char* hex = "0123456789abcdef";
    for (uint8_t b : data) {
        s.push_back(hex[b >> 4]);
        s.push_back(hex[b & 0xf]);
    }
    set(key, s);
}

void Manifest::set_tail(const std::string& key, const Bytes& tail) {
    if (tail.empty()) return;
    const bool text = std::all_of(tail.begin(), tail.end(), [](uint8_t b) { return b >= 0x20 && b < 0x7F; });
    if (text)
        set(key, std::string(tail.begin(), tail.end()));
    else
        set_hex(key + "_hex", tail);
}

Bytes Manifest::get_tail(const std::string& key) const {
    if (has(key + "_hex")) return get_hex(key + "_hex");
    const std::string s = get(key);
    return Bytes(s.begin(), s.end());
}

Bytes Manifest::get_hex(const std::string& key) const {
    std::string s = get(key);
    Bytes out;
    out.reserve(s.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (s.size() % 2 != 0)
        throw FormatError("manifest.txt: " + key + " has an odd number of hexadecimal digits (" + std::to_string(s.size()) + ")");
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = nibble(s[i]), lo = nibble(s[i + 1]);
        if (hi < 0 || lo < 0) throw FormatError("invalid hex value for manifest key: " + key);
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

}  // namespace abr
