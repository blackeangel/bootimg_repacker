// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/manifest.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>

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
    std::ifstream f(path, std::ios::binary);  // CR before LF is trimmed below; no text-mode surprises
    if (!f) throw FormatError("cannot open manifest: " + path.string());
    Manifest m;
    std::string line;
    size_t number = 0;
    while (std::getline(f, line)) {
        ++number;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        // A value that would not read back the same as plain text is written in double quotes (save() below).
        std::string value, why;
        if (!textquote::unquote(trim(t.substr(eq + 1)), value, why))
            throw FormatError(path.string() + ", line " + std::to_string(number) + ": " + why);
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

bool Manifest::has(const std::string& key) const {
    for (auto& [k, v] : entries_)
        if (k == key) return true;
    return false;
}

void Manifest::set(const std::string& key, const std::string& value) {
    for (auto& [k, v] : entries_) {
        if (k == key) {
            v = value;
            return;
        }
    }
    entries_.emplace_back(key, value);
}

std::string Manifest::get(const std::string& key, const std::string& def) const {
    for (auto& [k, v] : entries_)
        if (k == key) return v;
    return def;
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
        throw FormatError("manifest.txt: " + key + "=" + textquote::quote(v, true) + " " + why +
                          ". A file the manifest names has to be in the directory it is in (a relative path "
                          "without '..'); copy it there");
    return v;
}

void Manifest::set_u32(const std::string& key, uint32_t v) { set(key, std::to_string(v)); }
void Manifest::set_u64(const std::string& key, uint64_t v) { set(key, std::to_string(v)); }

uint32_t Manifest::get_u32(const std::string& key, uint32_t def) const {
    if (!has(key)) return def;
    return static_cast<uint32_t>(std::stoul(get(key), nullptr, 0));
}
uint64_t Manifest::get_u64(const std::string& key, uint64_t def) const {
    if (!has(key)) return def;
    return std::stoull(get(key), nullptr, 0);
}

void Manifest::set_addr(const std::string& key, uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    set(key, buf);
}
uint64_t Manifest::get_addr(const std::string& key, uint64_t def) const {
    if (!has(key)) return def;
    return std::stoull(get(key), nullptr, 0);  // base 0 auto-detects the 0x prefix
}

void Manifest::set_bool(const std::string& key, bool v) { set(key, v ? "true" : "false"); }
bool Manifest::get_bool(const std::string& key, bool def) const {
    if (!has(key)) return def;
    std::string v = get(key);
    return v == "true" || v == "1" || v == "yes";
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
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = nibble(s[i]), lo = nibble(s[i + 1]);
        if (hi < 0 || lo < 0) throw FormatError("invalid hex value for manifest key: " + key);
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

}  // namespace abr
