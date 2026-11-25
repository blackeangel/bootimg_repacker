// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::kernelinfo -- the searches (the report is written by kernelinfo_out.cpp). See kernelinfo.hpp.
#include "abr/kernelinfo.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <map>
#include <set>
#include <string_view>

#include "abr/asn1.hpp"
#include "abr/cpio.hpp"
#include "abr/dts.hpp"
#include "abr/fdt.hpp"
#include "abr/kernel.hpp"
#include "abr/parallel.hpp"
#include "abr/sha.hpp"

namespace abr::kernelinfo {

namespace {

constexpr size_t kMaxStreamPlain = size_t{128} << 20;     // the most a stream inside the kernel may expand to
constexpr size_t kMaxRetained = size_t{384} << 20;        // the most plain data the report keeps of all the streams
constexpr size_t kMaxItems = 64;                          // the most of one kind of thing that is reported
constexpr size_t kMaxStreamTries = 96;                    // the most streams that are tried (the magics are checked first)
constexpr size_t kMaxCpioTries = 256;
constexpr size_t kMaxCertificate = 64 * 1024;             // a certificate or a PEM block is smaller than this
constexpr size_t kMaxLine = 1024;                         // a banner is shorter than this
constexpr size_t kZImageStubSearch = 0x20000;             // the decompressor of a zImage is in the first bytes: the stream is within them
constexpr size_t kMinPayload = 64 * 1024;                 // a kernel is bigger than this

// ----------------------------------------------------------------------------------------------------------------------------- bytes --

bool fits(const Bytes& d, size_t at, size_t n) { return at <= d.size() && n <= d.size() - at; }

uint16_t rd16(const Bytes& d, size_t at, bool be = false) {
    if (!fits(d, at, 2)) return 0;
    return be ? static_cast<uint16_t>(d[at] << 8 | d[at + 1]) : static_cast<uint16_t>(d[at] | d[at + 1] << 8);
}
uint32_t rd32(const Bytes& d, size_t at, bool be = false) {
    if (!fits(d, at, 4)) return 0;
    const uint32_t b0 = d[at], b1 = d[at + 1], b2 = d[at + 2], b3 = d[at + 3];
    return be ? (b0 << 24 | b1 << 16 | b2 << 8 | b3) : (b3 << 24 | b2 << 16 | b1 << 8 | b0);
}
uint64_t rd64(const Bytes& d, size_t at, bool be = false) {
    if (!fits(d, at, 8)) return 0;
    const uint64_t a = rd32(d, at, be), b = rd32(d, at + 4, be);
    return be ? (a << 32 | b) : (b << 32 | a);
}

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

bool printable(uint8_t c) { return c >= 0x20 && c < 0x7f; }

// Calls f(at) for every place in `d`, from `from`, where `magic` is; f returns false to stop.
template <class F>
void each_match(const Bytes& d, std::string_view magic, size_t from, F&& f) {
    if (magic.empty() || d.size() < magic.size()) return;
    const auto first = static_cast<uint8_t>(magic[0]);
    size_t i = from;
    while (i + magic.size() <= d.size()) {
        const void* hit = std::memchr(d.data() + i, first, d.size() - magic.size() + 1 - i);
        if (!hit) return;
        i = static_cast<size_t>(static_cast<const uint8_t*>(hit) - d.data());
        if (std::memcmp(d.data() + i, magic.data(), magic.size()) == 0 && !f(i)) return;
        ++i;
    }
}

// The printable text that starts at `at` and ends at the first byte that is not printable (a NUL, a line feed): at most `limit` bytes.
std::string text_at(const Bytes& d, size_t at, size_t limit = kMaxLine) {
    std::string s;
    while (at < d.size() && s.size() < limit && printable(d[at])) s.push_back(static_cast<char>(d[at++]));
    return s;
}

bool all_bytes(const uint8_t* p, size_t n, uint8_t value) {
    for (size_t i = 0; i < n; ++i)
        if (p[i] != value) return false;
    return true;
}

bool looks_like_text(const Bytes& d) {
    const size_t n = std::min<size_t>(d.size(), 4096);
    if (n < 8) return false;
    for (size_t i = 0; i < n; ++i)
        if (!(printable(d[i]) || d[i] == '\n' || d[i] == '\t' || d[i] == '\r')) return false;
    return true;
}

// ------------------------------------------------------------------------------------------------------------------ the header --

struct Probe {
    Kind kind = Kind::Unknown;
    std::vector<Field> header;
    size_t end = 0;           // where the image ends according to its header (0: it does not say)
    size_t payload_at = 0;    // a bzImage: where the compressed kernel is
    size_t payload_len = 0;
};

void add(Probe& p, const char* name, std::string value) { p.header.push_back({name, std::move(value)}); }

std::string arm64_flags(uint64_t f) {
    static const char* const pages[] = {"page size not stated", "4 KiB pages", "16 KiB pages", "64 KiB pages"};
    std::string s = (f & 1) ? "big endian" : "little endian";
    s += std::string(", ") + pages[(f >> 1) & 3];
    s += (f & 8) ? ", placed anywhere in memory" : ", placed as near the start of memory as possible";
    return s;
}

Probe probe(const Bytes& d) {
    Probe p;
    if (fits(d, 0, 0x40) && std::memcmp(d.data() + 0x38, "ARM\x64", 4) == 0) {
        p.kind = Kind::Arm64Image;
        const uint64_t text_offset = rd64(d, 8), image_size = rd64(d, 0x10), flags = rd64(d, 0x18);
        add(p, "text_offset", hex(text_offset));
        add(p, "image_size", image_size ? hex(image_size) + " (" + std::to_string(image_size) + " bytes)" : "0 (not stated)");
        add(p, "flags", hex(flags) + ": " + arm64_flags(flags));
        if (d[0] == 'M' && d[1] == 'Z') add(p, "efi_stub", "yes: it is a PE/COFF file too, the PE header is at " + hex(rd32(d, 0x3c)));
        if (image_size > 0 && image_size <= d.size()) p.end = static_cast<size_t>(image_size);
        return p;
    }
    if (fits(d, 0x28, 8) && (rd32(d, 0x24) == 0x016f2818 || rd32(d, 0x24, true) == 0x016f2818)) {
        p.kind = Kind::ArmZImage;
        const bool be = rd32(d, 0x24) != 0x016f2818;
        const uint32_t start = rd32(d, 0x28, be), end = rd32(d, 0x2c, be);
        add(p, "byte_order", be ? "big endian" : "little endian");
        add(p, "start", hex(start));
        add(p, "end", hex(end) + " (the zImage is " + std::to_string(end >= start ? end - start : 0) + " bytes)");
        if (end > start && end - start <= d.size()) p.end = static_cast<size_t>(end - start);
        return p;
    }
    if (fits(d, 0x200, 0x70) && std::memcmp(d.data() + 0x202, "HdrS", 4) == 0) {
        p.kind = Kind::X86BzImage;
        const uint16_t version = rd16(d, 0x206);
        size_t setup_sects = d[0x1f1] ? d[0x1f1] : 4;
        add(p, "boot_protocol", std::to_string(version >> 8) + "." + std::to_string(version & 0xff));
        add(p, "setup_sects", std::to_string(setup_sects));
        if (const uint16_t ptr = rd16(d, 0x20e); ptr && fits(d, 0x200 + ptr, 1)) {
            const std::string s = text_at(d, 0x200 + ptr, 256);
            if (!s.empty()) add(p, "kernel_version", s);
        }
        add(p, "loadflags", hex(d[0x211]));
        add(p, "code32_start", hex(rd32(d, 0x214)));
        if (version >= 0x0205) {
            add(p, "kernel_alignment", hex(rd32(d, 0x230)));
            add(p, "relocatable_kernel", d[0x234] ? "yes" : "no");
        }
        if (version >= 0x020c) add(p, "xloadflags", hex(rd16(d, 0x236)));
        if (version >= 0x0206) add(p, "cmdline_size", std::to_string(rd32(d, 0x238)));
        if (version >= 0x020a) {
            add(p, "pref_address", hex(rd64(d, 0x258)));
            add(p, "init_size", hex(rd32(d, 0x260)));
        }
        if (version >= 0x020b) add(p, "handover_offset", hex(rd32(d, 0x264)));
        if (version >= 0x0208) {
            const uint32_t off = rd32(d, 0x248), len = rd32(d, 0x24c);
            add(p, "payload_offset", hex(off) + " (from the protected-mode code)");
            add(p, "payload_length", hex(len) + " (" + std::to_string(len) + " bytes)");
            p.payload_at = (setup_sects + 1) * 512 + off;
            p.payload_len = len;
        }
        return p;
    }
    if (fits(d, 0x38, 4) && std::memcmp(d.data() + 0x38, "RSC\x05", 4) == 0) {
        p.kind = Kind::RiscvImage;
        const uint64_t image_size = rd64(d, 0x10);
        add(p, "text_offset", hex(rd64(d, 8)));
        add(p, "image_size", hex(image_size));
        add(p, "flags", hex(rd64(d, 0x18)));
        const uint32_t v = rd32(d, 0x20);
        add(p, "version", std::to_string(v >> 16) + "." + std::to_string(v & 0xffff));
        if (image_size > 0 && image_size <= d.size()) p.end = static_cast<size_t>(image_size);
        return p;
    }
    if (fits(d, 0, 0x34) && std::memcmp(d.data(), "\x7f" "ELF", 4) == 0 && (d[4] == 1 || d[4] == 2) && (d[5] == 1 || d[5] == 2)) {
        p.kind = Kind::Elf;
        const bool be = d[5] == 2;
        add(p, "class", d[4] == 2 ? "ELF 64-bit" : "ELF 32-bit");
        add(p, "byte_order", be ? "big endian" : "little endian");
        add(p, "type", std::to_string(rd16(d, 16, be)));
        add(p, "machine", std::to_string(rd16(d, 18, be)));
        add(p, "entry", hex(d[4] == 2 ? rd64(d, 24, be) : rd32(d, 24, be)));
        return p;
    }
    return p;
}

// ------------------------------------------------------------------------------------------------------------ compressed streams --

struct Candidate {
    Codec codec = Codec::NONE;
    size_t at = 0;
};

bool power_or_three_halves(uint32_t v) {
    if (v < 0x10000) return false;
    const uint32_t low = v & (~v + 1);  // the lowest bit
    const uint32_t rest = v - low;
    return rest == 0 || (rest & (rest - 1)) == 0;  // 2^n or 2^n + 2^(n-1)
}

// The places in [from, to) where a stream of a codec may begin: its magic, and the fields of its header that can be checked on the spot.
std::vector<Candidate> stream_candidates(const Bytes& d, size_t from, size_t to) {
    std::vector<Candidate> out;
    to = std::min(to, d.size());
    if (from >= to) return out;
    const auto in_range = [&](size_t at) { return at < to; };
    const auto scan = [&](std::string_view magic, Codec codec, auto&& check) {
        each_match(d, magic, from, [&](size_t at) {
            if (!in_range(at)) return false;
            if (check(at)) out.push_back({codec, at});
            return true;
        });
    };
    scan(std::string_view("\x1f\x8b\x08", 3), Codec::GZIP, [&](size_t at) {
        if (!fits(d, at, 10)) return false;
        const uint8_t flg = d[at + 3], xfl = d[at + 8], os = d[at + 9];
        return (flg & 0xe0) == 0 && (xfl == 0 || xfl == 2 || xfl == 4) && (os <= 13 || os == 255);
    });
    scan(std::string_view("\xfd" "7zXZ\x00", 6), Codec::XZ, [&](size_t at) {
        return fits(d, at, 12) && d[at + 6] == 0 && (d[at + 7] == 0 || d[at + 7] == 1 || d[at + 7] == 4 || d[at + 7] == 10);
    });
    scan(std::string_view("\x28\xb5\x2f\xfd", 4), Codec::ZSTD, [&](size_t at) { return fits(d, at, 6) && (d[at + 4] & 0x08) == 0; });
    scan(std::string_view("BZh", 3), Codec::BZIP2, [&](size_t at) {
        return fits(d, at, 10) && d[at + 3] >= '1' && d[at + 3] <= '9' && std::memcmp(d.data() + at + 4, "\x31\x41\x59\x26\x53\x59", 6) == 0;
    });
    scan(std::string_view("\x04\x22\x4d\x18", 4), Codec::LZ4, [&](size_t at) {
        if (!fits(d, at, 7)) return false;
        const uint8_t flg = d[at + 4], bd = d[at + 5];
        return (flg >> 6) == 1 && (flg & 0x02) == 0 && (bd & 0x8f) == 0 && ((bd >> 4) & 7) >= 4;
    });
    scan(std::string_view("\x02\x21\x4c\x18", 4), Codec::LZ4_LEGACY, [&](size_t at) {
        if (!fits(d, at, 12)) return false;
        const uint32_t block = rd32(d, at + 4);
        return block > 0 && block <= 8u * 1024 * 1024 + 65536 && fits(d, at + 8, block);
    });
    scan(std::string_view("\x89LZO\x00\x0d\x0a\x1a\x0a", 9), Codec::LZO, [&](size_t at) { return fits(d, at, 32); });
    // LZMA alone has no magic: the properties byte of the usual settings, a dictionary of a size the encoders write, the size of the data
    // (not said: all 0xFF) and the first byte of the range coder, which is always zero.
    scan(std::string_view("\x5d", 1), Codec::LZMA, [&](size_t at) {
        if (!fits(d, at, 14) || d[at + 13] != 0) return false;
        if (!power_or_three_halves(rd32(d, at + 1))) return false;
        const uint64_t size = rd64(d, at + 5);
        return size == ~uint64_t{0} || size < (uint64_t{1} << 31);
    });
    std::sort(out.begin(), out.end(), [](const Candidate& a, const Candidate& b) { return a.at < b.at; });
    return out;
}

struct Stream {
    size_t offset = 0;
    size_t stored = 0;
    Codec codec = Codec::NONE;
    Bytes plain;
};

// What the stream at `at` is, when it is one: it decompresses to its end (with the checks its format has), and is not empty.
std::optional<Stream> try_stream(const Bytes& d, const Candidate& c, size_t max_plain) {
    try {
        const Bytes slice(d.begin() + static_cast<std::ptrdiff_t>(c.at), d.begin() + static_cast<std::ptrdiff_t>(std::min(d.size(), c.at + max_plain * 2)));
        size_t consumed = 0;
        std::string damage;
        Bytes plain = decompress(c.codec, slice, max_plain, &damage, &consumed);
        if (!damage.empty() || plain.empty() || consumed == 0) return std::nullopt;
        return Stream{c.at, consumed, c.codec, std::move(plain)};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ----------------------------------------------------------------------------------------------------------------------- the kernel --

// The kernel inside a zImage or a bzImage.
std::optional<Payload> find_payload(const Bytes& img, const Probe& p) {
    if (p.kind == Kind::X86BzImage && p.payload_len > 0 && fits(img, p.payload_at, p.payload_len)) {
        const Bytes slice(img.begin() + static_cast<std::ptrdiff_t>(p.payload_at), img.begin() + static_cast<std::ptrdiff_t>(p.payload_at + p.payload_len));
        const Codec codec = detect_codec(slice);
        if (codec == Codec::NONE) return std::nullopt;
        try {
            size_t consumed = 0;
            Bytes plain = decompress(codec, slice, kMaxDecompressedSize, nullptr, &consumed);
            if (plain.size() >= kMinPayload) return Payload{p.payload_at, consumed, codec, std::move(plain)};
        } catch (const std::exception&) {
        }
        return std::nullopt;
    }
    if (p.kind == Kind::ArmZImage) {
        size_t tries = 0;
        for (const Candidate& c : stream_candidates(img, 0x30, kZImageStubSearch)) {
            if (++tries > 16) break;
            if (auto s = try_stream(img, c, kMaxDecompressedSize); s && s->plain.size() >= kMinPayload) return Payload{s->offset, s->stored, s->codec, std::move(s->plain)};
        }
    }
    return std::nullopt;
}

// --------------------------------------------------------------------------------------------------------------------- the text --

Banner parse_banner(size_t at, std::string text) {
    Banner b;
    b.offset = at;
    b.text = std::move(text);
    // "Linux version " release " (" builder ") (" compiler ") " build
    const std::string_view t = b.text;
    constexpr std::string_view lead = "Linux version ";
    size_t p = lead.size();
    const size_t sp = t.find(' ', p);
    b.release = std::string(t.substr(p, sp == std::string_view::npos ? std::string_view::npos : sp - p));
    if (sp == std::string_view::npos) return b;
    p = sp + 1;
    const auto group = [&](std::string& into) {  // "(...)" with the parentheses inside in pairs
        if (p >= t.size() || t[p] != '(') return false;
        int depth = 0;
        size_t q = p;
        for (; q < t.size(); ++q) {
            if (t[q] == '(') ++depth;
            else if (t[q] == ')' && --depth == 0) break;
        }
        if (q >= t.size()) return false;
        into = std::string(t.substr(p + 1, q - p - 1));
        while (!into.empty() && into.back() == ' ') into.pop_back();  // "(gcc version 4.9.x (GCC) )": the compiler's own text ends in a blank
        while (!into.empty() && into.front() == ' ') into.erase(into.begin());
        p = q + 1;
        if (p < t.size() && t[p] == ' ') ++p;
        return true;
    };
    if (!group(b.builder)) return b;
    if (!group(b.compiler)) return b;
    b.build = std::string(t.substr(p));
    return b;
}

void find_text(const Bytes& d, Report& r) {
    std::set<std::string> seen;
    each_match(d, "Linux version ", 0, [&](size_t at) {
        if (r.banners.size() >= 8) return false;
        if (!fits(d, at + 14, 1) || d[at + 14] < '0' || d[at + 14] > '9') return true;
        std::string s = text_at(d, at);
        if (s.size() < 24 || !seen.insert(s).second) return true;
        r.banners.push_back(parse_banner(at, std::move(s)));
        return true;
    });
    if (!r.banners.empty() && !r.banners[0].release.empty()) {
        // the vermagic: a string of its own that begins with the release and goes on with what a module has to agree with
        const std::string key = r.banners[0].release + " ";
        each_match(d, key, 0, [&](size_t at) {
            if (at > 0 && d[at - 1] != 0) return true;
            const std::string s = text_at(d, at, 200);
            const std::string rest = s.substr(key.size());
            static const char* const flags[] = {"SMP", "preempt", "mod_unload", "modversions", "PREEMPT", "MODULE_UNLOAD", "UP"};
            bool ok = false;
            for (const char* f : flags) {
                const std::string_view w(f);
                if (rest.compare(0, w.size(), w) == 0 && (rest.size() == w.size() || rest[w.size()] == ' ')) ok = true;
            }
            if (!ok) return true;
            r.vermagic = s;
            while (!r.vermagic.empty() && r.vermagic.back() == ' ') r.vermagic.pop_back();
            return false;
        });
    }
    std::set<std::string> compilers;
    each_match(d, "GCC: (", 0, [&](size_t at) {
        if (at > 0 && d[at - 1] != 0 && d[at - 1] != '\n') return true;
        compilers.insert(text_at(d, at, 200));
        return compilers.size() < 16;
    });
    r.compilers.assign(compilers.begin(), compilers.end());
    std::set<std::string> boot;
    each_match(d, "androidboot.", 0, [&](size_t at) {
        std::string s;
        for (size_t i = at; i < d.size() && s.size() < 120 && printable(d[i]) && d[i] != ' ' && d[i] != '"' && d[i] != ','; ++i) s.push_back(static_cast<char>(d[i]));
        if (s.size() > 12) boot.insert(s);
        return boot.size() < 128;
    });
    r.androidboot.assign(boot.begin(), boot.end());
}

// ---------------------------------------------------------------------------------------------------------------- the configuration --

void parse_config(Config& c) {
    static const char* const notable[] = {"CONFIG_LOCALVERSION", "CONFIG_LOCALVERSION_AUTO", "CONFIG_CC_VERSION_TEXT", "CONFIG_CC_IS_CLANG", "CONFIG_GCC_VERSION",
                                          "CONFIG_CLANG_VERSION", "CONFIG_DEFAULT_HOSTNAME", "CONFIG_CMDLINE", "CONFIG_CMDLINE_FORCE", "CONFIG_CMDLINE_EXTEND",
                                          "CONFIG_BUILD_SALT", "CONFIG_BLK_DEV_INITRD", "CONFIG_INITRAMFS_SOURCE", "CONFIG_MODULES", "CONFIG_MODULE_SIG",
                                          "CONFIG_MODULE_SIG_FORCE", "CONFIG_MODULE_SIG_KEY", "CONFIG_SYSTEM_TRUSTED_KEYS", "CONFIG_KALLSYMS", "CONFIG_KALLSYMS_ALL",
                                          "CONFIG_KALLSYMS_BASE_RELATIVE", "CONFIG_SECURITY_SELINUX", "CONFIG_ANDROID", "CONFIG_ARM64_VA_BITS", "CONFIG_ARM64_PAGE_SHIFT",
                                          "CONFIG_PAGE_OFFSET", "CONFIG_PHYS_OFFSET", "CONFIG_RANDOMIZE_BASE", "CONFIG_KASAN", "CONFIG_SHADOW_CALL_STACK", "CONFIG_CFI_CLANG",
                                          "CONFIG_LTO_CLANG", "CONFIG_KERNEL_GZIP", "CONFIG_KERNEL_LZ4", "CONFIG_KERNEL_LZMA", "CONFIG_KERNEL_XZ", "CONFIG_KERNEL_ZSTD",
                                          "CONFIG_DM_VERITY", "CONFIG_IKCONFIG", "CONFIG_IKCONFIG_PROC"};
    const std::string& t = c.text;
    size_t pos = 0;
    while (pos < t.size()) {
        size_t eol = t.find('\n', pos);
        if (eol == std::string::npos) eol = t.size();
        const std::string_view line(t.data() + pos, eol - pos);
        pos = eol + 1;
        if (line.empty()) continue;
        if (line[0] == '#') {
            if (c.title.empty() && line.rfind("# Linux", 0) == 0) c.title = std::string(line);
            if (line.rfind("# CONFIG_", 0) == 0 && line.size() > 12 && line.substr(line.size() - 11) == " is not set") ++c.no;
            continue;
        }
        const size_t eq = line.find('=');
        if (eq == std::string_view::npos || line.rfind("CONFIG_", 0) != 0) continue;
        const std::string_view key = line.substr(0, eq), value = line.substr(eq + 1);
        if (value == "y") ++c.yes;
        else if (value == "m") ++c.modules;
        else ++c.value;
        for (const char* n : notable)
            if (key == n) {
                c.notable.push_back({std::string(key), std::string(value)});
                break;
            }
    }
}

std::optional<Config> find_config(const Bytes& d) {
    std::optional<Config> found;
    each_match(d, "IKCFG_ST", 0, [&](size_t at) {
        const size_t start = at + 8;
        if (!fits(d, start, 18) || d[start] != 0x1f || d[start + 1] != 0x8b) return true;
        try {
            const Bytes slice(d.begin() + static_cast<std::ptrdiff_t>(start), d.end());
            size_t consumed = 0;
            std::string damage;
            const Bytes plain = decompress(Codec::GZIP, slice, size_t{64} << 20, &damage, &consumed);
            if (!damage.empty()) return true;  // cut short: its last line would be half of one
            Config c;
            c.offset = start;
            c.stored = consumed;
            c.text.assign(plain.begin(), plain.end());
            if (c.text.find("CONFIG_") == std::string::npos) return true;
            parse_config(c);
            found = std::move(c);
            return false;
        } catch (const std::exception&) {
            return true;
        }
    });
    return found;
}

// ----------------------------------------------------------------------------------------------------------------- certificates --

std::string oid_name(const std::string& oid) {
    static const std::map<std::string, std::string> names = {
        {"1.2.840.113549.1.1.1", "rsaEncryption"},
        {"1.2.840.113549.1.1.4", "md5WithRSAEncryption"},
        {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
        {"1.2.840.113549.1.1.10", "RSASSA-PSS"},
        {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
        {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
        {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
        {"1.2.840.113549.1.1.14", "sha224WithRSAEncryption"},
        {"1.2.840.10045.2.1", "id-ecPublicKey"},
        {"1.2.840.10045.4.1", "ecdsa-with-SHA1"},
        {"1.2.840.10045.4.3.1", "ecdsa-with-SHA224"},
        {"1.2.840.10045.4.3.2", "ecdsa-with-SHA256"},
        {"1.2.840.10045.4.3.3", "ecdsa-with-SHA384"},
        {"1.2.840.10045.4.3.4", "ecdsa-with-SHA512"},
        {"1.2.840.10045.3.1.7", "prime256v1 (P-256)"},
        {"1.3.132.0.34", "secp384r1 (P-384)"},
        {"1.3.132.0.35", "secp521r1 (P-521)"},
        {"1.3.101.112", "Ed25519"},
        {"1.3.101.113", "Ed448"},
    };
    const auto it = names.find(oid);
    return it == names.end() ? oid : it->second;
}

const char* attribute_key(const std::string& oid) {
    if (oid == "2.5.4.3") return "CN";
    if (oid == "2.5.4.4") return "SN";
    if (oid == "2.5.4.5") return "serialNumber";
    if (oid == "2.5.4.6") return "C";
    if (oid == "2.5.4.7") return "L";
    if (oid == "2.5.4.8") return "ST";
    if (oid == "2.5.4.10") return "O";
    if (oid == "2.5.4.11") return "OU";
    if (oid == "1.2.840.113549.1.9.1") return "emailAddress";
    return nullptr;
}

std::string name_text(const Bytes& d, const der::Tlv& name) {
    std::string out;
    for (const der::Tlv& rdn : der::children(d, name)) {
        if (rdn.tag != der::kSet) continue;
        for (const der::Tlv& atv : der::children(d, rdn)) {
            const std::vector<der::Tlv> kv = der::children(d, atv);
            if (kv.size() != 2 || kv[0].tag != der::kOid) continue;
            const std::string oid = der::oid_to_string(der::content(d, kv[0]));
            const Bytes v = der::content(d, kv[1]);
            std::string value;
            if (kv[1].tag == 0x1e) {  // BMPString
                for (size_t i = 0; i + 1 < v.size(); i += 2) value.push_back(v[i] == 0 && v[i + 1] < 0x80 ? static_cast<char>(v[i + 1]) : '?');
            } else {
                bool plain = true;
                for (uint8_t c : v)
                    if (c < 0x20 || c > 0x7e) plain = false;
                if (plain) value.assign(v.begin(), v.end());
                else {
                    value = "#";
                    char b[4];
                    for (uint8_t c : v) {
                        std::snprintf(b, sizeof b, "%02x", c);
                        value += b;
                    }
                }
            }
            if (!out.empty()) out += ", ";
            const char* key = attribute_key(oid);
            out += (key ? std::string(key) : oid) + "=" + value;
        }
    }
    return out;
}

std::string time_text(const Bytes& d, const der::Tlv& t) {
    const Bytes c = der::content(d, t);
    std::string s(c.begin(), c.end());
    if (!s.empty() && s.back() == 'Z') s.pop_back();
    for (char ch : s)
        if (ch < '0' || ch > '9') return std::string(c.begin(), c.end());
    std::string year;
    if (t.tag == 0x17 && s.size() >= 10) year = (s[0] >= '5' ? "19" : "20") + s.substr(0, 2), s = s.substr(2);
    else if (t.tag == 0x18 && s.size() >= 12) year = s.substr(0, 4), s = s.substr(4);
    else return std::string(c.begin(), c.end());
    std::string out = year + "-" + s.substr(0, 2) + "-" + s.substr(2, 2) + " " + s.substr(4, 2) + ":" + s.substr(6, 2);
    out += ":" + (s.size() >= 10 ? s.substr(8, 2) : std::string("00")) + " UTC";
    return out;
}

// "RSA 4096 bits, exponent 65537", "EC prime256v1 (P-256)", "Ed25519"
std::string key_text(const Bytes& d, const der::Tlv& spki) {
    const std::vector<der::Tlv> parts = der::children(d, spki);
    if (parts.size() != 2 || parts[0].tag != der::kSequence || parts[1].tag != der::kBitString) return {};
    const std::vector<der::Tlv> alg = der::children(d, parts[0]);
    if (alg.empty() || alg[0].tag != der::kOid) return {};
    const std::string oid = der::oid_to_string(der::content(d, alg[0]));
    if (oid == "1.2.840.113549.1.1.1" && parts[1].content_len > 1) {
        try {
            const der::Tlv key = der::read(d, parts[1].content_offset() + 1, parts[1].end());
            const std::vector<der::Tlv> ne = der::children(d, key);
            if (ne.size() == 2 && ne[0].tag == der::kInteger && ne[1].tag == der::kInteger) {
                size_t first = ne[0].content_offset();
                const size_t last = ne[0].end();
                while (first < last && d[first] == 0) ++first;
                size_t bits = (last - first) * 8;
                if (first < last) {
                    uint8_t top = d[first];
                    while (top && !(top & 0x80)) top = static_cast<uint8_t>(top << 1), --bits;
                }
                uint64_t e = 0;
                for (size_t i = ne[1].content_offset(); i < ne[1].end() && i < ne[1].content_offset() + 8; ++i) e = e << 8 | d[i];
                return "RSA " + std::to_string(bits) + " bits, exponent " + std::to_string(e);
            }
        } catch (const std::exception&) {
        }
        return "RSA";
    }
    if (oid == "1.2.840.10045.2.1" && alg.size() > 1 && alg[1].tag == der::kOid) return "EC " + oid_name(der::oid_to_string(der::content(d, alg[1])));
    return oid_name(oid);
}

std::string hex_string(const Bytes& v) {
    std::string s;
    char b[4];
    for (uint8_t c : v) {
        std::snprintf(b, sizeof b, "%02x", c);
        s += b;
    }
    return s;
}

// The certificate that is the DER at `at`, with what is to be said of it; nothing when it is not one. Needs the structure of RFC 5280 to hold.
std::optional<Certificate> read_der_certificate(const Bytes& d, size_t at) {
    if (!fits(d, at, 8) || d[at] != 0x30 || (d[at + 1] != 0x81 && d[at + 1] != 0x82)) return std::nullopt;
    try {
        const der::Tlv top = der::read(d, at, d.size());
        if (top.total() < 64 || top.total() > kMaxCertificate) return std::nullopt;
        const std::vector<der::Tlv> parts = der::children(d, top);
        if (parts.size() != 3 || parts[0].tag != der::kSequence || parts[1].tag != der::kSequence || parts[2].tag != der::kBitString) return std::nullopt;
        const std::vector<der::Tlv> tbs = der::children(d, parts[0]);
        const size_t i = !tbs.empty() && tbs[0].tag == 0xA0 ? 1 : 0;  // [0] version
        if (tbs.size() < i + 6 || tbs[i].tag != der::kInteger) return std::nullopt;
        for (size_t k = 1; k <= 5; ++k)
            if (tbs[i + k].tag != der::kSequence) return std::nullopt;
        const std::vector<der::Tlv> validity = der::children(d, tbs[i + 3]);
        if (validity.size() != 2) return std::nullopt;
        for (const der::Tlv& v : validity)
            if (v.tag != 0x17 && v.tag != 0x18) return std::nullopt;
        // the algorithm of the signature is named twice, and it is the same
        const std::vector<der::Tlv> a1 = der::children(d, tbs[i + 1]), a2 = der::children(d, parts[1]);
        if (a1.empty() || a2.empty() || a1[0].tag != der::kOid || a2[0].tag != der::kOid || a1[0].content_len != a2[0].content_len ||
            std::memcmp(d.data() + a1[0].content_offset(), d.data() + a2[0].content_offset(), a1[0].content_len) != 0)
            return std::nullopt;
        Certificate c;
        c.offset = at;
        c.size = top.total();
        c.label = "CERTIFICATE";
        c.der.assign(d.begin() + static_cast<std::ptrdiff_t>(at), d.begin() + static_cast<std::ptrdiff_t>(top.end()));
        c.issuer = name_text(d, tbs[i + 2]);
        c.subject = name_text(d, tbs[i + 4]);
        c.not_before = time_text(d, validity[0]);
        c.not_after = time_text(d, validity[1]);
        c.signature_algorithm = oid_name(der::oid_to_string(der::content(d, a1[0])));
        c.public_key = key_text(d, tbs[i + 5]);
        {
            size_t first = tbs[i].content_offset();
            while (first + 1 < tbs[i].end() && d[first] == 0) ++first;
            c.serial = hex_string(Bytes(d.begin() + static_cast<std::ptrdiff_t>(first), d.begin() + static_cast<std::ptrdiff_t>(tbs[i].end())));
        }
        c.sha256 = hex_string(hash::sha256(c.der));
        return c;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void find_pem(const Bytes& d, std::vector<Certificate>& out) {
    each_match(d, "-----BEGIN ", 0, [&](size_t at) {
        if (out.size() >= kMaxItems) return false;
        const size_t p = at + 11;
        size_t q = p;
        while (q < d.size() && q - p < 64 && d[q] != '-' && printable(d[q])) ++q;
        if (q == p || !fits(d, q, 5) || std::memcmp(d.data() + q, "-----", 5) != 0) return true;
        const std::string label(d.begin() + static_cast<std::ptrdiff_t>(p), d.begin() + static_cast<std::ptrdiff_t>(q));
        const std::string end_mark = "-----END " + label + "-----";
        const size_t limit = std::min(d.size(), q + 5 + kMaxCertificate);
        const auto e = std::search(d.begin() + static_cast<std::ptrdiff_t>(q + 5), d.begin() + static_cast<std::ptrdiff_t>(limit), end_mark.begin(), end_mark.end());
        if (e == d.begin() + static_cast<std::ptrdiff_t>(limit)) return true;
        const size_t end = static_cast<size_t>(e - d.begin()) + end_mark.size();
        std::string text(d.begin() + static_cast<std::ptrdiff_t>(at), d.begin() + static_cast<std::ptrdiff_t>(end));
        for (char ch : text)
            if (!printable(static_cast<uint8_t>(ch)) && ch != '\n' && ch != '\r' && ch != '\t') return true;
        Certificate c;
        try {
            const std::vector<der::PemBlock> blocks = der::pem_decode(text);
            if (blocks.size() == 1) c.der = blocks[0].der;
        } catch (const std::exception&) {
        }
        if (label == "CERTIFICATE" && !c.der.empty()) {
            if (auto parsed = read_der_certificate(c.der, 0)) c = std::move(*parsed);
        }
        c.offset = at;
        c.size = end - at;
        c.pem = true;
        c.label = label;
        c.pem_text = std::move(text);
        out.push_back(std::move(c));
        return true;
    });
}

std::vector<Certificate> find_certificates(const Bytes& d) {
    std::vector<Certificate> out;
    size_t skip_to = 0;
    each_match(d, std::string_view("\x30", 1), 0, [&](size_t at) {
        if (at < skip_to) return true;
        if (!fits(d, at, 2) || (d[at + 1] != 0x81 && d[at + 1] != 0x82)) return true;
        if (auto c = read_der_certificate(d, at)) {
            skip_to = at + c->size;
            out.push_back(std::move(*c));
        }
        return out.size() < kMaxItems;
    });
    find_pem(d, out);
    std::stable_sort(out.begin(), out.end(), [](const Certificate& a, const Certificate& b) { return a.offset < b.offset; });
    if (out.size() > kMaxItems) out.resize(kMaxItems);
    return out;
}

// ----------------------------------------------------------------------------------------------------- ELF files and device trees --

const char* machine_name(uint16_t m) {
    switch (m) {
        case 3: return "x86";
        case 8: return "MIPS";
        case 20: return "PowerPC";
        case 21: return "PowerPC64";
        case 40: return "ARM";
        case 62: return "x86-64";
        case 164: return "Hexagon";
        case 183: return "AArch64";
        case 243: return "RISC-V";
        case 258: return "LoongArch";
        default: return nullptr;
    }
}

struct ElfFound {
    size_t size = 0;
    std::string what;
};

// An ELF file at `at`: the header of a class and a byte order, the tables where the header says they are, and every segment and section
// inside the bytes there are; its size is the end of the last of them.
std::optional<ElfFound> elf_at(const Bytes& d, size_t at) {
    if (!fits(d, at, 52) || std::memcmp(d.data() + at, "\x7f" "ELF", 4) != 0) return std::nullopt;
    const uint8_t cls = d[at + 4], data = d[at + 5];
    if ((cls != 1 && cls != 2) || (data != 1 && data != 2) || d[at + 6] != 1) return std::nullopt;
    const bool be = data == 2, is64 = cls == 2;
    if (is64 && !fits(d, at, 64)) return std::nullopt;
    const auto r16 = [&](size_t o) { return rd16(d, at + o, be); };
    const auto r32 = [&](size_t o) { return rd32(d, at + o, be); };
    const auto r64 = [&](size_t o) { return rd64(d, at + o, be); };
    const uint16_t type = r16(16), machine = r16(18);
    if (type < 1 || type > 4 || r32(20) != 1) return std::nullopt;
    const uint64_t phoff = is64 ? r64(32) : r32(28), shoff = is64 ? r64(40) : r32(32);
    const uint16_t ehsize = r16(is64 ? 52 : 40), phentsize = r16(is64 ? 54 : 42), phnum = r16(is64 ? 56 : 44), shentsize = r16(is64 ? 58 : 46), shnum = r16(is64 ? 60 : 48);
    if (ehsize != (is64 ? 64 : 52)) return std::nullopt;
    if (phnum > 0 && phentsize != (is64 ? 56 : 32)) return std::nullopt;
    if (shnum > 0 && shentsize != (is64 ? 64 : 40)) return std::nullopt;
    if (phnum > 256 || shnum > 4096 || (phnum == 0 && shnum == 0)) return std::nullopt;
    const uint64_t room = d.size() - at;
    uint64_t extent = ehsize;
    const auto take = [&](uint64_t end) {
        if (end > room) return false;
        extent = std::max(extent, end);
        return true;
    };
    if (phnum > 0) {
        if (phoff > room || !take(phoff + uint64_t{phnum} * phentsize)) return std::nullopt;
        for (uint16_t k = 0; k < phnum; ++k) {
            const size_t h = static_cast<size_t>(phoff) + k * phentsize;
            const uint64_t offset = is64 ? r64(h + 8) : r32(h + 4), filesz = is64 ? r64(h + 32) : r32(h + 16);
            if (offset > room || filesz > room || !take(offset + filesz)) return std::nullopt;
        }
    }
    if (shnum > 0) {
        if (shoff > room || !take(shoff + uint64_t{shnum} * shentsize)) return std::nullopt;
        for (uint16_t k = 0; k < shnum; ++k) {
            const size_t h = static_cast<size_t>(shoff) + k * shentsize;
            const uint32_t sh_type = r32(h + 4);
            if (sh_type == 8 /* NOBITS */ || sh_type == 0) continue;
            const uint64_t offset = is64 ? r64(h + 24) : r32(h + 16), size = is64 ? r64(h + 32) : r32(h + 20);
            if (offset > room || size > room || !take(offset + size)) return std::nullopt;
        }
    }
    ElfFound f;
    f.size = static_cast<size_t>(extent);
    static const char* const types[] = {"", "relocatable file", "executable", "shared object", "core file"};
    f.what = std::string(is64 ? "ELF 64-bit " : "ELF 32-bit ") + (be ? "big endian " : "little endian ") + types[type] + ", ";
    if (const char* m = machine_name(machine)) f.what += m;
    else f.what += "machine " + std::to_string(machine);
    // the vDSO that the kernel maps into every process: an object that exports the kernel's entry points
    const auto first = d.begin() + static_cast<std::ptrdiff_t>(at), last = first + static_cast<std::ptrdiff_t>(f.size);
    for (const std::string_view key : {std::string_view("LINUX_2.6"), std::string_view("__kernel_rt_sigreturn"), std::string_view("__vdso_clock_gettime")})
        if (std::search(first, last, key.begin(), key.end()) != last) {
            f.what += ", the vDSO";
            break;
        }
    return f;
}

void find_elf_and_trees(const Bytes& d, std::vector<Embedded>& out) {
    size_t elf_end = 0;
    each_match(d, std::string_view("\x7f" "ELF", 4), 0, [&](size_t at) {
        if (out.size() >= kMaxItems) return false;
        if (at < elf_end) return true;
        if (auto e = elf_at(d, at)) {
            Embedded x;
            x.kind = "elf";
            x.what = e->what;
            x.offset = at;
            x.stored = e->size;
            x.data.assign(d.begin() + static_cast<std::ptrdiff_t>(at), d.begin() + static_cast<std::ptrdiff_t>(at + e->size));
            out.push_back(std::move(x));
            elf_end = at + e->size;
        }
        return true;
    });
    size_t tree_end = 0;
    each_match(d, std::string_view("\xd0\x0d\xfe\xed", 4), 0, [&](size_t at) {
        if (out.size() >= 2 * kMaxItems) return false;
        if (at < tree_end || !kernel::plausible_tree(d, at)) return true;
        const size_t total = rd32(d, at + 4, true);
        if (!fits(d, at, total)) return true;
        Embedded x;
        x.kind = "dtb";
        x.offset = at;
        x.stored = total;
        x.data.assign(d.begin() + static_cast<std::ptrdiff_t>(at), d.begin() + static_cast<std::ptrdiff_t>(at + total));
        try {
            const fdt::Tree tree = fdt::parse(x.data);
            x.text = dts::print(tree);
            x.what = "device tree";
            if (std::string model; tree.root.get_string("model", model) && !model.empty()) x.what += ", model \"" + model + "\"";
        } catch (const std::exception&) {
            x.what = "device tree (its source could not be written)";
        }
        out.push_back(std::move(x));
        tree_end = at + total;
        return true;
    });
}

// -------------------------------------------------------------------------------------------------------- initramfs, streams --

std::string classify(const Bytes& plain) {
    if (plain.size() >= 4 && std::memcmp(plain.data(), "\x7f" "ELF", 4) == 0) return "elf";
    if (plain.size() >= 4 && std::memcmp(plain.data(), "\xd0\x0d\xfe\xed", 4) == 0) return "dtb";
    if (looks_like_text(plain)) return "text";
    return "data";
}

std::string stream_what(const std::string& kind, Codec codec, size_t stored, size_t plain) {
    std::string s = std::string(codec_name(codec)) + " stream of " + std::to_string(stored) + " bytes that holds ";
    if (kind == "elf") s += "an ELF file";
    else if (kind == "dtb") s += "a device tree";
    else if (kind == "text") s += "text";
    else s += "data";
    return s + " (" + std::to_string(plain) + " bytes)";
}

// The archives that are linked into the kernel as they are.
void find_plain_cpio(const Bytes& d, std::vector<Initramfs>& out) {
    std::vector<size_t> at;
    for (const char* magic : {"070701", "070702"}) each_match(d, magic, 0, [&](size_t p) { return at.push_back(p), at.size() < 4096; });
    std::sort(at.begin(), at.end());
    size_t end = 0, tries = 0;
    for (const size_t p : at) {
        if (p < end) continue;
        if (++tries > kMaxCpioTries || out.size() >= kMaxItems) break;
        std::string error;
        const auto parsed = cpio::parse(d.data() + p, d.size() - p, error);
        if (!parsed) continue;
        Initramfs x;
        x.offset = p;
        x.stored = parsed->length;
        x.plain.assign(d.begin() + static_cast<std::ptrdiff_t>(p), d.begin() + static_cast<std::ptrdiff_t>(p + parsed->length));
        x.entries = parsed->archive.entries.size();
        out.push_back(std::move(x));
        end = p + parsed->length;
    }
}

// The streams in the kernel: the one that holds an archive is an initramfs, the others are files.
void find_streams(const Bytes& d, std::vector<Initramfs>& initramfs, std::vector<Embedded>& embedded) {
    size_t end = 0, tries = 0, retained = 0;
    for (const Candidate& c : stream_candidates(d, 0, d.size())) {
        if (c.at < end) continue;
        if (c.at >= 8 && std::memcmp(d.data() + c.at - 8, "IKCFG_ST", 8) == 0) continue;  // the configuration: its own file
        if (++tries > kMaxStreamTries) break;
        auto s = try_stream(d, c, kMaxStreamPlain);
        if (!s) continue;
        end = s->offset + s->stored;
        retained += s->plain.size();
        if (retained > kMaxRetained) break;
        std::string error;
        if (s->plain.size() >= 6 && std::memcmp(s->plain.data(), "07070", 5) == 0 && (s->plain[5] == '1' || s->plain[5] == '2')) {
            if (const auto parsed = cpio::parse(s->plain, error)) {
                Initramfs x;
                x.offset = s->offset;
                x.stored = s->stored;
                x.codec = s->codec;
                x.entries = parsed->archive.entries.size();
                x.plain = std::move(s->plain);
                initramfs.push_back(std::move(x));
                continue;
            }
        }
        Embedded x;
        x.kind = classify(s->plain);
        x.offset = s->offset;
        x.stored = s->stored;
        x.codec = s->codec;
        x.what = stream_what(x.kind, s->codec, s->stored, s->plain.size());
        if (x.kind == "dtb") {
            try {
                x.text = dts::print(fdt::parse(s->plain));
            } catch (const std::exception&) {
            }
        }
        x.data = std::move(s->plain);
        embedded.push_back(std::move(x));
        if (embedded.size() >= kMaxItems) break;
    }
}

// --------------------------------------------------------------------------------------------------------------------- the tail --

std::string describe_bytes(const uint8_t* p, size_t n) {
    if (n == 0) return "nothing";
    if (all_bytes(p, n, 0)) return "all zeros";
    if (all_bytes(p, n, 0xff)) return "all 0xFF";
    const auto starts = [&](std::string_view s) { return n >= s.size() && std::memcmp(p, s.data(), s.size()) == 0; };
    if (starts("SEANDROIDENFORCE")) return "the text SEANDROIDENFORCE (Samsung's mark of a kernel that enforces SELinux)" + std::string(n > 16 ? " and more" : "");
    if (starts("\xd0\x0d\xfe\xed")) return "a device tree";
    if (starts("ANDROID!")) return "an Android boot image";
    if (starts("\x1f\x8b\x08")) return "a gzip stream";
    if (starts("\xfd" "7zXZ")) return "an xz stream";
    if (starts("\x28\xb5\x2f\xfd")) return "a zstd frame";
    if (starts("\x30\x82") || starts("\x30\x81")) return "DER data (a signature or a certificate)";
    std::string s = std::to_string(n) + " bytes of data, beginning ";
    char b[4];
    for (size_t i = 0; i < std::min<size_t>(n, 16); ++i) {
        std::snprintf(b, sizeof b, "%02x", p[i]);
        s += b;
    }
    return s;
}

}  // namespace

// ------------------------------------------------------------------------------------------------------------------- the report --

const char* kind_name(Kind kind) {
    switch (kind) {
        case Kind::Unknown: return "kernel (no header that abr knows)";
        case Kind::Arm64Image: return "arm64 Image";
        case Kind::ArmZImage: return "arm zImage";
        case Kind::X86BzImage: return "x86 bzImage";
        case Kind::RiscvImage: return "riscv Image";
        case Kind::Elf: return "ELF (vmlinux)";
    }
    return "kernel";
}

Report analyze(const Bytes& kernel) {
    Report r;
    r.size = kernel.size();
    try {
        const Probe p = probe(kernel);
        r.kind = p.kind;
        r.header = p.header;
        r.payload = find_payload(kernel, p);
        const Bytes& flat = r.payload ? r.payload->plain : kernel;
        // A flat kernel that has no header of its own (what a zImage holds): if it has one (an Image inside), it is the kind that is told.
        if (r.payload && r.kind != Kind::Unknown) {
            const Probe inner = probe(flat);
            if (inner.kind != Kind::Unknown) r.header.push_back({"payload_kind", kind_name(inner.kind)});
        }

        std::vector<Initramfs> cpio_plain, cpio_streams;
        std::vector<Embedded> streams, files;
        std::vector<Certificate> certs;
        const auto guarded = [](auto&& job) {
            return [job = std::forward<decltype(job)>(job)]() {
                try {
                    job();
                } catch (...) {
                }
            };
        };
        par::run_all({
            guarded([&] { find_text(flat, r); }),
            guarded([&] { r.config = find_config(flat); }),
            guarded([&] { r.kallsyms = kallsyms::find(flat); }),
            guarded([&] { find_streams(flat, cpio_streams, streams); }),
            guarded([&] { find_plain_cpio(flat, cpio_plain); }),
            guarded([&] { certs = find_certificates(flat); }),
            guarded([&] { find_elf_and_trees(flat, files); }),
        });

        r.initramfs = std::move(cpio_plain);
        for (Initramfs& x : cpio_streams) r.initramfs.push_back(std::move(x));
        std::sort(r.initramfs.begin(), r.initramfs.end(), [](const Initramfs& a, const Initramfs& b) { return a.offset < b.offset; });
        r.certificates = std::move(certs);
        r.embedded = std::move(files);
        for (Embedded& x : streams) r.embedded.push_back(std::move(x));
        std::sort(r.embedded.begin(), r.embedded.end(), [](const Embedded& a, const Embedded& b) { return a.offset < b.offset; });

        if (p.end > 0 && p.end < kernel.size()) {
            Tail t;
            t.offset = p.end;
            t.size = kernel.size() - p.end;
            t.what = describe_bytes(kernel.data() + p.end, t.size);
            r.tail = std::move(t);
        }
    } catch (...) {
        // whatever was found stays; a report is what could be learned
    }
    return r;
}

}  // namespace abr::kernelinfo
