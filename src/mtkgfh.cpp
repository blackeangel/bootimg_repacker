// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/mtkgfh.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "abr/sha.hpp"

namespace abr::mtkgfh {

namespace {

uint16_t le16(const Bytes& d, size_t at) { return static_cast<uint16_t>(d[at] | (d[at + 1] << 8)); }

uint32_t le32(const Bytes& d, size_t at) {
    return uint32_t{d[at]} | (uint32_t{d[at + 1]} << 8) | (uint32_t{d[at + 2]} << 16) | (uint32_t{d[at + 3]} << 24);
}

void put16(Bytes& out, size_t at, uint16_t v) {
    out[at] = static_cast<uint8_t>(v);
    out[at + 1] = static_cast<uint8_t>(v >> 8);
}

void put32(Bytes& out, size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) out[at + i] = static_cast<uint8_t>(v >> (8 * i));
}

void append32(Bytes& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

constexpr size_t kMaxHeaders = 64;

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

// `text` and a zero behind it at the start of the `field` bytes at `at` (what C's strcmp makes of a name in a field).
bool field_is(const Bytes& d, size_t at, size_t field, std::string_view text) {
    if (text.size() >= field || at > d.size() || d.size() - at < field) return false;
    return std::memcmp(d.data() + at, text.data(), text.size()) == 0 && d[at + text.size()] == 0;
}

bool header_at(const Bytes& d, size_t at) { return at <= d.size() && d.size() - at >= kCommonSize && (le32(d, at) & 0xFFFFFF) == kMagic; }

// A FILE_INFO header at `at`: "MMM", a size that holds all of it, type 0, and its name.
bool file_info_at(const Bytes& d, size_t at) {
    if (at > d.size() || d.size() - at < kFileInfoSize || !header_at(d, at)) return false;
    return le16(d, at + 4) >= kFileInfoSize && le16(d, at + 6) == kTypeFileInfo && field_is(d, at + 8, 12, "FILE_INFO");
}

// The problem of the FILE_INFO at `at` (which must be there): empty when its sizes hold together.
std::string problem_at(const Bytes& d, size_t at) {
    const uint32_t size = le16(d, at + 4), total = le32(d, at + 32), hdr = le32(d, at + 40), sig = le32(d, at + 44);
    if (hdr < size) return "FILE_INFO.hdr_size (" + std::to_string(hdr) + ") is smaller than the FILE_INFO header itself (" + std::to_string(size) + ")";
    if (uint64_t{hdr} + sig > total)
        return "FILE_INFO.hdr_size and sig_size (" + std::to_string(hdr) + " + " + std::to_string(sig) + " bytes) are more than FILE_INFO.total_size (" + std::to_string(total) + ")";
    if (uint64_t{at} + total > d.size())
        return "the file is cut short: FILE_INFO.total_size says that the loader is " + std::to_string(total) + " bytes from offset " + std::to_string(at) +
               ", and the file has " + std::to_string(d.size() - at) + " bytes from there";
    return {};
}

}  // namespace

// ------------------------------------------------------------------------------------------------------------------------ names --

std::string type_name(uint16_t type) {
    switch (type) {
        case kTypeFileInfo: return "FILE_INFO";
        case kTypeBlInfo: return "BL_INFO";
        case kTypeAntiClone: return "ANTI_CLONE";
        case kTypeBlSecKey: return "BL_SEC_KEY";
        case kTypeBromCfg: return "BROM_CFG";
        case kTypeBromSecCfg: return "BROM_SEC_CFG";
        default: return "type " + std::to_string(type);
    }
}

std::string sig_type_name(uint8_t sig_type) {
    if (sig_type == kSigNone) return "none";
    if (sig_type == kSigSha256) return "SHA-256";
    return "kind " + std::to_string(sig_type);
}

std::string flash_type_name(uint8_t flash_type) {
    if (flash_type == 5) return "generic (NOR, SD, eMMC)";
    if (flash_type == 2) return "NAND";
    return "type " + std::to_string(flash_type);
}

std::string brlyt_type_name(uint32_t type) {
    switch (type) {
        case kBrlytEmmc: return "eMMC";
        case kBrlytNor: return "NOR";
        case kBrlytSdmmc: return "SD/MMC";
        case kBrlytNand: return "NAND";
        case kBrlytSerialNand: return "serial NAND";
        default: return hex(type);
    }
}

const char* size_basis_name(SizeBasis b) {
    switch (b) {
        case SizeBasis::File: return "file";
        case SizeBasis::Chain: return "chain";
        default: return "literal";
    }
}

std::optional<SizeBasis> size_basis_from_name(std::string_view name) {
    if (name == "file") return SizeBasis::File;
    if (name == "chain") return SizeBasis::Chain;
    if (name == "literal") return SizeBasis::Literal;
    return std::nullopt;
}

// ---------------------------------------------------------------------------------------------------------------------- headers --

namespace {

// The bits of BROM_CFG.cfg_bits that U-Boot's definitions name.
std::string cfg_bits_text(uint32_t bits) {
    static constexpr struct {
        uint32_t bit;
        const char* name;
    } kFlags[] = {{0x02, "usbdl_by_auto_detect_timeout_en"}, {0x10, "usbdl_auto_detect_dis"}, {0x80, "usbdl_by_kcol0_timeout_en"},
                  {0x100, "usbdl_by_flag_timeout_en"},       {0x1000, "jump_bl_arm64_en"}};
    std::string out;
    uint32_t known = 0;
    for (const auto& f : kFlags) {
        if (bits & f.bit) out += (out.empty() ? "" : ", ") + std::string(f.name);
        known |= f.bit;
    }
    if (bits & ~known) out += (out.empty() ? "" : ", ") + std::string("other bits ") + hex(bits & ~known);
    return out;
}

}  // namespace

std::string describe(const Header& h) {
    const Bytes& b = h.body;  // offsets below are those of the whole header, minus the eight common bytes
    auto u32 = [&](size_t at) { return le32(b, at - kCommonSize); };
    switch (h.type) {
        case kTypeBlInfo:
            if (b.size() >= 4) return "attr " + hex(u32(8));
            break;
        case kTypeAntiClone:
            if (b.size() >= 12)
                return "ac_b2k " + std::to_string(b[0]) + ", ac_b2c " + std::to_string(b[1]) + ", ac_offset " + hex(u32(12)) + ", ac_len " + hex(u32(16));
            break;
        case kTypeBromCfg:
            if (b.size() >= 92) {
                const uint32_t bits = u32(8);
                std::string out = "cfg_bits " + hex(bits);
                if (const std::string t = cfg_bits_text(bits); !t.empty()) out += " (" + t + ")";
                out += ", usbdl_by_auto_detect_timeout_ms " + std::to_string(u32(12)) + ", jump_bl_arm64 " + hex(b[85 - kCommonSize]) +
                       ", usbdl_by_kcol0_timeout_ms " + std::to_string(u32(88)) + ", usbdl_by_flag_timeout_ms " + std::to_string(u32(92));
                return out;
            }
            break;
        case kTypeBromSecCfg:
            if (b.size() >= 36) {
                const uint32_t bits = u32(8);
                std::string flags;
                if (bits & 1) flags += "jtag_en";
                if (bits & 2) flags += std::string(flags.empty() ? "" : ", ") + "uart_en";
                if (bits & ~3u) flags += std::string(flags.empty() ? "" : ", ") + "other bits " + hex(bits & ~3u);
                std::string name;
                for (size_t i = 12 - kCommonSize; i < 44 - kCommonSize && b[i]; ++i) name += static_cast<char>(b[i] >= 0x20 && b[i] < 0x7f ? b[i] : '?');
                return "cfg_bits " + hex(bits) + (flags.empty() ? "" : " (" + flags + ")") + ", customer_name \"" + name + "\"";
            }
            break;
        default: break;
    }
    return {};
}

std::string FileInfo::name_text() const {
    size_t n = 0;
    while (n < name.size() && name[n]) ++n;
    return std::string(reinterpret_cast<const char*>(name.data()), n);
}

Bytes FileInfo::name_tail() const {
    size_t n = 0;
    while (n < name.size() && name[n]) ++n;
    if (n < name.size()) ++n;  // the zero itself
    size_t end = name.size();
    while (end > n && name[end - 1] == 0) --end;
    return Bytes(name.begin() + static_cast<std::ptrdiff_t>(n), name.begin() + static_cast<std::ptrdiff_t>(end));
}

FileInfo read_file_info(const Header& h) {
    if (h.type != kTypeFileInfo) throw FormatError("mtkgfh: the header is " + type_name(h.type) + ", not FILE_INFO");
    if (h.size() < kFileInfoSize) throw FormatError("mtkgfh: a FILE_INFO header of " + std::to_string(h.size()) + " bytes (it has 56)");
    const Bytes& b = h.body;  // FILE_INFO starts with its eight common bytes, so every offset is smaller by that
    FileInfo f;
    f.version = h.version;
    std::copy(b.begin(), b.begin() + 12, f.name.begin());
    f.file_ver = le32(b, 12);
    f.file_type = le16(b, 16);
    f.flash_type = b[18];
    f.sig_type = b[19];
    f.load_addr = le32(b, 20);
    f.total_size = le32(b, 24);
    f.max_size = le32(b, 28);
    f.hdr_size = le32(b, 32);
    f.sig_size = le32(b, 36);
    f.jump_offset = le32(b, 40);
    f.processed = le32(b, 44);
    f.extra.assign(b.begin() + 48, b.end());
    return f;
}

Header write_file_info(const FileInfo& f) {
    Header h;
    h.version = f.version;
    h.type = kTypeFileInfo;
    h.body.assign(kFileInfoSize - kCommonSize, 0);
    Bytes& b = h.body;
    std::copy(f.name.begin(), f.name.end(), b.begin());
    put32(b, 12, f.file_ver);
    put16(b, 16, f.file_type);
    b[18] = f.flash_type;
    b[19] = f.sig_type;
    put32(b, 20, f.load_addr);
    put32(b, 24, f.total_size);
    put32(b, 28, f.max_size);
    put32(b, 32, f.hdr_size);
    put32(b, 36, f.sig_size);
    put32(b, 40, f.jump_offset);
    put32(b, 44, f.processed);
    b.insert(b.end(), f.extra.begin(), f.extra.end());
    return h;
}

std::optional<Marker> find_bloader_marker(const Bytes& payload) {
    static constexpr std::string_view kText = "MTK_BLOADER_INFO_v";
    const auto it = std::search(payload.begin(), payload.end(), kText.begin(), kText.end());
    if (it == payload.end()) return std::nullopt;
    Marker m;
    m.offset = static_cast<size_t>(it - payload.begin());
    size_t end = m.offset + kText.size();
    while (end < payload.size() && end < m.offset + kText.size() + 4 && payload[end] >= '0' && payload[end] <= '9') ++end;
    m.text.assign(payload.begin() + static_cast<std::ptrdiff_t>(m.offset), payload.begin() + static_cast<std::ptrdiff_t>(end));
    return m;
}

std::vector<Header> split_headers(const Bytes& d, size_t from, size_t to, Bytes* pad) {
    to = std::min(to, d.size());
    std::vector<Header> out;
    size_t o = from;
    while (o < to && to - o >= kCommonSize && header_at(d, o)) {
        if (out.size() == kMaxHeaders) throw FormatError("mtkgfh: more than " + std::to_string(kMaxHeaders) + " headers in a row");
        const uint16_t size = le16(d, o + 4);
        if (size < kCommonSize) throw FormatError("mtkgfh: the header at offset " + std::to_string(o) + " says it is " + std::to_string(size) + " bytes, fewer than its own eight");
        if (size > to - o)
            throw FormatError("mtkgfh: the header at offset " + std::to_string(o) + " (" + type_name(le16(d, o + 6)) + ", " + std::to_string(size) +
                              " bytes) goes beyond the end of the headers (offset " + std::to_string(to) + ")");
        Header h;
        h.version = d[o + 3];
        h.type = le16(d, o + 6);
        h.body.assign(d.begin() + static_cast<std::ptrdiff_t>(o + kCommonSize), d.begin() + static_cast<std::ptrdiff_t>(o + size));
        out.push_back(std::move(h));
        o += size;
    }
    if (pad) pad->assign(d.begin() + static_cast<std::ptrdiff_t>(std::min(o, to)), d.begin() + static_cast<std::ptrdiff_t>(to));
    return out;
}

Bytes serialize_headers(const std::vector<Header>& chain, size_t first) {
    Bytes out;
    for (size_t i = first; i < chain.size(); ++i) {
        const Header& h = chain[i];
        if (h.size() > 0xFFFF) throw FormatError("mtkgfh: a header of " + std::to_string(h.size()) + " bytes does not fit in the 16 bits of its size");
        append32(out, kMagic | (uint32_t{h.version} << 24));
        out.push_back(static_cast<uint8_t>(h.size()));
        out.push_back(static_cast<uint8_t>(h.size() >> 8));
        out.push_back(static_cast<uint8_t>(h.type));
        out.push_back(static_cast<uint8_t>(h.type >> 8));
        out.insert(out.end(), h.body.begin(), h.body.end());
    }
    return out;
}

// ------------------------------------------------------------------------------------------------------------------------ image --

std::optional<Device> parse_device(const Bytes& d) {
    if (d.size() < kDeviceHeaderSize + kBrlytSize) return std::nullopt;
    std::string name;
    for (const char* n : {"EMMC_BOOT", "SF_BOOT", "SDMMC_BOOT"})
        if (field_is(d, 0, 12, n)) name = n;
    if (name.empty() || le32(d, 12) != 1 || le32(d, 16) != kDeviceHeaderSize) return std::nullopt;
    constexpr size_t b = kDeviceHeaderSize;
    if (!field_is(d, b, 8, "BRLYT") || le32(d, b + 20) != kBrlytMagic) return std::nullopt;
    Device v;
    v.boot_name = name;
    v.boot_version = le32(d, 12);
    v.boot_size = le32(d, 16);
    v.version = le32(d, b + 8);
    v.header_size = le32(d, b + 12);
    v.total_size = le32(d, b + 16);
    v.magic = le32(d, b + 20);
    v.type = le32(d, b + 24);
    v.header_size_2 = le32(d, b + 28);
    v.total_size_2 = le32(d, b + 32);
    v.unused = le32(d, b + 36);
    if (v.type != kBrlytEmmc && v.type != kBrlytNor && v.type != kBrlytSdmmc) return std::nullopt;
    return v;
}

std::optional<size_t> find_chain(const Bytes& d, std::optional<Device>* device) {
    if (device) device->reset();
    if (file_info_at(d, 0)) return 0;
    const std::optional<Device> v = parse_device(d);
    if (!v) return std::nullopt;
    const uint64_t at = v->header_size;
    if (at < kDeviceHeaderSize + kBrlytSize || at >= d.size() || !file_info_at(d, static_cast<size_t>(at))) return std::nullopt;
    if (device) *device = v;
    return static_cast<size_t>(at);
}

std::string problem(const Bytes& d) {
    const std::optional<size_t> at = find_chain(d);
    return at ? problem_at(d, *at) : std::string();
}

bool looks_like(const Bytes& d) {
    const std::optional<size_t> at = find_chain(d);
    return at && problem_at(d, *at).empty();
}

Image parse(const Bytes& d) {
    Image img;
    const std::optional<size_t> found = find_chain(d, &img.device);
    if (!found) throw FormatError("mtkgfh: no FILE_INFO header at the start of the file or where a BRLYT says the headers are");
    const size_t at = *found;
    if (const std::string why = problem_at(d, at); !why.empty()) throw FormatError("mtkgfh: " + why);
    img.prefix.assign(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(at));

    const FileInfo first = read_file_info(split_headers(d, at, at + le16(d, at + 4), nullptr).at(0));
    const size_t hdr_end = at + first.hdr_size;
    img.chain = split_headers(d, at, hdr_end, &img.chain_pad);
    if (img.chain.empty() || img.chain[0].type != kTypeFileInfo) throw FormatError("mtkgfh: the headers do not start with FILE_INFO");
    const size_t sig_at = at + first.total_size - first.sig_size;
    img.payload.assign(d.begin() + static_cast<std::ptrdiff_t>(hdr_end), d.begin() + static_cast<std::ptrdiff_t>(sig_at));
    img.signature.assign(d.begin() + static_cast<std::ptrdiff_t>(sig_at), d.begin() + static_cast<std::ptrdiff_t>(at + first.total_size));
    img.consumed = at + first.total_size;

    if (first.sig_type == kSigSha256 && first.sig_size == kSha256Size) {
        hash::Sha256 h;
        h.update(d.data() + at, sig_at - at);
        img.sha256_trailer = h.finish() == img.signature;
    }

    if (img.device) {
        const Device& v = *img.device;
        if (v.total_size == v.total_size_2 && v.header_size == v.header_size_2) {
            if (v.total_size == d.size()) img.basis = SizeBasis::File;
            else if (v.total_size == img.consumed) img.basis = SizeBasis::Chain;
        }
    }
    return img;
}

Bytes build(const Image& img) {
    if (img.chain.empty() || img.chain[0].type != kTypeFileInfo) throw FormatError("mtkgfh: the headers do not start with FILE_INFO");
    std::vector<Header> chain = img.chain;
    size_t chain_size = 0;
    for (const Header& h : chain) chain_size += h.size();
    const uint64_t hdr_size = chain_size + img.chain_pad.size();
    const uint64_t sig_size = img.sha256_trailer ? kSha256Size : img.signature.size();
    const uint64_t total = hdr_size + img.payload.size() + sig_size;
    if (total > 0xFFFFFFFFull) throw FormatError("mtkgfh: the loader is " + std::to_string(total) + " bytes, more than the 32 bits of FILE_INFO.total_size");
    FileInfo f = read_file_info(chain[0]);
    f.hdr_size = static_cast<uint32_t>(hdr_size);
    f.sig_size = static_cast<uint32_t>(sig_size);
    f.total_size = static_cast<uint32_t>(total);
    if (img.sha256_trailer) f.sig_type = kSigSha256;
    chain[0] = write_file_info(f);

    Bytes out;
    out.reserve(img.prefix.size() + total);
    out.insert(out.end(), img.prefix.begin(), img.prefix.end());
    const Bytes headers = serialize_headers(chain);
    out.insert(out.end(), headers.begin(), headers.end());
    out.insert(out.end(), img.chain_pad.begin(), img.chain_pad.end());
    out.insert(out.end(), img.payload.begin(), img.payload.end());
    if (img.sha256_trailer) {
        hash::Sha256 h;
        h.update(out.data() + img.prefix.size(), out.size() - img.prefix.size());
        const Bytes digest = h.finish();
        out.insert(out.end(), digest.begin(), digest.end());
    } else {
        out.insert(out.end(), img.signature.begin(), img.signature.end());
    }
    return out;
}

void fix_device(Bytes& file, const Image& img) {
    if (!img.device || img.basis == SizeBasis::Literal) return;
    constexpr size_t b = kDeviceHeaderSize;
    if (file.size() < b + kBrlytSize) return;
    uint64_t total = file.size();
    if (img.basis == SizeBasis::Chain) {
        const size_t at = img.at();
        if (file.size() < at + kFileInfoSize) return;
        total = at + uint64_t{le32(file, at + 32)};
    }
    if (total > 0xFFFFFFFFull) throw FormatError("mtkgfh: the file is " + std::to_string(total) + " bytes, more than the 32 bits of the sizes of the BRLYT");
    put32(file, b + 16, static_cast<uint32_t>(total));
    put32(file, b + 32, static_cast<uint32_t>(total));
}

}  // namespace abr::mtkgfh
