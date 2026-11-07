// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/mtkimg.hpp"

#include <algorithm>
#include <cstring>
#include <map>

namespace abr::mtkimg {

namespace {

uint32_t le32(const Bytes& d, size_t at) {
    return uint32_t{d[at]} | (uint32_t{d[at + 1]} << 8) | (uint32_t{d[at + 2]} << 16) | (uint32_t{d[at + 3]} << 24);
}

void put32(Bytes& out, size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) out[at + i] = static_cast<uint8_t>(v >> (8 * i));
}

constexpr size_t kMaxSections = 4096;
constexpr uint32_t kMaxPictures = 4096;

// Where the next header may be, behind data that ends at `end`: the next multiple of the alignment the header names, then of the ones that
// are in use (16 is the one the loader says it is where nobody says). The alignment that found it is in `align`.
std::optional<size_t> find_next(const Bytes& d, size_t end, uint32_t& align) {
    std::vector<uint32_t> tries{align, 16, 4, 8, 32, 64, 128, 256, 512, 1024, 4096};
    for (size_t i = 0; i < tries.size(); ++i) {
        const uint32_t a = tries[i];
        if (a == 0 || std::find(tries.begin(), tries.begin() + i, a) != tries.begin() + i) continue;
        const size_t next = end + pad_length(end, a);
        if (next < d.size() && looks_like(d, next)) {
            align = a;
            return next;
        }
    }
    return std::nullopt;
}

}  // namespace

// ------------------------------------------------------------------------------------------------------------------------ header --

std::string Header::name_text() const {
    size_t n = 0;
    while (n < name.size() && name[n]) ++n;
    return std::string(reinterpret_cast<const char*>(name.data()), n);
}

Bytes Header::name_tail() const {
    size_t n = 0;
    while (n < name.size() && name[n]) ++n;
    if (n < name.size()) ++n;  // the zero itself
    Bytes tail(name.begin() + n, name.end());
    if (std::all_of(tail.begin(), tail.end(), [](uint8_t b) { return b == 0; })) tail.clear();
    return tail;
}

void Header::set_name(std::string_view text, const Bytes& tail) {
    if (text.size() >= name.size()) throw FormatError("mtk: the name " + std::string(text) + " is longer than the 31 characters of a header");
    name.fill(0);
    std::memcpy(name.data(), text.data(), text.size());
    const size_t room = name.size() - text.size() - 1;
    if (tail.size() > room) throw FormatError("mtk: the bytes behind the name do not fit in the 32 bytes of its field");
    if (!tail.empty()) std::memcpy(name.data() + text.size() + 1, tail.data(), tail.size());
}

uint32_t Header::alignment() const {
    if (extended() && align_size >= 4 && align_size <= 65536 && (align_size & (align_size - 1)) == 0) return align_size;
    return 16;
}

Header Header::fresh(std::string_view name) {
    Header h;
    h.set_name(name);
    h.ext_magic = kExtMagic;
    h.hdr_size = kHeaderSize;
    h.hdr_version = 0;
    h.img_type = 0;
    h.img_list_end = 1;
    h.align_size = 16;
    h.dsize_extend = 0;
    h.maddr_extend = 0;
    return h;
}

Header parse_header(const Bytes& d, size_t at) {
    if (at > d.size() || d.size() - at < kHeaderSize) throw FormatError("mtk: cut short in a header (" + std::to_string(at > d.size() ? 0 : d.size() - at) + " bytes of the 512)");
    if (le32(d, at) != kMagic) throw FormatError("mtk: no header at offset " + std::to_string(at) + " (its magic is not 0x58881688)");
    Header h;
    h.dsize = le32(d, at + 4);
    std::copy(d.begin() + at + 8, d.begin() + at + 40, h.name.begin());
    h.maddr = le32(d, at + 40);
    h.mode = le32(d, at + 44);
    h.ext_magic = le32(d, at + 48);
    h.hdr_size = le32(d, at + 52);
    h.hdr_version = le32(d, at + 56);
    h.img_type = le32(d, at + 60);
    h.img_list_end = le32(d, at + 64);
    h.align_size = le32(d, at + 68);
    h.dsize_extend = le32(d, at + 72);
    h.maddr_extend = le32(d, at + 76);
    h.reserved.assign(d.begin() + at + 80, d.begin() + at + kHeaderSize);
    return h;
}

Bytes serialize_header(const Header& h) {
    Bytes out(kHeaderSize, 0xFF);
    put32(out, 0, kMagic);
    put32(out, 4, h.dsize);
    std::copy(h.name.begin(), h.name.end(), out.begin() + 8);
    put32(out, 40, h.maddr);
    put32(out, 44, h.mode);
    put32(out, 48, h.ext_magic);
    put32(out, 52, h.hdr_size);
    put32(out, 56, h.hdr_version);
    put32(out, 60, h.img_type);
    put32(out, 64, h.img_list_end);
    put32(out, 68, h.align_size);
    put32(out, 72, h.dsize_extend);
    put32(out, 76, h.maddr_extend);
    if (h.reserved.size() != kHeaderSize - 80) throw FormatError("mtk: the reserved bytes of a header are not 432");
    std::copy(h.reserved.begin(), h.reserved.end(), out.begin() + 80);
    return out;
}

bool looks_like(const Bytes& d, size_t at) {
    if (at > d.size() || d.size() - at < kHeaderSize || le32(d, at) != kMagic) return false;
    const Header h = parse_header(d, at);
    size_t n = 0;
    while (n < h.name.size() && h.name[n]) {
        if (h.name[n] < 0x20 || h.name[n] > 0x7e) return false;
        ++n;
    }
    if (n == 0 || n == h.name.size()) return false;  // no name, or no zero that ends it
    if (h.extended() && h.hdr_size != kHeaderSize) return false;
    return h.data_size() <= d.size() - at - kHeaderSize;
}

size_t pad_length(uint64_t end, uint32_t align) {
    if (align <= 1) return 0;
    return static_cast<size_t>((align - end % align) % align);
}

// ------------------------------------------------------------------------------------------------------------------------- chain --

Chain parse(const Bytes& d) {
    if (!looks_like(d, 0)) {
        if (d.size() >= 4 && le32(d, 0) == kMagic && d.size() >= kHeaderSize) {
            const Header h = parse_header(d, 0);
            if (h.extended() && h.hdr_size != kHeaderSize)
                throw FormatError("mtk: the header says it is " + std::to_string(h.hdr_size) + " bytes; abr knows the one of 512");
            if (h.data_size() > d.size() - kHeaderSize)
                throw FormatError("mtk: the header says " + std::to_string(h.data_size()) + " bytes of data and the file has " + std::to_string(d.size() - kHeaderSize) +
                                  " behind it: the image is cut short");
        }
        throw FormatError("mtk: the file does not begin with a section (the header of 512 bytes, its magic 0x58881688, a name)");
    }
    Chain chain;
    size_t at = 0;
    for (;;) {
        if (chain.sections.size() >= kMaxSections) throw FormatError("mtk: more than " + std::to_string(kMaxSections) + " sections");
        Section s;
        s.header = parse_header(d, at);
        const uint64_t size = s.header.data_size();
        const size_t data_at = at + kHeaderSize;
        if (size > d.size() - data_at)
            throw FormatError("mtk: the section " + s.header.name_text() + " says " + std::to_string(size) + " bytes of data and the file has " +
                              std::to_string(d.size() - data_at) + " behind its header: the image is cut short");
        s.data.assign(d.begin() + data_at, d.begin() + data_at + size);
        const size_t end = data_at + size;
        s.align = s.header.alignment();
        chain.consumed = end;
        std::optional<size_t> next;
        if (!(s.header.extended() && s.header.img_list_end == 1)) next = find_next(d, end, s.align);
        if (next) s.pad.assign(d.begin() + end, d.begin() + *next);
        chain.sections.push_back(std::move(s));
        if (!next) break;
        at = *next;
    }
    return chain;
}

Bytes build(const Chain& chain) {
    Bytes out;
    size_t total = 0;
    for (const Section& s : chain.sections) total += kHeaderSize + s.data.size() + s.pad.size();
    out.reserve(total);
    for (const Section& s : chain.sections) {
        Header h = s.header;
        const uint64_t size = s.data.size();
        h.dsize = static_cast<uint32_t>(size);
        if (h.extended()) {
            if ((size >> 32) != 0 || h.dsize_extend != kAny) h.dsize_extend = static_cast<uint32_t>(size >> 32);
        } else if ((size >> 32) != 0) {
            throw FormatError("mtk: the data of the section " + h.name_text() + " is " + std::to_string(size) +
                              " bytes, which a header without the extension cannot say (4 GiB at most)");
        }
        const Bytes head = serialize_header(h);
        out.insert(out.end(), head.begin(), head.end());
        out.insert(out.end(), s.data.begin(), s.data.end());
        out.insert(out.end(), s.pad.begin(), s.pad.end());
    }
    return out;
}

// ------------------------------------------------------------------------------------------------------------------ the logo table --

std::optional<Logo> parse_logo(const Bytes& data) {
    if (data.size() < 12) return std::nullopt;
    const uint32_t count = le32(data, 0);
    if (count == 0 || count > kMaxPictures) return std::nullopt;
    const uint64_t table_end = 8 + uint64_t{count} * 4;
    if (table_end > data.size() || le32(data, 4) != data.size()) return std::nullopt;
    std::vector<uint32_t> offsets(count);
    for (uint32_t i = 0; i < count; ++i) offsets[i] = le32(data, 8 + size_t{i} * 4);
    if (offsets[0] != table_end) return std::nullopt;
    for (uint32_t i = 0; i < count; ++i) {
        const uint64_t next = i + 1 < count ? offsets[i + 1] : data.size();
        if (offsets[i] > next || next > data.size()) return std::nullopt;
    }
    Logo logo;
    logo.pictures.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        const size_t next = i + 1 < count ? offsets[i + 1] : data.size();
        logo.pictures.emplace_back(data.begin() + offsets[i], data.begin() + next);
    }
    return logo;
}

Bytes build_logo(const std::vector<Bytes>& pictures) {
    if (pictures.empty() || pictures.size() > kMaxPictures) throw FormatError("mtk: a logo table has 1 to " + std::to_string(kMaxPictures) + " pictures");
    size_t total = 8 + pictures.size() * 4;
    for (const Bytes& p : pictures) total += p.size();
    if (total > 0xFFFFFFFFull) throw FormatError("mtk: the pictures are more than 4 GiB");
    Bytes out(8 + pictures.size() * 4);
    put32(out, 0, static_cast<uint32_t>(pictures.size()));
    put32(out, 4, static_cast<uint32_t>(total));
    size_t at = out.size();
    for (size_t i = 0; i < pictures.size(); ++i) {
        put32(out, 8 + i * 4, static_cast<uint32_t>(at));
        at += pictures[i].size();
    }
    out.reserve(total);
    for (const Bytes& p : pictures) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// -------------------------------------------------------------------------------------------------------------------------- pixels --

std::string_view format_name(PixelFormat f) {
    switch (f) {
        case PixelFormat::BGRA8888: return "bgra8888";
        case PixelFormat::RGBA8888: return "rgba8888";
        case PixelFormat::RGB565: return "rgb565";
        case PixelFormat::BGR888: return "bgr888";
        case PixelFormat::RGB888: return "rgb888";
    }
    return "bgra8888";
}

std::optional<PixelFormat> format_from_name(std::string_view name) {
    for (const PixelFormat f : {PixelFormat::BGRA8888, PixelFormat::RGBA8888, PixelFormat::RGB565, PixelFormat::BGR888, PixelFormat::RGB888})
        if (format_name(f) == name) return f;
    return std::nullopt;
}

size_t bytes_per_pixel(PixelFormat f) {
    switch (f) {
        case PixelFormat::BGRA8888:
        case PixelFormat::RGBA8888: return 4;
        case PixelFormat::RGB565: return 2;
        default: return 3;
    }
}

namespace {

// The sizes that the pictures of a logo.bin are known to have, width and height. A picture does not say how wide it is, so what is known is its
// area, and the guess is the first entry of the table with that area. The table is that of github.com/blackeangel/mtklogorepacker (which was
// made from the logos of phones), with a few sizes of screens added to it.
const Resolution kResolutions[] = {
    // Sizes that have the area of an entry further down and are the likelier of the two on a phone or a tablet of MediaTek (the first of an area is taken).
    {720, 1440}, {600, 1024}, {1440, 3200},
    // The table of mtklogorepacker, widths first here (that tool has the height first), in its order, without the entries that no picture can reach.
    {102, 1}, {135, 1}, {163, 1}, {169, 1}, {304, 1}, {79, 2}, {138, 20}, {135, 24},
    {152, 24}, {15, 27}, {30, 27}, {169, 28}, {163, 29}, {23, 32}, {34, 32}, {27, 36},
    {32, 36}, {28, 40}, {32, 40}, {36, 51}, {218, 51}, {304, 52}, {38, 54}, {48, 54},
    {45, 64}, {32, 105}, {63, 105}, {84, 121}, {108, 121}, {72, 128}, {45, 139}, {120, 160},
    {286, 214}, {160, 240}, {680, 250}, {2, 263}, {47, 263}, {240, 320}, {240, 360}, {640, 360},
    {240, 376}, {240, 384}, {240, 400}, {240, 428}, {240, 432}, {197, 445}, {270, 480}, {272, 480},
    {320, 480}, {360, 480}, {320, 570}, {384, 640}, {480, 640}, {480, 720}, {480, 768}, {480, 800},
    {600, 800}, {2560, 800}, {480, 848}, {480, 852}, {480, 853}, {480, 854}, {480, 856}, {540, 960},
    {576, 1024}, {768, 1024}, {768, 1152}, {720, 1280}, {768, 1280}, {800, 1280}, {768, 1360}, {768, 1366},
    {864, 1152}, {870, 1152}, {832, 1120}, {960, 1280}, {1024, 1280}, {1050, 1400}, {900, 1440}, {960, 1440},
    {720, 1600}, {900, 1600}, {1200, 1600}, {720, 1640}, {1050, 1680}, {1080, 1920}, {1200, 1920}, {1152, 2048},
    {1536, 2048}, {1080, 2400}, {1080, 2408}, {1440, 2560}, {1600, 2560}, {2048, 2560}, {1800, 3200}, {2048, 3200},
    {2400, 3200}, {2160, 3840}, {2400, 3840}, {2160, 4096}, {3072, 4096}, {2880, 5120}, {3200, 5120}, {4096, 5120},
    {4096, 6400}, {4800, 6400}, {4320, 7680}, {4800, 7680}, {8640, 15360},
    // Sizes of screens that came later, portrait.
    {720, 1520}, {720, 1560}, {1080, 2160}, {1080, 2280}, {1080, 2340}, {1080, 2412}, {1080, 2460}, {1200, 2000},
    {1200, 2640}, {1440, 2960}, {1440, 3040}, {1440, 3120}, {1440, 3216},
};

const std::map<uint64_t, Resolution>& resolution_by_area() {
    static const std::map<uint64_t, Resolution> table = [] {
        std::map<uint64_t, Resolution> t;
        for (const Resolution& r : kResolutions) t.emplace(uint64_t{r.width} * r.height, r);  // (emplace keeps the first of an area)
        return t;
    }();
    return table;
}

}  // namespace

std::optional<Resolution> guess_resolution(uint64_t pixels) {
    const auto& t = resolution_by_area();
    const auto it = t.find(pixels);
    if (it == t.end()) return std::nullopt;
    return it->second;
}

PixelFormat guess_format(const std::vector<size_t>& sizes) {
    static const std::pair<PixelFormat, size_t> candidates[] = {{PixelFormat::BGRA8888, 4}, {PixelFormat::RGB565, 2}, {PixelFormat::BGR888, 3}};
    PixelFormat best = PixelFormat::BGRA8888;
    size_t best_score = 0;
    for (const auto& [format, bpp] : candidates) {
        size_t score = 0;
        for (const size_t s : sizes)
            if (s != 0 && s % bpp == 0 && guess_resolution(s / bpp)) ++score;
        if (score > best_score) best_score = score, best = format;
    }
    return best;
}

Bytes pixels_to_rgba(PixelFormat f, const Bytes& raw, uint32_t width, uint32_t height) {
    const size_t n = size_t{width} * height;
    if (raw.size() != n * bytes_per_pixel(f)) throw FormatError("mtk: " + std::to_string(raw.size()) + " bytes are not " + std::to_string(width) + "x" + std::to_string(height) + " pixels of " + std::string(format_name(f)));
    Bytes out(n * 4);
    for (size_t i = 0; i < n; ++i) {
        uint8_t* o = &out[4 * i];
        switch (f) {
            case PixelFormat::BGRA8888: o[0] = raw[4 * i + 2], o[1] = raw[4 * i + 1], o[2] = raw[4 * i], o[3] = raw[4 * i + 3]; break;
            case PixelFormat::RGBA8888: std::memcpy(o, &raw[4 * i], 4); break;
            case PixelFormat::RGB565: {
                const unsigned v = raw[2 * i] | (raw[2 * i + 1] << 8);
                const unsigned r = v >> 11, g = (v >> 5) & 63, b = v & 31;
                o[0] = static_cast<uint8_t>((r << 3) | (r >> 2));
                o[1] = static_cast<uint8_t>((g << 2) | (g >> 4));
                o[2] = static_cast<uint8_t>((b << 3) | (b >> 2));
                o[3] = 255;
                break;
            }
            case PixelFormat::BGR888: o[0] = raw[3 * i + 2], o[1] = raw[3 * i + 1], o[2] = raw[3 * i], o[3] = 255; break;
            case PixelFormat::RGB888: o[0] = raw[3 * i], o[1] = raw[3 * i + 1], o[2] = raw[3 * i + 2], o[3] = 255; break;
        }
    }
    return out;
}

Bytes rgba_to_pixels(PixelFormat f, const Bytes& rgba, uint32_t width, uint32_t height, bool with_alpha, uint8_t alpha) {
    const size_t n = size_t{width} * height;
    if (rgba.size() != n * 4) throw FormatError("mtk: the pixels are not width * height * 4 bytes");
    Bytes out(n * bytes_per_pixel(f));
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* p = &rgba[4 * i];
        const uint8_t a = with_alpha ? p[3] : alpha;
        switch (f) {
            case PixelFormat::BGRA8888: out[4 * i] = p[2], out[4 * i + 1] = p[1], out[4 * i + 2] = p[0], out[4 * i + 3] = a; break;
            case PixelFormat::RGBA8888: out[4 * i] = p[0], out[4 * i + 1] = p[1], out[4 * i + 2] = p[2], out[4 * i + 3] = a; break;
            case PixelFormat::RGB565: {
                const unsigned v = ((p[0] >> 3) << 11) | ((p[1] >> 2) << 5) | (p[2] >> 3);
                out[2 * i] = static_cast<uint8_t>(v), out[2 * i + 1] = static_cast<uint8_t>(v >> 8);
                break;
            }
            case PixelFormat::BGR888: out[3 * i] = p[2], out[3 * i + 1] = p[1], out[3 * i + 2] = p[0]; break;
            case PixelFormat::RGB888: out[3 * i] = p[0], out[3 * i + 1] = p[1], out[3 * i + 2] = p[2]; break;
        }
    }
    return out;
}

std::optional<uint8_t> constant_alpha(PixelFormat f, const Bytes& raw) {
    if (f != PixelFormat::BGRA8888 && f != PixelFormat::RGBA8888) return std::nullopt;
    if (raw.size() < 4) return std::nullopt;
    const uint8_t a = raw[3];
    for (size_t i = 3; i < raw.size(); i += 4)
        if (raw[i] != a) return std::nullopt;
    return a;
}

}  // namespace abr::mtkimg
