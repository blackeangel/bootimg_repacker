// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr::legacy's Sony SIN reader (include/abr/legacy/sin.hpp) and of the Sony ELF boot image
// (include/abr/legacy/elf_boot.hpp). Run by tests/run_tests.sh as `abr_unit_tests legacy`.
//
//   SIN   * the signature (01 00 00 00, 02 00 00 00, "\x03SIN") and nothing near it;
//         * the three headers, what follows them -- the image, a loader, data in front of the image, MMCF with ADDR and
//           LZ4A parts (gaps filled with 0xFF, a part that starts too early put at the end, entries longer than their
//           fields) -- and the image that comes out;
//         * every size checked against the file: what sony_dump would go on with (an entry shorter than its fields, a
//           part past the end, an LZ4 block that decodes to less than the entry says ...) is an error with the reason;
//         * extract_sin() itself refuses an image beyond kSinMaxPayload (before it allocates it);
//         * the parts of a large container are decoded on one thread and on four with the same result;
//         * tens of thousands of damaged containers: no crash, no other exception than FormatError, and what is
//           accepted has the size parse_sin() said.
//   ELF   * the layout elftool writes is rebuilt from the fields of the segments (ELF32 and ELF64, addresses beyond
//           32 bits) and is not recorded as a layout;
//         * another layout (the block in front of the data, padding between and behind the segments, an e_entry of its
//           own, the OS/ABI byte, p_align, p_memsz, the order of the data) is kept, comes back as it was, and an
//           edited segment lands in it with the sizes and offsets that follow;
//         * what the kept layout cannot take (another count of segments, data in a segment that had none) falls back
//           to elftool's layout and says why; an address that does not fit an ELF32 header is an error;
//         * tens of thousands of damaged images: no crash, no other exception than FormatError, and a layout that
//           parse() keeps always gives the image back.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/legacy/elf_boot.hpp"
#include "abr/legacy/sin.hpp"
#include "abr/parallel.hpp"

using namespace abr;
using namespace abr::legacy;

namespace {

int g_failures = 0;
int g_checks = 0;

#define EXPECT(cond)                                                      \
    do {                                                                  \
        ++g_checks;                                                       \
        if (!(cond)) {                                                    \
            ++g_failures;                                                 \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                 \
    } while (0)

// f() throws a FormatError that has `text` in its message.
template <class F>
bool refuses(F&& f, const char* text) {
    try {
        f();
    } catch (const FormatError& e) {
        const bool found = std::string(e.what()).find(text) != std::string::npos;
        if (!found) std::printf("    (the message is \"%s\", not one with \"%s\")\n", e.what(), text);
        return found;
    } catch (...) {
        return false;
    }
    return false;
}

Bytes filled(size_t n, uint8_t v) { return Bytes(n, v); }

Bytes pattern(size_t n, uint32_t seed) {
    Bytes b(n);
    uint32_t x = seed * 2654435761u + 12345u;
    for (auto& c : b) {
        x = x * 1664525u + 1013904223u;
        c = static_cast<uint8_t>(x >> 24);
    }
    return b;
}

void put32(Bytes& b, size_t pos, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[pos + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (24 - 8 * i));
}
void add32(Bytes& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (24 - 8 * i)));
}
void add64(Bytes& b, uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>(v >> (56 - 8 * i)));
}
void add(Bytes& b, const Bytes& more) { b.insert(b.end(), more.begin(), more.end()); }
void add(Bytes& b, const char* tag) { b.insert(b.end(), tag, tag + std::strlen(tag)); }

// ---- SIN -----------------------------------------------------------------------------------------------------------

Bytes v3_header(uint32_t psize, uint32_t dsize) {
    Bytes h(psize, 0x5A);
    std::memcpy(h.data(), "\x03SIN", 4);
    put32(h, 4, psize);
    put32(h, 0x18, dsize);
    return h;
}

Bytes v12_header(uint8_t version, uint32_t hsize) {
    Bytes h(hsize + 16u, 0x5A);
    h[0] = version;
    h[1] = h[2] = h[3] = 0;
    put32(h, 2, hsize);  // bytes 2 and 3 stay zero for a size below 64 KiB
    return h;
}

Bytes padded(Bytes b, size_t floor = 1024) {
    if (b.size() < floor) b.resize(floor, 0xEE);
    return b;
}

// An LZ4 block that is all literals: the smallest valid one (the last sequence of a block has no match).
Bytes lz4_literals(const Bytes& d) {
    Bytes out;
    const size_t n = d.size();
    out.push_back(static_cast<uint8_t>(std::min<size_t>(n, 15) << 4));
    if (n >= 15) {
        size_t r = n - 15;
        while (r >= 255) {
            out.push_back(255);
            r -= 255;
        }
        out.push_back(static_cast<uint8_t>(r));
    }
    add(out, d);
    return out;
}

struct Part {
    bool lz4 = false;
    Bytes data;
    std::optional<uint64_t> offset;  // where the part goes in the image (default: where the image has got to)
    uint32_t extra = 0;              // bytes added to the entry
    int64_t size_error = 0;          // added to the unpacked size an LZ4A entry says
};

// A container with an MMCF block; `image` receives what a converter should write.
Bytes mmcf_container(int version, const std::vector<Part>& parts, Bytes* image = nullptr, uint32_t header = 0x400) {
    Bytes data_region, entries, img;
    uint64_t end = 0;  // how far the image has got (it is only made when somebody asks for it: it can be huge)
    for (const Part& p : parts) {
        const Bytes blob = p.lz4 ? lz4_literals(p.data) : p.data;
        const uint64_t packed_off = data_region.size();
        add(data_region, blob);
        const uint64_t uoff = p.offset ? *p.offset : end;
        if (image) {
            if (img.size() < uoff) img.resize(uoff, 0xFF);
            add(img, p.data);
        }
        end = std::max<uint64_t>(end, uoff) + p.data.size();
        if (p.lz4) {
            add(entries, "LZ4A");
            add32(entries, 40 + p.extra);
            add64(entries, packed_off);
            add64(entries, static_cast<uint64_t>(static_cast<int64_t>(p.data.size()) + p.size_error));
            add64(entries, blob.size());
            add64(entries, uoff);
        } else {
            add(entries, "ADDR");
            add32(entries, 32 + p.extra);
            add64(entries, packed_off);
            add64(entries, blob.size());
            add64(entries, uoff);
        }
        add(entries, filled(p.extra, 0x77));
    }
    Bytes gptp;
    add(gptp, "GPTP");
    add32(gptp, static_cast<uint32_t>(24 + entries.size()));
    add(gptp, pattern(16, 99));
    Bytes block;
    add(block, "MMCF");
    add32(block, static_cast<uint32_t>(gptp.size() + entries.size()));
    add(block, gptp);
    add(block, entries);
    Bytes out;
    if (version < 3) {
        out = v12_header(static_cast<uint8_t>(version), header - 16);
    } else {
        out = v3_header(header, 1);
    }
    add(out, block);
    add(out, data_region);
    out = padded(out);
    if (version >= 3) put32(out, 0x18, static_cast<uint32_t>(out.size() - header));
    if (image) *image = img;
    return out;
}

void test_signature() {
    auto sig = [](std::initializer_list<uint8_t> b) { return has_sin_header(Bytes(b)); };
    EXPECT(sig({0x01, 0, 0, 0}));
    EXPECT(sig({0x02, 0, 0, 0}));
    EXPECT(sig({0x03, 'S', 'I', 'N'}));
    EXPECT(!sig({0x01, 0, 0, 1}));
    EXPECT(!sig({0x02, 0, 1, 0}));
    EXPECT(!sig({0x01, 1, 0, 0}));
    EXPECT(!sig({0x03, 'S', 'I', 'M'}));
    EXPECT(!sig({0x04, 'S', 'I', 'N'}));
    EXPECT(!sig({0x00, 0, 0, 0}));
    EXPECT(!sig({0x03, 'S', 'I'}));
    EXPECT(!has_sin_header(Bytes()));
}

void test_sin_plain() {
    const Bytes payload = pattern(3000, 1);
    // v3: the image behind the header
    Bytes c = v3_header(0x400, static_cast<uint32_t>(payload.size()));
    add(c, payload);
    SinInfo s = parse_sin(c);
    EXPECT(s.version == 3 && !s.mmcf && !s.loader && s.header_size == 0x400 && s.payload_offset == 0x400 && s.payload_size == 3000);
    EXPECT(extract_sin(c, s) == payload);
    EXPECT(describe_sin(s).find("Sony SIN v3") == 0 && describe_sin(s).find("image 3000 bytes") != std::string::npos);
    // v3: data in front of the image, which the size at 0x18 counts
    c = v3_header(0x400, 700);
    add(c, filled(700, 0x44));
    add(c, payload);
    s = parse_sin(c);
    EXPECT(s.payload_offset == 0x400 + 700 && s.payload_size == payload.size() && extract_sin(c, s) == payload);
    EXPECT(describe_sin(s).find("700 bytes of data in front of the image") != std::string::npos);
    // v1 and v2: header = H + 16 bytes, the rest is the image
    for (uint8_t v : {1, 2}) {
        c = v12_header(v, 0x3F0);
        add(c, payload);
        s = parse_sin(c);
        EXPECT(s.version == v && s.header_size == 0x400 && s.payload_size == payload.size() && extract_sin(c, s) == payload);
    }
    // the smallest file is 1024 bytes
    for (uint32_t room : {31u, 32u}) {
        c = v3_header(0x3E0, room);
        add(c, filled(room, 0x11));
        if (c.size() == 1023) {
            EXPECT(refuses([&] { parse_sin(c); }, "at least 1024"));
        } else {
            s = parse_sin(c);
            EXPECT(c.size() == 1024 && s.payload_size == 32 && extract_sin(c, s) == filled(32, 0x11));
        }
    }
    // v1 and v2: a header of H + 16 bytes that is the whole file leaves nothing to convert, one byte less leaves one
    c = padded(v12_header(1, 1008));
    EXPECT(c.size() == 1024);
    EXPECT(refuses([&] { parse_sin(c); }, "leaves no room for data"));
    c = v12_header(1, 1007);
    c.push_back(0x66);
    s = parse_sin(c);
    EXPECT(s.payload_size == 1 && extract_sin(c, s) == Bytes{0x66});
    EXPECT(refuses([&] { parse_sin(padded(v12_header(2, 0))); }, "the size of the header is 0"));
    // a loader: an ELF behind the header; the size must be what is left
    Bytes elf(2000, 0x33);
    std::memcpy(elf.data(), "\x7f" "ELF", 4);
    c = v3_header(0x420, static_cast<uint32_t>(elf.size()));
    add(c, elf);
    s = parse_sin(c);
    EXPECT(s.loader && s.payload_size == elf.size() && extract_sin(c, s) == elf);
    put32(c, 0x18, static_cast<uint32_t>(elf.size() - 1));
    EXPECT(refuses([&] { parse_sin(c); }, "does not fit the file"));
}

void test_sin_mmcf() {
    Bytes image;
    // ADDR, a gap of 0xFF, ADDR, LZ4A at the end of what there is
    std::vector<Part> parts(3);
    parts[0].data = filled(1000, 0x11);
    parts[1].data = filled(500, 0x22);
    parts[1].offset = 2000;
    parts[2].lz4 = true;
    parts[2].data = pattern(700, 3);
    Bytes c = mmcf_container(3, parts, &image);
    SinInfo s = parse_sin(c);
    EXPECT(s.mmcf && s.parts.size() == 3 && s.notes.empty() && s.payload_size == image.size());
    EXPECT(extract_sin(c, s) == image);
    EXPECT(image[1000] == 0xFF && image[1999] == 0xFF && image[2000] == 0x22);
    EXPECT(describe_sin(s).find("MMCF (3 parts: 2 ADDR, 1 LZ4A; GPTP") != std::string::npos);
    {
        const Bytes uuid = pattern(16, 99);  // what mmcf_container() puts in the GPTP block
        EXPECT(std::equal(uuid.begin(), uuid.end(), s.gptp_uuid.begin()));
        char text[40];
        std::snprintf(text, sizeof text, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", uuid[0], uuid[1],
                      uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12],
                      uuid[13], uuid[14], uuid[15]);
        EXPECT(describe_sin(s).find(std::string("GPTP ") + text + ")") != std::string::npos);
    }
    // v1 and v2 containers
    for (int v : {1, 2}) {
        c = mmcf_container(v, parts, &image, 0x410);
        s = parse_sin(c);
        EXPECT(s.version == v && s.header_size == 0x410 && extract_sin(c, s) == image);
    }
    // a part that starts before the end of the image is put at the end, and the note says so
    parts[1].offset = 0;
    c = mmcf_container(3, parts, nullptr);
    Bytes expect_image = parts[0].data;
    add(expect_image, parts[1].data);
    add(expect_image, parts[2].data);
    s = parse_sin(c);
    EXPECT(s.notes.size() == 1 && s.notes[0].find("it is put at the end") != std::string::npos);
    EXPECT(s.parts[1].out_offset == 1000 && extract_sin(c, s) == expect_image);
    // entries longer than their fields, the next one is where the entry size says
    parts[1].offset = std::nullopt;
    parts[0].extra = 13;
    parts[1].extra = 1;
    parts[2].extra = 24;
    c = mmcf_container(3, parts, &image);
    s = parse_sin(c);
    EXPECT(extract_sin(c, s) == image && s.parts[0].entry_size == 32 + 13);
    // an empty ADDR part is a part
    parts[1].data.clear();
    c = mmcf_container(3, parts, &image);
    s = parse_sin(c);
    EXPECT(s.parts.size() == 3 && extract_sin(c, s) == image);
}

void test_sin_refusals() {
    std::vector<Part> two(2);
    two[0].data = pattern(900, 5);
    two[1].lz4 = true;
    two[1].data = pattern(900, 6);
    const Bytes good = mmcf_container(3, two);
    EXPECT(parse_sin(good).parts.size() == 2);
    const size_t entries = 0x400 + 8 + 24;  // the first entry
    auto patched32 = [&](size_t pos, uint32_t v) {
        Bytes c = good;
        put32(c, pos, v);
        return c;
    };
    EXPECT(refuses([&] { parse_sin(Bytes(good.begin(), good.begin() + 1000)); }, "at least 1024"));
    EXPECT(refuses([&] { parse_sin(Bytes{1, 2, 3, 4}); }, "does not start like one"));
    EXPECT(refuses([&] { parse_sin(patched32(0x404, 0)); }, "MMCF block is empty"));
    EXPECT(refuses([&] { parse_sin(patched32(0x404, 10)); }, "less than its 24-byte GPTP block"));
    EXPECT(refuses([&] { parse_sin(patched32(0x404, 0x7FFFFFFF)); }, "MMCF block (2147483647 bytes at 0x408) is out of the file"));
    EXPECT(refuses([&] { parse_sin(patched32(0x404, 24)); }, "has no parts"));
    EXPECT(refuses([&] { parse_sin(patched32(entries, 0x58595A57)); }, "unknown type 58 59 5a 57"));
    EXPECT(refuses([&] { parse_sin(patched32(entries + 4, 8)); }, "shorter than the 32 bytes of its fields"));
    EXPECT(refuses([&] { parse_sin(patched32(entries + 4, 0)); }, "shorter than"));
    EXPECT(refuses([&] { parse_sin(patched32(0x4, 0)); }, "the size of the header or of the data is 0"));
    EXPECT(refuses([&] { parse_sin(patched32(0x4, static_cast<uint32_t>(good.size() + 1))); }, "the header is"));
    // the data of a part past the end of the file
    {
        Bytes c = good;
        for (int i = 0; i < 8; ++i) c[entries + 8 + static_cast<size_t>(i)] = i < 4 ? 0 : 0xFF;  // packed offset 0xFFFFFF
        EXPECT(refuses([&] { parse_sin(c); }, "its data ("));
    }
    // nothing in any part: there is no image
    {
        std::vector<Part> p(1);
        EXPECT(refuses([&] { parse_sin(mmcf_container(3, p)); }, "every part of the MMCF block is empty"));
    }
    // the LZ4 sizes: more than LZ4 can hold, and a part that holds nothing
    {
        Bytes c = good;
        put32(c, 0x440 + 16 + 4, 0x80000000u);  // the unpacked size of the second entry (an LZ4A one)
        EXPECT(refuses([&] { parse_sin(c); }, "beyond what LZ4 can hold"));
        std::vector<Part> p = two;
        p[1].data.clear();
        c = mmcf_container(3, p);
        EXPECT(refuses([&] { parse_sin(c); }, "an LZ4 part with no data"));
    }
    // an entry that the MMCF block says is there and the file ends in
    {
        Bytes c = v3_header(0x400, 1);
        add(c, "MMCF");
        add32(c, 24 + 20);
        add(c, "GPTP");
        add32(c, 24);
        add(c, pattern(16, 1));
        add(c, "ADDR");
        add32(c, 32);
        add(c, filled(12, 0));
        put32(c, 0x18, static_cast<uint32_t>(c.size() - 0x400));
        EXPECT(c.size() == 0x434);
        EXPECT(refuses([&] { parse_sin(c); }, "is cut short"));
    }
    // an LZ4 part that decodes to less than its entry says (the second entry follows the 32 bytes of the first)
    {
        std::vector<Part> p = two;
        p[1].size_error = 7;
        Bytes c = mmcf_container(3, p);
        const SinInfo s = parse_sin(c);
        EXPECT(refuses([&] { extract_sin(c, s); }, "decodes to 900 bytes, the entry says 907"));
        p[1].size_error = -7;
        c = mmcf_container(3, p);
        const SinInfo t = parse_sin(c);
        EXPECT(refuses([&] { extract_sin(c, t); }, "the LZ4 block is damaged"));
    }
    // extract_sin() has a limit of its own: an image beyond it is not allocated
    {
        std::vector<Part> p(2);
        p[0].data = pattern(300, 7);
        p[1].data = pattern(300, 8);
        p[1].offset = kSinMaxPayload + 4096;
        const Bytes c = mmcf_container(3, p);
        const SinInfo s = parse_sin(c);
        EXPECT(s.payload_size > kSinMaxPayload);
        EXPECT(refuses([&] { extract_sin(c, s); }, "more than the"));
    }
}

void test_sin_threads() {
    // two LZ4A parts that are 18 MiB together: decoded on several threads once there is that much
    std::vector<Part> p(2);
    for (int i = 0; i < 2; ++i) {
        p[static_cast<size_t>(i)].lz4 = true;
        p[static_cast<size_t>(i)].data = pattern(9u << 20, 10 + static_cast<uint32_t>(i));
    }
    Bytes image;
    const Bytes c = mmcf_container(3, p, &image);
    const SinInfo s = parse_sin(c);
    const unsigned before = par::max_threads();
    par::set_max_threads(1);
    const Bytes one = extract_sin(c, s);
    par::set_max_threads(4);
    const Bytes four = extract_sin(c, s);
    par::set_max_threads(before);
    EXPECT(one == image);
    EXPECT(four == image);
}

void test_sin_fuzz() {
    std::vector<Part> mixed(3);
    mixed[0].data = pattern(700, 21);
    mixed[1].lz4 = true;
    mixed[1].data = pattern(900, 22);
    mixed[2].data = pattern(300, 23);
    mixed[2].offset = 5000;
    std::vector<Bytes> bases;
    bases.push_back(mmcf_container(3, mixed));
    bases.push_back(mmcf_container(1, mixed, nullptr, 0x420));
    {
        Bytes c = v3_header(0x400, 600);
        add(c, filled(600, 1));
        add(c, pattern(2000, 24));
        bases.push_back(c);
    }
    {
        Bytes c = v12_header(2, 0x3F0);
        add(c, pattern(2000, 25));
        bases.push_back(c);
    }
    std::mt19937 rng(20261018);
    size_t accepted = 0, refused = 0;
    for (int i = 0; i < 40000; ++i) {
        Bytes c = bases[rng() % bases.size()];
        const int edits = 1 + static_cast<int>(rng() % 3);
        for (int e = 0; e < edits; ++e) {
            const size_t span = std::min<size_t>(c.size(), 1300);
            const size_t pos = rng() % span;
            switch (rng() % 4) {
                case 0: c[pos] = static_cast<uint8_t>(rng()); break;
                case 1: c[pos] ^= static_cast<uint8_t>(1u << (rng() % 8)); break;
                case 2: c[pos] = 0xFF; break;
                default: c[pos] = 0; break;
            }
        }
        if (rng() % 10 == 0) c.resize(rng() % c.size());
        try {
            const SinInfo s = parse_sin(c);
            if (s.payload_size <= (8u << 20)) {
                const Bytes out = extract_sin(c, s);
                EXPECT(out.size() == s.payload_size);
            }
            ++accepted;
        } catch (const FormatError&) {
            ++refused;
        } catch (...) {
            EXPECT(!"an exception that is not a FormatError");
        }
    }
    std::printf("    %zu damaged containers accepted, %zu refused\n", accepted, refused);
    EXPECT(accepted > 1000 && refused > 1000);  // (the mutations do reach both)
}

// ---- ELF boot images ------------------------------------------------------------------------------------------------

// An image the way elf_tool.py writes one (tests/tools/elf_tool.py), for the layouts that are not elftool's.
struct ElfSpec {
    bool is64 = false;
    uint32_t start = 4096;
    std::vector<uint32_t> pads;  // between the data of the segments in file order
    uint8_t pad_fill = 0;
    Bytes tail;
    std::optional<uint64_t> entry;
    uint8_t osabi = 0x61;
    uint64_t align = 0;
    std::vector<uint64_t> memsz_extra;  // per segment
    std::vector<uint32_t> file_order;
    uint8_t hdr_fill = 0;
    uint16_t machine = 40;
    std::vector<uint64_t> paddr_abs;  // per segment: p_paddr (0: the same as p_vaddr, as elftool writes it)
    std::vector<uint64_t> memsz_abs;  // per segment: p_memsz (0: the size of the data plus memsz_extra)
};

void le(Bytes& b, uint64_t v, int width) {
    for (int i = 0; i < width; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void put_le(Bytes& b, size_t pos, uint64_t v, int width) {
    for (int i = 0; i < width; ++i) b[pos + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}

Bytes elf_make(const std::vector<ElfSegment>& segs, const ElfSpec& sp) {
    const size_t n = segs.size();
    const int aw = sp.is64 ? 8 : 4;
    const size_t ehsize = sp.is64 ? 64 : 52, phentsize = sp.is64 ? 56 : 32;
    std::vector<uint32_t> order = sp.file_order;
    if (order.empty())
        for (uint32_t i = 0; i < n; ++i) order.push_back(i);
    std::vector<uint64_t> offset(n);
    uint64_t cursor = sp.start;
    for (size_t k = 0; k < order.size(); ++k) {
        offset[order[k]] = cursor;
        cursor += segs[order[k]].data.size() + (k < sp.pads.size() ? sp.pads[k] : 0);
    }
    Bytes b = {0x7F, 'E', 'L', 'F', static_cast<uint8_t>(sp.is64 ? 2 : 1), 1, 1, sp.osabi};
    b.insert(b.end(), 8, 0);
    le(b, 2, 2);
    le(b, sp.machine, 2);
    le(b, 1, 4);
    le(b, sp.entry ? *sp.entry : segs[0].addr, aw);
    le(b, ehsize, aw);  // e_phoff
    le(b, 0, aw);       // e_shoff
    le(b, 0, 4);        // e_flags
    le(b, ehsize, 2);
    le(b, phentsize, 2);
    le(b, n, 2);
    le(b, 0, 6);
    b.resize(sp.start, sp.hdr_fill);
    for (size_t i = 0; i < n; ++i) {
        const ElfSegment& s = segs[i];
        const uint64_t memsz = i < sp.memsz_abs.size() && sp.memsz_abs[i]
                                   ? sp.memsz_abs[i]
                                   : s.data.size() + (i < sp.memsz_extra.size() ? sp.memsz_extra[i] : 0);
        const uint64_t paddr = i < sp.paddr_abs.size() && sp.paddr_abs[i] ? sp.paddr_abs[i] : s.addr;
        const uint32_t type = s.role == "cmdline" ? 4 : 1;
        Bytes ph;
        if (sp.is64) {
            le(ph, type, 4);
            le(ph, s.flags, 4);
            le(ph, offset[i], 8);
            le(ph, s.addr, 8);
            le(ph, paddr, 8);
            le(ph, s.data.size(), 8);
            le(ph, memsz, 8);
            le(ph, sp.align, 8);
        } else {
            le(ph, type, 4);
            le(ph, offset[i], 4);
            le(ph, s.addr, 4);
            le(ph, paddr, 4);
            le(ph, s.data.size(), 4);
            le(ph, memsz, 4);
            le(ph, s.flags, 4);
            le(ph, sp.align, 4);
        }
        std::copy(ph.begin(), ph.end(), b.begin() + static_cast<std::ptrdiff_t>(ehsize + i * phentsize));
    }
    for (size_t k = 0; k < order.size(); ++k) {
        add(b, segs[order[k]].data);
        if (k + 1 < order.size() && k < sp.pads.size()) b.insert(b.end(), sp.pads[k], sp.pad_fill);
    }
    add(b, sp.tail);
    return b;
}

std::vector<ElfSegment> three_segments() {
    std::vector<ElfSegment> s(3);
    s[0].role = "kernel";
    s[0].flags = 0;
    s[0].addr = 0x8000;
    s[0].data = pattern(5000, 31);
    s[1].role = "ramdisk";
    s[1].flags = kElfFlagsRamdisk;
    s[1].addr = 0x2000000;
    s[1].data = pattern(777, 32);
    s[2].role = "cmdline";
    s[2].flags = kElfFlagsCmdline;
    s[2].addr = 0;
    s[2].data = pattern(43, 33);
    return s;
}

void test_elf_elftool_layout() {
    for (bool is64 : {false, true}) {
        ElfBootImage img;
        img.is_64bit = is64;
        img.segments = three_segments();
        if (is64) img.segments[0].addr = 0xFFFFFFC000080000ull;
        const Bytes b = img.build_elftool();
        EXPECT(b.size() == 4096 + 5000 + 777 + 43);
        ElfBootImage back = ElfBootImage::parse(b);
        EXPECT(!back.layout && !back.entry && back.is_64bit == is64 && back.machine == 40);
        EXPECT(back.segments.size() == 3 && back.segments[0].addr == img.segments[0].addr);
        EXPECT(back.segments[0].role == "kernel" && back.segments[1].role == "ramdisk" && back.segments[2].role == "cmdline");
        EXPECT(back.segments[1].data == img.segments[1].data && back.build() == b);
        // the spec the independent writer uses writes the same bytes
        ElfSpec canonical;
        canonical.is64 = is64;
        EXPECT(elf_make(img.segments, canonical) == b);
        // e_machine is the image's own
        img.machine = 183;
        back = ElfBootImage::parse(img.build_elftool());
        EXPECT(back.machine == 183 && back.build() == img.build_elftool());
    }
    // the ipl and the rpm are known by their flags, wherever they are
    {
        std::vector<ElfSegment> s = three_segments();
        ElfSegment ipl, rpm;
        ipl.role = "ipl";
        ipl.flags = kElfFlagsIpl;
        ipl.addr = 0x1000;
        ipl.data = pattern(100, 34);
        rpm.role = "rpm";
        rpm.flags = kElfFlagsRpm;
        rpm.addr = 0x2000;
        rpm.data = pattern(60, 35);
        s.insert(s.begin() + 2, ipl);
        s.push_back(rpm);
        ElfBootImage img;
        img.segments = s;
        const Bytes b = img.build_elftool();
        EXPECT(elf_make(s, ElfSpec{}) == b);
        const ElfBootImage back = ElfBootImage::parse(b);
        const char* roles[] = {"kernel", "ramdisk", "ipl", "cmdline", "rpm"};
        EXPECT(back.segments.size() == 5 && !back.layout && back.build() == b);
        for (size_t i = 0; i < 5 && i < back.segments.size(); ++i) EXPECT(back.segments[i].role == roles[i]);
        EXPECT(back.segments[2].flags == kElfFlagsIpl && back.segments[4].flags == kElfFlagsRpm);
    }
    // the positional convention: unflagged segments are the kernel, then the ramdisk, then the others
    ElfBootImage img;
    img.segments = three_segments();
    img.segments[1].flags = 0;
    img.segments[2].flags = 0x1234;
    img.segments[2].role = "extra0";
    const ElfBootImage back = ElfBootImage::parse(elf_make(img.segments, ElfSpec{}));
    EXPECT(back.segments[0].role == "kernel" && back.segments[1].role == "ramdisk" && back.segments[2].role == "extra0");
    // a ramdisk that is found by its flags is the ramdisk: an unflagged segment after the kernel is an extra, not a second one
    {
        std::vector<ElfSegment> s = three_segments();
        s[2].flags = 0x1234;
        s[2].role = "extra0";
        const ElfBootImage back2 = ElfBootImage::parse(elf_make(s, ElfSpec{}));
        EXPECT(back2.segments[0].role == "kernel" && back2.segments[1].role == "ramdisk" && back2.segments[2].role == "extra0");
        s[0].flags = 0x1235;  // a kernel with flags that are not elftool's is still the first segment not known by its flags
        s[0].role = "kernel";
        EXPECT(ElfBootImage::parse(elf_make(s, ElfSpec{})).segments[0].role == "kernel");
    }
    // a table of program headers that does not fit in front of byte 4096: the data starts at the next 4096
    {
        ElfBootImage many;
        many.segments = three_segments();
        for (int i = 0; i < 128; ++i) {
            ElfSegment e;
            e.flags = 0x1234;
            e.role = "extra" + std::to_string(i + 1);
            e.addr = 0x10000 + 16u * static_cast<uint32_t>(i);
            e.data = pattern(3, 40 + static_cast<uint32_t>(i));
            many.segments.push_back(e);
        }
        many.segments[2].role = "extra0";
        many.segments[2].flags = 0x1234;
        const Bytes b = many.build_elftool();
        EXPECT(b.size() == 8192 + 5000 + 777 + 43 + 3 * 128);  // 52 + 131 * 32 = 4244 bytes of headers
        ElfSpec spec;
        spec.start = 8192;
        EXPECT(elf_make(many.segments, spec) == b);
        const ElfBootImage again = ElfBootImage::parse(b);
        EXPECT(again.segments.size() == 131 && !again.layout && again.build() == b);
        EXPECT(again.segments[130].data == many.segments[130].data);
    }
    // an ELF32 header cannot hold an address beyond 32 bits
    img.segments[0].addr = 0x100000000ull;
    EXPECT(refuses([&] { img.build_elftool(); }, "does not fit an ELF32 image"));
    img.segments[0].addr = 0x8000;
    img.entry = 0x100000000ull;
    EXPECT(refuses([&] { img.build_elftool(); }, "does not fit an ELF32 image"));
    // the highest address an ELF32 header holds
    {
        ElfBootImage edge;
        edge.segments = three_segments();
        edge.segments[0].addr = 0xFFFFFFFFull;
        EXPECT(ElfBootImage::parse(edge.build_elftool()).segments[0].addr == 0xFFFFFFFFull);
    }
    // ... and that is not an ELF at all
    {
        Bytes b = elf_make(three_segments(), ElfSpec{});
        EXPECT(ElfBootImage::looks_like(b));
        Bytes big_endian = b, bad_class = b, bad_magic = b;
        big_endian[5] = 2;
        bad_class[4] = 3;
        bad_magic[1] = 'X';
        EXPECT(!ElfBootImage::looks_like(big_endian) && !ElfBootImage::looks_like(bad_class) && !ElfBootImage::looks_like(bad_magic));
        EXPECT(!ElfBootImage::looks_like(Bytes(b.begin(), b.begin() + 19)) && ElfBootImage::looks_like(Bytes(b.begin(), b.begin() + 20)));
    }
}

// What an edit of the first segment does to an image whose layout is kept, written the way the independent writer
// takes it: spec2 is the spec of the edited image.
struct ElfEdit {
    const char* what;
    size_t grow = 0;                    // bytes added to the kernel
    std::optional<uint64_t> new_addr;   // the kernel's new address
    std::optional<uint16_t> machine;
};

void test_elf_kept_layout() {
    const std::vector<ElfSegment> segs = three_segments();
    struct Case {
        const char* name;
        ElfSpec spec;
    };
    std::vector<Case> cases;
    {
        ElfSpec s;
        s.start = 8192;
        cases.push_back({"8 KiB in front of the data", s});
    }
    {
        ElfSpec s;
        s.start = 148;  // the data right behind the table of program headers
        cases.push_back({"the data right behind the program headers", s});
    }
    {
        ElfSpec s;
        s.pads = {100, 7};
        s.pad_fill = 0xA5;
        s.tail = pattern(35, 41);
        cases.push_back({"padding between, a tail behind", s});
    }
    {
        ElfSpec s;
        s.entry = 0x1234;
        s.osabi = 0;
        s.align = 0x1000;
        s.memsz_extra = {50, 0, 0};
        cases.push_back({"own e_entry, OS/ABI 0, p_align, p_memsz beyond p_filesz", s});
    }
    {
        ElfSpec s;
        s.file_order = {1, 0, 2};
        s.pads = {3, 4};
        cases.push_back({"data in another order", s});
    }
    {
        ElfSpec s;
        s.hdr_fill = 0x5A;
        cases.push_back({"the block in front filled with 5A", s});
    }
    {
        ElfSpec s;
        s.paddr_abs = {0x4000, 0, 0};  // the kernel's p_paddr is not its p_vaddr
        cases.push_back({"p_paddr of its own", s});
    }
    {
        ElfSpec s;
        s.is64 = true;
        s.start = 0x2000;
        s.pads = {16, 0};
        s.tail = {'x', 'y'};
        s.align = 0x1000;
        s.entry = 0xFFFFFFC000080000ull;
        s.machine = 183;
        cases.push_back({"ELF64 with e_entry, padding, tail, p_align", s});
    }
    {
        ElfSpec s;
        s.is64 = true;
        s.start = 232;
        cases.push_back({"ELF64, the data right behind the program headers", s});
    }
    {
        ElfSpec s;
        s.is64 = true;
        s.paddr_abs = {0x4000, 0, 0};
        cases.push_back({"ELF64, p_paddr of its own", s});
    }
    const ElfEdit edits[] = {
        {"nothing"},
        {"kernel 2 bytes longer", 2},
        {"kernel 100 bytes longer", 100},
        {"kernel at another address", 0, 0x9000},
        {"another machine", 0, std::nullopt, 183},
        {"all of it", 17, 0x7000, 40},
    };
    for (const Case& c : cases) {
        const Bytes img = elf_make(segs, c.spec);
        const ElfBootImage parsed = ElfBootImage::parse(img);
        if (!parsed.layout) std::printf("    (%s: no layout kept)\n", c.name);
        EXPECT(parsed.layout.has_value());
        EXPECT(parsed.build() == img);
        EXPECT(parsed.entry.has_value() == c.spec.entry.has_value());
        for (const ElfEdit& e : edits) {
            ElfBootImage a = parsed;
            std::vector<ElfSegment> s2 = segs;
            ElfSpec sp2 = c.spec;
            if (e.grow) {
                a.segments[0].data.resize(a.segments[0].data.size() + e.grow, 0x99);
                s2[0].data = a.segments[0].data;
            }
            if (e.new_addr) {
                a.segments[0].addr = *e.new_addr;
                s2[0].addr = *e.new_addr;
            }
            if (e.machine) {
                a.machine = *e.machine;
                sp2.machine = *e.machine;
            }
            // p_memsz stays where it was unless the data has outgrown it; p_paddr follows p_vaddr only if it did
            const uint64_t memsz0 = segs[0].data.size() + (c.spec.memsz_extra.empty() ? 0 : c.spec.memsz_extra[0]);
            if (!c.spec.memsz_extra.empty() && c.spec.memsz_extra[0]) sp2.memsz_abs = {std::max<uint64_t>(memsz0, s2[0].data.size()), 0, 0};
            std::string why;
            const Bytes out = a.build(&why);
            const std::string label = std::string(c.name) + ", " + e.what;
            if (!why.empty()) std::printf("    (%s: %s)\n", label.c_str(), why.c_str());
            EXPECT(why.empty());
            const Bytes expect = elf_make(s2, sp2);
            if (out != expect) std::printf("    (%s: the image is not what the independent writer makes)\n", label.c_str());
            EXPECT(out == expect);
            // and what comes out is a kept layout again, the same one
            const ElfBootImage again = ElfBootImage::parse(out);
            EXPECT(again.layout.has_value() && again.build() == out);
            if (again.layout && parsed.layout) {
                EXPECT(again.layout->header.size() == parsed.layout->header.size());
                EXPECT(again.layout->order == parsed.layout->order);
                EXPECT(again.layout->after == parsed.layout->after);
            }
            EXPECT(again.segments.size() == 3 && again.segments[0].data == a.segments[0].data);
            EXPECT(again.segments[1].data == segs[1].data && again.segments[2].data == segs[2].data);
            EXPECT(again.machine == a.machine && again.segments[0].addr == a.segments[0].addr);
        }
        // an address that does not fit an ELF32 header: no layout can take it, and elftool's cannot either
        if (!c.spec.is64) {
            ElfBootImage a = parsed;
            a.segments[0].addr = 0x100000000ull;
            EXPECT(refuses([&] { a.build(); }, "does not fit an ELF32"));
            ElfBootImage b = parsed;
            b.entry = 0x100000000ull;
            EXPECT(refuses([&] { b.build(); }, "does not fit an ELF32"));
        }
    }
}

// The p_offset of program header i, in an image of either class.
size_t p_offset_pos(size_t i, bool is64) { return is64 ? 64 + i * 56 + 8 : 52 + i * 32 + 4; }
uint64_t get_p_offset(const Bytes& b, size_t i, bool is64) {
    uint64_t v = 0;
    const size_t pos = p_offset_pos(i, is64);
    for (int k = (is64 ? 8 : 4) - 1; k >= 0; --k) v = (v << 8) | b[pos + static_cast<size_t>(k)];
    return v;
}
void set_p_offset(Bytes& b, size_t i, bool is64, uint64_t v) { put_le(b, p_offset_pos(i, is64), v, is64 ? 8 : 4); }

// A segment without data has a p_offset all the same. Where it points behind the data of a segment (into the bytes that
// follow it, at the start of the next segment's data, at the end of the file) it moves with that data when the data in
// front of it grows or shrinks; where it points anywhere else (in the block in front of the data, inside a segment's
// data) it stays where it is. The expected images are the independent writer's, with the offset of the segment put where
// the rule above says.
void test_elf_empty_segments() {
    std::vector<ElfSegment> mid = three_segments();  // kernel, [ramdisk without data], cmdline
    mid[1].data.clear();
    const std::vector<ElfSegment> last = {mid[0], mid[2], mid[1]};  // kernel, cmdline, [ramdisk without data]

    enum class Rule { Behind, Stays, EndOfFile };
    struct Case {
        const char* name;
        const std::vector<ElfSegment>* segs;
        ElfSpec spec;
        Rule rule;
        size_t anchor;       // Behind: the segment whose data it points behind ...
        uint64_t distance;   // ... and how far behind its end
        uint64_t offset;     // Stays: where it points
    };
    struct Edit {
        const char* what;
        std::vector<std::pair<int, int>> resize;  // 0: the kernel, 1: the cmdline; bytes more (or fewer)
    };
    const Edit edits[] = {
        {"nothing", {}},
        {"kernel 8 bytes longer", {{0, 8}}},
        {"kernel 20 bytes shorter", {{0, -20}}},
        {"cmdline 3 bytes longer", {{1, 3}}},
        {"kernel 8 longer, cmdline 5 shorter", {{0, 8}, {1, -5}}},
    };

    for (bool is64 : {false, true}) {
        const uint64_t table_end = is64 ? 64 + 3 * 56 : 52 + 3 * 32;
        auto spec_of = [&](std::vector<uint32_t> pads, size_t tail) {
            ElfSpec sp;
            sp.is64 = is64;
            sp.pads = std::move(pads);
            sp.pad_fill = 0xA5;
            sp.tail = pattern(tail, 51);
            return sp;
        };
        std::vector<Case> cases;
        // kernel, [empty], cmdline: 10 bytes between the first and the last, 5 behind the last
        for (uint64_t d : {0u, 3u, 10u})
            cases.push_back({d == 0 ? "in the middle, right behind the kernel's data"
                                    : d == 3 ? "in the middle, in the padding behind the kernel's data"
                                             : "in the middle, at the start of the next segment's data",
                             &mid, spec_of({10, 0}, 5), Rule::Behind, 0, d, 0});
        // kernel, cmdline, [empty]: 7 and 3 bytes of padding, 5 behind
        cases.push_back({"last, in the padding behind the data of the segment before it", &last, spec_of({7, 3}, 5), Rule::Behind, 1, 3, 0});
        cases.push_back({"last, right behind the data of the segment before it", &last, spec_of({7, 3}, 5), Rule::Behind, 1, 0, 0});
        cases.push_back({"last, at the end of the file", &last, spec_of({7, 3}, 5), Rule::EndOfFile, 0, 0, 0});
        cases.push_back({"in the middle, at the end of the file", &mid, spec_of({10, 0}, 5), Rule::EndOfFile, 0, 0, 0});
        cases.push_back({"in the middle, behind the cmdline's data", &mid, spec_of({10, 2}, 5), Rule::Behind, 2, 4, 0});
        // where it stays
        cases.push_back({"offset 0", &mid, spec_of({10, 0}, 5), Rule::Stays, 0, 0, 0});
        cases.push_back({"offset behind the program headers", &mid, spec_of({10, 0}, 5), Rule::Stays, 0, 0, table_end});
        cases.push_back({"offset in the block in front of the data", &mid, spec_of({10, 0}, 5), Rule::Stays, 0, 0, 3000});
        cases.push_back({"offset at the start of the data", &mid, spec_of({10, 0}, 5), Rule::Stays, 0, 0, 4096});
        cases.push_back({"offset inside the kernel's data", &mid, spec_of({10, 0}, 5), Rule::Stays, 0, 0, 4096 + 100});

        for (const Case& c : cases) {
            const std::vector<ElfSegment>& segs = *c.segs;
            size_t empty = 0, cmdline = 0;
            for (size_t i = 0; i < segs.size(); ++i) {
                if (segs[i].data.empty()) empty = i;
                if (segs[i].role == "cmdline") cmdline = i;
            }
            EXPECT(segs[0].role == "kernel" && empty != 0 && segs[empty].data.empty() && cmdline != 0);
            Bytes img = elf_make(segs, c.spec);
            uint64_t at = c.offset;
            if (c.rule == Rule::Behind) at = get_p_offset(img, c.anchor, is64) + segs[c.anchor].data.size() + c.distance;
            if (c.rule == Rule::EndOfFile) at = img.size();
            set_p_offset(img, empty, is64, at);

            const ElfBootImage parsed = ElfBootImage::parse(img);
            const std::string label = std::string(is64 ? "ELF64, " : "ELF32, ") + c.name;
            if (!parsed.layout) std::printf("    (%s: no layout kept)\n", label.c_str());
            EXPECT(parsed.layout.has_value());
            EXPECT(parsed.build() == img);
            EXPECT(parsed.segments.size() == 3 && parsed.segments[empty].data.empty());

            for (const Edit& e : edits) {
                ElfBootImage a = parsed;
                std::vector<ElfSegment> s2 = segs;
                for (const auto& [which, delta] : e.resize) {
                    const size_t i = which == 0 ? 0 : cmdline;
                    const size_t n = delta < 0 ? s2[i].data.size() - static_cast<size_t>(-delta) : s2[i].data.size() + static_cast<size_t>(delta);
                    s2[i].data.resize(n, 0x99);
                    a.segments[i].data = s2[i].data;
                }
                std::string why;
                const Bytes out = a.build(&why);
                const std::string what = label + ", " + e.what;
                if (!why.empty()) std::printf("    (%s: %s)\n", what.c_str(), why.c_str());
                EXPECT(why.empty());
                Bytes expect = elf_make(s2, c.spec);
                uint64_t want = c.offset;
                if (c.rule == Rule::Behind) want = get_p_offset(expect, c.anchor, is64) + s2[c.anchor].data.size() + c.distance;
                if (c.rule == Rule::EndOfFile) want = expect.size();
                set_p_offset(expect, empty, is64, want);
                if (out != expect)
                    std::printf("    (%s: p_offset is %llu, the independent writer's image has %llu)\n", what.c_str(),
                                static_cast<unsigned long long>(out.size() > p_offset_pos(empty, is64) + 8 ? get_p_offset(out, empty, is64) : 0),
                                static_cast<unsigned long long>(want));
                EXPECT(out == expect);
                // what comes out is a kept layout again, and it gives itself back
                try {
                    const ElfBootImage again = ElfBootImage::parse(out);
                    EXPECT(again.layout.has_value() && again.build() == out);
                    EXPECT(again.segments.size() == 3 && again.segments[empty].data.empty());
                } catch (const FormatError& ex) {
                    std::printf("    (%s: the image that is written is refused: %s)\n", what.c_str(), ex.what());
                    EXPECT(!"the image that is written can be read again");
                }
            }
        }
    }
}

void test_elf_fallbacks() {
    std::vector<ElfSegment> segs = three_segments();
    ElfSpec sp;
    sp.pads = {9, 9};
    sp.tail = {1, 2, 3};
    const Bytes img = elf_make(segs, sp);
    ElfBootImage a = ElfBootImage::parse(img);
    EXPECT(a.layout.has_value());
    // another count of segments: elftool's layout, and the reason
    ElfBootImage two = a;
    two.segments.pop_back();
    std::string why;
    Bytes out = two.build(&why);
    EXPECT(why.find("3 program headers, the image has 2 segments") != std::string::npos);
    EXPECT(out == two.build_elftool());
    // a kept layout that does not belong to the class of the image
    ElfBootImage other = a;
    other.is_64bit = true;
    why.clear();
    other.build(&why);
    EXPECT(why.find("ELF class") != std::string::npos);
    // data in a segment that had none
    segs[2].data.clear();
    ElfBootImage e = ElfBootImage::parse(elf_make(segs, sp));
    EXPECT(e.layout.has_value() && e.build() == elf_make(segs, sp));
    e.segments[2].data = {'a', 'b'};
    why.clear();
    out = e.build(&why);
    EXPECT(why.find("had no data in the image that was unpacked") != std::string::npos && out == e.build_elftool());
    // a segment whose data is emptied is in the layout and just has no data now
    ElfBootImage f = a;
    f.segments[1].data.clear();
    why.clear();
    out = f.build(&why);
    EXPECT(why.empty());
    ElfBootImage f2 = ElfBootImage::parse(out);
    EXPECT(f2.segments[1].data.empty() && f2.segments[0].data == a.segments[0].data && f2.segments[2].data == a.segments[2].data);
    // a damaged layout is not trusted
    auto damaged = [&](const char* what, auto&& damage) {
        ElfBootImage d = a;
        damage(*d.layout);
        std::string reason;
        const Bytes o = d.build(&reason);
        if (reason.empty()) std::printf("    (%s: not noticed)\n", what);
        EXPECT(!reason.empty() && o == d.build_elftool());
    };
    damaged("a segment that is not there", [](ElfLayout& l) { l.order[0] = 17; });
    damaged("a segment twice", [](ElfLayout& l) { l.order[1] = l.order[0]; });
    damaged("a segment twice, besides all the others", [](ElfLayout& l) {
        l.order.push_back(2);
        l.after.emplace_back();
    });
    damaged("one stretch fewer", [](ElfLayout& l) { l.after.pop_back(); });
    damaged("no ELF header", [](ElfLayout& l) { l.header[1] = 'X'; });
    damaged("a header block that is cut short", [](ElfLayout& l) { l.header.resize(40); });
    damaged("program headers outside the block", [](ElfLayout& l) { l.header.resize(100); });
    // segments that overlap, or data inside the block of headers: nothing to keep, elftool's layout is written, the
    // image says so by not being the file
    {
        Bytes b = elf_make(three_segments(), ElfSpec{});
        put_le(b, 52 + 32 * 2 + 4, 4096 + 5000 + 100, 4);  // the data of segment 2 starts inside that of segment 1
        const ElfBootImage p = ElfBootImage::parse(b);
        EXPECT(!p.layout && p.segments.size() == 3 && p.segments[2].data.size() == 43);
        EXPECT(p.build() != b && p.build().size() == 4096 + 5000 + 777 + 43);
    }
    {
        Bytes b = elf_make(three_segments(), ElfSpec{});
        put_le(b, 52 + 4, 100, 4);  // the kernel's data starts in the middle of the program headers
        const ElfBootImage p = ElfBootImage::parse(b);
        EXPECT(!p.layout && p.segments[0].data.size() == 5000 && p.build() != b);
    }
    {
        // nothing has data: nothing to keep
        ElfBootImage nothing;
        nothing.segments = three_segments();
        for (ElfSegment& s : nothing.segments) s.data.clear();
        const Bytes b = nothing.build_elftool();
        const ElfBootImage p = ElfBootImage::parse(b);
        EXPECT(!p.layout && p.build() == b && p.segments.size() == 3);
    }
}

void test_elf_malformed() {
    const Bytes img = elf_make(three_segments(), ElfSpec{});
    EXPECT(refuses([&] { ElfBootImage::parse(Bytes(img.begin(), img.begin() + 30)); }, "cut short"));
    {
        Bytes b = img;
        put_le(b, 44, 5000, 2);  // e_phnum far beyond the file
        EXPECT(refuses([&] { ElfBootImage::parse(b); }, "runs past the file end"));
    }
    {
        Bytes b = img;
        put_le(b, 52 + 16, 0xFFFFFF00u, 4);  // p_filesz of the first segment
        EXPECT(refuses([&] { ElfBootImage::parse(b); }, "runs past the file end"));
    }
    {
        Bytes b = img;
        put_le(b, 42, 8, 2);  // e_phentsize too small for a program header
        EXPECT(refuses([&] { ElfBootImage::parse(b); }, "program headers are 8 bytes"));
    }
    EXPECT(refuses([&] { ElfBootImage::parse(Bytes{'n', 'o', 'p', 'e', 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); },
                   "not an ELF boot image"));

    {
        // a header and no program headers: no segments, and nothing to keep
        Bytes h(img.begin(), img.begin() + 52);
        put_le(h, 44, 0, 2);
        const ElfBootImage p = ElfBootImage::parse(h);
        EXPECT(p.segments.empty() && !p.layout);
        EXPECT(p.entry && *p.entry == 0x8000);
    }

    // damage the header block everywhere: nothing crashes, nothing but a FormatError comes out, and a layout that is
    // kept gives the image back
    std::vector<Bytes> bases;
    bases.push_back(img);
    {
        ElfSpec s;
        s.pads = {5, 6};
        s.tail = {9};
        s.start = 4096;
        bases.push_back(elf_make(three_segments(), s));
    }
    {
        ElfSpec s;
        s.is64 = true;
        s.start = 0x1000;
        bases.push_back(elf_make(three_segments(), s));
    }
    std::mt19937 rng(20261018);
    size_t accepted = 0, refused = 0, kept = 0;
    for (int i = 0; i < 40000; ++i) {
        Bytes b = bases[rng() % bases.size()];
        const int edits = 1 + static_cast<int>(rng() % 3);
        for (int e = 0; e < edits; ++e) {
            const size_t pos = rng() % std::min<size_t>(b.size(), 260);
            switch (rng() % 4) {
                case 0: b[pos] = static_cast<uint8_t>(rng()); break;
                case 1: b[pos] ^= static_cast<uint8_t>(1u << (rng() % 8)); break;
                case 2: b[pos] = 0xFF; break;
                default: b[pos] = 0; break;
            }
        }
        if (rng() % 15 == 0) b.resize(rng() % b.size());
        try {
            ElfBootImage p = ElfBootImage::parse(b);
            ++accepted;
            if (p.layout) {
                ++kept;
                EXPECT(p.build() == b);
            }
            (void)p.build();
        } catch (const FormatError&) {
            ++refused;
        } catch (...) {
            EXPECT(!"an exception that is not a FormatError");
        }
    }
    std::printf("    %zu damaged images accepted (%zu with a kept layout), %zu refused\n", accepted, kept, refused);
    EXPECT(accepted > 1000 && refused > 1000);
}

}  // namespace

int run_legacy_tests() {
    std::puts("Sony SIN: the signature");
    test_signature();
    std::puts("Sony SIN: the image behind the header, a loader, data in front of it");
    test_sin_plain();
    std::puts("Sony SIN: MMCF");
    test_sin_mmcf();
    std::puts("Sony SIN: what is refused");
    test_sin_refusals();
    std::puts("Sony SIN: decoding on several threads");
    test_sin_threads();
    std::puts("Sony SIN: damaged containers");
    test_sin_fuzz();
    std::puts("Sony ELF boot images: elftool's layout");
    test_elf_elftool_layout();
    std::puts("Sony ELF boot images: another layout is kept");
    test_elf_kept_layout();
    std::puts("Sony ELF boot images: a segment without data in a kept layout");
    test_elf_empty_segments();
    std::puts("Sony ELF boot images: what the layout cannot take");
    test_elf_fallbacks();
    std::puts("Sony ELF boot images: damaged images");
    test_elf_malformed();

    if (g_failures == 0) std::printf("legacy: ok (%d checks)\n", g_checks);
    else std::printf("legacy: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
