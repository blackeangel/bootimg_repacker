// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr/mtkimg.hpp, the container of the small MediaTek images (md1img, lk, tee, scp, logo, ...). Run by tests/run_tests.sh as
// `abr_unit_tests mtkimg`. The images here are made by hand from the layout of the partition header (there is no device image in the tests of
// this group):
//
//   * a header is read and written back to the same 512 bytes, the older kind (no extension, 0xFF behind the load address) and the newer one,
//     a name with bytes behind its zero, every field kept;
//   * looks_like() takes the believable headers and refuses the rest (no magic, no name, a name that does not end, text that cannot print, a
//     size of header other than 512, data that is longer than the file);
//   * a chain of sections is parsed and built back to the same bytes: alignments 16, 512 and 4096, padding that is not zero, a chain that
//     ends by its img_list_end and one that ends by the lack of a next header, bytes after the last section left out of the chain, a
//     header with a size above 4 GiB (the high word), cut short at every place, and a first section that is not one;
//   * the table of pictures of a logo (count, size of the whole, offsets) is parsed and built back, and refused where it is not one;
//   * the pixel formats: every format round-trips through RGBA (RGB565 as far as it can be: a picture of 565 pixels comes back the same),
//     the constant alpha, the table of resolutions and the guess of the format from the sizes.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "abr/mtkimg.hpp"

using namespace abr;
using namespace abr::mtkimg;

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

template <typename F>
bool throws(F&& f) {
    try {
        f();
    } catch (const FormatError&) {
        return true;
    }
    return false;
}

Bytes pattern(size_t n, uint8_t seed) {
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>(seed + i * 7 + (i >> 8));
    return b;
}

Section make_section(const char* name, size_t size, uint8_t seed, bool last, uint32_t align = 16, uint8_t pad_byte = 0) {
    Section s;
    s.header = Header::fresh(name);
    s.header.maddr = 0x40000000u + seed;
    s.header.mode = 0;
    s.header.img_list_end = last ? 1 : 0;
    s.header.align_size = align;
    s.align = align;
    s.data = pattern(size, seed);
    (void)pad_byte;
    return s;
}

// A chain whose paddings are those the alignment asks for, filled with `pad_byte`.
Chain make_chain(const std::vector<std::tuple<const char*, size_t, uint32_t>>& list, uint8_t pad_byte = 0) {
    Chain c;
    uint64_t at = 0;
    for (size_t i = 0; i < list.size(); ++i) {
        const auto& [name, size, align] = list[i];
        Section s = make_section(name, size, static_cast<uint8_t>(i * 31 + 5), i + 1 == list.size(), align);
        at += kHeaderSize + size;
        if (i + 1 != list.size()) {
            s.pad.assign(pad_length(at, align), pad_byte);
            at += s.pad.size();
        }
        c.sections.push_back(std::move(s));
    }
    c.consumed = static_cast<size_t>(at);
    return c;
}

void test_header() {
    // The newer kind, every field a value of its own.
    Header h = Header::fresh("md1rom");
    h.dsize = 0x1234;
    h.maddr = 0x80000000u;
    h.mode = 0xFFFFFFFFu;
    h.hdr_version = 3;
    h.img_type = 7;
    h.img_list_end = 0;
    h.align_size = 64;
    h.dsize_extend = 0;
    h.maddr_extend = 0x11;
    const Bytes raw = serialize_header(h);
    EXPECT(raw.size() == kHeaderSize);
    EXPECT(raw[0] == 0x88 && raw[1] == 0x16 && raw[2] == 0x88 && raw[3] == 0x58);
    EXPECT(raw[48] == 0x89 && raw[49] == 0x16 && raw[50] == 0x89 && raw[51] == 0x58);
    EXPECT(raw[80] == 0xFF && raw[511] == 0xFF);
    const Header back = parse_header(raw, 0);
    EXPECT(back.name_text() == "md1rom");
    EXPECT(back.dsize == 0x1234 && back.maddr == 0x80000000u && back.mode == kAny && back.hdr_version == 3 && back.img_type == 7);
    EXPECT(back.img_list_end == 0 && back.align_size == 64 && back.maddr_extend == 0x11 && back.extended());
    EXPECT(serialize_header(back) == raw);
    EXPECT(back.alignment() == 64);

    // At an offset inside a bigger buffer.
    Bytes big(100, 0xAA);
    big.insert(big.end(), raw.begin(), raw.end());
    EXPECT(serialize_header(parse_header(big, 100)) == raw);

    // The older kind: no extension, the bytes behind the load address all 0xFF.
    Bytes old(kHeaderSize, 0xFF);
    old[0] = 0x88, old[1] = 0x16, old[2] = 0x88, old[3] = 0x58;
    old[4] = 0x10, old[5] = old[6] = old[7] = 0;  // dsize 16
    const char* nm = "KERNEL";
    for (int i = 0; nm[i]; ++i) old[8 + i] = static_cast<uint8_t>(nm[i]);
    for (int i = 6; i < 32; ++i) old[8 + i] = 0;
    old[40] = 0x00, old[41] = 0x80, old[42] = 0x00, old[43] = 0x80;  // maddr 0x80008000
    const Header o = parse_header(old, 0);
    EXPECT(!o.extended() && o.data_size() == 16 && o.name_text() == "KERNEL" && o.maddr == 0x80008000u);
    EXPECT(o.alignment() == 16);  // nobody says: 16
    EXPECT(serialize_header(o) == old);

    // A name with bytes behind its zero.
    Bytes odd = raw;
    odd[8 + 7] = 0x5A, odd[8 + 8] = 0xA5;
    const Header t = parse_header(odd, 0);
    EXPECT(t.name_text() == "md1rom" && t.name_tail().size() == 25 && t.name_tail()[0] == 0x5A);
    EXPECT(serialize_header(t) == odd);
    Header t2 = Header::fresh("x");
    t2.set_name("md1rom", t.name_tail());
    EXPECT(t2.name_text() == "md1rom" && t2.name_tail() == t.name_tail());
    EXPECT(h.name_tail().empty());

    // A name that does not fit, bytes behind it that do not fit.
    EXPECT(throws([] { Header::fresh("a-name-that-is-longer-than-the-31-chars-of-it"); }));
    EXPECT(throws([] { Header h2 = Header::fresh("x"); h2.set_name(std::string(31, 'n'), Bytes(1, 1)); }));
    EXPECT(throws([] { parse_header(Bytes(100, 0), 0); }));
    EXPECT(throws([&] { parse_header(Bytes(kHeaderSize, 0), 0); }));

    // The size is a 64-bit number when the extension is there.
    Header wide = Header::fresh("big");
    wide.dsize = 5;
    wide.dsize_extend = 2;
    EXPECT(wide.data_size() == (uint64_t{2} << 32) + 5);
    wide.dsize_extend = kAny;
    EXPECT(wide.data_size() == 5);
    Header narrow = wide;
    narrow.ext_magic = kAny;
    narrow.dsize_extend = 3;
    EXPECT(narrow.data_size() == 5);

    // The alignment: a power of two between 4 and 65536, else 16.
    Header a = Header::fresh("a");
    for (uint32_t v : {4u, 8u, 512u, 4096u, 65536u}) {
        a.align_size = v;
        EXPECT(a.alignment() == v);
    }
    for (uint32_t v : {0u, 1u, 2u, 3u, 24u, 100u, 131072u, kAny}) {
        a.align_size = v;
        EXPECT(a.alignment() == 16);
    }
}

void test_looks_like() {
    Section s = make_section("logo", 40, 3, true);
    Chain c;
    c.sections.push_back(s);
    const Bytes one = build(c);
    EXPECT(looks_like(one));
    EXPECT(looks_like(one, 0));
    EXPECT(!looks_like(Bytes()));
    EXPECT(!looks_like(Bytes(100, 0x88)));
    EXPECT(!looks_like(one, 1));
    EXPECT(!looks_like(one, one.size()));

    Bytes b = one;
    b[0] ^= 1;
    EXPECT(!looks_like(b));
    b = one;
    for (int i = 0; i < 32; ++i) b[8 + i] = 0;  // no name
    EXPECT(!looks_like(b));
    b = one;
    for (int i = 0; i < 32; ++i) b[8 + i] = 'x';  // the name does not end
    EXPECT(!looks_like(b));
    b = one;
    b[8 + 1] = 0x07;  // text that cannot print
    EXPECT(!looks_like(b));
    b = one;
    b[8 + 1] = 0xE9;
    EXPECT(!looks_like(b));
    b = one;
    b[52] = 0x00, b[53] = 0x04;  // header of 1024 bytes
    EXPECT(!looks_like(b));
    b = one;
    b[4] = 41;  // one byte more than the file has
    EXPECT(!looks_like(b));
    b[4] = 40;
    EXPECT(looks_like(b));

    // The older kind says nothing of its size of header.
    Bytes old(kHeaderSize + 4, 0xFF);
    old[0] = 0x88, old[1] = 0x16, old[2] = 0x88, old[3] = 0x58;
    old[4] = 4, old[5] = old[6] = old[7] = 0;
    old[8] = 'K', old[9] = 0;
    for (int i = 2; i < 32; ++i) old[8 + i] = 0;
    EXPECT(looks_like(old));
}

void test_chain() {
    // Three sections of different sizes, the paddings the alignment of 16 asks for.
    const Chain c = make_chain({{"md1rom", 1000, 16}, {"md1dsp", 333, 16}, {"md1_file_map", 51, 16}});
    const Bytes img = build(c);
    EXPECT(img.size() == c.consumed);
    EXPECT(img.size() % 1 == 0 && looks_like(img, 0));
    const Chain p = parse(img);
    EXPECT(p.sections.size() == 3 && p.consumed == img.size());
    EXPECT(p.sections[0].header.name_text() == "md1rom" && p.sections[1].header.name_text() == "md1dsp" && p.sections[2].header.name_text() == "md1_file_map");
    EXPECT(p.sections[0].data == c.sections[0].data && p.sections[1].data == c.sections[1].data && p.sections[2].data == c.sections[2].data);
    EXPECT(p.sections[0].pad.size() == pad_length(kHeaderSize + 1000, 16) && p.sections[2].pad.empty());
    EXPECT(build(p) == img);
    EXPECT(p.sections[0].align == 16);

    // scan() says where the sections are without copying them.
    {
        size_t consumed = 0;
        const std::vector<Span> spans = scan(img, &consumed);
        EXPECT(spans.size() == 3 && consumed == img.size());
        EXPECT(spans[0].header_at == 0 && spans[0].data_at == kHeaderSize && spans[0].data_size == 1000);
        EXPECT(spans[1].header_at == spans[0].data_at + 1000 + spans[0].pad_size && spans[1].data_size == 333);
        EXPECT(spans[2].pad_size == 0 && spans[2].data_at + spans[2].data_size == img.size());
        EXPECT(spans[0].header.name_text() == "md1rom" && spans[0].align == 16);
    }

    // Bytes after the last section are not part of the chain.
    Bytes with_tail = img;
    with_tail.insert(with_tail.end(), 77, 0xFF);
    const Chain pt = parse(with_tail);
    EXPECT(pt.sections.size() == 3 && pt.consumed == img.size() && build(pt) == img);

    // Padding that is not zero is kept as it is.
    Chain ff = make_chain({{"a", 100, 16}, {"b", 100, 16}}, 0xFF);
    const Bytes ff_img = build(ff);
    EXPECT(parse(ff_img).sections[0].pad == ff.sections[0].pad && build(parse(ff_img)) == ff_img);
    Chain odd = make_chain({{"a", 101, 16}, {"b", 100, 16}});
    for (size_t i = 0; i < odd.sections[0].pad.size(); ++i) odd.sections[0].pad[i] = static_cast<uint8_t>(0xC0 + i);
    const Bytes odd_img = build(odd);
    EXPECT(parse(odd_img).sections[0].pad == odd.sections[0].pad && build(parse(odd_img)) == odd_img);

    // Alignment of 512 and of 4096: the next header is where the header of the first says.
    for (uint32_t al : {512u, 4096u}) {
        Chain big = make_chain({{"one", 700, al}, {"two", 5000, al}, {"three", 10, al}});
        const Bytes bi = build(big);
        const Chain pb = parse(bi);
        EXPECT(pb.sections.size() == 3 && pb.sections[0].align == al && build(pb) == bi);
        EXPECT(pb.sections[1].header.name_text() == "two" && pb.sections[1].data.size() == 5000);
    }

    // A header that says nothing of its alignment: the one that the image shows is found (here 512 where 16 is the default).
    Chain unsaid = make_chain({{"one", 700, 512}, {"two", 100, 512}});
    for (Section& s : unsaid.sections) s.header.align_size = kAny;
    const Bytes ui = build(unsaid);
    const Chain pu = parse(ui);
    EXPECT(pu.sections.size() == 2 && pu.sections[0].align == 512 && build(pu) == ui);

    // A chain that ends by its list-end mark although something that looks like a header follows: the follower is not a section of it.
    Chain stop = make_chain({{"one", 100, 16}, {"two", 100, 16}});
    stop.sections[0].header.img_list_end = 1;
    stop.sections[0].pad.clear();
    Bytes si = build(stop);
    const Chain ps = parse(si);
    EXPECT(ps.sections.size() == 1 && ps.consumed == kHeaderSize + 100);

    // Older headers (no extension): the list does not say where it ends, the next header is searched for.
    Chain legacy = make_chain({{"KERNEL", 70, 16}, {"ROOTFS", 90, 16}});
    for (Section& s : legacy.sections) {
        s.header.ext_magic = kAny, s.header.hdr_size = kAny, s.header.hdr_version = kAny, s.header.img_type = kAny, s.header.img_list_end = kAny;
        s.header.align_size = kAny, s.header.dsize_extend = kAny, s.header.maddr_extend = kAny;
    }
    const Bytes li = build(legacy);
    const Chain pl = parse(li);
    EXPECT(pl.sections.size() == 2 && pl.sections[1].header.name_text() == "ROOTFS" && build(pl) == li);

    // Zero-length data: a section that is its header.
    Chain empty = make_chain({{"empty", 0, 16}, {"after", 8, 16}});
    const Bytes ei = build(empty);
    const Chain pe = parse(ei);
    EXPECT(pe.sections.size() == 2 && pe.sections[0].data.empty() && pe.sections[1].data.size() == 8 && build(pe) == ei);

    // The size of the data is written by build(), whatever the header held.
    Chain stale = make_chain({{"a", 20, 16}});
    stale.sections[0].header.dsize = 9999;
    const Bytes sti = build(stale);
    EXPECT(parse(sti).sections[0].data.size() == 20 && parse(sti).sections[0].header.dsize == 20);

    // The high word of the size: written from the data (here it is zero), refused in a header that cannot say it.
    Chain legacy_big = make_chain({{"KERNEL", 10, 16}});
    legacy_big.sections[0].header.ext_magic = kAny;
    EXPECT(!throws([&] { build(legacy_big); }));

    // A duplicate name is no problem for the container (md1img has more than one section of the same name in some images).
    Chain dup = make_chain({{"cert", 30, 16}, {"cert", 31, 16}, {"cert", 32, 16}});
    const Bytes di = build(dup);
    const Chain pd = parse(di);
    EXPECT(pd.sections.size() == 3 && pd.sections[1].data.size() == 31 && build(pd) == di);

    // Damage: no section at the start, a section cut short (at every length), a size that the file does not have.
    EXPECT(throws([] { parse(Bytes()); }));
    EXPECT(throws([] { parse(Bytes(2000, 0)); }));
    EXPECT(throws([&] { parse(Bytes(img.begin() + 4, img.end())); }));
    bool all_refused = true;
    for (size_t cut : {size_t{511}, size_t{512}, size_t{600}, size_t{1000}, size_t{1511}}) {
        Bytes shorter(img.begin(), img.begin() + cut);
        if (!throws([&] { parse(shorter); })) all_refused = false;
    }
    EXPECT(all_refused);
    // Cut inside the second section: the first one is whole and the second is no section any more -- the chain is the first alone, the rest is a tail.
    const Bytes cut2(img.begin(), img.begin() + kHeaderSize + 1000 + pad_length(kHeaderSize + 1000, 16) + 300);
    const Chain pc2 = parse(cut2);
    EXPECT(pc2.sections.size() == 1 && pc2.sections[0].data.size() == 1000 && pc2.consumed == kHeaderSize + 1000);
    EXPECT(throws([&] { Bytes b = img; b[52] = 0x40; parse(b); }));  // size of header 0x440
    // More sections than a chain may have.
    {
        Chain many;
        for (int i = 0; i < 4100; ++i) many.sections.push_back(make_section("m", 0, 1, i == 4099));
        const Bytes mi = build(many);
        EXPECT(throws([&] { parse(mi); }));
    }
}

void test_logo() {
    const std::vector<Bytes> pics = {pattern(100, 1), pattern(7, 2), pattern(3000, 3), Bytes()};
    const Bytes table = build_logo(pics);
    EXPECT(table.size() == 8 + 16 + 100 + 7 + 3000);
    EXPECT(table[0] == 4 && table[4] == (table.size() & 0xFF));
    const auto parsed = parse_logo(table);
    EXPECT(parsed.has_value() && parsed->pictures == pics);
    EXPECT(build_logo(parsed->pictures) == table);

    // One picture.
    const Bytes one = build_logo({pattern(50, 9)});
    EXPECT(parse_logo(one) && parse_logo(one)->pictures.size() == 1 && parse_logo(one)->pictures[0] == pattern(50, 9));

    // Where it is not a table of pictures.
    EXPECT(!parse_logo(Bytes()));
    EXPECT(!parse_logo(Bytes(11, 0)));
    EXPECT(!parse_logo(pattern(500, 4)));
    Bytes b = table;
    b[0] = 0;  // no pictures
    EXPECT(!parse_logo(b));
    b = table;
    b[0] = 5;  // five where the table has four
    EXPECT(!parse_logo(b));
    b = table;
    b[4] ^= 1;  // the size of the whole is not the size of the data
    EXPECT(!parse_logo(b));
    b = table;
    b[8] += 4;  // the first offset is not right behind the table
    EXPECT(!parse_logo(b));
    b = table;
    b[12] = 0xFF, b[13] = 0xFF;  // an offset beyond the data
    EXPECT(!parse_logo(b));
    b = table;
    std::swap(b[12], b[16]), std::swap(b[13], b[17]);  // offsets that fall
    EXPECT(!parse_logo(b));
    b = table;
    b[0] = 0x01, b[1] = 0x10, b[2] = 0, b[3] = 0;  // 4097 pictures
    EXPECT(!parse_logo(b));
    EXPECT(throws([] { build_logo({}); }));
    EXPECT(throws([] { build_logo(std::vector<Bytes>(4097)); }));
}

void test_pixels() {
    // The same four pixels (red, green, blue, half-transparent white) in every format.
    const Bytes rgba = {255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 128};
    const Bytes bgra = rgba_to_pixels(PixelFormat::BGRA8888, rgba, 4, 1, true, 255);
    EXPECT((bgra == Bytes{0, 0, 255, 255, 0, 255, 0, 255, 255, 0, 0, 255, 255, 255, 255, 128}));
    EXPECT(pixels_to_rgba(PixelFormat::BGRA8888, bgra, 4, 1) == rgba);
    EXPECT(rgba_to_pixels(PixelFormat::RGBA8888, rgba, 4, 1, true, 255) == rgba);
    EXPECT(pixels_to_rgba(PixelFormat::RGBA8888, rgba, 4, 1) == rgba);
    const Bytes bgr = rgba_to_pixels(PixelFormat::BGR888, rgba, 4, 1, true, 255);
    EXPECT((bgr == Bytes{0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255}));
    EXPECT(pixels_to_rgba(PixelFormat::BGR888, bgr, 4, 1)[3] == 255 && pixels_to_rgba(PixelFormat::BGR888, bgr, 4, 1)[15] == 255);
    const Bytes rgb = rgba_to_pixels(PixelFormat::RGB888, rgba, 4, 1, true, 255);
    EXPECT((rgb == Bytes{255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255}));
    const Bytes r565 = rgba_to_pixels(PixelFormat::RGB565, rgba, 4, 1, true, 255);
    EXPECT((r565 == Bytes{0x00, 0xF8, 0xE0, 0x07, 0x1F, 0x00, 0xFF, 0xFF}));
    EXPECT((pixels_to_rgba(PixelFormat::RGB565, r565, 4, 1) == Bytes{255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255}));

    // The alpha that a PNG without alpha brings.
    EXPECT(rgba_to_pixels(PixelFormat::BGRA8888, rgba, 4, 1, false, 200)[3] == 200);
    EXPECT(rgba_to_pixels(PixelFormat::BGRA8888, rgba, 4, 1, true, 200)[3] == 255);

    // Every 565 value comes back as itself, through RGBA.
    Bytes all565(65536 * 2);
    for (uint32_t v = 0; v < 65536; ++v) all565[2 * v] = uint8_t(v), all565[2 * v + 1] = uint8_t(v >> 8);
    EXPECT(rgba_to_pixels(PixelFormat::RGB565, pixels_to_rgba(PixelFormat::RGB565, all565, 256, 256), 256, 256, true, 255) == all565);
    // Every format, a picture of noise.
    const Bytes noise = pattern(32 * 8 * 4, 17);
    for (PixelFormat f : {PixelFormat::BGRA8888, PixelFormat::RGBA8888}) EXPECT(pixels_to_rgba(f, rgba_to_pixels(f, noise, 32, 8, true, 255), 32, 8) == noise);
    for (PixelFormat f : {PixelFormat::BGR888, PixelFormat::RGB888}) {
        const Bytes px = rgba_to_pixels(f, noise, 32, 8, true, 255);
        EXPECT(rgba_to_pixels(f, pixels_to_rgba(f, px, 32, 8), 32, 8, true, 255) == px);
    }

    // The sizes that are wrong.
    EXPECT(throws([&] { pixels_to_rgba(PixelFormat::BGRA8888, bgra, 3, 1); }));
    EXPECT(throws([&] { pixels_to_rgba(PixelFormat::RGB565, bgra, 4, 1); }));
    EXPECT(throws([&] { rgba_to_pixels(PixelFormat::BGRA8888, rgba, 5, 1, true, 255); }));

    // Names.
    for (PixelFormat f : {PixelFormat::BGRA8888, PixelFormat::RGBA8888, PixelFormat::RGB565, PixelFormat::BGR888, PixelFormat::RGB888}) {
        EXPECT(format_from_name(format_name(f)) == f);
    }
    EXPECT(!format_from_name("argb"));
    EXPECT(bytes_per_pixel(PixelFormat::BGRA8888) == 4 && bytes_per_pixel(PixelFormat::RGB565) == 2 && bytes_per_pixel(PixelFormat::BGR888) == 3);

    // The constant alpha.
    Bytes ca = bgra;
    for (size_t i = 3; i < ca.size(); i += 4) ca[i] = 255;
    EXPECT(constant_alpha(PixelFormat::BGRA8888, ca) == uint8_t{255});
    EXPECT(!constant_alpha(PixelFormat::BGRA8888, bgra));
    EXPECT(!constant_alpha(PixelFormat::RGB565, r565));
    EXPECT(!constant_alpha(PixelFormat::BGRA8888, Bytes()));
    for (size_t i = 3; i < ca.size(); i += 4) ca[i] = 0;
    EXPECT(constant_alpha(PixelFormat::RGBA8888, ca) == uint8_t{0});
}

void test_guess() {
    const auto hd = guess_resolution(uint64_t{1080} * 1920);
    EXPECT(hd && hd->width == 1080 && hd->height == 1920);
    const auto hdp = guess_resolution(uint64_t{720} * 1280);
    EXPECT(hdp && hdp->width == 720 && hdp->height == 1280);
    const auto tall = guess_resolution(uint64_t{1080} * 2400);
    EXPECT(tall && tall->width == 1080 && tall->height == 2400);
    // The sizes that share their area with an older entry of the table and are the likelier ones come first.
    const auto hdplus = guess_resolution(uint64_t{720} * 1440);
    EXPECT(hdplus && hdplus->width == 720 && hdplus->height == 1440);
    const auto tab = guess_resolution(uint64_t{600} * 1024);
    EXPECT(tab && tab->width == 600 && tab->height == 1024);
    const auto qhd = guess_resolution(uint64_t{1440} * 3200);
    EXPECT(qhd && qhd->width == 1440 && qhd->height == 3200);
    // The first of the table is the guess when two sizes have the same area: portrait before landscape.
    const auto land = guess_resolution(uint64_t{1920} * 1080);
    EXPECT(land && land->width == 1080 && land->height == 1920);
    EXPECT(!guess_resolution(0));
    // A size that is not in the table: as wide as the picture it is like, when that makes whole rows.
    const std::optional<Resolution> like = Resolution{1080, 1920};
    const auto strip = guess_resolution(uint64_t{1080} * 123, like);
    EXPECT(strip && strip->width == 1080 && strip->height == 123);
    EXPECT(!guess_resolution(uint64_t{1080} * 123 + 1, like));
    EXPECT(!guess_resolution(uint64_t{1080} * 123, std::nullopt));
    const auto known_first = guess_resolution(uint64_t{720} * 1280, like);  // the table says first
    EXPECT(known_first && known_first->width == 720);
    EXPECT(!guess_resolution(12345679));
    // An area that is in the table comes back as sizes that give that area.
    bool every = true;
    for (uint64_t a : {uint64_t{480} * 800, uint64_t{540} * 960, uint64_t{1440} * 2560, uint64_t{240} * 320, uint64_t{1200} * 1920}) {
        const auto r = guess_resolution(a);
        if (!r || uint64_t{r->width} * r->height != a) every = false;
    }
    EXPECT(every);

    // The format that explains the sizes of the pictures.
    EXPECT(guess_format({1080 * 1920 * 4, 1080 * 1920 * 4}) == PixelFormat::BGRA8888);
    EXPECT(guess_format({480 * 800 * 2}) == PixelFormat::RGB565);
    EXPECT(guess_format({1080 * 1920 * 3, 480 * 800 * 3}) == PixelFormat::BGR888);
    EXPECT(guess_format({7}) == PixelFormat::BGRA8888);  // nothing explains it: the format of the rest
    EXPECT(guess_format({}) == PixelFormat::BGRA8888);
    EXPECT(guess_format({480 * 800 * 2, 480 * 800 * 2, 1080 * 1920 * 4}) == PixelFormat::RGB565);
}

}  // namespace

int run_mtkimg_tests() {
    test_header();
    test_looks_like();
    test_chain();
    test_logo();
    test_pixels();
    test_guess();
    if (g_failures == 0) std::printf("mtkimg: ok (%d checks)\n", g_checks);
    else std::printf("mtkimg: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
