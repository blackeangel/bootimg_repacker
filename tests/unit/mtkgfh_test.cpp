// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr/mtkgfh.hpp, the loader image of a MediaTek boot ROM (the "preloader"). Run by tests/run_tests.sh as `abr_unit_tests mtkgfh`.
// The images here are made by hand, from the layout of the headers (tools/mtk_image.h of U-Boot) -- the check against the real loaders is
// the live one of `abr unpack` / `abr pack` on the files of mtkclient, not a unit test:
//
//   * the names (header types, signature kinds, flash types, BRLYT types), FILE_INFO read and written back, its name and what is behind the
//     zero of the name, a FILE_INFO that is longer than 56 bytes;
//   * an image that starts with its chain (the sizes of the real ones: hdr_size 0xF0 with four bytes of padding after the last header, or
//     0x300 with BL_SEC_KEY and no padding) is parsed and built back to the same bytes, for every kind of signature;
//   * the SHA-256 trailer: recognised only where it is the hash, made again when the loader is edited, left alone where it is not the hash;
//   * the sizes in FILE_INFO follow what is built (a longer loader, a header more, another signature);
//   * an image of a partition (device header, BRLYT, chain at 0x800, fill to 0x200): found, kept, and the sizes of the BRLYT worked out from
//     the file, or from the end of the loader, or kept as they were;
//   * find_chain()/looks_like()/problem() on files that are not one, on the damaged ones (every cut of an image, sizes that do not agree, a
//     BRLYT that points at nothing) and split_headers() on headers that are cut short or too many;
//   * describe() of the headers that have names.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "abr/mtkgfh.hpp"
#include "abr/sha.hpp"

using namespace abr;
using namespace abr::mtkgfh;

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
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>(seed + i * 13 + (i >> 7));
    return b;
}

void put32(Bytes& b, size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[at + i] = static_cast<uint8_t>(v >> (8 * i));
}
uint32_t get32(const Bytes& b, size_t at) { return uint32_t{b[at]} | (uint32_t{b[at + 1]} << 8) | (uint32_t{b[at + 2]} << 16) | (uint32_t{b[at + 3]} << 24); }

// One header as the bytes lie in a file: "MMM" + version, size, type, the body.
Bytes gfh(uint8_t version, uint16_t type, const Bytes& body) {
    Bytes b(kCommonSize + body.size());
    put32(b, 0, kMagic | (uint32_t{version} << 24));
    b[4] = static_cast<uint8_t>(b.size());
    b[5] = static_cast<uint8_t>(b.size() >> 8);
    b[6] = static_cast<uint8_t>(type);
    b[7] = static_cast<uint8_t>(type >> 8);
    std::copy(body.begin(), body.end(), b.begin() + kCommonSize);
    return b;
}

struct Spec {
    uint8_t sig_type = 5;
    size_t payload = 1000;
    size_t sig = 0x40;
    bool sec_key = false;     // a BL_SEC_KEY at the end of the chain (and no padding behind it)
    bool right_hash = false;  // sig_type 1: the signature is the SHA-256, else it is what `sig` bytes of pattern are
    uint32_t load_addr = 0x200f10;
    uint32_t max_size = 0x80000;
};

// A chain like those of the real loaders, built from the layout and not with the library: FILE_INFO, BL_INFO, BROM_CFG, ANTI_CLONE,
// BROM_SEC_CFG, and either BL_SEC_KEY or four bytes of padding; then the loader, then the signature.
Bytes make_image(const Spec& s, size_t at = 0, Bytes* chain_out = nullptr) {
    Bytes bl_info(4);
    put32(bl_info, 0, 1);
    Bytes brom_cfg(92, 0);
    put32(brom_cfg, 0, 0x90);        // cfg_bits
    put32(brom_cfg, 80, 5000);       // usbdl_by_kcol0_timeout_ms
    Bytes anti_clone(12, 0);
    put32(anti_clone, 4, 0x10);
    put32(anti_clone, 8, 0x80);
    Bytes sec_cfg(40, 0);
    put32(sec_cfg, 0, 3);
    Bytes rest;
    for (const Bytes& h : {gfh(1, kTypeBlInfo, bl_info), gfh(1, kTypeBromCfg, brom_cfg), gfh(1, kTypeAntiClone, anti_clone), gfh(1, kTypeBromSecCfg, sec_cfg)})
        rest.insert(rest.end(), h.begin(), h.end());
    if (s.sec_key) {
        const Bytes key = gfh(1, kTypeBlSecKey, pattern(0x20c, 77));
        rest.insert(rest.end(), key.begin(), key.end());
    } else {
        rest.insert(rest.end(), 4, 0);
    }
    const size_t hdr_size = kFileInfoSize + rest.size();
    const size_t sig_size = s.sig_type == kSigSha256 && s.right_hash ? 32 : s.sig;
    const size_t total = hdr_size + s.payload + sig_size;

    Bytes fi(kFileInfoSize - kCommonSize, 0);
    const char* name = "FILE_INFO";
    std::copy(name, name + 9, fi.begin());
    put32(fi, 12, 1);
    fi[16] = 1;
    fi[18] = 5;
    fi[19] = s.sig_type;
    put32(fi, 20, s.load_addr);
    put32(fi, 24, static_cast<uint32_t>(total));
    put32(fi, 28, s.max_size);
    put32(fi, 32, static_cast<uint32_t>(hdr_size));
    put32(fi, 36, static_cast<uint32_t>(sig_size));
    put32(fi, 40, static_cast<uint32_t>(hdr_size));
    put32(fi, 44, 3261071361u);

    Bytes out(at, 0xFF);
    const Bytes first = gfh(1, kTypeFileInfo, fi);
    out.insert(out.end(), first.begin(), first.end());
    out.insert(out.end(), rest.begin(), rest.end());
    if (chain_out) *chain_out = Bytes(out.begin() + static_cast<std::ptrdiff_t>(at), out.end());
    const Bytes payload = pattern(s.payload, 5);
    out.insert(out.end(), payload.begin(), payload.end());
    if (s.sig_type == kSigSha256 && s.right_hash) {
        const Bytes h = hash::sha256(out.data() + at, out.size() - at);
        out.insert(out.end(), h.begin(), h.end());
    } else {
        const Bytes sig = pattern(sig_size, 201);
        out.insert(out.end(), sig.begin(), sig.end());
    }
    return out;
}

// The device header and the BRLYT in front of a chain at 0x800 (what the images of a partition have), the chain, and 0xFF up to a multiple of
// 0x200. The BRLYT holds the size of the file.
Bytes make_partition_image(const Spec& s, const char* boot_name = "EMMC_BOOT", uint32_t brlyt_type = kBrlytEmmc, bool total_is_file = true) {
    Bytes d = make_image(s, 0x800);
    const size_t end = d.size();
    d.resize((end + 0x1FF) / 0x200 * 0x200, 0xFF);
    std::fill(d.begin(), d.begin() + 0x800, 0xFF);
    for (size_t i = 0; i < 12; ++i) d[i] = 0;
    for (size_t i = 0; boot_name[i]; ++i) d[i] = static_cast<uint8_t>(boot_name[i]);
    put32(d, 12, 1);
    put32(d, 16, 0x200);
    const char* brlyt = "BRLYT";
    for (size_t i = 0; i < 8; ++i) d[0x200 + i] = i < 5 ? static_cast<uint8_t>(brlyt[i]) : 0;
    const uint32_t total = total_is_file ? static_cast<uint32_t>(d.size()) : static_cast<uint32_t>(end);
    put32(d, 0x200 + 8, 1);
    put32(d, 0x200 + 12, 0x800);
    put32(d, 0x200 + 16, total);
    put32(d, 0x200 + 20, kBrlytMagic);
    put32(d, 0x200 + 24, brlyt_type);
    put32(d, 0x200 + 28, 0x800);
    put32(d, 0x200 + 32, total);
    put32(d, 0x200 + 36, 1);
    for (size_t i = 0x228; i < 0x400; ++i) d[i] = 0;
    return d;
}

// ------------------------------------------------------------------------------------------------------------------------ names --

void test_names() {
    EXPECT(type_name(0) == "FILE_INFO");
    EXPECT(type_name(1) == "BL_INFO");
    EXPECT(type_name(2) == "ANTI_CLONE");
    EXPECT(type_name(3) == "BL_SEC_KEY");
    EXPECT(type_name(7) == "BROM_CFG");
    EXPECT(type_name(8) == "BROM_SEC_CFG");
    EXPECT(type_name(9) == "type 9");
    EXPECT(sig_type_name(0) == "none");
    EXPECT(sig_type_name(1) == "SHA-256");
    EXPECT(sig_type_name(5) == "kind 5");
    EXPECT(flash_type_name(5) == "generic (NOR, SD, eMMC)");
    EXPECT(flash_type_name(2) == "NAND");
    EXPECT(flash_type_name(9) == "type 9");
    EXPECT(brlyt_type_name(kBrlytEmmc) == "eMMC");
    EXPECT(brlyt_type_name(kBrlytNor) == "NOR");
    EXPECT(brlyt_type_name(kBrlytSdmmc) == "SD/MMC");
    EXPECT(brlyt_type_name(0x12345) == "0x12345");
    EXPECT(std::string(size_basis_name(SizeBasis::File)) == "file");
    EXPECT(std::string(size_basis_name(SizeBasis::Chain)) == "chain");
    EXPECT(std::string(size_basis_name(SizeBasis::Literal)) == "literal");
    EXPECT(size_basis_from_name("file") == SizeBasis::File);
    EXPECT(size_basis_from_name("chain") == SizeBasis::Chain);
    EXPECT(size_basis_from_name("literal") == SizeBasis::Literal);
    EXPECT(!size_basis_from_name("File"));
    EXPECT(!size_basis_from_name(""));
}

// ----------------------------------------------------------------------------------------------------------------------- FILE_INFO --

void test_file_info() {
    const Bytes img = make_image(Spec{});
    const std::vector<Header> chain = split_headers(img, 0, kFileInfoSize, nullptr);
    EXPECT(chain.size() == 1);
    const FileInfo f = read_file_info(chain[0]);
    EXPECT(f.version == 1);
    EXPECT(f.name_text() == "FILE_INFO");
    EXPECT(f.name_tail().empty());
    EXPECT(f.file_ver == 1 && f.file_type == 1 && f.flash_type == 5 && f.sig_type == 5);
    EXPECT(f.load_addr == 0x200f10 && f.max_size == 0x80000 && f.jump_offset == 0xF0 && f.processed == 3261071361u);
    EXPECT(f.hdr_size == 0xF0 && f.sig_size == 0x40 && f.total_size == 0xF0 + 1000 + 0x40);
    EXPECT(f.extra.empty());
    const Header again = write_file_info(f);
    EXPECT(again.version == chain[0].version && again.type == chain[0].type && again.body == chain[0].body);

    // The bytes behind the zero of the name are kept; a longer FILE_INFO keeps what is behind its 56 bytes.
    FileInfo g = f;
    g.name[10] = 'x';
    g.version = 2;
    g.extra = {1, 2, 3, 4, 5, 6, 7, 8};
    EXPECT(g.name_text() == "FILE_INFO");
    EXPECT(g.name_tail() == Bytes({'x'}));
    const Header longer = write_file_info(g);
    EXPECT(longer.size() == kFileInfoSize + 8 && longer.version == 2);
    const FileInfo h = read_file_info(longer);
    EXPECT(h.name == g.name && h.extra == g.extra && h.version == 2);

    Header not_it;
    not_it.type = kTypeBlInfo;
    not_it.body.assign(48, 0);
    EXPECT(throws([&] { read_file_info(not_it); }));
    Header short_one;
    short_one.type = kTypeFileInfo;
    short_one.body.assign(40, 0);
    EXPECT(throws([&] { read_file_info(short_one); }));
}

// ----------------------------------------------------------------------------------------------------------------- round trips --

void test_round_trips() {
    for (uint8_t sig_type : {uint8_t{0}, uint8_t{1}, uint8_t{3}, uint8_t{5}, uint8_t{9}}) {
        for (bool sec_key : {false, true}) {
            for (bool right_hash : {false, true}) {
                Spec s;
                s.sig_type = sig_type;
                s.sec_key = sec_key;
                s.right_hash = right_hash;
                s.sig = sig_type == kSigNone ? 0 : 0x124;
                const Bytes d = make_image(s);
                EXPECT(looks_like(d));
                EXPECT(problem(d).empty());
                const Image img = parse(d);
                EXPECT(img.at() == 0 && !img.device);
                EXPECT(img.consumed == d.size());
                EXPECT(img.chain.size() == (sec_key ? 6u : 5u));
                EXPECT(img.chain_pad.size() == (sec_key ? 0u : 4u));
                EXPECT(img.payload == pattern(1000, 5));
                EXPECT(img.sha256_trailer == (sig_type == kSigSha256 && right_hash));
                EXPECT(build(img) == d);
            }
        }
    }

    // The chain as it is in the file: the type names, in the order of the real loaders.
    Spec s;
    s.sec_key = true;
    s.sig_type = 3;
    s.sig = 0x124;
    s.load_addr = 0x200d00;
    s.max_size = 0x40000;
    const Image img = parse(make_image(s));
    const uint16_t want[] = {kTypeFileInfo, kTypeBlInfo, kTypeBromCfg, kTypeAntiClone, kTypeBromSecCfg, kTypeBlSecKey};
    bool order = img.chain.size() == 6;
    for (size_t i = 0; order && i < 6; ++i) order = img.chain[i].type == want[i];
    EXPECT(order);
    EXPECT(img.chain[2].size() == 100 && img.chain[5].size() == 0x214);
    EXPECT(img.signature == pattern(0x124, 201));
    EXPECT(read_file_info(img.chain[0]).hdr_size == 0x300);

    // A loader with nothing in it, and an image that is only FILE_INFO.
    Spec empty;
    empty.payload = 0;
    empty.sig = 0;
    empty.sig_type = 0;
    const Bytes e = make_image(empty);
    EXPECT(build(parse(e)) == e);
    EXPECT(parse(e).payload.empty() && parse(e).signature.empty());

    Bytes only = gfh(1, kTypeFileInfo, Bytes(48, 0));
    const char* name = "FILE_INFO";
    std::copy(name, name + 9, only.begin() + 8);
    put32(only, 32, 56);  // total_size
    put32(only, 40, 56);  // hdr_size
    const Image one = parse(only);
    EXPECT(one.chain.size() == 1 && one.chain_pad.empty() && one.payload.empty());
    EXPECT(build(one) == only);

    // Four bytes that begin like a header are padding when they are too few to be one.
    Spec spad;
    Bytes d = make_image(spad);
    const Image parsed = parse(d);
    EXPECT(parsed.chain_pad.size() == 4);
    Image changed = parsed;
    changed.chain_pad = {'M', 'M', 'M', 1};
    const Bytes b = build(changed);
    const Image back = parse(b);
    EXPECT(back.chain_pad == changed.chain_pad && back.chain.size() == parsed.chain.size());
}

// ------------------------------------------------------------------------------------------------------------------------ edits --

void test_edits() {
    Spec s;
    s.sig_type = 3;
    s.sig = 0x124;
    s.sec_key = true;
    const Bytes d = make_image(s);
    Image img = parse(d);

    // A longer loader: total_size follows, nothing else moves.
    img.payload.resize(1500, 0x5A);
    Bytes b = build(img);
    FileInfo f = read_file_info(parse(b).chain[0]);
    EXPECT(f.total_size == 0x300 + 1500 + 0x124 && f.hdr_size == 0x300 && f.sig_size == 0x124);
    EXPECT(b.size() == f.total_size);
    EXPECT(parse(b).payload == img.payload && parse(b).signature == img.signature);

    // A header more in the chain: hdr_size follows.
    Image more = parse(d);
    Header extra;
    extra.version = 2;
    extra.type = 0x20;
    extra.body = {1, 2, 3, 4};
    more.chain.push_back(extra);
    b = build(more);
    f = read_file_info(parse(b).chain[0]);
    EXPECT(f.hdr_size == 0x300 + 12 && f.total_size == 0x300 + 12 + 1000 + 0x124);
    const Image reread = parse(b);
    EXPECT(reread.chain.size() == 7 && reread.chain[6].type == 0x20 && reread.chain[6].version == 2 && reread.chain[6].body == extra.body);
    EXPECT(type_name(reread.chain[6].type) == "type 32");

    // Another signature: sig_size follows.
    Image resigned = parse(d);
    resigned.signature = pattern(0x66c, 9);
    b = build(resigned);
    f = read_file_info(parse(b).chain[0]);
    EXPECT(f.sig_size == 0x66c && f.total_size == 0x300 + 1000 + 0x66c && parse(b).signature == resigned.signature);

    // The padding behind the chain.
    Image padded = parse(make_image(Spec{}));
    padded.chain_pad.assign(12, 0);
    b = build(padded);
    EXPECT(read_file_info(parse(b).chain[0]).hdr_size == 0xEC + 12);
    EXPECT(parse(b).chain_pad.size() == 12);

    // What FILE_INFO holds that is not a size is what the manifest says.
    Image tuned = parse(d);
    FileInfo t = read_file_info(tuned.chain[0]);
    t.load_addr = 0x201000;
    t.max_size = 0x100000;
    t.jump_offset = 0x40;
    tuned.chain[0] = write_file_info(t);
    b = build(tuned);
    const FileInfo u = read_file_info(parse(b).chain[0]);
    EXPECT(u.load_addr == 0x201000 && u.max_size == 0x100000 && u.jump_offset == 0x40 && u.total_size == t.total_size);

    // A chain that does not start with FILE_INFO cannot be built.
    Image no_info = parse(d);
    no_info.chain.erase(no_info.chain.begin());
    EXPECT(throws([&] { build(no_info); }));
    Image nothing;
    EXPECT(throws([&] { build(nothing); }));
    // A header whose size does not fit in 16 bits.
    Image huge = parse(d);
    Header big;
    big.type = 0x30;
    big.body.assign(0x10000, 0);
    huge.chain.push_back(big);
    EXPECT(throws([&] { build(huge); }));
}

// ---------------------------------------------------------------------------------------------------------------------- SHA-256 --

void test_sha256() {
    Spec s;
    s.sig_type = kSigSha256;
    s.right_hash = true;
    const Bytes d = make_image(s);
    Image img = parse(d);
    EXPECT(img.sha256_trailer && img.signature.size() == 32);
    EXPECT(build(img) == d);

    // Edited: the hash is made again, and is the hash of everything before it.
    img.payload[10] ^= 0x55;
    img.payload.push_back(9);
    const Bytes b = build(img);
    EXPECT(b.size() == d.size() + 1);
    const Bytes want = hash::sha256(b.data(), b.size() - 32);
    EXPECT(Bytes(b.end() - 32, b.end()) == want);
    const Image again = parse(b);
    EXPECT(again.sha256_trailer);
    EXPECT(read_file_info(again.chain[0]).sig_size == 32);

    // A change in the headers goes into the hash too.
    Image tuned = parse(d);
    FileInfo f = read_file_info(tuned.chain[0]);
    f.load_addr += 0x100;
    tuned.chain[0] = write_file_info(f);
    const Bytes t = build(tuned);
    EXPECT(Bytes(t.end() - 32, t.end()) == hash::sha256(t.data(), t.size() - 32));
    EXPECT(Bytes(t.end() - 32, t.end()) != Bytes(d.end() - 32, d.end()));

    // sig_type 1 where the 32 bytes are not the hash: they stay as they were, whatever is edited.
    Spec wrong;
    wrong.sig_type = kSigSha256;
    wrong.right_hash = false;
    wrong.sig = 32;
    const Bytes w = make_image(wrong);
    Image wi = parse(w);
    EXPECT(!wi.sha256_trailer && wi.signature == pattern(32, 201));
    wi.payload[0] ^= 1;
    const Bytes wb = build(wi);
    EXPECT(Bytes(wb.end() - 32, wb.end()) == pattern(32, 201));

    // Another size of signature is not a hash.
    Spec other;
    other.sig_type = kSigSha256;
    other.right_hash = false;
    other.sig = 48;
    EXPECT(!parse(make_image(other)).sha256_trailer);

    // A hash that was true and is made false by hand (sha256_trailer cleared): the bytes that are in `signature` are written.
    Image manual = parse(d);
    manual.sha256_trailer = false;
    manual.payload[3] ^= 0xFF;
    const Bytes mb = build(manual);
    EXPECT(Bytes(mb.end() - 32, mb.end()) == manual.signature);

    // With a device header in front, the hash starts at the chain.
    Spec ps;
    ps.sig_type = kSigSha256;
    ps.right_hash = true;
    const Bytes p = make_partition_image(ps);
    Image pi = parse(p);
    EXPECT(pi.sha256_trailer && pi.at() == 0x800);
    pi.payload.push_back(1);
    const Bytes pb = build(pi);
    EXPECT(Bytes(pb.end() - 32, pb.end()) == hash::sha256(pb.data() + 0x800, pb.size() - 0x800 - 32));
}

// --------------------------------------------------------------------------------------------------------- image of a partition --

void test_device() {
    const Bytes d = make_partition_image(Spec{});
    std::optional<Device> dev;
    const std::optional<size_t> at = find_chain(d, &dev);
    EXPECT(at && *at == 0x800);
    EXPECT(dev && dev->boot_name == "EMMC_BOOT" && dev->boot_version == 1 && dev->boot_size == 0x200);
    EXPECT(dev && dev->version == 1 && dev->header_size == 0x800 && dev->header_size_2 == 0x800 && dev->magic == kBrlytMagic);
    EXPECT(dev && dev->type == kBrlytEmmc && dev->total_size == d.size() && dev->total_size_2 == d.size() && dev->unused == 1);
    EXPECT(looks_like(d));
    EXPECT(d.size() % 0x200 == 0);

    const Image img = parse(d);
    EXPECT(img.at() == 0x800 && img.prefix.size() == 0x800 && img.device);
    // The device header and the BRLYT are read from the prefix alone, too.
    const std::optional<Device> from_prefix = parse_device(img.prefix);
    EXPECT(from_prefix && from_prefix->boot_name == "EMMC_BOOT" && from_prefix->header_size == 0x800 && from_prefix->total_size == d.size());
    EXPECT(!parse_device(Bytes(img.prefix.begin(), img.prefix.begin() + 0x227)));
    EXPECT(!parse_device(make_image(Spec{})));
    EXPECT(!parse_device({}));
    EXPECT(img.consumed < d.size() && d.size() - img.consumed < 0x200);
    EXPECT(img.basis == SizeBasis::File);
    EXPECT(std::equal(img.prefix.begin(), img.prefix.end(), d.begin()));
    // build() gives the file up to the end of the signature; the fill behind it is the caller's.
    Bytes b = build(img);
    EXPECT(b.size() == img.consumed && std::equal(b.begin(), b.end(), d.begin()));

    // The loader grows: the sizes of the BRLYT follow the file (File), after the caller made it a multiple of 0x200.
    Image grown = img;
    grown.payload.resize(grown.payload.size() + 700, 0x33);
    b = build(grown);
    b.resize((b.size() + 0x1FF) / 0x200 * 0x200, 0xFF);
    fix_device(b, grown);
    EXPECT(get32(b, 0x200 + 16) == b.size() && get32(b, 0x200 + 32) == b.size());
    EXPECT(get32(b, 0x200 + 12) == 0x800 && get32(b, 0x200 + 28) == 0x800);
    EXPECT(parse(b).device->total_size == b.size() && parse(b).basis == SizeBasis::File);
    EXPECT(parse(b).payload == grown.payload);

    // Untouched, the BRLYT comes back as it was.
    Bytes same = build(img);
    same.resize(d.size(), 0xFF);
    fix_device(same, img);
    EXPECT(same == d);

    // The sizes of the BRLYT that are the end of the loader (a file that was not rounded up and has something after it).
    Bytes chain_total = make_partition_image(Spec{}, "EMMC_BOOT", kBrlytEmmc, /*total_is_file=*/false);
    chain_total.resize(chain_total.size() + 0x300, 0xFF);
    const Image ci = parse(chain_total);
    EXPECT(ci.basis == SizeBasis::Chain);
    Image cg = ci;
    cg.payload.resize(cg.payload.size() + 50, 1);
    b = build(cg);
    const size_t end = b.size();
    b.resize(end + 0x400, 0xFF);
    fix_device(b, cg);
    EXPECT(get32(b, 0x200 + 16) == end && get32(b, 0x200 + 32) == end);

    // Sizes that are neither: kept.
    Bytes odd = make_partition_image(Spec{});
    put32(odd, 0x200 + 16, 12345);
    put32(odd, 0x200 + 32, 12345);
    const Image oi = parse(odd);
    EXPECT(oi.basis == SizeBasis::Literal);
    Image og = oi;
    og.payload.resize(og.payload.size() + 10, 0);
    b = build(og);
    b.resize(b.size() + 100, 0xFF);
    fix_device(b, og);
    EXPECT(get32(b, 0x200 + 16) == 12345 && get32(b, 0x200 + 32) == 12345);
    // Two sizes that differ from each other: kept as well.
    Bytes two = make_partition_image(Spec{});
    put32(two, 0x200 + 32, get32(two, 0x200 + 32) + 0x200);
    EXPECT(parse(two).basis == SizeBasis::Literal);

    // An image without a BRLYT has nothing to fix.
    const Bytes raw = make_image(Spec{});
    Bytes rb = build(parse(raw));
    fix_device(rb, parse(raw));
    EXPECT(rb == raw);

    // The other boot media and the other kinds of BRLYT.
    for (const char* name : {"SF_BOOT", "SDMMC_BOOT"}) {
        const Bytes x = make_partition_image(Spec{}, name, name[0] == 'S' && name[1] == 'F' ? kBrlytNor : kBrlytSdmmc);
        std::optional<Device> v;
        EXPECT(find_chain(x, &v) == std::optional<size_t>(0x800));
        EXPECT(v && v->boot_name == name);
        EXPECT(build(parse(x)).size() == parse(x).consumed);
    }
    EXPECT(!find_chain(make_partition_image(Spec{}, "EMMC_BOOT", kBrlytNand)));        // the NAND ones have another layout
    EXPECT(!find_chain(make_partition_image(Spec{}, "EMMC_BOOT", 0x10006)));
    EXPECT(!find_chain(make_partition_image(Spec{}, "SPI_BOOT", kBrlytEmmc)));

    // The BRLYT is what says where the chain is.
    Bytes moved = make_partition_image(Spec{});
    put32(moved, 0x200 + 12, 0x900);
    EXPECT(!find_chain(moved) && !looks_like(moved));
    put32(moved, 0x200 + 12, 0x10);  // inside the BRLYT
    EXPECT(!find_chain(moved));
    put32(moved, 0x200 + 12, static_cast<uint32_t>(moved.size() + 5));
    EXPECT(!find_chain(moved));
    Bytes bad_version = make_partition_image(Spec{});
    put32(bad_version, 12, 2);
    EXPECT(!find_chain(bad_version));
    Bytes bad_size = make_partition_image(Spec{});
    put32(bad_size, 16, 0x100);
    EXPECT(!find_chain(bad_size));
    Bytes bad_magic = make_partition_image(Spec{});
    put32(bad_magic, 0x200 + 20, 0x43434343);
    EXPECT(!find_chain(bad_magic));
    Bytes bad_name = make_partition_image(Spec{});
    bad_name[0x200] = 'X';
    EXPECT(!find_chain(bad_name));
    // The name of the boot media must end where U-Boot's strcmp wants it to.
    Bytes long_name = make_partition_image(Spec{});
    for (size_t i = 9; i < 12; ++i) long_name[i] = 'X';
    EXPECT(!find_chain(long_name));
}

// ---------------------------------------------------------------------------------------------------------------------- damaged --

void test_damaged() {
    Spec s;
    s.sig_type = 3;
    s.sig = 0x124;
    s.sec_key = true;
    const Bytes d = make_image(s);

    // Cut short at every place.
    bool all_refused = true, all_explained = true;
    for (size_t n = 0; n < d.size(); ++n) {
        const Bytes cut(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(n));
        if (looks_like(cut)) all_refused = false;
        if (!throws([&] { (void)parse(cut); })) all_refused = false;
        if (n >= kFileInfoSize && problem(cut).empty()) all_explained = false;
    }
    EXPECT(all_refused);
    EXPECT(all_explained);
    EXPECT(problem(Bytes(d.begin(), d.end() - 1)).find("cut short") != std::string::npos);
    // After the end: the loader is all that the sizes say, the rest is not its.
    Bytes longer = d;
    longer.insert(longer.end(), 100, 0xFF);
    EXPECT(looks_like(longer) && parse(longer).consumed == d.size());

    // Sizes that do not agree.
    Bytes b = d;
    put32(b, 40, 0x10);  // hdr_size below the FILE_INFO header
    EXPECT(!looks_like(b) && !problem(b).empty() && throws([&] { (void)parse(b); }));
    b = d;
    put32(b, 44, 0x10000);  // sig_size above what total_size holds
    EXPECT(!looks_like(b) && !problem(b).empty() && throws([&] { (void)parse(b); }));
    b = d;
    put32(b, 32, 0xFFFFFFF0u);  // total_size beyond the file
    EXPECT(!looks_like(b) && !problem(b).empty() && throws([&] { (void)parse(b); }));
    b = d;
    put32(b, 40, 0x2F0);  // hdr_size shorter than the chain: the last header goes beyond it
    EXPECT(looks_like(b));
    EXPECT(throws([&] { (void)parse(b); }));
    b = d;
    put32(b, 40, 0x304);  // four more: they are padding
    EXPECT(looks_like(b) && parse(b).chain_pad.size() == 4);

    // Headers: a size below eight, one that goes beyond the others, a name that is not FILE_INFO, a version in the magic.
    b = d;
    b[kFileInfoSize + 4] = 4;  // BL_INFO says 4 bytes
    EXPECT(throws([&] { (void)parse(b); }));
    b = d;
    b[kFileInfoSize + 4] = 0xFF;  // BL_INFO says 255 bytes: still inside hdr_size, the chain is wrong though
    EXPECT(parse(b).chain.size() != parse(d).chain.size() || parse(b).chain_pad != parse(d).chain_pad);
    b = d;
    b[8] = 'f';  // FILE_INFO -> file_INFO
    EXPECT(!looks_like(b) && !find_chain(b));
    b = d;
    b[6] = 1;  // the type of the first header is not 0
    EXPECT(!find_chain(b));
    b = d;
    b[4] = 40;  // a FILE_INFO that says it is shorter than 56
    EXPECT(!find_chain(b));
    b = d;
    b[3] = 0x7F;  // another version is fine
    EXPECT(looks_like(b) && parse(b).chain[0].version == 0x7F && build(parse(b)) == b);
    b = d;
    b[0] = 'N';
    EXPECT(!find_chain(b));

    // A header size that does not fit in the headers (and nothing else is wrong).
    Bytes tooshort = d;
    put32(tooshort, 40, 0x100);  // the headers end in the middle of BL_SEC_KEY
    EXPECT(throws([&] { (void)parse(tooshort); }));

    // What is not a loader.
    EXPECT(!looks_like({}));
    EXPECT(!looks_like(Bytes(100, 0)));
    EXPECT(!looks_like(Bytes(0x1000, 0xFF)));
    EXPECT(!find_chain(Bytes(0x1000, 0)));
    EXPECT(problem(Bytes(0x1000, 0)).empty());
    EXPECT(throws([&] { (void)parse(Bytes(0x100, 0)); }));
    EXPECT(throws([&] { (void)parse({}); }));
    // "MMM" and the rest of a FILE_INFO, but nothing in it that holds together.
    Bytes junk(0x100, 0);
    const Bytes fi = gfh(1, kTypeFileInfo, Bytes(48, 0));
    std::copy(fi.begin(), fi.end(), junk.begin());
    const char* name = "FILE_INFO";
    std::copy(name, name + 9, junk.begin() + 8);
    EXPECT(find_chain(junk) && !looks_like(junk));  // hdr_size 0 is below the header
}

// ---------------------------------------------------------------------------------------------------------------------- headers --

void test_split_headers() {
    Bytes d;
    for (int i = 0; i < 5; ++i) {
        const Bytes h = gfh(static_cast<uint8_t>(i), static_cast<uint16_t>(10 + i), pattern(static_cast<size_t>(4 + i), 1));
        d.insert(d.end(), h.begin(), h.end());
    }
    d.insert(d.end(), {9, 9, 9});
    Bytes pad;
    std::vector<Header> v = split_headers(d, 0, d.size(), &pad);
    EXPECT(v.size() == 5 && pad == Bytes({9, 9, 9}));
    EXPECT(v[3].version == 3 && v[3].type == 13 && v[3].body == pattern(7, 1));
    EXPECT(serialize_headers(v) == Bytes(d.begin(), d.end() - 3));
    EXPECT(serialize_headers(v, 2) == Bytes(d.begin() + 8 + 4 + 8 + 5, d.end() - 3));
    EXPECT(serialize_headers(v, 5).empty() && serialize_headers({}).empty());

    // `to` ends the headers where it is: a header that goes beyond it is an error, what is behind it is not read.
    EXPECT(throws([&] { (void)split_headers(d, 0, 20, nullptr); }));
    v = split_headers(d, 0, 12, &pad);
    EXPECT(v.size() == 1 && pad.empty());
    v = split_headers(d, 0, 12 + 3, &pad);
    EXPECT(v.size() == 1 && pad.size() == 3);
    EXPECT(split_headers(d, 0, 0, &pad).empty() && pad.empty());
    EXPECT(split_headers(d, 4, 20, &pad).empty() && pad.size() == 16);  // nothing starts there

    // A size below eight.
    Bytes tiny = gfh(1, 1, Bytes(4, 0));
    tiny[4] = 7;
    EXPECT(throws([&] { (void)split_headers(tiny, 0, tiny.size(), nullptr); }));
    tiny[4] = 0;
    EXPECT(throws([&] { (void)split_headers(tiny, 0, tiny.size(), nullptr); }));
    // A header of eight bytes is a header (no body).
    const Bytes bare = gfh(1, 0x44, {});
    v = split_headers(bare, 0, bare.size(), nullptr);
    EXPECT(v.size() == 1 && v[0].body.empty() && v[0].size() == 8 && v[0].type == 0x44);

    // More than 64 in a row.
    Bytes many;
    for (int i = 0; i < 64; ++i) {
        const Bytes h = gfh(1, 5, {});
        many.insert(many.end(), h.begin(), h.end());
    }
    EXPECT(split_headers(many, 0, many.size(), nullptr).size() == 64);
    const Bytes one_more = gfh(1, 5, {});
    many.insert(many.end(), one_more.begin(), one_more.end());
    EXPECT(throws([&] { (void)split_headers(many, 0, many.size(), nullptr); }));
}

void test_describe() {
    Header cfg;
    cfg.type = kTypeBromCfg;
    cfg.body.assign(92, 0);
    put32(cfg.body, 0, 0x90 | 0x2 | 0x100 | 0x1000 | 0x40000);
    put32(cfg.body, 4, 100);
    cfg.body[85 - 8] = 0x64;
    put32(cfg.body, 80, 5000);
    put32(cfg.body, 84, 3000);
    const std::string c = describe(cfg);
    EXPECT(c.find("cfg_bits 0x41192") != std::string::npos);
    EXPECT(c.find("usbdl_by_auto_detect_timeout_en") != std::string::npos);
    EXPECT(c.find("usbdl_auto_detect_dis") != std::string::npos);
    EXPECT(c.find("usbdl_by_kcol0_timeout_en") != std::string::npos);
    EXPECT(c.find("usbdl_by_flag_timeout_en") != std::string::npos);
    EXPECT(c.find("jump_bl_arm64_en") != std::string::npos);
    EXPECT(c.find("other bits 0x40000") != std::string::npos);
    EXPECT(c.find("usbdl_by_auto_detect_timeout_ms 100") != std::string::npos);
    EXPECT(c.find("jump_bl_arm64 0x64") != std::string::npos);
    EXPECT(c.find("usbdl_by_kcol0_timeout_ms 5000") != std::string::npos);
    EXPECT(c.find("usbdl_by_flag_timeout_ms 3000") != std::string::npos);

    Header sec;
    sec.type = kTypeBromSecCfg;
    sec.body.assign(40, 0);
    put32(sec.body, 0, 3);
    sec.body[4] = 'A';
    sec.body[5] = 'c';
    sec.body[6] = 'm';
    sec.body[7] = 'e';
    const std::string t = describe(sec);
    EXPECT(t.find("cfg_bits 0x3 (jtag_en, uart_en)") != std::string::npos && t.find("customer_name \"Acme\"") != std::string::npos);
    sec.body[0] = 0;
    EXPECT(describe(sec).find("cfg_bits 0x0,") != std::string::npos);

    Header ac;
    ac.type = kTypeAntiClone;
    ac.body.assign(12, 0);
    put32(ac.body, 4, 0x10);
    put32(ac.body, 8, 0x80);
    EXPECT(describe(ac) == "ac_b2k 0, ac_b2c 0, ac_offset 0x10, ac_len 0x80");

    Header bl;
    bl.type = kTypeBlInfo;
    bl.body = {1, 0, 0, 0};
    EXPECT(describe(bl) == "attr 0x1");

    // A header of a kind without names, or one that is shorter than its kind: nothing to say.
    Header key;
    key.type = kTypeBlSecKey;
    key.body.assign(0x20c, 0);
    EXPECT(describe(key).empty());
    Header odd;
    odd.type = 77;
    odd.body.assign(3, 0);
    EXPECT(describe(odd).empty());
    Header cut;
    cut.type = kTypeBromCfg;
    cut.body.assign(10, 0);
    EXPECT(describe(cut).empty());
    Header cut_sec;
    cut_sec.type = kTypeBromSecCfg;
    cut_sec.body.assign(20, 0);
    EXPECT(describe(cut_sec).empty());
    Header cut_ac;
    cut_ac.type = kTypeAntiClone;
    cut_ac.body.assign(8, 0);
    EXPECT(describe(cut_ac).empty());
    Header cut_bl;
    cut_bl.type = kTypeBlInfo;
    cut_bl.body.assign(2, 0);
    EXPECT(describe(cut_bl).empty());
}

void test_marker() {
    Bytes code = pattern(500, 3);
    EXPECT(!find_bloader_marker(code));
    const std::string text = "MTK_BLOADER_INFO_v35";
    std::copy(text.begin(), text.end(), code.begin() + 400);
    const std::optional<Marker> m = find_bloader_marker(code);
    EXPECT(m && m->offset == 400 && m->text == "MTK_BLOADER_INFO_v35");
    // The digits are at most four, and none is none.
    Bytes long_digits(100, 0);
    const std::string t2 = "MTK_BLOADER_INFO_v1234567";
    std::copy(t2.begin(), t2.end(), long_digits.begin() + 10);
    EXPECT(find_bloader_marker(long_digits) && find_bloader_marker(long_digits)->text == "MTK_BLOADER_INFO_v1234");
    Bytes bare(100, 0);
    const std::string t3 = "MTK_BLOADER_INFO_v";
    std::copy(t3.begin(), t3.end(), bare.begin() + 5);
    EXPECT(find_bloader_marker(bare) && find_bloader_marker(bare)->text == "MTK_BLOADER_INFO_v" && find_bloader_marker(bare)->offset == 5);
    // At the very end of the data, and cut short in the middle of the text.
    Bytes end_of(30, 0);
    std::copy(text.begin(), text.end(), end_of.begin() + 10);
    EXPECT(find_bloader_marker(end_of) && find_bloader_marker(end_of)->text == "MTK_BLOADER_INFO_v35");
    EXPECT(!find_bloader_marker(Bytes(text.begin(), text.begin() + 12)));
    EXPECT(!find_bloader_marker({}));
}

}  // namespace

int run_mtkgfh_tests() {
    test_names();
    test_file_info();
    test_round_trips();
    test_edits();
    test_sha256();
    test_device();
    test_damaged();
    test_split_headers();
    test_describe();
    test_marker();
    if (g_failures == 0) std::printf("mtkgfh: ok (%d checks)\n", g_checks);
    else std::printf("mtkgfh: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
