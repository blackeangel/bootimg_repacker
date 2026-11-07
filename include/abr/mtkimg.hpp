// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::mtkimg -- the container that MediaTek puts around the small images of its phones: lk, logo, tee, scp, sspm, spmfw, md1img (the modem) and
// the rest of that kind. An image is one or more sections; a section is a header of 512 bytes (the partition header of MediaTek's boot loader, the
// same that sits in front of the kernel and the ramdisk of an MTK boot image), its data, and padding up to the next header:
//
//     0   u32  magic 0x58881688 (the bytes 88 16 88 58)
//     4   u32  size of the data (the low 32 bits)
//     8   32   name, text ("logo", "md1rom", "tee", ...), the rest of the field zero
//    40   u32  load address of the data (the low 32 bits)
//    44   u32  mode (where the address counts from: 0xFFFFFFFF in the images that do not say)
//    48   u32  0x58891689: the header has the extension that follows -- or 0xFFFFFFFF in a header that is the older kind (and bytes 48 to 511
//              are all 0xFF)
//    52   u32  size of the header, 512
//    56   u32  version of the header
//    60   u32  type of the image
//    64   u32  1 in the last section of a list, 0 in the others
//    68   u32  alignment of the data in bytes (16 where nobody says: the encryption works in blocks of 16)
//    72   u32  size of the data, the high 32 bits (images of 4 GiB and more)
//    76   u32  load address, the high 32 bits
//    80   432  0xFF
//
// The data of a section that follows another begins at the next multiple of the alignment behind the data of the one before. The file may go on
// after the last section (fill up to the size of the partition).
//
// The sources of these fields are the loader of the phone itself (its part_hdr_t) and the md1img tool that precedes this one
// (github.com/blackeangel/md1img_repacker), which reads and writes the same header; what this file adds is every field of the header kept as
// it is (nothing is lost that abr does not know), the alignment taken from the image, and the padding between the sections kept.
//
// A section named "logo" holds a table of pictures (see Logo below): the number of them, the size of the whole, where each begins, and the
// pictures one behind the other, each a zlib stream of raw pixels (or raw pixels, where nobody compressed them).
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::mtkimg {

inline constexpr uint32_t kMagic = 0x58881688;
inline constexpr uint32_t kExtMagic = 0x58891689;
inline constexpr size_t kHeaderSize = 512;
inline constexpr uint32_t kAny = 0xFFFFFFFFu;  // what a field of a header holds that has nothing to say

struct Header {
    uint32_t dsize = 0;                    // the low 32 bits of the size of the data (build() writes the real size)
    std::array<uint8_t, 32> name{};        // as it is in the file
    uint32_t maddr = kAny, mode = kAny;
    uint32_t ext_magic = kAny, hdr_size = kAny, hdr_version = kAny, img_type = kAny, img_list_end = kAny, align_size = kAny, dsize_extend = kAny,
             maddr_extend = kAny;
    Bytes reserved = Bytes(kHeaderSize - 80, 0xFF);  // bytes 80 to 511

    bool extended() const { return ext_magic == kExtMagic; }
    // The name up to its first zero byte.
    std::string name_text() const;
    // The bytes of the name field behind that zero (empty when they are all zero, as they are in a header that was made by a tool).
    Bytes name_tail() const;
    void set_name(std::string_view text, const Bytes& tail = {});
    // The size of the data: the low and the high word when the header is extended.
    uint64_t data_size() const { return extended() && dsize_extend != kAny ? (uint64_t{dsize_extend} << 32) | dsize : dsize; }
    // The alignment of the sections: what the header says if that is a number a loader could use (4 to 65536, a power of two), else 16.
    uint32_t alignment() const;
    // A header of a new section: the extension is there, version and type unset, the alignment 16.
    static Header fresh(std::string_view name);
};

struct Section {
    Header header;
    Bytes data;
    Bytes pad;  // the bytes between the data and the next header; empty in the last section
    uint32_t align = 16;  // the alignment that the position of the next header follows (the header's own, or the one that the image shows)
};

struct Chain {
    std::vector<Section> sections;
    size_t consumed = 0;  // the end of the data of the last section: what the file holds behind it is not part of the chain
};

// A header at `at` that is believable: the magic, a name of printable text, the extension (when it is there) saying 512, a size that fits in the
// bytes that are left.
bool looks_like(const Bytes& d, size_t at = 0);

Header parse_header(const Bytes& d, size_t at);
Bytes serialize_header(const Header& h);

// The sections from offset 0: a FormatError when the first one is no section or is cut short; a header behind a section that is not one
// ends the chain (what is left is the padding of the file).
Chain parse(const Bytes& d);

// The file: every header (with the size of its data as it is now), data and pad, one after the other.
Bytes build(const Chain& chain);

// How many bytes of padding put `end` (the offset behind some data) on a multiple of `align`.
size_t pad_length(uint64_t end, uint32_t align);

// ------------------------------------------------------------------------------------------------------------------ the logo table --

struct Logo {
    std::vector<Bytes> pictures;  // each picture as stored: the bytes from its offset to the next one (a zlib stream, with what follows it)
};

// The data of a section that is a table of pictures, or nullopt when it is not one: the number of pictures (1 to 4096), the size of the whole that is
// the size of the data, the first offset right behind the table, the offsets rising and inside the data.
std::optional<Logo> parse_logo(const Bytes& data);
Bytes build_logo(const std::vector<Bytes>& pictures);

// -------------------------------------------------------------------------------------------------------------------------- pixels --

enum class PixelFormat { BGRA8888, RGBA8888, RGB565, BGR888, RGB888 };

std::string_view format_name(PixelFormat f);
std::optional<PixelFormat> format_from_name(std::string_view name);
size_t bytes_per_pixel(PixelFormat f);

struct Resolution {
    uint32_t width = 0, height = 0;
};

// The resolution that a picture of `pixels` pixels has, from a table of the sizes that the logos of MediaTek phones have (the pictures of a
// logo.bin do not say how wide they are): the first of the table, which lists the portrait one before the landscape one of the same area.
std::optional<Resolution> guess_resolution(uint64_t pixels);

// The format that explains most of the sizes (the numbers of bytes of the pictures): 4 bytes per pixel (BGRA), 2 (RGB565) or 3 (BGR), the one
// whose pixel counts are most often in the table of resolutions; BGRA when none is.
PixelFormat guess_format(const std::vector<size_t>& sizes);

// `raw` is width * height * bytes_per_pixel(f) bytes. 32-bit formats keep their alpha; the others are opaque.
Bytes pixels_to_rgba(PixelFormat f, const Bytes& raw, uint32_t width, uint32_t height);
// The other way. The alpha of a format that has it is that of `rgba`, or `alpha` where `with_alpha` is false (a PNG that has no alpha channel).
Bytes rgba_to_pixels(PixelFormat f, const Bytes& rgba, uint32_t width, uint32_t height, bool with_alpha, uint8_t alpha);
// All the pixels of a 32-bit picture have the same alpha: that alpha (the PNG of such a picture has no alpha channel); nullopt otherwise or for the other formats.
std::optional<uint8_t> constant_alpha(PixelFormat f, const Bytes& raw);

}  // namespace abr::mtkimg
