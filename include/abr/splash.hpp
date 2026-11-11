// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::splash -- the pictures that the boot loader of a phone shows before Android starts, as they lie in the partitions `splash` and `logo`
// of Qualcomm phones. Four containers are read here, each by what its own tool writes (the tools are public; they are named where the
// container is described, and none of their code is in abr):
//
//   * Qualcomm's own "SPLASH!!" image, the one that logo_gen.py of the QRD reference design (source.codeaurora.org/quic/la/device/qcom/common,
//     display/logo) makes: a header of 512 bytes and one picture. A longer form of the same header holds several pictures (seen in the
//     boot loader of the OPPO Watch 2, described in github.com/MlgmXyysd/Magic-Splash-Wand). The pictures are stored as pixels (blue,
//     green, red; the rows from the top) or run-length coded (RLE24, below).
//   * the OPLUS "SPLASH LOGO!" image of OPPO, realme and OnePlus phones: 0x4000 bytes that hold a header of the signing ("DDPH") or nothing,
//     a header of 0x4000 bytes with a table of named pictures, and the pictures from 0x8000 on, each a BMP file (gzip is usual). Described by
//     Magic-Splash-Wand and by github.com/LyraVoid/FolkSplash, which read the same table.
//   * the Xiaomi / Redmi "LOGO!!!!" image (MIUI before 13): 0x4000 bytes in front, a table of 4 KiB with the offset and the size of each picture
//     in units of 4096 bytes, the pictures behind it -- BMP files, but PNG in some (github.com/msdos03/xiaomi-bootlogo-editor).
//   * the Motorola "MotoLogo" image: a table of 24-byte names with the offset and the size of each picture, the pictures at multiples of 512
//     bytes. A picture is usually a "MotoRun" image, run-length coded (github.com/eriktim/moto-bootlogo, from the script of carock).
//
// What this file holds is the reading and the writing of the containers and of the two run-length codings, with every field kept as it is
// (what abr does not know it does not lose) and the places of the pictures worked out again when a picture changes its size. The pictures
// themselves are `Bitmap`s: three bytes a pixel, blue first, which is how both codings and the "raw" form of Qualcomm's image keep them. No
// image of a phone was at hand when this was written: what is here is what the sources above say, and what their own tools write is what the
// tests of abr read back.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::splash {

// A picture is no wider or higher than this, and holds no more pixels than kMaxPixels (a screen of a phone is not near them; what a
// header may ask of the memory is decided here).
inline constexpr uint32_t kMaxSide = 16384;
inline constexpr uint64_t kMaxPixels = uint64_t{1} << 26;

// ------------------------------------------------------------------------------------------------------------------------- pictures --

// `bgr` is width * height * 3 bytes: blue, green, red of each pixel, the rows from the top, no padding between the rows.
struct Bitmap {
    uint32_t width = 0, height = 0;
    Bytes bgr;
};

// A picture from the RGBA pixels of a PNG (`rgba` is width * height * 4 bytes). Colours that are not opaque are put on black, the way
// Qualcomm's logo_gen.py does it (a pixel is as bright as its alpha lets it be).
Bitmap bitmap_from_rgba(const Bytes& rgba, uint32_t width, uint32_t height);
// The RGBA pixels of a picture, all opaque.
Bytes bitmap_to_rgba(const Bitmap& bmp);

// ---- RLE24: the coding of the pixels in the "SPLASH!!" image of Qualcomm (type 1)
//
// Packets one behind the other, no packet crossing the end of a row where a tool makes them: a byte, `(c & 0x7F) + 1` is the number of
// pixels; with bit 7 set one pixel (three bytes) follows and is repeated that many times, with bit 7 clear that many pixels follow.
// The longest packet is 128 pixels.

// The packets of a picture: the rows one after another, a run of equal pixels (two or more) is one packet, the pixels between two runs are
// one packet (or several, 128 at the most each). Rows are coded on several threads.
Bytes rle24_encode(const Bytes& bgr, uint32_t width, uint32_t height);
// The pixels of the stream at data[0, size): exactly width * height of them. `used` (when given) is how many bytes of the stream they take.
// FormatError for a stream that ends before the picture is whole, or one whose packet goes beyond it.
Bytes rle24_decode(const uint8_t* data, size_t size, uint32_t width, uint32_t height, size_t* used = nullptr);

// ---- "MotoRun": the coding of a picture of a Motorola logo
//
//   0   "MotoRun" and a zero byte
//   8   u16 width, big endian
//  10   u16 height, big endian
//  12   packets until the end: a byte whose bits 4 to 6 are zero -- bit 7 set: one pixel follows and is repeated, clear: that many pixels
//       follow -- and the low 4 bits of it and the next byte make the number of pixels (12 bits, big endian)
inline constexpr size_t kMotoHeaderSize = 12;
inline constexpr uint32_t kMotoMaxSide = 0xFFFF;
// nullopt for bytes that are no such picture: another magic, no size, a packet that is not one, pixels that are not exactly width * height.
std::optional<Bitmap> moto_decode(const Bytes& data);
// `bmp` is at most 65535 pixels wide and high. Runs of three equal pixels and more are one packet, none crosses the end of a row.
Bytes moto_encode(const Bitmap& bmp);

// ---------------------------------------------------------------------------------------------- Qualcomm's "SPLASH!!" image --
//
//   single picture                               several pictures
//   0   "SPLASH!!"                               0   "SPLASH!!"
//   8   u32 width                                8   u32 count (1 to 25)
//  12   u32 height                              12   count times, 20 bytes each: u32 width, u32 height, u32 type, u32 blocks, u32 offset
//  16   u32 type: 0 pixels, 1 RLE24
//  20   u32 blocks: the size of the data in blocks of 512 bytes, rounded up
//  24   zeros up to 512                              zeros up to 512
// 512   the data                                offset   the data of each picture, one behind the other from 512 (offset in bytes)
//
// The data of a picture is its pixels (width * height * 3 bytes) or its RLE24 packets. What follows it up to the block is padding;
// the file may end in the middle of the last block (logo_gen.py writes no padding) and may go on behind the last one (a partition).
// The single picture may say 0 blocks -- the images of Qualcomm's own (the mm_splash.img and lp_splash.img of its sample images, 1080x1920
// pixels) do -- and then its data is exactly the pixels, or the packets that make the picture; a table has no entry of 0 blocks.

inline constexpr char kQcMagic[8] = {'S', 'P', 'L', 'A', 'S', 'H', '!', '!'};
inline constexpr size_t kQcHeaderSize = 512;
inline constexpr size_t kQcBlock = 512;
inline constexpr uint32_t kQcMaxPictures = 25;  // (512 - 12) / 20
inline constexpr uint32_t kQcRaw = 0, kQcRle24 = 1;

struct QcPicture {
    uint32_t width = 0, height = 0;
    uint32_t type = kQcRaw;
    uint32_t blocks = 0;  // as the header says (0: the single picture does not say; `data` is then `stream` bytes)
    uint32_t offset = 0;  // from the start of the file; 512 for the single picture
    Bytes data;           // the bytes of the picture as they lie: `blocks` * 512 of them, fewer where the file ends first
    size_t stream = 0;    // how many of them are the pixels or the packets (what follows is padding)
};

struct QcSplash {
    bool several = false;  // the longer header: a table of pictures
    std::vector<QcPicture> pictures;
    Bytes header_rest;     // what the 512 bytes hold behind the fields, up to the last byte that is not zero (nothing in an image of logo_gen.py)
    size_t consumed = 0;   // the end of the data of the last picture
};

// The magic, 512 bytes and fields that make a header of either form (the sizes and the places of the pictures add up, in the file): the cheap
// question, no pixel is looked at.
bool qc_looks_like(const Bytes& d);
// FormatError (with the reason) for an image whose header or pictures are not readable.
QcSplash qc_parse(const Bytes& d);
// The reason an image that starts with the magic cannot be read; empty when it can.
std::string qc_problem(const Bytes& d);
// The pixels of a picture.
Bitmap qc_decode(const QcPicture& p);
// The data of a picture of the type `type` from its pixels: the pixels as they are, or the RLE24 packets. Not padded to the block.
Bytes qc_encode(const Bitmap& bmp, uint32_t type);
// The blocks of 512 bytes that `size` bytes take.
uint32_t qc_blocks(uint64_t size);
// The file: the header from the fields (offsets are worked out: the first at 512, the others after the data of the one before), the data. In
// the several-pictures form every picture but the last has `blocks` * 512 bytes of data.
Bytes qc_build(const QcSplash& s);
std::string qc_type_name(uint32_t type);

// ----------------------------------------------------------------------------------------------- the OPLUS "SPLASH LOGO!" image --
//
//        0   0x4000 bytes: zeros, or a header of the signing that begins "DDPH" (u32 0x48504444, u32 a flag)
//   0x4000   "SPLASH LOGO!"
//   0x400C   four descriptions of 64 bytes, text
//   0x410C   u32 count
//   0x4110   u32 version
//   0x4114   u32 width
//   0x4118   u32 height
//   0x411C   u32 compression: 1 when the pictures are gzip streams
//   0x4120   count times, 128 bytes each: u32 offset, u32 size of the BMP, u32 size as stored, 116 bytes the name, text
//   0x8000   the pictures: each at 0x8000 + its offset, one behind the other. A picture is a BMP file, gzip stream or not.
//
// (The sources say that the header is 0x4000 bytes; what is behind the table is zeros.)

inline constexpr char kOplusMagic[12] = {'S', 'P', 'L', 'A', 'S', 'H', ' ', 'L', 'O', 'G', 'O', '!'};
inline constexpr size_t kOplusPreamble = 0x4000;  // in front of the header
inline constexpr size_t kOplusHeaderSize = 0x4000;
inline constexpr size_t kOplusDataAt = 0x8000;
inline constexpr size_t kOplusTableAt = 288;      // in the header: the first entry
inline constexpr size_t kOplusEntrySize = 128;
inline constexpr size_t kOplusNameSize = 116;
inline constexpr size_t kOplusDescSize = 64;
inline constexpr uint32_t kOplusMaxEntries = (kOplusHeaderSize - kOplusTableAt) / kOplusEntrySize;  // 125
inline constexpr uint32_t kDdphMagic = 0x48504444;

struct OplusEntry {
    std::string name;
    Bytes name_tail;         // what the 116 bytes hold behind the zero that ends the name
    uint32_t plain_size = 0; // the size of the BMP, as the header says
    Bytes data;              // as stored: its stored size, a gzip stream or the BMP itself
};

struct OplusLogo {
    Bytes preamble;          // the 0x4000 bytes in front of the header
    std::array<std::string, 4> desc;
    std::array<Bytes, 4> desc_tail;
    uint32_t version = 0, width = 0, height = 0, compression = 1;
    std::vector<OplusEntry> entries;
    Bytes header_rest;       // what the header holds behind the table, up to the last byte that is not zero
    size_t consumed = 0;     // the end of the data of the last picture
};

bool oplus_looks_like(const Bytes& d);
OplusLogo oplus_parse(const Bytes& d);
std::string oplus_problem(const Bytes& d);
// The file: the preamble (zeros to 0x4000 where it is shorter), the header from the fields (offsets and stored sizes are worked out), the data.
Bytes oplus_build(const OplusLogo& l);

// ------------------------------------------------------------------------------------------------- the Xiaomi "LOGO!!!!" image --
//
//        0   0x4000 bytes in front (zeros)
//   0x4000   "LOGO!!!!"
//   0x4008   up to 511 times: u32 offset, u32 size, both in units of 4096 bytes, from the start of the file; the first with no size and no offset
//            (zero) ends the list
//   0x5000   the pictures, each a whole number of units (BMP files with zeros up to the unit; PNG in some images), one behind the other

inline constexpr char kXiaomiMagic[8] = {'L', 'O', 'G', 'O', '!', '!', '!', '!'};
inline constexpr size_t kXiaomiPreamble = 0x4000;
inline constexpr size_t kXiaomiTableSize = 0x1000;
inline constexpr size_t kXiaomiUnit = 0x1000;
inline constexpr uint32_t kXiaomiMaxEntries = (kXiaomiTableSize - 8) / 8;  // 511

struct XiaomiLogo {
    Bytes preamble;
    std::vector<Bytes> pictures;  // each a whole number of units
    Bytes table_rest;             // what the table holds behind its last entry, up to the last byte that is not zero
    size_t consumed = 0;
};

bool xiaomi_looks_like(const Bytes& d);
XiaomiLogo xiaomi_parse(const Bytes& d);
std::string xiaomi_problem(const Bytes& d);
// The file: the preamble, the table (offsets and sizes are worked out from the pictures, each padded with zeros to a unit), the pictures.
Bytes xiaomi_build(const XiaomiLogo& l);
// How long a picture really is when its unit-sized data has padding of zeros: a BMP file by the size in its header, a PNG by its IEND chunk;
// the whole length for anything else, or when what follows is not all zero.
size_t xiaomi_content_size(const Bytes& data);

// ------------------------------------------------------------------------------------------------------- the Motorola "MotoLogo" --
//
//    0   "MotoLogo" and a zero byte
//    9   u32 size of the table: 13 + 32 * the number of entries
//   13   for every entry, 32 bytes: 24 bytes the name (text), u32 offset, u32 size (both in bytes, from the start of the file)
//   ...  the bytes up to the first picture are 0xFF (in the images seen)
//        the pictures at multiples of 512 bytes, the bytes between them filled up
//
// An entry with no offset and no size is an empty slot.

inline constexpr char kMotoMagic[9] = {'M', 'o', 't', 'o', 'L', 'o', 'g', 'o', '\0'};
inline constexpr size_t kMotoTableAt = 13;
inline constexpr size_t kMotoEntrySize = 32;
inline constexpr size_t kMotoNameSize = 24;
inline constexpr uint32_t kMotoMaxEntries = 2048;

struct MotoEntry {
    std::string name;
    Bytes name_tail;  // what the 24 bytes hold behind the zero that ends the name
    Bytes data;       // the picture; empty for an empty slot
};

struct MotoLogo {
    std::vector<MotoEntry> entries;
    uint32_t align = 512;        // the pictures lie at multiples of this (a power of two)
    uint8_t header_fill = 0xFF;  // the bytes between the table and the first picture
    uint8_t gap_fill = 0xFF;     // the bytes between a picture and the next
    size_t consumed = 0;         // the end of the last picture
};

bool moto_looks_like(const Bytes& d);
MotoLogo moto_parse(const Bytes& d);
std::string moto_problem(const Bytes& d);
// The file: the table (the offsets are worked out: the first at the table's end rounded up to `align`, the next at the end of the one before
// rounded up), the fill, the pictures.
Bytes moto_build(const MotoLogo& l);

// ------------------------------------------------------------------------------------------------------------------------- the rest --

// What a file of a picture is, by its first bytes: "bmp", "png", "jpg", or "bin" for anything else (the extension of the file abr writes).
std::string picture_extension(const Bytes& data);

}  // namespace abr::splash
