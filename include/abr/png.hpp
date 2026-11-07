// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::png -- the small PNG reader and writer that the picture formats use (the pictures of a MediaTek logo.bin). abr's own code: no libpng, so
// that abr stays one file with nothing it has to load, and so that what a damaged or a hostile picture may ask of the memory is decided here.
//
// What it reads: every kind of PNG there is (greyscale, truecolour, palette, with alpha; 1, 2, 4, 8 and 16 bits; interlaced or not; tRNS) as
// 8-bit RGBA. What it writes: 8-bit truecolour (with alpha, or without it), one IDAT chunk, a filter chosen for every row. The picture a
// person edits is a file of this kind, and what comes back from an editor (GIMP, Photoshop, Paint) in any of the others is read all the same.
#pragma once

#include <cstdint>

#include "abr/byte_io.hpp"

namespace abr::png {

struct Image {
    uint32_t width = 0, height = 0;
    Bytes rgba;              // width * height * 4 bytes, R G B A, alpha not premultiplied
    bool has_alpha = false;  // the PNG had an alpha channel or a transparency entry (decode()); what a caller wants written (encode()) is its own say
};

// The most pixels a picture may have: a PNG of a few hundred bytes can ask for gigabytes of memory (and a logo of a phone is not near a
// hundred megapixels).
inline constexpr uint64_t kMaxPixels = uint64_t{1} << 27;

// The eight bytes every PNG begins with.
bool looks_like(const Bytes& data);

// A FormatError for a file that is not a PNG, is cut short, has a chunk whose CRC is wrong, or asks for more than kMaxPixels.
Image decode(const Bytes& png);

// 8-bit truecolour: colour type 6 (RGBA) when `with_alpha`, 2 (RGB) when not (the alpha of the pixels is left out). `img.rgba` must hold
// exactly width * height * 4 bytes. The same picture always makes the same bytes.
Bytes encode(const Image& img, bool with_alpha);

}  // namespace abr::png
