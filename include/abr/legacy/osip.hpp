// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::osip -- Intel's boot image for Android devices, "OSIP" for Android Image Kitchen, which opens
// it with osm0sis' mboot (after Jocelyn Falempe's mboot.py). The layout, as mboot reads and writes it:
//
//   header      512 bytes, "$OS$" 00 00 01 ...: the OSIP header (an image of a device without one starts
//               with the cmdline)
//   signature   0, 480, 728 or 1024 bytes: Intel's signature of a signed image
//   cmdline     1024 bytes, text padded with NULs
//   image info  3072 bytes: u32 kernel_size, u32 ramdisk_size, 8 bytes "parameter", then padding -- zeros,
//               but BD 02 BD 02 BD 12 BD 12 right behind the parameter in a signed image
//   bootstub    4096 bytes (8192 on some devices)
//   kernel      kernel_size bytes
//   ramdisk     ramdisk_size bytes (a gzip-compressed cpio archive)
//   padding     up to a multiple of 512 bytes, 0xFF
//
// The OSIP header is the 32-byte header proper and one 24-byte "OSII" entry (the image):
//
//   0   "$OS$"   4 reserved   5 revision minor   6 revision major (1)   7 checksum
//   8   number of pointers   9 number of images   10 header size (u16)   12..31 reserved
//   32  OSII: u16 minor, u16 major, u32 start block, u32 DDR load address, u32 entry point,
//       u32 size of the image (in 512-byte sectors, not counting the header's own), u8 attribute, 3 reserved
//
// mboot keeps three things in the header up to date when it packs: the size of the image in sectors (offset
// 48), the "unsigned" bit of the attribute (offset 52, set when there is no signature; 0 is a signed boot
// image, 1 an unsigned one, 0x0C and 0x0D the same for a recovery) and the checksum (byte 7: the XOR of the
// first 56 bytes of the header, the checksum byte counted as zero). abr does the same, but only when the
// size of the image or the presence of a signature changed -- an image that was not touched comes back as it
// was, whatever its header says.
//
// Where the layout is not fixed (the size of the signature, of the bootstub) mboot guesses from the text of
// the cmdline and from what follows the bootstub. abr makes the same guess first and keeps it if the sizes in
// the image info fit the file and the ramdisk starts like one; otherwise it tries the other layouts mboot
// knows, and takes the one that fits.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "abr/byte_io.hpp"

namespace abr::legacy {

constexpr size_t kOsipHeaderSize = 512;
constexpr size_t kOsipCmdlineSize = 1024;
constexpr size_t kOsipInfoSize = 3072;         // the image info: sizes, parameter, padding
constexpr size_t kOsipInfoFixedSize = 16;      // kernel_size, ramdisk_size, parameter
constexpr size_t kOsipFirstBlockSize = kOsipCmdlineSize + kOsipInfoSize;  // 4096, in front of the bootstub
constexpr size_t kOsipSectorSize = 512;
constexpr size_t kOsipChecksummedSize = 56;    // what the header's checksum covers
constexpr size_t kOsipChecksumOffset = 7;
constexpr size_t kOsipSectorsOffset = 48;
constexpr size_t kOsipAttributeOffset = 52;

// Behind the parameter of a signed image.
extern const uint8_t kOsipSignedMagic[8];

struct OsipImage {
    Bytes header;                       // kOsipHeaderSize bytes, or empty (no OSIP header)
    Bytes signature;                    // 0, 480, 728 or 1024 bytes
    Bytes cmdline;                      // the kOsipCmdlineSize-byte block as it is
    std::array<uint8_t, 8> parameter{};
    Bytes info_rest;                    // kOsipInfoSize - kOsipInfoFixedSize bytes: behind the parameter
    Bytes bootstub;                     // 4096 or 8192 bytes
    Bytes kernel;
    Bytes ramdisk;
    size_t consumed = 0;                // parse: where the ramdisk ends in the file (no padding)

    // "$OS$" 00 00 01 at the very start, or no header and a bootstub (FC FA BC 00) where one starts in an
    // image that has none.
    static bool looks_like(const Bytes& data);

    // Refuses (FormatError, saying why) what is cut short or whose sizes do not fit the file.
    static OsipImage parse(const Bytes& data);

    // The image as it is: header, signature, cmdline, info, bootstub, kernel, ramdisk; no padding. Refuses
    // (FormatError) a block that is not the size it has to be.
    Bytes build() const;
    size_t body_size() const;

    // The text of the cmdline: up to the first NUL.
    std::string cmdline_text() const;
};

// What a header says. All of it is false/zero for a header that is not there or too short.
bool osip_header_checksum_ok(const Bytes& header);
uint8_t osip_header_checksum(const Bytes& header);   // what byte 7 should be
uint32_t osip_header_sectors(const Bytes& header);   // the size of the image in sectors, as stored
uint8_t osip_header_attribute(const Bytes& header);  // the image type: 0/1 boot, 0x0C/0x0D recovery

// mboot's rules for the fields that depend on the image: `padded_size` is the image with its padding up to a
// whole sector (what the header's sector count describes, less the header's own sector); the "unsigned" bit
// is set when there is no signature (and left as it is when there is one); the checksum is made afresh.
void osip_refresh_header(Bytes& header, uint64_t padded_size, bool signed_image);
void osip_set_header_checksum(Bytes& header);

}  // namespace abr::legacy
