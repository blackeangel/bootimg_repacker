// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::mtkgfh -- the loader image of a MediaTek chip's boot ROM (the "preloader"): the file that the boot ROM of the SoC reads from the boot
// partition of the flash (eMMC boot partition 1, SD, NOR) and runs before anything else. It is a chain of GFH headers ("general file header"),
// the loader's code, and a signature:
//
//   [ device header  0x200 bytes: "EMMC_BOOT" (or "SF_BOOT", "SDMMC_BOOT") padded to 12, u32 version, u32 size, 0xFF ]   (images of a partition)
//   [ BRLYT          the boot ROM's layout record: "BRLYT", version, the offset of the chain, the size of the file, "BBBB", the kind of flash
//                    (0x10005 eMMC), the offset and the size again, one more word; zeros and 0xFF up to the chain ]
//   [ GFH chain      FILE_INFO, BL_INFO, BROM_CFG, ANTI_CLONE, BROM_SEC_CFG, BL_SEC_KEY ... each: u32 "MMM" + version byte, u16 size, u16 type ]
//   [ the loader's code and data ]
//   [ signature      FILE_INFO.sig_size bytes ]
//   [ 0xFF up to a multiple of 0x200 (the images of a partition that were looked at) ]
//
// The layouts and the names of the fields are those of MediaTek's own header definitions as they stand in U-Boot's tools/mtk_image.h (written by
// MediaTek engineers). The images that the layout was checked against are five real preloaders: GFH at the start of the file (three of them), and
// behind a device header and a BRLYT at 0x800 (two of them). The sizes of all six headers that they have (FILE_INFO 0x38, BL_INFO 0xC, BROM_CFG 0x64,
// ANTI_CLONE 0x14, BROM_SEC_CFG 0x30, BL_SEC_KEY 0x214) are the sizes that the definitions give.
//
// What is known of the fields is used and no more: FILE_INFO is read as its fields (the sizes in it are made again by build()), every other
// header is kept as the bytes it is, so that a header of a kind that abr has no name for loses nothing. A signature that is the SHA-256 of the
// image (FILE_INFO.sig_type 1, the kind that U-Boot's mkimage writes, over the bytes from the first header to the signature) is made again by
// build() -- but only for an image whose signature is that hash to begin with. Other kinds of signature (sig_type 3 and 5, 0x124 and 0x66c bytes,
// are what the five loaders carry) are kept as they are: abr does not know how they are made, and the loader that is edited no longer matches them.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::mtkgfh {

inline constexpr uint32_t kMagic = 0x4D4D4D;  // "MMM"; the byte behind it (the top one of the word) is the version of the header
inline constexpr size_t kCommonSize = 8;      // magic and version, size, type
inline constexpr size_t kFileInfoSize = 56;

inline constexpr uint16_t kTypeFileInfo = 0;
inline constexpr uint16_t kTypeBlInfo = 1;
inline constexpr uint16_t kTypeAntiClone = 2;
inline constexpr uint16_t kTypeBlSecKey = 3;
inline constexpr uint16_t kTypeBromCfg = 7;
inline constexpr uint16_t kTypeBromSecCfg = 8;

inline constexpr uint8_t kSigNone = 0;
inline constexpr uint8_t kSigSha256 = 1;
inline constexpr size_t kSha256Size = 32;

inline constexpr size_t kDeviceHeaderSize = 0x200;
inline constexpr size_t kBrlytSize = 0x28;
inline constexpr uint32_t kBrlytMagic = 0x42424242;  // "BBBB"
inline constexpr uint32_t kBrlytNand = 0x10002;
inline constexpr uint32_t kBrlytEmmc = 0x10005;
inline constexpr uint32_t kBrlytNor = 0x10007;
inline constexpr uint32_t kBrlytSdmmc = 0x10008;
inline constexpr uint32_t kBrlytSerialNand = 0x10009;

// "FILE_INFO", "BL_INFO", "ANTI_CLONE", "BL_SEC_KEY", "BROM_CFG", "BROM_SEC_CFG", or "type N".
std::string type_name(uint16_t type);
// "none", "SHA-256", or "kind N".
std::string sig_type_name(uint8_t sig_type);
// "generic (NOR, SD, eMMC)" for 5 and "NAND" for 2 (U-Boot's names), else "type N".
std::string flash_type_name(uint8_t flash_type);
// "eMMC", "NOR", "SD/MMC", "NAND", "serial NAND", else the number in hex.
std::string brlyt_type_name(uint32_t type);

struct Header {
    uint8_t version = 1;
    uint16_t type = 0;
    Bytes body;  // the bytes of the header after its eight common ones (size - 8 of them)

    size_t size() const { return kCommonSize + body.size(); }
};

// One line about what a header holds, in the names of U-Boot's definitions ("cfg_bits 0x90 (usbdl_auto_detect_dis, usbdl_by_kcol0_timeout_en)",
// "ac_offset 0x10, ac_len 0x80"); empty for a type that has no names (or a header that is shorter than its type's). The values are the bytes as they are.
std::string describe(const Header& h);

// What FILE_INFO (the header of type 0, the first of the chain) holds.
struct FileInfo {
    uint8_t version = 1;  // of the header
    std::array<uint8_t, 12> name{};
    uint32_t file_ver = 1;  // the word that U-Boot's definition calls "unused" (1 in every image that was looked at)
    uint16_t file_type = 1;
    uint8_t flash_type = 5;
    uint8_t sig_type = 0;
    uint32_t load_addr = 0, max_size = 0, jump_offset = 0, processed = 0;
    uint32_t total_size = 0, hdr_size = 0, sig_size = 0;  // read from the file; build() writes them from the parts
    Bytes extra;                                          // bytes of the header behind the 56 (a FILE_INFO that is longer)

    std::string name_text() const;  // "FILE_INFO"
    Bytes name_tail() const;        // what the 12 bytes of the name hold behind its zero, up to the last byte that is not zero
};
FileInfo read_file_info(const Header& h);
Header write_file_info(const FileInfo& f);

// The device header and the BRLYT of an image of a partition (what is in front of the chain).
struct Device {
    std::string boot_name;  // "EMMC_BOOT", "SF_BOOT", "SDMMC_BOOT"
    uint32_t boot_version = 1, boot_size = 0;
    uint32_t version = 0, header_size = 0, total_size = 0, magic = 0, type = 0, header_size_2 = 0, total_size_2 = 0, unused = 0;
};

// How the two sizes of the BRLYT are worked out when the image is built again: they are the size of the whole file (the 0xFF fill that makes it
// a multiple of 0x200 is in it: what the two images that have a BRLYT show), the end of the loader (where the chain begins + FILE_INFO.total_size),
// or neither -- a number that is kept as it is.
enum class SizeBasis { Literal, File, Chain };
const char* size_basis_name(SizeBasis b);
std::optional<SizeBasis> size_basis_from_name(std::string_view name);

struct Image {
    Bytes prefix;                 // the bytes in front of the chain, verbatim (the device header, the BRLYT and what is between them and the chain)
    std::optional<Device> device;  // what the prefix says, when it is a device header and a BRLYT
    SizeBasis basis = SizeBasis::Literal;
    std::vector<Header> chain;    // chain[0] is FILE_INFO
    Bytes chain_pad;              // the bytes between the end of the chain and the end of the headers (FILE_INFO.hdr_size)
    Bytes payload;                // the loader: from the end of the headers to the signature
    Bytes signature;              // FILE_INFO.sig_size bytes
    bool sha256_trailer = false;  // the signature is the SHA-256 of everything from the chain to it: build() makes it again
    size_t consumed = 0;          // the end of the signature in the file it was parsed from

    size_t at() const { return prefix.size(); }  // where the chain begins
};

// The device header and the BRLYT at the start of `d` (or of the prefix of an image: what is in front of the chain), or nothing when `d` does not
// start with a device header of a boot medium that U-Boot's definitions name (EMMC_BOOT, SF_BOOT, SDMMC_BOOT) and a BRLYT of the kind they name.
std::optional<Device> parse_device(const Bytes& d);

// Where the chain begins: 0 for a file that starts with a FILE_INFO header; the offset that the BRLYT names when the file starts with a device
// header and a BRLYT. nullopt for anything else. `device` (when given) gets the device header and the BRLYT, or nothing.
std::optional<size_t> find_chain(const Bytes& d, std::optional<Device>* device = nullptr);

// What is wrong with a file that has a FILE_INFO header (the sizes that it holds, against each other and against the size of the file); empty when
// all is well or the file has none.
std::string problem(const Bytes& d);

// A FILE_INFO header that can be believed, and sizes that agree with it and with the file.
bool looks_like(const Bytes& d);

// The headers in d[from, to): as many as there are in a row, the bytes after the last one in `pad`. A FormatError for a header that is cut
// short by `to` or has a size below eight, or for more than 64 of them.
std::vector<Header> split_headers(const Bytes& d, size_t from, size_t to, Bytes* pad);
// The text "MTK_BLOADER_INFO_v" and the digits behind it ("MTK_BLOADER_INFO_v28"), the first time it is in `payload`, and where: it is in the code of
// every one of the five loaders that were looked at, near the end of it. It says which generation of the loader the code is.
struct Marker {
    size_t offset = 0;
    std::string text;
};
std::optional<Marker> find_bloader_marker(const Bytes& payload);

// The bytes of the headers [first, end) of the chain, one after the other.
Bytes serialize_headers(const std::vector<Header>& chain, size_t first = 0);

// The image in `d`: a FormatError for a chain that is cut short or whose sizes do not agree (the headers longer than FILE_INFO says they are, a
// signature or a total that does not fit in the file).
Image parse(const Bytes& d);

// The file up to the end of the signature: the prefix as it is, the chain, the padding behind it, the loader and the signature, with the sizes in
// FILE_INFO made right (hdr_size, total_size, sig_size) and the SHA-256 trailer made again where that is what the signature is. The BRLYT is
// left as it is: fix_device() sets its sizes when the file has the size it will have (what is put behind the signature is the caller's).
Bytes build(const Image& img);

// The sizes of the BRLYT in `file`, worked out as img.basis says from the size that `file` has. Nothing for an image without one.
void fix_device(Bytes& file, const Image& img);

}  // namespace abr::mtkgfh
