// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::cpio -- the "newc" cpio archive, the only kind a Linux kernel unpacks as an initramfs and
// so the only kind an Android ramdisk is.
//
// Two magics belong to the format: "070701" (newc) and "070702" (crc: the same header, with the
// byte sum of the file's contents in the last field). Both are read and written here. The older
// odc ("070707") and binary cpio formats are not: no kernel takes them as a ramdisk.
//
// A record is a 110-byte header of 13 eight-digit hexadecimal fields, the name with its NUL, and
// the data, the name and the data each padded with zeros to a multiple of four bytes (counted
// from the start of the header). The archive ends with a record named "TRAILER!!!". What comes
// after that -- zeros up to a block size, in practice -- is not part of the archive.
//
// The hexadecimal digits are lower case in what Android's mkbootfs, Magisk and libarchive write and
// upper case in what GNU cpio (and so `find . | cpio -H newc`, as Android Image Kitchen packs) and the
// kernel's gen_init_cpio write. An archive keeps to one of them; Archive::upper_hex remembers which, so
// that what is read is written back the same. Both cases in one archive is an error.
//
// parse() is strict on purpose: it accepts what write() would produce for the same fields, or says
// why not. Anything it would have to guess about (a missing NUL, a name with a NUL inside, a field
// that is not hexadecimal, a size that runs past the end) is an error, not a repair.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::cpio {

// st_mode file types.
constexpr uint32_t kTypeMask = 0170000;
constexpr uint32_t kSocket = 0140000;
constexpr uint32_t kSymlink = 0120000;
constexpr uint32_t kRegular = 0100000;
constexpr uint32_t kBlockDev = 0060000;
constexpr uint32_t kDirectory = 0040000;
constexpr uint32_t kCharDev = 0020000;
constexpr uint32_t kFifo = 0010000;

constexpr const char* kTrailerName = "TRAILER!!!";
constexpr size_t kHeaderSize = 110;

struct Entry {
    uint32_t ino = 0;
    uint32_t mode = 0;  // file type and permission bits, as st_mode
    uint32_t uid = 0;
    uint32_t gid = 0;
    uint32_t nlink = 1;
    uint32_t mtime = 0;
    uint32_t devmajor = 0;  // the device the file lived on
    uint32_t devminor = 0;
    uint32_t rdevmajor = 0;  // for device nodes: which device
    uint32_t rdevminor = 0;
    std::string name;  // the bytes of the name, without the NUL
    Bytes data;        // the contents; for a symbolic link its target

    uint32_t type() const { return mode & kTypeMask; }
};

enum class Magic { NEWC, CRC };

struct Archive {
    Magic magic = Magic::NEWC;
    bool upper_hex = false;      // the digits A-F of the headers are upper case (GNU cpio) rather than lower
    std::vector<Entry> entries;  // everything in front of the trailer
    Entry trailer;               // the TRAILER!!! record as it was written (name is set by write())
};

struct Parsed {
    Archive archive;
    size_t length = 0;  // bytes from the start through the trailer record, 4-aligned
};

// Reads the archive that starts at `data`. `error` says why not when it returns nothing.
std::optional<Parsed> parse(const uint8_t* data, size_t size, std::string& error);
inline std::optional<Parsed> parse(const Bytes& data, std::string& error) {
    return parse(data.data(), data.size(), error);
}

// True if `data` starts like a newc/crc archive (the magic and nothing more is looked at).
bool looks_like_cpio(const uint8_t* data, size_t size);

// True for the other cpio formats (odc, binary): named so that the refusal can say so.
bool looks_like_other_cpio(const uint8_t* data, size_t size);

// The sum of the bytes, which the crc format keeps in each regular file's header.
uint32_t byte_sum(const Bytes& data);

// The archive as bytes: every record, then the trailer. Nothing is added after the trailer; the
// caller pads to whatever block size it wants. A crc archive gets its check fields computed.
Bytes write(const Archive& archive);

}  // namespace abr::cpio
