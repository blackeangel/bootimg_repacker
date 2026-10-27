// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::Manifest -- a small, human-editable key=value sidecar file that
// `unpack` writes next to the extracted component files and `repack`
// reads back. One flat namespace, insertion order preserved (so a
// human reading the file sees fields in a sensible order rather than
// alphabetized), `#`-prefixed lines and blank lines ignored on read. A value that
// cannot be written as plain text and read back the same (a line break, white
// space at an end, a leading quote, control bytes) is written in double quotes
// with the escapes of C (abr/textquote.hpp).
//
// This class only knows about text/hex/bool/address encoding; mapping
// specific keys to a specific image format's fields lives in main.cpp,
// one small function per format.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {

inline constexpr uint32_t kMaxEntries = 65536;

class Manifest {
public:
    static Manifest load(const std::filesystem::path& path);
    void save(const std::filesystem::path& path, const std::string& header_comment = "") const;

    bool has(const std::string& key) const;
    void set(const std::string& key, const std::string& value);
    std::string get(const std::string& key, const std::string& def = "") const;
    // A value that names a file or a directory of the unpack (`kernel_file`, `ramdisk_tree`, ...): what repack opens. It
    // must lie in the directory of the manifest -- a relative path, without '..', a drive, a colon or a backslash -- or
    // FormatError says so. (The directory may have come from anyone; a manifest that points at /etc/passwd or at
    // ../../.ssh/id_rsa must not get that file built into an image.)
    std::string get_path(const std::string& key, const std::string& def = "") const;

    // Numbers: decimal digits, or 0x and hexadecimal digits, and nothing else -- no sign, no octal ("010" is ten), no
    // trailing text, no white space inside. What is not a number, or does not fit in the field it is read for (a value
    // above 32 bits for a 32-bit field is refused, not cut to it), is a FormatError that names the key and the value.
    // A key that is not there gives `def`; one that is there and empty is an error.
    void set_u32(const std::string& key, uint32_t v);
    void set_u64(const std::string& key, uint64_t v);
    uint32_t get_u32(const std::string& key, uint32_t def = 0) const;
    uint64_t get_u64(const std::string& key, uint64_t def = 0) const;
    // A number of at most `bits` bits (8, 16, 32 or 64).
    uint64_t get_bounded(const std::string& key, uint64_t def, unsigned bits) const;
    // A number that is at least `lo` and at most `hi` (a level of compression, a count).
    int64_t get_int(const std::string& key, int64_t def, int64_t lo, int64_t hi) const;
    // A version "2.2": two decimal numbers of a 32-bit word each, a dot between them, nothing else.
    std::pair<uint32_t, uint32_t> get_version(const std::string& key, uint32_t def_major, uint32_t def_minor) const;
    // The size of an image or of a partition (`pad_to`, `avb_partition_size`, ...): at most kMaxImageSize, because no
    // image of the family is bigger and a value beyond it only makes abr ask for memory it cannot have.
    uint64_t get_size(const std::string& key, uint64_t def = 0) const;
    // How many entries there are (descriptors, ramdisks, blobs, segments): at most kMaxEntries. A count that is not
    // checked is a loop that runs to four billion.
    uint32_t get_count(const std::string& key, uint32_t def = 0) const;

    // Addresses are written/read as 0x-prefixed hex for readability.
    void set_addr(const std::string& key, uint64_t v);
    uint64_t get_addr(const std::string& key, uint64_t def = 0) const;
    // An address that is 32 bits in the header it goes into.
    uint32_t get_addr32(const std::string& key, uint32_t def = 0) const;

    // true / false / yes / no / 1 / 0 (in any case). Anything else, and an empty value, is a FormatError: a typo that
    // reads as `false` would silently turn a feature off.
    void set_bool(const std::string& key, bool v);
    bool get_bool(const std::string& key, bool def = false) const;

    // Binary blobs too short/structural to deserve their own component
    // file (ids, salts, small keys) are stored inline as hex text.
    void set_hex(const std::string& key, const Bytes& data);
    // An even number of hexadecimal digits (any case); an odd one or another character is a FormatError.
    Bytes get_hex(const std::string& key) const;

    // What a text field of a header holds behind the NUL that ends its text (BinaryReader::asciiz), only when there is
    // any, so that the manifest of an ordinary image does not change: as text under `key` when it is printable ASCII
    // (the rest of an older command line), else as hex under `key`_hex (the one that is there is the one read; the hex
    // one wins when both are).
    void set_tail(const std::string& key, const Bytes& tail);
    Bytes get_tail(const std::string& key) const;

private:
    std::vector<std::pair<std::string, std::string>> entries_;  // in the order they were set (and are written)
    std::unordered_map<std::string, size_t> index_;              // key -> its place in entries_ (a manifest can have many lines)
};

}  // namespace abr
