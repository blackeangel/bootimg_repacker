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
#include <utility>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {

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

    void set_u32(const std::string& key, uint32_t v);
    void set_u64(const std::string& key, uint64_t v);
    uint32_t get_u32(const std::string& key, uint32_t def = 0) const;
    uint64_t get_u64(const std::string& key, uint64_t def = 0) const;

    // Addresses are written/read as 0x-prefixed hex for readability.
    void set_addr(const std::string& key, uint64_t v);
    uint64_t get_addr(const std::string& key, uint64_t def = 0) const;

    void set_bool(const std::string& key, bool v);
    bool get_bool(const std::string& key, bool def = false) const;

    // Binary blobs too short/structural to deserve their own component
    // file (ids, salts, small keys) are stored inline as hex text.
    void set_hex(const std::string& key, const Bytes& data);
    Bytes get_hex(const std::string& key) const;

private:
    std::vector<std::pair<std::string, std::string>> entries_;
};

}  // namespace abr
