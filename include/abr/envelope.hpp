// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::Envelope -- the bytes *around* a parsed container.
//
// A container parser (boot image, vendor_boot, dtbo, ...) only understands
// what its own header declares. Real images carry more than that:
//
//   * a vendor wrapper in front (Spreadtrum "BFBF/SSSS" signing header, a
//     leftover MTK/Samsung header, ...) -- the container's magic is then not
//     at offset 0;
//   * bytes after the last component: a boot_signer (AVBv1) signature, a
//     vendor trailer, and above all fill up to the partition size
//     (a 16 MiB boot partition holding an 8 MiB image).
//
// Silently dropping any of that yields a file that is smaller than the
// original and, on a device that checks it, unbootable. The rule for this
// project is therefore: never lose a byte we did not understand. The
// envelope stores those bytes verbatim (or, for long fill runs, as
// "byte + target size") and puts them back around the rebuilt container.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {

constexpr size_t kMagicSearchLimit = 64 * 1024;  // same window osm0sis' unpackbootimg scans

// Offset of the first occurrence of `magic` within the first `limit` bytes
// of `data`, or std::string::npos.
size_t find_magic(const Bytes& data, const char* magic, size_t magic_len,
                  size_t limit = kMagicSearchLimit);

struct Envelope {
    Bytes prefix;         // bytes in front of the container, verbatim
    Bytes tail;           // bytes after the container (before the padding), verbatim
    uint8_t pad_byte = 0; // value of the trailing padding run
    uint64_t pad_to = 0;  // pad the rebuilt file with pad_byte up to this size; 0 = don't

    // A trailing run of identical bytes is only treated as padding when it
    // is at least this long. (A vendor trailer that happens to end in
    // 0xffffffff must stay a trailer, not turn into "size-dependent fill".)
    static constexpr uint64_t kMinPadRun = 64;

    // Splits `host` around the container occupying [core_off, core_off+core_len).
    static Envelope capture(const Bytes& host, size_t core_off, size_t core_len);

    // prefix + core + tail, padded up to pad_to. `note`, if given, receives
    // a human-readable remark when the result outgrew pad_to.
    Bytes assemble(const Bytes& core, std::string* note = nullptr) const;

    bool empty() const { return prefix.empty() && tail.empty() && pad_to == 0; }
};

}  // namespace abr
