// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/amonet.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>

#include "abr/envelope.hpp"  // kMagicSearchLimit: the window the signature search uses everywhere in abr

namespace abr::legacy {

namespace {
constexpr std::string_view kAndroidMagic = "ANDROID!";
constexpr std::string_view kMicroloaderWord = "microloader";
constexpr size_t kWordFrom = 96;  // androidbootimg.magic looks for the word behind this offset
}  // namespace

bool has_amonet_patch(const Bytes& data) {
    if (data.size() < kAmonetMicroloaderSize + kAndroidMagic.size()) return false;
    if (std::memcmp(data.data() + kAmonetMicroloaderSize, kAndroidMagic.data(), kAndroidMagic.size()) != 0)
        return false;
    const size_t end = std::min(data.size(), kMagicSearchLimit);
    if (end <= kWordFrom) return false;
    const auto first = data.begin() + static_cast<std::ptrdiff_t>(kWordFrom);
    const auto last = data.begin() + static_cast<std::ptrdiff_t>(end);
    return std::search(first, last, kMicroloaderWord.begin(), kMicroloaderWord.end()) != last;
}

std::optional<AmonetInfo> strip_amonet(const Bytes& data, Bytes& original_out) {
    if (!has_amonet_patch(data)) return std::nullopt;
    if (data.size() < kAmonetPrefixSize)
        throw FormatError("this AMONET-patched image is cut short: " + std::to_string(data.size()) +
                          " bytes, and the patch alone takes " + std::to_string(kAmonetPrefixSize));
    AmonetInfo info;
    info.microloader.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(kAmonetMicroloaderSize));

    // The head (the first 1024 bytes of the boot image), the 1024 zeros the patch overwrote, the rest.
    Bytes original;
    original.reserve(data.size());
    original.insert(original.end(), data.begin() + static_cast<std::ptrdiff_t>(kAmonetMicroloaderSize),
                    data.begin() + static_cast<std::ptrdiff_t>(kAmonetPrefixSize));
    original.insert(original.end(), kAmonetHeadSize, 0);
    original.insert(original.end(), data.begin() + static_cast<std::ptrdiff_t>(kAmonetPrefixSize), data.end());
    original_out = std::move(original);
    return info;
}

Bytes apply_amonet(const Bytes& image, const AmonetInfo& info) {
    if (info.microloader.size() != kAmonetMicroloaderSize)
        throw FormatError("the AMONET microloader must be exactly " + std::to_string(kAmonetMicroloaderSize) +
                          " bytes, this one is " + std::to_string(info.microloader.size()));
    if (image.size() < kAmonetPrefixSize)
        throw FormatError("an image of " + std::to_string(image.size()) +
                          " bytes is too small for the AMONET patch, which takes " + std::to_string(kAmonetPrefixSize));
    // The patch overwrites [1024, 2048) of the image: only the padding of the first page may be there.
    for (size_t i = kAmonetHeadSize; i < kAmonetPrefixSize; ++i) {
        if (image[i] != 0)
            throw FormatError(
                "this image has data between bytes 1024 and 2048 (a header longer than 1024 bytes, or a first page "
                "that is not 2048 bytes long), which the AMONET patch would overwrite");
    }
    Bytes out = image;
    std::copy(info.microloader.begin(), info.microloader.end(), out.begin());
    std::copy(image.begin(), image.begin() + static_cast<std::ptrdiff_t>(kAmonetHeadSize),
              out.begin() + static_cast<std::ptrdiff_t>(kAmonetMicroloaderSize));
    return out;
}

}  // namespace abr::legacy
