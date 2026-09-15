// SPDX-License-Identifier: MIT
//
// abr::VbmetaImage -- parser/builder for AVB vbmeta blobs (vbmeta.img,
// vbmeta_system.img), and for the AVB hash footer some other partitions
// carry appended to their own data. Field layout, big-endian byte order
// and the 256/64-byte header/footer sizes are verified against AOSP
// platform/external/avb libavb/{avb_vbmeta_image.h,avb_footer.h,
// avb_*_descriptor.h}.
//
// Signing note: re-signing (build() with a supplied PEM private key) uses
// OpenSSL to produce a standard RSASSA-PKCS1-v1.5 signature over the
// SHA-256/SHA-512 digest, which is the scheme AVB documents. This path is
// not validated against `avbtool verify_image` from this sandbox (no real
// device/avbtool available here) -- treat it as best-effort and verify
// before relying on it for a locked or verity-enforcing device. Passthrough
// repacking (no key supplied, nothing that affects the hash changed) does
// not depend on this at all: it just keeps the original signature bytes.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {

enum class AvbAlgorithm : uint32_t {
    NONE = 0,
    SHA256_RSA2048 = 1,
    SHA256_RSA4096 = 2,
    SHA256_RSA8192 = 3,
    SHA512_RSA2048 = 4,
    SHA512_RSA4096 = 5,
    SHA512_RSA8192 = 6,
};

std::string avb_algorithm_name(uint32_t algorithm_type);

enum class AvbDescriptorTag : uint64_t {
    PROPERTY = 0,
    HASHTREE = 1,
    HASH = 2,
    KERNEL_CMDLINE = 3,
    CHAIN_PARTITION = 4,
};

// Descriptors are kept as opaque (tag, content) pairs so an untouched
// descriptor round-trips byte-for-byte. `describe()` decodes the common
// tag types for human-readable `info` output only.
struct AvbDescriptor {
    uint64_t tag = 0;
    Bytes content;  // the descriptor's `num_bytes_following` bytes, verbatim

    std::string describe() const;
};

struct VbmetaImage {
    uint32_t required_libavb_version_major = 1;
    uint32_t required_libavb_version_minor = 0;
    uint32_t algorithm_type = 0;  // AvbAlgorithm
    uint64_t rollback_index = 0;
    uint32_t flags = 0;
    uint32_t rollback_index_location = 0;
    std::string release_string;

    Bytes public_key;           // opaque AVB public-key blob
    Bytes public_key_metadata;  // opaque
    std::vector<AvbDescriptor> descriptors;

    // As read from the source image; used for passthrough when rebuilding
    // without a private key and nothing that affects the hash has changed.
    Bytes hash;
    Bytes signature;

    // Populated only when parsed from an AVB *footer* (i.e. this vbmeta
    // struct was appended to some other partition's own data, such as a
    // boot.img using a hash footer) rather than being a dedicated
    // vbmeta.img/vbmeta_system.img file.
    bool has_footer = false;
    Bytes host_prefix;  // the other partition's bytes before the vbmeta blob
    uint64_t footer_original_image_size = 0;
    uint64_t source_total_size = 0;  // total size of the file this was parsed from

    static VbmetaImage parse(const Bytes& image);

    // Rebuilds the AVB blob. If this instance has_footer, the return
    // value is the *whole* host image (host_prefix + new blob + footer,
    // padded back out to source_total_size); otherwise it's just the
    // vbmeta blob itself (header + authentication + auxiliary data),
    // which is what vbmeta.img/vbmeta_system.img actually are.
    //
    // private_key_pem, if non-empty, (re-)signs with that RSA key --
    // required whenever algorithm_type != NONE and any descriptor,
    // flags, rollback_index, or key material changed relative to what
    // was parsed. Without a key, an unchanged hash lets the original
    // signature bytes pass through; a changed hash throws FormatError
    // rather than emitting a self-inconsistent (and therefore useless)
    // signed blob.
    Bytes build(const std::string& private_key_pem = "") const;
};

}  // namespace abr
