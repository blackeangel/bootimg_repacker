// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::legacy::chromeos -- ChromeOS kernel blobs: the "verified boot" (vboot) format of a Chromebook's kernel
// partition. Android Image Kitchen calls it CHROMEOS, takes the kernel out with `futility vbutil_kernel
// --get-vmlinuz` and puts the rebuilt image back with `futility vbutil_kernel --pack`, signed with the public
// developer keys of vboot_reference; abr does both on its own.
//
//     keyblock     "CHROMEOS", version, size, the signature and checksum of the keyblock, flags, the data key
//                  (a packed RSA public key)                                   opaque to abr: kept as it is
//     preamble     preamble_size  signature of the preamble  header version  kernel version  body_load_address
//                  bootloader_address  bootloader_size  signature of the body  [vmlinuz header address and size]
//                  [flags]                                                    96, 112 or 116 bytes (2.0, 2.1, 2.2)
//                  the signature of the body, the signature of the preamble, zeros up to preamble_size
//     body         the kernel (4096-aligned), the config (4096 bytes: the command line, NUL-terminated), the
//                  params (4096 bytes: the x86 boot parameters, zeros on ARM), the bootloader (bootloader_size
//                  bytes, 4096-aligned)
//
// The keyblock and the preamble together are the "verification block", 64 KiB by default (--pad). Both
// signatures are RSA PKCS#1 v1.5 made with the data key of the keyblock: the body's over the whole body, the
// preamble's over the preamble header and the body signature. All little endian; the offsets of a signature
// are counted from the start of its descriptor.
//
// The kernel is what abr works on: AIK's `--get-vmlinuz` gives the whole body on ARM, and the image inside it
// is the Android boot image (or whatever the device boots) with zeros up to the 4096 boundary. abr takes the
// kernel's own bytes (K, with that padding) as the plain image, like a DHTB header's content, and keeps the
// rest: the keyblock, the fields of the preamble, the config, the params and the bootloader, the signatures
// as they were, and what follows the blob in a partition dump. A blob for x86 (a vmlinuz header in the
// preamble) holds a bzImage no Android tool opens; it is refused.
//
// Repack: the kernel is padded up to 4096 again, the body and the preamble are made afresh from what the
// manifest says, and the signatures are
//   - kept as they were when nothing they cover has changed (a blob that went through an unpack and a repack
//     untouched comes back byte for byte, whoever signed it);
//   - made again, with the key the keyblock's data key belongs to, when something has: abr has the public
//     developer data key of vboot_reference (tests/devkeys of the Chromium OS project; the same one Android
//     Image Kitchen signs with), or the key of --chromeos-key;
//   - made with the developer key and a developer keyblock when the blob's keyblock is somebody else's and no
//     key of it was given -- as Android Image Kitchen does, which replaces the keyblock every time. A device
//     that is in developer mode boots such a blob; one that checks the keyblock against its own keys does not.
//
// The format is vboot_reference's (firmware/2lib/include/2struct.h, futility/cmd_vbutil_kernel.c;
// BSD-3-Clause, (c) The Chromium OS Authors). The test suite compares abr with the real `futility
// vbutil_kernel` and with OpenWrt's cros-vbutil wherever they are installed.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "abr/byte_io.hpp"
#include "abr/envelope.hpp"
#include "abr/rsa.hpp"

namespace abr::legacy {

constexpr size_t kChromeosAlign = 4096;       // the kernel and the bootloader are aligned to this
constexpr size_t kChromeosConfigSize = 4096;  // the command line: a field of this size
constexpr size_t kChromeosParamsSize = 4096;  // the x86 boot parameters: a field of this size
constexpr uint32_t kChromeosDefaultPad = 0x10000;  // keyblock + preamble: 64 KiB unless --pad says otherwise

// vboot's algorithm numbers: a signature algorithm (the size of the key and its public exponent) and a hash.
struct ChromeosAlgorithm {
    size_t key_bits = 0;
    uint32_t exponent = 65537;
    HashAlg hash = HashAlg::SHA256;
};
// 0-17 as `futility vbutil_key --pack` lists them; std::nullopt for any other.
std::optional<ChromeosAlgorithm> chromeos_algorithm(uint64_t id);
// "RSA-2048/SHA-256"; "algorithm 99" for a number that is not one.
std::string chromeos_algorithm_name(uint64_t id);

// A signing key as `.vbprivk` holds it: the algorithm (u64) and the DER RSAPrivateKey (PKCS#1).
struct ChromeosKey {
    uint64_t algorithm = 0;
    RsaPrivateKey rsa;
};
// Refuses (FormatError, saying why) a file that is not a .vbprivk, an algorithm abr does not know, and a key
// whose size is not the algorithm's.
ChromeosKey parse_vbprivk(const Bytes& file);

// The data key a keyblock carries: the key the signatures of the preamble and the body are checked with.
struct ChromeosDataKey {
    uint64_t algorithm = 0;
    uint64_t version = 0;
    std::optional<RsaPublicKey> rsa;  // empty when the algorithm is not one abr knows, or the key is not its size
};
// Refuses a keyblock that is cut short or has no data key (FormatError).
ChromeosDataKey keyblock_data_key(const Bytes& keyblock);

// The public developer keys of vboot_reference (tests/devkeys): kernel.keyblock and kernel_data_key.vbprivk.
// They protect nothing; they are there so that a blob can be signed the way Android Image Kitchen signs it.
const Bytes& chromeos_dev_keyblock();
const ChromeosKey& chromeos_dev_key();

// What a blob has that the plain kernel does not (see the layout above).
struct ChromeosInfo {
    Bytes keyblock;  // verbatim
    uint32_t preamble_major = 2;
    uint32_t preamble_minor = 2;  // 0, 1 or 2: the fields and the size of the preamble header
    uint32_t kernel_version = 1;
    uint64_t body_load_address = 0x100000;
    // The address of the bootloader. A blob made by futility has body_load_address + the kernel + the config +
    // the params there, and so does abr unless the blob says something else: then it is kept.
    std::optional<uint64_t> bootloader_address;
    uint32_t bootloader_size = 0;       // the bootloader field of the body: its size, as the preamble says
    uint64_t vmlinuz_header_address = 0;  // preamble 2.1 and 2.2; the size is always 0 (ARM)
    uint32_t flags = 0;                 // preamble 2.2
    uint32_t pad = kChromeosDefaultPad;  // the size of the verification block, keyblock and preamble
    // The fields of the body that follow the kernel, up to their last byte that is not zero (the rest is zeros).
    Bytes config, params, bootloader;
    // The signatures as they were in the blob.
    Bytes body_signature, preamble_signature;
    // SHA-256 of what they cover: the keyblock, the part of the preamble the preamble signature covers, the
    // body. If it is the same at repack, the signatures are still good and are kept.
    Bytes signed_sha256;

    // Filled in by strip_chromeos; not kept in a manifest.
    size_t core_size = 0;  // the verification block and the body: what the blob proper takes of the file
    Envelope tail;         // what follows it: other data, or the fill up to the size of the partition
    size_t kernel_size = 0;  // the plain kernel (with its padding), as it lies in the body
    std::optional<uint64_t> data_key_algorithm;  // empty when the keyblock's data key cannot be read
    bool data_key_is_dev = false;  // the data key is the developer key abr can sign with
    // Whether the signatures verify with the data key: std::nullopt when abr cannot check them (an algorithm it
    // does not know, a key that is not the size of the algorithm).
    std::optional<bool> body_signature_ok;
    std::optional<bool> preamble_signature_ok;
};

// True when `data` starts with a keyblock: "CHROMEOS".
bool has_chromeos_header(const Bytes& data);

// Takes the blob apart: `kernel_out` becomes the kernel field of the body (what `futility vbutil_kernel
// --get-vmlinuz` writes first: the plain image, with zeros up to a 4096 boundary). If `data` is no blob,
// std::nullopt comes back and `kernel_out` is left alone. A blob that is not laid out the way futility writes
// it (see above) is refused: FormatError, with the reason; nothing is ever read wrongly.
std::optional<ChromeosInfo> strip_chromeos(const Bytes& data, Bytes& kernel_out);

// What the command line can add to apply_chromeos: a signing key, and a keyblock for it.
struct ChromeosSigning {
    std::optional<Bytes> keyblock;       // --chromeos-keyblock: replaces the blob's
    std::optional<ChromeosKey> key;      // --chromeos-key: signs; its public half is the data key of the keyblock
};

// How apply_chromeos got to its signatures.
enum class ChromeosSigned {
    KEPT,              // nothing they cover changed: the signatures of the original
    SIGNED,            // made again, with the developer key or the key given, under the keyblock the blob had
    NEW_KEYBLOCK,      // made again, under a keyblock that was given
    DEVELOPER_KEYBLOCK,  // made again with the developer key under abr's developer keyblock: the blob's keyblock
                       // was somebody else's and no key for it was given
};

// The blob for `kernel`: the verification block and the body made from `info` (the kernel padded up to 4096,
// the fields behind it), with the signatures as described above. `how`, if given, says which it was. Without
// `info.tail`, which the caller adds (Envelope::assemble). Refuses what cannot be made (a config longer than
// the field, a key that is not the keyblock's, a verification block too small for the signatures).
Bytes apply_chromeos(const Bytes& kernel, const ChromeosInfo& info, const ChromeosSigning& signing = {},
                     ChromeosSigned* how = nullptr);

}  // namespace abr::legacy
