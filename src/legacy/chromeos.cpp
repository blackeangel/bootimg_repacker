// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/chromeos.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include "abr/sha.hpp"

namespace abr::legacy {

namespace detail {
extern const uint8_t kChromeosDevKeyblock[];
extern const size_t kChromeosDevKeyblockSize;
extern const uint8_t kChromeosDevKernelDataKey[];
extern const size_t kChromeosDevKernelDataKeySize;
}  // namespace detail

namespace {

constexpr char kKeyblockMagic[] = "CHROMEOS";
constexpr size_t kKeyblockMagicSize = 8;
constexpr size_t kKeyblockHeaderSize = 112;  // vb2_keyblock: the fields, then the data key's descriptor at 80
constexpr size_t kDataKeyDescriptor = 80;    // u64 key_offset, key_size, algorithm, key_version (32 bytes)
constexpr size_t kPreambleV20 = 96;          // vb2_kernel_preamble 2.0
constexpr size_t kPreambleV21 = 112;         // 2.1: + the vmlinuz header's address and size
constexpr size_t kPreambleV22 = 116;         // 2.2: + the flags
constexpr size_t kPreambleSigAt = 8;         // the descriptor of the preamble's signature
constexpr size_t kBodySigAt = 72;            // the descriptor of the body's signature
constexpr size_t kSignatureDescriptorSize = 24;

uint32_t get32(const Bytes& d, size_t off) {
    return uint32_t(d[off]) | uint32_t(d[off + 1]) << 8 | uint32_t(d[off + 2]) << 16 | uint32_t(d[off + 3]) << 24;
}
uint64_t get64(const Bytes& d, size_t off) { return uint64_t(get32(d, off)) | uint64_t(get32(d, off + 4)) << 32; }
void put32(Bytes& d, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) d[off + i] = static_cast<uint8_t>(v >> (8 * i));
}
void put64(Bytes& d, size_t off, uint64_t v) {
    put32(d, off, static_cast<uint32_t>(v));
    put32(d, off + 4, static_cast<uint32_t>(v >> 32));
}

size_t preamble_fixed_size(uint32_t minor) { return minor == 0 ? kPreambleV20 : minor == 1 ? kPreambleV21 : kPreambleV22; }

Bytes digest(HashAlg alg, const uint8_t* p, size_t n) {
    switch (alg) {
        case HashAlg::SHA1: return hash::sha1(p, n);
        case HashAlg::SHA256: return hash::sha256(p, n);
        case HashAlg::SHA512: return hash::sha512(p, n);
    }
    return {};
}

Bytes trimmed(const Bytes& d, size_t off, size_t len) {
    size_t end = off + len;
    while (end > off && d[end - 1] == 0) --end;
    return Bytes(d.begin() + static_cast<std::ptrdiff_t>(off), d.begin() + static_cast<std::ptrdiff_t>(end));
}

// One field of the body: `content` (up to its last non-zero byte) padded with zeros to `size`.
void append_field(Bytes& body, const Bytes& content, size_t size, const char* what) {
    if (content.size() > size)
        throw FormatError(std::string("the ") + what + " of a ChromeOS blob is " + std::to_string(content.size()) +
                          " bytes; its field holds " + std::to_string(size));
    body.insert(body.end(), content.begin(), content.end());
    body.resize(body.size() + (size - content.size()), 0);
}

// The signature descriptor at `at` of the preamble: sig_offset, sig_size, data_size, each followed by a reserved
// word that must be zero (a descriptor that has anything there is not one futility wrote).
struct Descriptor {
    uint32_t offset = 0, size = 0, data_size = 0;
};
Descriptor read_descriptor(const Bytes& pre, size_t at, const char* what) {
    if (get32(pre, at + 4) != 0 || get32(pre, at + 12) != 0 || get32(pre, at + 20) != 0)
        throw FormatError(std::string("this ChromeOS blob has something in the reserved words of the descriptor of its ") +
                          what + ", which abr could not keep");
    return {get32(pre, at), get32(pre, at + 8), get32(pre, at + 16)};
}

void write_descriptor(Bytes& pre, size_t at, const Descriptor& d) {
    put32(pre, at, d.offset);
    put32(pre, at + 8, d.size);
    put32(pre, at + 16, d.data_size);
}

bool is_dev_data_key(const ChromeosDataKey& k) {
    const ChromeosKey& dev = chromeos_dev_key();
    return k.rsa && k.algorithm == dev.algorithm && k.rsa->n == dev.rsa.n;
}

// SHA-256 of what the signatures cover (see ChromeosInfo::signed_sha256): the keyblock, the preamble's head (the
// header and the body signature), the body.
Bytes signed_hash(const Bytes& keyblock, const uint8_t* head, size_t head_size, const uint8_t* body, size_t body_size) {
    hash::Sha256 h;
    h.update(keyblock);
    h.update(head, head_size);
    h.update(body, body_size);
    return h.finish();
}

}  // namespace

std::optional<ChromeosAlgorithm> chromeos_algorithm(uint64_t id) {
    static const size_t kBits[] = {1024, 2048, 4096, 8192};
    static const HashAlg kHash[] = {HashAlg::SHA1, HashAlg::SHA256, HashAlg::SHA512};
    ChromeosAlgorithm a;
    if (id <= 11) {
        a.key_bits = kBits[id / 3];
        a.hash = kHash[id % 3];
    } else if (id <= 14) {
        a.key_bits = 2048;
        a.exponent = 3;
        a.hash = kHash[id - 12];
    } else if (id <= 17) {
        a.key_bits = 3072;
        a.exponent = 3;
        a.hash = kHash[id - 15];
    } else {
        return std::nullopt;
    }
    return a;
}

std::string chromeos_algorithm_name(uint64_t id) {
    const auto a = chromeos_algorithm(id);
    if (!a) return "algorithm " + std::to_string(id);
    const char* hash = a->hash == HashAlg::SHA1 ? "SHA-1" : a->hash == HashAlg::SHA256 ? "SHA-256" : "SHA-512";
    return "RSA-" + std::to_string(a->key_bits) + (a->exponent == 3 ? "-EXP3" : "") + "/" + hash;
}

ChromeosKey parse_vbprivk(const Bytes& file) {
    if (file.size() < 8 + 16)
        throw FormatError("this is not a .vbprivk file (too short: it is the algorithm, 8 bytes, and a DER RSA key)");
    ChromeosKey k;
    k.algorithm = get64(file, 0);
    const auto alg = chromeos_algorithm(k.algorithm);
    if (!alg)
        throw FormatError("this .vbprivk file names algorithm " + std::to_string(k.algorithm) +
                          ", which abr does not know (0 to 17)");
    // DER from the ninth byte on: the key of the PKCS#1 RSAPrivateKey (what i2d_RSAPrivateKey writes).
    try {
        k.rsa = rsa_parse_private_key(Bytes(file.begin() + 8, file.end()));
    } catch (const FormatError& e) {
        throw FormatError(std::string("this .vbprivk file does not hold an RSA key behind its algorithm word: ") + e.what());
    }
    if (k.rsa.size_bytes() * 8 != alg->key_bits)
        throw FormatError("this .vbprivk file names " + chromeos_algorithm_name(k.algorithm) + ", a key of " +
                          std::to_string(alg->key_bits) + " bits, and holds one of " + std::to_string(k.rsa.n.bit_length()));
    return k;
}

ChromeosDataKey keyblock_data_key(const Bytes& keyblock) {
    if (keyblock.size() < kKeyblockHeaderSize)
        throw FormatError("this keyblock is cut short: its header does not fit");
    ChromeosDataKey k;
    const uint64_t key_offset = get64(keyblock, kDataKeyDescriptor);
    const uint64_t key_size = get64(keyblock, kDataKeyDescriptor + 8);
    k.algorithm = get64(keyblock, kDataKeyDescriptor + 16);
    k.version = get64(keyblock, kDataKeyDescriptor + 24);
    // The offset counts from the descriptor.
    if (key_offset > keyblock.size() || key_size > keyblock.size() ||
        kDataKeyDescriptor + key_offset + key_size > keyblock.size())
        throw FormatError("the data key of this keyblock lies outside of it");
    const auto alg = chromeos_algorithm(k.algorithm);
    if (!alg) return k;
    // A packed key: u32 arrsize (the modulus in 32-bit words), u32 n0inv, n (arrsize words, least significant
    // first), rr (the same). The words are little endian, so n is simply the little endian bytes.
    const size_t at = static_cast<size_t>(kDataKeyDescriptor + key_offset);
    if (key_size < 8) return k;
    const uint32_t arrsize = get32(keyblock, at);
    if (uint64_t(arrsize) * 32 != alg->key_bits || key_size != 8 + uint64_t(arrsize) * 8) return k;
    Bytes n_be(keyblock.begin() + static_cast<std::ptrdiff_t>(at + 8),
               keyblock.begin() + static_cast<std::ptrdiff_t>(at + 8 + size_t(arrsize) * 4));
    std::reverse(n_be.begin(), n_be.end());
    RsaPublicKey pub;
    pub.n = BigInt::from_bytes_be(n_be);
    pub.e = BigInt(alg->exponent);
    if (!pub.n.is_odd() || pub.n.bit_length() != alg->key_bits) return k;
    k.rsa = pub;
    return k;
}

const Bytes& chromeos_dev_keyblock() {
    static const Bytes kb(detail::kChromeosDevKeyblock, detail::kChromeosDevKeyblock + detail::kChromeosDevKeyblockSize);
    return kb;
}

const ChromeosKey& chromeos_dev_key() {
    static const ChromeosKey key = parse_vbprivk(
        Bytes(detail::kChromeosDevKernelDataKey, detail::kChromeosDevKernelDataKey + detail::kChromeosDevKernelDataKeySize));
    return key;
}

bool has_chromeos_header(const Bytes& data) {
    return data.size() >= kKeyblockMagicSize && std::memcmp(data.data(), kKeyblockMagic, kKeyblockMagicSize) == 0;
}

std::optional<ChromeosInfo> strip_chromeos(const Bytes& data, Bytes& kernel_out) {
    if (!has_chromeos_header(data)) return std::nullopt;
    ChromeosInfo info;

    // --- the keyblock: kept as it is
    if (data.size() < kKeyblockHeaderSize)
        throw FormatError("this ChromeOS kernel blob is cut short: its keyblock does not fit");
    const uint32_t kb_major = get32(data, 8);
    const uint32_t kb_minor = get32(data, 12);
    if (kb_major != 2)
        throw FormatError("this ChromeOS kernel blob has a keyblock of version " + std::to_string(kb_major) + "." +
                          std::to_string(kb_minor) + "; abr reads version 2");
    const uint64_t kb_size = get64(data, 16);
    if (kb_size < kKeyblockHeaderSize)
        throw FormatError("this ChromeOS kernel blob says its keyblock is " + std::to_string(kb_size) +
                          " bytes, which is less than its header");
    if (kb_size > data.size() || data.size() - kb_size < kPreambleV20)
        throw FormatError("this ChromeOS kernel blob is cut short: its keyblock of " + std::to_string(kb_size) +
                          " bytes and the preamble do not fit in the " + std::to_string(data.size()) + " bytes of the file");
    info.keyblock.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(kb_size));

    // --- the preamble
    const size_t pre_off = static_cast<size_t>(kb_size);
    const uint32_t preamble_size = get32(data, pre_off);
    if (get32(data, pre_off + 4) != 0)
        throw FormatError("this ChromeOS kernel blob has a non-zero reserved word in its preamble, which abr could not keep");
    if (preamble_size < kPreambleV20)
        throw FormatError("this ChromeOS kernel blob says its preamble is " + std::to_string(preamble_size) +
                          " bytes, which is less than its header");
    if (data.size() - pre_off < preamble_size)
        throw FormatError("this ChromeOS kernel blob is cut short: its preamble of " + std::to_string(preamble_size) +
                          " bytes does not fit");
    const Bytes pre(data.begin() + static_cast<std::ptrdiff_t>(pre_off),
                    data.begin() + static_cast<std::ptrdiff_t>(pre_off) + preamble_size);

    info.preamble_major = get32(pre, 32);
    info.preamble_minor = get32(pre, 36);
    if (info.preamble_major != 2 || info.preamble_minor > 2)
        throw FormatError("this ChromeOS kernel blob has a preamble of version " + std::to_string(info.preamble_major) + "." +
                          std::to_string(info.preamble_minor) + "; abr reads 2.0, 2.1 and 2.2");
    const size_t fixed = preamble_fixed_size(info.preamble_minor);
    if (preamble_size < fixed)
        throw FormatError("this ChromeOS kernel blob says its preamble is " + std::to_string(preamble_size) +
                          " bytes; a preamble of version 2." + std::to_string(info.preamble_minor) + " has " +
                          std::to_string(fixed) + " bytes before its signatures");

    const Descriptor psig = read_descriptor(pre, kPreambleSigAt, "preamble signature");
    const Descriptor bsig = read_descriptor(pre, kBodySigAt, "body signature");
    if (get32(pre, 44) != 0 || get32(pre, 68) != 0 || (info.preamble_minor >= 1 && get32(pre, 108) != 0))
        throw FormatError("this ChromeOS kernel blob has a non-zero reserved word in its preamble, which abr could not keep");

    // The layout futility writes: the header, the body's signature, the preamble's signature, zeros. Anything else
    // is not read, so that nothing is lost.
    if (bsig.size == 0 || psig.size == 0)
        throw FormatError("this ChromeOS kernel blob has an empty signature");
    if (bsig.offset != fixed - kBodySigAt || psig.offset != fixed + uint64_t(bsig.size) - kPreambleSigAt ||
        psig.data_size != fixed + uint64_t(bsig.size) || fixed + uint64_t(bsig.size) + psig.size > preamble_size)
        throw FormatError("this ChromeOS kernel blob does not have its signatures where futility puts them (the body's "
                          "right behind the preamble header, the preamble's after it, zeros after that); abr reads "
                          "only that layout, so that nothing is lost");
    const size_t sigs_end = fixed + bsig.size + psig.size;
    for (size_t i = sigs_end; i < preamble_size; ++i)
        if (pre[i] != 0)
            throw FormatError("this ChromeOS kernel blob has data of its own behind the signatures of its preamble (at " +
                              std::to_string(pre_off + i) + "), which abr could not keep");

    info.kernel_version = get32(pre, 40);
    info.body_load_address = get64(pre, 48);
    const uint64_t bootloader_address = get64(pre, 56);
    info.bootloader_size = get32(pre, 64);
    if (info.preamble_minor >= 1) {
        info.vmlinuz_header_address = get64(pre, 96);
        if (get32(pre, 104) != 0)
            throw FormatError("this ChromeOS kernel blob carries a vmlinuz header (" + std::to_string(get32(pre, 104)) +
                              " bytes): it is a kernel for x86, a bzImage that no Android tool opens");
    }
    if (info.preamble_minor >= 2) info.flags = get32(pre, 112);
    info.pad = static_cast<uint32_t>(kb_size + preamble_size);
    info.body_signature.assign(pre.begin() + static_cast<std::ptrdiff_t>(fixed),
                               pre.begin() + static_cast<std::ptrdiff_t>(fixed + bsig.size));
    info.preamble_signature.assign(pre.begin() + static_cast<std::ptrdiff_t>(fixed + bsig.size),
                                   pre.begin() + static_cast<std::ptrdiff_t>(sigs_end));

    // --- the body: kernel, config, params, bootloader
    const size_t body_off = pre_off + preamble_size;
    const uint64_t body_size = bsig.data_size;
    if (data.size() - body_off < body_size)
        throw FormatError("this ChromeOS blob is cut short: its body is " + std::to_string(body_size) +
                          " bytes and the file has " + std::to_string(data.size() - body_off) + " behind the preamble");
    if (info.bootloader_size % kChromeosAlign != 0)
        throw FormatError("this ChromeOS blob has a bootloader of " + std::to_string(info.bootloader_size) +
                          " bytes; abr reads a body of fields of 4096 bytes, as futility makes it");
    const uint64_t fixed_fields = kChromeosConfigSize + kChromeosParamsSize + uint64_t(info.bootloader_size);
    if (body_size <= fixed_fields)
        throw FormatError("this ChromeOS blob has a body of " + std::to_string(body_size) + " bytes, too small for a kernel, "
                          "the config, the params and a bootloader of " + std::to_string(info.bootloader_size) + " bytes");
    const size_t kernel_size = static_cast<size_t>(body_size - fixed_fields);
    if (kernel_size % kChromeosAlign != 0)
        throw FormatError("this ChromeOS blob has a kernel of " + std::to_string(kernel_size) +
                          " bytes (its body minus the other fields); abr reads a kernel aligned to 4096 bytes, as futility makes it");
    if (bootloader_address != info.body_load_address + kernel_size + kChromeosConfigSize + kChromeosParamsSize)
        info.bootloader_address = bootloader_address;
    info.kernel_size = kernel_size;

    // (the body is read in place: `data` holds it, a copy of a 64 MiB kernel is not made)
    const uint8_t* body = data.data() + body_off;
    info.config = trimmed(data, body_off + kernel_size, kChromeosConfigSize);
    info.params = trimmed(data, body_off + kernel_size + kChromeosConfigSize, kChromeosParamsSize);
    info.bootloader = trimmed(data, body_off + kernel_size + kChromeosConfigSize + kChromeosParamsSize, info.bootloader_size);

    // --- what the signatures cover, and whether they are good
    info.signed_sha256 = signed_hash(info.keyblock, pre.data(), fixed + bsig.size, body, static_cast<size_t>(body_size));
    try {
        const ChromeosDataKey dk = keyblock_data_key(info.keyblock);
        info.data_key_algorithm = dk.algorithm;
        info.data_key_is_dev = is_dev_data_key(dk);
        if (dk.rsa) {
            const ChromeosAlgorithm alg = *chromeos_algorithm(dk.algorithm);
            if (bsig.size == alg.key_bits / 8)
                info.body_signature_ok = rsa_pkcs1_verify(*dk.rsa, alg.hash, digest(alg.hash, body, static_cast<size_t>(body_size)),
                                                          info.body_signature);
            if (psig.size == alg.key_bits / 8)
                info.preamble_signature_ok = rsa_pkcs1_verify(*dk.rsa, alg.hash, digest(alg.hash, pre.data(), fixed + bsig.size),
                                                              info.preamble_signature);
        }
    } catch (const FormatError&) {
        // A keyblock whose data key cannot be read: the signatures are not checked, nothing else changes.
    }

    kernel_out.assign(body, body + kernel_size);
    info.core_size = body_off + static_cast<size_t>(body_size);
    info.tail = Envelope::capture(data, 0, info.core_size);
    return info;
}

Bytes apply_chromeos(const Bytes& kernel, const ChromeosInfo& info, const ChromeosSigning& signing, ChromeosSigned* how) {
    if (kernel.empty()) throw FormatError("the kernel of a ChromeOS blob cannot be empty");
    if (info.preamble_major != 2 || info.preamble_minor > 2)
        throw FormatError("a ChromeOS preamble of version " + std::to_string(info.preamble_major) + "." +
                          std::to_string(info.preamble_minor) + " is not one abr makes (2.0, 2.1 and 2.2 are)");
    if (info.preamble_minor < 2 && info.flags != 0) {
        char flags[16];
        std::snprintf(flags, sizeof flags, "0x%x", info.flags);
        throw FormatError(std::string("the flags of a ChromeOS blob (") + flags + ") need a preamble of version 2.2; this one is 2." +
                          std::to_string(info.preamble_minor));
    }
    if (info.preamble_minor < 1 && info.vmlinuz_header_address != 0)
        throw FormatError("the vmlinuz header address of a ChromeOS blob needs a preamble of version 2.1 or 2.2");

    // --- the body
    const size_t kernel_size = static_cast<size_t>(align_up(kernel.size(), kChromeosAlign));
    const size_t bootloader_size = static_cast<size_t>(
        align_up(std::max<uint64_t>(info.bootloader_size, info.bootloader.size()), kChromeosAlign));
    Bytes body = kernel;
    body.resize(kernel_size, 0);
    append_field(body, info.config, kChromeosConfigSize, "config");
    append_field(body, info.params, kChromeosParamsSize, "params");
    append_field(body, info.bootloader, bootloader_size, "bootloader");
    const uint64_t bootloader_address =
        info.bootloader_address.value_or(info.body_load_address + kernel_size + kChromeosConfigSize + kChromeosParamsSize);

    // --- the preamble's head with the signatures of the original, and what it covers: if that is what the
    //     signatures covered, they are good
    auto build_head = [&](size_t keyblock_size, size_t body_sig_size, size_t preamble_sig_size, size_t* preamble_size) {
        const size_t fixed = preamble_fixed_size(info.preamble_minor);
        if (info.pad < keyblock_size + fixed + body_sig_size + preamble_sig_size)
            throw FormatError("the verification block of this ChromeOS blob is " + std::to_string(info.pad) +
                              " bytes; the keyblock of " + std::to_string(keyblock_size) + " bytes, the preamble header of " +
                              std::to_string(fixed) + " and two signatures of " + std::to_string(body_sig_size) + " and " +
                              std::to_string(preamble_sig_size) + " do not fit");
        *preamble_size = info.pad - keyblock_size;
        Bytes head(fixed, 0);
        put32(head, 0, static_cast<uint32_t>(*preamble_size));
        write_descriptor(head, kPreambleSigAt,
                         {static_cast<uint32_t>(fixed + body_sig_size - kPreambleSigAt), static_cast<uint32_t>(preamble_sig_size),
                          static_cast<uint32_t>(fixed + body_sig_size)});
        put32(head, 32, info.preamble_major);
        put32(head, 36, info.preamble_minor);
        put32(head, 40, info.kernel_version);
        put64(head, 48, info.body_load_address);
        put64(head, 56, bootloader_address);
        put32(head, 64, static_cast<uint32_t>(bootloader_size));
        write_descriptor(head, kBodySigAt,
                         {static_cast<uint32_t>(fixed - kBodySigAt), static_cast<uint32_t>(body_sig_size),
                          static_cast<uint32_t>(body.size())});
        if (info.preamble_minor >= 1) put64(head, 96, info.vmlinuz_header_address);
        if (info.preamble_minor >= 2) put32(head, 112, info.flags);
        return head;
    };
    auto assemble = [&](const Bytes& keyblock, const Bytes& head, size_t preamble_size, const Bytes& body_sig, const Bytes& preamble_sig) {
        Bytes out;
        out.reserve(keyblock.size() + preamble_size + body.size());
        out.insert(out.end(), keyblock.begin(), keyblock.end());
        out.insert(out.end(), head.begin(), head.end());
        out.insert(out.end(), body_sig.begin(), body_sig.end());
        out.insert(out.end(), preamble_sig.begin(), preamble_sig.end());
        out.resize(keyblock.size() + preamble_size, 0);
        out.insert(out.end(), body.begin(), body.end());
        return out;
    };

    if (signing.keyblock) {
        const Bytes& kb = *signing.keyblock;
        if (!has_chromeos_header(kb))
            throw FormatError("the keyblock given (--chromeos-keyblock) is not a keyblock: it does not start with \"CHROMEOS\"");
        if (kb.size() < kKeyblockHeaderSize)
            throw FormatError("the keyblock given (--chromeos-keyblock) is cut short: its header is " +
                              std::to_string(kKeyblockHeaderSize) + " bytes and the file has " + std::to_string(kb.size()));
        if (get64(kb, 16) != kb.size())
            throw FormatError("the keyblock given (--chromeos-keyblock) says it is " + std::to_string(get64(kb, 16)) +
                              " bytes; the file has " + std::to_string(kb.size()));
    }
    const Bytes& keyblock = signing.keyblock ? *signing.keyblock : info.keyblock;
    ChromeosDataKey data_key;
    try {
        data_key = keyblock_data_key(keyblock);
    } catch (const FormatError& e) {
        if (signing.keyblock) throw FormatError(std::string("the keyblock given is not usable: ") + e.what());
        // The keyblock of the blob: its data key cannot be read; kept signatures are all there can be.
    }
    if (signing.key) {
        const ChromeosKey& k = *signing.key;
        if (!data_key.rsa || data_key.algorithm != k.algorithm || data_key.rsa->n != k.rsa.n)
            throw FormatError("the key given (--chromeos-key) is not the data key of the keyblock (" +
                              std::string(signing.keyblock ? "the one given with --chromeos-keyblock" : "the blob's; the keyblock "
                                          "made for the key is given with --chromeos-keyblock") + ")");
    }

    {
        size_t preamble_size = 0;
        const Bytes head = build_head(keyblock.size(), info.body_signature.size(), info.preamble_signature.size(), &preamble_size);
        Bytes signed_head = head;
        signed_head.insert(signed_head.end(), info.body_signature.begin(), info.body_signature.end());
        if (!info.signed_sha256.empty() &&
            signed_hash(keyblock, signed_head.data(), signed_head.size(), body.data(), body.size()) == info.signed_sha256) {
            if (how) *how = ChromeosSigned::KEPT;
            return assemble(keyblock, head, preamble_size, info.body_signature, info.preamble_signature);
        }
    }

    // --- something the signatures cover has changed: they are made again
    const Bytes* use_keyblock = &keyblock;
    ChromeosKey key;
    ChromeosSigned made = signing.keyblock ? ChromeosSigned::NEW_KEYBLOCK : ChromeosSigned::SIGNED;
    if (signing.key) {
        key = *signing.key;
    } else if (is_dev_data_key(data_key)) {
        key = chromeos_dev_key();
    } else if (signing.keyblock) {
        throw FormatError("the keyblock given (--chromeos-keyblock) has a data key of which abr has no key: pass the key "
                          "with --chromeos-key");
    } else {
        use_keyblock = &chromeos_dev_keyblock();
        key = chromeos_dev_key();
        made = ChromeosSigned::DEVELOPER_KEYBLOCK;
    }
    const ChromeosAlgorithm alg = *chromeos_algorithm(key.algorithm);
    const size_t sig_size = alg.key_bits / 8;
    size_t preamble_size = 0;
    Bytes head = build_head(use_keyblock->size(), sig_size, sig_size, &preamble_size);
    const Bytes body_sig = rsa_pkcs1_sign(key.rsa, alg.hash, digest(alg.hash, body.data(), body.size()));
    Bytes signed_head = head;
    signed_head.insert(signed_head.end(), body_sig.begin(), body_sig.end());
    const Bytes preamble_sig = rsa_pkcs1_sign(key.rsa, alg.hash, digest(alg.hash, signed_head.data(), signed_head.size()));
    if (how) *how = made;
    return assemble(*use_keyblock, head, preamble_size, body_sig, preamble_sig);
}

}  // namespace abr::legacy
