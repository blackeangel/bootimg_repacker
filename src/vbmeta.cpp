// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/vbmeta.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstring>
#include <sstream>

namespace abr {

namespace {
constexpr size_t kVbmetaHeaderSize = 256;
constexpr size_t kAvbFooterSize = 64;
constexpr uint32_t kAvbMagic4 = 0x41564230;   // "AVB0" read as a big-endian u32, for readability only
constexpr uint32_t kAvbFooterMagic4 = 0x41564266;  // "AVBf"

struct AlgoParams {
    size_t hash_size;
    size_t sig_size;  // == RSA key size in bytes
    bool sha512;
};

AlgoParams algo_params(uint32_t algorithm_type) {
    switch (algorithm_type) {
        case 0: return {0, 0, false};       // NONE
        case 1: return {32, 256, false};    // SHA256_RSA2048
        case 2: return {32, 512, false};    // SHA256_RSA4096
        case 3: return {32, 1024, false};   // SHA256_RSA8192
        case 4: return {64, 256, true};     // SHA512_RSA2048
        case 5: return {64, 512, true};     // SHA512_RSA4096
        case 6: return {64, 1024, true};    // SHA512_RSA8192
        default:
            throw FormatError("unknown AVB algorithm_type: " + std::to_string(algorithm_type));
    }
}

Bytes digest(const Bytes& data, bool sha512) {
    Bytes out(sha512 ? 64 : 32);
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len,
                    sha512 ? EVP_sha512() : EVP_sha256(), nullptr) != 1)
        throw FormatError("EVP_Digest failed");
    out.resize(len);
    return out;
}

Bytes rsa_sign_pkcs1(const std::string& pem, const Bytes& msg_digest, bool sha512) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) throw FormatError("BIO_new_mem_buf failed");
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) throw FormatError("failed to parse AVB signing key (expected a PEM RSA private key)");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    Bytes sig;
    bool ok = false;
    if (ctx && EVP_PKEY_sign_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0 &&
        EVP_PKEY_CTX_set_signature_md(ctx, sha512 ? EVP_sha512() : EVP_sha256()) > 0) {
        size_t siglen = 0;
        if (EVP_PKEY_sign(ctx, nullptr, &siglen, msg_digest.data(), msg_digest.size()) > 0) {
            sig.resize(siglen);
            if (EVP_PKEY_sign(ctx, sig.data(), &siglen, msg_digest.data(), msg_digest.size()) > 0) {
                sig.resize(siglen);
                ok = true;
            }
        }
    }
    if (ctx) EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    if (!ok) throw FormatError("RSA signing failed (check that the key size matches algorithm_type)");
    return sig;
}

Bytes build_avb_footer(uint64_t original_image_size, uint64_t vbmeta_offset,
                        uint64_t vbmeta_size) {
    BinaryWriter w;
    w.bytes(reinterpret_cast<const uint8_t*>("AVBf"), 4);
    w.be32(1);  // version_major
    w.be32(0);  // version_minor
    w.be64(original_image_size);
    w.be64(vbmeta_offset);
    w.be64(vbmeta_size);
    w.zeros(28);
    return w.take();
}
}  // namespace

std::string avb_algorithm_name(uint32_t algorithm_type) {
    switch (algorithm_type) {
        case 0: return "NONE";
        case 1: return "SHA256_RSA2048";
        case 2: return "SHA256_RSA4096";
        case 3: return "SHA256_RSA8192";
        case 4: return "SHA512_RSA2048";
        case 5: return "SHA512_RSA4096";
        case 6: return "SHA512_RSA8192";
        default: return "UNKNOWN(" + std::to_string(algorithm_type) + ")";
    }
}

namespace {
std::string cstr_from(const uint8_t* p, size_t max_len) {
    size_t n = 0;
    while (n < max_len && p[n] != 0) ++n;
    return std::string(reinterpret_cast<const char*>(p), n);
}
}  // namespace

// Decodes the well-known descriptor payloads (struct layouts from
// avb_{hash,hashtree,property,kernel_cmdline,chain_partition}_descriptor.h,
// all big-endian, each followed by its variable-length data). Falls back
// to a generic "N bytes" summary for anything that doesn't parse cleanly
// (unknown tag, or a payload too short for its declared fixed part).
std::string AvbDescriptor::describe() const {
    try {
        BinaryReader r(content);
        switch (static_cast<AvbDescriptorTag>(tag)) {
            case AvbDescriptorTag::PROPERTY: {
                uint64_t klen = r.be64();
                r.be64();  // value length (not needed for the summary)
                std::string key = cstr_from(content.data() + r.pos(), klen);
                return "property: " + key;
            }
            case AvbDescriptorTag::HASH: {
                uint64_t image_size = r.be64();
                auto algo = r.fixed_bytes<32>();
                uint32_t pn_len = r.be32();
                r.be32();  // salt_len
                uint32_t digest_len = r.be32();
                r.be32();  // flags
                r.skip(60);
                std::string pname = cstr_from(content.data() + r.pos(), pn_len);
                return "hash: partition=" + pname + " algo=" + cstr_from(algo.data(), 32) +
                       " image_size=" + std::to_string(image_size) +
                       " digest=" + std::to_string(digest_len) + "B";
            }
            case AvbDescriptorTag::HASHTREE: {
                r.be32();  // dm_verity_version
                uint64_t image_size = r.be64();
                r.be64();
                r.be64();  // tree_offset, tree_size
                r.be32();
                r.be32();  // data_block_size, hash_block_size
                r.be32();  // fec_num_roots
                r.be64();
                r.be64();  // fec_offset, fec_size
                auto algo = r.fixed_bytes<32>();
                uint32_t pn_len = r.be32();
                r.be32();  // salt_len
                r.be32();  // root_digest_len
                r.be32();  // flags
                r.skip(60);
                std::string pname = cstr_from(content.data() + r.pos(), pn_len);
                return "hashtree: partition=" + pname + " algo=" + cstr_from(algo.data(), 32) +
                       " image_size=" + std::to_string(image_size);
            }
            case AvbDescriptorTag::KERNEL_CMDLINE: {
                r.be32();  // flags
                uint32_t clen = r.be32();
                std::string cmd = cstr_from(content.data() + r.pos(), clen);
                return "kernel_cmdline: " + cmd;
            }
            case AvbDescriptorTag::CHAIN_PARTITION: {
                r.be32();  // rollback_index_location
                uint32_t pn_len = r.be32();
                uint32_t pk_len = r.be32();
                r.be32();  // flags
                r.skip(60);
                std::string pname = cstr_from(content.data() + r.pos(), pn_len);
                return "chain_partition: " + pname + " (pubkey " + std::to_string(pk_len) + "B)";
            }
        }
    } catch (const FormatError&) {
        // fall through to the generic form below
    }
    const char* name = "unknown";
    switch (static_cast<AvbDescriptorTag>(tag)) {
        case AvbDescriptorTag::PROPERTY: name = "property"; break;
        case AvbDescriptorTag::HASHTREE: name = "hashtree"; break;
        case AvbDescriptorTag::HASH: name = "hash"; break;
        case AvbDescriptorTag::KERNEL_CMDLINE: name = "kernel_cmdline"; break;
        case AvbDescriptorTag::CHAIN_PARTITION: name = "chain_partition"; break;
    }
    return std::string(name) + " descriptor (" + std::to_string(content.size()) + " bytes)";
}

namespace {
VbmetaImage parse_header_at(const Bytes& image, size_t header_start) {
    if (header_start + kVbmetaHeaderSize > image.size())
        throw FormatError("AVB header would run past the end of the image");
    BinaryReader r(image);
    r.seek(header_start);
    if (!r.starts_with("AVB0", 4)) throw FormatError("not an AVB vbmeta header (bad magic)");
    r.skip(4);

    VbmetaImage v;
    v.required_libavb_version_major = r.be32();
    v.required_libavb_version_minor = r.be32();
    uint64_t auth_size = r.be64();
    uint64_t aux_size = r.be64();
    v.algorithm_type = r.be32();
    uint64_t hash_offset = r.be64();
    uint64_t hash_size = r.be64();
    uint64_t sig_offset = r.be64();
    uint64_t sig_size = r.be64();
    uint64_t pubkey_offset = r.be64();
    uint64_t pubkey_size = r.be64();
    uint64_t pubkey_meta_offset = r.be64();
    uint64_t pubkey_meta_size = r.be64();
    uint64_t desc_offset = r.be64();
    uint64_t desc_size = r.be64();
    v.rollback_index = r.be64();
    v.flags = r.be32();
    v.rollback_index_location = r.be32();
    v.release_string = r.asciiz(48);
    r.skip(80);  // reserved

    size_t auth_start = header_start + kVbmetaHeaderSize;
    size_t aux_start = auth_start + static_cast<size_t>(auth_size);
    if (aux_start + aux_size > image.size())
        throw FormatError("AVB auxiliary data block runs past the end of the image");

    if (hash_size > 0) {
        BinaryReader hr(image);
        hr.seek(auth_start + static_cast<size_t>(hash_offset));
        v.hash = hr.bytes(static_cast<size_t>(hash_size));
    }
    if (sig_size > 0) {
        BinaryReader sr(image);
        sr.seek(auth_start + static_cast<size_t>(sig_offset));
        v.signature = sr.bytes(static_cast<size_t>(sig_size));
    }
    if (pubkey_size > 0) {
        BinaryReader pr(image);
        pr.seek(aux_start + static_cast<size_t>(pubkey_offset));
        v.public_key = pr.bytes(static_cast<size_t>(pubkey_size));
    }
    if (pubkey_meta_size > 0) {
        BinaryReader pmr(image);
        pmr.seek(aux_start + static_cast<size_t>(pubkey_meta_offset));
        v.public_key_metadata = pmr.bytes(static_cast<size_t>(pubkey_meta_size));
    }
    if (desc_size > 0) {
        BinaryReader dr(image);
        dr.seek(aux_start + static_cast<size_t>(desc_offset));
        size_t end = dr.pos() + static_cast<size_t>(desc_size);
        while (dr.pos() + 16 <= end) {
            AvbDescriptor d;
            d.tag = dr.be64();
            uint64_t nbf = dr.be64();
            if (dr.pos() + nbf > end)
                throw FormatError("AVB descriptor length runs past the descriptor block");
            d.content = dr.bytes(static_cast<size_t>(nbf));
            v.descriptors.push_back(std::move(d));
        }
    }
    return v;
}

Bytes build_blob(const VbmetaImage& v, const std::string& private_key_pem) {
    AlgoParams ap = algo_params(v.algorithm_type);

    BinaryWriter aux;
    for (auto& d : v.descriptors) {
        aux.be64(d.tag);
        aux.be64(d.content.size());
        aux.bytes(d.content);
    }
    uint64_t descriptors_size = aux.size();
    aux.align(8);
    uint64_t pubkey_offset = aux.size();
    aux.bytes(v.public_key);
    aux.align(8);
    uint64_t pubkey_meta_offset = aux.size();
    aux.bytes(v.public_key_metadata);
    aux.align(8);
    aux.align(64);
    Bytes aux_bytes = aux.take();

    uint64_t auth_size = (ap.hash_size || ap.sig_size) ? align_up(ap.hash_size + ap.sig_size, 64) : 0;

    BinaryWriter hdr;
    hdr.bytes(reinterpret_cast<const uint8_t*>("AVB0"), 4);
    hdr.be32(v.required_libavb_version_major);
    hdr.be32(v.required_libavb_version_minor);
    hdr.be64(auth_size);
    hdr.be64(aux_bytes.size());
    hdr.be32(v.algorithm_type);
    hdr.be64(0);
    hdr.be64(ap.hash_size);
    hdr.be64(ap.hash_size);
    hdr.be64(ap.sig_size);
    hdr.be64(pubkey_offset);
    hdr.be64(v.public_key.size());
    hdr.be64(pubkey_meta_offset);
    hdr.be64(v.public_key_metadata.size());
    hdr.be64(0);
    hdr.be64(descriptors_size);
    hdr.be64(v.rollback_index);
    hdr.be32(v.flags);
    hdr.be32(v.rollback_index_location);
    hdr.asciiz(v.release_string, 48);
    hdr.zeros(80);
    Bytes header_bytes = hdr.take();

    Bytes result = header_bytes;
    if (v.algorithm_type == 0) {
        result.insert(result.end(), aux_bytes.begin(), aux_bytes.end());
        return result;
    }

    Bytes to_hash = header_bytes;
    to_hash.insert(to_hash.end(), aux_bytes.begin(), aux_bytes.end());
    Bytes h = digest(to_hash, ap.sha512);

    Bytes sig;
    if (!private_key_pem.empty()) {
        sig = rsa_sign_pkcs1(private_key_pem, h, ap.sha512);
        if (sig.size() != ap.sig_size)
            throw FormatError("signing key size does not match algorithm_type " +
                               avb_algorithm_name(v.algorithm_type) + " (expected a " +
                               std::to_string(ap.sig_size * 8) + "-bit RSA key)");
    } else if (h == v.hash && v.signature.size() == ap.sig_size) {
        sig = v.signature;  // untouched passthrough
    } else {
        throw FormatError(
            "vbmeta content changed (or was never signed with a key we have) and no "
            "private key was supplied to re-sign; pass a signing key or rebuild with "
            "algorithm_type=NONE for an unsigned image");
    }

    Bytes auth_block(static_cast<size_t>(auth_size), 0);
    std::copy(h.begin(), h.end(), auth_block.begin());
    std::copy(sig.begin(), sig.end(), auth_block.begin() + static_cast<long>(ap.hash_size));
    result.insert(result.end(), auth_block.begin(), auth_block.end());
    result.insert(result.end(), aux_bytes.begin(), aux_bytes.end());
    return result;
}
}  // namespace

VbmetaImage VbmetaImage::parse(const Bytes& image) {
    if (image.size() >= 4 && std::memcmp(image.data(), "AVB0", 4) == 0) {
        VbmetaImage v = parse_header_at(image, 0);
        v.source_total_size = image.size();
        return v;
    }
    if (image.size() >= kAvbFooterSize) {
        BinaryReader fr(image);
        fr.seek(image.size() - kAvbFooterSize);
        if (fr.starts_with("AVBf", 4)) {
            fr.skip(4);
            fr.be32();  // footer version_major
            fr.be32();  // footer version_minor
            uint64_t orig_size = fr.be64();
            uint64_t vbmeta_offset = fr.be64();
            uint64_t vbmeta_size = fr.be64();
            if (vbmeta_offset + vbmeta_size > image.size())
                throw FormatError("AVB footer points past the end of the image");
            VbmetaImage v = parse_header_at(image, static_cast<size_t>(vbmeta_offset));
            v.has_footer = true;
            v.footer_original_image_size = orig_size;
            v.host_prefix.assign(image.begin(), image.begin() + static_cast<long>(vbmeta_offset));
            v.source_total_size = image.size();
            return v;
        }
    }
    throw FormatError("not a vbmeta image: no 'AVB0' header at offset 0 and no 'AVBf' footer found");
}

Bytes VbmetaImage::build(const std::string& private_key_pem) const {
    Bytes blob = build_blob(*this, private_key_pem);
    if (!has_footer) return blob;

    Bytes out = host_prefix;
    uint64_t vbmeta_offset = out.size();
    out.insert(out.end(), blob.begin(), blob.end());

    uint64_t footer_pos =
        source_total_size >= kAvbFooterSize ? source_total_size - kAvbFooterSize : out.size();
    if (footer_pos < out.size()) footer_pos = out.size();
    out.resize(static_cast<size_t>(footer_pos), 0);

    uint64_t orig_size = footer_original_image_size ? footer_original_image_size : vbmeta_offset;
    Bytes footer = build_avb_footer(orig_size, vbmeta_offset, blob.size());
    out.insert(out.end(), footer.begin(), footer.end());
    if (source_total_size > out.size()) out.resize(static_cast<size_t>(source_total_size), 0);
    return out;
}

}  // namespace abr
