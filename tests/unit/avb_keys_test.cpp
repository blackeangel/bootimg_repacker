// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of the AVB 2.0 test keys built into abr (include/abr/avb_keys.hpp) and of what the vbmeta code does with them. Run by
// tests/run_tests.sh as `abr_unit_tests avbkeys`.
//
//   * every key parses, has the size it is listed with, is different from the others, and signs: what it signs verifies with its public
//     key; the public key blob of each is the one an independent calculation gives (Python's integers; the SHA-1 of it is what avbtool
//     prints as the key's id);
//   * a key whose numbers do not agree (any of n, e, d, p, q, dp, dq, qinv wrong; a prime of 1) is refused when it is read, one written
//     back from its own numbers is taken, and one without CRT numbers is used through d and gives the same signature;
//   * a key is found by the public key blob of a vbmeta and by nothing else: not a blob of another size, not one with a byte changed,
//     not an empty one, not a short one;
//   * choose_avb_test_key: for each RSA algorithm the key of the size it needs -- the image's own when the blob is one of these, else the
//     first of that size --, and nothing for NONE, for ML-DSA and for numbers that are no algorithm;
//   * a vbmeta made with the chosen key for each RSA algorithm: it parses, it holds the key's public key blob, its signature verifies over
//     the digest of the header and the auxiliary block, can_keep_signature() is true; false once something the signature covers has
//     changed, and true again for the rebuild with the key; an image rebuilt without a key comes back byte for byte and, changed, is refused;
//   * ML-DSA (algorithm 7 and 8), an image made here by hand after libavb's layout: it is read, listed, rebuilt byte for byte when nothing has
//     changed, and refused (with the reason) when something has, with or without an RSA key; the algorithm names;
//   * the description of a chain partition descriptor names the test key its public key is, and a descriptor that lies about its sizes is
//     described without a crash; describe_avb_public_key.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "abr/asn1.hpp"
#include "abr/avb_keys.hpp"
#include "abr/byte_io.hpp"
#include "abr/rsa.hpp"
#include "abr/sha.hpp"
#include "abr/vbmeta.hpp"

using namespace abr;

namespace {

int g_failures = 0;
int g_checks = 0;

#define EXPECT(cond)                                                      \
    do {                                                                  \
        ++g_checks;                                                       \
        if (!(cond)) {                                                    \
            ++g_failures;                                                 \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                 \
    } while (0)

// f() throws a FormatError that has `text` in its message.
template <class F>
bool refuses(F&& f, const char* text) {
    try {
        f();
    } catch (const FormatError& e) {
        return std::string(e.what()).find(text) != std::string::npos;
    } catch (...) {
    }
    return false;
}

Bytes bytes_of(const char* s) { return Bytes(reinterpret_cast<const uint8_t*>(s), reinterpret_cast<const uint8_t*>(s) + std::strlen(s)); }

std::string hex(const Bytes& b) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (const uint8_t x : b) {
        out.push_back(digits[x >> 4]);
        out.push_back(digits[x & 15]);
    }
    return out;
}

uint64_t be64_at(const Bytes& b, size_t off) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) v = (v << 8) | b[off + i];
    return v;
}

// (parsed once: reading a key of 8192 bits is not free)
const RsaPrivateKey& parse_key(const AvbTestKey& k) {
    static std::map<std::string, RsaPrivateKey> cache;
    auto it = cache.find(k.name);
    if (it == cache.end()) it = cache.emplace(k.name, rsa_parse_private_key(bytes_of(k.pem))).first;
    return it->second;
}

// The SHA-1 of each key's public key blob, from Python's integers (n0inv = -1/n mod 2^32, R^2 = 2^(2 bits) mod n).
struct Known {
    const char* name;
    unsigned bits;
    const char* sha1;
};
const Known kKnown[] = {
    {"testkey_rsa2048", 2048, "cdbb77177f731920bbe0a0f94f84d9038ae0617d"},
    {"testkey_rsa4096", 4096, "2597c218aae470a130f61162feaae70afd97f011"},
    {"testkey_rsa8192", 8192, "5227b569de003adc7f8ec3fc03e05dfbd969abad"},
    {"testkey_rsa2048_2", 2048, "6474a3f23259eaee2a5d885fa0869b0baba63712"},
};

const AvbTestKey* key_named(const char* name) {
    for (const AvbTestKey& k : avb_test_keys())
        if (std::strcmp(k.name, name) == 0) return &k;
    return nullptr;
}

void test_keys() {
    const auto keys = avb_test_keys();
    EXPECT(keys.size() == sizeof(kKnown) / sizeof(kKnown[0]));
    std::set<std::string> names;
    std::set<std::string> blobs;
    for (const Known& want : kKnown) {
        const AvbTestKey* k = key_named(want.name);
        EXPECT(k != nullptr);
        if (!k) continue;
        names.insert(k->name);
        EXPECT(k->bits == want.bits);
        const RsaPrivateKey key = parse_key(*k);
        EXPECT(key.n.bit_length() == want.bits);
        EXPECT(key.has_crt());
        const Bytes blob = avb_encode_public_key(key.public_key());
        EXPECT(blob.size() == 8 + 2 * (want.bits / 8));
        EXPECT(hex(hash::sha1(blob)) == want.sha1);
        blobs.insert(hex(blob));
        // describe says what avbtool would call the key
        const std::string said = describe_avb_public_key(blob);
        EXPECT(said.find(std::to_string(want.bits) + "-bit RSA") == 0);
        EXPECT(said.find(std::string("sha1 ") + want.sha1) != std::string::npos);
        EXPECT(said.find(std::string("the public AVB test key ") + want.name) != std::string::npos);
        // it signs, and the signature is the one its public key checks (and no other message's)
        const Bytes message = bytes_of("what the signature covers");
        const Bytes digest = hash::sha256(message);
        const Bytes sig = rsa_pkcs1_sign(key, HashAlg::SHA256, digest);
        EXPECT(sig.size() == want.bits / 8);
        EXPECT(rsa_pkcs1_verify(key.public_key(), HashAlg::SHA256, digest, sig));
        EXPECT(!rsa_pkcs1_verify(key.public_key(), HashAlg::SHA256, hash::sha256(bytes_of("another message")), sig));
    }
    EXPECT(names.size() == keys.size());   // (no name twice)
    EXPECT(blobs.size() == keys.size());   // (no key twice)
    // the first of a size is the one abr signs with: the plain testkey_rsa2048 before its second one
    EXPECT(std::strcmp(keys[0].name, "testkey_rsa2048") == 0);
}

// A key as PKCS#1 DER, from its numbers.
Bytes encode_key(const RsaPrivateKey& k) {
    return der::encode_sequence({der::encode_integer(uint64_t(0)), der::encode_integer(k.n), der::encode_integer(k.e), der::encode_integer(k.d),
                                 der::encode_integer(k.p), der::encode_integer(k.q), der::encode_integer(k.dp), der::encode_integer(k.dq),
                                 der::encode_integer(k.qinv)});
}

// A key whose numbers do not agree is refused when it is read, whichever of them is wrong; the key written back from its own numbers is
// taken, and so is one that has no CRT numbers (it is used through d, and checked through d).
void test_key_consistency() {
    const RsaPrivateKey& good = parse_key(*key_named("testkey_rsa2048"));
    EXPECT(rsa_parse_private_key(encode_key(good)).n == good.n);
    const BigInt two(2);
    const BigInt one(1);
    struct Field {
        const char* name;
        BigInt RsaPrivateKey::*member;
        const BigInt* by;
    };
    for (const Field& f : {Field{"n", &RsaPrivateKey::n, &two}, Field{"e", &RsaPrivateKey::e, &two}, Field{"d", &RsaPrivateKey::d, &two},
                           Field{"p", &RsaPrivateKey::p, &two}, Field{"q", &RsaPrivateKey::q, &two}, Field{"dp", &RsaPrivateKey::dp, &one},
                           Field{"dq", &RsaPrivateKey::dq, &one}, Field{"qinv", &RsaPrivateKey::qinv, &one}}) {
        RsaPrivateKey bad = good;
        bad.*(f.member) = BigInt::add(bad.*(f.member), *f.by);
        const Bytes der = encode_key(bad);
        const bool refused = refuses([&] { rsa_parse_private_key(der); }, "inconsistent");
        EXPECT(refused);
        if (!refused) std::printf("    (a key with a wrong %s was taken)\n", f.name);
    }
    // a prime of 1 or a missing one is no division by zero
    {
        RsaPrivateKey bad = good;
        bad.p = one;
        EXPECT(refuses([&] { rsa_parse_private_key(encode_key(bad)); }, "inconsistent"));
        bad = good;
        bad.q = one;
        EXPECT(refuses([&] { rsa_parse_private_key(encode_key(bad)); }, "inconsistent"));
    }
    // no CRT numbers: checked and used through d
    RsaPrivateKey plain = good;
    plain.p = plain.q = plain.dp = plain.dq = plain.qinv = BigInt(0);
    const RsaPrivateKey taken = rsa_parse_private_key(encode_key(plain));
    EXPECT(!taken.has_crt());
    const Bytes digest = hash::sha256(bytes_of("without the CRT numbers"));
    const Bytes sig = rsa_pkcs1_sign(taken, HashAlg::SHA256, digest);
    EXPECT(sig == rsa_pkcs1_sign(good, HashAlg::SHA256, digest));  // (the same signature, with or without them)
    EXPECT(rsa_pkcs1_verify(good.public_key(), HashAlg::SHA256, digest, sig));
    plain.d = BigInt::add(plain.d, two);
    EXPECT(refuses([&] { rsa_parse_private_key(encode_key(plain)); }, "inconsistent"));
}

void test_find() {
    for (const AvbTestKey& k : avb_test_keys()) {
        Bytes blob = avb_encode_public_key(parse_key(k).public_key());
        const AvbTestKey* found = find_avb_test_key(blob);
        EXPECT(found == &k);
        // a byte of the modulus changed, of the R^2 changed, of the n0inv changed
        for (const size_t at : {size_t(5), size_t(8), size_t(8) + k.bits / 8 - 1, size_t(8) + k.bits / 8, blob.size() - 1}) {
            Bytes damaged = blob;
            damaged[at] ^= 0x10;
            EXPECT(find_avb_test_key(damaged) == nullptr);
        }
        // a blob that is too short, too long, or says another size
        Bytes shorter(blob.begin(), blob.end() - 1);
        Bytes longer = blob;
        longer.push_back(0);
        EXPECT(find_avb_test_key(shorter) == nullptr);
        EXPECT(find_avb_test_key(longer) == nullptr);
        Bytes other_size = blob;
        other_size[2] ^= 0x01;
        EXPECT(find_avb_test_key(other_size) == nullptr);
    }
    EXPECT(find_avb_test_key(Bytes()) == nullptr);
    EXPECT(find_avb_test_key(Bytes(7, 0)) == nullptr);
    EXPECT(find_avb_test_key(Bytes(8, 0)) == nullptr);
    EXPECT(find_avb_test_key(Bytes(520, 0xff)) == nullptr);
    // describe_avb_public_key of what is no key of abr's
    EXPECT(describe_avb_public_key(Bytes()) == "none");
    EXPECT(describe_avb_public_key(Bytes(7, 1)).find("7 bytes, sha1 ") == 0);
    EXPECT(describe_avb_public_key(Bytes(7, 1)).find("test key") == std::string::npos);
    {
        // an RSA-shaped blob that is nobody's: the size is said, the name is not
        Bytes shaped = avb_encode_public_key(parse_key(*key_named("testkey_rsa2048")).public_key());
        shaped[100] ^= 1;
        const std::string said = describe_avb_public_key(shaped);
        EXPECT(said.find("2048-bit RSA, sha1 ") == 0);
        EXPECT(said.find("test key") == std::string::npos);
    }
}

void test_choose() {
    struct Row {
        uint32_t algorithm;
        unsigned bits;
    };
    const Row rows[] = {{1, 2048}, {2, 4096}, {3, 8192}, {4, 2048}, {5, 4096}, {6, 8192}};
    for (const Row& row : rows) {
        EXPECT(avb_algorithm_key_bits(row.algorithm) == row.bits);
        // an image that has no key of its own to show: the first key of the size, and it is nobody's but abr's choice
        const AvbKeyChoice none = choose_avb_test_key(row.algorithm, Bytes());
        EXPECT(none.key != nullptr && none.key->bits == row.bits && !none.the_images_key);
        // a blob that is none of the keys: the same
        Bytes stranger(8 + 2 * (row.bits / 8), 0x5a);
        stranger[0] = static_cast<uint8_t>(row.bits >> 24);
        stranger[1] = static_cast<uint8_t>(row.bits >> 16);
        stranger[2] = static_cast<uint8_t>(row.bits >> 8);
        stranger[3] = static_cast<uint8_t>(row.bits);
        const AvbKeyChoice other = choose_avb_test_key(row.algorithm, stranger);
        EXPECT(other.key == none.key && !other.the_images_key);
        // an image signed with one of them: that one (so the new signature is as valid as the old one was)
        for (const AvbTestKey& k : avb_test_keys()) {
            const Bytes blob = avb_encode_public_key(parse_key(k).public_key());
            const AvbKeyChoice mine = choose_avb_test_key(row.algorithm, blob);
            if (k.bits == row.bits) {
                EXPECT(mine.key == &k && mine.the_images_key);
            } else {
                // (a key of another size cannot be what this algorithm signs with)
                EXPECT(mine.key == none.key && !mine.the_images_key);
            }
        }
    }
    // the plain 2048 first, and the second one when the image says it
    EXPECT(std::strcmp(choose_avb_test_key(1, Bytes()).key->name, "testkey_rsa2048") == 0);
    EXPECT(std::strcmp(choose_avb_test_key(4, Bytes()).key->name, "testkey_rsa2048") == 0);
    {
        const Bytes second = avb_encode_public_key(parse_key(*key_named("testkey_rsa2048_2")).public_key());
        const AvbKeyChoice c = choose_avb_test_key(1, second);
        EXPECT(c.key != nullptr && std::strcmp(c.key->name, "testkey_rsa2048_2") == 0 && c.the_images_key);
    }
    // NONE, ML-DSA, and numbers that are no algorithm: no RSA key signs for them
    for (const uint32_t algorithm : {0u, 7u, 8u, 9u, 100u, 0xffffffffu}) {
        EXPECT(avb_algorithm_key_bits(algorithm) == 0);
        const AvbKeyChoice c = choose_avb_test_key(algorithm, Bytes());
        EXPECT(c.key == nullptr && !c.the_images_key);
    }
    EXPECT(avb_algorithm_name(7) == "MLDSA65");
    EXPECT(avb_algorithm_name(8) == "MLDSA87");
    EXPECT(avb_algorithm_name(9) == "UNKNOWN(9)");
}

// A vbmeta that says `algorithm`, a property descriptor, and (for the RSA algorithms) the public key of `key`.
VbmetaImage make_vbmeta(uint32_t algorithm, const AvbTestKey* key) {
    VbmetaImage v;
    v.algorithm_type = algorithm;
    v.rollback_index = 7;
    v.flags = 2;
    v.release_string = "abr test";
    AvbDescriptor d;
    d.tag = static_cast<uint64_t>(AvbDescriptorTag::PROPERTY);
    BinaryWriter w;
    w.be64(3);  // key length
    w.be64(5);  // value length
    w.bytes(bytes_of("key"));
    w.u8(0);
    w.bytes(bytes_of("value"));
    w.u8(0);
    d.content = w.take();
    v.descriptors.push_back(d);
    if (key) v.public_key = avb_encode_public_key(parse_key(*key).public_key());
    return v;
}

// Checks the signature of a built vbmeta the way libavb would: over the digest of the header and the auxiliary block, with the public key
// the image itself holds.
bool signature_verifies(const Bytes& blob, uint32_t algorithm) {
    if (blob.size() < 256) return false;
    const uint64_t auth_size = be64_at(blob, 12);
    const uint64_t aux_size = be64_at(blob, 20);
    if (256 + auth_size + aux_size > blob.size()) return false;
    const bool sha512 = algorithm >= 4 && algorithm <= 6;
    const size_t hash_size = sha512 ? 64 : 32;
    const unsigned bits = avb_algorithm_key_bits(algorithm);
    Bytes signed_bytes(blob.begin(), blob.begin() + 256);
    signed_bytes.insert(signed_bytes.end(), blob.begin() + 256 + static_cast<long>(auth_size),
                        blob.begin() + 256 + static_cast<long>(auth_size + aux_size));
    const HashAlg alg = sha512 ? HashAlg::SHA512 : HashAlg::SHA256;
    const Bytes digest = hash_bytes(alg, signed_bytes);
    const Bytes stored_hash(blob.begin() + 256, blob.begin() + 256 + static_cast<long>(hash_size));
    const Bytes sig(blob.begin() + 256 + static_cast<long>(hash_size), blob.begin() + 256 + static_cast<long>(hash_size + bits / 8));
    const VbmetaImage parsed = VbmetaImage::parse(blob);
    // the key the image holds: modulus and exponent 65537 (what AVB keys have); the blob has the modulus after the 8 bytes of header
    RsaPublicKey pub;
    pub.n = BigInt::from_bytes_be(Bytes(parsed.public_key.begin() + 8, parsed.public_key.begin() + 8 + bits / 8));
    pub.e = BigInt::from_bytes_be(Bytes{0x01, 0x00, 0x01});
    return stored_hash == digest && rsa_pkcs1_verify(pub, alg, digest, sig);
}

void test_vbmeta_with_chosen_keys() {
    // every RSA algorithm; the 8192-bit ones sign slowly, so one of the two is enough there
    for (const uint32_t algorithm : {1u, 2u, 3u, 4u, 5u}) {
        VbmetaImage v = make_vbmeta(algorithm, nullptr);
        const AvbKeyChoice c = choose_avb_test_key(algorithm, v.public_key);
        EXPECT(c.key != nullptr);
        if (!c.key) continue;
        const std::string pem = c.key->pem;
        std::vector<std::string> notes;
        const Bytes blob = v.build(pem, &notes);
        EXPECT(notes.empty());  // (no public key was there to be replaced)
        EXPECT(signature_verifies(blob, algorithm));
        const VbmetaImage back = VbmetaImage::parse(blob);
        EXPECT(back.algorithm_type == algorithm);
        EXPECT(back.public_key == avb_encode_public_key(parse_key(*c.key).public_key()));
        EXPECT(find_avb_test_key(back.public_key) == c.key);
        EXPECT(back.can_keep_signature());
        EXPECT(back.build("") == blob);  // no key: the signature it has comes back, byte for byte

        // something the signature covers changes: it cannot be kept, and a build without a key says so
        VbmetaImage changed = back;
        changed.flags ^= 1;
        EXPECT(!changed.can_keep_signature());
        EXPECT(refuses([&] { changed.build(""); }, "no private key"));
        // ... and each of the other fields it covers
        {
            VbmetaImage c2 = back;
            c2.rollback_index += 1;
            EXPECT(!c2.can_keep_signature());
            VbmetaImage c3 = back;
            c3.descriptors[0].content.back() ^= 1;
            EXPECT(!c3.can_keep_signature());
            VbmetaImage c4 = back;
            c4.release_string = "another";
            EXPECT(!c4.can_keep_signature());
            VbmetaImage c5 = back;
            c5.public_key_metadata = bytes_of("metadata");
            EXPECT(!c5.can_keep_signature());
        }
        // with the key it signs again, with the same public key, and the result stands
        const Bytes again = changed.build(pem, &notes);
        EXPECT(notes.empty());
        EXPECT(signature_verifies(again, algorithm));
        const VbmetaImage again_parsed = VbmetaImage::parse(again);
        EXPECT(again_parsed.can_keep_signature());
        EXPECT(again_parsed.flags == changed.flags);
        EXPECT(again != blob);
        // what the signature does not cover can be touched and the signature stays: the signature and the hash it keeps are the same
        // bytes, since nothing in the header or the auxiliary block moved
        EXPECT(again_parsed.hash.size() == (algorithm >= 4 ? 64u : 32u));
    }
    // an image of a key that is not one of ours: its public key is kept while the signature is, and the key to sign with is the first of the size
    {
        const AvbTestKey* second = key_named("testkey_rsa2048_2");
        VbmetaImage v = make_vbmeta(1, second);
        const Bytes blob = v.build(second->pem);
        EXPECT(signature_verifies(blob, 1));
        VbmetaImage back = VbmetaImage::parse(blob);
        const AvbKeyChoice c = choose_avb_test_key(1, back.public_key);
        EXPECT(c.key == second && c.the_images_key);  // (the image's own, even though it is not the first of its size)
        // signed again with the other key of the size: the public key in the image becomes that key's, and the build says it did
        std::vector<std::string> notes;
        back.flags ^= 1;
        const Bytes swapped = back.build(key_named("testkey_rsa2048")->pem, &notes);
        EXPECT(notes.size() == 1 && notes[0].find("replaced") != std::string::npos);
        EXPECT(signature_verifies(swapped, 1));
        EXPECT(VbmetaImage::parse(swapped).public_key == avb_encode_public_key(parse_key(*key_named("testkey_rsa2048")).public_key()));
        // a key of the wrong size for the algorithm is refused
        EXPECT(refuses([&] { back.build(key_named("testkey_rsa4096")->pem); }, "does not match"));
    }
    // NONE: nothing to sign, nothing to keep
    {
        VbmetaImage v = make_vbmeta(0, nullptr);
        EXPECT(v.can_keep_signature());
        const Bytes blob = v.build("");
        EXPECT(VbmetaImage::parse(blob).algorithm_type == 0);
        EXPECT(VbmetaImage::parse(blob).can_keep_signature());
    }
    // a number that is no algorithm is an error, as ever
    {
        VbmetaImage v = make_vbmeta(1, nullptr);
        v.algorithm_type = 99;
        EXPECT(refuses([&] { v.can_keep_signature(); }, "unknown AVB algorithm_type"));
    }
}

// An ML-DSA vbmeta after libavb 1.4's layout: no digest in the authentication block, the signature right at its start, the public key
// a be32 length and the key; signature and key are patterns here (abr does not check an ML-DSA signature, and a pattern is enough to
// tell a byte that moved).
Bytes make_mldsa_vbmeta(uint32_t algorithm, size_t signature_size, size_t key_size, uint32_t flags) {
    BinaryWriter key_blob;
    key_blob.be32(static_cast<uint32_t>(key_size));
    for (size_t i = 0; i < key_size; ++i) key_blob.u8(static_cast<uint8_t>(i * 13 + 1));
    BinaryWriter aux;
    aux.bytes(key_blob.take());
    const uint64_t pubkey_size = aux.size();
    aux.align(8);
    const uint64_t meta_offset = aux.size();
    aux.align(64);
    const Bytes aux_bytes = aux.take();
    const uint64_t auth_size = (signature_size + 63) / 64 * 64;
    BinaryWriter h;
    h.bytes(bytes_of("AVB0"));
    h.be32(1);
    h.be32(4);
    h.be64(auth_size);
    h.be64(aux_bytes.size());
    h.be32(algorithm);
    h.be64(0);  // hash offset
    h.be64(0);  // hash size: none
    h.be64(0);  // signature offset
    h.be64(signature_size);
    h.be64(0);  // public key offset
    h.be64(pubkey_size);
    h.be64(meta_offset);
    h.be64(0);  // metadata size
    h.be64(0);  // descriptors offset
    h.be64(0);  // descriptors size
    h.be64(3);  // rollback index
    h.be32(flags);
    h.be32(0);  // rollback index location
    h.asciiz("avbtool test", 48);
    h.zeros(80);
    BinaryWriter out;
    out.bytes(h.take());
    for (size_t i = 0; i < auth_size; ++i) out.u8(i < signature_size ? static_cast<uint8_t>(i * 7 + 3) : 0);
    out.bytes(aux_bytes);
    return out.take();
}

void test_mldsa() {
    struct Row {
        uint32_t algorithm;
        const char* name;
        size_t signature_size;
        size_t key_size;
    };
    for (const Row& row : {Row{7, "MLDSA65", 3309, 1952}, Row{8, "MLDSA87", 4627, 2592}}) {
        const Bytes image = make_mldsa_vbmeta(row.algorithm, row.signature_size, row.key_size, 0);
        VbmetaImage v = VbmetaImage::parse(image);
        EXPECT(v.algorithm_type == row.algorithm);
        EXPECT(avb_algorithm_name(v.algorithm_type) == row.name);
        EXPECT(v.signature.size() == row.signature_size);
        EXPECT(v.public_key.size() == 4 + row.key_size);
        EXPECT(v.rollback_index == 3);
        EXPECT(v.release_string == "avbtool test");
        EXPECT(v.hash.size() == 32);  // (abr's record of what the signature covers: the image has no digest)
        // unchanged: rebuilt byte for byte, without a key
        EXPECT(v.can_keep_signature());
        EXPECT(v.build("") == image);
        // something it covers changed: it cannot be signed, whatever key is at hand
        VbmetaImage changed = v;
        changed.flags = 1;
        EXPECT(!changed.can_keep_signature());
        EXPECT(refuses([&] { changed.build(""); }, "ML-DSA"));
        EXPECT(refuses([&] { changed.build(key_named("testkey_rsa4096")->pem); }, "ML-DSA"));
        // the flags that were in the image are in what the record covers: an image that differs in them is another record
        const Bytes other = make_mldsa_vbmeta(row.algorithm, row.signature_size, row.key_size, 1);
        EXPECT(VbmetaImage::parse(other).hash != v.hash);
        // the signature is not what the record covers: one that differs there leaves the record alone
        Bytes resigned = image;
        resigned[256] ^= 0xff;
        const VbmetaImage rs = VbmetaImage::parse(resigned);
        EXPECT(rs.hash == v.hash);
        EXPECT(rs.signature != v.signature && rs.build("") == resigned);
        // nothing for an RSA key to do, and no test key signs for it
        EXPECT(choose_avb_test_key(row.algorithm, v.public_key).key == nullptr);
        EXPECT(describe_avb_public_key(v.public_key).find(std::to_string(4 + row.key_size) + " bytes, sha1 ") == 0);
    }
}

void test_chain_descriptor() {
    const AvbTestKey* k4096 = key_named("testkey_rsa4096");
    const Bytes blob = avb_encode_public_key(parse_key(*k4096).public_key());
    auto chain = [&](uint32_t location, const std::string& name, const Bytes& key, uint32_t declared_key_size) {
        BinaryWriter w;
        w.be32(location);
        w.be32(static_cast<uint32_t>(name.size()));
        w.be32(declared_key_size);
        w.be32(0);
        w.zeros(60);
        w.bytes(bytes_of(name.c_str()));
        w.bytes(key);
        AvbDescriptor d;
        d.tag = static_cast<uint64_t>(AvbDescriptorTag::CHAIN_PARTITION);
        d.content = w.take();
        return d;
    };
    {
        const std::string said = chain(2, "boot", blob, static_cast<uint32_t>(blob.size())).describe();
        EXPECT(said.find("chain_partition: boot") == 0);
        EXPECT(said.find("rollback index location 2") != std::string::npos);
        EXPECT(said.find("pubkey 1032B") != std::string::npos);
        EXPECT(said.find("the AVB test key testkey_rsa4096") != std::string::npos);
    }
    {
        // a key that is nobody's: described, not named
        Bytes stranger = blob;
        stranger[40] ^= 1;
        const std::string said = chain(1, "vbmeta_system", stranger, static_cast<uint32_t>(stranger.size())).describe();
        EXPECT(said.find("pubkey 1032B") != std::string::npos);
        EXPECT(said.find("test key") == std::string::npos);
    }
    // a descriptor that says its key is longer than what it holds, or lies about the name: no crash, no name
    EXPECT(chain(1, "boot", blob, 100000).describe().find("test key") == std::string::npos);
    EXPECT(chain(1, "boot", Bytes(), 1032).describe().find("test key") == std::string::npos);
    EXPECT(chain(1, "boot", blob, 0xffffffffu).describe().find("test key") == std::string::npos);
    {
        AvbDescriptor d = chain(1, "boot", blob, static_cast<uint32_t>(blob.size()));
        d.content.resize(100);  // cut in the middle of the name and the key
        EXPECT(!d.describe().empty());
        d.content.resize(10);
        EXPECT(!d.describe().empty());
    }
}

}  // namespace

int run_avb_keys_tests() {
    test_keys();
    test_key_consistency();
    test_find();
    test_choose();
    test_vbmeta_with_chosen_keys();
    test_mldsa();
    test_chain_descriptor();
    if (g_failures == 0) std::printf("avbkeys: ok (%d checks)\n", g_checks);
    else std::printf("avbkeys: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
