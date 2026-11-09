// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/mbn.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "abr/asn1.hpp"
#include "abr/sha.hpp"

namespace abr::mbn {

namespace {

uint16_t le16(const Bytes& d, size_t at) { return static_cast<uint16_t>(d[at] | (d[at + 1] << 8)); }
uint32_t le32(const Bytes& d, size_t at) {
    return uint32_t{d[at]} | (uint32_t{d[at + 1]} << 8) | (uint32_t{d[at + 2]} << 16) | (uint32_t{d[at + 3]} << 24);
}
uint64_t le64(const Bytes& d, size_t at) { return uint64_t{le32(d, at)} | (uint64_t{le32(d, at + 4)} << 32); }

void put(Bytes& out, uint64_t v, int width) {
    for (int i = 0; i < width; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

using U = Field::Use;

// The words of the headers. The names are those of Qualcomm's tools as coreboot's mbn_tools.py and qtestsign write them, made a little shorter.
const std::vector<Field> kBoot3 = {
    {"image_id", 0, U::Keep},   {"version", 1, U::Fixed},     {"image_src", 2, U::Keep}, {"image_dest", 3, U::Keep}, {"image_size", 4, U::Derived},
    {"code_size", 5, U::Derived}, {"sig_ptr", 6, U::Pointer}, {"sig_size", 7, U::Derived}, {"cert_ptr", 8, U::Pointer}, {"cert_size", 9, U::Derived},
};
// Version 5: words 2 and 3 are the sizes of Qualcomm's signature and chain, not an image_src and a load address.
const std::vector<Field> kBoot5 = {
    {"image_id", 0, U::Keep},   {"version", 1, U::Fixed},        {"sig_size_qti", 2, U::Derived}, {"cert_size_qti", 3, U::Derived}, {"image_size", 4, U::Derived},
    {"code_size", 5, U::Derived}, {"sig_ptr", 6, U::Pointer},    {"sig_size", 7, U::Derived},     {"cert_ptr", 8, U::Pointer},      {"cert_size", 9, U::Derived},
};
const std::vector<Field> kBoot6 = {
    {"image_id", 0, U::Keep},   {"version", 1, U::Fixed},        {"sig_size_qti", 2, U::Derived}, {"cert_size_qti", 3, U::Derived}, {"image_size", 4, U::Derived},
    {"code_size", 5, U::Derived}, {"sig_ptr", 6, U::Pointer},    {"sig_size", 7, U::Derived},     {"cert_ptr", 8, U::Pointer},      {"cert_size", 9, U::Derived},
    {"metadata_size_qti", 10, U::Derived}, {"metadata_size", 11, U::Derived},
};
// Version 7: the first word is reserved; there is no image_size and no address; 24 bytes of "common metadata" end the header.
const std::vector<Field> kBoot7 = {
    {"reserved", 0, U::Keep},
    {"version", 1, U::Fixed},
    {"common_metadata_size", 2, U::Keep},
    {"metadata_size_qti", 3, U::Derived},
    {"metadata_size", 4, U::Derived},
    {"code_size", 5, U::Derived},
    {"sig_size_qti", 6, U::Derived},
    {"cert_size_qti", 7, U::Derived},
    {"sig_size", 8, U::Derived},
    {"cert_size", 9, U::Derived},
    {"common_major", 10, U::Keep},
    {"common_minor", 11, U::Keep},
    {"software_id", 12, U::Keep},
    {"secondary_software_id", 13, U::Keep},
    {"hash_table_algorithm", 14, U::Keep},
    {"measurement_register_target", 15, U::Keep},
};
const std::vector<Field> kSbl = {
    {"codeword", 0, U::Fixed},           {"magic", 1, U::Fixed},     {"image_id", 2, U::Keep},       {"reserved_1", 3, U::Keep},
    {"reserved_2", 4, U::Keep},          {"image_src", 5, U::Keep},  {"image_dest", 6, U::Keep},     {"image_size", 7, U::Derived},
    {"code_size", 8, U::Derived},        {"sig_ptr", 9, U::Pointer}, {"sig_size", 10, U::Derived},   {"cert_ptr", 11, U::Pointer},
    {"cert_size", 12, U::Derived},       {"oem_root_cert_sel", 13, U::Keep}, {"oem_num_root_certs", 14, U::Keep},
    {"booting_image_config", 15, U::Keep}, {"reserved_6", 16, U::Keep}, {"reserved_7", 17, U::Keep}, {"reserved_8", 18, U::Keep}, {"reserved_9", 19, U::Keep},
};
const std::vector<Field> kNone;

// The index of the word with that name, or -1.
int index_of(Kind kind, uint32_t version, std::string_view name) {
    for (const Field& f : fields(kind, version))
        if (name == f.name) return static_cast<int>(f.index);
    return -1;
}

uint32_t word_at(const std::vector<uint32_t>& w, int index) { return index >= 0 && static_cast<size_t>(index) < w.size() ? w[static_cast<size_t>(index)] : 0; }

// The sizes of the parts as a header says them.
struct Sizes {
    uint64_t meta_qti = 0, meta = 0, code = 0, sig_qti = 0, cert_qti = 0, sig = 0, cert = 0;
    uint64_t sum() const { return meta_qti + meta + code + sig_qti + cert_qti + sig + cert; }
};

Sizes sizes_of(Kind kind, uint32_t version, const std::vector<uint32_t>& w) {
    Sizes s;
    s.meta_qti = word_at(w, index_of(kind, version, "metadata_size_qti"));
    s.meta = word_at(w, index_of(kind, version, "metadata_size"));
    s.code = word_at(w, index_of(kind, version, "code_size"));
    s.sig_qti = word_at(w, index_of(kind, version, "sig_size_qti"));
    s.cert_qti = word_at(w, index_of(kind, version, "cert_size_qti"));
    s.sig = word_at(w, index_of(kind, version, "sig_size"));
    s.cert = word_at(w, index_of(kind, version, "cert_size"));
    return s;
}

}  // namespace

// ----------------------------------------------------------------------------------------------------------------------------------- hashes --

const char* algo_name(Algo a) {
    switch (a) {
        case Algo::Sha1: return "SHA-1";
        case Algo::Sha256: return "SHA-256";
        case Algo::Sha384: return "SHA-384";
        default: return "none";
    }
}

const char* algo_key(Algo a) {
    switch (a) {
        case Algo::Sha1: return "sha1";
        case Algo::Sha256: return "sha256";
        case Algo::Sha384: return "sha384";
        default: return "none";
    }
}

std::optional<Algo> algo_from_key(std::string_view key) {
    if (key == "sha1") return Algo::Sha1;
    if (key == "sha256") return Algo::Sha256;
    if (key == "sha384") return Algo::Sha384;
    if (key == "none") return Algo::None;
    return std::nullopt;
}

size_t digest_size(Algo a) {
    switch (a) {
        case Algo::Sha1: return 20;
        case Algo::Sha256: return 32;
        case Algo::Sha384: return 48;
        default: return 0;
    }
}

Bytes digest(Algo a, const uint8_t* data, size_t size) {
    switch (a) {
        case Algo::Sha1: return hash::sha1(data, size);
        case Algo::Sha256: return hash::sha256(data, size);
        case Algo::Sha384: return hash::sha384(data, size);
        default: return {};
    }
}

// ------------------------------------------------------------------------------------------------------------------------------ the structure --

const std::vector<Field>& fields(Kind kind, uint32_t version) {
    if (kind == Kind::Sbl) return kSbl;
    switch (version) {
        case 3: return kBoot3;
        case 5: return kBoot5;
        case 6: return kBoot6;
        case 7: return kBoot7;
        default: return kNone;
    }
}

size_t header_size(Kind kind, uint32_t version) {
    if (kind == Kind::Sbl) return kSblHeaderSize;
    switch (version) {
        case 3: case 5: return 40;
        case 6: return 48;
        case 7: return 64;
        default: return 0;
    }
}

uint64_t Block::parts_size() const {
    return uint64_t{metadata_qti.size()} + metadata.size() + code.size() + sig_qti.size() + cert_qti.size() + sig.size() + cert.size();
}

bool Block::has_word(std::string_view name) const { return index_of(kind, version, name) >= 0; }

uint32_t Block::word(std::string_view name) const { return word_at(w, index_of(kind, version, name)); }

std::string image_id_name(uint32_t id) {
    // The ids of the image types in the header (ImageType in coreboot's mbn_tools.py, which is Qualcomm's).
    static const char* const kNames[] = {"NONE",    "OEM_SBL", "AMSS",     "QCSBL",   "HASH",   "APPSBL",  "APPS",        "HOSTDL",       "DSP1",
                                         "FSBL",    "DBL",     "OSBL",     "DSP2",    "EHOSTDL", "NANDPRG", "NORPRG",    "RAMFS1",       "RAMFS2",
                                         "ADSP_Q5", "APPS_KERNEL", "BACKUP_RAMFS", "SBL1", "SBL2", "RPM",    "SBL3",        "TZ"};
    if (id < sizeof kNames / sizeof kNames[0]) return kNames[id];
    if (id == 32) return "PSI";
    return {};
}

bool Block::set_word(std::string_view name, uint32_t value) {
    const int i = index_of(kind, version, name);
    if (i < 0 || static_cast<size_t>(i) >= w.size()) return false;
    w[static_cast<size_t>(i)] = value;
    return true;
}

Block make_block(Kind kind, uint32_t version) {
    Block b;
    b.kind = kind;
    b.version = kind == Kind::Sbl ? 0 : version;
    b.w.assign(header_size(kind, b.version) / 4, 0);
    if (kind == Kind::Sbl) {
        b.w[0] = kSblCodeword;
        b.w[1] = kSblMagic;
        b.w[5] = static_cast<uint32_t>(kSblHeaderSize);
    } else if (b.w.size() > 1) {
        b.w[1] = version;
        if (version == 7) b.w[2] = 24;
    }
    return b;
}

std::string block_problem(const Bytes& d, size_t at, size_t limit) {
    if (limit > d.size()) limit = d.size();
    if (at > limit || limit - at < 8) return "there are fewer than 8 bytes for a header";
    const size_t room = limit - at;
    Kind kind = Kind::Boot;
    uint32_t version = 0;
    if (le32(d, at) == kSblCodeword && le32(d, at + 4) == kSblMagic) {
        kind = Kind::Sbl;
    } else {
        version = le32(d, at + 4);
    }
    const size_t hs = header_size(kind, version);
    if (hs == 0) return "the header version " + std::to_string(version) + " is none of 3, 5, 6, 7 (and the codeword and the magic of an SBL header are not there)";
    if (room < hs) return "the header (" + std::to_string(hs) + " bytes) is cut short: " + std::to_string(room) + " are there";
    std::vector<uint32_t> w(hs / 4);
    for (size_t i = 0; i < w.size(); ++i) w[i] = le32(d, at + 4 * i);
    if (kind == Kind::Boot && version == 7 && w[2] != 24)
        return "common_metadata_size is " + std::to_string(w[2]) + " (abr knows the 24 bytes that the version 7 header has)";
    if (kind == Kind::Sbl && w[5] != kSblHeaderSize)
        return "image_src of the SBL header is " + std::to_string(w[5]) + ": the code is expected right behind the header, at " + std::to_string(kSblHeaderSize);
    const Sizes s = sizes_of(kind, version, w);
    const uint64_t sum = s.sum();
    const int image_size_at = index_of(kind, version, "image_size");
    uint64_t total = sum;
    if (image_size_at >= 0) {
        const uint64_t image_size = w[static_cast<size_t>(image_size_at)];
        if (image_size < sum || image_size - sum > 3)
            return "image_size (" + std::to_string(image_size) + ") is not the size of the parts (" + std::to_string(sum) + ", and up to three bytes of rounding)";
        total = image_size;
    }
    if (total > room - hs) return "the parts (" + std::to_string(total) + " bytes) do not fit in the " + std::to_string(room - hs) + " bytes behind the header";
    return {};
}

Block parse_block(const Bytes& d, size_t at, size_t limit) {
    if (const std::string why = block_problem(d, at, limit); !why.empty()) throw FormatError("MBN header: " + why);
    Block b;
    b.kind = le32(d, at) == kSblCodeword && le32(d, at + 4) == kSblMagic ? Kind::Sbl : Kind::Boot;
    b.version = b.kind == Kind::Sbl ? 0 : le32(d, at + 4);
    const size_t hs = b.header_bytes();
    b.w.resize(hs / 4);
    for (size_t i = 0; i < b.w.size(); ++i) b.w[i] = le32(d, at + 4 * i);
    const Sizes s = sizes_of(b.kind, b.version, b.w);
    size_t pos = at + hs;
    const auto take = [&](uint64_t n) {
        Bytes out(d.begin() + static_cast<std::ptrdiff_t>(pos), d.begin() + static_cast<std::ptrdiff_t>(pos + n));
        pos += static_cast<size_t>(n);
        return out;
    };
    b.metadata_qti = take(s.meta_qti);
    b.metadata = take(s.meta);
    b.code = take(s.code);
    b.sig_qti = take(s.sig_qti);
    b.cert_qti = take(s.cert_qti);
    b.sig = take(s.sig);
    b.cert = take(s.cert);
    const int image_size_at = index_of(b.kind, b.version, "image_size");
    if (image_size_at >= 0) {
        b.slack = take(b.w[static_cast<size_t>(image_size_at)] - s.sum());
        b.align4 = !b.slack.empty() && (s.sum() + b.slack.size()) % 4 == 0;
    }
    const int sig_ptr_at = index_of(b.kind, b.version, "sig_ptr"), cert_ptr_at = index_of(b.kind, b.version, "cert_ptr");
    if (sig_ptr_at >= 0 && cert_ptr_at >= 0) {
        const uint32_t sig_ptr = b.w[static_cast<size_t>(sig_ptr_at)], cert_ptr = b.w[static_cast<size_t>(cert_ptr_at)];
        if (sig_ptr != 0 && sig_ptr != 0xFFFFFFFFu && cert_ptr == static_cast<uint32_t>(sig_ptr + s.sig)) {
            b.derived_ptrs = true;
            b.ptr_base = static_cast<uint32_t>(sig_ptr - s.code);
        }
    }
    b.consumed = pos - at;
    return b;
}

Bytes build_block(const Block& b) {
    const size_t hs = b.header_bytes();
    if (hs == 0) throw FormatError("MBN header: version " + std::to_string(b.version) + " is none of 3, 5, 6, 7");
    std::vector<uint32_t> w = b.w;
    w.resize(hs / 4, 0);
    const auto size32 = [](uint64_t n, const char* what) {
        if (n > 0xFFFFFFFFull) throw FormatError(std::string("MBN header: the ") + what + " is " + std::to_string(n) + " bytes, more than a 32-bit field holds");
        return static_cast<uint32_t>(n);
    };
    const auto set = [&](const char* name, uint64_t v, const char* what) {
        if (const int i = index_of(b.kind, b.version, name); i >= 0) w[static_cast<size_t>(i)] = size32(v, what);
    };
    set("metadata_size_qti", b.metadata_qti.size(), "QTI metadata");
    set("metadata_size", b.metadata.size(), "metadata");
    set("code_size", b.code.size(), "code");
    set("sig_size_qti", b.sig_qti.size(), "QTI signature");
    set("cert_size_qti", b.cert_qti.size(), "QTI certificate chain");
    set("sig_size", b.sig.size(), "signature");
    set("cert_size", b.cert.size(), "certificate chain");
    const uint64_t sum = b.parts_size();
    size_t slack_len = 0;
    if (index_of(b.kind, b.version, "image_size") >= 0) {
        slack_len = b.align4 ? static_cast<size_t>(padding_for(sum, 4)) : b.slack.size();
        set("image_size", sum + slack_len, "image");
    }
    if (b.derived_ptrs) {
        const int sp = index_of(b.kind, b.version, "sig_ptr"), cp = index_of(b.kind, b.version, "cert_ptr");
        if (sp >= 0 && cp >= 0) {
            w[static_cast<size_t>(sp)] = static_cast<uint32_t>(b.ptr_base + b.code.size());
            w[static_cast<size_t>(cp)] = static_cast<uint32_t>(w[static_cast<size_t>(sp)] + b.sig.size());
        }
    }
    if (b.kind == Kind::Sbl) {
        w[0] = kSblCodeword;
        w[1] = kSblMagic;
    } else {
        w[1] = b.version;
    }
    Bytes out;
    out.reserve(hs + sum + slack_len);
    for (uint32_t v : w) put(out, v, 4);
    for (const Bytes* part : {&b.metadata_qti, &b.metadata, &b.code, &b.sig_qti, &b.cert_qti, &b.sig, &b.cert}) out.insert(out.end(), part->begin(), part->end());
    for (size_t i = 0; i < slack_len; ++i) out.push_back(i < b.slack.size() ? b.slack[i] : 0);
    return out;
}

bool has_sbl_words(const Bytes& d) { return d.size() >= 8 && le32(d, 0) == kSblCodeword && le32(d, 4) == kSblMagic; }

bool flat_looks_like(const Bytes& d) {
    if (d.size() < 40) return false;
    if (le32(d, 0) == kSblCodeword && le32(d, 4) == kSblMagic) return block_problem(d, 0, d.size()).empty();
    const uint32_t id = le32(d, 0), version = le32(d, 4);
    if (version != 3 && version != 5 && version != 6 && version != 7) return false;
    if (id > 0xFF) return false;
    if (!block_problem(d, 0, d.size()).empty()) return false;
    return !parse_block(d, 0, d.size()).code.empty();  // an image has code; ten words and a version are not enough to take a file for one
}

std::string flat_problem(const Bytes& d) {
    if (d.size() < 12 || le32(d, 0) != kSblCodeword || le32(d, 4) != kSblMagic) return {};
    if (le32(d, 8) == kSblPreambleMagic)
        return "it begins with the codeword and the magic of an SBL header followed by 0x7D0B435A: the page-size preamble that Qualcomm's tools put in front of an SBL on NAND flash. abr "
               "does not open a file with one";
    return block_problem(d, 0, d.size());
}

std::string describe_header(const Block& b) {
    if (b.kind == Kind::Sbl) return "SBL header (80 bytes)";
    return "header version " + std::to_string(b.version) + " (" + std::to_string(b.header_bytes()) + " bytes)";
}

// ---------------------------------------------------------------------------------------------------------------------- the certificate chain --

namespace {

// The text of a string of an X.509 name: printable as it is, else the bytes in hex.
std::string name_text(const Bytes& buf, const der::Tlv& t) {
    const Bytes c = der::content(buf, t);
    bool plain = true;
    for (uint8_t ch : c)
        if (ch < 0x20 || ch > 0x7E) plain = false;
    if (plain) return std::string(c.begin(), c.end());
    std::string out = "#";
    char b[4];
    for (uint8_t ch : c) {
        std::snprintf(b, sizeof b, "%02x", ch);
        out += b;
    }
    return out;
}

std::string attribute_name(const std::string& oid) {
    if (oid == "2.5.4.3") return "CN";
    if (oid == "2.5.4.5") return "serialNumber";
    if (oid == "2.5.4.6") return "C";
    if (oid == "2.5.4.7") return "L";
    if (oid == "2.5.4.8") return "ST";
    if (oid == "2.5.4.10") return "O";
    if (oid == "2.5.4.11") return "OU";
    return oid;
}

// A Name: "C=US, O=QUALCOMM, OU=..., CN=..." in the order the entries stand; the OU texts also go to `ous`.
std::string read_name(const Bytes& buf, const der::Tlv& name, std::vector<std::string>* ous) {
    std::string out;
    for (const der::Tlv& rdn : der::children(buf, name)) {
        if (rdn.tag != der::kSet) continue;
        for (const der::Tlv& atv : der::children(buf, rdn)) {
            if (atv.tag != der::kSequence) continue;
            const std::vector<der::Tlv> kv = der::children(buf, atv);
            if (kv.size() < 2 || kv[0].tag != der::kOid) continue;
            const std::string key = attribute_name(der::oid_to_string(der::content(buf, kv[0])));
            const std::string value = name_text(buf, kv[1]);
            if (!out.empty()) out += ", ";
            out += key + "=" + value;
            if (key == "OU" && ous) ous->push_back(value);
        }
    }
    return out;
}

}  // namespace

std::vector<Cert> read_chain(const Bytes& chain, size_t* rest) {
    std::vector<Cert> out;
    size_t at = 0;
    while (at < chain.size() && chain[at] == der::kSequence) {
        Cert c;
        try {
            const der::Tlv cert = der::read(chain, at, chain.size());
            const std::vector<der::Tlv> top = der::children(chain, cert);
            if (top.empty() || top[0].tag != der::kSequence) break;
            const std::vector<der::Tlv> tbs = der::children(chain, top[0]);
            const size_t v = !tbs.empty() && tbs[0].tag == 0xA0 ? 1 : 0;  // [0] EXPLICIT version
            if (tbs.size() < v + 6 || tbs[v + 2].tag != der::kSequence || tbs[v + 4].tag != der::kSequence) break;
            c.offset = at;
            c.size = cert.total();
            c.issuer = read_name(chain, tbs[v + 2], nullptr);
            c.subject = read_name(chain, tbs[v + 4], &c.attributes);
            at = cert.end();
        } catch (const FormatError&) {
            break;
        }
        out.push_back(std::move(c));
    }
    if (rest) *rest = chain.size() - at;
    return out;
}

std::string attribute_text(const std::string& ou) {
    // "01 0000000000000003 SW_ID": two digits, the value in hex, the name in capitals (Qualcomm's attributes of an image).
    const size_t a = ou.find(' ');
    if (a != 2) return {};
    const size_t b = ou.find(' ', a + 1);
    if (b == std::string::npos || b == a + 1 || ou.find(' ', b + 1) != std::string::npos) return {};
    const std::string index = ou.substr(0, a), value = ou.substr(a + 1, b - a - 1), name = ou.substr(b + 1);
    const auto hexdigits = [](const std::string& s) { return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; }); };
    if (!hexdigits(index) || !hexdigits(value) || name.empty()) return {};
    for (char c : name)
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) return {};
    return name + " 0x" + value;
}

// ---------------------------------------------------------------------------------------------------------------------------------- the ELF --

std::string segment_type_name(unsigned type) {
    switch (type) {
        case 1: return "AMSS";
        case 2: return "HASH";
        case 3: return "BOOT";
        case 4: return "L4BSP";
        case 5: return "SWAPPED";
        case 6: return "SWAP_POOL";
        case 7: return "PHDR";
        default: return {};
    }
}

std::string access_type_name(unsigned type) {
    switch (type) {
        case 1: return "RO";
        case 2: return "ZI";
        case 3: return "NOTUSED";
        case 4: return "SHARED";
        case 7: return "RWE";
        default: return {};
    }
}

std::string describe_flags(uint32_t flags) {
    std::string out;
    out += (flags & 4) ? 'r' : '-';
    out += (flags & 2) ? 'w' : '-';
    out += (flags & 1) ? 'x' : '-';
    const auto add = [&](const std::string& s) {
        if (!s.empty()) out += ", " + s;
    };
    add(segment_type_name(segment_type(flags)));
    add(access_type_name(access_type(flags)));
    if (flags & kFlagPageModeMask) add("paged");
    if (flags & 0x08000000) add("pool 1");
    return out;
}

namespace {

struct Ehdr {
    bool is64 = false;
    uint16_t type = 0, machine = 0, ehsize = 0, phentsize = 0, phnum = 0, shentsize = 0, shnum = 0, shstrndx = 0;
    uint32_t version = 0, flags = 0;
    uint64_t entry = 0, phoff = 0, shoff = 0;
};

bool read_ehdr(const Bytes& d, Ehdr& e) {
    if (d.size() < 52 || std::memcmp(d.data(), "\x7F" "ELF", 4) != 0) return false;
    if (d[5] != 1 || (d[4] != 1 && d[4] != 2)) return false;
    e.is64 = d[4] == 2;
    if (d.size() < (e.is64 ? 64u : 52u)) return false;
    e.type = le16(d, 16);
    e.machine = le16(d, 18);
    e.version = le32(d, 20);
    if (e.is64) {
        e.entry = le64(d, 24), e.phoff = le64(d, 32), e.shoff = le64(d, 40), e.flags = le32(d, 48);
        e.ehsize = le16(d, 52), e.phentsize = le16(d, 54), e.phnum = le16(d, 56), e.shentsize = le16(d, 58), e.shnum = le16(d, 60), e.shstrndx = le16(d, 62);
    } else {
        e.entry = le32(d, 24), e.phoff = le32(d, 28), e.shoff = le32(d, 32), e.flags = le32(d, 36);
        e.ehsize = le16(d, 40), e.phentsize = le16(d, 42), e.phnum = le16(d, 44), e.shentsize = le16(d, 46), e.shnum = le16(d, 48), e.shstrndx = le16(d, 50);
    }
    return true;
}

Phdr read_phdr(const Bytes& d, size_t at, bool is64) {
    Phdr p;
    p.type = le32(d, at);
    if (is64) {
        p.flags = le32(d, at + 4), p.offset = le64(d, at + 8), p.vaddr = le64(d, at + 16), p.paddr = le64(d, at + 24);
        p.filesz = le64(d, at + 32), p.memsz = le64(d, at + 40), p.align = le64(d, at + 48);
    } else {
        p.offset = le32(d, at + 4), p.vaddr = le32(d, at + 8), p.paddr = le32(d, at + 12), p.filesz = le32(d, at + 16), p.memsz = le32(d, at + 20);
        p.flags = le32(d, at + 24), p.align = le32(d, at + 28);
    }
    return p;
}

void write_phdr(Bytes& out, const Phdr& p, bool is64) {
    put(out, p.type, 4);
    if (is64) {
        put(out, p.flags, 4), put(out, p.offset, 8), put(out, p.vaddr, 8), put(out, p.paddr, 8);
        put(out, p.filesz, 8), put(out, p.memsz, 8), put(out, p.align, 8);
    } else {
        put(out, p.offset, 4), put(out, p.vaddr, 4), put(out, p.paddr, 4), put(out, p.filesz, 4), put(out, p.memsz, 4);
        put(out, p.flags, 4), put(out, p.align, 4);
    }
}

// The program headers of the ELF in `d`; false for a table that is not inside the file or has an entry that is too small, or too many.
bool read_phdrs(const Bytes& d, const Ehdr& e, std::vector<Phdr>& out) {
    const size_t min = e.is64 ? 56 : 32;
    if (e.phnum == 0 || e.phnum > kMaxSegments || e.phentsize < min) return false;
    const uint64_t end = e.phoff + uint64_t{e.phnum} * e.phentsize;
    if (e.phoff < (e.is64 ? 64u : 52u) || end > d.size() || end < e.phoff) return false;
    out.clear();
    for (size_t i = 0; i < e.phnum; ++i) out.push_back(read_phdr(d, static_cast<size_t>(e.phoff) + i * e.phentsize, e.is64));
    return true;
}

enum class Scan { NotElf, NoHash, Bad, Ok };

bool is_placeholder(const Phdr& p) { return p.type == 0 && segment_type(p.flags) == kSegPhdr && p.offset == 0; }

// Reads the ELF header and the program headers of `d` and tells whether this is an ELF with an MBN hash segment, and if it cannot be taken apart, why.
Scan scan_elf(const Bytes& d, Ehdr& eh, std::vector<Phdr>& ph, size_t& hash, std::string& why) {
    if (!read_ehdr(d, eh)) return Scan::NotElf;
    if (!read_phdrs(d, eh, ph)) return Scan::NoHash;
    bool found = false;
    for (size_t i = 0; i < ph.size() && !found; ++i)
        if (segment_type(ph[i].flags) == kSegHash) hash = i, found = true;
    if (!found) return Scan::NoHash;
    const Phdr& h = ph[hash];
    if (h.offset > d.size() || h.filesz > d.size() - h.offset) {
        why = "the hash segment (program header " + std::to_string(hash) + ", " + hex(h.filesz) + " bytes at " + hex(h.offset) + ") runs past the end of the file";
        return Scan::Bad;
    }
    if (const std::string p = block_problem(d, static_cast<size_t>(h.offset), static_cast<size_t>(h.offset + h.filesz)); !p.empty()) {
        why = "the hash segment (program header " + std::to_string(hash) + ") does not hold an MBN header and its parts: " + p;
        return Scan::Bad;
    }
    if (le32(d, static_cast<size_t>(h.offset)) == kSblCodeword && le32(d, static_cast<size_t>(h.offset) + 4) == kSblMagic) {
        why = "the hash segment holds an SBL header; abr knows the header versions 3, 5, 6 and 7 there";
        return Scan::Bad;
    }
    for (size_t i = 0; i < ph.size(); ++i) {
        if (i == hash || is_placeholder(ph[i]) || ph[i].filesz == 0) continue;
        if (ph[i].offset > d.size() || ph[i].filesz > d.size() - ph[i].offset) {
            why = "program header " + std::to_string(i) + " (" + hex(ph[i].filesz) + " bytes at " + hex(ph[i].offset) +
                  ") runs past the end of the file: the segments of a firmware that is split into a .mdt and .bNN files are in files of their own";
            return Scan::Bad;
        }
    }
    return Scan::Ok;
}

// The segments with data, by where their data lies in the file (the hash segment among them).
std::vector<size_t> ranges_of(const Elf& e) {
    std::vector<size_t> order;
    for (size_t i = 0; i < e.seg.size(); ++i)
        if (e.seg[i].role != Role::Headers && e.seg[i].ph.filesz > 0) order.push_back(i);
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return e.seg[a].ph.offset < e.seg[b].ph.offset; });
    return order;
}

// The largest power of two, at most 0x10000, that divides `offset` (1 for 0).
uint64_t alignment_of(uint64_t offset) {
    uint64_t a = 1;
    while (a < 0x10000 && offset % (a * 2) == 0 && offset != 0) a *= 2;
    return a;
}

// The step in which a segment that has to move may move: its p_align when that is a power of two (a program header says that p_offset and p_vaddr are
// the same modulo that), else the alignment its old place had.
uint64_t placement_unit(uint64_t p_align, uint64_t offset) {
    if (p_align >= 2 && p_align <= 0x10000 && (p_align & (p_align - 1)) == 0) return p_align;
    return alignment_of(offset);
}

// What the table of the ELF is made of, entry by entry: nothing for a layout that abr does not make a table for.
// emit(kind, segment, position, length): kind 0 zeros, 1 the headers, 2 data of the segment.
template <typename F>
bool walk_table(const Elf& e, F&& emit) {
    for (size_t i = 0; i < e.seg.size(); ++i) {
        const Segment& s = e.seg[i];
        if (s.ph.type == 6) return false;  // PT_PHDR: the tool takes them out; a table with one is not one abr knows how to make
        if (s.role == Role::Headers) {
            emit(1, i, size_t{0}, size_t{0});
            continue;
        }
        if (s.role == Role::Hash) {
            emit(0, i, size_t{0}, size_t{0});
            continue;
        }
        const bool checked = segment_type(s.ph.flags) != kSegHash && access_type(s.ph.flags) != kAccessNotUsed && access_type(s.ph.flags) != kAccessShared;
        const size_t size = s.data.size();
        if ((s.ph.flags & kFlagPageModeMask) != 0) {
            // A paged segment: an entry for every page of it, counted from the first page boundary of its address.
            const uint64_t off = s.ph.vaddr & (kPageSize - 1);
            const uint64_t skip = off ? kPageSize - off : 0;
            if (skip > size || (size - skip) % kPageSize != 0) return false;
            for (uint64_t pos = skip; pos < size; pos += kPageSize) emit(checked ? 2 : 0, i, static_cast<size_t>(pos), static_cast<size_t>(kPageSize));
        } else if (checked && size > 0) {
            emit(2, i, size_t{0}, size);
        } else {
            emit(0, i, size_t{0}, size_t{0});
        }
    }
    return true;
}

Bytes encode_ehdr(const Elf& e) {
    Bytes out = {0x7F, 'E', 'L', 'F', static_cast<uint8_t>(e.is64 ? 2 : 1), 1, 1};
    out.resize(16, 0);
    put(out, e.type, 2);
    put(out, e.machine, 2);
    put(out, 1, 4);
    const int a = e.is64 ? 8 : 4;
    const uint64_t ehsize = e.is64 ? 64 : 52;
    put(out, e.entry, a);
    put(out, ehsize, a);  // e_phoff: the table follows the header
    put(out, 0, a);       // e_shoff
    put(out, e.flags, 4);
    put(out, ehsize, 2);
    put(out, e.is64 ? 56 : 32, 2);
    put(out, e.seg.size(), 2);
    put(out, e.shentsize, 2);
    put(out, 0, 2);  // e_shnum
    put(out, 0, 2);  // e_shstrndx
    return out;
}

}  // namespace

bool elf_looks_like(const Bytes& d) {
    Ehdr eh;
    std::vector<Phdr> ph;
    size_t hash = 0;
    std::string why;
    return scan_elf(d, eh, ph, hash, why) == Scan::Ok;
}

std::string elf_problem(const Bytes& d) {
    Ehdr eh;
    std::vector<Phdr> ph;
    size_t hash = 0;
    std::string why;
    return scan_elf(d, eh, ph, hash, why) == Scan::Bad ? why : std::string();
}

std::optional<size_t> table_entries(const Elf& e) {
    size_t n = 0;
    if (!walk_table(e, [&](int, size_t, size_t, size_t) { ++n; })) return std::nullopt;
    return n;
}

std::optional<Bytes> make_table(const Elf& e, Algo algo, const Bytes& header) {
    const size_t ds = digest_size(algo);
    if (ds == 0) return std::nullopt;
    Bytes out;
    const bool ok = walk_table(e, [&](int kind, size_t seg, size_t pos, size_t len) {
        if (kind == 0) {
            out.insert(out.end(), ds, 0);
        } else if (kind == 1) {
            const Bytes h = digest(algo, header.data(), header.size());
            out.insert(out.end(), h.begin(), h.end());
        } else {
            const Bytes h = digest(algo, e.seg[seg].data.data() + pos, len);
            out.insert(out.end(), h.begin(), h.end());
        }
    });
    if (!ok) return std::nullopt;
    return out;
}

namespace {

// The headers of `e` with the program headers `ph` (the segments' own, or the ones a build has made for what the segments now hold).
Bytes headers_with(const Elf& e, const std::vector<Phdr>& ph) {
    if (!e.tidy) {
        Bytes out(e.skeleton.begin(), e.skeleton.begin() + static_cast<std::ptrdiff_t>(std::min<size_t>(e.ehsize, e.skeleton.size())));
        const size_t at = static_cast<size_t>(e.phoff), n = ph.size() * e.phentsize;
        if (at <= e.skeleton.size() && n <= e.skeleton.size() - at)
            out.insert(out.end(), e.skeleton.begin() + static_cast<std::ptrdiff_t>(at), e.skeleton.begin() + static_cast<std::ptrdiff_t>(at + n));
        return out;
    }
    Bytes out = encode_ehdr(e);
    for (const Phdr& p : ph) write_phdr(out, p, e.is64);
    return out;
}

}  // namespace

Bytes elf_header_bytes(const Elf& e) {
    std::vector<Phdr> ph;
    for (const Segment& s : e.seg) ph.push_back(s.ph);
    return headers_with(e, ph);
}

void classify(Elf& e) {
    bool found = false;
    for (size_t i = 0; i < e.seg.size(); ++i) {
        Segment& s = e.seg[i];
        if (!found && segment_type(s.ph.flags) == kSegHash) {
            s.role = Role::Hash;
            e.hash_index = i;
            found = true;
        } else if (is_placeholder(s.ph)) {
            s.role = Role::Headers;
        } else {
            s.role = Role::Plain;
        }
    }
    if (!found) throw FormatError("no program header is a hash segment (p_flags & 0x07000000 == 0x02000000)");
}

Elf parse_elf(const Bytes& d) {
    Ehdr eh;
    std::vector<Phdr> ph;
    size_t hash = 0;
    std::string why;
    switch (scan_elf(d, eh, ph, hash, why)) {
        case Scan::NotElf: throw FormatError("not an ELF (32 or 64 bits, little-endian)");
        case Scan::NoHash: throw FormatError("this ELF has no hash segment (no program header with p_flags & 0x07000000 == 0x02000000)");
        case Scan::Bad: throw FormatError("ELF with a hash segment: " + why);
        case Scan::Ok: break;
    }
    Elf e;
    e.is64 = eh.is64;
    e.type = eh.type;
    e.machine = eh.machine;
    e.shentsize = eh.shentsize;
    e.flags = eh.flags;
    e.entry = eh.entry;
    e.phoff = eh.phoff;
    e.ehsize = eh.ehsize;
    e.phentsize = eh.phentsize;
    for (const Phdr& p : ph) {
        Segment s;
        s.ph = p;
        e.seg.push_back(std::move(s));
    }
    classify(e);
    if (e.hash_index != hash) throw FormatError("ELF with a hash segment: internal error (the hash segment moved)");
    for (Segment& s : e.seg)
        if (s.role == Role::Plain && s.ph.filesz > 0)
            s.data.assign(d.begin() + static_cast<std::ptrdiff_t>(s.ph.offset), d.begin() + static_cast<std::ptrdiff_t>(s.ph.offset + s.ph.filesz));

    const Phdr& h = ph[hash];
    e.block = parse_block(d, static_cast<size_t>(h.offset), static_cast<size_t>(h.offset + h.filesz));
    e.hash_pad.assign(d.begin() + static_cast<std::ptrdiff_t>(h.offset + e.block.consumed), d.begin() + static_cast<std::ptrdiff_t>(h.offset + h.filesz));

    // The data of the segments, in the order of the file, and the bytes between them.
    const std::vector<size_t> order = ranges_of(e);
    const uint64_t header_end = std::max<uint64_t>(e.ehsize, e.phoff + uint64_t{e.seg.size()} * e.phentsize);
    uint64_t pos = header_end;
    for (size_t i : order) {
        const Phdr& p = e.seg[i].ph;
        if (p.offset < pos)
            throw FormatError("ELF with a hash segment: the data of program header " + std::to_string(i) + " (at " + hex(p.offset) + ") overlaps the " +
                              (pos == header_end ? std::string("ELF header and the program headers") : std::string("data before it")) + " (which ends at " + hex(pos) + ")");
        pos = p.offset + p.filesz;
    }
    e.consumed = static_cast<size_t>(pos);

    // The hash table: does abr make exactly this?
    const Bytes header(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(std::min<size_t>(e.ehsize, d.size())));
    Bytes headers = header;
    headers.insert(headers.end(), d.begin() + static_cast<std::ptrdiff_t>(e.phoff), d.begin() + static_cast<std::ptrdiff_t>(e.phoff + uint64_t{e.seg.size()} * e.phentsize));
    if (const std::optional<size_t> n = table_entries(e); n && *n > 0 && e.block.code.size() % *n == 0) {
        const size_t ds = e.block.code.size() / *n;
        const Algo algo = ds == 20 ? Algo::Sha1 : ds == 32 ? Algo::Sha256 : ds == 48 ? Algo::Sha384 : Algo::None;
        if (algo != Algo::None)
            if (const std::optional<Bytes> t = make_table(e, algo, headers); t && *t == e.block.code) e.algo = algo;
    }

    // The tidy layout, if the file is exactly what build_elf() makes of it: the same fill everywhere between the parts.
    bool uniform = true;
    uint8_t fill = 0;
    bool have_fill = false;
    const auto scan_fill = [&](uint64_t from, uint64_t to) {
        for (uint64_t i = from; i < to; ++i) {
            if (!have_fill) fill = d[static_cast<size_t>(i)], have_fill = true;
            else if (d[static_cast<size_t>(i)] != fill) uniform = false;
        }
    };
    {
        uint64_t at = header_end;
        for (size_t i : order) {
            scan_fill(at, e.seg[i].ph.offset);
            at = e.seg[i].ph.offset + e.seg[i].ph.filesz;
        }
    }
    e.tidy = true;
    e.fill = fill;
    if (uniform) {
        try {
            e.tidy = build_elf(e) == Bytes(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(e.consumed));
        } catch (const FormatError&) {
            e.tidy = false;
        }
    } else {
        e.tidy = false;
    }
    if (!e.tidy) {
        e.skeleton.clear();
        uint64_t at = 0;
        for (size_t i : order) {
            e.skeleton.insert(e.skeleton.end(), d.begin() + static_cast<std::ptrdiff_t>(at), d.begin() + static_cast<std::ptrdiff_t>(e.seg[i].ph.offset));
            at = e.seg[i].ph.offset + e.seg[i].ph.filesz;
        }
        e.fill = 0;
    }
    return e;
}

Elf elf_shell(const Bytes& skeleton) {
    Ehdr eh;
    std::vector<Phdr> ph;
    if (!read_ehdr(skeleton, eh) || !read_phdrs(skeleton, eh, ph)) throw FormatError("the skeleton does not start with an ELF header and its program headers");
    Elf e;
    e.is64 = eh.is64;
    e.type = eh.type;
    e.machine = eh.machine;
    e.shentsize = eh.shentsize;
    e.flags = eh.flags;
    e.entry = eh.entry;
    e.phoff = eh.phoff;
    e.ehsize = eh.ehsize;
    e.phentsize = eh.phentsize;
    for (const Phdr& p : ph) {
        Segment s;
        s.ph = p;
        e.seg.push_back(std::move(s));
    }
    classify(e);
    e.tidy = false;
    e.skeleton = skeleton;
    const std::vector<size_t> order = ranges_of(e);
    uint64_t end = std::max<uint64_t>(e.ehsize, e.phoff + uint64_t{e.seg.size()} * e.phentsize);
    for (size_t i : order) end = std::max<uint64_t>(end, e.seg[i].ph.offset + e.seg[i].ph.filesz);
    e.consumed = static_cast<size_t>(end);
    return e;
}

Bytes build_elf(const Elf& e, std::string* note) {
    const size_t n = e.seg.size();
    if (n == 0 || n > kMaxSegments) throw FormatError("ELF: " + std::to_string(n) + " program headers (1 to " + std::to_string(kMaxSegments) + " are possible)");
    if (e.hash_index >= n || e.seg[e.hash_index].role != Role::Hash) throw FormatError("ELF: no hash segment");
    if (e.block.kind != Kind::Boot) throw FormatError("ELF: the hash segment holds an SBL header; abr knows the header versions 3, 5, 6 and 7 there");

    // The hash segment, with a table of the size it will have.
    Block blk = e.block;
    if (e.algo != Algo::None) {
        const std::optional<size_t> entries = table_entries(e);
        if (!entries) throw FormatError("ELF: the hash table cannot be made from these program headers (one of type PT_PHDR, or a paged segment that is not made of whole pages)");
        blk.code.assign(*entries * digest_size(e.algo), 0);
    }
    Bytes hash_data = build_block(blk);
    hash_data.insert(hash_data.end(), e.hash_pad.begin(), e.hash_pad.end());

    std::vector<Phdr> ph(n);
    for (size_t i = 0; i < n; ++i) ph[i] = e.seg[i].ph;
    std::vector<uint64_t> len(n, 0);
    for (size_t i = 0; i < n; ++i) {
        const Segment& s = e.seg[i];
        len[i] = s.role == Role::Hash ? hash_data.size() : s.role == Role::Plain ? s.data.size() : 0;
    }

    // Where the data goes.
    std::vector<uint64_t> start(n, 0);
    std::vector<size_t> order;
    std::string moved;
    if (e.tidy) {
        for (size_t i = 0; i < n; ++i) {
            const Segment& s = e.seg[i];
            if (s.role != Role::Headers && len[i] > 0) order.push_back(i);
        }
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return e.seg[a].ph.offset < e.seg[b].ph.offset; });
        uint64_t cursor = e.header_size();
        for (size_t i : order) {
            const uint64_t old = e.seg[i].ph.offset;
            start[i] = old >= cursor ? old : old + align_up(cursor - old, placement_unit(e.seg[i].ph.align, old));
            if (start[i] != old) moved += (moved.empty() ? "" : ", ") + std::string("program header ") + std::to_string(i) + " " + hex(old) + " -> " + hex(start[i]);
            cursor = start[i] + len[i];
        }
        for (size_t i = 0; i < n; ++i) {
            Phdr& p = ph[i];
            const Segment& s = e.seg[i];
            if (s.role == Role::Headers) {
                p.filesz = e.header_size();
                continue;
            }
            p.filesz = len[i];
            if (len[i] > 0) p.offset = start[i];
            if (p.memsz < p.filesz) p.memsz = s.role == Role::Hash ? align_up(p.filesz, p.align ? p.align : 1) : p.filesz;
        }
    } else {
        for (size_t i = 0; i < n; ++i) {
            const Segment& s = e.seg[i];
            if (s.role != Role::Headers && s.ph.filesz > 0) order.push_back(i);
            if (s.role != Role::Headers && len[i] != s.ph.filesz)
                throw FormatError("ELF: program header " + std::to_string(i) + " is " + std::to_string(len[i]) + " bytes, and it was " + std::to_string(s.ph.filesz) +
                                  ": the layout of this image (data that is not a fill, section headers, or headers that are not those Qualcomm's tools write) is kept as it is, "
                                  "so every segment must keep its size");
            start[i] = s.ph.offset;
        }
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return start[a] < start[b]; });
    }
    if (!e.is64) {
        for (size_t i = 0; i < n; ++i)
            if (ph[i].offset > 0xFFFFFFFFull || ph[i].filesz > 0xFFFFFFFFull || ph[i].memsz > 0xFFFFFFFFull)
                throw FormatError("ELF: program header " + std::to_string(i) + " does not fit a 32-bit ELF (offset " + hex(ph[i].offset) + ", " + std::to_string(ph[i].filesz) + " bytes)");
    }

    // The headers as they will be, and the table made from them.
    const Bytes headers = headers_with(e, ph);
    if (e.algo != Algo::None) {
        const std::optional<Bytes> table = make_table(e, e.algo, headers);
        if (!table) throw FormatError("ELF: the hash table cannot be made");
        blk.code = *table;
        hash_data = build_block(blk);
        hash_data.insert(hash_data.end(), e.hash_pad.begin(), e.hash_pad.end());
    }

    Bytes out;
    if (e.tidy) {
        out = headers;
        uint8_t fill = e.fill;
        for (size_t i : order) {
            out.resize(static_cast<size_t>(start[i]), fill);
            const Segment& s = e.seg[i];
            const Bytes& data = s.role == Role::Hash ? hash_data : s.data;
            out.insert(out.end(), data.begin(), data.end());
        }
    } else {
        size_t sk = 0;
        uint64_t pos = 0;
        for (size_t i : order) {
            const size_t gap = static_cast<size_t>(start[i] - pos);
            if (sk + gap > e.skeleton.size()) throw FormatError("ELF: the skeleton is shorter than the layout it stands for");
            out.insert(out.end(), e.skeleton.begin() + static_cast<std::ptrdiff_t>(sk), e.skeleton.begin() + static_cast<std::ptrdiff_t>(sk + gap));
            sk += gap;
            const Segment& s = e.seg[i];
            const Bytes& data = s.role == Role::Hash ? hash_data : s.data;
            out.insert(out.end(), data.begin(), data.end());
            pos = start[i] + len[i];
        }
    }
    if (note) *note = moved.empty() ? std::string() : "moved: " + moved;
    return out;
}

}  // namespace abr::mbn
