// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::mbn -- the images of Qualcomm's secure boot (the "MBN" files): sbl1/xbl, tz, hyp, rpm, aboot/appsboot, devcfg, keymaster and the like.
//
// An MBN image is built from one structure, the "image header" and what hangs on it, in one of two containers.
//
//   The structure (`Block`):
//     [ header           40 bytes (version 3 and 5), 48 (6), 64 (7), or 80 bytes (the SBL header: the codeword 0x844BDCD1, the magic 0x73D71034) ]
//     [ metadata         versions 6 and 7: Qualcomm's (metadata_size_qti bytes), then the OEM's (metadata_size) ]
//     [ code             the code of the image -- or, in an ELF, the table of hashes of its segments ]
//     [ signature        versions 5 and later: Qualcomm's (sig_size_qti), then the OEM's (sig_size) ]
//     [ certificate chain  the same: Qualcomm's (cert_chain_size_qti), then the OEM's (cert_chain_size) ]
//   Versions 3 and 5 have the 40 bytes; 6 adds the two sizes of the metadata; 7 is another header (no image_size, the sizes of the parts, then 24 bytes
//   of "common metadata"; the OEM metadata of 224 bytes follows it). The header holds the size of every part; version 3 and the SBL header also
//   the size of the whole (image_size: the parts, and up to three bytes that round them up to a multiple of four), and the addresses at which the signature
//   and the chain lie once the image is loaded.
//
//   The containers:
//     flat   the file is the structure ("bin" images: aboot/appsboot, the SBL1 of older chips): the header, the code, the signature, the chain.
//     ELF    the file is an ELF (32 or 64 bits, little-endian) whose program headers describe the segments of the firmware, and one more of them,
//            the "hash segment" (p_type 0, the segment-type bits of p_flags set to 2: p_flags & 0x07000000 == 0x02000000), holds the structure
//            -- and its code is a table: a hash for every program header, in the order of the table. The first program header is a placeholder
//            (type 0, segment type 7, p_offset 0, p_filesz the size of the ELF header and the program headers) whose hash is that of those bytes;
//            the hash segment's own entry is zeros; a segment without data has zeros too, as have the kinds the loader does not check (p_flags access
//            type 3 and 4). The hash is SHA-256 (versions 3, 5; SHA-1 in older images) or SHA-384 (6, 7).
//
// Where this comes from. The layouts, the names of the fields and the flag values are those of the two tools that make these images and are
// written down in the open: coreboot's util/qualcomm/mbn_tools.py (BSD-3-Clause, Qualcomm's) and qtestsign (GPL-2.0-only AND BSD-3-Clause);
// they were read for the layout and nothing of them is in abr. Qualcomm's own documents (Secure Boot and Image Authentication) are the
// source of the names of the certificate attributes. No image from a device was at hand while this was written: the tests build images in the
// layout of those tools, with the hashes made by another implementation, and what this code cannot read it says so and keeps (see below).
//
// What is made again and what is kept. The sizes in the header, image_size, the pointers (where they were address + size to begin with) and the
// hash table of an ELF (where abr can make exactly the table that is in the image: it is checked when the image is read) are made again from
// the parts. Signatures and certificate chains are kept as they are -- abr cannot sign -- and an image that is edited no longer matches them: the
// caller warns. A table that abr cannot make again (an algorithm or a layout it does not know) is kept as it is.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr::mbn {

inline constexpr uint32_t kSblCodeword = 0x844BDCD1;
inline constexpr uint32_t kSblMagic = 0x73D71034;
// The third word of the preamble that Qualcomm's tools put in front of an SBL on NAND (the same two words, then this): abr tells it, it does not open it.
inline constexpr uint32_t kSblPreambleMagic = 0x7D0B435A;
inline constexpr size_t kSblHeaderSize = 80;

// ---------------------------------------------------------------------------------------------------------------------------------- hashes --

enum class Algo { None, Sha1, Sha256, Sha384 };
const char* algo_name(Algo a);                     // "SHA-1", "SHA-256", "SHA-384", "none"
const char* algo_key(Algo a);                      // "sha1", "sha256", "sha384", "none" (what the manifest says)
std::optional<Algo> algo_from_key(std::string_view key);
size_t digest_size(Algo a);                        // 20, 32, 48; 0 for None
Bytes digest(Algo a, const uint8_t* data, size_t size);

// ----------------------------------------------------------------------------------------------------------------------------- the structure --

enum class Kind { Boot, Sbl };

// One word of a header: its name (the manifest's key), its place, and what it is.
struct Field {
    enum class Use {
        Keep,     // a value that abr does not know the meaning of or that nothing derives: kept as it is, the manifest names it
        Derived,  // a size or the total: made from the parts
        Pointer,  // an address of the signature or of the chain: made from `ptr_base` and the sizes, when they were that
        Fixed     // the version, the codeword, the magic
    };
    const char* name;
    unsigned index;
    Use use;
};

// The words of a header, in order: Kind::Boot with its version (3, 5, 6, 7), or Kind::Sbl (the version is ignored). Empty for a version that has none.
const std::vector<Field>& fields(Kind kind, uint32_t version);
// 40, 40, 48, 64 for the Boot versions 3, 5, 6, 7; 80 for Sbl; 0 for anything else.
size_t header_size(Kind kind, uint32_t version);

struct Block {
    Kind kind = Kind::Boot;
    uint32_t version = 3;         // of a Boot header; an Sbl header has none
    std::vector<uint32_t> w;      // the words of the header as they were read (build() makes the derived ones right)
    Bytes metadata_qti, metadata; // versions 6 and 7
    Bytes code;                   // the code of a flat image; the table of hashes of an ELF's hash segment
    Bytes sig_qti, cert_qti;      // versions 5 and later
    Bytes sig, cert;
    Bytes slack;                  // the bytes between the parts and image_size (zero to three; not in version 7)
    bool align4 = false;          // the slack is what rounds the parts up to a multiple of four (build() makes it again)
    bool derived_ptrs = false;    // the signature address is ptr_base + code size, and the chain's follows it
    uint32_t ptr_base = 0;
    size_t consumed = 0;          // how many bytes the structure takes in the buffer it was read from

    size_t header_bytes() const { return header_size(kind, version); }
    // The sizes of the parts, added.
    uint64_t parts_size() const;
    // The word of that name, or 0 when this header has none.
    uint32_t word(std::string_view name) const;
    // Sets it; false when this header has no such word.
    bool set_word(std::string_view name, uint32_t value);
};

// A block of that kind and version with the fixed words in place and everything else zero.
Block make_block(Kind kind, uint32_t version);

// Why the bytes of d[at, limit) are not the structure (empty when they are): the version, the sizes that do not add up, the parts that do not fit.
std::string block_problem(const Bytes& d, size_t at, size_t limit);
// The structure at d[at], which must end by `limit`; FormatError with the reason (block_problem) otherwise.
Block parse_block(const Bytes& d, size_t at, size_t limit);
// The bytes of the structure: the header (the derived words made from the parts), the parts, the slack.
Bytes build_block(const Block& b);

// A flat MBN image: the structure at the start of the file, at least 4-byte aligned parts that end inside the file, an image_id that is a small number
// (a header of version 3..6 has one). Weak by nature -- ten words and a version -- so it is meant to be asked last.
bool flat_looks_like(const Bytes& d);
// What is wrong with a file that has the codeword and the magic of an SBL header (a preamble on NAND, a code that does not follow the header);
// empty when it is no such file or is fine.
std::string flat_problem(const Bytes& d);

// The meaning of a header's version for a line of text: "version 3 (40 bytes)", "SBL header (80 bytes)".
std::string describe_header(const Block& b);

// ------------------------------------------------------------------------------------------------------------------ the certificate chain --

// One certificate of a chain (a chain is DER certificates one behind the other, filled up with 0xFF or zeros).
struct Cert {
    size_t offset = 0, size = 0;
    std::string subject, issuer;                  // "C=US, O=QUALCOMM, OU=..., CN=..." in the order they stand
    std::vector<std::string> attributes;          // the OU entries of the subject ("01 0000000000000003 SW_ID", ...) -- Qualcomm's attributes of the image
};
// The certificates that the chain starts with (as many as are certificates one behind the other); what follows them is `rest` bytes.
std::vector<Cert> read_chain(const Bytes& chain, size_t* rest = nullptr);
// "SW_ID" ... for "01 0000000000000003 SW_ID": the attribute named by the text of an OU entry, and its value, in the words of Qualcomm's documents.
std::string attribute_text(const std::string& ou);

// --------------------------------------------------------------------------------------------------------------------------------- the ELF --

inline constexpr uint32_t kFlagSegmentTypeMask = 0x07000000;
inline constexpr unsigned kFlagSegmentTypeShift = 24;
inline constexpr uint32_t kFlagAccessTypeMask = 0x00E00000;
inline constexpr unsigned kFlagAccessTypeShift = 21;
inline constexpr uint32_t kFlagPageModeMask = 0x00100000;
inline constexpr unsigned kSegHash = 2;      // the hash segment
inline constexpr unsigned kSegPhdr = 7;      // the placeholder for the ELF header and the program headers
inline constexpr unsigned kAccessNotUsed = 3;
inline constexpr unsigned kAccessShared = 4;
inline constexpr size_t kMaxSegments = 256;
inline constexpr uint64_t kPageSize = 0x1000;

// The names of the fields of p_flags in Qualcomm's headers: "HASH", "PHDR", "AMSS", ... and "RO", "RW", "ZI", "NOTUSED", "SHARED", "RWE".
std::string segment_type_name(unsigned type);
std::string access_type_name(unsigned type);
// "HASH, RO" "AMSS, RO, paged": what the flags say, in words (empty when the Qualcomm bits are all zero: a segment of an ordinary ELF).
std::string describe_flags(uint32_t flags);

struct Phdr {
    uint32_t type = 0, flags = 0;
    uint64_t offset = 0, vaddr = 0, paddr = 0, filesz = 0, memsz = 0, align = 0;
};

enum class Role { Plain, Headers, Hash };

struct Segment {
    Phdr ph;
    Role role = Role::Plain;
    Bytes data;  // the bytes of a Plain segment in the file (empty for the other two: the hash segment is Elf::block and hash_pad)
};

struct Elf {
    bool is64 = false;
    uint16_t type = 2, machine = 0, shentsize = 0;
    uint32_t flags = 0;
    uint64_t entry = 0;
    std::vector<Segment> seg;   // in the order of the program headers
    size_t hash_index = 0;      // which one is the hash segment
    Block block;                // what the hash segment holds
    Bytes hash_pad;             // the bytes of the hash segment behind the structure (what its p_filesz has more)
    Algo algo = Algo::None;     // how the table is made, when abr makes exactly the table that is in the image; None: it is kept as it is
    bool tidy = true;           // the layout is the one build() makes from the segments (see below); else `skeleton` is what is between them
    uint8_t fill = 0;           // tidy: the byte between the headers and the segments, and between the segments
    Bytes skeleton;             // not tidy: the bytes of the file that are not the data of a segment, in the order they lie (run by run)
    size_t consumed = 0;        // where the data of the last segment ends
    // Of the file as it was read; the hash of the headers is made of them when the layout is not tidy (a tidy one writes the standard).
    uint64_t phoff = 0;
    uint16_t ehsize = 0, phentsize = 0;

    // The ELF header and the program header table as a tidy layout writes them: 52 + 32 n or 64 + 56 n bytes.
    uint64_t header_size() const { return (is64 ? 64u : 52u) + (is64 ? 56u : 32u) * uint64_t{seg.size()}; }
};

// The segment-type bits of p_flags.
inline unsigned segment_type(uint32_t flags) { return (flags & kFlagSegmentTypeMask) >> kFlagSegmentTypeShift; }
inline unsigned access_type(uint32_t flags) { return (flags & kFlagAccessTypeMask) >> kFlagAccessTypeShift; }

// An ELF (class 32 or 64, little-endian) with a hash segment that holds a structure of this namespace, and segments that lie in the file.
bool elf_looks_like(const Bytes& d);
// Why an ELF that has a hash segment cannot be read (a segment past the end of the file -- the .mdt of a split firmware; a header that is
// no structure ...); empty for a file that is no ELF, has no hash segment, or can be read.
std::string elf_problem(const Bytes& d);

// The ELF in `d`: FormatError for what is not one that abr can take apart.
Elf parse_elf(const Bytes& d);
// The ELF of a layout that is not tidy, from its skeleton (what parse_elf() left in Elf::skeleton): the program headers are read from it, the
// segments' data and the hash segment's parts are for the caller to put in.
Elf elf_shell(const Bytes& skeleton);
// Sets the role of every segment and hash_index from the program headers (the first with the segment type 2 is the hash segment, a NULL header of
// type 7 at offset 0 is the placeholder); FormatError when there is no hash segment.
void classify(Elf& e);

// The file up to the end of the last segment. The tidy layout is the one that Qualcomm's tools make: the ELF header, the program headers (at once
// behind it), a run of `fill`, the data of the segments in the order they were in the file -- each where it was while that is behind the end of
// the one before it, else at the next multiple of the alignment that its old place had (at most 0x10000) -- and `fill` between them; the
// sizes and offsets in the program headers made for what the segments now hold (p_memsz grows with p_filesz only where it must), and the
// hash table made again. Where the layout is not tidy (section headers, something else than a fill between the segments, an ELF header or a
// program header size that is not the standard) the file is made from the skeleton, and every segment must have the size it had.
// `note` (if given) tells what moved.
Bytes build_elf(const Elf& e, std::string* note = nullptr);

// The ELF header, the program headers (and the table of hashes made from them is not part of it): as build_elf() writes them for `e` as it stands.
Bytes elf_header_bytes(const Elf& e);

// The hash table of an ELF made from its segments with `algo`; nullopt where abr does not make it (a program header of type PT_PHDR, a paged
// segment that is not made of whole pages). `header` is the ELF header and the program headers (what the placeholder's hash is made of).
std::optional<Bytes> make_table(const Elf& e, Algo algo, const Bytes& header);

// How many entries make_table() would make, without the hashing: nullopt as above.
std::optional<size_t> table_entries(const Elf& e);

}  // namespace abr::mbn
