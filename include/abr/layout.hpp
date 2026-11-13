// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::layout -- where the parts of an image are: the offset and the size of each, in the order they lie in the file.
//
// `unpack`, `pack` and `info` all say it, from here, so that the numbers one of them gives are the numbers of the others: a
// Layout is made of an image that is there (the bytes of the file, or of the image that was just built), never of what abr
// meant to write. The tests build images with the builders of abr and check that the bytes at [offset, offset + size) of every
// region are the part they say (tests/unit/layout_test.cpp).
//
// A region is a part of the file with a name; some are the parts that `unpack` writes to a file of their own (`key` is then the
// prefix of the keys of the manifest that tell what became of it: `kernel` for `kernel_file`, `kernel_compression`, ...). Regions
// of depth 1 or more lie inside the region before them that has a smaller depth: the fragments of the vendor ramdisk in the
// ramdisk section, the descriptors in the auxiliary block of a vbmeta. What is between the regions is padding.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {
struct BootImage;
struct VendorBootImage;
struct UImage;
namespace legacy {
struct KrnlImage;
struct ElfBootImage;
struct BlobImage;
struct OsipImage;
struct ChromeosInfo;
}  // namespace legacy
}  // namespace abr

namespace abr::layout {

struct Region {
    std::string name;       // "header", "kernel", "AVB footer"
    std::string key;        // the prefix of its keys in the manifest ("kernel", "ramdisk0", "entry3"), when `unpack` writes it to a file
    uint64_t offset = 0;    // from the start of the file
    uint64_t size = 0;
    unsigned depth = 0;
    std::string note;       // a few words about what the bytes are ("header version 2", "device tree")
    std::string codec;      // the stream the bytes are, when they are one ("gzip"); the plain data is what the file of the part holds

    // What the caller that knows the manifest and the folder adds (annotate in main.cpp): the file the part was unpacked to, how
    // big it is (the size of the plain data, when the part is a stream), and the level the stream was made with.
    std::string file;
    uint64_t unpacked = 0;
    int level = -1;
};

struct Layout {
    std::string format;       // "boot image, header version 2"
    uint64_t size = 0;        // the size of the file
    std::vector<Region> regions;

    Region& add(std::string name, std::string key, uint64_t offset, uint64_t size, unsigned depth = 0, std::string note = {});
    // Moves every region `by` bytes on: the layout of a container that does not start at the start of the file.
    void shift(uint64_t by);
};

// ------------------------------------------------------------------------------------------------ the containers --
// Each gives the regions of the container, from its own first byte: the caller (around(), below) puts what is around it.

Layout boot(const BootImage& img);
Layout vendor_boot(const VendorBootImage& img);
// `table` is the bytes of the dtbo: the entries are read from the table as they lie there (an entry may be stored deflated, and the
// sizes of the parsed entries are those of the plain data).
Layout dtbo(const Bytes& table);
Layout uimage(const UImage& img);
// A Qualcomm device tree table, read from its bytes (the table at the start of `data`).
Layout qcdt(const Bytes& data, const std::string& key_prefix = "");
// The vbmeta blob at `at` in `data` (a vbmeta image has it at 0; the AVB footer of a partition points at it), added to `l` with its
// header, its authentication and auxiliary blocks, the descriptors, the public key. `key_prefix` is the prefix of the manifest's
// keys for it ("" for a vbmeta image, "avb_" for the footer of another partition). Nothing is added for what is not a vbmeta blob.
void vbmeta(Layout& l, const Bytes& data, uint64_t at, unsigned depth, const std::string& key_prefix);
Layout vbmeta_image(const Bytes& data);
// Flattened device trees one after the other (a dtb file): the size of each, and the zero bytes in front of each (`gaps`, as many as
// the sizes, or none: the trees follow one another).
Layout dtb_blobs(const std::vector<size_t>& sizes, const std::vector<size_t>& gaps = {});
// A U-Boot FIT image, read from `file` (the flattened tree is walked): the header, the reservation map, the structure block and the strings
// block, and the data of every image, where it is -- inside the structure block (`data`), or behind the tree (data-offset, data-position).
// `keys[i]` is the key of the manifest for the i-th child of /images (empty: none).
Layout fit(const Bytes& file, const std::vector<std::string>& keys);
// A Sony ELF boot image, read from the program headers of `file` (the bytes `img` was parsed from): the ELF header, the table of program
// headers, the data of every segment. `keys[i]` is the key of the manifest for the component of segment i.
Layout elf_boot(const legacy::ElfBootImage& img, const Bytes& file, const std::vector<std::string>& keys);
// A Rockchip KRNL image: "KRNL" and the size, the payload (`key`: "kernel" or "ramdisk", the component it became), the CRC.
Layout krnl(const legacy::KrnlImage& img, const std::string& key);
// An ASUS blob: the secure header of a signed one, the blob header, the table, the partitions (`blob_part<N>`), what follows (the signature).
Layout blob(const legacy::BlobImage& img);
// An Intel OSIP image: the OSIP header, the signature, the cmdline, the image info, the bootstub, the kernel, the ramdisk.
Layout osip(const legacy::OsipImage& img);
// A ChromeOS kernel blob, read from `file`: the verification block (the keyblock and the preamble in it) and the body (the kernel, the
// config, the params, the bootloader in it).
Layout chromeos(const legacy::ChromeosInfo& info, const Bytes& file);

// A MediaTek partition image (abr/mtkimg.hpp), read from `file`: for every section its header (512 bytes), its data and the padding behind
// it. `section<i>` is the key of the data of the section i (and of its file in the manifest) when it is a file of its own; the pictures of
// a logo table are regions of depth 1 inside the data of their section, `section<i>_p<k>` their keys. Empty for a file that is no such image.
Layout mtk_image(const Bytes& file);

// The loader of a MediaTek boot ROM (abr/mtkgfh.hpp): the device header and the BRLYT in front of it (key `device`), FILE_INFO, the headers behind
// it one by one (key `headers` for all of them), the loader's code (key `loader`), the signature (key `signature`, none for a SHA-256 that is made again).
Layout mtk_preloader(const Bytes& file);

// A flat Qualcomm MBN image (abr/mbn.hpp), read from `file`: the header, then the parts that hang on it one behind the other -- the metadata, the code
// (key `code`), the signature and the certificate chain (QTI's and the OEM's; the certificates of a chain are regions of depth 1) -- and the bytes that round
// them up. The key of a part is the prefix of its keys in the manifest (`metadata`, `signature`, `cert_chain`, ...). Empty for a file that is no such image.
Layout mbn(const Bytes& file);

// A Qualcomm ELF image with a hash segment, read from `file`: the ELF header, the program headers, the data of every segment (key `seg<i>` for the program
// header i) and the hash segment, whose structure is laid out at depth 1 -- the header, the metadata, the table of hashes (key `hash_table`), the signature
// and the certificate chain. Empty for a file that is no such image.
Layout mbn_elf(const Bytes& file);

// The picture partitions of a phone (abr/splash.hpp), read from `file`: Qualcomm's "SPLASH!!" image (the header, the pictures: key `picture<i>`; a region
// is the pixels or the packets of a picture, the padding up to the block is not one), the OPLUS "SPLASH LOGO!" image (the preamble in front of the header, the
// header with its descriptions and table at depth 1, the pictures: key `entry<i>`), the Xiaomi "LOGO!!!!" image (the preamble, the table, the pictures: key
// `picture<i>`; a region is the file, not the zeros that fill its last unit) and the Motorola "MotoLogo" image (the table, the pictures: key `entry<i>`, empty
// slots are no region). Empty for a file that is no such image.
Layout qc_splash(const Bytes& file);
Layout oplus_logo(const Bytes& file);
Layout xiaomi_logo(const Bytes& file);
Layout moto_logo(const Bytes& file);

// What is around the container that lies at [core_off, core_off + core_len) of `whole`: the bytes in front of it, the bytes after
// it, the fill up to the size of the partition (Envelope), and the AVB hash footer at the end (vbmeta block and footer). The regions of
// the container are moved by core_off; the size and the regions of the layout are those of `whole`. `host_size` is the number of bytes
// the AVB footer protects when the file has one (the first `host_size` bytes are the image and what is around it), else the size of the
// file.
void around(Layout& l, const Bytes& whole, size_t host_size, size_t core_off, size_t core_len);

// ----------------------------------------------------------------------------------------------------- the text --

// The table `unpack`, `pack` and `info` print, one line per region: offset (hex), size (decimal), the name, and what is known of
// the part. Every line starts with `indent`.
std::string render(const Layout& l, const std::string& indent = "  ");

// The lines of the layout block of a manifest, as (key, value): `layout_<name>_offset`, `layout_<name>_size` for every region, and for
// a stream `layout_<name>_unpacked_size`. <name> is the key of the region, or its name made into letters, digits and underscores
// (header, tail, avb_footer; the same name twice gets a number behind it).
std::vector<std::pair<std::string, std::string>> manifest_lines(const Layout& l);

// Writes the block into the manifest file at `path` (text: the lines that are there stay as they are): the lines of an earlier block
// are taken out, the new one goes to the end, with `what` ("the image this folder was unpacked from") in the comment before it.
// Nothing is written when the file is not there. Returns false when it could not be written.
bool write_manifest_block(const std::filesystem::path& path, const Layout& l, const std::string& what);

}  // namespace abr::layout
