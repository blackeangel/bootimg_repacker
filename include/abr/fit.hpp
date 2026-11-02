// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::fit -- a U-Boot FIT image (flattened image tree; U-Boot's doc/uImage.FIT/source_file_format.txt): a flattened device tree
// (fdt.hpp) whose /images hold the kernel, the ramdisk, the device trees and the rest, and whose /configurations say which of
// them go together.
//
// The data of an image is in the tree (`data`: what mkimage makes of /incbin/("file")) or behind it. `mkimage -E` takes it out
// of the tree and writes `data-size` and `data-offset` (the offset from the end of the tree, which is taken to be a multiple of 4),
// `mkimage -E -p N` writes `data-size` and `data-position` (the offset from the start of the file). Where the images are is the
// *place*: inline, offset or position.
//
// open() takes a file apart into the tree (the data of every image taken out of it: in its place a property `data` without a
// value, which the caller gives the name of the file the data goes to), the images, and the layout; build() puts them together
// again. open() says no to a file that build() would not write byte for byte -- it builds it again to see -- and the caller then
// treats the file as the plain device tree it is. What the layout is, for a file that is taken:
//   * inline: the blob and nothing else (what is behind it is the caller's: fill, a signature);
//   * offset or position: the blob (padded to a multiple of `tree_align`, when the file had it so, or with `slack` zeros), zeros
//     up to the first image, the images (each with its zeros in front of it), zeros up to a multiple of `end_align`. Where the images are, and how big they are, is what the properties data-size and data-offset
//     (data-position) of their nodes say -- the caller keeps those in the text of the tree, so an image that has not changed
//     size stays where it was. When one has, build() lays the images out again: in the order they had, each one at the next
//     multiple of `align` behind the one before.
//
// A hash node of an image (crc32, md5, sha1, sha256, sha384, sha512; U-Boot checks it before it boots the image) is made again
// by refresh_hashes() for the images that changed. abr signs nothing: a signature node (of an image or of a configuration) that
// covers an image that changed is named by stale_signatures(), for the caller to say so.
#pragma once

#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/fdt.hpp"

namespace abr::fit {

enum class Place { INLINE, OFFSET, POSITION };

const char* place_name(Place p);  // "inline", "offset", "position"
std::optional<Place> place_from_name(std::string_view name);

struct Layout {
    Place place = Place::INLINE;
    size_t align = 4;      // offset, position: what an image is placed at a multiple of when the layout is made again
    size_t end_align = 1;  // offset, position: the end of the file is padded with zeros up to a multiple of this (1: it is not)
    size_t slack = 0;      // the zero bytes behind the strings block of the tree (fdt::Layout::slack)
    // offset, position: the tree is padded with zeros up to a multiple of this -- what mkimage -E does with its -B, so that the
    // first image, which comes right behind the tree, is aligned -- and `slack` is not used; 0: `slack` bytes, however big the tree is.
    size_t tree_align = 0;
};

struct Image {
    size_t index = 0;  // which child of /images it is
    std::string name;  // the name of its node
    std::string type;  // its `type` property ("kernel", "ramdisk", "flat_dt", ...), or empty
    Bytes data;        // what the image holds, as it is stored (compressed, if it is)
};

struct Opened {
    fdt::Tree tree;  // the images' `data` taken out (see above); the strings block is the one of the file
    Layout layout;
    size_t consumed = 0;  // how much of the file the FIT takes (the tree, the images, their padding); the rest is the caller's
    std::vector<Image> images;
};

// A file that starts with a flattened device tree that has an /images node with a node in it.
bool looks_like(const Bytes& file);

// The file as a tree and images; nullopt, with the reason in `why`, for one that is not a FIT in the layout described above (a
// tree that is not laid out as dtc writes one, images that overlap, bytes that are not zero between them, two images of one
// name, a property that is not a number where one is read, ...) or that would not come back as it is.
std::optional<Opened> open(const Bytes& file, std::string& why);

// The file of a tree and a layout. The `data` of every image has its bytes (not an /incbin/). For an offset or position
// place the properties data-size and data-offset (data-position) of the images are written -- the ones that are in the tree
// are kept where they are and given the numbers; new ones are put first in their node, as mkimage does. FormatError for a
// tree that cannot be written: data that is not resolved, images that overlap, a position that is inside the tree, a number
// that does not fit in 32 bits.
Bytes build(fdt::Tree tree, const Layout& layout);

// The digest of `data` that the hash node of the algorithm `algo` holds (crc32 is its four bytes, big endian); nullopt for an
// algorithm that abr does not know.
std::optional<Bytes> hash_value(std::string_view algo, const Bytes& data);

// Gives every hash node of the images `which` (indices of the children of /images; the `data` of each has its bytes) the
// digest of the image. A node without `value` gets one (first in the node, as mkimage does); a node whose algorithm abr does
// not know, or that has none, is left alone and named in `notes`. Returns how many nodes it set.
size_t refresh_hashes(fdt::Tree& tree, const std::vector<size_t>& which, std::vector<std::string>& notes);

// The hash nodes of the images whose `value` is not the digest of the data, one line each (an algorithm that abr does not know is
// not checked). `images` are the ones open() gave, for the tree it gave.
std::vector<std::string> wrong_hashes(const fdt::Tree& tree, const std::vector<Image>& images);

// Every signature node of the tree (a node whose name starts with "signature" in an image or a configuration), as its path.
std::vector<std::string> signatures(const fdt::Tree& tree);

// The signature nodes that the images `changed` (the names of their nodes) make wrong: those of the images themselves and
// those of the configurations that name one of them.
std::vector<std::string> stale_signatures(const fdt::Tree& tree, const std::set<std::string>& changed);

// For `abr info`: one line about an image node, and one about each configuration.
std::string describe_image(const fdt::Node& image);
std::vector<std::string> describe_configurations(const fdt::Tree& tree);

}  // namespace abr::fit
