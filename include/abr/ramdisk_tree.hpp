// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::ramdisk_tree -- a ramdisk (a cpio archive) as a directory you can edit.
//
// `unpack` writes the decompressed ramdisk as ramdisk.cpio, byte for byte what the image held, and
// -- when it can -- as a directory tree next to it, the way Android Image Kitchen does:
//
//     ramdisk.cpio       what the image held, decompressed
//     ramdisk/           the files
//     ramdisk.meta       what a directory cannot say: owner, mode, the order of the records ...
//     ramdisk.vol2/      only when the ramdisk is several cpio archives one after the other: every
//     ramdisk.vol2.meta  archive after the first is a directory and a metadata file of its own
//
// Several archives one after the other ("volumes") are legal: the kernel unpacks them in turn, each
// over the one before, and Magisk's cpio reads them the same way. Android boot images that were
// patched by one tool or another do have them. Each volume is kept apart, because that is the only
// way to build back what was there; to change a file of the first, edit ramdisk/, to put one over
// it, edit ramdisk.vol2/. Delete the directory of a volume and that archive is left out (delete all of
// them and ramdisk.cpio is what repack uses).
//
// The metadata is text: a few lines about the archive as a whole (its magic, the case of the hexadecimal
// digits, whether the names start with "./", the order, how inodes and link counts are numbered, the
// zero fill behind it, the defaults for what is new), then one line per entry:
//
//     type mode uid gid mtime extras path
//
//     d 0755 0 0 0 - system/bin          type: d directory, f file, l symbolic link, c/b device,
//     l 0777 0 0 0 - bin                       p fifo, s socket
//     c 0600 0 0 0 rdev=5:1 dev/console  extras: ino=, nlink=, dev=, rdev= or "-"
//
// It is what makes the tool work the same on every system: Windows cannot store an owner or a
// mode, cannot hold a device node, and links are a privilege there, so nothing is read from the file
// system about the entries that were unpacked -- the metadata is. A path that is missing from the tree
// has been deleted. A path that is not in the metadata is new and gets what the header of the file
// says (`default` for the owner and time, `newmode` for the permissions); the repack says which entries
// those were. By default that is 0644 for a file, 0755 for an executable one (a file with the
// executable bit where the system has one, an ELF program or a #! script -- which works on Windows too),
// 0755 for a directory and 0777 for a link. A line of its own in the metadata gives a new path whatever
// it should have.
//
// Symbolic links. On Linux and macOS a link in the tree is a link. Windows cannot make one without
// administrator rights, so there (and wherever the file system refuses links) it is a small file in the
// format Cygwin and MSYS2 use for theirs, which needs no right at all: "!<symlink>", the byte order mark
// FF FE, the target in UTF-16LE and two zero bytes, and on Windows the System attribute. A link is
// read back from any of them -- and from a plain text file holding only the target, when the
// metadata says the entry is a link -- wherever the tree has been carried since.
//
// Reading the tree back is the same process in reverse and is deterministic: the archive that
// pack_ramdisk_tree() builds from an unmodified tree is byte-identical to the one that was
// unpacked. unpack proves it (and says so when it cannot), and records the SHA-256 of what the
// tree builds, so that `repack` can tell "the tree was edited" from "it was not" without relying
// on file times.
//
// Not every archive can be a tree: ones with hard links, with the same name twice, with names the
// file system cannot hold, with something that is not a cpio archive after the first, anything that
// is not newc/crc. Those stay ramdisk.cpio only, and the reason is reported.
#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"

namespace abr {

struct RamdiskTree {
    bool created = false;   // the directories and the metadata files were written
    std::string reason;     // when not created: why. Empty if `plain` was not a cpio archive at all.
    Bytes rebuilt_sha256;   // SHA-256 of pack_ramdisk_tree() run on what was written
    bool exact = false;     // ... and that is the original, byte for byte
    std::string difference; // when it is not: what differs (for the message to the user)
    size_t entries = 0;     // files, directories and links written, in all the volumes
    size_t volumes = 0;     // how many archives one after the other the ramdisk is
};

// What pack_ramdisk_tree() has to say, for the user: `warnings` are things that probably are not
// what was meant, `notes` are things that are worth knowing. Each starts with the directory it is about.
// `built` names the directories (without the slash) the archives were made of, in the order of the archives.
struct PackReport {
    std::vector<std::string> warnings;
    std::vector<std::string> notes;
    std::vector<std::string> built;
};

// Where the volumes of the ramdisk called `prefix` live: the first one is `prefix`, the next ones
// `prefix.vol2`, `prefix.vol3` ...; the metadata of each is that name and ".meta". `index` counts from 0.
std::string ramdisk_volume_name(const std::string& prefix, size_t index);
std::string ramdisk_volume_meta(const std::string& prefix, size_t index);

// Writes `plain` (a decompressed ramdisk) as directories and metadata files in `dir`. Refuses (says why
// in `reason`) when one of them is there already and is not an empty directory: the caller removes
// what an earlier unpack left, this never deletes anything it did not write itself.
RamdiskTree extract_ramdisk_tree(const Bytes& plain, const std::filesystem::path& dir,
                                 const std::string& prefix);

// The cpio archive(s) for the ramdisk `prefix` in `dir`, made of `volumes` volumes. Without a
// metadata file everything is built like Android's mkbootfs does it (owner root, directories 0755,
// files 0644 or 0755 if executable, the records sorted, inodes counted from 300000), which is what a tree
// made by another tool needs. A volume whose directory is not there is left out (the report says so);
// when none is there, there is nothing to build and that is an error.
Bytes pack_ramdisk_tree(const std::filesystem::path& dir, const std::string& prefix, size_t volumes = 1,
                        PackReport* report = nullptr);

// The symbolic link file of Cygwin/MSYS2 (see above) for `target`, which must be UTF-8.
Bytes cygwin_link_file(const std::string& target);

// Reads such a file. Nothing is returned when `data` is not one (`error` stays empty), or when it is one
// that cannot be read (`error` says why). The target is UTF-8.
std::optional<std::string> read_cygwin_link_file(const Bytes& data, std::string& error);

}  // namespace abr
