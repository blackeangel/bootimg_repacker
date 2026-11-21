// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::dtfile -- one device tree in the folder of an unpack.
//
// A tree is unpacked as what a person can read and edit: its source, NAME.dts (abr/dts.hpp: the language of dtc), which `pack` compiles
// again. Where the source does not give the blob back byte for byte -- a blob that is laid out another way than dtc lays one out (the
// order of the strings, free space at the end, mkimage's bytes behind a value, a version of the format that dtc does not write), or
// whose text dtc's checks refuse (a node twice) -- the blob as it was is kept beside the folder's files, in .abr_raw/NAME.dts.raw, and goes
// back into the image for as long as the source is as it was unpacked. Edit the source and the tree is compiled from it, laid out the way
// dtc lays it out. A tree that has no source at all (abr cannot read it as a tree, or it has a name that a source cannot say) is the file
// NAME.dtb, and goes back as it is.
//
// The keys of the manifest, for the slot `P` of a tree (`blob0`, `entry3`, `dtb1`, ...):
//   P_file        the file of the tree: NAME.dts (a source), or any other name (a blob, which goes into the image as it is)
//   P_slack       how many zero bytes of free space the tree has behind its strings (a blob that was made with room to grow, as a FIT's trees are
//                 by U-Boot's libfdt, or dtbTool's): a source is compiled with that much, so that it gives the blob back without a raw copy
//   P_text_hash   SHA-256 of the source as unpack wrote it: a source that has it is as it was unpacked, one that has another was edited
//   P_raw_hash    SHA-256 of the blob in .abr_raw/NAME.dts.raw, when there is one (that file is believed only if it has this hash)
#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/manifest.hpp"

namespace abr::dtfile {

// What there is to write for one blob. prepare() does the work (reading the blob as a tree, writing its source, compiling the source to see
// whether it gives the blob back) and may run on any thread; commit() writes the files and the keys.
struct Prepared {
    bool text = false;      // the tree has a source (`source`); else it is a file of the blob only
    std::string source;     // the text, when `text`
    size_t slack = 0;       // the blob has this many zero bytes behind its strings (a tree that was made with room to grow): `<prefix>_slack`
    bool keep_raw = false;  // the source does not give the blob back: the blob is kept in .abr_raw too
    std::string note;       // what a person is told about it (empty when there is nothing to tell), without the name of the file
};
Prepared prepare(const Bytes& blob);

// The source is the file `file` of the folder (a relative name that ends in .dts, "dtb/entry0.dts"); a tree without a source is the
// file of the same name that ends in .dtb. Sets `<prefix>_file` and what goes with it (see above).
void commit(Manifest& m, const std::filesystem::path& dir, const std::string& prefix, const std::string& file, const Prepared& p,
            const Bytes& blob);

// The name that commit() gives the file of a tree: `file` as it is when the tree has a source, else with .dtb for .dts.
std::string file_name(const std::string& file, const Prepared& p);

struct Loaded {
    Bytes blob;
    std::vector<std::string> warnings;  // what the compiler says and goes on (a value that does not fit its cell and is cut)
    std::string note;                   // what a person is told (empty: nothing)
    bool edited = false;                // the source is not the one that was unpacked (a file of a blob is never said to be: abr cannot tell)
};

// The blob of the slot `prefix`: the file of `<prefix>_file`, which is a blob as it is, or a source that is compiled (an /include/ or an
// /incbin/ in it is read from the folder of the source, and not from outside the unpacked folder) -- or, for a source that is as it was
// unpacked and has a raw copy, the blob that the copy holds. FormatError, naming the file, for what cannot be: a file that is not there, a
// source with an error (the line is said), a raw copy that does not belong to the source. Reads the manifest and the folder and changes
// nothing, so it may run on several threads.
//
// `must_be_tree`: a file that is not a source has to be a device tree (check_fdt_blob()); not where any bytes are the content of the slot (the data
// of an entry of a dtbo table, which may be an ACPI table).
Loaded load(const Manifest& m, const std::filesystem::path& dir, const std::string& prefix, bool must_be_tree = true);

// The blob of a source: what dtc makes of `text` (named `name` in the messages), the free space of `slack` zero bytes behind its strings. An
// /include/ or an /incbin/ in it is read from `folder` (and not from outside it). FormatError with the line, for a text that dtc refuses.
// `warnings`: what the compiler says and goes on with (may be null).
Bytes compile(const Bytes& text, const std::string& name, const std::filesystem::path& folder, size_t slack = 0,
              std::vector<std::string>* warnings = nullptr);

// Is `name` the name of a source (it ends in .dts, in any case)?
bool is_source_name(const std::string& name);

}  // namespace abr::dtfile
