// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::kernelinfo -- everything that can be learned from a kernel, written as files a person can read.
//
// The kernel of a boot image is a flat binary that carries a good deal about itself: the symbol table that /proc/kallsyms prints, the
// build configuration (CONFIG_IKCONFIG: /proc/config.gz), the banner that `uname -v` and the oops messages print, the initramfs that
// is linked in, the X.509 certificates that the kernel trusts, device trees, the ELF of the vDSO and other files that are linked into
// its sections. `abr unpack` writes all of it to the folder `kernel_info/`, next to the kernel:
//
//     kernel_info/
//       README.txt        what the folder is (also: the sign that abr made it, and may replace it when it unpacks again)
//       summary.txt       everything in one text: the kind of image, its header, the version, the build, what was found and where
//       config            the build configuration, as text (the .config the kernel was built with)
//       kallsyms.txt      the symbol table, as /proc/kallsyms prints it: address, type, name
//       payload.bin       the kernel inside a zImage or a bzImage (they hold it compressed, for a stub to unpack at boot)
//       initramfs.cpio    the initramfs linked into the kernel (decompressed), and initramfs/ + initramfs.meta: the same as a folder
//       certs/            the certificates and keys the kernel holds: NN-name.der (or .pem), with NN-name.txt that says what they are
//       binaries/         what else lies inside: device trees (.dtb and .dts), ELF files, compressed streams (decompressed)
//
// The folder is information only. `pack` never reads it: what goes back into the image is the `kernel` file (and `kernel_dtb/`), as
// before, and a folder that is edited, deleted or left behind changes nothing. A kernel is not rebuilt from its symbols.
//
// The offsets in the files are those of the image that was searched: of `kernel`, or -- for a zImage and a bzImage, whose kernel is a
// compressed stream inside them -- of payload.bin.
//
// How the pieces are found. A kernel has no table of contents, so each piece is looked for by what it is:
//   * the banner: "Linux version " followed by a digit; the vermagic is the string that begins with the release of the banner and is
//     followed by the flags (` SMP preempt mod_unload aarch64`);
//   * the configuration: "IKCFG_ST", a gzip stream, "IKCFG_ED";
//   * the symbols: kallsyms.hpp, which finds the six tables by their structure;
//   * the initramfs: a cpio archive (newc, 110 bytes of hexadecimal header that really are hexadecimal and a trailer that is there), or a
//     compressed stream that holds one;
//   * the certificates: a DER SEQUENCE that has the structure of X.509 (a tbsCertificate of version, serial, algorithm, issuer, validity,
//     subject, key; the algorithm again; the signature) -- and PEM blocks in the text;
//   * the embedded files: an ELF header whose tables fit inside the image, a device tree whose header holds together (kernel.hpp), and a
//     stream of any of the codecs (gzip, xz, bzip2, zstd, lz4, lzop) that really decompresses, to its end, with the checksum it has.
// Nothing is taken on its magic alone, and nothing here guesses: what is not proved is not reported. Never throws, whatever the bytes are.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "abr/byte_io.hpp"
#include "abr/compression.hpp"
#include "abr/kallsyms.hpp"

namespace abr::kernelinfo {

// What the image is.
enum class Kind {
    Unknown,     // no header that abr knows: a flat binary (or something else); everything else is looked for all the same
    Arm64Image,  // arch/arm64/boot/Image (the header of Documentation/arm64/booting.rst)
    ArmZImage,   // arch/arm/boot/zImage: a decompressor stub and the kernel as a compressed stream behind it
    X86BzImage,  // arch/x86/boot/bzImage: the boot protocol header (HdrS), the setup code and the compressed kernel
    RiscvImage,  // arch/riscv/boot/Image
    Elf,         // vmlinux
};
const char* kind_name(Kind kind);

// One line of what the header says: "text_offset", "0x80000".
struct Field {
    std::string name;
    std::string value;
};

// The kernel inside a zImage or a bzImage.
struct Payload {
    size_t offset = 0;      // of the stream in the image
    size_t stored = 0;      // its size there
    Codec codec = Codec::NONE;
    Bytes plain;            // the kernel inside, decompressed; the rest of the report is about these bytes
};

// "Linux version 5.4.125 (builder@host) (compiler) #1 SMP PREEMPT Fri Aug 6 ..." and its parts.
struct Banner {
    size_t offset = 0;
    std::string text;       // as written, without the line feed and the NUL
    std::string release;    // "5.4.125"
    std::string builder;    // "builder@host"
    std::string compiler;   // "Android (6443078 based on r383902) clang version 11.0.1 (...), LLD 11.0.1 (...)"
    std::string build;      // "#1 SMP PREEMPT Fri Aug  6 11:22:29 UTC 2021"
};

// The configuration the kernel was built with: /proc/config.gz.
struct Config {
    size_t offset = 0;      // of the gzip stream
    size_t stored = 0;      // its size
    std::string text;       // the .config
    size_t yes = 0, modules = 0, no = 0, value = 0;  // `=y`, `=m`, `# ... is not set`, and the options with a number or a string
    // The few options a person looks for first, as they are written ("CONFIG_LOCALVERSION", "\"-perf\""), in the order of the file.
    std::vector<Field> notable;
    std::string title;      // the first line that says what the file is: "# Linux/arm64 5.4.125 Kernel Configuration"
};

// The initramfs that is linked into the kernel.
struct Initramfs {
    size_t offset = 0;
    size_t stored = 0;      // the bytes it takes in the image (the archive, or the compressed stream that holds it)
    Codec codec = Codec::NONE;
    Bytes plain;            // the cpio archive
    size_t entries = 0;     // files, directories, links and nodes in it
};

// An X.509 certificate, or the other things that are in a kernel as PEM (keys).
struct Certificate {
    size_t offset = 0;
    size_t size = 0;
    bool pem = false;       // found as a PEM block (the text is `pem_text`), else as DER
    std::string label;      // PEM: "CERTIFICATE", "PUBLIC KEY", "RSA PRIVATE KEY" ...; DER: "CERTIFICATE"
    Bytes der;              // the certificate (or key) as DER
    std::string pem_text;   // PEM: the block as it is written in the image
    // What a person reads about a certificate (empty for a key that is not one):
    std::string subject, issuer, serial, not_before, not_after, signature_algorithm, public_key, sha256;
    std::string describe() const;  // all of it as text
};

// A file inside the kernel: a device tree, an ELF, a stream (what is written is what it holds, decompressed).
struct Embedded {
    std::string kind;       // "dtb", "elf", "gzip" ... (what the data is, or the codec of the stream: see `holds`)
    std::string what;       // a line for a person: "ELF 64-bit little endian shared object, AArch64, the vDSO"
    size_t offset = 0;
    size_t stored = 0;      // the bytes it takes in the image
    Codec codec = Codec::NONE;  // a stream: how it was compressed (`data` is what came out)
    Bytes data;
    std::string text;       // a device tree's source; empty for the others
};

// What lies behind the end that the header of the image names (arm64 `image_size`, zImage `end`).
struct Tail {
    size_t offset = 0;
    size_t size = 0;
    std::string what;       // "all zeros", "the text SEANDROIDENFORCE", "a device tree", ...
};

struct Report {
    Kind kind = Kind::Unknown;
    size_t size = 0;                   // of the bytes that were looked at
    std::vector<Field> header;         // what the header of the image says
    std::optional<Payload> payload;    // the kernel inside, when there is one (zImage, bzImage)
    std::vector<Banner> banners;       // the first is the one the kernel prints
    std::string vermagic;              // "5.4.125 SMP preempt mod_unload modversions aarch64": what a module has to say to be loaded
    std::vector<std::string> compilers;       // "GCC: (GNU) 4.9.x 20150123 (prerelease)" ...: strings of the compiler that are not in the banner
    std::vector<std::string> androidboot;     // the "androidboot.xxx=" parameters that the kernel looks for in the command line
    std::optional<Config> config;
    std::optional<kallsyms::Table> kallsyms;
    std::vector<Initramfs> initramfs;
    std::vector<Certificate> certificates;
    std::vector<Embedded> embedded;
    std::optional<Tail> tail;
    std::vector<std::string> container;  // set by the caller: what the field of the image that held the kernel was ("gzip stream ...")
};

// Everything that can be learned from `kernel`. Never throws. The searches run on several threads.
Report analyze(const Bytes& kernel);

// summary.txt: the report as text.
std::string summary(const Report& report);

// One line for the console: "Linux 5.4.125 (arm64 Image): config 1024 options, 66321 symbols, 1 certificate".
std::string one_line(const Report& report);

// The README of the folder; its first line is what abr looks for to know the folder is its own (is_ours()).
std::string readme();

// Writes the report into `dir` (created; what is in it is not removed: the caller removes the folder of an earlier unpack). The files
// are those listed at the top. Returns the names of the files written, relative to `dir`, in the order they were written.
std::vector<std::string> write(const Report& report, const std::filesystem::path& dir);

// Is `dir` a folder that abr wrote (its README begins with the line that readme() starts with)? A folder with that name that is not is
// somebody's, and is not touched.
bool is_ours(const std::filesystem::path& dir);

}  // namespace abr::kernelinfo
