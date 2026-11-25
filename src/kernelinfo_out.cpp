// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::kernelinfo -- the report as text and as files (the searches are in kernelinfo.cpp). See kernelinfo.hpp.
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>

#include "abr/kernelinfo.hpp"
#include "abr/ramdisk_tree.hpp"

namespace abr::kernelinfo {

namespace fs = std::filesystem;

namespace {

constexpr const char* kReadmeFirstLine = "abr kernel_info -- what abr learned from the kernel of this image";

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

std::string hex_bare(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "%llx", static_cast<unsigned long long>(v));
    return b;
}

std::string bytes_text(uint64_t n) {
    std::string s = std::to_string(n) + " bytes";
    char b[32];
    if (n >= (uint64_t{1} << 20)) {
        std::snprintf(b, sizeof b, " (%.1f MiB)", static_cast<double>(n) / (1 << 20));
        s += b;
    } else if (n >= 4096) {
        std::snprintf(b, sizeof b, " (%.1f KiB)", static_cast<double>(n) / 1024);
        s += b;
    }
    return s;
}

// The text of a label of summary.txt, in a column: at least one blank follows it, however long it is.
constexpr size_t kLabelColumn = 20;  // the longest label of a header (relocatable_kernel, kernel_alignment) and two blanks

std::string left(std::string s, size_t width) {
    s.append(s.size() < width ? width - s.size() : 1, ' ');
    return s;
}

// A name for a file out of a piece of text: letters, digits and . _ - only, at most 40 of them.
std::string slug(const std::string& text) {
    std::string out;
    for (char c : text) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (ok) out.push_back(c);
        else if (!out.empty() && out.back() != '_') out.push_back('_');
        if (out.size() >= 40) break;
    }
    while (!out.empty() && (out.back() == '_' || out.back() == '.')) out.pop_back();
    while (!out.empty() && out.front() == '.') out.erase(out.begin());
    return out;
}

std::string two(size_t i) {
    std::string s = std::to_string(i);
    if (s.size() < 2) s.insert(0, 2 - s.size(), '0');
    return s;
}

// The file names, one rule for the text and for the folder.
std::string initramfs_name(size_t i) { return i == 0 ? "initramfs" : "initramfs" + std::to_string(i + 1); }

std::string certificate_file(size_t i, const Certificate& c) {
    std::string name = c.subject;
    if (const size_t cn = name.find("CN="); cn != std::string::npos) {
        name = name.substr(cn + 3);
        if (const size_t end = name.find(", "); end != std::string::npos) name.resize(end);  // the value of CN, not the names that follow it
    }
    std::string s = slug(name.empty() ? c.label : name);
    if (s.empty()) s = "cert";
    return "certs/" + two(i) + "-" + s;
}

std::string embedded_file(size_t i, const Embedded& e) {
    std::string name = "binaries/" + two(i) + "_" + e.kind + "_" + hex_bare(e.offset);
    if (e.codec != Codec::NONE) name += "_from_" + std::string(codec_name(e.codec));
    return name;
}

std::string embedded_extension(const Embedded& e) {
    if (e.kind == "elf") return "elf";
    if (e.kind == "dtb") return "dtb";
    if (e.kind == "text") return "txt";
    return "bin";
}

}  // namespace

std::string Certificate::describe() const {
    std::ostringstream o;
    if (subject.empty() && issuer.empty()) {
        o << (pem ? "PEM block " : "") << label << ", " << size << " bytes\n";
        if (label.find("PRIVATE") != std::string::npos) o << "this is a private key\n";
        if (!der.empty()) o << "DER of " << der.size() << " bytes\n";
        return o.str();
    }
    o << "subject:    " << subject << "\n";
    o << "issuer:     " << issuer << (issuer == subject ? "  (self-signed)" : "") << "\n";
    o << "serial:     " << serial << "\n";
    o << "valid:      " << not_before << " to " << not_after << "\n";
    o << "signature:  " << signature_algorithm << "\n";
    if (!public_key.empty()) o << "key:        " << public_key << "\n";
    o << "sha256:     " << sha256 << "\n";
    return o.str();
}

std::string readme() {
    std::ostringstream o;
    o << kReadmeFirstLine << "\n\n"
      << "This folder is information only. `abr pack` never reads it: what goes back into the image is the `kernel` file\n"
      << "(and `kernel_dtb/`) next to it, so nothing in here has to be kept, and a change to a file in here changes nothing.\n"
      << "A kernel is not built from its symbols or its configuration; to change the kernel, change `kernel`.\n\n"
      << "  summary.txt     everything that was found, in one text: the kind of image, its header, the version, the build, where things are\n"
      << "  config          the build configuration the kernel carries (/proc/config.gz), as the .config text\n"
      << "  kallsyms.txt    the kernel's symbol table, as /proc/kallsyms prints it\n"
      << "  payload.bin     the kernel inside a zImage or a bzImage (they keep it compressed)\n"
      << "  initramfs.cpio  the initramfs linked into the kernel, and initramfs/ + initramfs.meta: the same as a folder\n"
      << "  certs/          the certificates and keys the kernel holds (.der or .pem) and what they are (.txt)\n"
      << "  binaries/       the other files that lie inside the kernel: device trees (.dtb and .dts), ELF files, compressed streams (decompressed)\n\n"
      << "abr unpacks again over this folder: it is replaced (only a folder that begins with this text is, never one that is somebody's).\n"
      << "`abr unpack --no-kernel-info` leaves it out.\n";
    return o.str();
}

bool is_ours(const fs::path& dir) {
    std::ifstream f(dir / "README.txt", std::ios::binary);
    if (!f) return false;
    std::string line;
    std::getline(f, line);
    return line == kReadmeFirstLine;
}

std::string summary(const Report& r) {
    std::ostringstream o;
    o << kReadmeFirstLine << "\n";
    o << "(offsets are those of " << (r.payload ? "payload.bin, the kernel inside the image" : "the kernel file") << ")\n\n";

    o << "IMAGE\n";
    o << "  " << left("kind", kLabelColumn) << kind_name(r.kind) << ", " << bytes_text(r.size) << "\n";
    for (const std::string& c : r.container) o << "  " << left("in the image", kLabelColumn) << c << "\n";
    for (const Field& f : r.header) o << "  " << left(f.name, kLabelColumn) << f.value << "\n";
    if (r.payload) {
        o << "  " << left("kernel inside", kLabelColumn) << codec_name(r.payload->codec) << " stream at " << hex(r.payload->offset) << ", " << bytes_text(r.payload->stored)
          << "; it is payload.bin, " << bytes_text(r.payload->plain.size()) << "\n";
    }

    o << "\nVERSION\n";
    if (r.banners.empty()) {
        o << "  no \"Linux version\" banner found\n";
    } else {
        const Banner& b = r.banners[0];
        o << "  " << left("release", kLabelColumn) << b.release << "\n";
        if (!b.builder.empty()) o << "  " << left("built by", kLabelColumn) << b.builder << "\n";
        if (!b.compiler.empty()) o << "  " << left("compiler", kLabelColumn) << b.compiler << "\n";
        if (!b.build.empty()) o << "  " << left("build", kLabelColumn) << b.build << "\n";
        if (!r.vermagic.empty()) o << "  " << left("vermagic", kLabelColumn) << r.vermagic << "   (what a module has to say to be loaded)\n";
        for (size_t i = 0; i < r.banners.size(); ++i) o << "  " << left(i == 0 ? "banner" : "another banner", kLabelColumn) << "at " << hex(r.banners[i].offset) << ": " << r.banners[i].text << "\n";
    }
    for (const std::string& c : r.compilers) o << "  " << left("compiler string", kLabelColumn) << c << "\n";
    if (!r.androidboot.empty()) {
        o << "  " << left("androidboot", kLabelColumn) << "parameters that the kernel looks for in the command line:\n";
        for (const std::string& a : r.androidboot) o << "      " << a << "\n";
    }

    o << "\nCONFIGURATION (config)\n";
    if (!r.config) {
        o << "  none found: no \"IKCFG_ST\" and gzip stream (the kernel was built without CONFIG_IKCONFIG)\n";
    } else {
        const Config& c = *r.config;
        if (!c.title.empty()) o << "  " << c.title << "\n";
        o << "  gzip stream at " << hex(c.offset) << ", " << bytes_text(c.stored) << "; " << (c.yes + c.modules + c.no + c.value) << " options: " << c.yes << " =y, "
          << c.modules << " =m, " << c.value << " with a value, " << c.no << " not set\n";
        for (const Field& f : c.notable) o << "  " << f.name << "=" << f.value << "\n";
    }

    o << "\nSYMBOLS (kallsyms.txt)\n";
    if (!r.kallsyms) {
        o << "  none found: no symbol table (kernel built without CONFIG_KALLSYMS, or one that has too few symbols to be told from other data)\n";
    } else {
        const kallsyms::Table& t = *r.kallsyms;
        o << "  " << t.symbols.size() << " symbols; " << (t.big_endian ? "big" : "little") << " endian, " << t.address_size * 8 << "-bit addresses; ";
        switch (t.layout) {
            case kallsyms::Layout::Absolute: o << "the address of every symbol (kallsyms_addresses)\n"; break;
            case kallsyms::Layout::Relative: o << "offsets from the base " << hex(t.relative_base) << " (kallsyms_offsets)\n"; break;
            case kallsyms::Layout::RelativePercpu: o << "offsets from the base " << hex(t.relative_base) << ", per-CPU symbols absolute (kallsyms_offsets, x86-64)\n"; break;
        }
        o << "  names at " << hex(t.names_at) << ".." << hex(t.names_end) << ", markers at " << hex(t.markers_at) << ", token table at " << hex(t.token_table_at) << ", addresses at "
          << hex(t.addresses_at) << "\n";
        size_t text = 0, data = 0, other = 0;
        for (const kallsyms::Symbol& s : t.symbols) {
            const char c = static_cast<char>(s.type | 0x20);
            if (c == 't') ++text;
            else if (c == 'd' || c == 'b' || c == 'r' || c == 'a' || c == 'g' || c == 's' || c == 'v' || c == 'w') ++data;
            else ++other;
        }
        o << "  " << text << " of text (T t), " << data << " of data and other kinds, " << other << " not told\n";
        for (const char* name : {"_text", "_stext", "_etext", "_end", "linux_banner"})
            for (const kallsyms::Symbol& s : t.symbols)
                if (s.name == name) {
                    o << "  " << left(name, 14) << hex(s.address) << "\n";
                    break;
                }
    }

    o << "\nINITRAMFS\n";
    if (r.initramfs.empty()) {
        o << "  none found\n";
    } else {
        for (size_t i = 0; i < r.initramfs.size(); ++i) {
            const Initramfs& x = r.initramfs[i];
            o << "  at " << hex(x.offset) << ": " << (x.codec == Codec::NONE ? std::string("cpio archive") : std::string(codec_name(x.codec)) + " stream that holds a cpio archive") << ", "
              << bytes_text(x.stored) << ", " << x.entries << " entries -> " << initramfs_name(i) << ".cpio\n";
        }
    }

    o << "\nCERTIFICATES AND KEYS (certs/)\n";
    if (r.certificates.empty()) {
        o << "  none found\n";
    } else {
        for (size_t i = 0; i < r.certificates.size(); ++i) {
            const Certificate& c = r.certificates[i];
            o << "  at " << hex(c.offset) << ": " << (c.pem ? "PEM " : "DER ") << c.label << ", " << c.size << " bytes -> " << certificate_file(i, c) << (c.pem ? ".pem" : ".der") << "\n";
            std::istringstream lines(c.describe());
            for (std::string line; std::getline(lines, line);) o << "      " << line << "\n";
        }
    }

    o << "\nFILES INSIDE THE KERNEL (binaries/)\n";
    if (r.embedded.empty()) {
        o << "  none found\n";
    } else {
        for (size_t i = 0; i < r.embedded.size(); ++i) {
            const Embedded& e = r.embedded[i];
            o << "  at " << hex(e.offset) << ", " << bytes_text(e.stored) << ": " << e.what << " -> " << embedded_file(i, e) << "." << embedded_extension(e) << "\n";
        }
    }

    if (r.tail) o << "\nBEHIND THE END OF THE IMAGE\n  at " << hex(r.tail->offset) << ": " << bytes_text(r.tail->size) << ", " << r.tail->what << "\n";
    return o.str();
}

std::string one_line(const Report& r) {
    std::string s;
    if (!r.banners.empty() && !r.banners[0].release.empty()) s = "Linux " + r.banners[0].release + " (" + kind_name(r.kind) + ")";
    else s = kind_name(r.kind);
    std::vector<std::string> parts;
    if (r.config) parts.push_back("config of " + std::to_string(r.config->yes + r.config->modules + r.config->no + r.config->value) + " options");
    if (r.kallsyms) parts.push_back(std::to_string(r.kallsyms->symbols.size()) + " symbols");
    if (!r.initramfs.empty()) parts.push_back(std::to_string(r.initramfs.size()) + " initramfs");
    if (!r.certificates.empty()) parts.push_back(std::to_string(r.certificates.size()) + (r.certificates.size() == 1 ? " certificate" : " certificates"));
    if (!r.embedded.empty()) parts.push_back(std::to_string(r.embedded.size()) + (r.embedded.size() == 1 ? " embedded file" : " embedded files"));
    for (size_t i = 0; i < parts.size(); ++i) s += (i == 0 ? ": " : ", ") + parts[i];
    return s;
}

std::vector<std::string> write(const Report& r, const fs::path& dir) {
    fs::create_directories(dir);
    std::vector<std::string> written;
    const auto put = [&](const std::string& name, const uint8_t* data, size_t size) {
        const fs::path path = dir / fs::path(name);
        fs::create_directories(path.parent_path());
        write_file(path, data, size);
        written.push_back(name);
    };
    const auto put_text = [&](const std::string& name, const std::string& text) { put(name, reinterpret_cast<const uint8_t*>(text.data()), text.size()); };
    const auto put_bytes = [&](const std::string& name, const Bytes& b) { put(name, b.data(), b.size()); };

    put_text("README.txt", readme());
    put_text("summary.txt", summary(r));
    if (r.config) put_text("config", r.config->text);
    if (r.kallsyms) put_text("kallsyms.txt", kallsyms::format(*r.kallsyms));
    if (r.payload) put_bytes("payload.bin", r.payload->plain);
    for (size_t i = 0; i < r.initramfs.size(); ++i) {
        const std::string name = initramfs_name(i);
        put_bytes(name + ".cpio", r.initramfs[i].plain);
        try {
            const RamdiskTree t = extract_ramdisk_tree(r.initramfs[i].plain, dir, name);
            if (t.created) {
                written.push_back(name + "/");
                written.push_back(name + ".meta");
            }
        } catch (const std::exception&) {
            // an archive that cannot be a folder stays the file
        }
    }
    for (size_t i = 0; i < r.certificates.size(); ++i) {
        const Certificate& c = r.certificates[i];
        const std::string base = certificate_file(i, c);
        if (c.pem) put_text(base + ".pem", c.pem_text + "\n");
        else put_bytes(base + ".der", c.der);
        put_text(base + ".txt", "offset " + hex(c.offset) + ", " + std::to_string(c.size) + " bytes\n" + c.describe());
    }
    for (size_t i = 0; i < r.embedded.size(); ++i) {
        const Embedded& e = r.embedded[i];
        const std::string base = embedded_file(i, e);
        put_bytes(base + "." + embedded_extension(e), e.data);
        if (!e.text.empty()) put_text(base + ".dts", e.text);
    }
    return written;
}

}  // namespace abr::kernelinfo
