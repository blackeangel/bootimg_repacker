// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/legacy/elf_boot.hpp"

#include <algorithm>
#include <cstring>

namespace abr::legacy {

namespace {
constexpr size_t kEhdr32Size = 52;
constexpr size_t kEhdr64Size = 64;
constexpr size_t kPhdr32Size = 32;
constexpr size_t kPhdr64Size = 56;
constexpr uint32_t kPtLoad = 1;
constexpr uint32_t kPtNote = 4;

std::string role_for_flags(uint32_t flags, bool& recognized) {
    recognized = true;
    switch (flags) {
        case kElfFlagsRamdisk: return "ramdisk";
        case kElfFlagsIpl: return "ipl";
        case kElfFlagsCmdline: return "cmdline";
        case kElfFlagsRpm: return "rpm";
        default: recognized = false; return "";
    }
}
}  // namespace

bool ElfBootImage::looks_like(const Bytes& data) {
    if (data.size() < 20 || !std::equal(kElfMagic, kElfMagic + 4, data.begin())) return false;
    uint8_t ei_class = data[4];
    uint8_t ei_data = data[5];
    return (ei_class == 1 || ei_class == 2) && ei_data == 1;  // ELFCLASS32/64, ELFDATA2LSB
}

ElfBootImage ElfBootImage::parse(const Bytes& data) {
    if (!looks_like(data)) throw FormatError("not an ELF boot image (bad magic/class/endianness)");

    BinaryReader r(data);
    r.skip(4);
    uint8_t ei_class = r.u8();
    r.skip(11);  // EI_DATA, EI_VERSION, EI_OSABI, EI_ABIVERSION, EI_PAD[7]

    ElfBootImage img;
    img.is_64bit = (ei_class == 2);

    r.le16();  // e_type
    img.machine = r.le16();
    r.le32();  // e_version
    uint64_t e_phoff;
    uint16_t e_phentsize, e_phnum;
    if (img.is_64bit) {
        r.le64();  // e_entry
        e_phoff = r.le64();
        r.le64();          // e_shoff
        r.le32();          // e_flags
        r.le16();          // e_ehsize
        e_phentsize = r.le16();
        e_phnum = r.le16();
    } else {
        r.le32();  // e_entry
        e_phoff = r.le32();
        r.le32();          // e_shoff
        r.le32();          // e_flags
        r.le16();          // e_ehsize
        e_phentsize = r.le16();
        e_phnum = r.le16();
    }
    // e_shentsize/e_shnum/e_shstrndx follow but aren't needed: this
    // format has no section headers in every known real-world case.

    bool have_kernel = false, have_ramdisk = false;
    int extra_index = 0;
    for (uint16_t i = 0; i < e_phnum; ++i) {
        BinaryReader pr(data);
        pr.seek(static_cast<size_t>(e_phoff) + static_cast<size_t>(i) * e_phentsize);
        ElfSegment seg;
        uint64_t p_offset, p_vaddr, p_filesz;
        if (img.is_64bit) {
            pr.le32();  // p_type
            seg.flags = pr.le32();
            p_offset = pr.le64();
            p_vaddr = pr.le64();
            pr.le64();  // p_paddr
            p_filesz = pr.le64();
        } else {
            pr.le32();  // p_type
            p_offset = pr.le32();
            p_vaddr = pr.le32();
            pr.le32();  // p_paddr
            p_filesz = pr.le32();
            pr.le32();  // p_memsz
            seg.flags = pr.le32();
        }
        seg.addr = static_cast<uint32_t>(p_vaddr);
        if (p_offset + p_filesz > data.size())
            throw FormatError("ELF boot segment " + std::to_string(i) + " runs past the file end");
        seg.data.assign(data.begin() + static_cast<long>(p_offset),
                         data.begin() + static_cast<long>(p_offset + p_filesz));

        bool recognized;
        std::string name = role_for_flags(seg.flags, recognized);
        if (!recognized) {
            if (!have_kernel) { name = "kernel"; have_kernel = true; }
            else if (!have_ramdisk) { name = "ramdisk"; have_ramdisk = true; }
            else { name = "extra" + std::to_string(extra_index++); }
        }
        seg.role = name;
        img.segments.push_back(std::move(seg));
    }
    return img;
}

Bytes ElfBootImage::build() const {
    size_t ehdr_size = is_64bit ? kEhdr64Size : kEhdr32Size;
    size_t phdr_size = is_64bit ? kPhdr64Size : kPhdr32Size;
    size_t phoff = ehdr_size;

    uint32_t entry = 0;
    for (auto& s : segments)
        if (s.role == "kernel") { entry = s.addr; break; }

    BinaryWriter w;
    w.bytes(kElfMagic, 4);
    w.u8(is_64bit ? 2 : 1);  // EI_CLASS
    w.u8(1);                 // EI_DATA = LSB
    w.u8(1);                 // EI_VERSION
    w.u8(0x61);              // EI_OSABI: the Android-boot marker every known packer uses
    w.zeros(8);              // EI_ABIVERSION + EI_PAD
    w.le16(2);               // e_type = ET_EXEC
    w.le16(machine);
    w.le32(1);                // e_version
    if (is_64bit) {
        w.le64(entry);
        w.le64(phoff);
        w.le64(0);  // e_shoff
        w.le32(0);  // e_flags
        w.le16(static_cast<uint16_t>(ehdr_size));
        w.le16(static_cast<uint16_t>(phdr_size));
        w.le16(static_cast<uint16_t>(segments.size()));
        w.le16(0);  // e_shentsize
        w.le16(0);  // e_shnum
        w.le16(0);  // e_shstrndx
    } else {
        w.le32(entry);
        w.le32(static_cast<uint32_t>(phoff));
        w.le32(0);
        w.le32(0);
        w.le16(static_cast<uint16_t>(ehdr_size));
        w.le16(static_cast<uint16_t>(phdr_size));
        w.le16(static_cast<uint16_t>(segments.size()));
        w.le16(0);
        w.le16(0);
        w.le16(0);
    }

    std::vector<uint64_t> offsets(segments.size());
    uint64_t cursor = kElfDataStartOffset;
    for (size_t i = 0; i < segments.size(); ++i) {
        offsets[i] = cursor;
        cursor += segments[i].data.size();
    }

    for (size_t i = 0; i < segments.size(); ++i) {
        const auto& s = segments[i];
        uint32_t p_type = (s.role == "cmdline") ? kPtNote : kPtLoad;
        if (is_64bit) {
            w.le32(p_type);
            w.le32(s.flags);
            w.le64(offsets[i]);
            w.le64(s.addr);
            w.le64(s.addr);
            w.le64(s.data.size());
            w.le64(s.data.size());
            w.le64(0);  // p_align -- elftool never sets this, confirmed by diffing its real output
        } else {
            w.le32(p_type);
            w.le32(static_cast<uint32_t>(offsets[i]));
            w.le32(s.addr);
            w.le32(s.addr);
            w.le32(static_cast<uint32_t>(s.data.size()));
            w.le32(static_cast<uint32_t>(s.data.size()));
            w.le32(s.flags);
            w.le32(0);  // p_align -- ditto
        }
    }

    w.zeros(kElfDataStartOffset - w.size());
    for (auto& s : segments) w.bytes(s.data);
    return w.take();
}

}  // namespace abr::legacy
