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

// Little-endian fields at a position of a buffer; callers have checked that the position is inside.
uint64_t get_le(const Bytes& b, size_t pos, int width) {
    uint64_t v = 0;
    for (int i = width - 1; i >= 0; --i) v = (v << 8) | b[pos + static_cast<size_t>(i)];
    return v;
}
void put_le(Bytes& b, size_t pos, uint64_t v, int width) {
    for (int i = 0; i < width; ++i) b[pos + static_cast<size_t>(i)] = static_cast<uint8_t>(v >> (8 * i));
}
void append_le(Bytes& b, uint64_t v, int width) {
    for (int i = 0; i < width; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

// The fields of the ELF header that matter here, by class.
struct Ehdr {
    bool is64 = false;
    uint16_t machine = 0;
    uint64_t entry = 0, phoff = 0;
    uint16_t ehsize = 0, phentsize = 0, phnum = 0;
    size_t entry_pos = 0;  // where e_entry is, and its width
    int addr_width = 4;
};

Ehdr read_ehdr(const Bytes& d) {
    Ehdr e;
    e.is64 = d.size() > 4 && d[4] == 2;
    const size_t need = e.is64 ? kEhdr64Size : kEhdr32Size;
    if (d.size() < need) throw FormatError("ELF boot image: the ELF header is cut short");
    e.addr_width = e.is64 ? 8 : 4;
    e.machine = static_cast<uint16_t>(get_le(d, 18, 2));
    e.entry_pos = 24;
    e.entry = get_le(d, 24, e.addr_width);
    e.phoff = get_le(d, 24 + static_cast<size_t>(e.addr_width), e.addr_width);
    const size_t after = 24 + 3 * static_cast<size_t>(e.addr_width) + 4;  // e_entry, e_phoff, e_shoff, e_flags
    e.ehsize = static_cast<uint16_t>(get_le(d, after, 2));
    e.phentsize = static_cast<uint16_t>(get_le(d, after + 2, 2));
    e.phnum = static_cast<uint16_t>(get_le(d, after + 4, 2));
    return e;
}

struct Phdr {
    uint32_t type = 0, flags = 0;
    uint64_t offset = 0, vaddr = 0, paddr = 0, filesz = 0, memsz = 0, align = 0;
};

// Field positions of a program header (ELF32: type offset vaddr paddr filesz memsz flags align; ELF64: type flags
// offset vaddr paddr filesz memsz align).
Phdr read_phdr(const Bytes& d, size_t at, bool is64) {
    Phdr p;
    p.type = static_cast<uint32_t>(get_le(d, at, 4));
    if (is64) {
        p.flags = static_cast<uint32_t>(get_le(d, at + 4, 4));
        p.offset = get_le(d, at + 8, 8);
        p.vaddr = get_le(d, at + 16, 8);
        p.paddr = get_le(d, at + 24, 8);
        p.filesz = get_le(d, at + 32, 8);
        p.memsz = get_le(d, at + 40, 8);
        p.align = get_le(d, at + 48, 8);
    } else {
        p.offset = get_le(d, at + 4, 4);
        p.vaddr = get_le(d, at + 8, 4);
        p.paddr = get_le(d, at + 12, 4);
        p.filesz = get_le(d, at + 16, 4);
        p.memsz = get_le(d, at + 20, 4);
        p.flags = static_cast<uint32_t>(get_le(d, at + 24, 4));
        p.align = get_le(d, at + 28, 4);
    }
    return p;
}

void write_phdr(Bytes& d, size_t at, const Phdr& p, bool is64) {
    put_le(d, at, p.type, 4);
    if (is64) {
        put_le(d, at + 4, p.flags, 4);
        put_le(d, at + 8, p.offset, 8);
        put_le(d, at + 16, p.vaddr, 8);
        put_le(d, at + 24, p.paddr, 8);
        put_le(d, at + 32, p.filesz, 8);
        put_le(d, at + 40, p.memsz, 8);
        put_le(d, at + 48, p.align, 8);
    } else {
        put_le(d, at + 4, p.offset, 4);
        put_le(d, at + 8, p.vaddr, 4);
        put_le(d, at + 12, p.paddr, 4);
        put_le(d, at + 16, p.filesz, 4);
        put_le(d, at + 20, p.memsz, 4);
        put_le(d, at + 24, p.flags, 4);
        put_le(d, at + 28, p.align, 4);
    }
}

bool fits(uint64_t v, bool is64) { return is64 || v <= 0xFFFFFFFFull; }

// What the file holds that is not the data of a segment, if the segments can be taken out of it and put back:
// the data ranges must lie behind the header block and not overlap.
std::optional<ElfLayout> capture_layout(const Bytes& d, const Ehdr& e, const std::vector<Phdr>& ph) {
    struct Range {
        uint64_t start, end;
        uint32_t index;
    };
    std::vector<Range> ranges;
    for (uint32_t i = 0; i < ph.size(); ++i)
        if (ph[i].filesz > 0) ranges.push_back({ph[i].offset, ph[i].offset + ph[i].filesz, i});
    if (ranges.empty()) return std::nullopt;
    std::stable_sort(ranges.begin(), ranges.end(), [](const Range& a, const Range& b) { return a.start < b.start; });
    const uint64_t table_end = e.phoff + uint64_t(e.phnum) * e.phentsize;
    if (ranges[0].start < table_end || ranges[0].start < std::max<uint64_t>(e.ehsize, e.is64 ? kEhdr64Size : kEhdr32Size))
        return std::nullopt;
    for (size_t k = 1; k < ranges.size(); ++k)
        if (ranges[k].start < ranges[k - 1].end) return std::nullopt;
    if (ranges.back().end > d.size()) return std::nullopt;
    ElfLayout layout;
    layout.header.assign(d.begin(), d.begin() + static_cast<std::ptrdiff_t>(ranges[0].start));
    for (size_t k = 0; k < ranges.size(); ++k) {
        const uint64_t next = k + 1 < ranges.size() ? ranges[k + 1].start : d.size();
        layout.order.push_back(ranges[k].index);
        layout.after.emplace_back(d.begin() + static_cast<std::ptrdiff_t>(ranges[k].end),
                                  d.begin() + static_cast<std::ptrdiff_t>(next));
    }
    return layout;
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

    const Ehdr e = read_ehdr(data);
    ElfBootImage img;
    img.is_64bit = e.is64;
    img.machine = e.machine;

    const size_t phdr_min = e.is64 ? kPhdr64Size : kPhdr32Size;
    if (e.phnum > 0 && e.phentsize < phdr_min)
        throw FormatError("ELF boot image: the program headers are " + std::to_string(e.phentsize) + " bytes, " +
                          std::to_string(phdr_min) + " are needed");
    // (e_shoff and the section headers follow but aren't needed: this format has none in every known real-world case.)

    std::vector<Phdr> headers;
    bool have_kernel = false, have_ramdisk = false;
    int extra_index = 0;
    for (uint16_t i = 0; i < e.phnum; ++i) {
        const uint64_t at = e.phoff + uint64_t(i) * e.phentsize;
        if (at + phdr_min > data.size() || at + phdr_min < at)
            throw FormatError("ELF boot image: program header " + std::to_string(i) + " runs past the file end");
        const Phdr ph = read_phdr(data, static_cast<size_t>(at), e.is64);
        headers.push_back(ph);

        ElfSegment seg;
        seg.flags = ph.flags;
        seg.addr = ph.vaddr;
        if (ph.offset > data.size() || ph.filesz > data.size() - ph.offset)
            throw FormatError("ELF boot segment " + std::to_string(i) + " runs past the file end");
        seg.data.assign(data.begin() + static_cast<std::ptrdiff_t>(ph.offset),
                        data.begin() + static_cast<std::ptrdiff_t>(ph.offset + ph.filesz));

        bool recognized;
        std::string name = role_for_flags(seg.flags, recognized);
        if (recognized) {
            if (name == "ramdisk") have_ramdisk = true;  // a ramdisk found by its flags: no second one by position
        } else {
            if (!have_kernel) { name = "kernel"; have_kernel = true; }
            else if (!have_ramdisk) { name = "ramdisk"; have_ramdisk = true; }
            else { name = "extra" + std::to_string(extra_index++); }
        }
        seg.role = name;
        img.segments.push_back(std::move(seg));
    }
    if (img.segments.empty() ? e.entry != 0 : e.entry != img.segments[0].addr) img.entry = e.entry;

    // elftool's layout gives the file back (nearly every image): nothing more to keep. Otherwise what is around the
    // segments is kept -- if that gives the file back.
    if (img.build_elftool() == data) return img;
    img.layout = capture_layout(data, e, headers);
    if (img.layout && img.build() != data) img.layout.reset();
    return img;
}

Bytes ElfBootImage::build_elftool() const {
    const size_t ehdr_size = is_64bit ? kEhdr64Size : kEhdr32Size;
    const size_t phdr_size = is_64bit ? kPhdr64Size : kPhdr32Size;
    const int aw = is_64bit ? 8 : 4;
    const size_t phoff = ehdr_size;

    const uint64_t entry_addr = entry ? *entry : (segments.empty() ? 0 : segments[0].addr);
    if (!fits(entry_addr, is_64bit)) throw FormatError("ELF boot image: the entry address does not fit an ELF32 image (is_64bit=false)");
    for (size_t i = 0; i < segments.size(); ++i)
        if (!fits(segments[i].addr, is_64bit))
            throw FormatError("ELF boot image: the address of segment " + std::to_string(i) + " does not fit an ELF32 image (is_64bit=false)");

    Bytes w;
    w.insert(w.end(), kElfMagic, kElfMagic + 4);
    w.push_back(is_64bit ? 2 : 1);  // EI_CLASS
    w.push_back(1);                 // EI_DATA = LSB
    w.push_back(1);                 // EI_VERSION
    w.push_back(0x61);              // EI_OSABI: the Android-boot marker every known packer uses
    w.insert(w.end(), 8, 0);        // EI_ABIVERSION + EI_PAD
    append_le(w, 2, 2);             // e_type = ET_EXEC
    append_le(w, machine, 2);
    append_le(w, 1, 4);             // e_version
    append_le(w, entry_addr, aw);   // e_entry
    append_le(w, phoff, aw);        // e_phoff
    append_le(w, 0, aw);            // e_shoff
    append_le(w, 0, 4);             // e_flags
    append_le(w, ehdr_size, 2);
    append_le(w, phdr_size, 2);
    append_le(w, segments.size(), 2);
    append_le(w, 0, 2);  // e_shentsize
    append_le(w, 0, 2);  // e_shnum
    append_le(w, 0, 2);  // e_shstrndx

    // elftool writes the data from byte 4096 on (a table of more than 126 headers would not fit in front of it)
    uint64_t data_start = kElfDataStartOffset;
    const uint64_t table_end = phoff + uint64_t(segments.size()) * phdr_size;
    if (table_end > data_start) data_start = (table_end + 4095) / 4096 * 4096;

    uint64_t cursor = data_start;
    for (const ElfSegment& s : segments) {
        Phdr p;
        p.type = s.role == "cmdline" ? kPtNote : kPtLoad;
        p.flags = s.flags;
        p.offset = cursor;
        p.vaddr = p.paddr = s.addr;
        p.filesz = p.memsz = s.data.size();
        p.align = 0;  // elftool never sets this, confirmed by diffing its real output
        const size_t at = w.size();
        w.resize(at + phdr_size);
        write_phdr(w, at, p, is_64bit);
        cursor += s.data.size();
    }
    if (!fits(cursor, is_64bit)) throw FormatError("ELF boot image: more than an ELF32 image can hold (is_64bit=false)");
    w.resize(static_cast<size_t>(data_start), 0);
    for (const ElfSegment& s : segments) w.insert(w.end(), s.data.begin(), s.data.end());
    return w;
}

Bytes ElfBootImage::build(std::string* note) const {
    if (!layout) return build_elftool();
    auto fallback = [&](const std::string& why) {
        if (note) *note = why;
        return build_elftool();
    };
    const ElfLayout& L = *layout;
    const Bytes& h = L.header;
    if (h.size() < kEhdr32Size || std::memcmp(h.data(), kElfMagic, 4) != 0)
        return fallback("the layout kept for this image is damaged (no ELF header)");
    Ehdr e;
    try {
        e = read_ehdr(h);
    } catch (const FormatError&) {
        return fallback("the layout kept for this image is damaged (the ELF header is cut short)");
    }
    if (e.is64 != is_64bit) return fallback("the ELF class of the image is not the one of the layout kept for it");
    const size_t phdr_min = e.is64 ? kPhdr64Size : kPhdr32Size;
    if (e.phnum != segments.size())
        return fallback("the layout kept for this image has " + std::to_string(e.phnum) + " program headers, the image has " +
                        std::to_string(segments.size()) + " segments");
    if (e.phnum > 0 && (e.phentsize < phdr_min || e.phoff + uint64_t(e.phnum) * e.phentsize > h.size()))
        return fallback("the layout kept for this image is damaged (the program headers are not in its header block)");
    if (L.order.size() != L.after.size()) return fallback("the layout kept for this image is damaged");

    // where the data of each segment goes: in the order it had, each followed by what followed it
    std::vector<uint64_t> where(segments.size(), 0);
    std::vector<bool> placed(segments.size(), false);
    uint64_t cursor = h.size();
    for (size_t k = 0; k < L.order.size(); ++k) {
        const uint32_t i = L.order[k];
        if (i >= segments.size() || placed[i]) return fallback("the layout kept for this image is damaged (the order of its segments)");
        where[i] = cursor;
        placed[i] = true;
        cursor += segments[i].data.size() + L.after[k].size();
    }
    for (size_t i = 0; i < segments.size(); ++i)
        if (!placed[i] && !segments[i].data.empty())
            return fallback("segment " + std::to_string(i) + " (" + segments[i].role +
                            ") had no data in the image that was unpacked and has some now");

    // A segment without data has a p_offset all the same. Where it pointed behind the data of a segment (into the bytes
    // that followed it, at the start of the next one's data, at the end of the file), it points there again once the data
    // in front of it has grown or shrunk; anywhere else (in the block in front of the data, inside a segment's data) it
    // points where it did. (parse() takes no offset beyond the end of the file.)
    struct Zone {
        uint64_t orig_end, gap, new_end;  // the end of a segment's data as it was, the bytes behind it, the end as it is now
    };
    std::vector<Zone> zones;
    {
        uint64_t orig_cursor = h.size();
        for (size_t k = 0; k < L.order.size(); ++k) {
            const Phdr q = read_phdr(h, static_cast<size_t>(e.phoff + uint64_t(L.order[k]) * e.phentsize), e.is64);
            const uint64_t end = orig_cursor + q.filesz;
            zones.push_back({end, L.after[k].size(), where[L.order[k]] + segments[L.order[k]].data.size()});
            orig_cursor = end + L.after[k].size();
        }
    }
    auto offset_of_empty = [&](uint64_t offset) {
        for (const Zone& z : zones)
            if (offset >= z.orig_end && offset - z.orig_end <= z.gap) return z.new_end + (offset - z.orig_end);
        return offset;
    };

    Bytes out = h;
    put_le(out, 18, machine, 2);
    const uint64_t entry_addr = entry ? *entry : (segments.empty() ? e.entry : segments[0].addr);
    if (!fits(entry_addr, e.is64)) return fallback("the entry address does not fit an ELF32 header");
    put_le(out, e.entry_pos, entry_addr, e.addr_width);
    for (size_t i = 0; i < segments.size(); ++i) {
        const size_t at = static_cast<size_t>(e.phoff + uint64_t(i) * e.phentsize);
        Phdr p = read_phdr(h, at, e.is64);
        const ElfSegment& s = segments[i];
        if (!fits(s.addr, e.is64)) return fallback("the address of segment " + std::to_string(i) + " does not fit an ELF32 header");
        const bool paddr_follows = p.paddr == p.vaddr;
        const bool memsz_follows = p.memsz == p.filesz;
        p.flags = s.flags;
        p.vaddr = s.addr;
        if (paddr_follows) p.paddr = s.addr;
        p.filesz = s.data.size();
        p.memsz = memsz_follows ? p.filesz : std::max<uint64_t>(p.memsz, p.filesz);
        p.offset = placed[i] ? where[i] : offset_of_empty(p.offset);
        if (!fits(p.offset + p.filesz, e.is64)) return fallback("the image would be larger than an ELF32 header can describe");
        write_phdr(out, at, p, e.is64);
    }
    for (size_t k = 0; k < L.order.size(); ++k) {
        const Bytes& data = segments[L.order[k]].data;
        out.insert(out.end(), data.begin(), data.end());
        out.insert(out.end(), L.after[k].begin(), L.after[k].end());
    }
    return out;
}

}  // namespace abr::legacy
