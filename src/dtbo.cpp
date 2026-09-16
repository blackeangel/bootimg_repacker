// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/dtbo.hpp"

#include <zlib.h>

#include <algorithm>

namespace abr {

namespace {
constexpr uint32_t kHeaderSize = 32;  // struct.calcsize('>8I')
constexpr uint32_t kEntrySize = 32;   // struct.calcsize('>8I')

Bytes zlib_deflate(const Bytes& in, int window_bits) {
    z_stream strm{};
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, window_bits, 8,
                      Z_DEFAULT_STRATEGY) != Z_OK)
        throw FormatError("deflateInit2 failed for dtbo entry");
    Bytes out(deflateBound(&strm, in.size()));
    strm.next_in = const_cast<Bytef*>(in.data());
    strm.avail_in = static_cast<uInt>(in.size());
    strm.next_out = out.data();
    strm.avail_out = static_cast<uInt>(out.size());
    int rc = deflate(&strm, Z_FINISH);
    size_t produced = out.size() - strm.avail_out;
    deflateEnd(&strm);
    if (rc != Z_STREAM_END) throw FormatError("deflate failed for dtbo entry");
    out.resize(produced);
    return out;
}

// mkdtboimg.py decompresses both its ZLIB and GZIP entry formats with
// wbits=47 (= 32 + 15, i.e. "auto-detect zlib or gzip header"), so a
// single auto-detecting inflate covers both on the read side.
Bytes zlib_inflate_auto(const Bytes& in) {
    z_stream strm{};
    if (inflateInit2(&strm, 15 + 32) != Z_OK) throw FormatError("inflateInit2 failed for dtbo entry");
    Bytes out(std::max<size_t>(in.size() * 4, 4096));
    strm.next_in = const_cast<Bytef*>(in.data());
    strm.avail_in = static_cast<uInt>(in.size());
    size_t produced = 0;
    for (;;) {
        if (produced == out.size()) out.resize(out.size() * 2);
        strm.next_out = out.data() + produced;
        strm.avail_out = static_cast<uInt>(out.size() - produced);
        int rc = inflate(&strm, Z_FINISH);
        produced = out.size() - strm.avail_out;
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK && rc != Z_BUF_ERROR) {
            inflateEnd(&strm);
            throw FormatError("inflate failed for dtbo entry");
        }
        if (rc == Z_BUF_ERROR && strm.avail_in == 0) break;
    }
    inflateEnd(&strm);
    out.resize(produced);
    return out;
}
}  // namespace

DtboImage DtboImage::parse(const Bytes& image) {
    if (image.size() < kHeaderSize) throw FormatError("dtbo image too small");
    BinaryReader r(image);
    uint32_t magic = r.be32();
    bool acpio = (magic == kAcpioTableMagic);
    if (magic != kDtTableMagic && !acpio)
        throw FormatError("not a dtbo/acpio image (bad magic)");
    r.be32();  // total_size, recomputed on build()
    uint32_t header_size = r.be32();
    uint32_t entry_size = r.be32();
    uint32_t entry_count = r.be32();
    uint32_t entries_offset = r.be32();
    uint32_t page_size = r.be32();
    uint32_t version = r.be32();

    if (header_size < kHeaderSize) throw FormatError("dtbo header_size implausibly small");
    if (entry_count > 0 && entry_size < kEntrySize)
        throw FormatError("dtbo dt_entry_size implausibly small");
    if (version > 1) throw FormatError("unsupported dtbo version: " + std::to_string(version));

    DtboImage img;
    img.version = version;
    img.page_size = page_size;
    img.acpio = acpio;

    for (uint32_t i = 0; i < entry_count; ++i) {
        BinaryReader er(image);
        er.seek(entries_offset + static_cast<size_t>(i) * entry_size);
        DtboEntry e;
        uint32_t dt_size = er.be32();
        uint32_t dt_offset = er.be32();
        e.id = er.be32();
        e.rev = er.be32();
        for (auto& x : e.extra) x = er.be32();

        if (static_cast<uint64_t>(dt_offset) + dt_size > image.size())
            throw FormatError("dtbo entry " + std::to_string(i) + " points outside the image");
        Bytes raw(image.begin() + dt_offset, image.begin() + dt_offset + dt_size);
        uint32_t comp = (version == 1) ? (e.extra[0] & 0x0f) : 0;
        e.data = (comp == 1 || comp == 2) ? zlib_inflate_auto(raw) : std::move(raw);
        img.entries.push_back(std::move(e));
    }
    return img;
}

Bytes DtboImage::build() const {
    if (version > 1) throw FormatError("unsupported dtbo version: " + std::to_string(version));
    uint32_t entry_count = static_cast<uint32_t>(entries.size());
    uint32_t entries_offset = kHeaderSize;
    uint32_t cursor = entries_offset + entry_count * kEntrySize;

    std::vector<Bytes> payload(entries.size());
    std::vector<uint32_t> offsets(entries.size()), sizes(entries.size());
    for (size_t i = 0; i < entries.size(); ++i) {
        uint32_t comp = (version == 1) ? entries[i].compression() : 0;
        if (comp == 1)
            payload[i] = zlib_deflate(entries[i].data, 15);       // plain zlib wrapper
        else if (comp == 2)
            payload[i] = zlib_deflate(entries[i].data, 15 + 16);  // gzip wrapper
        else
            payload[i] = entries[i].data;
        offsets[i] = cursor;
        sizes[i] = static_cast<uint32_t>(payload[i].size());
        cursor += sizes[i];
    }

    BinaryWriter w;
    w.be32(acpio ? kAcpioTableMagic : kDtTableMagic);
    w.be32(cursor);  // total_size
    w.be32(kHeaderSize);
    w.be32(kEntrySize);
    w.be32(entry_count);
    w.be32(entries_offset);
    w.be32(page_size);
    w.be32(version);
    for (size_t i = 0; i < entries.size(); ++i) {
        w.be32(sizes[i]);
        w.be32(offsets[i]);
        w.be32(entries[i].id);
        w.be32(entries[i].rev);
        for (auto x : entries[i].extra) w.be32(x);
    }
    for (auto& p : payload) w.bytes(p);
    return w.take();
}

}  // namespace abr
