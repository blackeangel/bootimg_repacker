#!/usr/bin/env python3
"""An independent writer and reader of Sony SIN containers (versions 1 to 3), for the tests of abr.

The layout is the one include/abr/legacy/sin.hpp describes, which was read from the source of sony_dump
(github.com/munjeni/anyxperia_dumper), the program Android Image Kitchen opens a SIN with. This shares no code
with abr (src/legacy/sin.cpp); where the real sony_dump is at hand the test suite asks it as well
(ABR_SONY_DUMP). All numbers are big endian.

  sin_tool.py payloads DIR
        writes the images the containers are made around: DIR/aosp.img (a boot image), DIR/elf.img (a Sony ELF boot
        image, the layout elf_tool.py writes) and DIR/big.img (an 18 MiB boot image, for a part that is decoded on
        its own thread). None has the byte pair 53 EF in it, which sony_dump takes for the superblock of an ext4 file
        system -- and then pads the file to the size it believes that file system has.
  sin_tool.py cases DIR --aosp FILE --elf FILE [--big FILE] [--seed N]
        writes DIR/<name>.sin for a catalogue of containers around the two images, DIR/<name>.expect (what
        sony_dump makes of each one that it converts) and DIR/index.txt: one line per case,
            ok      <name> <the line `abr info` must show>
            nonboot <name> <what `abr unpack` must say: the container is fine, what it holds is not a boot image>
            refuse  <name> <what `abr unpack` must say: the container is damaged>
  sin_tool.py wrap IN OUT [--version 1|2|3] [--mmcf lz4|addr|mixed]
        the file IN as the image of a container: behind the header, or (--mmcf) in an MMCF block
  sin_tool.py convert IN OUT
        the independent reader: writes the image a SIN holds (exit 1, with the reason, when it cannot be read)
  sin_tool.py lz4 IN OUT [--literals]
        writes an LZ4 block of IN (and checks that it decodes to IN)
"""
import os
import random
import struct
import sys


def be16(x):
    return struct.pack(">H", x)


def be32(x):
    return struct.pack(">I", x)


def be64(x):
    return struct.pack(">Q", x)


# ---------------------------------------------------------------------------------------------------- LZ4 ---

def lz4_block(data, literals_only=False):
    """An LZ4 block (not a frame): a greedy matcher with a table of the last place each four bytes were seen, or
    -- literals_only, for the big parts, where speed counts more than size -- the data as one run of literals."""
    n = len(data)
    out = bytearray()

    def emit(lit_start, lit_end, mlen=0, off=0):
        ll = lit_end - lit_start
        token = min(ll, 15) << 4
        if mlen:
            token |= min(mlen - 4, 15)
        out.append(token)
        if ll >= 15:
            r = ll - 15
            out.extend(b"\xff" * (r // 255))
            out.append(r % 255)
        out.extend(data[lit_start:lit_end])
        if mlen:
            out.extend(struct.pack("<H", off))
            if mlen - 4 >= 15:
                r = mlen - 4 - 15
                out.extend(b"\xff" * (r // 255))
                out.append(r % 255)

    if literals_only or n < 13:
        emit(0, n)
        return bytes(out)
    table = {}
    i = anchor = 0
    last_start = n - 12  # the last match starts at least 12 bytes before the end ...
    end_limit = n - 5  # ... and ends at least 5 bytes before it
    while i <= last_start:
        key = bytes(data[i:i + 4])
        cand = table.get(key)
        table[key] = i
        if cand is not None and i - cand <= 0xFFFF:
            m = 4
            while i + m < end_limit and data[cand + m] == data[i + m]:
                m += 1
            emit(anchor, i, m, i - cand)
            i += m
            anchor = i
        else:
            i += 1
    emit(anchor, n)
    return bytes(out)


def lz4_decode(src, size):
    out = bytearray()
    i = 0
    while i < len(src):
        token = src[i]
        i += 1
        ll = token >> 4
        if ll == 15:
            while True:
                b = src[i]
                i += 1
                ll += b
                if b != 255:
                    break
        out += src[i:i + ll]
        i += ll
        if i >= len(src):
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        ml = token & 15
        if ml == 15:
            while True:
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        for _ in range(ml + 4):
            out.append(out[-off])
    assert len(out) == size, "lz4_decode: %d bytes, wanted %d" % (len(out), size)
    return bytes(out)


# -------------------------------------------------------------------------------------------- the writer ---

def header_v12(version, hsize, rnd):
    """A header of hsize + 16 bytes: the version, three zero bytes, the size in bytes 2 to 5, what stands for the
    hash tables and the signature (random bytes) in the rest."""
    assert 1 <= hsize < 65536
    h = bytearray(rnd.randbytes(hsize + 16))
    h[0] = version
    h[1] = h[2] = h[3] = 0
    h[4:6] = be16(hsize)
    return bytes(h)


def header_v3(psize, dsize, rnd):
    assert psize >= 0x1C
    h = bytearray(rnd.randbytes(psize))
    h[0:4] = b"\x03SIN"
    h[4:8] = be32(psize)
    h[0x18:0x1C] = be32(dsize)
    return bytes(h)


def pad_to_min(data, rnd, floor=1024):
    return data + rnd.randbytes(floor - len(data)) if len(data) < floor else data


def raw(version, payload, rnd, header=0x3F0, first=0):
    """No MMCF: the image follows the header (version 3 with `first` > 0: `first` bytes of something else, which
    the size at byte 0x18 counts, then the image)."""
    if version < 3:
        assert first == 0
        return pad_to_min(header_v12(version, header, rnd) + payload, rnd)
    psize = header
    if first:
        return pad_to_min(header_v3(psize, first, rnd) + rnd.randbytes(first) + payload, rnd)
    return pad_to_min(header_v3(psize, len(payload), rnd) + payload, rnd)


def mmcf(version, parts, rnd, header=0x400, uuid=None, want_image=True):
    """MMCF: `parts` is a list of dicts {kind: "lz4"|"addr", data, offset (the unpacked offset; default: where the
    image has got to), extra (bytes added to the entry), pre (bytes of other data in front of the part's data in the
    file), literals (LZ4: no matching)}. Returns (the container, the image sony_dump makes of it)."""
    data_region = bytearray()
    placed = []
    for p in parts:
        data_region += rnd.randbytes(p.get("pre", 0))
        blob = lz4_block(p["data"], p.get("literals", False)) if p["kind"] == "lz4" else p["data"]
        if p["kind"] == "lz4":
            assert lz4_decode(blob, len(p["data"])) == p["data"]
        placed.append((len(data_region), len(blob)))
        data_region += blob
    entries = bytearray()
    image = bytearray()
    for p, (poff, psize) in zip(parts, placed):
        uoff = p["offset"] if p.get("offset") is not None else len(image)
        if want_image:
            if len(image) < uoff:
                image += b"\xff" * (uoff - len(image))
            image += p["data"]
        extra = p.get("extra", 0)
        if p["kind"] == "lz4":
            entries += b"LZ4A" + be32(40 + extra) + be64(poff) + be64(len(p["data"])) + be64(psize) + be64(uoff)
        else:
            entries += b"ADDR" + be32(32 + extra) + be64(poff) + be64(psize) + be64(uoff)
        entries += rnd.randbytes(extra)
    uuid = uuid or rnd.randbytes(16)
    gptp = b"GPTP" + be32(24 + len(entries)) + uuid
    block = b"MMCF" + be32(len(gptp) + len(entries)) + gptp + entries
    if version < 3:
        head = header_v12(version, header - 16, rnd)
        body = pad_to_min(head + block + bytes(data_region), rnd)
    else:
        body = bytearray(pad_to_min(header_v3(header, 1, rnd) + block + bytes(data_region), rnd))
        body[0x18:0x1C] = be32(len(body) - header)
        body = bytes(body)
    return body, bytes(image), uuid


def uuid_text(u):
    h = u.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


# -------------------------------------------------------------------------------------------- the reader ---

class Refused(Exception):
    pass


def convert(sin):
    """The image a SIN holds, the way sony_dump makes it (nothing of its ext4 padding: that is for partition
    images). Raises Refused where sony_dump has no answer."""
    size = len(sin)
    if size < 1024:
        raise Refused("shorter than 1024 bytes")
    version = sin[0]
    if version not in (1, 2, 3):
        raise Refused("unsupported version")
    if version == 3:
        if sin[0:4] != b"\x03SIN":
            raise Refused("not a sin")
        hdr = struct.unpack(">I", sin[4:8])[0]
        dsz = struct.unpack(">I", sin[0x18:0x1C])[0]
    else:
        if sin[1:4] != b"\x00\x00\x00":
            raise Refused("not a sin")
        hdr = struct.unpack(">I", sin[2:6])[0]
        if hdr < 1:
            raise Refused("header size 0")
        hdr += 16
        if hdr >= size:
            raise Refused("header leaves no data")
        dsz = size - hdr
    if hdr < 1 or dsz < 1:
        raise Refused("header or data size 0")
    if hdr > size:
        raise Refused("header beyond the file")
    magic = sin[hdr:hdr + 8]
    if len(magic) == 8 and magic[:4] == b"MMCF":
        glen = struct.unpack(">I", magic[4:8])[0]
        if glen == 0:
            raise Refused("empty MMCF block")
        if glen < 24:
            raise Refused("MMCF block smaller than its GPTP block")
        base = hdr + 8 + glen
        if base > size:
            raise Refused("MMCF block out of the file")
        out = bytearray()
        t = 0
        parts = 0
        while t < glen - 24:
            pos = hdr + 8 + 24 + t
            if pos + 8 > size:
                raise Refused("entry cut short")
            tag = sin[pos:pos + 4]
            ent = struct.unpack(">I", sin[pos + 4:pos + 8])[0]
            if tag == b"LZ4A":
                if ent < 40 or pos + 40 > size:
                    raise Refused("bad LZ4A entry")
                poff, usize, psize, uoff = struct.unpack(">QQQQ", sin[pos + 8:pos + 40])
            elif tag == b"ADDR":
                if ent < 32 or pos + 32 > size:
                    raise Refused("bad ADDR entry")
                poff, psize, uoff = struct.unpack(">QQQ", sin[pos + 8:pos + 32])
                usize = psize
            else:
                raise Refused("unknown part type")
            start = base + poff
            if start + psize > size:
                raise Refused("part data out of the file")
            if len(out) < uoff:
                if uoff > (1 << 31):
                    raise Refused("image far too large")
                out += b"\xff" * (uoff - len(out))
            blob = sin[start:start + psize]
            if tag == b"LZ4A":
                if psize < 1 or usize < 1:
                    raise Refused("empty LZ4 part")
                try:
                    blob = lz4_decode(blob, usize)
                except (AssertionError, IndexError):
                    raise Refused("LZ4 block does not decode to the size of its entry")
            out += blob
            parts += 1
            t += ent
        if parts == 0:
            raise Refused("no parts")
        if not out:
            raise Refused("empty image")
        return bytes(out)
    if magic[:4] == b"\x7fELF":
        if hdr + dsz != size:
            raise Refused("data size does not fit the file")
        return sin[hdr:]
    if hdr + dsz != size:
        if hdr + dsz > size:
            raise Refused("data size beyond the file")
        return sin[hdr + dsz:]
    return sin[hdr:]


# ----------------------------------------------------------------------------------------------- the cases ---

def largest_ff_run(data, floor=4096):
    """(start, end) of the first run of at least `floor` 0xFF bytes, or None."""
    i = data.find(b"\xff" * floor)
    if i < 0:
        return None
    j = i + floor
    while j < len(data) and data[j] == 0xFF:
        j += 1
    return i, j


def split(data, *cuts):
    pieces = []
    last = 0
    for c in list(cuts) + [len(data)]:
        pieces.append(data[last:c])
        last = c
    return pieces


def cases(outdir, aosp, elf, seed, big=None):
    rnd = random.Random(seed)
    os.makedirs(outdir, exist_ok=True)
    index = []

    def put(name, sin, expect, status, pattern):
        with open(os.path.join(outdir, name + ".sin"), "wb") as f:
            f.write(sin)
        if expect is not None:
            with open(os.path.join(outdir, name + ".expect"), "wb") as f:
                f.write(expect)
        index.append("%s\t%s\t%s" % (status, name, pattern))

    def info_raw(version, header, payload, extra=""):
        hdr = header + 16 if version < 3 else header
        return "Sony SIN v%d%s, header %d bytes, image %d bytes" % (version, extra, hdr, len(payload))

    # ---- no MMCF: the image behind the header ----
    for version, header in ((1, 0x3F0), (2, 0x7FF0)):
        sin = raw(version, aosp, rnd, header)
        put("v%d_raw_aosp" % version, sin, aosp, "ok", info_raw(version, header, aosp))
    for version in (1, 2):
        sin = raw(version, elf, rnd, 0x3E0)
        put("v%d_loader_elf" % version, sin, elf, "ok", info_raw(version, 0x3E0, elf, ", a loader (ELF behind the header)"))
    sin = raw(3, aosp, rnd, 0x400)
    put("v3_raw_aosp", sin, aosp, "ok", info_raw(3, 0x400, aosp))
    sin = raw(3, elf, rnd, 0x420)
    put("v3_loader_elf", sin, elf, "ok", info_raw(3, 0x420, elf, ", a loader (ELF behind the header)"))
    sin = raw(3, aosp, rnd, 0x400, first=512)
    put("v3_first_aosp", sin, aosp, "ok", info_raw(3, 0x400, aosp, ", 512 bytes of data in front of the image"))
    sin = raw(3, elf, rnd, 0x800, first=0x1000)
    put("v3_first_elf", sin, elf, "ok", info_raw(3, 0x800, elf, ", 4096 bytes of data in front of the image"))

    # ---- MMCF ----
    def mmcf_case(name, version, parts, header=0x400, image=None, note=None):
        sin, made, uuid = mmcf(version, parts, rnd, header)
        want = image if image is not None else made
        assert made == want, name + ": the writer's own image is not the one wanted"
        n_lz4 = sum(1 for p in parts if p["kind"] == "lz4")
        line = "Sony SIN v%d, MMCF (%d %s: %d ADDR, %d LZ4A; GPTP %s), header %d bytes, image %d bytes" % (
            version, len(parts), "part" if len(parts) == 1 else "parts", len(parts) - n_lz4, n_lz4, uuid_text(uuid),
            header, len(want))
        put(name, sin, want, "ok", line)
        return sin, want

    mmcf_case("v3_mmcf_addr_elf", 3, [dict(kind="addr", data=elf)])
    mmcf_case("v3_mmcf_lz4_elf", 3, [dict(kind="lz4", data=elf)])
    a, b, c = split(elf, 4096, len(elf) // 2)
    mmcf_case("v3_mmcf_mixed_elf", 3, [dict(kind="addr", data=a), dict(kind="lz4", data=b), dict(kind="addr", data=c)], header=0x410)
    mmcf_case("v2_mmcf_elf", 2, [dict(kind="lz4", data=a + b), dict(kind="addr", data=c)], header=0x400)
    mmcf_case("v1_mmcf_elf", 1, [dict(kind="addr", data=a), dict(kind="lz4", data=b + c, literals=True)], header=0x420)
    p1, p2, p3, p4 = split(aosp, 2048, len(aosp) // 3, len(aosp) * 3 // 4)
    mmcf_case("v3_mmcf_mixed_aosp", 3,
              [dict(kind="addr", data=p1), dict(kind="lz4", data=p2), dict(kind="lz4", data=p3, literals=True),
               dict(kind="addr", data=p4)])
    # entries longer than their fields, other data between the parts' data in the file
    mmcf_case("v3_mmcf_extra_elf", 3,
              [dict(kind="lz4", data=a + b[:5000], extra=16, pre=13), dict(kind="addr", data=b[5000:], extra=24, pre=100),
               dict(kind="lz4", data=c, extra=1, pre=7)])
    # a gap between two parts: 0xFF fills it, so the image is the one the parts were cut from if the gap was a run of 0xFF
    run = largest_ff_run(elf)
    if run:
        i, j = run
        mmcf_case("v3_mmcf_gap_elf", 3,
                  [dict(kind="addr", data=elf[:i]), dict(kind="lz4", data=elf[j:], offset=j)], image=elf)
        mmcf_case("v3_mmcf_gap2_elf", 3,
                  [dict(kind="lz4", data=elf[:i - 100]), dict(kind="addr", data=elf[i - 100:i], offset=i - 100),
                   dict(kind="addr", data=elf[j:j + 700], offset=j), dict(kind="lz4", data=elf[j + 700:])], image=elf)
    # parts that start before the end of what there is are put at the end (sony_dump does not seek)
    mmcf_case("v3_mmcf_append_elf", 3,
              [dict(kind="addr", data=elf[:len(elf) // 2], offset=0), dict(kind="lz4", data=elf[len(elf) // 2:], offset=0)])
    # many small parts, and one that is empty
    pieces = [elf[k:k + 1500] for k in range(0, len(elf), 1500)][:60]
    rest = elf[sum(len(x) for x in pieces):]
    parts = [dict(kind="addr" if k % 2 else "lz4", data=x, literals=(k % 4 == 0)) for k, x in enumerate(pieces)]
    if rest:
        parts.append(dict(kind="lz4", data=rest))
    mmcf_case("v3_mmcf_many_elf", 3, parts)
    mmcf_case("v3_mmcf_emptyaddr_elf", 3,
              [dict(kind="addr", data=a), dict(kind="addr", data=b""), dict(kind="lz4", data=b + c)])

    # ---- a payload big enough for the parts to be decoded on several threads ----
    if big is not None:
        half = len(big) // 2
        mmcf_case("v3_mmcf_big_aosp", 3,
                  [dict(kind="lz4", data=big[:half], literals=True), dict(kind="lz4", data=big[half:], literals=True)])

    # ---- what is in the container is not a boot image ----
    ext4 = bytearray(rnd.randbytes(300000))
    ext4[0:1024] = bytes(1024)
    ext4[0x404:0x408] = struct.pack("<I", 100)  # blocks count
    ext4[0x408:0x40C] = bytes(4)  # reserved blocks
    ext4[0x438:0x43A] = b"\x53\xef"
    sin, _, _ = mmcf(3, [dict(kind="lz4", data=bytes(ext4[:150000])), dict(kind="lz4", data=bytes(ext4[150000:]))], rnd)
    put("v3_mmcf_ext4", sin, None, "nonboot", "ext2/3/4 filesystem image")
    sin = raw(1, rnd.randbytes(5000), rnd, 0x400)
    put("v1_raw_random", sin, None, "nonboot", "unrecognized image format")
    sin, _, _ = mmcf(3, [dict(kind="addr", data=elf[:4096]), dict(kind="addr", data=elf[4096:], offset=1 << 36)], rnd,
                     want_image=False)
    put("v3_mmcf_huge", sin, None, "nonboot", "far too large")
    # a container whose image is a container: one layer comes off, not two (a SIN holds an image, not another SIN)
    put("v1_nested_sin", raw(1, raw(3, aosp, rnd, 0x400), rnd, 0x3F0), None, "nonboot", "another SIN container")

    # ---- damaged containers ----
    good_raw = raw(3, aosp, rnd, 0x400)
    good_v1 = raw(1, aosp, rnd, 0x3F0)
    small_v1 = raw(1, rnd.randbytes(100), rnd, 0x3F0)
    good_mmcf, _, _ = mmcf(3, [dict(kind="lz4", data=elf[:6000]), dict(kind="addr", data=elf[6000:])], rnd)

    def patched(sin, off, new):
        return sin[:off] + new + sin[off + len(new):]

    put("bad_short", good_raw[:1000], None, "refuse", "at least 1024")
    put("bad_v1_h0", patched(good_v1, 2, be32(0)), None, "refuse", "size of the header is 0")
    put("bad_v1_hbig", patched(small_v1, 2, be32(5000)), None, "refuse", "leaves no room for data")
    put("bad_v3_p0", patched(good_raw, 4, be32(0)), None, "refuse", "size of the header or of the data is 0")
    put("bad_v3_d0", patched(good_raw, 0x18, be32(0)), None, "refuse", "size of the header or of the data is 0")
    put("bad_v3_pbig", patched(good_raw, 4, be32(len(good_raw) + 1)), None, "refuse", "the header is")
    elf_raw = raw(3, elf, rnd, 0x400)
    put("bad_v3_loader_d", patched(elf_raw, 0x18, be32(len(elf) - 1)), None, "refuse", "does not fit the file")
    put("bad_v3_firstbig", patched(good_raw, 0x18, be32(len(good_raw))), None, "refuse", "is more than the file holds")
    put("bad_mmcf_empty", patched(good_mmcf, 0x404, be32(0)), None, "refuse", "MMCF block is empty")
    put("bad_mmcf_small", patched(good_mmcf, 0x404, be32(10)), None, "refuse", "less than its 24-byte GPTP block")
    put("bad_mmcf_out", patched(good_mmcf, 0x404, be32(len(good_mmcf))), None, "refuse", "MMCF block (")
    put("bad_mmcf_noparts", patched(good_mmcf, 0x404, be32(24)), None, "refuse", "has no parts")
    entry = 0x400 + 8 + 24  # the first entry
    put("bad_tag", patched(good_mmcf, entry, b"XYZW"), None, "refuse", "unknown type 58 59 5a 57")
    put("bad_entry_small", patched(good_mmcf, entry + 4, be32(8)), None, "refuse", "shorter than the 40 bytes of its fields")
    put("bad_part_out", patched(good_mmcf, entry + 24, be64(len(good_mmcf))), None, "refuse", "its data (")
    put("bad_lz4_empty", patched(good_mmcf, entry + 16, be64(0)), None, "refuse", "an LZ4 part with no data")
    # a second entry that the file ends in the middle of: the block holds the first entry and 12 bytes of the second
    cut = (header_v3(0x3E0, 1, rnd) + b"MMCF" + be32(24 + 32 + 12) + b"GPTP" + be32(24 + 32 + 12) + rnd.randbytes(16) +
           b"ADDR" + be32(32) + be64(0) + be64(0) + be64(0) + b"ADDR" + be32(32) + bytes(4))
    cut = patched(cut, 0x18, be32(len(cut) - 0x3E0))
    assert len(cut) >= 1024 and len(cut) == 0x3E0 + 8 + 24 + 32 + 12
    put("bad_entry_cut", cut, None, "refuse", "is cut short")
    # LZ4 data that cannot be decoded (a run of literals that is longer than what is left), and blocks that decode to
    # another size than the entry says
    sin2, _, _ = mmcf(3, [dict(kind="addr", data=elf[:4096]), dict(kind="lz4", data=b"x" * 5000)], rnd)
    e2 = entry + 32  # the entry of the second part
    poff = struct.unpack(">Q", sin2[e2 + 8:e2 + 16])[0]
    psize = struct.unpack(">Q", sin2[e2 + 24:e2 + 32])[0]
    data_base = 0x400 + 8 + struct.unpack(">I", sin2[0x404:0x408])[0]
    junk = (b"\xf0" + b"\xff" * 20 + bytes(psize))[:psize]
    assert psize >= 21
    put("bad_lz4_junk", sin2[:data_base + poff] + junk + sin2[data_base + poff + psize:], None, "refuse", "the LZ4 block is damaged")
    for name, usize, why in (("bad_lz4_short", 3600 + 10, "decodes to 3600 bytes, the entry says 3610"),
                             ("bad_lz4_long", 3600 - 10, "the LZ4 block is damaged")):
        sin3, _, _ = mmcf(3, [dict(kind="addr", data=elf[:4096]), dict(kind="lz4", data=b"abcabcabc" * 400)], rnd)
        put(name, patched(sin3, e2 + 16, be64(usize)), None, "refuse", why)

    with open(os.path.join(outdir, "index.txt"), "w") as f:
        f.write("\n".join(index) + "\n")


def newc(files):
    """A cpio archive (newc) of [(name, mode, data)]: small enough to compress to a gzip stream without 53 EF."""
    out = bytearray()

    def rec(ino, name, mode, data):
        nm = name.encode() + b"\0"
        out.extend(b"070701" + b"".join(b"%08x" % v for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0)))
        out.extend(nm)
        out.extend(bytes((-len(out)) % 4))
        out.extend(data)
        out.extend(bytes((-len(out)) % 4))

    for ino, (name, mode, data) in enumerate(files, 1):
        rec(ino, name, mode, data)
    rec(0, "TRAILER!!!", 0, b"")
    return bytes(out)


def payloads(outdir, seed=20261018):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import zlib

    import elf_tool
    import fixtures

    r = random.Random(seed)

    def scrub(b):
        return b.replace(b"\x53\xef", b"\x53\xee")

    cpio = newc([("init", 0o100755, b"#!/bin/sh\nexec /sbin/adbd\n"), ("sbin", 0o040755, b""),
                 ("sbin/adbd", 0o100755, b"adbd " * 40), ("default.prop", 0o100644, b"ro.secure=0\nro.debuggable=1\n")])
    ramdisk = None
    for level in range(9, 0, -1):
        c = zlib.compressobj(level, zlib.DEFLATED, 31)
        gz = c.compress(cpio) + c.flush()
        if b"\x53\xef" not in gz:
            ramdisk = gz
            break
    assert ramdisk, "no ramdisk without 53 EF"
    os.makedirs(outdir, exist_ok=True)
    aosp = fixtures.boot_v012(0, scrub(r.randbytes(70001)), ramdisk, page=2048,
                              cmdline="console=ttyS0,115200 androidboot.hardware=sintest", name="sintest")
    kernel = bytearray(scrub(r.randbytes(60000)))
    kernel[10000:19000] = b"\xff" * 9000  # a run of 0xFF in the middle: the gap cases cut the image there
    elf = elf_tool.make([("kernel", 0x8000, bytes(kernel)), ("ramdisk", 0x2000000, ramdisk),
                         ("cmdline", 0, b"console=ttyS0 androidboot.hardware=sintest\0")])
    big = scrub(fixtures.boot_v012(0, scrub(r.randbytes(18 << 20)), ramdisk, page=2048, cmdline="x", name="big"))
    for name, data in (("aosp.img", aosp), ("elf.img", elf), ("big.img", big)):
        assert b"\x53\xef" not in data or name == "elf.img", name
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)


def wrap(data, version=3, kind=None, seed=20261018):
    """`data` as the image of a container: behind the header (kind None), or in an MMCF block as one LZ4A part
    ("lz4"), one ADDR part ("addr") or its first half ADDR and the rest LZ4A ("mixed")."""
    rnd = random.Random(seed)
    if kind is None:
        return raw(version, data, rnd)
    literals = len(data) > (1 << 20)  # a greedy matcher in Python is slow on tens of megabytes
    if kind == "lz4":
        parts = [dict(kind="lz4", data=data, literals=literals)]
    elif kind == "addr":
        parts = [dict(kind="addr", data=data)]
    elif kind == "mixed":
        cut = len(data) // 2
        parts = [dict(kind="addr", data=data[:cut]), dict(kind="lz4", data=data[cut:], literals=literals)]
    else:
        raise SystemExit("wrap: --mmcf takes lz4, addr or mixed")
    sin, image, _ = mmcf(version, parts, rnd)
    assert image == data
    return sin


def main(argv):
    if len(argv) >= 4 and argv[1] == "wrap":
        opts = argv[4:]
        version = int(opts[opts.index("--version") + 1]) if "--version" in opts else 3
        kind = opts[opts.index("--mmcf") + 1] if "--mmcf" in opts else None
        with open(argv[2], "rb") as f:
            data = f.read()
        with open(argv[3], "wb") as f:
            f.write(wrap(data, version, kind))
        return 0
    if len(argv) == 3 and argv[1] == "payloads":
        payloads(argv[2])
        return 0
    if len(argv) >= 3 and argv[1] == "cases":
        outdir = argv[2]
        opts = dict(zip(argv[3::2], argv[4::2]))
        with open(opts["--aosp"], "rb") as f:
            aosp = f.read()
        with open(opts["--elf"], "rb") as f:
            elf = f.read()
        big = None
        if "--big" in opts:
            with open(opts["--big"], "rb") as f:
                big = f.read()
        cases(outdir, aosp, elf, int(opts.get("--seed", "20261018")), big)
        return 0
    if len(argv) == 4 and argv[1] == "convert":
        with open(argv[2], "rb") as f:
            sin = f.read()
        try:
            image = convert(sin)
        except Refused as e:
            sys.stderr.write("refused: %s\n" % e)
            return 1
        with open(argv[3], "wb") as f:
            f.write(image)
        return 0
    if len(argv) >= 4 and argv[1] == "lz4":
        with open(argv[2], "rb") as f:
            data = f.read()
        block = lz4_block(data, "--literals" in argv[4:])
        assert lz4_decode(block, len(data)) == data
        with open(argv[3], "wb") as f:
            f.write(block)
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
