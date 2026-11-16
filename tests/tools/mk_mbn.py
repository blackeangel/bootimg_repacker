#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic images of Qualcomm's secure boot (MBN), made and checked WITHOUT abr.

The layouts are those of coreboot's util/qualcomm/mbn_tools.py and of qtestsign, as the unit tests of abr::mbn know them: this script is the
independent second writer. It has two commands:

  mk_mbn.py make   <dir>             writes a set of images into <dir>
  mk_mbn.py verify <image>           parses an image on its own (flat or ELF) and checks the sizes and every hash of the table; exit 0 when it holds

Nothing of abr is used here: only hashlib, struct, gzip and the `cryptography` package for the certificates.
"""
import gzip
import hashlib
import os
import random
import struct
import sys

try:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:  # the certificates are only for the images that carry a chain
    x509 = None


def sha(algo, data):
    return hashlib.new(algo, data).digest()


def align_up(v, a):
    return (v + a - 1) // a * a if a > 1 else v


def u32(*words):
    return b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)


def blob(seed, n, head=b"\x00\x00\xa0\xe1"):
    rnd = random.Random(seed)
    return head + bytes(rnd.randrange(256) for _ in range(n - len(head)))


# ------------------------------------------------------------------------------------------------------------ certificates


def make_chain(seed, ous, fill_to=0, fill=0xFF):
    """Three DER certificates (root, CA, attestation certificate with the OU attributes `ous`), the leaf first, then `fill` up to `fill_to`."""
    assert x509 is not None, "the cryptography package is needed for a certificate chain"
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    now = datetime.datetime(2020, 1, 1)

    def name(cn, units):
        attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QUALCOMM")]
        attrs += [x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u) for u in units]
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        return x509.Name(attrs)

    names = [name("QCT Root CA 1", ["QCT Root"]), name("QCT Attestation CA", ["QCT CA"]), name("QCT Attestation", ous)]
    ders = []
    for i in range(3):
        issuer_i = max(i - 1, 0)
        cert = (
            x509.CertificateBuilder()
            .subject_name(names[i])
            .issuer_name(names[issuer_i])
            .public_key(keys[i].public_key())
            .serial_number(1000 + i)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(keys[issuer_i], hashes.SHA256())
        )
        ders.append(cert.public_bytes(serialization.Encoding.DER))
    chain = ders[2] + ders[1] + ders[0]
    if fill_to > len(chain):
        chain += bytes([fill]) * (fill_to - len(chain))
    return chain


ATTRS = ["01 0000000000000003 SW_ID", "02 0000000000000000 HW_ID", "03 0000 DEBUG", "04 0000 OEM_ID", "05 00000000 SW_SIZE", "06 0000 MODEL_ID"]

# ------------------------------------------------------------------------------------------------------------ the structure


def structure(version, code, sig=b"", cert=b"", meta_qti=b"", meta=b"", sig_qti=b"", cert_qti=b"", image_id=5, image_src=0x28, image_dest=0x8F600000,
              round4=False, slack_byte=0, ptr_literal=None, extra_words=None):
    """The header and the parts. `version` is 3, 5, 6, 7 or 'sbl'."""
    parts = meta_qti + meta + code + sig_qti + cert_qti + sig + cert
    total = len(parts)
    slack = b""
    if round4:
        slack = bytes([slack_byte]) * (-total % 4)
    image_size = total + len(slack)
    sig_ptr = image_dest + len(code)
    cert_ptr = sig_ptr + len(sig)
    if ptr_literal is not None:
        sig_ptr, cert_ptr = ptr_literal
    if version == 3:
        hdr = u32(image_id, 3, image_src, image_dest, image_size, len(code), sig_ptr, len(sig), cert_ptr, len(cert))
        assert not (meta_qti or meta or sig_qti or cert_qti)
    elif version == 5:
        hdr = u32(image_id, 5, len(sig_qti), len(cert_qti), image_size, len(code), sig_ptr, len(sig), cert_ptr, len(cert))
        assert not (meta_qti or meta)
    elif version == 6:
        hdr = u32(image_id, 6, len(sig_qti), len(cert_qti), image_size, len(code), sig_ptr, len(sig), cert_ptr, len(cert), len(meta_qti), len(meta))
    elif version == 7:
        ew = extra_words or [1, 2, 0x11, 0x22, 3, 0]
        hdr = u32(0, 7, 24, len(meta_qti), len(meta), len(code), len(sig_qti), len(cert_qti), len(sig), len(cert), *ew)
        assert len(hdr) == 64
        slack = b""
    elif version == "sbl":
        hdr = u32(0x844BDCD1, 0x73D71034, image_id, 0, 0, 80, image_dest, image_size, len(code), sig_ptr, len(sig), cert_ptr, len(cert), 0, 1, 0, 0, 0, 0, 0)
        assert len(hdr) == 80
    else:
        raise ValueError(version)
    return hdr + parts + slack


# ------------------------------------------------------------------------------------------------------------ the ELF


def table_entries(segs, algo, headers):
    """The entries of the table of hashes: the placeholder (the hash of the ELF header and the program headers), the hash segment (zeros), then every
    segment -- a hash of its data, zeros for what is not checked (no data, access type NOTUSED or SHARED), a hash of every page for a paged one."""
    ds = {"sha1": 20, "sha256": 32, "sha384": 48}[algo]
    zero = b"\0" * ds
    entries = [sha(algo, headers), zero]
    for s in segs:
        flags, data = s["flags"], s["data"]
        checked = ((flags >> 21) & 7) not in (3, 4) and ((flags >> 24) & 7) != 2
        if flags & 0x00100000 and data:
            off = s["vaddr"] & 0xFFF
            skip = 4096 - off if off else 0
            assert (len(data) - skip) % 4096 == 0, "a paged segment is made of whole pages"
            for pos in range(skip, len(data), 4096):
                entries.append(sha(algo, data[pos:pos + 4096]) if checked else zero)
        elif data and checked:
            entries.append(sha(algo, data))
        else:
            entries.append(zero)
    return entries


PT_NULL, PT_LOAD = 0, 1
F_HASH = 0x02200000  # segment type 2 (HASH), access type 1 (RO)
F_PHDR = 0x07000000  # segment type 7 (PHDR)


def elf_image(segs, is64=False, hash_version=3, algo="sha256", sig=b"", cert=b"", meta_qti=b"", meta=b"", sig_qti=b"", cert_qti=b"", fill=0,
              machine=0xA4, entry=0x86000000, sections=False, table_override=None, tail=b"", seg_align=0x1000, first_at=0x1000, hash_pad=b"", image_id=0):
    """An ELF in the layout of Qualcomm's tools: ELF header, program headers, a fill, the hash segment, the other segments one behind the other (each at a
    multiple of seg_align). `segs`: list of dicts with data, flags, vaddr (and optionally paddr, memsz, align, type)."""
    ehsize, phentsize = (64, 56) if is64 else (52, 32)
    phnum = 2 + len(segs)
    header_end = ehsize + phnum * phentsize
    # where the data goes
    hash_at = align_up(max(header_end, first_at), seg_align)
    # the size of the hash segment
    digest_len = {"sha1": 20, "sha256": 32, "sha384": 48}[algo]
    table_len = len(table_override) if table_override is not None else len(table_entries(segs, algo, b"")) * digest_len
    hdr_len = {3: 40, 5: 40, 6: 48, 7: 64}[hash_version]
    hash_len = hdr_len + len(meta_qti) + len(meta) + table_len + len(sig_qti) + len(cert_qti) + len(sig) + len(cert) + len(hash_pad)
    at = [hash_at]
    pos = hash_at + hash_len
    offsets = []
    for s in segs:
        if s["data"]:
            pos = align_up(pos, seg_align)
            offsets.append(pos)
            pos += len(s["data"])
        else:
            offsets.append(s.get("offset", 0))
    end = pos
    if sections:
        # a section header table behind the data: an ELF that Qualcomm's tools do not write, and abr keeps as it is
        shoff = align_up(end, 8)
        end = shoff + 3 * 40
    # program headers
    phdrs = []

    def ph(type_, flags, offset, vaddr, paddr, filesz, memsz, align):
        if is64:
            return struct.pack("<IIQQQQQQ", type_, flags, offset, vaddr, paddr, filesz, memsz, align)
        return struct.pack("<8I", type_, offset, vaddr, paddr, filesz, memsz, flags, align)

    phdrs.append(ph(PT_NULL, F_PHDR, 0, 0, 0, header_end, 0, 0))
    hash_vaddr = 0x80000000
    phdrs.append(ph(PT_NULL, F_HASH, hash_at, hash_vaddr, hash_vaddr, hash_len, align_up(hash_len, 0x1000), 0x1000))
    for s, off in zip(segs, offsets):
        d = s["data"]
        phdrs.append(ph(s.get("type", PT_LOAD), s["flags"], off, s["vaddr"], s.get("paddr", s["vaddr"]), len(d), s.get("memsz", len(d)), s.get("align", seg_align)))
    # ELF header
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1, 1]) + b"\0" * 9
    shoff_v, shnum = (shoff, 3) if sections else (0, 0)
    if is64:
        ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, entry, ehsize, shoff_v, 0, ehsize, phentsize, phnum, 64 if sections else 0, shnum, 0)
    else:
        ehdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, machine, 1, entry, ehsize, shoff_v, 0, ehsize, phentsize, phnum, 40 if sections else 0, shnum, 0)
    headers = ehdr + b"".join(phdrs)
    assert len(headers) == header_end
    # the table
    table = table_override if table_override is not None else b"".join(table_entries(segs, algo, headers))
    block = structure(hash_version, table, sig=sig, cert=cert, meta_qti=meta_qti, meta=meta, sig_qti=sig_qti, cert_qti=cert_qti, image_id=image_id,
                      image_src=0, image_dest=hash_vaddr + 0x28, round4=False)
    block += hash_pad
    assert len(block) == hash_len, (len(block), hash_len)
    out = bytearray(headers)
    out += bytes([fill]) * (hash_at - len(out))
    out += block
    for s, off in zip(segs, offsets):
        if not s["data"]:
            continue
        out += bytes([fill]) * (off - len(out))
        out += s["data"]
    if sections:
        out += bytes([fill]) * (shoff - len(out))
        out += b"\0" * (3 * 40)
    return bytes(out) + tail


# ------------------------------------------------------------------------------------------------------------ the set


def make(outdir):
    os.makedirs(outdir, exist_ok=True)

    def put(name, data):
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)

    chain = make_chain(1, ATTRS, fill_to=3072)
    sig = blob(2, 256, head=b"\x42\x42")
    code = blob(3, 5000)
    put("flat_v3.mbn", structure(3, code, sig=sig, cert=chain))
    put("flat_v3_unsigned.mbn", structure(3, code))
    put("flat_v3_round.mbn", structure(3, code[:4999], sig=sig[:255], cert=chain[:3071], round4=True, slack_byte=0xA5))
    put("flat_v3_literal_ptrs.mbn", structure(3, code, sig=sig, cert=chain, ptr_literal=(0x1234, 0x9999)))
    tail = structure(3, code, sig=sig, cert=chain)
    put("flat_v3_padded.mbn", tail + b"\xff" * (16384 - len(tail)))
    put("flat_v3_trailer.mbn", tail + b"TRAILER-DATA-12345")
    put("flat_v5.mbn", structure(5, code, sig=sig, cert=chain, sig_qti=blob(4, 256, head=b"\x51\x51"), cert_qti=make_chain(5, ["01 0000000000000000 SW_ID"], fill_to=1024), image_id=23))
    put("flat_v6.mbn", structure(6, code, sig=sig, cert=chain, sig_qti=blob(6, 256, head=b"\x61\x61"), meta_qti=blob(7, 72, head=b"\x71"), meta=blob(8, 100, head=b"\x72"),
                                  image_id=21, round4=True))
    put("flat_v7.mbn", structure(7, code, sig=sig, cert=chain, sig_qti=blob(9, 256, head=b"\x91\x91"), meta_qti=blob(10, 24, head=b"\xa1"), meta=blob(11, 224, head=b"\xa2")))
    put("flat_sbl.mbn", structure("sbl", code, sig=sig, cert=chain, image_id=21))
    put("flat_v3_gzip.mbn", structure(3, gzip.compress(blob(12, 7000), mtime=0), sig=sig, cert=chain))

    seg_a = blob(20, 6000)
    seg_b = blob(21, 3000, head=b"\x11\x11")
    segs = [
        {"data": seg_a, "flags": 0x01200005, "vaddr": 0x86000000},
        {"data": seg_b, "flags": 0x01200006, "vaddr": 0x86100000},
    ]
    put("elf32.mbn", elf_image(segs))
    put("elf64.mbn", elf_image(segs, is64=True, machine=0xB7, entry=0xA0000000))
    put("elf32_sha1.mbn", elf_image(segs, algo="sha1"))
    put("elf32_v6_sha384.mbn", elf_image(segs, algo="sha384", hash_version=6, meta_qti=blob(30, 72, head=b"\x71"), meta=blob(31, 40, head=b"\x72"), sig_qti=blob(32, 256, head=b"\x31\x31"),
                                          cert_qti=make_chain(33, ["01 0000000000000000 SW_ID"], fill_to=1024)))
    put("elf32_signed.mbn", elf_image(segs, sig=sig, cert=chain, fill=0xFF, image_id=25))
    put("elf32_padded.mbn", elf_image(segs, tail=b"\x00" * 9000))
    put("elf32_hashpad.mbn", elf_image(segs, hash_pad=b"\xEE" * 33))
    put("elf32_gzip.mbn", elf_image([{"data": gzip.compress(blob(40, 9000), mtime=0), "flags": 0x01200005, "vaddr": 0x86000000}, segs[1]]))
    put("elf32_empty_seg.mbn", elf_image(segs + [{"data": b"", "flags": 0x01200006, "vaddr": 0x87000000, "memsz": 0x4000, "offset": 0}]))
    put("elf32_paged.mbn", elf_image([{"data": blob(41, 8192), "flags": 0x01300005, "vaddr": 0x86000000}, {"data": blob(42, 4096), "flags": 0x01200006, "vaddr": 0x86100000}]))
    put("elf32_sections.mbn", elf_image(segs, sections=True))
    put("elf32_unknown_table.mbn", elf_image(segs, table_override=blob(50, 4 * 32, head=b"\x05")))
    put("elf32_notused.mbn", elf_image(segs + [{"data": blob(43, 700), "flags": 0x01600004, "vaddr": 0x88000000}]))
    # not images
    plain = bytearray(elf_image(segs))
    ph_off = 52 + 32  # program header 1 is the hash segment
    plain[ph_off + 24:ph_off + 28] = struct.pack("<I", 0x00000004)  # its flags are plain read now
    put("not_mbn_plain.elf", bytes(plain))
    split = bytearray(elf_image(segs))
    # a .mdt: the segments are in files of their own (their offsets are past the end)
    for i in (2, 3):
        o = 52 + 32 * i
        split[o + 4:o + 8] = struct.pack("<I", 0x100000 * i)
    put("not_mbn_split.mdt", bytes(split))
    put("sbl_nand_preamble.bin", u32(0x844BDCD1, 0x73D71034, 0x7D0B435A, 2048) + b"\0" * 4000)
    put("truncated_v3.mbn", structure(3, code, sig=sig, cert=chain)[:3000])
    return 0


# ------------------------------------------------------------------------------------------------------------ the check


def rd(d, at, n):
    return int.from_bytes(d[at:at + n], "little")


def verify_block(d, at, limit):
    """Checks the sizes of a structure at d[at]; returns (version, kind, sizes dict, code_offset, code, end)."""
    first, second = rd(d, at, 4), rd(d, at + 4, 4)
    if first == 0x844BDCD1 and second == 0x73D71034:
        names = ["codeword", "magic", "image_id", "r1", "r2", "image_src", "image_dest", "image_size", "code_size", "sig_ptr", "sig_size", "cert_ptr", "cert_size"]
        hs = 80
        w = {n: rd(d, at + 4 * i, 4) for i, n in enumerate(names)}
        sizes = dict(meta_qti=0, meta=0, code=w["code_size"], sig_qti=0, cert_qti=0, sig=w["sig_size"], cert=w["cert_size"])
        image_size = w["image_size"]
        version = "sbl"
    else:
        version = second
        hs = {3: 40, 5: 40, 6: 48, 7: 64}[version]
        if version in (3, 5, 6):
            w = {n: rd(d, at + 4 * i, 4) for i, n in enumerate(["image_id", "version", "w2", "w3", "image_size", "code_size", "sig_ptr", "sig_size", "cert_ptr", "cert_size", "meta_qti", "meta"][:hs // 4])}
            sizes = dict(meta_qti=w.get("meta_qti", 0), meta=w.get("meta", 0), code=w["code_size"], sig_qti=w["w2"] if version >= 5 else 0, cert_qti=w["w3"] if version >= 5 else 0,
                         sig=w["sig_size"], cert=w["cert_size"])
            image_size = w["image_size"]
        else:
            w = {n: rd(d, at + 4 * i, 4) for i, n in enumerate(["reserved", "version", "common", "meta_qti", "meta", "code_size", "sig_qti", "cert_qti", "sig", "cert"])}
            sizes = dict(meta_qti=w["meta_qti"], meta=w["meta"], code=w["code_size"], sig_qti=w["sig_qti"], cert_qti=w["cert_qti"], sig=w["sig"], cert=w["cert"])
            image_size = sum(sizes.values())
    total = sum(sizes.values())
    assert 0 <= image_size - total <= 3, f"image_size {image_size} is not the size of the parts {total}"
    end = at + hs + image_size
    assert end <= limit, f"the structure ends at {end}, past {limit}"
    code_at = at + hs + sizes["meta_qti"] + sizes["meta"]
    return version, sizes, code_at, d[code_at:code_at + sizes["code"]], end


def verify(path):
    d = open(path, "rb").read()
    if d[:4] == b"\x7fELF":
        is64 = d[4] == 2
        if is64:
            phoff, = struct.unpack_from("<Q", d, 32)
            phentsize, phnum = struct.unpack_from("<HH", d, 54)
            ehsize, = struct.unpack_from("<H", d, 52)
        else:
            phoff, = struct.unpack_from("<I", d, 28)
            phentsize, phnum = struct.unpack_from("<HH", d, 42)
            ehsize, = struct.unpack_from("<H", d, 40)
        phs = []
        for i in range(phnum):
            o = phoff + i * phentsize
            if is64:
                t, f, off, va, pa, fs_, ms, al = struct.unpack_from("<IIQQQQQQ", d, o)
            else:
                t, off, va, pa, fs_, ms, f, al = struct.unpack_from("<8I", d, o)
            phs.append(dict(type=t, flags=f, offset=off, vaddr=va, filesz=fs_, memsz=ms))
        hash_i = next(i for i, p in enumerate(phs) if (p["flags"] >> 24) & 7 == 2)
        h = phs[hash_i]
        version, sizes, code_at, table, end = verify_block(d, h["offset"], h["offset"] + h["filesz"])
        headers = d[:max(ehsize, phoff + phnum * phentsize)]
        segs = []
        for i, p in enumerate(phs):
            if i == hash_i or (p["type"] == 0 and (p["flags"] >> 24) & 7 == 7 and p["offset"] == 0):
                continue
            segs.append(dict(flags=p["flags"], vaddr=p["vaddr"], data=d[p["offset"]:p["offset"] + p["filesz"]]))
        # (the entries are in the order of the program headers; this expects the placeholder first and the hash segment second, as the images of this script have them)
        assert phs[0]["offset"] == 0 and hash_i == 1, "this check knows the order placeholder, hash segment, segments"
        ds = len(table) // len(table_entries(segs, "sha256", headers))
        algo = {20: "sha1", 32: "sha256", 48: "sha384"}[ds]
        want = b"".join(table_entries(segs, algo, headers))
        assert table == want, "the table of hashes is not the one made of the segments"
        print(f"{path}: ELF{64 if is64 else 32}, {phnum} program headers, structure version {version}, {algo} table of {len(table) // ds} entries: every one is right")
    else:
        version, sizes, code_at, code, end = verify_block(d, 0, len(d))
        print(f"{path}: flat, version {version}, sizes {sizes}, ends at {end} of {len(d)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "make":
        sys.exit(make(sys.argv[2]))
    if len(sys.argv) >= 3 and sys.argv[1] == "verify":
        sys.exit(verify(sys.argv[2]))
    print(__doc__)
    sys.exit(2)
