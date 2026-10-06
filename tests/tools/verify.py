#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent checks of abr's output, written from the formats (AOSP
bootimg.h, avbtool) and not from abr's code.

    verify.py boot-id <image> <scheme>            sha1|sha1_dt|sha256|sha256_dt
    verify.py avb-footer <image> [pubkey.pem]     every HASH descriptor, size, layout
    verify.py boot-field <image> <field>          print one header field (v0-v2)
    verify.py ramdisk <image> <out>               slice the ramdisk out of a boot image (v0-v4)

Exit status 0 = verified, 1 = mismatch (details on stderr), 2 = usage.
"""
import hashlib
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(msg):
    print("verify: " + msg, file=sys.stderr)
    sys.exit(1)


# ------------------------------------------------------------ boot id ----

def _page_size(v):
    return 2048 <= v <= 131072 and v & (v - 1) == 0


def parse_boot_pxa(d):
    """Marvell PXA header: v0 with `unknown` behind dt_size (osm0sis/pxa-mkbootimg bootimg.h)."""
    (ksz, _ka, rsz, _ra, ssz, _sa, dt_size, unknown, _ta, page) = struct.unpack_from("<10I", d, 8)
    f = {"version": 0, "page": page, "dt_size": dt_size, "id": d[584:616], "unknown": unknown,
         "dtbo": b"", "dtb": b""}
    pos = page

    def take(n):
        nonlocal pos
        data = d[pos:pos + n]
        pos += -(-n // page) * page
        return data

    f["kernel"], f["ramdisk"], f["second"] = take(ksz), take(rsz), take(ssz)
    f["dt"] = take(dt_size) if dt_size else b""
    return f


def parse_boot_012(d):
    if d[:8] != b"ANDROID!":
        fail("no ANDROID! magic at offset 0")
    if not _page_size(struct.unpack_from("<I", d, 36)[0]) and _page_size(struct.unpack_from("<I", d, 44)[0]):
        return parse_boot_pxa(d)
    (ksz, _ka, rsz, _ra, ssz, _sa, _ta, page, word10, _osv) = struct.unpack_from("<10I", d, 8)
    version = word10 if word10 <= 8 else 0
    dt_size = word10 if word10 > 8 else 0
    f = {"version": version, "page": page, "dt_size": dt_size, "id": d[576:608]}
    dtbo_size = dtb_size = 0
    if version >= 1:
        dtbo_size, _off, _hs = struct.unpack_from("<IQI", d, 1632)
    if version >= 2:
        dtb_size, _addr = struct.unpack_from("<IQ", d, 1648)
    pos = page

    def take(n):
        nonlocal pos
        data = d[pos:pos + n]
        pos += -(-n // page) * page
        return data

    f["kernel"], f["ramdisk"], f["second"] = take(ksz), take(rsz), take(ssz)
    f["dt"] = take(dt_size) if dt_size else b""
    f["dtbo"] = take(dtbo_size) if version >= 1 else b""
    f["dtb"] = take(dtb_size) if version >= 2 else b""
    return f


def boot_id(f, scheme):
    h = hashlib.sha256() if scheme.startswith("sha256") else hashlib.sha1()

    def feed(x):
        h.update(x)
        h.update(struct.pack("<I", len(x)))

    feed(f["kernel"])
    feed(f["ramdisk"])
    feed(f["second"])
    if scheme.endswith("_dt"):
        feed(f["dt"])
    if f["version"] >= 1:
        feed(f["dtbo"])
    if f["version"] >= 2:
        feed(f["dtb"])
    return h.digest()


def cmd_boot_id(path, scheme):
    f = parse_boot_012(Path(path).read_bytes())
    want = boot_id(f, scheme)
    got = f["id"][:len(want)]
    if want != got:
        fail(f"id mismatch for scheme {scheme}: header has {got.hex()}, content gives {want.hex()}")
    print(f"boot id ok ({scheme}): {got.hex()}")


def cmd_boot_field(path, field):
    f = parse_boot_012(Path(path).read_bytes())
    v = f[field]
    print(len(v) if isinstance(v, bytes) else v)


def boot_ramdisk(d):
    if d[:8] != b"ANDROID!":
        fail("no ANDROID! magic at offset 0")
    if struct.unpack_from("<I", d, 40)[0] in (3, 4):  # v3/v4: 4096-byte pages, sizes at 8 and 12
        ksz, rsz = struct.unpack_from("<2I", d, 8)
        pos = 4096 + -(-ksz // 4096) * 4096
        return d[pos:pos + rsz]
    return parse_boot_012(d)["ramdisk"]


def cmd_ramdisk(path, out):
    # The codec tests decompress this with the real gzip/lz4/zstd/xz/bzip2/lzop,
    # so the slicing has to be independent of abr.
    Path(out).write_bytes(boot_ramdisk(Path(path).read_bytes()))


# ------------------------------------------------------------ AVB ----

def cmd_avb_footer(path, pubkey=None):
    d = Path(path).read_bytes()
    magic, vmaj, _vmin, orig, voff, vsize = struct.unpack(">4sIIQQQ", d[-64:][:36])
    if magic != b"AVBf":
        fail("no AVBf footer in the last 64 bytes")
    if orig > voff or orig > len(d):
        fail(f"original_image_size {orig} is inconsistent with vbmeta offset {voff}")
    if voff % 4096 or voff < orig or voff - orig >= 4096:
        fail(f"vbmeta offset {voff} is not the next 4096 boundary after original size {orig}")
    vb = d[voff:voff + vsize]
    (vmagic, _a, _b, auth_size, aux_size, algo, hash_off, hash_size, sig_off, sig_size,
     _pko, _pks, _pmo, _pms, desc_off, desc_size) = struct.unpack_from(">4sIIQQIQQQQQQQQQQ", vb, 0)
    if vmagic != b"AVB0":
        fail("vbmeta blob does not start with AVB0")
    aux = vb[256 + auth_size:256 + auth_size + aux_size]
    descs = aux[desc_off:desc_off + desc_size]
    host = d[:orig]
    checked = pos = 0
    while pos + 16 <= len(descs):
        tag, nbf = struct.unpack_from(">QQ", descs, pos)
        payload = descs[pos + 16:pos + 16 + nbf]
        pos += 16 + nbf
        if tag != 2:
            continue
        image_size, algo_name = struct.unpack_from(">Q32s", payload, 0)
        name_len, salt_len, digest_len, _flags = struct.unpack_from(">IIII", payload, 40)
        base = 116
        salt = payload[base + name_len:base + name_len + salt_len]
        digest = payload[base + name_len + salt_len:base + name_len + salt_len + digest_len]
        if image_size != orig:
            fail(f"hash descriptor image_size {image_size} != footer original size {orig}")
        h = hashlib.new(algo_name.rstrip(b"\0").decode())
        h.update(salt + host)
        if h.digest() != digest:
            fail(f"hash descriptor digest does not match the first {orig} bytes of the image")
        checked += 1
    if not checked:
        fail("no HASH descriptor found")
    msg = f"avb footer ok: {checked} hash descriptor(s) match the host ({orig} bytes)"
    if algo != 0:
        auth = vb[256:256 + auth_size]
        embedded_hash = auth[hash_off:hash_off + hash_size]
        sig = auth[sig_off:sig_off + sig_size]
        if hashlib.sha256(vb[:256] + aux).digest() != embedded_hash:
            fail("vbmeta header+aux hash does not match the authentication block")
        if pubkey:
            with tempfile.TemporaryDirectory() as t:
                (Path(t) / "sig").write_bytes(sig)
                (Path(t) / "dig").write_bytes(embedded_hash)
                r = subprocess.run(
                    ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pubkey,
                     "-sigfile", str(Path(t) / "sig"), "-in", str(Path(t) / "dig"),
                     "-pkeyopt", "digest:sha256", "-pkeyopt", "rsa_padding_mode:pkcs1"],
                    capture_output=True)
                if r.returncode != 0:
                    fail("vbmeta signature rejected by openssl")
            msg += "; vbmeta RSA signature verified by openssl"
    print(msg)


def main(argv):
    try:
        if argv[1] == "boot-id" and len(argv) == 4:
            return cmd_boot_id(argv[2], argv[3])
        if argv[1] == "boot-field" and len(argv) == 4:
            return cmd_boot_field(argv[2], argv[3])
        if argv[1] == "ramdisk" and len(argv) == 4:
            return cmd_ramdisk(argv[2], argv[3])
        if argv[1] == "avb-footer" and len(argv) in (3, 4):
            return cmd_avb_footer(argv[2], argv[3] if len(argv) == 4 else None)
    except IndexError:
        pass
    print(__doc__, file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main(sys.argv)
