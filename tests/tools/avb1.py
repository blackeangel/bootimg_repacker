#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""An independent implementation of the AOSP boot_signer ("AVBv1") boot
signature, for tests/run_tests.sh. It shares no code with abr: the DER is
assembled here and the RSA/ECDSA signature comes from the `openssl` command.

    avb1.py size   <image>                                   page-aligned image size (what the signature covers)
    avb1.py sign   <image> <target> <key.pem> <cert.pem> [--ec]
                                                             write  image[:size] + signature  to stdout
    avb1.py der    <image> <target> <key.pem> <cert.pem> [--ec]
                                                             write only the signature DER to stdout
    avb1.py verify <image> [<cert.pem>]                      exit 0 and print "VALID" if the signature
                                                             after the image checks out with the key
                                                             in its own (or the given) certificate
    avb1.py show   <image>                                   target / length / cert sha256 / algorithm

The size rule is AOSP's BootSignature.getSignableImageSize(): header page +
page-aligned kernel, ramdisk, second, (v1..v4: recovery dtbo), (v2: dtb),
(v0 with a Qualcomm dt: word 10 is that blob's size), rounded up to a page.
"""
import hashlib
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ALG_SHA256_RSA = bytes.fromhex("300b06092a864886f70d01010b")  # no NULL parameters, as boot_signer writes
ALG_ECDSA_SHA256 = bytes.fromhex("300a06082a8648ce3d040302")


def signable_size(d):
    if d[:8] != b"ANDROID!":
        raise SystemExit("not an Android boot image")
    kernel, _, ramdisk, _, second = struct.unpack_from("<5I", d, 8)
    page, word10 = struct.unpack_from("<2I", d, 36)

    def pages(n):
        return (n + page - 1) // page * page

    length = page + pages(kernel) + pages(ramdisk) + pages(second)
    if 0 < word10 <= 4:
        length += pages(struct.unpack_from("<I", d, 1632)[0])
        if word10 == 2:
            length += pages(struct.unpack_from("<I", d, 1648)[0])
    elif word10 > 4:
        length += pages(word10)  # CAF/QCDT device-tree blob
    return pages(length)


# ---------------------------------------------------------------- DER ----

def der(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([tag, n])
    else:
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(nb)]) + nb
    return head + body


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")  # +8: room for the sign bit
    return der(0x02, b)


def read_tlv(buf, off):
    tag = buf[off]
    n = buf[off + 1]
    hl = 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[off + 2:off + 2 + k], "big")
        hl = 2 + k
    return tag, buf[off + hl:off + hl + n], hl + n


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def cert_der(cert_pem):
    return openssl("x509", "-in", cert_pem, "-outform", "DER")


def attributes(target, length):
    return der(0x30, der(0x13, target.encode()) + der_int(length))


def signature_der(core, target, key_pem, cert_pem, ec=False):
    attrs = attributes(target, len(core))
    sig = openssl("dgst", "-sha256", "-sign", key_pem, data=core + attrs)
    alg = ALG_ECDSA_SHA256 if ec else ALG_SHA256_RSA
    return der(0x30, der_int(1) + cert_der(cert_pem) + alg + attrs + der(0x04, sig))


def parse_signature(d, off):
    tag, body, total = read_tlv(d, off)
    if tag != 0x30:
        raise SystemExit("no signature structure at offset %d" % off)
    pos = 0
    parts = []
    while pos < len(body):
        t, b, n = read_tlv(body, pos)
        parts.append((t, body[pos:pos + n], b))
        pos += n
    if len(parts) != 5:
        raise SystemExit("unexpected signature layout")
    cert = parts[1][1]
    alg = parts[2][1]
    attrs_raw = parts[3][1]
    _, attrs_body, _ = read_tlv(attrs_raw, 0)
    t0, target, n0 = read_tlv(attrs_body, 0)
    _, length_b, _ = read_tlv(attrs_body, n0)
    return {"cert": cert, "alg": alg, "target": target.decode(), "length": int.from_bytes(length_b, "big"),
            "sig": parts[4][2], "size": total}


def verify(d, cert_pem=None):
    size = signable_size(d)
    s = parse_signature(d, size)
    ok_len = s["length"] == size
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        if cert_pem is None:
            (t / "c.der").write_bytes(s["cert"])
            openssl("x509", "-inform", "DER", "-in", str(t / "c.der"), "-out", str(t / "c.pem"))
            cert_pem = str(t / "c.pem")
        pub = openssl("x509", "-in", cert_pem, "-pubkey", "-noout")
        (t / "pub.pem").write_bytes(pub)
        (t / "sig").write_bytes(s["sig"])
        signed = d[:s["length"]] + attributes(s["target"], s["length"])
        (t / "signed").write_bytes(signed)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(t / "pub.pem"), "-signature",
                            str(t / "sig"), str(t / "signed")], capture_output=True, text=True)
    return ok_len and r.returncode == 0, ok_len, s


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd, image = sys.argv[1], Path(sys.argv[2])
    d = image.read_bytes()
    ec = "--ec" in sys.argv
    args = [a for a in sys.argv[3:] if a != "--ec"]
    if cmd == "size":
        print(signable_size(d))
    elif cmd in ("sign", "der"):
        target, key, cert = args
        core = d[:signable_size(d)]
        sig = signature_der(core, target, key, cert, ec)
        sys.stdout.buffer.write((core + sig) if cmd == "sign" else sig)
    elif cmd == "verify":
        ok, ok_len, s = verify(d, args[0] if args else None)
        print("VALID" if ok else "INVALID" + ("" if ok_len else " (length field != image size)"))
        sys.exit(0 if ok else 1)
    elif cmd == "show":
        s = parse_signature(d, signable_size(d))
        print("target=%s length=%d cert_sha256=%s alg=%s der_size=%d" % (
            s["target"], s["length"], hashlib.sha256(s["cert"]).hexdigest(), s["alg"].hex(), s["size"]))
    else:
        sys.exit(__doc__)


main()
