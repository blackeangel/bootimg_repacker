#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""An independent maker and reader of ChromeOS kernel blobs, to judge abr by.

Written from vboot_reference's layout (firmware/2lib/include/2struct.h, futility/cmd_vbutil_kernel.c) and shares no
code with abr; the RSA is Python's own big integers. It makes what `futility vbutil_kernel --pack` makes (the test
suite checks that where futility is installed), for any version of the preamble, any algorithm, any keyblock:

    chromeos_tool.py make OUT --kernel F --keyblock F --key F.vbprivk [--minor 0|1|2] [--kernel-version N]
                      [--flags N] [--load ADDR] [--bootloader-address ADDR] [--config F] [--params F]
                      [--bootloader F] [--bootloader-size N] [--pad N] [--vmlinuz-header-address ADDR] [--tail F]
                      [--fill-to N]
    chromeos_tool.py keyblock OUT --key F.vbprivk [--flags N] [--version N]   (a keyblock with a checksum, not signed)
    chromeos_tool.py dump BLOB          the fields, as key=value lines (the signatures are checked)
    chromeos_tool.py verify BLOB        exit 0 when both signatures verify with the keyblock's data key
    chromeos_tool.py kernel BLOB OUT    the kernel field of the body
    chromeos_tool.py field BLOB NAME OUT  config | params | bootloader | keyblock
    chromeos_tool.py corrupt BLOB OUT WHAT  a blob damaged in one way: what abr must refuse (a layout futility does not
                                            write), or what it must keep as it is (a signature that is bad, a data key that
                                            is unreadable)
    chromeos_tool.py algorithms         the algorithm numbers
    chromeos_tool.py vbprivk OUT --pem F.pem --algorithm N   a .vbprivk from a PKCS#1 PEM key (openssl genrsa -traditional)
    chromeos_tool.py devkeys SRC.cpp OUTDIR   kernel.keyblock and kernel_data_key.vbprivk, read out of the C++ source
                                              abr embeds them in (src/legacy/chromeos_devkeys.cpp)
"""
import base64
import hashlib
import re
import struct
import sys

ALIGN = 4096
CONFIG = 4096
PARAMS = 4096
KEYBLOCK_HEADER = 112
DIGEST_INFO = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def algorithms():
    """id -> (bits, exponent, hash)"""
    table = {}
    for i, bits in enumerate((1024, 2048, 4096, 8192)):
        for j, h in enumerate(("sha1", "sha256", "sha512")):
            table[i * 3 + j] = (bits, 65537, h)
    for j, h in enumerate(("sha1", "sha256", "sha512")):
        table[12 + j] = (2048, 3, h)
        table[15 + j] = (3072, 3, h)
    return table


ALGS = algorithms()


def roundup(n, to=ALIGN):
    return (n + to - 1) // to * to


# ------------------------------------------------------------------ DER / keys
def der_read(d, pos):
    tag = d[pos]
    n = d[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(d[pos:pos + k], "big")
        pos += k
    return tag, d[pos:pos + n], pos + n


def load_vbprivk(path):
    return load_vbprivk_from(open(path, "rb").read())


def load_vbprivk_from(raw):
    alg = struct.unpack_from("<Q", raw, 0)[0]
    tag, body, _ = der_read(raw[8:], 0)
    assert tag == 0x30
    ints = []
    pos = 0
    while pos < len(body):
        t, v, pos = der_read(body, pos)
        assert t == 0x02
        ints.append(int.from_bytes(v, "big"))
    _, n, e, d = ints[:4]
    return alg, n, e, d


def packed_pubkey(n, bits):
    words = bits // 32
    n0inv = (-pow(n, -1, 1 << 32)) % (1 << 32)
    rr = pow(1 << bits, 2, n)
    return struct.pack("<II", words, n0inv) + n.to_bytes(bits // 8, "little") + rr.to_bytes(bits // 8, "little")


def hash_of(name, data):
    return hashlib.new(name, data).digest()


def sign(n, d, bits, hname, data):
    k = bits // 8
    t = DIGEST_INFO[hname] + hash_of(hname, data)
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def verify_sig(n, e, bits, hname, data, sig):
    k = bits // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = DIGEST_INFO[hname] + hash_of(hname, data)
    return em == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


# ------------------------------------------------------------------ keyblock
def make_keyblock(n, alg, flags=7, key_version=1):
    """A keyblock with a SHA-512 checksum and no signature (what a developer-mode device accepts)."""
    bits, _, _ = ALGS[alg]
    key = packed_pubkey(n, bits)
    signed_len = KEYBLOCK_HEADER + len(key)
    size = signed_len + 64
    kb = bytearray(size)
    kb[0:8] = b"CHROMEOS"
    struct.pack_into("<II", kb, 8, 2, 1)
    struct.pack_into("<Q", kb, 16, size)
    # keyblock_signature: none (offset behind the checksum, size 0), data_size = what the checksum covers
    struct.pack_into("<IIIIII", kb, 24, size - 24, 0, 0, 0, signed_len, 0)
    # keyblock_hash: SHA-512 of the header and the key
    struct.pack_into("<IIIIII", kb, 48, signed_len - 48, 0, 64, 0, signed_len, 0)
    struct.pack_into("<II", kb, 72, flags, 0)
    struct.pack_into("<QQQQ", kb, 80, KEYBLOCK_HEADER - 80, len(key), alg, key_version)
    kb[KEYBLOCK_HEADER:signed_len] = key
    kb[signed_len:size] = hashlib.sha512(bytes(kb[:signed_len])).digest()
    return bytes(kb)


def keyblock_data_key(kb):
    off, size, alg, version = struct.unpack_from("<QQQQ", kb, 80)
    key = kb[80 + off:80 + off + size]
    bits = ALGS[alg][0]
    words = struct.unpack_from("<I", key, 0)[0]
    assert words * 32 == bits and size == 8 + 8 * words
    n = int.from_bytes(key[8:8 + bits // 8], "little")
    return alg, version, n


# ------------------------------------------------------------------ blobs
def preamble_fixed(minor):
    return {0: 96, 1: 112, 2: 116}[minor]


def make_blob(kernel, keyblock, key, minor=2, kernel_version=1, flags=0, load=0x100000, bootloader_address=None,
              config=b"", params=b"", bootloader=b"", bootloader_size=None, pad=0x10000, vmlinuz_header_address=0):
    alg, n, e, d = key
    bits, _, hname = ALGS[alg]
    k = roundup(len(kernel))
    if bootloader_size is None:
        bootloader_size = roundup(len(bootloader))
    assert len(config) <= CONFIG and len(params) <= PARAMS and len(bootloader) <= bootloader_size
    body = kernel + b"\0" * (k - len(kernel))
    body += config + b"\0" * (CONFIG - len(config))
    body += params + b"\0" * (PARAMS - len(params))
    body += bootloader + b"\0" * (bootloader_size - len(bootloader))
    if bootloader_address is None:
        bootloader_address = load + k + CONFIG + PARAMS
    fixed = preamble_fixed(minor)
    sig = bits // 8
    preamble_size = pad - len(keyblock)
    assert preamble_size >= fixed + 2 * sig
    pre = bytearray(preamble_size)
    struct.pack_into("<I", pre, 0, preamble_size)
    struct.pack_into("<IIIIII", pre, 8, fixed + sig - 8, 0, sig, 0, fixed + sig, 0)  # the preamble's signature
    struct.pack_into("<II", pre, 32, 2, minor)
    struct.pack_into("<I", pre, 40, kernel_version)
    struct.pack_into("<QQ", pre, 48, load, bootloader_address)
    struct.pack_into("<I", pre, 64, bootloader_size)
    struct.pack_into("<IIIIII", pre, 72, fixed - 72, 0, sig, 0, len(body), 0)  # the body's signature
    if minor >= 1:
        struct.pack_into("<QI", pre, 96, vmlinuz_header_address, 0)
    if minor >= 2:
        struct.pack_into("<I", pre, 112, flags)
    pre[fixed:fixed + sig] = sign(n, d, bits, hname, body)
    pre[fixed + sig:fixed + 2 * sig] = sign(n, d, bits, hname, bytes(pre[:fixed + sig]))
    return keyblock + bytes(pre) + body


class Blob:
    def __init__(self, data):
        self.data = data
        assert data[:8] == b"CHROMEOS"
        self.kb_size = struct.unpack_from("<Q", data, 16)[0]
        self.keyblock = data[:self.kb_size]
        p = self.kb_size
        self.pre_off = p
        self.preamble_size = struct.unpack_from("<I", data, p)[0]
        self.major, self.minor = struct.unpack_from("<II", data, p + 32)
        self.fixed = preamble_fixed(self.minor)
        self.kernel_version = struct.unpack_from("<I", data, p + 40)[0]
        self.load, self.bootloader_address = struct.unpack_from("<QQ", data, p + 48)
        self.bootloader_size = struct.unpack_from("<I", data, p + 64)[0]
        self.bsig_size = struct.unpack_from("<I", data, p + 80)[0]
        self.body_size = struct.unpack_from("<I", data, p + 88)[0]
        self.psig_size = struct.unpack_from("<I", data, p + 16)[0]
        self.vmlinuz_header_address = struct.unpack_from("<Q", data, p + 96)[0] if self.minor >= 1 else 0
        self.vmlinuz_header_size = struct.unpack_from("<I", data, p + 104)[0] if self.minor >= 1 else 0
        self.flags = struct.unpack_from("<I", data, p + 112)[0] if self.minor >= 2 else 0
        self.body_off = p + self.preamble_size
        self.body = data[self.body_off:self.body_off + self.body_size]
        self.body_sig = data[p + self.fixed:p + self.fixed + self.bsig_size]
        self.pre_sig = data[p + self.fixed + self.bsig_size:p + self.fixed + self.bsig_size + self.psig_size]
        self.pre_head = data[p:p + self.fixed + self.bsig_size]
        self.kernel_size = self.body_size - CONFIG - PARAMS - self.bootloader_size
        self.kernel = self.body[:self.kernel_size]
        self.config = self.body[self.kernel_size:self.kernel_size + CONFIG]
        self.params = self.body[self.kernel_size + CONFIG:self.kernel_size + CONFIG + PARAMS]
        self.bootloader = self.body[self.kernel_size + CONFIG + PARAMS:]
        self.tail = data[self.body_off + self.body_size:]

    def check(self):
        alg, version, n = keyblock_data_key(self.keyblock)
        bits, e, hname = ALGS[alg]
        return (verify_sig(n, e, bits, hname, self.body, self.body_sig),
                verify_sig(n, e, bits, hname, self.pre_head, self.pre_sig))


def trim0(b):
    return b.rstrip(b"\0")


# ------------------------------------------------------------------ the commands
def read(path):
    return open(path, "rb").read()


def opt(args, name, default=None):
    if name in args:
        i = args.index(name)
        return args[i + 1]
    return default


def cmd_make(args):
    out = args[0]
    kernel = read(opt(args, "--kernel"))
    keyblock = read(opt(args, "--keyblock"))
    key = load_vbprivk(opt(args, "--key"))
    kw = {}
    if opt(args, "--minor"): kw["minor"] = int(opt(args, "--minor"))
    if opt(args, "--kernel-version"): kw["kernel_version"] = int(opt(args, "--kernel-version"), 0)
    if opt(args, "--flags"): kw["flags"] = int(opt(args, "--flags"), 0)
    if opt(args, "--load"): kw["load"] = int(opt(args, "--load"), 0)
    if opt(args, "--bootloader-address"): kw["bootloader_address"] = int(opt(args, "--bootloader-address"), 0)
    if opt(args, "--config"): kw["config"] = read(opt(args, "--config"))
    if opt(args, "--params"): kw["params"] = read(opt(args, "--params"))
    if opt(args, "--bootloader"): kw["bootloader"] = read(opt(args, "--bootloader"))
    if opt(args, "--bootloader-size"): kw["bootloader_size"] = int(opt(args, "--bootloader-size"), 0)
    if opt(args, "--pad"): kw["pad"] = int(opt(args, "--pad"), 0)
    if opt(args, "--vmlinuz-header-address"): kw["vmlinuz_header_address"] = int(opt(args, "--vmlinuz-header-address"), 0)
    blob = make_blob(kernel, keyblock, key, **kw)
    if opt(args, "--tail"): blob += read(opt(args, "--tail"))
    if opt(args, "--fill-to"):
        blob += b"\0" * (int(opt(args, "--fill-to"), 0) - len(blob))
    open(out, "wb").write(blob)


def cmd_keyblock(args):
    alg, n, e, d = load_vbprivk(opt(args, "--key"))
    flags = int(opt(args, "--flags", "7"), 0)
    version = int(opt(args, "--version", "1"), 0)
    open(args[0], "wb").write(make_keyblock(n, alg, flags, version))


def cmd_dump(args):
    b = Blob(read(args[0]))
    alg, version, n = keyblock_data_key(b.keyblock)
    ok_body, ok_pre = b.check()
    print("preamble_version=%d.%d" % (b.major, b.minor))
    print("kernel_version=%d" % b.kernel_version)
    print("flags=0x%x" % b.flags)
    print("load=0x%x" % b.load)
    print("bootloader_address=0x%x" % b.bootloader_address)
    print("bootloader_size=%d" % b.bootloader_size)
    print("vblock_size=%d" % (b.kb_size + b.preamble_size))
    print("keyblock_size=%d" % b.kb_size)
    print("kernel_size=%d" % b.kernel_size)
    print("config=%s" % trim0(b.config).decode("latin-1"))
    print("params_size=%d" % len(trim0(b.params)))
    print("bootloader_used=%d" % len(trim0(b.bootloader)))
    print("data_key_algorithm=%d" % alg)
    print("tail=%d" % len(b.tail))
    print("body_signature=%s" % ("ok" if ok_body else "BAD"))
    print("preamble_signature=%s" % ("ok" if ok_pre else "BAD"))


def cmd_verify(args):
    ok_body, ok_pre = Blob(read(args[0])).check()
    sys.exit(0 if ok_body and ok_pre else 1)


def cmd_kernel(args):
    open(args[1], "wb").write(Blob(read(args[0])).kernel)


def cmd_field(args):
    b = Blob(read(args[0]))
    value = {"config": trim0(b.config), "params": trim0(b.params), "bootloader": trim0(b.bootloader),
             "keyblock": b.keyblock}[args[1]]
    open(args[2], "wb").write(value)


def cmd_corrupt(args):
    data = bytearray(read(args[0]))
    out, what = args[1], args[2]
    b = Blob(bytes(data))
    p = b.pre_off
    if what == "short-keyblock":
        data = data[:100]
    elif what == "short-preamble":
        data = data[:b.kb_size + 90]
    elif what == "short-preamble-body":
        data = data[:b.kb_size + b.preamble_size - 1]
    elif what == "short-body":
        data = data[:b.body_off + b.body_size - 1]
    elif what == "keyblock-version":
        struct.pack_into("<I", data, 8, 3)
    elif what == "keyblock-size-small":
        struct.pack_into("<Q", data, 16, 50)
    elif what == "preamble-major":
        struct.pack_into("<I", data, p + 32, 3)
    elif what == "preamble-minor":
        struct.pack_into("<I", data, p + 36, 3)
    elif what == "preamble-reserved":
        struct.pack_into("<I", data, p + 4, 1)
    elif what == "descriptor-reserved":
        struct.pack_into("<I", data, p + 76, 1)
    elif what == "field-reserved":
        struct.pack_into("<I", data, p + 44, 1)
    elif what == "x86":
        struct.pack_into("<I", data, p + 104, 4096)
    elif what == "sig-layout":
        struct.pack_into("<I", data, p + 72, 200)
    elif what == "psig-layout":
        struct.pack_into("<I", data, p + 8, 500)
    elif what == "pre-data-size":
        struct.pack_into("<I", data, p + 24, 100)
    elif what == "empty-signature":
        struct.pack_into("<I", data, p + 80, 0)
    elif what == "pad-nonzero":
        data[b.kb_size + b.preamble_size - 5] = 1
    elif what == "bootloader-size":
        struct.pack_into("<I", data, p + 64, b.bootloader_size + 100)
    elif what == "kernel-unaligned":
        struct.pack_into("<I", data, p + 88, b.body_size - 100)
        data = data[:b.body_off + b.body_size - 100]
    elif what == "body-small":
        struct.pack_into("<I", data, p + 88, 8192)
    elif what == "preamble-size-small":
        struct.pack_into("<I", data, p, 50)
    # damage that leaves the layout whole: what abr must keep as it is, not repair
    elif what == "body-byte":          # the kernel changed behind the signatures' backs: the body signature is bad
        data[b.body_off + 5000] ^= 1   # (inside the kernel of the boot image in it, not in its header)
    elif what == "body-sig-byte":      # the body signature itself: it is bad, and the preamble signature covers it
        data[p + b.fixed + 5] ^= 1
    elif what == "pre-sig-byte":       # only the preamble signature is bad
        data[p + b.fixed + b.bsig_size + 5] ^= 1
    elif what == "kb-algorithm":       # a data key of an algorithm nobody knows
        struct.pack_into("<Q", data, 80 + 16, 99)
    elif what == "kb-arrsize":         # a packed key that is not the size of its algorithm
        struct.pack_into("<I", data, 80 + struct.unpack_from("<Q", data, 80)[0], 3)
    elif what == "kb-outside":         # a data key that lies outside of the keyblock
        struct.pack_into("<Q", data, 80, 0xFFFFFFFF)
    else:
        sys.exit("unknown damage: " + what)
    open(out, "wb").write(bytes(data))


def cmd_vbprivk(args):
    """.vbprivk: the algorithm as a u64, then the DER RSAPrivateKey (PKCS#1) -- what vboot's own tools write."""
    alg = int(opt(args, "--algorithm"), 0)
    if alg not in ALGS:
        sys.exit("no algorithm %d" % alg)
    lines = open(opt(args, "--pem")).read().strip().splitlines()
    if not lines or lines[0] != "-----BEGIN RSA PRIVATE KEY-----" or lines[-1] != "-----END RSA PRIVATE KEY-----":
        sys.exit("not a PKCS#1 PEM key (make it with `openssl genrsa -traditional`)")
    der = base64.b64decode("".join(lines[1:-1]))
    _, n, e, d = load_vbprivk_from(struct.pack("<Q", alg) + der)
    if n.bit_length() != ALGS[alg][0]:
        sys.exit("the key has %d bits, algorithm %d wants %d" % (n.bit_length(), alg, ALGS[alg][0]))
    if e != ALGS[alg][1]:
        sys.exit("the key has the public exponent %d, algorithm %d wants %d" % (e, alg, ALGS[alg][1]))
    open(args[0], "wb").write(struct.pack("<Q", alg) + der)


def cmd_devkeys(args):
    """The developer keyblock and key, from the C arrays of the source abr embeds them in."""
    src = open(args[0]).read()
    out = args[1]

    def array(name):
        m = re.search(r"const uint8_t %s\[\] = \{(.*?)\};" % name, src, re.S)
        if not m:
            sys.exit("no array %s in %s" % (name, args[0]))
        return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))

    open(out + "/kernel.keyblock", "wb").write(array("kChromeosDevKeyblock"))
    open(out + "/kernel_data_key.vbprivk", "wb").write(array("kChromeosDevKernelDataKey"))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "algorithms":
        for i, (bits, e, h) in sorted(ALGS.items()):
            print(i, bits, e, h)
        return
    {"make": cmd_make, "keyblock": cmd_keyblock, "dump": cmd_dump, "verify": cmd_verify, "kernel": cmd_kernel,
     "field": cmd_field, "corrupt": cmd_corrupt, "vbprivk": cmd_vbprivk,
     "devkeys": cmd_devkeys}.get(cmd, lambda a: sys.exit(__doc__))(args)


main()
