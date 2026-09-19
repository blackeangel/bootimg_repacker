#!/usr/bin/env bash
# Round-trip regression suite for `abr`.
#
# Usage: tests/run_tests.sh [path-to-abr-binary]
#
# Builds real reference images with AOSP's own mkbootimg.py (vendored
# in tests/reference/mkbootimg/), the system `dtc` (device tree
# compiler) and `mkimage` (U-Boot), then checks that
# `abr unpack X && abr repack` reproduces each one byte-for-byte. Also
# exercises AVB vbmeta (unsigned, RSA-signed, and footer-attached)
# with a self-generated test key, cross-checking the RSA signature
# with `openssl pkeyutl -verify` independently of abr's own code.
#
# A byte-identical round trip on an *unmodified* image is the bar this
# suite holds `abr` to -- see save_component()/load_component() in
# src/main.cpp for how that's achieved despite decompressing components
# for editability (short version: the original compressed bytes are
# kept as a fallback and replayed verbatim when the decompressed
# extract comes back unchanged).
set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
ABR="${1:-$REPO_ROOT/build/abr}"
case "$ABR" in
    /*) ;;                  # already absolute
    *) ABR="$(pwd)/$ABR" ;; # make relative paths absolute before we cd elsewhere
esac

if [ ! -x "$ABR" ]; then
    echo "error: abr binary not found/executable at $ABR" >&2
    echo "       build it first, or pass its path as \$1" >&2
    exit 2
fi

for tool in python3 dtc mkimage openssl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: required tool '$tool' not found on PATH" >&2
        exit 2
    fi
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

PASS=0
FAIL=0
check() {
    if cmp -s "$1" "$2"; then
        echo "PASS: $3"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $3 ($1 vs $2 differ)"
        FAIL=$((FAIL + 1))
    fi
}
roundtrip_check() {
    local original="$1" label="$2" dir="rt_$3"
    "$ABR" unpack "$original" -o "$dir" >/dev/null
    "$ABR" repack "$dir" -o "${dir}.out" >/dev/null
    check "$original" "${dir}.out" "$label"
}

MKBOOTIMG="$REPO_ROOT/tests/reference/mkbootimg/mkbootimg.py"

# --------------------------------------------------------- boot v4 --
head -c 200000 /dev/urandom | gzip -9 >kernel.gz
head -c 500000 /dev/urandom >ramdisk.raw
lz4 -q -9 -f ramdisk.raw ramdisk.lz4 2>/dev/null || gzip -9 -c ramdisk.raw >ramdisk.lz4  # lz4 optional
python3 "$MKBOOTIMG" >/dev/null --header_version 4 --kernel kernel.gz --ramdisk ramdisk.lz4 \
    --cmdline "console=ttyMSM0,115200n8" --os_version 14.0.0 --os_patch_level 2024-05 \
    --output boot_v4.img
roundtrip_check boot_v4.img "boot v4 (compressed kernel+ramdisk)" bootv4

# --------------------------------------------------------- boot v2 --
head -c 100000 /dev/urandom | gzip -9 >kernel_v2.gz
head -c 200000 /dev/urandom | gzip -9 >ramdisk_v2.gz
cat >v2.dts <<'EOF'
/dts-v1/;
/ { model = "Test"; compatible = "test,board"; #address-cells=<1>; #size-cells=<1>; };
EOF
dtc -I dts -O dtb -o v2.dtb v2.dts 2>/dev/null
python3 "$MKBOOTIMG" >/dev/null --header_version 2 --kernel kernel_v2.gz --ramdisk ramdisk_v2.gz --dtb v2.dtb \
    --cmdline "console=ttyS0" --board "TestBoardV2" --base 0x10000000 --pagesize 2048 \
    --os_version 12.0.0 --os_patch_level 2022-03 --id --output boot_v2.img
roundtrip_check boot_v2.img "boot v2 (dtb, board name, content-hash id)" bootv2

# ------------------------------------------------------ vendor_boot v3 --
head -c 300000 /dev/urandom >vramdisk.raw
gzip -9 -c vramdisk.raw >vramdisk.gz
dtc -I dts -O dtb -o vendor.dtb v2.dts 2>/dev/null
python3 "$MKBOOTIMG" >/dev/null --header_version 3 --vendor_ramdisk vramdisk.gz --dtb vendor.dtb \
    --vendor_cmdline "androidboot.hardware=vendtest" --vendor_boot vendor_boot_v3.img
roundtrip_check vendor_boot_v3.img "vendor_boot v3 (single ramdisk)" vbv3

# ------------------------------------------------ vendor_boot v4 (multi) --
head -c 150000 /dev/urandom >frag_platform.raw
zstd -q -19 -f frag_platform.raw -o frag_platform.zst 2>/dev/null || gzip -9 -c frag_platform.raw >frag_platform.zst
head -c 80000 /dev/urandom >frag_dlkm.raw
lz4 -q -9 -f frag_dlkm.raw frag_dlkm.lz4 2>/dev/null || gzip -9 -c frag_dlkm.raw >frag_dlkm.lz4
printf 'androidboot.foo=bar\n' >bootconfig.txt
python3 "$MKBOOTIMG" >/dev/null --header_version 4 --dtb vendor.dtb \
    --vendor_cmdline "androidboot.hardware=vendtest4" --vendor_bootconfig bootconfig.txt \
    --ramdisk_type platform --ramdisk_name "" --vendor_ramdisk_fragment frag_platform.zst \
    --ramdisk_type dlkm --ramdisk_name "dlkm_frag" --board_id0 7 --vendor_ramdisk_fragment frag_dlkm.lz4 \
    --vendor_boot vendor_boot_v4.img
roundtrip_check vendor_boot_v4.img "vendor_boot v4 (2 typed/named fragments)" vbv4

# vendor_boot v4 with a trailing AVB hash-footer (unsigned, one hash +
# one property descriptor) -- mirrors a real OrangeFox recovery
# vendor_boot.img that first exposed this as a real gap: unpack was
# silently ignoring the footer since VendorBootImage doesn't need it,
# but repack was dropping it entirely instead of reproducing it.
python3 - <<'PYEOF'
import struct
vb = open("vendor_boot_v4.img", "rb").read()
descriptors = b""
partition = b"vendor_boot"
digest = b"\x11" * 32  # placeholder digest -- this test checks byte-for-byte
                        # tail preservation through unpack+repack, not AVB semantics
d1 = struct.pack(">Q", len(vb)) + b"sha256".ljust(32, b"\x00")
d1 += struct.pack(">III", len(partition), 0, len(digest)) + struct.pack(">I", 0) + b"\x00" * 60
d1 += partition + digest
descriptors += struct.pack(">QQ", 2, len(d1)) + d1  # tag 2 = HASH
prop_key = b"com.android.build.vendor_boot.fingerprint"
prop_val = b"test/fingerprint/0"
d0 = struct.pack(">QQ", len(prop_key), len(prop_val)) + prop_key + b"\x00" + prop_val + b"\x00"
d0 += b"\x00" * ((-len(d0)) % 8)
descriptors += struct.pack(">QQ", 0, len(d0)) + d0  # tag 0 = PROPERTY
desc_size = len(descriptors)
aux = descriptors + b"\x00" * ((-desc_size) % 64)
pubkey_off = desc_size + ((-desc_size) % 8)  # matches abr's own 8-byte-aligned layout convention
header = b"AVB0" + struct.pack(">II", 1, 0) + struct.pack(">QQ", 0, len(aux))
header += struct.pack(">I", 0)  # algorithm NONE
header += struct.pack(">QQQQQQQQQQ", 0, 0, 0, 0, pubkey_off, 0, pubkey_off, 0, 0, desc_size)
header += struct.pack(">Q", 0)  # rollback_index
header += struct.pack(">II", 0, 0)  # flags, rollback_index_location
header += b"avbtool 1.3.0".ljust(48, b"\x00")
header += b"\x00" * 80
assert len(header) == 256
vbmeta = header + aux
partition_size = len(vb) + ((-len(vb)) % 4096) + len(vbmeta) + ((-len(vbmeta)) % 4096) + 4096
out = bytearray(partition_size)
out[0:len(vb)] = vb
vbmeta_offset = len(vb) + ((-len(vb)) % 4096)
out[vbmeta_offset:vbmeta_offset + len(vbmeta)] = vbmeta
footer_pos = partition_size - 64
out[footer_pos:footer_pos + 64] = struct.pack(">4sIIQQQ28x", b"AVBf", 1, 0, len(vb), vbmeta_offset, len(vbmeta))
open("vendor_boot_v4_avbfooter.img", "wb").write(bytes(out))
PYEOF
roundtrip_check vendor_boot_v4_avbfooter.img "vendor_boot v4 + trailing AVB footer (hash+property descriptors)" vbv4avb
grep -q "^has_avb_footer=true" rt_vbv4avb/manifest.txt \
  && { echo "PASS: vendor_boot AVB footer decomposed into manifest fields"; PASS=$((PASS + 1)); } \
  || { echo "FAIL: vendor_boot AVB footer not recorded in manifest"; FAIL=$((FAIL + 1)); }

# --------------------------------------------------------------- dtb --
dtc -I dts -O dtb -o a.dtb v2.dts 2>/dev/null
cp a.dtb b.dtb
cat a.dtb b.dtb >concat.dtb
roundtrip_check a.dtb "dtb (single blob)" dtb1
roundtrip_check concat.dtb "dtb (2 concatenated blobs)" dtb2

# -------------------------------------------------------------- uimage --
head -c 65536 /dev/urandom >payload.bin
mkimage -q -A arm64 -O linux -T kernel -C none -a 0x80080000 -e 0x80080000 -n "Test" \
    -d payload.bin uimage_plain.img >/dev/null
roundtrip_check uimage_plain.img "uimage (uncompressed)" ui1
gzip -9 -c payload.bin >payload.gz
mkimage -q -A arm64 -O linux -T kernel -C gzip -a 0x80080000 -e 0x80080000 -n "Test" \
    -d payload.gz uimage_gz.img >/dev/null
roundtrip_check uimage_gz.img "uimage (gzip)" ui2

# ---------------------------------------------------------------- dtbo --
mkdir -p dtbo_manifest
cat >dtbo_manifest/manifest.txt <<EOF
type=dtbo
version=1
page_size=4096
acpio=false
entry_count=1
entry0_id=1
entry0_rev=0
entry0_extra=0200000000000000000000000000000000000000000000000000000000000000000000000000
entry0_file=entry0.dtb
EOF
# extra is 4 words (16 bytes = 32 hex chars); trim to correct length
python3 - <<'PYEOF'
import re
p = "dtbo_manifest/manifest.txt"
s = open(p).read()
s = s.replace("entry0_extra=0200000000000000000000000000000000000000000000000000000000000000000000000000",
              "entry0_extra=02000000000000000000000000000000")
open(p, "w").write(s)
PYEOF
cp a.dtb dtbo_manifest/entry0.dtb
"$ABR" repack dtbo_manifest -o dtbo_built.img >/dev/null
roundtrip_check dtbo_built.img "dtbo (v1, zlib-compressed entry)" dtbo1

# ------------------------------------------------------------------ lzo --
# Raw LZO1X has no magic, so it can only be exercised through a
# container that names its compression explicitly (a boot.img ramdisk
# here) rather than via detect_codec() on a bare blob.
python3 -c "open('lzo_payload.bin','wb').write((b'the quick brown fox jumps over the lazy dog ' * 5000)[:200000])"
mkdir -p lzo_manifest
cat >lzo_manifest/manifest.txt <<'EOF'
type=boot
header_version=4
os_version=14.0.0
os_patch_level=2024-05
cmdline=test
kernel_file=kernel
kernel_compression=none
ramdisk_file=ramdisk.cpio
ramdisk_compression=lzo
EOF
cp lzo_payload.bin lzo_manifest/kernel
cp lzo_payload.bin lzo_manifest/ramdisk.cpio
"$ABR" repack lzo_manifest -o lzo_boot.img >/dev/null
roundtrip_check lzo_boot.img "boot v4 (lzo ramdisk)" lzoboot

if python3 -c "import lzo" 2>/dev/null; then
    # abr's encoder -> independently decompressed by real liblzo2 (not minilzo)
    python3 - <<'PYEOF'
import struct, lzo, sys
raw = open("rt_lzoboot/.abr_raw/ramdisk.cpio.raw", "rb").read()
assert raw[:9] == b"\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a"
pos = 9
version = struct.unpack(">H", raw[pos:pos+2])[0]; pos += 7
if version >= 0x0940: pos += 1
flags = struct.unpack(">I", raw[pos:pos+4])[0]; pos += 4
if flags & 0x800: pos += 4
pos += 8
if version >= 0x0940: pos += 4
fname_len = raw[pos]; pos += 1 + fname_len + 4
out = b""
while True:
    dst_len = struct.unpack(">I", raw[pos:pos+4])[0]; pos += 4
    if dst_len == 0:
        break
    src_len = struct.unpack(">I", raw[pos:pos+4])[0]; pos += 8
    block = raw[pos:pos+src_len]; pos += src_len
    out += block if src_len == dst_len else lzo.decompress(block, False, dst_len)
sys.exit(0 if out == open("lzo_payload.bin", "rb").read() else 1)
PYEOF
    if [ $? -eq 0 ]; then
        echo "PASS: lzo -- abr's encoder output independently decompressed by real liblzo2"
        PASS=$((PASS + 1))
    else
        echo "FAIL: lzo -- abr's encoder output rejected by real liblzo2"
        FAIL=$((FAIL + 1))
    fi

    # real liblzo2 (not minilzo) -> abr's decoder, via a hand-built boot.img
    # so abr's own recompress-on-repack convenience doesn't mask the check
    python3 - <<'PYEOF'
import struct, lzo, zlib
payload = open("lzo_payload.bin", "rb").read()
block = lzo.compress(payload, 1, False)
h = bytearray()
h += b"\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a"
h += struct.pack(">H", 0x0100) * 3
h += bytes([1])
h += struct.pack(">I", 2)
h += struct.pack(">I", 0) * 2
h += bytes([0])
h += struct.pack(">I", zlib.adler32(bytes(h[9:])) & 0xffffffff)
h += struct.pack(">I", len(payload))
h += struct.pack(">I", len(block))
h += struct.pack(">I", zlib.adler32(block) & 0xffffffff)
h += block
h += struct.pack(">I", 0)
ramdisk = bytes(h)
kernel = b"x"
img = bytearray(b"ANDROID!")
img += struct.pack("<I", len(kernel)) + struct.pack("<I", len(ramdisk))
img += struct.pack("<I", 0) + struct.pack("<I", 1584) + b"\x00" * 16
img += struct.pack("<I", 4) + b"test".ljust(1536, b"\x00") + struct.pack("<I", 0)
img += b"\x00" * (4096 - len(img))
img += kernel + b"\x00" * ((-len(kernel)) % 4096)
img += ramdisk + b"\x00" * ((-len(ramdisk)) % 4096)
open("liblzo2_cross.img", "wb").write(bytes(img))
PYEOF
    "$ABR" unpack liblzo2_cross.img -o liblzo2_cross_unpacked >/dev/null
    if cmp -s lzo_payload.bin liblzo2_cross_unpacked/ramdisk.cpio; then
        echo "PASS: lzo -- abr's decoder correctly reads a real-liblzo2-produced stream"
        PASS=$((PASS + 1))
    else
        echo "FAIL: lzo -- abr's decoder misreads a real-liblzo2-produced stream"
        FAIL=$((FAIL + 1))
    fi
else
    echo "SKIP: lzo cross-validation against real liblzo2 (python-lzo not installed)"
fi

# --------------------------------------------------------------- vbmeta --
mkdir -p vbmeta_unsigned
cat >vbmeta_unsigned/manifest.txt <<'EOF'
type=vbmeta
required_libavb_version_major=1
required_libavb_version_minor=0
algorithm_type=0
rollback_index=0
flags=0
rollback_index_location=0
release_string=abr test 1.0
descriptor_count=1
descriptor0_tag=3
descriptor0_file=descriptor0.bin
EOF
python3 - <<'PYEOF'
import struct
cmdline = b"androidboot.veritymode=enforcing"
data = struct.pack(">II", 0, len(cmdline)) + cmdline
data += b"\x00" * ((-len(data)) % 8)
open("vbmeta_unsigned/descriptor0.bin", "wb").write(data)
PYEOF
"$ABR" repack vbmeta_unsigned -o vbmeta_unsigned.img >/dev/null
roundtrip_check vbmeta_unsigned.img "vbmeta (unsigned, kernel_cmdline descriptor)" vbu

openssl genrsa -out avb_test_key.pem 2048 >/dev/null 2>&1
openssl rsa -in avb_test_key.pem -pubout -out avb_test_key_pub.pem >/dev/null 2>&1
mkdir -p vbmeta_signed
cp vbmeta_unsigned/manifest.txt vbmeta_signed/manifest.txt
sed -i 's/algorithm_type=0/algorithm_type=1/' vbmeta_signed/manifest.txt
cp vbmeta_unsigned/descriptor0.bin vbmeta_signed/descriptor0.bin
"$ABR" repack vbmeta_signed -o vbmeta_signed.img --avb-key avb_test_key.pem >/dev/null
roundtrip_check vbmeta_signed.img "vbmeta (RSA-2048 signed, passthrough repack w/o key)" vbs

python3 - <<'PYEOF'
import struct, hashlib
data = open("vbmeta_signed.img", "rb").read()
(magic, maj, minr, auth_size, aux_size, algo, hash_off, hash_size,
 sig_off, sig_size, *_rest) = struct.unpack(">4sIIQQIQQQQQQQQQQQII", data[0:128])
header, auth_start = data[0:256], 256
aux = data[auth_start + auth_size: auth_start + auth_size + aux_size]
embedded_hash = data[auth_start + hash_off: auth_start + hash_off + hash_size]
embedded_sig = data[auth_start + sig_off: auth_start + sig_off + sig_size]
assert hashlib.sha256(header + aux).digest() == embedded_hash, "AVB hash mismatch"
open("sig.bin", "wb").write(embedded_sig)
open("digest.bin", "wb").write(embedded_hash)
PYEOF
if openssl pkeyutl -verify -pubin -inkey avb_test_key_pub.pem -sigfile sig.bin -in digest.bin \
    -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pkcs1 >/dev/null 2>&1; then
    echo "PASS: vbmeta RSA-2048 signature independently verified by openssl"
    PASS=$((PASS + 1))
else
    echo "FAIL: vbmeta RSA-2048 signature failed independent openssl verification"
    FAIL=$((FAIL + 1))
fi

python3 - <<'PYEOF'
import struct
host = open("payload.bin", "rb").read()
vbmeta = open("vbmeta_unsigned.img", "rb").read()
host_padded = host + b"\x00" * ((-len(host)) % 4096)
partition_size = len(host_padded) + 4096 + len(vbmeta) + 4096
out = bytearray(partition_size)
out[0:len(host_padded)] = host_padded
vbmeta_offset = len(host_padded)
out[vbmeta_offset:vbmeta_offset + len(vbmeta)] = vbmeta
footer_pos = partition_size - 64
out[footer_pos:footer_pos + 64] = struct.pack(">4sIIQQQ28x", b"AVBf", 1, 0, len(host), vbmeta_offset, len(vbmeta))
open("host_with_footer.img", "wb").write(out)
PYEOF
roundtrip_check host_with_footer.img "vbmeta (AVB footer on a host image)" vbf

echo ""
echo "===== $PASS passed, $FAIL failed ====="
exit "$FAIL"
