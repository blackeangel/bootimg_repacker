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
