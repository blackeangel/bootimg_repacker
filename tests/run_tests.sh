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

# A Windows build (abr.exe, cross-compiled) is run under wine, so every check
# below exercises the real executable. Small wrapper scripts keep the rest of
# the suite calling "$ABR" and "$UNIT" as plain commands.
UNIT_DEFAULT="$(dirname "$ABR")/abr_unit_tests"
case "$ABR" in
    *.exe | *.EXE)
        if ! command -v wine >/dev/null 2>&1; then
            echo "error: $ABR is a Windows executable and wine is not installed" >&2
            exit 2
        fi
        export WINEDEBUG="${WINEDEBUG:--all}"
        mkdir -p "$WORK/winebin"
        for pair in "$ABR:abr" "$(dirname "$ABR")/abr_unit_tests.exe:abr_unit_tests"; do
            exe="${pair%:*}"
            [ -f "$exe" ] || continue
            printf '#!/bin/sh\nexec wine "%s" "$@"\n' "$exe" >"$WORK/winebin/${pair##*:}"
            chmod +x "$WORK/winebin/${pair##*:}"
        done
        ABR="$WORK/winebin/abr"
        UNIT_DEFAULT="$WORK/winebin/abr_unit_tests"
        echo "note: running the Windows build under $(wine --version 2>/dev/null)"
        ;;
    *)
        # ABR_RUNNER runs the binaries under an emulator, e.g. an arm64 build on an
        # x86-64 machine: ABR_RUNNER="qemu-aarch64 -cpu max" tests/run_tests.sh build-arm64/abr
        if [ -n "${ABR_RUNNER:-}" ]; then
            mkdir -p "$WORK/runbin"
            for pair in "$ABR:abr" "$(dirname "$ABR")/abr_unit_tests:abr_unit_tests"; do
                exe="${pair%:*}"
                [ -f "$exe" ] || continue
                printf '#!/bin/sh\nexec %s "%s" "$@"\n' "$ABR_RUNNER" "$exe" >"$WORK/runbin/${pair##*:}"
                chmod +x "$WORK/runbin/${pair##*:}"
            done
            ABR="$WORK/runbin/abr"
            UNIT_DEFAULT="$WORK/runbin/abr_unit_tests"
            echo "note: running abr under: $ABR_RUNNER"
        fi
        ;;
esac

PASS=0
FAIL=0
# said <pattern> <command...>: run the command, succeed only if it succeeded and
# its output (stdout + stderr) contains the pattern. Deliberately not
# `command | grep -q`: under `pipefail`, grep -q quitting at its first match can
# SIGPIPE a command that is still writing, turning a pass into a failure that
# depends on timing.
said() {
    local pattern="$1" out
    shift
    out="$("$@" 2>&1)" || return 1
    grep -q -- "$pattern" <<<"$out"
}
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
import hashlib, struct
vb = open("vendor_boot_v4.img", "rb").read()
descriptors = b""
partition = b"vendor_boot"
digest = hashlib.sha256(vb).digest()  # a real digest: abr verifies it and warns when stale
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

# --------------------------------------------------------------- mtk --
# Synthetic fixtures (not vendoring osm0sis/mkmtkhdr's source here --
# unlike mkbootimg.py it carries no explicit repo-level license, so
# this project generates the MTK sub-header itself in Python from the
# struct layout documented in include/abr/legacy/mtk.hpp instead of
# redistributing that tool's code). The struct/magic/512-byte-size
# were independently confirmed against a locally-compiled mkmtkhdr
# during development, just not re-verified by every test run.
python3 - <<'PYEOF'
import struct
def mtk_wrap(payload, name):
    h = struct.pack("<II", 0x58881688, len(payload)) + name.encode().ljust(32, b"\x00")
    h += b"\xff" * (512 - len(h))
    return h + payload
open("mtk_kernel.bin", "wb").write(mtk_wrap(b"fake kernel data" * 500, "KERNEL"))
open("mtk_ramdisk.bin", "wb").write(mtk_wrap(b"fake ramdisk data" * 300, "ROOTFS"))
PYEOF
python3 "$MKBOOTIMG" --header_version 0 --kernel mtk_kernel.bin --ramdisk mtk_ramdisk.bin \
    --cmdline "console=ttyMT0" --base 0x40000000 --pagesize 2048 --output boot_mtk.img
roundtrip_check boot_mtk.img "boot v0 (MTK header on both kernel and ramdisk)" mtk1
grep -q "^kernel_mtk_name=KERNEL$" rt_mtk1/manifest.txt && grep -q "^ramdisk_mtk_name=ROOTFS$" rt_mtk1/manifest.txt \
  && { echo "PASS: MTK header names recorded correctly for both components"; PASS=$((PASS + 1)); } \
  || { echo "FAIL: MTK header names missing/wrong in manifest"; FAIL=$((FAIL + 1)); }

# -------------------------------------------------------------- dhtb --
# Same rationale as above for not vendoring osm0sis/dhtbsign's source
# (no repo-level license at all there, plus that specific reference
# tool has its own memory-corruption bug on exit -- see PROGRESS.md).
python3 - <<'PYEOF'
import hashlib, struct
inner = open("boot_mtk.img", "rb").read()
seandroid = b"SEANDROIDENFORCE"
padding = b"\xff\xff\xff\xff"
payload = inner + seandroid + padding
digest = hashlib.sha256(payload).digest()
header = b"DHTB\x01\x00\x00\x00" + digest + b"\x00" * 8 + struct.pack("<I", len(payload))
header += b"\x00" * (512 - len(header))
open("dhtb_wrapped.img", "wb").write(header + payload)
PYEOF
roundtrip_check dhtb_wrapped.img "boot (DHTB-wrapped, with SEAndroid footer + padding)" dhtb1
grep -q "^has_dhtb=true$" rt_dhtb1/manifest.txt \
  && { echo "PASS: DHTB wrapper decomposed into manifest fields"; PASS=$((PASS + 1)); } \
  || { echo "FAIL: DHTB wrapper not recorded in manifest"; FAIL=$((FAIL + 1)); }

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

# =========================================================================
# Quirks found by round-tripping real device dumps. The fixtures come from
# tests/tools/fixtures.py (built from the formats, not from abr's code) and
# tests/tools/verify.py re-checks abr's output independently of abr.
# =========================================================================
TOOLS="$SCRIPT_DIR/tools"
python3 "$TOOLS/fixtures.py" fx || { echo "error: could not generate quirk fixtures" >&2; exit 2; }

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
expect_line() {  # <unpacked dir> <exact manifest line> <label>
    if grep -qx -- "$2" "$1/manifest.txt"; then pass "$3"; else fail "$3 (no '$2' in $1/manifest.txt)"; fi
}
expect_key() {  # <unpacked dir> <manifest key> <label>
    if grep -q -- "^$2=" "$1/manifest.txt"; then pass "$3"; else fail "$3 (no '$2' in $1/manifest.txt)"; fi
}
# Replace the ramdisk of an unpacked image with new contents and repack it.
edit_and_repack() {  # <unpacked dir> <out image>
    head -c 3000 /dev/urandom >"$1/ramdisk.cpio"
    "$ABR" repack "$1" -o "$2" >/dev/null 2>"$2.err"
}
# After editing the ramdisk, the boot `id` must follow the scheme the source
# used, and the new ramdisk must really be in the rebuilt image.
id_follows_edit() {  # <image> <scheme> <tag> <label>
    "$ABR" unpack "$1" -o "ed_$3" >/dev/null 2>&1
    edit_and_repack "ed_$3" "ed_$3.out"
    "$ABR" unpack "ed_$3.out" -o "ed_${3}_re" >/dev/null 2>&1
    if python3 "$TOOLS/verify.py" boot-id "ed_$3.out" "$2" >/dev/null &&
        cmp -s "ed_$3/ramdisk.cpio" "ed_${3}_re/ramdisk.cpio"; then
        pass "$4"
    else
        fail "$4"
    fi
}

# ---- boot id: which hash produced it, and does an edit keep it consistent
roundtrip_check fx/boot_v0_qcdt_sha1_dt.img "boot v0 + CAF dt blob (QCDT: dt_size in header word 10)" qcdt
expect_line rt_qcdt "id_scheme=sha1_dt" "QCDT: id recognised as sha1 over kernel+ramdisk+second+dt"
expect_key rt_qcdt dt_file "QCDT: dt blob extracted as its own file"
id_follows_edit fx/boot_v0_qcdt_sha1_dt.img sha1_dt qcdt "QCDT: id recomputed (sha1_dt) after a ramdisk edit"

roundtrip_check fx/boot_v0_nodt_sha1_dt.img "boot v0 (sha1 id that includes an empty dt entry)" nodt
expect_line rt_nodt "id_scheme=sha1_dt" "empty-dt id recognised as sha1_dt, not mistaken for plain sha1"
id_follows_edit fx/boot_v0_nodt_sha1_dt.img sha1_dt nodt "empty-dt: id recomputed (sha1_dt) after a ramdisk edit"

roundtrip_check fx/boot_v0_sha256.img "boot v0 (sha256 id filling all 32 id bytes)" sha256id
expect_line rt_sha256id "id_scheme=sha256" "sha256 id recognised"
id_follows_edit fx/boot_v0_sha256.img sha256 sha256id "sha256: id recomputed after a ramdisk edit"

roundtrip_check fx/boot_v0_rawid.img "boot v0 (unrecognised id, kept verbatim)" rawid
expect_line rt_rawid "id_scheme=raw" "unrecognised id falls back to raw"
"$ABR" unpack fx/boot_v0_rawid.img -o ed_raw >/dev/null 2>&1
edit_and_repack ed_raw ed_raw.out
if [ "$(python3 "$TOOLS/verify.py" boot-field fx/boot_v0_rawid.img id)" = \
     "$(python3 "$TOOLS/verify.py" boot-field ed_raw.out id)" ]; then
    pass "raw id is left alone after an edit (not overwritten with a guess)"
else
    fail "raw id changed after an edit"
fi

# ---- header fields that must survive although nothing parses them
roundtrip_check fx/boot_v3_reserved_hdrsize.img "boot v3 (non-zero reserved words, non-standard header_size)" v3res
expect_key rt_v3res reserved "v3: reserved words recorded"
expect_line rt_v3res "header_size=1600" "v3: non-standard header_size recorded"
roundtrip_check fx/boot_v1_dtbo_offset.img "boot v1 (recovery_dtbo_offset/header_size differ from the computed ones)" v1off
expect_key rt_v1off recovery_dtbo_offset "v1: unusual recovery_dtbo_offset recorded"
roundtrip_check fx/boot_v2_header_garbage.img "boot v2 (vendor data after the header struct, inside its page)" v2garb
expect_key rt_v2garb header_padding_file "v2: non-zero header page padding kept"
roundtrip_check fx/boot_v2_trimmed_tail.img "boot v2 (final page padding trimmed by whoever dumped it)" trim
expect_key rt_trim missing_tail_padding "trimmed dump: missing final padding recorded"
roundtrip_check fx/vendor_boot_v4_emptytable_p2048.img "vendor_boot v4 (empty ramdisk table, page_size 2048, v3-sized header_size)" vbempty
expect_line rt_vbempty "ramdisk_table=false" "vendor_boot v4: empty ramdisk table recorded"
expect_key rt_vbempty header_size "vendor_boot v4: non-standard header_size recorded"

# ---- bytes around the container: tail, partition fill, vendor wrapper
roundtrip_check fx/boot_v2_tail_padded.img "boot v2 (SEAndroid tail + zero fill up to the partition size)" tailpad
expect_key rt_tailpad tail_file "tail after the image kept as a file"
expect_key rt_tailpad pad_to "partition-size fill recorded"
"$ABR" unpack fx/boot_v2_tail_padded.img -o ed_tail >/dev/null 2>&1
edit_and_repack ed_tail ed_tail.out
"$ABR" unpack ed_tail.out -o ed_tail_re >/dev/null 2>&1
if [ "$(stat -c %s ed_tail.out)" = "$(stat -c %s fx/boot_v2_tail_padded.img)" ] &&
    cmp -s ed_tail/ramdisk.cpio ed_tail_re/ramdisk.cpio &&
    cmp -s rt_tailpad/tail.bin ed_tail_re/tail.bin; then
    pass "an edited (smaller) image keeps its tail and is re-padded to the original partition size"
else
    fail "edited image lost its tail or its partition-size padding"
fi
roundtrip_check fx/boot_v4_prefixed_signed.img "boot v4 inside a BFBF/SSSS-style signed wrapper (prefix + trailer)" bfbf
expect_key rt_bfbf prefix_file "wrapper before the boot image kept as a file"
expect_key rt_bfbf tail_file "signature trailer after the image kept as a file"
"$ABR" repack rt_bfbf -o rt_bfbf.again >/dev/null 2>rt_bfbf.again.err
if ! grep -q "kept as they were" rt_bfbf.again.err; then
    pass "an unedited image inside a vendor wrapper repacks without a stale-signature warning"
else
    fail "unedited image inside a vendor wrapper triggered a stale-signature warning"
fi
"$ABR" unpack fx/boot_v4_prefixed_signed.img -o ed_bfbf >/dev/null 2>&1
edit_and_repack ed_bfbf ed_bfbf.out
if grep -q "kept as they were" ed_bfbf.out.err; then
    pass "editing an image inside a vendor wrapper warns that the wrapper's signature/sizes are stale"
else
    fail "no stale-signature warning after editing an image inside a vendor wrapper"
fi
edit_and_repack ed_tail ed_tail.again 2>/dev/null
if ! grep -q "kept as they were" ed_tail.again.err; then
    pass "a bare SEANDROIDENFORCE tail is not treated as a signature (no warning)"
else
    fail "bare SEANDROIDENFORCE tail triggered a stale-signature warning"
fi

# ---- AVB footer: host not 4096-aligned, salted digest, edit, signing
roundtrip_check fx/boot_v2_avbfooter_unaligned.img "boot v2 + AVB hash footer (host not 4096-aligned, salted digest)" avbun
if python3 "$TOOLS/verify.py" avb-footer fx/boot_v2_avbfooter_unaligned.img >/dev/null &&
    python3 "$TOOLS/verify.py" avb-footer rt_avbun.out >/dev/null; then
    pass "AVB footer fixture and abr's rebuild both verify independently"
else
    fail "AVB footer fixture/rebuild does not verify"
fi
"$ABR" unpack fx/boot_v2_avbfooter_unaligned.img -o ed_avb >/dev/null 2>&1
edit_and_repack ed_avb ed_avb.out
if python3 "$TOOLS/verify.py" avb-footer ed_avb.out &&
    [ "$(stat -c %s ed_avb.out)" = "$(stat -c %s fx/boot_v2_avbfooter_unaligned.img)" ] &&
    ! cmp -s ed_avb.out fx/boot_v2_avbfooter_unaligned.img; then
    pass "edited ramdisk: AVB hash descriptor refreshed, partition size unchanged"
else
    fail "edited ramdisk: AVB footer not refreshed correctly"
fi

# A signed footer cannot be regenerated without the key: that must be an
# error, not a silently unverifiable image.
"$ABR" unpack fx/boot_v2_avbfooter_unaligned.img -o ed_avbsig >/dev/null 2>&1
sed -i 's/^avb_algorithm_type=0$/avb_algorithm_type=1/' ed_avbsig/manifest.txt
head -c 3000 /dev/urandom >ed_avbsig/ramdisk.cpio
if "$ABR" repack ed_avbsig -o ed_avbsig.out >/dev/null 2>ed_avbsig.err; then
    fail "signed AVB footer repacked without a key"
elif grep -q -- "--avb-key" ed_avbsig.err; then
    pass "signed AVB footer + changed content without --avb-key is refused with an explanation"
else
    fail "signed AVB footer refusal message does not mention --avb-key"
fi
if "$ABR" repack ed_avbsig -o ed_avbsig.out --avb-key avb_test_key.pem >/dev/null 2>&1 &&
    python3 "$TOOLS/verify.py" avb-footer ed_avbsig.out avb_test_key_pub.pem >/dev/null; then
    pass "re-signed AVB footer: digest matches the edit and the RSA signature verifies (openssl)"
else
    fail "re-signed AVB footer does not verify"
fi

# A stale digest in the source must be reported, but an untouched repack
# must still reproduce the source (it is not silently "fixed").
python3 - <<'PYEOF'
d = bytearray(open("fx/boot_v2_avbfooter_unaligned.img", "rb").read())
d[5000] ^= 0xFF
open("avb_stale.img", "wb").write(d)
PYEOF
"$ABR" unpack avb_stale.img -o rt_stale >/dev/null 2>stale.err
"$ABR" repack rt_stale -o rt_stale.out >/dev/null 2>&1
if grep -q "does not match its content" stale.err; then
    pass "stale AVB hash descriptor in the source is reported"
else
    fail "stale AVB hash descriptor not reported"
fi
check avb_stale.img rt_stale.out "image with a stale AVB digest still round-trips byte-for-byte"

# ---- reporting: info, self-check, things that are not boot images
if said "hash check:   OK" "$ABR" info fx/boot_v2_avbfooter_unaligned.img; then
    pass "info reports the AVB footer and its digest check"
else
    fail "info does not report the AVB footer digest check"
fi
if said "id scheme:      sha1_dt" "$ABR" info fx/boot_v0_qcdt_sha1_dt.img; then
    pass "info reports the boot id scheme"
else
    fail "info does not report the boot id scheme"
fi
"$ABR" unpack fx/boot_v2_header_garbage.img -o sc_ok >sc_ok.out 2>&1
if grep -q "reproduces this image byte-for-byte" sc_ok.out; then
    pass "unpack self-check confirms an exact round trip"
else
    fail "unpack self-check did not confirm an exact round trip"
fi
"$ABR" unpack fx/boot_v2_dirty_padding.img -o sc_bad >sc_bad.out 2>&1
if grep -q "does NOT reproduce" sc_bad.out; then
    pass "unpack self-check flags an image abr cannot reproduce exactly (non-zero page padding)"
else
    fail "unpack self-check missed an image abr cannot reproduce exactly"
fi
if "$ABR" unpack fx/ext4_like.img -o rt_ext4 >/dev/null 2>ext4.err; then
    fail "an ext4 image was accepted as a boot-family container"
elif grep -q "ext2/3/4 filesystem" ext4.err; then
    pass "an ext4 image is rejected with an explanatory message"
else
    fail "ext4 rejection message is not explanatory"
fi

# =========================================================================
# Threads and codecs. What abr runs on several threads -- the 8 MiB blocks of
# an LZ4 legacy stream, the workers of a zstd frame, the components of an image
# -- must come out byte-for-byte the same whatever the thread count (-j1 = no
# extra thread), and every codec must write a stream the real tool reads: the
# ramdisk is sliced out of the repacked boot image by tests/tools/verify.py (not
# by abr) and handed to gzip, lz4, zstd, xz, bzip2 or lzop.
# =========================================================================
python3 - <<'PYEOF'
import random
r = random.Random(7)
words = [bytes(r.choices(b"abcdefghijklmnopqrstuvwxyz", k=r.randint(3, 9))) for _ in range(300)]
def text(n):  # compressible, but not trivially so
    return b" ".join(r.choices(words, k=n // 4 + 16))[:n]
open("thr_text.bin", "wb").write(text(300000))
# text, an incompressible stretch longer than an LZO block (256 KiB), text again, and a
# tail that is aligned to no block size
open("thr_mixed.bin", "wb").write(text(100000) + r.randbytes(600000) + text(100000) + r.randbytes(12345))
# more than one LZ4 legacy block (8 MiB each), so there is something to run side by side
open("thr_big.bin", "wb").write(text(9000000))
PYEOF

thr_dir() {  # <codec> <payload> <dir>: a boot v4 tree whose ramdisk abr has to compress with <codec>
    mkdir -p "$3"
    cat >"$3/manifest.txt" <<EOF
type=boot
header_version=4
os_version=14.0.0
os_patch_level=2024-05
cmdline=test
kernel_file=kernel
kernel_compression=none
ramdisk_file=ramdisk.cpio
ramdisk_compression=$1
EOF
    printf 'kernel' >"$3/kernel"
    cp "$2" "$3/ramdisk.cpio"
}
thr_decoder() {  # <codec>: the real tool's command (stdin -> stdout), if it is installed
    case "$1" in
        gzip) command -v gzip >/dev/null 2>&1 && echo "gzip -dc" ;;
        lz4 | lz4_legacy) command -v lz4 >/dev/null 2>&1 && echo "lz4 -dc" ;;
        zstd) command -v zstd >/dev/null 2>&1 && echo "zstd -dc -q" ;;
        xz) command -v xz >/dev/null 2>&1 && echo "xz -dc" ;;
        lzma) command -v xz >/dev/null 2>&1 && echo "xz --format=lzma -dc" ;;
        bzip2) command -v bzip2 >/dev/null 2>&1 && echo "bzip2 -dc" ;;
        lzo) command -v lzop >/dev/null 2>&1 && echo "lzop -dc" ;;
    esac
}
thr_codec_check() {  # <codec> <payload> <label> <thread counts...>
    local codec="$1" payload="$2" label="$3" dir first="" j js dec tool
    dir="thr_${codec}_$(basename "$payload" .bin)"
    shift 3
    js="$(printf -- '-j%s ' "$@")"
    js="${js% }"
    thr_dir "$codec" "$payload" "$dir"
    for j in "$@"; do
        if ! "$ABR" -j"$j" repack "$dir" -o "$dir.j$j.img" >/dev/null 2>"$dir.err"; then
            fail "$label: repack -j$j failed ($(head -c 200 "$dir.err"))"
            return
        fi
        if [ -z "$first" ]; then
            first="$dir.j$j.img"
        elif ! cmp -s "$first" "$dir.j$j.img"; then
            fail "$label: -j$j gives different bytes than the first run"
            return
        fi
    done
    dec="$(thr_decoder "$codec")"
    if [ -z "$dec" ]; then
        pass "$label: same bytes for ${js// /, } (the real decompressor is not installed: content not checked)"
        return
    fi
    tool="${dec%% *}"
    python3 "$TOOLS/verify.py" ramdisk "$first" "$dir.rd" || { fail "$label: could not slice the ramdisk out of the image"; return; }
    # shellcheck disable=SC2086
    if $dec <"$dir.rd" >"$dir.dec" 2>"$dir.dec.err" && cmp -s "$dir.dec" "$payload"; then
        pass "$label: same bytes for ${js// /, }, and the real $tool reads the ramdisk back"
    else
        fail "$label: the real $tool does not read back what abr wrote ($(head -c 200 "$dir.dec.err"))"
    fi
}

for codec in gzip lz4_legacy lz4 zstd xz lzma bzip2 lzo; do
    thr_codec_check "$codec" thr_mixed.bin "$codec ramdisk (text, incompressible stretch, odd tail)" 1 4
done
thr_codec_check lz4_legacy thr_big.bin "lz4_legacy ramdisk of two blocks" 1 2 8
thr_codec_check zstd thr_big.bin "zstd ramdisk of 9 MB" 1 2 8

# The compression level of a component can be chosen in the manifest (<prefix>_level).
thr_dir gzip thr_text.bin thr_level
for lvl in 1 9; do
    sed -i '/^ramdisk_level=/d' thr_level/manifest.txt
    echo "ramdisk_level=$lvl" >>thr_level/manifest.txt
    "$ABR" repack thr_level -o "thr_level_$lvl.img" >/dev/null 2>&1
    python3 "$TOOLS/verify.py" ramdisk "thr_level_$lvl.img" "thr_level_$lvl.rd"
done
if [ -s thr_level_1.rd ] && [ -s thr_level_9.rd ] &&
    [ "$(($(wc -c <thr_level_1.rd)))" -gt "$(($(wc -c <thr_level_9.rd)))" ] &&
    gzip -dc <thr_level_1.rd | cmp -s - thr_text.bin && gzip -dc <thr_level_9.rd | cmp -s - thr_text.bin; then
    pass "ramdisk_level=1 and =9 in the manifest give a larger and a smaller gzip stream, both valid"
else
    fail "ramdisk_level in the manifest is not honoured ($(wc -c <thr_level_1.rd 2>/dev/null) vs $(wc -c <thr_level_9.rd 2>/dev/null) bytes)"
fi

# An image with several components that are all recompressed at once (the case
# the threads help most): vendor_boot v4 with two edited ramdisk fragments.
"$ABR" unpack vendor_boot_v4.img -o thr_vb >/dev/null
head -c 400000 thr_text.bin >thr_vb/ramdisk0.cpio
head -c 250000 thr_mixed.bin >thr_vb/ramdisk1.cpio
"$ABR" -j1 repack thr_vb -o thr_vb.j1.img >/dev/null 2>&1
"$ABR" -j4 repack thr_vb -o thr_vb.j4.img >/dev/null 2>&1
check thr_vb.j1.img thr_vb.j4.img "vendor_boot v4, two edited fragments recompressed: -j1 and -j4 give the same bytes"
"$ABR" unpack thr_vb.j4.img -o thr_vb_back >/dev/null 2>&1
if cmp -s thr_vb_back/ramdisk0.cpio <(head -c 400000 thr_text.bin) && cmp -s thr_vb_back/ramdisk1.cpio <(head -c 250000 thr_mixed.bin); then
    pass "vendor_boot v4, two edited fragments: both come back as edited"
else
    fail "vendor_boot v4, two edited fragments: contents differ after the round trip"
fi

# -j / --threads: accepted in every spelling and position without changing the
# result; refused, with a message, when it is not a number.
thr_ref="$("$ABR" info boot_v4.img 2>&1)"
thr_opt_bad=""
for form in "-j2" "-j 2" "--threads 2" "--threads=2" "-j0" "-j1" "-j16"; do
    # shellcheck disable=SC2086
    [ "$("$ABR" $form info boot_v4.img 2>&1)" = "$thr_ref" ] || thr_opt_bad="$thr_opt_bad [$form]"
done
[ "$("$ABR" info boot_v4.img -j3 2>&1)" = "$thr_ref" ] || thr_opt_bad="$thr_opt_bad [trailing -j3]"
[ "$(ABR_THREADS=3 "$ABR" info boot_v4.img 2>&1)" = "$thr_ref" ] || thr_opt_bad="$thr_opt_bad [ABR_THREADS]"
if [ -z "$thr_opt_bad" ]; then
    pass "-j N, -jN, --threads N, --threads=N (before or after the command) and ABR_THREADS are accepted"
else
    fail "thread options changed the result or were refused:$thr_opt_bad"
fi
thr_opt_bad=""
for form in "-j abc" "--threads=" "--threads=2x" "-j 99999" "-j -1" "-j"; do
    # shellcheck disable=SC2086
    if "$ABR" $form info boot_v4.img >/dev/null 2>thr_opt.err; then
        thr_opt_bad="$thr_opt_bad [accepted: $form]"
    elif ! grep -q "number" thr_opt.err; then
        thr_opt_bad="$thr_opt_bad [no explanation for: $form]"
    fi
done
if "$ABR" info boot_v4.img -j >/dev/null 2>thr_opt.err || ! grep -q "needs a number" thr_opt.err; then
    thr_opt_bad="$thr_opt_bad [-j without a value at the end]"
fi
if [ -z "$thr_opt_bad" ]; then
    pass "a thread count that is not a number is refused with an explanation"
else
    fail "bad thread counts are not handled:$thr_opt_bad"
fi

# =========================================================================
# Self-contained crypto (abr links no OpenSSL) and AVB signing judged by the
# real avbtool. BigInt is checked against Python's integers, RSA against the
# openssl command line, and every image abr re-signs against avbtool's own
# verify_image -- three implementations that share no code with abr.
# =========================================================================
UNIT="$UNIT_DEFAULT"
AVBTOOL="$REPO_ROOT/tests/reference/avb/avbtool.py"

genkey() {  # <bits> <out.pem>: a PKCS#1 ("BEGIN RSA PRIVATE KEY") key, on OpenSSL 1.1 and 3.x
    openssl genrsa -traditional -out "$2" "$1" >/dev/null 2>&1 || openssl genrsa -out "$2" "$1" >/dev/null 2>&1
}
avb_verify() {  # <image> <partition name> <public key.pem> [<other image> <its partition name>] -> avbtool's verdict
    # avbtool resolves a descriptor's partition by file name next to the image,
    # so a vbmeta that carries a hash descriptor for "boot" needs boot.img beside it.
    local d; d="$(mktemp -d -p .)"
    cp "$1" "$d/$2.img"
    [ $# -ge 5 ] && cp "$4" "$d/$5.img"
    python3 "$AVBTOOL" verify_image --image "$d/$2.img" --key "$3" >"$d/out" 2>&1
    local rc=$?
    rm -rf "$d"
    return $rc
}

if [ -x "$UNIT" ]; then
    if out=$(python3 "$TOOLS/gen_bigint_vectors.py" | "$UNIT" bigint 2>&1); then
        pass "BigInt agrees with Python integers ($out)"
    else
        fail "BigInt disagrees with Python integers ($out)"
    fi

    # SHA-1/-256/-512 against Python's hashlib on the lengths where the padding
    # falls differently (0..129 bytes, block boundaries, 55/56) and with the input
    # fed in different chunk sizes -- once with whatever the CPU offers (x86 SHA-NI,
    # ARMv8 SHA1/SHA2) and once forced to the portable code, so both implementations
    # are judged on every machine.
    if python3 "$TOOLS/gen_sha_vectors.py" sha_blob.bin sha_expect.txt; then
        sha_auto=$("$UNIT" sha-check sha_blob.bin sha_expect.txt 2>&1) && sha_auto_ok=1 || sha_auto_ok=0
        sha_port=$(ABR_SHA_IMPL=portable "$UNIT" sha-check sha_blob.bin sha_expect.txt 2>&1) && sha_port_ok=1 || sha_port_ok=0
        if [ $sha_auto_ok -eq 1 ]; then
            pass "SHA-1/256/512 agree with hashlib, hardware-selected implementation ($sha_auto)"
        else
            fail "SHA-1/256/512 disagree with hashlib, hardware-selected implementation ($sha_auto)"
        fi
        if [ $sha_port_ok -eq 1 ] && [ "$(ABR_SHA_IMPL=portable "$UNIT" sha-impl)" = "portable" ]; then
            pass "SHA-1/256/512 agree with hashlib, portable implementation ($sha_port)"
        else
            fail "SHA-1/256/512 disagree with hashlib, portable implementation ($sha_port)"
        fi
    else
        fail "could not generate the SHA test vectors"
    fi

    # abr::par, the thread helper: every job once, the error of the lowest failing
    # job, nested regions, the cap on running threads, leases -- for several limits.
    if out=$("$UNIT" par 2>&1); then
        pass "thread helper abr::par ($(tail -n 1 <<<"$out"))"
    else
        fail "thread helper abr::par: $(tail -n 3 <<<"$out" | tr '\n' ' ')"
    fi

    head -c 70000 /dev/urandom >rsa_data.bin
    rsa_total=0; rsa_bad=0
    for bits in 1024 2048 4096; do
        genkey $bits rk$bits.pem
        openssl pkcs8 -topk8 -nocrypt -in rk$bits.pem -out rk${bits}_p8.pem
        openssl pkcs8 -topk8 -nocrypt -in rk$bits.pem -outform DER -out rk$bits.pk8
        openssl rsa -in rk$bits.pem -outform DER -out rk${bits}_p1.der >/dev/null 2>&1
        for alg in sha1 sha256 sha512; do
            openssl dgst -$alg -sign rk$bits.pem -out ref.sig rsa_data.bin
            want=$(od -An -v -tx1 ref.sig | tr -d ' \n')
            for k in rk$bits.pem rk${bits}_p8.pem rk$bits.pk8 rk${bits}_p1.der; do
                rsa_total=$((rsa_total + 1))
                [ "$("$UNIT" rsa-sign $k $alg rsa_data.bin)" = "$want" ] || { rsa_bad=$((rsa_bad + 1)); echo "  mismatch: $bits-bit $alg $k"; }
            done
        done
    done
    if [ $rsa_bad -eq 0 ]; then
        pass "RSA PKCS#1 v1.5 signatures equal openssl's byte-for-byte ($rsa_total: 3 key sizes x 3 hashes x PEM/PKCS#8/pk8/DER)"
    else
        fail "RSA signatures differ from openssl's in $rsa_bad of $rsa_total cases"
    fi

    openssl rsa -in rk2048.pem -pubout -out rk2048_pub.pem >/dev/null 2>&1
    openssl req -x509 -new -key rk2048.pem -subj "/CN=abr-test" -days 3650 -out rk2048_cert.pem >/dev/null 2>&1
    openssl x509 -in rk2048_cert.pem -outform DER -out rk2048_cert.der
    openssl dgst -sha256 -sign rk2048.pem -out rsa_ref.sig rsa_data.bin
    cp rsa_ref.sig rsa_bad.sig
    printf '\x55' | dd of=rsa_bad.sig bs=1 seek=100 conv=notrunc 2>/dev/null
    if "$UNIT" rsa-verify rk2048_pub.pem sha256 rsa_data.bin rsa_ref.sig >/dev/null &&
        "$UNIT" rsa-verify rk2048_cert.pem sha256 rsa_data.bin rsa_ref.sig >/dev/null &&
        "$UNIT" rsa-verify rk2048_cert.der sha256 rsa_data.bin rsa_ref.sig >/dev/null &&
        ! "$UNIT" rsa-verify rk2048_cert.pem sha256 rsa_data.bin rsa_bad.sig >/dev/null &&
        ! "$UNIT" rsa-verify rk2048_cert.pem sha1 rsa_data.bin rsa_ref.sig >/dev/null; then
        pass "RSA verify accepts openssl's signature via public key / PEM cert / DER cert, rejects a flipped byte and the wrong hash"
    else
        fail "RSA verify misbehaves"
    fi

    openssl pkcs8 -topk8 -v2 aes-128-cbc -passout pass:x -in rk2048.pem -out rk2048_enc.pem >/dev/null 2>&1
    if "$UNIT" rsa-sign rk2048_enc.pem sha256 rsa_data.bin >/dev/null 2>rsa_enc.err; then
        fail "a passphrase-protected key was accepted"
    elif grep -q "passphrase" rsa_enc.err; then
        pass "a passphrase-protected key is refused with an explanation"
    else
        fail "passphrase-protected key refusal is not explanatory"
    fi

    python3 -c "import random,sys; sys.stdout.buffer.write(bytes(random.Random(7).randrange(256) for _ in range(300)))" >rsa_garbage.bin
    printf 'this is a text file, not a key\n' >rsa_garbage.txt
    printf -- '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n' >rsa_garbage.pem
    garbage_ok=1
    for g in rsa_garbage.bin rsa_garbage.txt rsa_garbage.pem; do
        if "$UNIT" rsa-sign $g sha256 rsa_data.bin >/dev/null 2>rsa_garbage.err ||
            ! grep -q "cannot read the file as an RSA private key" rsa_garbage.err; then
            garbage_ok=0
            echo "  $g: $(cat rsa_garbage.err)"
        fi
    done
    if [ $garbage_ok -eq 1 ]; then
        pass "unreadable key files (random bytes, text, a PEM with a bad body) are refused with a message that says what was expected"
    else
        fail "an unreadable key file gives an unhelpful message (or was accepted)"
    fi
else
    echo "SKIP: BigInt/RSA unit checks (abr_unit_tests not built next to abr; configure with -DABR_BUILD_TESTS=ON)"
fi

if [ -x "$UNIT" ] && python3 "$AVBTOOL" version >/dev/null 2>&1; then
    genkey 2048 av_k2048.pem
    genkey 4096 av_k4096.pem
    genkey 2048 av_k2048b.pem
    for k in av_k2048 av_k4096 av_k2048b; do openssl rsa -in $k.pem -pubout -out ${k}_pub.pem >/dev/null 2>&1; done

    # The public-key blob libavb reads from the vbmeta: avbtool vs abr.
    python3 "$AVBTOOL" extract_public_key --key av_k2048.pem --output av_pk2048.bin
    python3 "$AVBTOOL" extract_public_key --key av_k4096.pem --output av_pk4096.bin
    if [ "$("$UNIT" avb-pubkey av_k2048.pem)" = "$(od -An -v -tx1 av_pk2048.bin | tr -d ' \n')" ] &&
        [ "$("$UNIT" avb-pubkey av_k4096.pem)" = "$(od -An -v -tx1 av_pk4096.bin | tr -d ' \n')" ]; then
        pass "AVB public-key blob (n0inv, modulus, R^2 mod n) equals avbtool extract_public_key (RSA-2048 and RSA-4096)"
    else
        fail "AVB public-key blob differs from avbtool's"
    fi

    # A signed hash footer written by the real avbtool.
    cp fx/boot_v0_qcdt_sha1_dt.img av_boot.img
    python3 "$AVBTOOL" add_hash_footer --image av_boot.img --partition_size 4194304 --partition_name boot \
        --algorithm SHA256_RSA2048 --key av_k2048.pem --salt 00112233445566778899aabbccddeeff \
        --prop foo:bar >/dev/null 2>&1
    "$ABR" unpack av_boot.img -o av_u >av_u.out 2>&1
    "$ABR" repack av_u -o av_u.out.img >/dev/null 2>&1
    check av_boot.img av_u.out.img "avbtool-signed hash footer (RSA-2048, salted): unpack+repack is byte-identical to avbtool's output"
    if said "SHA256_RSA2048 (signed)" "$ABR" info av_boot.img && said "hash check:   OK" "$ABR" info av_boot.img; then
        pass "info reports the signed footer and its digest check"
    else
        fail "info does not report the signed footer"
    fi

    head -c 5000 /dev/urandom >av_u/ramdisk.cpio
    if "$ABR" repack av_u -o av_edit_nokey.img >/dev/null 2>av_nokey.err; then
        fail "an edited image with a signed AVB footer was repacked without a key"
    elif grep -q -- "--avb-key" av_nokey.err; then
        pass "signed footer + edit without --avb-key is refused (not silently left invalid)"
    else
        fail "refusal for a signed footer does not mention --avb-key"
    fi
    "$ABR" repack av_u -o av_edit.img --avb-key av_k2048.pem >/dev/null 2>&1
    if avb_verify av_edit.img boot av_k2048_pub.pem; then
        pass "edited image re-signed by abr passes avbtool verify_image (vbmeta signature, embedded key, hash descriptor)"
    else
        fail "avbtool verify_image rejects the image abr re-signed"
    fi
    if "$ABR" repack av_u -o av_wrongsize.img --avb-key av_k4096.pem >/dev/null 2>av_wrongsize.err; then
        fail "a 4096-bit key was accepted for a SHA256_RSA2048 vbmeta"
    elif grep -q "2048-bit" av_wrongsize.err; then
        pass "a key of the wrong size for the algorithm is refused"
    else
        fail "wrong-size key refusal is not explanatory"
    fi
    "$ABR" repack av_u -o av_otherkey.img --avb-key av_k2048b.pem >/dev/null 2>av_otherkey.err
    if grep -q "public key stored in this vbmeta was replaced" av_otherkey.err &&
        avb_verify av_otherkey.img boot av_k2048b_pub.pem && ! avb_verify av_otherkey.img boot av_k2048_pub.pem; then
        pass "signing with a different key replaces the embedded public key, says so, and verifies only with the new key"
    else
        fail "signing with a different key is inconsistent"
    fi

    # A signed vbmeta image written by avbtool, carrying the footer's descriptor.
    python3 "$AVBTOOL" make_vbmeta_image --output av_vbmeta.img --algorithm SHA256_RSA4096 --key av_k4096.pem \
        --rollback_index 7 --prop a:b --kernel_cmdline "androidboot.x=1" \
        --include_descriptors_from_image av_boot.img >/dev/null 2>&1
    "$ABR" unpack av_vbmeta.img -o av_vu >/dev/null 2>&1
    "$ABR" repack av_vu -o av_vu.out.img >/dev/null 2>&1
    check av_vbmeta.img av_vu.out.img "avbtool-made signed vbmeta (RSA-4096, 4 descriptors): unpack+repack is byte-identical"
    "$ABR" repack av_vu -o av_vu_same.img --avb-key av_k4096.pem >/dev/null 2>&1
    check av_vbmeta.img av_vu_same.img "re-signing an unchanged vbmeta with the same key reproduces avbtool's bytes exactly"
    sed -i 's/^flags=0$/flags=2/' av_vu/manifest.txt
    if "$ABR" repack av_vu -o av_vu_flags_nokey.img >/dev/null 2>&1; then
        fail "a changed signed vbmeta was repacked without a key"
    else
        pass "a signed vbmeta whose flags changed is refused without a key"
    fi
    "$ABR" repack av_vu -o av_vu_flags.img --avb-key av_k4096.pem >/dev/null 2>&1
    if avb_verify av_vu_flags.img vbmeta av_k4096_pub.pem av_boot.img boot &&
        python3 "$AVBTOOL" info_image --image av_vu_flags.img | grep -q "^Flags:  *2"; then
        pass "vbmeta with edited flags, re-signed by abr, passes avbtool verify_image and shows the new flags"
    else
        fail "avbtool rejects the vbmeta abr re-signed"
    fi
else
    echo "SKIP: avbtool cross-checks (abr_unit_tests or tests/reference/avb/avbtool.py unavailable)"
fi

# =========================================================================
# AVBv1 boot signature -- the pre-AVB-2.0 signature AOSP's boot_signer
# appends after a boot image (what Android Image Kitchen calls AVBv1).
# Judged by two implementations that share no code with abr:
#   tests/tools/avb1.py   DER assembled in Python, RSA from `openssl`;
#   the real boot_signer  compiled from AOSP's own Java sources (needs a JDK
#                         and BouncyCastle; skipped without them).
# PKCS#1 v1.5 is deterministic, so "same key, same image" must give the same
# bytes from all three.
# =========================================================================
AVB1="$TOOLS/avb1.py"
BS_DIR="$REPO_ROOT/tests/reference/boot_signer"
VK_PK8="$BS_DIR/verity.pk8"
VK_PEM="$BS_DIR/verity.x509.pem"
openssl pkcs8 -inform DER -nocrypt -in "$VK_PK8" -out verity_key.pem 2>/dev/null

if python3 "$REPO_ROOT/tools/gen_aosp_verity_key.py" "$VK_PK8" "$VK_PEM" >gen_aosp_key.cpp 2>/dev/null &&
    cmp -s gen_aosp_key.cpp "$REPO_ROOT/src/legacy/avb1_aosp_key.cpp"; then
    pass "the AOSP dev key embedded in abr is exactly the vendored verity.pk8 + verity.x509.pem"
else
    fail "src/legacy/avb1_aosp_key.cpp does not match tests/reference/boot_signer/verity.* (rerun tools/gen_aosp_verity_key.py)"
fi

sign_py() {  # <in.img> <out.img> [key.pem cert.pem]: image + signature built by avb1.py
    python3 "$AVB1" sign "$1" /boot "${3:-verity_key.pem}" "${4:-$VK_PEM}" >"$2"
}

# --- an image signed by the independent signer is understood, and left alone ---
a1_ok=1
for v in v0 v0_qcdt v1 v2; do
    sign_py fx/avb1_$v.img a1_$v.img
    if ! python3 "$AVB1" verify a1_$v.img >/dev/null; then a1_ok=0; echo "  $v: the Python signer's own output does not verify"; fi
    if ! said "signature VALID" "$ABR" info a1_$v.img; then a1_ok=0; echo "  $v: info does not report VALID"; fi
    "$ABR" unpack a1_$v.img -o a1u_$v >a1u_$v.log 2>&1
    "$ABR" repack a1u_$v -o a1_$v.out >/dev/null 2>&1
    cmp -s a1_$v.img a1_$v.out || { a1_ok=0; echo "  $v: unpack+repack is not byte-identical"; }
    grep -q "^avb1_signature=true" a1u_$v/manifest.txt || { a1_ok=0; echo "  $v: manifest lacks avb1_signature"; }
done
if [ $a1_ok -eq 1 ]; then
    pass "AVBv1-signed v0 / v0+QCDT / v1 / v2 images: info says VALID, unpack+repack is byte-identical"
else
    fail "AVBv1-signed images are not handled correctly"
fi

# --- a damaged image is reported, and still round-trips ---
cp a1_v0.img a1_v0_bad.img
printf '\x55' | dd of=a1_v0_bad.img bs=1 seek=3000 conv=notrunc 2>/dev/null
"$ABR" unpack a1_v0_bad.img -o a1u_bad >a1u_bad.log 2>&1
"$ABR" repack a1u_bad -o a1_v0_bad.out >/dev/null 2>&1
if said "signature INVALID" "$ABR" info a1_v0_bad.img &&
    grep -q "does not match its content" a1u_bad.log && cmp -s a1_v0_bad.img a1_v0_bad.out; then
    pass "a boot signature that no longer matches the image is reported INVALID at unpack and in info, and kept as it was"
else
    fail "an invalid AVBv1 signature is not reported / not kept"
fi

# --- edited image: re-signed, equal to what the independent signer builds ---
a1_ok=1
for v in v0 v0_qcdt v1 v2; do
    printf 'abr-edit' >>a1u_$v/ramdisk.cpio
    "$ABR" repack a1u_$v -o a1_$v.edit >a1_$v.edit.log 2>&1
    sign_py a1_$v.edit a1_$v.resigned
    cmp -s a1_$v.edit a1_$v.resigned || { a1_ok=0; echo "  $v: differs from the independent signer's image"; }
    python3 "$AVB1" verify a1_$v.edit >/dev/null || { a1_ok=0; echo "  $v: independent verifier rejects it"; }
    grep -q "re-created the AVBv1 boot signature" a1_$v.edit.log || { a1_ok=0; echo "  $v: no note about re-signing"; }
    grep -q "^warning" a1_$v.edit.log && { a1_ok=0; echo "  $v: unexpected warning: $(grep '^warning' a1_$v.edit.log)"; }
done
if [ $a1_ok -eq 1 ]; then
    pass "edited AVBv1 images (v0, v0+QCDT, v1, v2) are re-signed: identical to the independent signer's output, no stale-signature warning"
else
    fail "re-signing after an edit is wrong"
fi

# --- a signer other than the AOSP test key: --avb1-key / --avb1-cert, AIK-style names, combined PEM ---
openssl genrsa -traditional -out a1_key.pem 4096 >/dev/null 2>&1 || openssl genrsa -out a1_key.pem 4096 >/dev/null 2>&1
openssl req -x509 -new -key a1_key.pem -subj "/CN=abr avb1 test/O=abr" -days 3650 -out a1_cert.pem >/dev/null 2>&1
mkdir -p aik
openssl pkcs8 -topk8 -nocrypt -outform DER -in a1_key.pem -out aik/mykey.pk8
cp a1_cert.pem aik/mykey.x509.pem
cat a1_key.pem a1_cert.pem >a1_combined.pem
cp fx/avb1_v1.img a1_plain_v1.img
"$ABR" unpack a1_plain_v1.img -o a1u_custom >/dev/null 2>&1
printf 'abr-edit' >>a1u_custom/ramdisk.cpio
"$ABR" repack a1u_custom -o a1_custom_flags.img --avb1-key a1_key.pem --avb1-cert a1_cert.pem >/dev/null 2>&1
"$ABR" repack a1u_custom -o a1_custom_aik.img --avb1-key aik/mykey >/dev/null 2>&1
"$ABR" repack a1u_custom -o a1_custom_combined.img --avb1-key a1_combined.pem >/dev/null 2>&1
sign_py a1_custom_flags.img a1_custom_expected.img a1_key.pem a1_cert.pem
if cmp -s a1_custom_flags.img a1_custom_expected.img &&
    cmp -s a1_custom_flags.img a1_custom_aik.img && cmp -s a1_custom_flags.img a1_custom_combined.img &&
    python3 "$AVB1" verify a1_custom_flags.img a1_cert.pem >/dev/null; then
    pass "--avb1-key/--avb1-cert (RSA-4096): equal to the independent signer; the AIK 'name.pk8 + name.x509.pem' form and a combined PEM give the same bytes"
else
    fail "signing with a custom key is wrong"
fi
if "$ABR" repack a1u_custom -o x.img --avb1-key a1_key.pem --avb1-cert "$VK_PEM" 2>a1_mismatch.err; then
    fail "a certificate that does not belong to the key was accepted"
elif grep -q "does not belong to this private key" a1_mismatch.err; then
    pass "a certificate that does not match the private key is refused"
else
    fail "key/certificate mismatch refusal is not explanatory"
fi
if "$ABR" repack a1u_custom -o x.img --avb1-key a1_key.pem 2>a1_nocert.err; then
    fail "a key without any certificate was accepted"
elif grep -q -- "--avb1-cert" a1_nocert.err; then
    pass "a key without a certificate is refused with the way to supply one"
else
    fail "missing-certificate refusal is not explanatory"
fi

# --- vendor trailer after the signature keeps its place when the signature changes size ---
size=$(python3 "$AVB1" size fx/avb1_v1.img)
sign_py fx/avb1_v1.img a1_v1_custom.img a1_key.pem a1_cert.pem
python3 - "$size" <<'PYEOF'
import sys
size = int(sys.argv[1])
d = open("a1_v1_custom.img", "rb").read()
assert len(d) < size + 2048
d += b"\0" * (size + 2048 - len(d)) + b"EEEE" + bytes(range(96))
open("a1_trailer.img", "wb").write(d)
PYEOF
"$ABR" unpack a1_trailer.img -o a1u_trailer >a1u_trailer.log 2>&1
sed -i 's/^cmdline=.*/cmdline=androidboot.edited=1/' a1u_trailer/manifest.txt
"$ABR" repack a1u_trailer -o a1_trailer.out >a1_trailer.log 2>&1
if python3 - "$size" <<'PYEOF'
import sys
size = int(sys.argv[1])
d = open("a1_trailer.out", "rb").read()
t = b"EEEE" + bytes(range(96))
sys.exit(0 if d[size + 2048:size + 2048 + len(t)] == t and len(d) == size + 2048 + len(t) else 1)
PYEOF
then
    ok_trailer=1
else
    ok_trailer=0
fi
if [ $ok_trailer -eq 1 ] && python3 "$AVB1" verify a1_trailer.out >/dev/null &&
    grep -q "whose private key abr does not have" a1_trailer.log &&
    grep -q "kept as they were" a1_trailer.log; then
    pass "foreign signer + vendor trailer: re-signed with the AOSP test key (with a warning), trailer still where it was, stale-trailer warning shown"
else
    fail "foreign signer / trailer handling is wrong ($(grep -h '^warning' a1_trailer.log | head -2))"
fi

# --- adding a signature to an unsigned image; options that do not apply ---
"$ABR" unpack fx/avb1_v0.img -o a1u_unsigned >/dev/null 2>&1
"$ABR" repack a1u_unsigned -o a1_unsigned.out >/dev/null 2>&1
echo 'avb1_signature=true' >>a1u_unsigned/manifest.txt
"$ABR" repack a1u_unsigned -o a1_added.out >/dev/null 2>&1
"$ABR" unpack fx/avb1_v0.img -o a1u_unsigned2 >/dev/null 2>&1
"$ABR" repack a1u_unsigned2 -o a1_added_key.out --avb1-key aik/mykey >/dev/null 2>&1
sign_py fx/avb1_v0.img a1_added_expected.img
sign_py fx/avb1_v0.img a1_added_key_expected.img a1_key.pem a1_cert.pem
if cmp -s fx/avb1_v0.img a1_unsigned.out && cmp -s a1_added.out a1_added_expected.img &&
    cmp -s a1_added_key.out a1_added_key_expected.img; then
    pass "an unsigned image stays unsigned; avb1_signature=true or --avb1-key adds a signature (equal to the independent signer's)"
else
    fail "adding an AVBv1 signature is wrong"
fi
if "$ABR" repack vbv3_dummy -o x.img --avb1-key aik/mykey >/dev/null 2>&1; then :; fi
"$ABR" unpack vendor_boot_v3.img -o a1u_vb >/dev/null 2>&1
if said "only apply to boot and recovery images" "$ABR" repack a1u_vb -o a1_vb.out --avb1-key aik/mykey; then
    pass "--avb1-key on a non-boot image is ignored with a warning"
else
    fail "--avb1-key on a vendor_boot gives no warning"
fi

# --- ECDSA-signed originals: not judged, kept, re-signed (with the AOSP RSA key) after an edit ---
openssl ecparam -name prime256v1 -genkey -noout -out a1_ec.pem >/dev/null 2>&1
openssl req -x509 -new -key a1_ec.pem -subj "/CN=abr ec test" -days 3650 -out a1_ec_cert.pem >/dev/null 2>&1
python3 "$AVB1" sign fx/avb1_v0.img /boot a1_ec.pem a1_ec_cert.pem --ec >a1_ec.img
"$ABR" unpack a1_ec.img -o a1u_ec >a1u_ec.log 2>&1
"$ABR" repack a1u_ec -o a1_ec.out >/dev/null 2>&1
printf 'abr-edit' >>a1u_ec/ramdisk.cpio
"$ABR" repack a1u_ec -o a1_ec.edit >a1_ec.edit.log 2>&1
if said "signature not checked" "$ABR" info a1_ec.img && cmp -s a1_ec.img a1_ec.out &&
    python3 "$AVB1" verify a1_ec.edit >/dev/null && grep -q "whose private key abr does not have" a1_ec.edit.log; then
    pass "an ECDSA boot signature is reported as not checked, round-trips exactly, and is replaced by an RSA one after an edit (with a warning)"
else
    fail "ECDSA-signed boot image handling is wrong"
fi

# --- the real boot_signer, compiled from AOSP's sources ---
BCPROV=""
for j in "${BCPROV_JAR:-}" /usr/share/java/bcprov.jar /usr/share/java/bcprov-*.jar; do
    if [ -n "$j" ] && [ -f "$j" ]; then BCPROV="$j"; break; fi
done
if command -v javac >/dev/null 2>&1 && command -v java >/dev/null 2>&1 && [ -n "$BCPROV" ] &&
    mkdir -p bsclasses && javac -cp "$BCPROV" -d bsclasses "$BS_DIR/BootSignature.java" "$BS_DIR/Utils.java" >/dev/null 2>&1; then
    bs() { java -cp "$BCPROV:bsclasses" com.android.verity.BootSignature "$@" >/dev/null 2>&1; }

    bs_ok=1
    for v in v0 v0_qcdt v1 v2; do
        bs /boot fx/avb1_$v.img "$VK_PK8" "$VK_PEM" bs_$v.img || { bs_ok=0; echo "  $v: boot_signer failed"; continue; }
        cmp -s bs_$v.img a1_$v.img || { bs_ok=0; echo "  $v: boot_signer and the Python signer disagree"; }
        said "signature VALID" "$ABR" info bs_$v.img || { bs_ok=0; echo "  $v: info does not report VALID for boot_signer's image"; }
        "$ABR" unpack bs_$v.img -o bsu_$v >/dev/null 2>&1
        "$ABR" repack bsu_$v -o bs_$v.out >/dev/null 2>&1
        cmp -s bs_$v.img bs_$v.out || { bs_ok=0; echo "  $v: round trip of boot_signer's image differs"; }
    done
    if [ $bs_ok -eq 1 ]; then
        pass "images signed by the real boot_signer (v0, v0+QCDT, v1, v2): same bytes as the Python signer, info says VALID, round trip identical"
    else
        fail "images signed by the real boot_signer are not handled correctly"
    fi

    bs_ok=1
    for v in v0 v0_qcdt v1 v2; do
        bs -verify a1_$v.edit || { bs_ok=0; echo "  $v: boot_signer -verify rejects abr's re-signed image"; }
        n=$(python3 "$AVB1" size a1_$v.edit)
        head -c "$n" a1_$v.edit >core_$v.img
        bs /boot core_$v.img "$VK_PK8" "$VK_PEM" core_$v.signed || { bs_ok=0; echo "  $v: boot_signer failed on the edited core"; continue; }
        cmp -s core_$v.signed a1_$v.edit || { bs_ok=0; echo "  $v: abr's signature differs from boot_signer's"; }
    done
    PK8_CUSTOM=aik/mykey.pk8
    bs /boot core_v1.img "$PK8_CUSTOM" a1_cert.pem core_v1_custom.signed || bs_ok=0
    head -c "$(python3 "$AVB1" size a1_custom_flags.img)" a1_custom_flags.img >core_custom.img
    bs /boot core_custom.img "$PK8_CUSTOM" a1_cert.pem core_custom.signed || bs_ok=0
    cmp -s core_custom.signed a1_custom_flags.img || { bs_ok=0; echo "  custom key: abr differs from boot_signer"; }
    bs -verify a1_custom_flags.img || { bs_ok=0; echo "  custom key: boot_signer -verify rejects abr's image"; }
    if [ $bs_ok -eq 1 ]; then
        pass "abr's re-signed images (AOSP key and a custom RSA-4096 key) are byte-identical to the real boot_signer's and pass its -verify"
    else
        fail "abr's signatures differ from the real boot_signer's"
    fi
else
    echo "SKIP: real boot_signer cross-check (needs javac, java and BouncyCastle bcprov.jar; set BCPROV_JAR to point at it)"
fi

# =========================================================================
# Identification: the signatures of Android Image Kitchen's androidbootimg.magic,
# written down as code. tests/tools/magic_samples.py makes one sample per rule
# (and the awkward combinations) and knows what each must be called. When
# ABR_AIK_MAGIC points at AIK's magic file and `file` is installed, abr is
# compared with file(1) itself as well (the file is not part of this repository).
# =========================================================================
if [ -n "${ABR_AIK_MAGIC:-}" ] && [ ! -f "$ABR_AIK_MAGIC" ]; then
    echo "warning: ABR_AIK_MAGIC=$ABR_AIK_MAGIC is not a file; comparing with the built-in table only" >&2
    ABR_AIK_MAGIC=""
fi
if python3 "$TOOLS/magic_samples.py" check "$ABR" "${ABR_AIK_MAGIC:-}" >idcheck.out 2>&1; then
    pass "identify: every signature of AIK's androidbootimg.magic is recognised as file(1) names it ($(tail -n1 idcheck.out))"
else
    fail "identify: abr and AIK's signature table disagree"
    cat idcheck.out
fi
python3 "$TOOLS/magic_samples.py" write idsamples
if [ "$("$ABR" identify idsamples/loki_rec)" = "idsamples/loki_rec: AOSP bootimg, LOKI header (recovery)" ]; then
    pass "identify: without -b the file name is printed in front of the label"
else
    fail "identify: output format"
fi
for kind in blob:SIGNBLOB chromeos:ChromeOS sin2:Sony osip:OSIP krnl:Rockchip; do
    sample="${kind%%:*}"
    word="${kind##*:}"
    rm -rf id_out
    out="$("$ABR" unpack "idsamples/$sample" -o id_out 2>&1)"
    rc=$?
    if [ $rc -ne 0 ] && grep -q -- "$word" <<<"$out" && [ ! -e id_out ]; then
        pass "unpack: a $sample image is named in the refusal, and no output directory is left behind"
    else
        fail "unpack: a $sample image should be refused by name, leaving no directory (rc=$rc: $out)"
    fi
done

echo ""
echo "===== $PASS passed, $FAIL failed ====="
exit "$FAIL"
