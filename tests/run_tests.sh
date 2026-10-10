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

# ---- constant signing blocks: Nook headers in front, the Bump magic behind
roundtrip_check fx/boot_v0_nook.img "boot v0 behind a Nook signing header (1 MiB master_boot.key)" nook
expect_line rt_nook "prefix_kind=NOOK" "Nook header recognised as a constant block"
roundtrip_check fx/boot_v0_nooktab.img "boot v0 behind a Nook tablet signing header (256 KiB)" nooktab
expect_line rt_nooktab "prefix_kind=NOOKTAB" "Nook tablet header recognised as a constant block"
for pair in nook:1048576 nooktab:262144; do
    t=${pair%%:*}
    hdr=${pair##*:}
    "$ABR" unpack "fx/boot_v0_$t.img" -o "ed_$t" >/dev/null 2>&1
    edit_and_repack "ed_$t" "ed_$t.out"
    "$ABR" unpack "ed_$t.out" -o "ed_${t}_re" >/dev/null 2>&1
    if cmp -s <(head -c "$hdr" "fx/boot_v0_$t.img") <(head -c "$hdr" "ed_$t.out") &&
        cmp -s "ed_$t/ramdisk.cpio" "ed_${t}_re/ramdisk.cpio" &&
        ! grep -q "kept as they were" "ed_$t.out.err"; then
        pass "an edited image behind a Nook header ($t): header put back unchanged, no stale-signature warning"
    else
        fail "an edited image behind a Nook header ($t) lost the header or warned about it"
    fi
done
if said "NOOK signing (green loader)" "$ABR" identify -b fx/boot_v0_nook.img; then
    pass "identify names the Nook wrapper"
else
    fail "identify did not name the Nook wrapper"
fi

roundtrip_check fx/boot_v0_bump.img "boot v0 + LG Bump footer" bump1
roundtrip_check fx/boot_v0_bump_filled.img "boot v0 + LG Bump footer + zero fill to the partition size" bump2
roundtrip_check fx/boot_v0_bump_seandroid.img "boot v0 + SEAndroid marker + LG Bump footer" bump3
for pair in bump:bump1 bump_filled:bump2 bump_seandroid:bump3; do
    t=${pair%%:*}
    rt=${pair##*:}
    "$ABR" unpack "fx/boot_v0_$t.img" -o "ed_$t" >/dev/null 2>&1
    edit_and_repack "ed_$t" "ed_$t.out"
    "$ABR" unpack "ed_$t.out" -o "ed_${t}_re" >/dev/null 2>&1
    before=$(stat -c %s "fx/boot_v0_$t.img")
    after=$(stat -c %s "ed_$t.out")
    ok=1
    ! grep -q "kept as they were" "ed_$t.out.err" || ok=0
    cmp -s "rt_$rt/tail.bin" "ed_${t}_re/tail.bin" || ok=0
    if [ "$t" = bump_filled ]; then  # still padded to the partition size
        [ "$after" = "$before" ] || ok=0
    else
        [ "$after" -lt "$before" ] || ok=0
    fi
    if [ "$ok" = 1 ]; then
        pass "an edited image keeps its constant footer ($t), no stale-signature warning"
    else
        fail "an edited image with a constant footer ($t) warned or lost the footer"
    fi
done

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

# ---- Marvell PXA headers, and where a long command line is cut
roundtrip_check fx/boot_pxa_030_dt.img "boot PXA (Marvell, unknown=0x03000000) with a dt blob" pxa030
expect_line rt_pxa030 "pxa=true" "PXA: recognised as the Marvell header variant"
expect_line rt_pxa030 "pxa_unknown=0x3000000" "PXA: the 'unknown' word is kept"
expect_line rt_pxa030 "id_scheme=sha1_dt" "PXA: id recognised as SHA-1 over kernel+ramdisk+second+dt"
expect_key rt_pxa030 dt_file "PXA: dt blob extracted as its own file"
roundtrip_check fx/boot_pxa_020_p4096_second.img "boot PXA, page 4096, second stage, no dt" pxa020
expect_line rt_pxa020 "id_scheme=sha1" "PXA: id without a dt entry is plain SHA-1"
roundtrip_check fx/boot_pxa_028_longcmd.img "boot PXA, command line cut after 511 bytes" pxa028
expect_line rt_pxa028 "cmdline_split=511" "PXA: a command line cut after 511 bytes (old C mkbootimg) is recorded"
roundtrip_check fx/boot_pxa_signed.img "boot PXA with a vendor signature after the image" pxas
roundtrip_check fx/boot_v0_cmdline512.img "boot v0: long command line cut at 512 (AOSP mkbootimg.py)" cmd512
roundtrip_check fx/boot_v0_cmdline511.img "boot v0: long command line cut at 511 (old C mkbootimg)" cmd511
expect_line rt_cmd511 "cmdline_split=511" "v0: the cut after 511 bytes is recorded"
if grep -q "^cmdline_split=" rt_cmd512/manifest.txt; then
    fail "v0: a cut at 512 is the default and needs no record"
else
    pass "v0: a cut at 512 is the default and needs no record"
fi
id_follows_edit fx/boot_pxa_030_dt.img sha1_dt pxa "PXA: after a ramdisk edit the id follows its scheme (checked independently) and the new ramdisk is in the image"
if said "PXA variant (030)" "$ABR" identify fx/boot_pxa_030_dt.img; then
    pass "identify: the PXA fixture is named like AIK's magic file names it"
else
    fail "identify: PXA fixture"
fi

# The real pxa-mkbootimg / pxa-unpackbootimg (osm0sis/pxa-mkbootimg; gcc -o pxa-mkbootimg
# mkbootimg.c libmincrypt/sha.c -I.) as an independent builder and reader.
# PXA_MKBOOTIMG=/path/to/pxa-mkbootimg [PXA_UNPACKBOOTIMG=/path/to/pxa-unpackbootimg]
if [ -n "${PXA_MKBOOTIMG:-}" ] && [ -x "$PXA_MKBOOTIMG" ]; then
    pxa_ok=1
    mvalue() { grep "^$2=" "$1/manifest.txt" | head -1 | cut -d= -f2-; }
    head -c 1500000 /dev/urandom >pxa_k.bin
    head -c 700000 /dev/urandom >pxa_r.bin
    head -c 60000 /dev/urandom >pxa_dt.bin
    long_cmd="androidboot.hardware=pxa1908 $(head -c 700 /dev/zero | tr '\0' x)"
    for variant in "02000000 2048 plain short" "02800000 4096 dt long" "03000000 2048 dt short" "03000000 16384 plain long"; do
        set -- $variant
        unk=$1 ps=$2 kind=$3 cmd=$4
        args=(--kernel pxa_k.bin --ramdisk pxa_r.bin --base 10000000 --pagesize "$ps" --unknown "$unk" --board SM-J110F)
        [ "$kind" = dt ] && args+=(--dt pxa_dt.bin)
        if [ "$cmd" = long ]; then args+=(--cmdline "$long_cmd"); else args+=(--cmdline "console=ttyS0 androidboot.selinux=permissive"); fi
        "$PXA_MKBOOTIMG" "${args[@]}" -o pxa_real.img >/dev/null 2>&1 || { pxa_ok=0; echo "  pxa-mkbootimg failed for $variant"; continue; }
        rm -rf pxa_u
        "$ABR" unpack pxa_real.img -o pxa_u >/dev/null 2>&1 || { pxa_ok=0; echo "  abr cannot unpack the real tool's image ($variant)"; continue; }
        "$ABR" repack pxa_u -o pxa_re.img >/dev/null 2>&1
        cmp -s pxa_real.img pxa_re.img || { pxa_ok=0; echo "  untouched repack differs ($variant)"; }
        head -c 123457 /dev/urandom >pxa_u/ramdisk.cpio
        "$ABR" repack pxa_u -o pxa_ed.img >/dev/null 2>&1
        a2=(--kernel pxa_u/kernel --ramdisk pxa_u/ramdisk.cpio --base 0 --pagesize "$(mvalue pxa_u page_size)"
            --unknown "$(mvalue pxa_u pxa_unknown | sed 's/^0x//')" --kernel_offset "$(mvalue pxa_u kernel_addr | sed 's/^0x//')"
            --ramdisk_offset "$(mvalue pxa_u ramdisk_addr | sed 's/^0x//')" --second_offset "$(mvalue pxa_u second_addr | sed 's/^0x//')"
            --tags_offset "$(mvalue pxa_u tags_addr | sed 's/^0x//')" --board "$(mvalue pxa_u board_name)" --cmdline "$(mvalue pxa_u cmdline)")
        [ -f pxa_u/dt.img ] && a2+=(--dt pxa_u/dt.img)
        "$PXA_MKBOOTIMG" "${a2[@]}" -o pxa_ref.img >/dev/null 2>&1
        cmp -s pxa_ed.img pxa_ref.img || { pxa_ok=0; echo "  edited image differs from the real tool's ($variant)"; }
        if [ -n "${PXA_UNPACKBOOTIMG:-}" ] && [ -x "$PXA_UNPACKBOOTIMG" ]; then
            rm -rf pxa_x
            mkdir pxa_x
            "$PXA_UNPACKBOOTIMG" -i pxa_ed.img -o pxa_x >/dev/null 2>&1
            cmp -s pxa_x/pxa_ed.img-ramdisk pxa_u/ramdisk.cpio || { pxa_ok=0; echo "  pxa-unpackbootimg does not read the edited ramdisk back ($variant)"; }
        fi
    done
    if [ $pxa_ok -eq 1 ]; then
        pass "PXA: images from the real pxa-mkbootimg round-trip exactly, and abr's edited images equal the real tool's (and read back)"
    else
        fail "PXA: abr and the real pxa-mkbootimg disagree"
    fi
else
    echo "SKIP: real pxa-mkbootimg cross-check (set PXA_MKBOOTIMG, and optionally PXA_UNPACKBOOTIMG, to the compiled osm0sis/pxa-mkbootimg tools)"
fi

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
    # Flip bits of byte 100 (an XOR, so it always changes: writing a fixed value would leave the
    # signature as it was once in 256 runs, when that byte happens to hold it already).
    python3 -c "import sys; b = bytearray(open(sys.argv[1], 'rb').read()); b[100] ^= 0x55; open(sys.argv[2], 'wb').write(b)" rsa_ref.sig rsa_bad.sig
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
# The ramdisk as a directory. `unpack` writes ramdisk.cpio (what the image held, byte for
# byte) and, when the archive can be one, the directory ramdisk/ with ramdisk.meta (owners,
# modes, order ...); a ramdisk that is several cpio archives one after the other (what Magisk
# makes) gets a directory and a metadata file for each (ramdisk.vol2/, ramdisk.vol2.meta ...).
# Archives come from tests/tools/cpio_gen.py (a writer of its own) and, when GNU cpio is
# installed, from `find . | cpio -H newc -o` as Android Image Kitchen makes them; GNU cpio and
# cpio_gen.py's reader also judge what abr built. Checked: an untouched image repacks to the
# same bytes; the directory is the archive's contents; every kind of edit (a file, a deletion,
# a new file/directory/link, a mode in the metadata, the archive file itself, both at once, one
# archive of several) lands in the image as asked and nowhere else; what a new file gets as its
# owner and mode, and what a symbolic link is on every system; archives that cannot be a
# directory are kept as files with the reason; nothing of somebody else's is overwritten.
# =========================================================================
RDG="$TOOLS/cpio_gen.py"
RDO="$TOOLS/ramdisk_oracle.py"
HAVE_GNU_CPIO=0
command -v cpio >/dev/null 2>&1 && HAVE_GNU_CPIO=1
RD_GNU=""
[ "$HAVE_GNU_CPIO" = 1 ] && RD_GNU=", GNU cpio agrees"
RD_WINE=0
case "$ABR" in */winebin/*) RD_WINE=1 ;; esac
head -c 100000 /dev/urandom | gzip -9n >rd_kernel.gz

rd_image() {  # <style> [<archive file>]: rdimg_<style>.img around a ramdisk of that style (boot v0, gzip)
    local style="$1" cpio="${2:-rdimg_$1.cpio}"
    [ -n "${2:-}" ] || python3 "$RDG" "$style" "$cpio" || return 1
    gzip -9n -c "$cpio" >"rdimg_$style.gz"
    python3 "$MKBOOTIMG" >/dev/null --header_version 0 --kernel rd_kernel.gz --ramdisk "rdimg_$style.gz" \
        --pagesize 2048 --base 0x10000000 --cmdline "rd=$style" --output "rdimg_$style.img"
}
# The records of an archive (of every archive of a stream of several), read by cpio_gen.py's own parser:
# "type mode uid gid size ino nlink name". Nothing here is piped into `grep -q` or `head`: under
# pipefail the writer may be killed by SIGPIPE and the pipeline then fails though grep was satisfied.
rd_list() { python3 "$RDG" list "$1"; }
rd_has() {  # <archive> <regex>: a record of the archive matches
    local out
    out="$(python3 "$RDG" list "$1")" || return 1
    grep -q -- "$2" <<<"$out"
}
rd_names() { rd_list "$1" | awk '{print $8}'; }
rd_count() { local out; out="$(python3 "$RDG" list "$1")" || return 1; wc -l <<<"$out" | tr -d ' '; }
rd_oracle() {  # <unpack dir> [<prefix>]: GNU cpio agrees with every volume's directory (true without GNU cpio)
    [ "$HAVE_GNU_CPIO" = 1 ] || return 0
    local p="${2:-ramdisk}"
    python3 -I "$RDO" --prefix "$1/$p.cpio" "$1" "$p" >"$1.oracle" 2>&1 || { cat "$1.oracle" >&2; return 1; }
}
rd_oracle_frags() {  # <unpack dir> <prefix>...: GNU cpio agrees with the directories of every prefix
    local d="$1" p
    shift
    for p in "$@"; do rd_oracle "$d" "$p" || return 1; done
}
rd_link() { python3 -I "$RDO" --link "$1"; }  # what a link in a tree points at: a real link, a Cygwin file or a text file
rd_cyg() {  # <path> <target>: a link in the Cygwin/MSYS2 format ("!<symlink>", FF FE, UTF-16LE, 00 00)
    python3 -c 'import sys; open(sys.argv[1], "wb").write(b"!<symlink>\xff\xfe" + sys.argv[2].encode("utf-16-le", "surrogatepass") + b"\0\0")' "$1" "$2"
}
rd_is_cyg() { [ "$(head -c 12 "$1" | od -An -tx1 | tr -d ' \n')" = "213c73796d6c696e6b3efffe" ]; }  # starts like a Cygwin link file

# Checks are collected and reported together: rd_ck <what> <command...> notes what failed.
rd_fails=""
rd_ck() { local what="$1"; shift; "$@" >/dev/null || rd_fails="$rd_fails [$what]"; }
rd_done() {  # <what the checks show>: one PASS or FAIL for the checks since the last call
    if [ -z "$rd_fails" ]; then pass "$1"; else fail "$1 --$rd_fails"; fi
    rd_fails=""
}
rd_unpack() {  # <image> <dir>: a fresh unpack
    rm -rf "$2"
    "$ABR" unpack "$1" -o "$2" >"$2.log" 2>&1
}
rd_repack_unpack() {  # <dir> <name>: repack <dir> to <name>.img (log: <name>.rlog), unpack that to <name>_re
    "$ABR" repack "$1" -o "$2.img" >"$2.rlog" 2>&1 || return 1
    rm -rf "${2}_re"
    "$ABR" unpack "$2.img" -o "${2}_re" >/dev/null 2>&1
}
changed_lines() {  # <archive a> <archive b>: how many lines differ between two listings
    diff <(rd_list "$1") <(rd_list "$2") | grep -c '^[<>]'
}
rd_idx() {  # <names, one per line> <name>: the position of a name (1 = first), nothing if it is not there
    grep -n -x -F -- "$2" <<<"$1" | cut -d: -f1
}
rd_vols() { case "$1" in volumes2 | volumes_tail) echo 2 ;; volumes3) echo 3 ;; *) echo 1 ;; esac; }
rd_has_text() { grep -q -F -- "$2" "$1"; }  # <file> <text>
# `diff -r` follows links: a dangling one is an error (status 2) and a link to a directory is compared as
# the directory. Compared as what they are, a link is the same when its target is.
rd_same_tree() { diff -r --no-dereference "$1" "$2" >/dev/null; }  # <dir> <dir>
rd_same_tree_x() { diff -r --no-dereference -x "$3" "$1" "$2" >/dev/null; }  # <dir> <dir> <a name to leave out>
rd_differ() { ! cmp -s "$1" "$2"; }                                  # <file> <file>: not the same bytes
rd_meta_add() {  # <meta file> <line>: a line of its own for a path (in front of the end record)
    python3 -I - "$1" "$2" <<'PYEOF'
import sys
path, line = sys.argv[1], sys.argv[2]
lines = open(path, "rb").read().decode("utf-8").split("\n")
at = next(i for i, l in enumerate(lines) if l.startswith("T "))
lines.insert(at, line)
open(path, "wb").write("\n".join(lines).encode("utf-8"))
PYEOF
}
rd_meta_sub() {  # <meta file> <old line> <new line>: one line of the metadata replaced (it must be there)
    python3 -I - "$1" "$2" "$3" <<'PYEOF'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path, "rb").read().decode("utf-8").split("\n")
if old not in lines:
    sys.exit("no line '%s' in %s" % (old, path))
lines[lines.index(old)] = new
open(path, "wb").write("\n".join(lines).encode("utf-8"))
PYEOF
}

if [ -x "$UNIT" ]; then
    if out=$("$UNIT" cpio 2>&1); then
        pass "cpio and ramdisk-directory unit tests ($(tail -n 1 <<<"$out"))"
    else
        fail "cpio and ramdisk-directory unit tests: $(tail -n 4 <<<"$out" | tr '\n' ' ')"
    fi
fi

# ---- archives that become directories: untouched round trip, the directory, GNU cpio's verdict
for style in mkbootfs crc upper uppercrc owners aik dotroot explicit tail weird big volumes2 volumes3 volumes_tail; do
    if ! rd_image "$style"; then fail "ramdisk directory: could not make the $style fixture"; continue; fi
    n="$(rd_vols "$style")"
    rd_unpack "rdimg_$style.img" "rd_$style"
    "$ABR" repack "rd_$style" -o "rd_$style.out" >/dev/null 2>&1
    if [ "$RD_WINE" = 1 ] && [ "$style" = weird ]; then
        # A quote, a backslash or a tab cannot be in a name on Windows: the ramdisk stays a file, with the reason.
        rd_ck "stays a file" grep -q "ramdisk.cpio stays a file only" "rd_$style.log"
        rd_ck "the reason" grep -q "Windows does not allow" "rd_$style.log"
        rd_ck "no directory" test ! -e "rd_$style/ramdisk"
        rd_ck "no metadata" test ! -e "rd_$style/ramdisk.meta"
        rd_ck "nothing about a tree in the manifest" test -z "$(grep _tree "rd_$style/manifest.txt")"
        rd_ck "ramdisk.cpio is the original" cmp -s "rdimg_$style.cpio" "rd_$style/ramdisk.cpio"
        rd_ck "untouched repack is identical" cmp -s "rdimg_$style.img" "rd_$style.out"
        rd_done "ramdisk directory (weird, on Windows): names that Windows cannot hold keep the ramdisk a file, with the reason, and it repacks identically"
        continue
    fi
    rd_ck "manifest" grep -qx "ramdisk_tree=ramdisk" "rd_$style/manifest.txt"
    rd_ck "ramdisk/" test -d "rd_$style/ramdisk"
    rd_ck "ramdisk.meta" test -f "rd_$style/ramdisk.meta"
    rd_ck "ramdisk.cpio is the original" cmp -s "rdimg_$style.cpio" "rd_$style/ramdisk.cpio"
    rd_ck "untouched repack is identical" cmp -s "rdimg_$style.img" "rd_$style.out"
    rd_ck "no warning" test -z "$(grep '^warning' "rd_$style.log")"
    if [ "$n" -gt 1 ]; then
        rd_ck "volumes in the manifest" grep -qx "ramdisk_tree_volumes=$n" "rd_$style/manifest.txt"
        for k in $(seq 2 "$n"); do
            rd_ck "ramdisk.vol$k/" test -d "rd_$style/ramdisk.vol$k"
            rd_ck "ramdisk.vol$k.meta" test -f "rd_$style/ramdisk.vol$k.meta"
        done
        rd_ck "no volume too many" test ! -e "rd_$style/ramdisk.vol$((n + 1))"
        rd_ck "the log counts the archives" grep -q "$n cpio archives one after the other" "rd_$style.log"
    else
        rd_ck "no volumes in the manifest" test -z "$(grep _tree_volumes "rd_$style/manifest.txt")"
        rd_ck "no vol2" test ! -e "rd_$style/ramdisk.vol2"
    fi
    rd_ck "GNU cpio" rd_oracle "rd_$style"
    rd_done "ramdisk directory ($style, $n archive$([ "$n" = 1 ] || echo s)): ramdisk.cpio is the original, the directories come with their metadata, an untouched repack is byte-identical$RD_GNU"
done
# What the metadata says about the layout of each kind of archive.
rd_ck "names ./x" grep -qx "names dotslash" rd_aik/ramdisk.meta
rd_ck "its own order" grep -qx "order archive" rd_aik/ramdisk.meta
rd_ck "inodes" grep -qx "inode explicit" rd_aik/ramdisk.meta
rd_ck "link counts" grep -qx "nlink posix" rd_aik/ramdisk.meta
rd_ck "GNU cpio's upper case digits" grep -qx "hex upper" rd_aik/ramdisk.meta
rd_ck "512-byte fill" grep -qx "tail align 512" rd_aik/ramdisk.meta
rd_ck "root" grep -q " ino=131073 \.$" rd_aik/ramdisk.meta
rd_done "ramdisk directory: the layout of a 'find . | cpio' archive (names ./x, its own order, inodes, link counts, upper case digits, 512-byte fill) is recorded as such"
rd_ck "plain names" grep -qx "names plain" rd_dotroot/ramdisk.meta
rd_ck "root is an entry" grep -q "^d 0755 0 0 1760000000 ino=131073 \.$" rd_dotroot/ramdisk.meta
rd_ck "upper case" grep -qx "hex upper" rd_dotroot/ramdisk.meta
rd_ck "plain names in the tree" test -f rd_dotroot/ramdisk/init.rc
rd_done "ramdisk directory: GNU cpio 2.15's layout (the root '.', every other name plain) is recorded as such"
rd_ck "format crc" grep -qx "format crc" rd_crc/ramdisk.meta
rd_ck "lower case" grep -qx "hex lower" rd_crc/ramdisk.meta
rd_ck "upper crc" grep -qx "format crc" rd_uppercrc/ramdisk.meta
rd_ck "upper crc digits" grep -qx "hex upper" rd_uppercrc/ramdisk.meta
rd_ck "upper" grep -qx "hex upper" rd_upper/ramdisk.meta
rd_ck "mkbootfs: lower case" grep -qx "hex lower" rd_mkbootfs/ramdisk.meta
rd_ck "mkbootfs: sequential inodes" grep -qx "inode sequential 300000" rd_mkbootfs/ramdisk.meta
rd_ck "mkbootfs: link count 1" grep -qx "nlink 1" rd_mkbootfs/ramdisk.meta
rd_ck "mkbootfs: sorted" grep -qx "order sorted" rd_mkbootfs/ramdisk.meta
rd_ck "mkbootfs: 256-byte fill" grep -qx "tail align 256" rd_mkbootfs/ramdisk.meta
rd_ck "mkbootfs: device node" grep -q "^c 0600 0 0 0 rdev=5:1 dev/console$" rd_mkbootfs/ramdisk.meta
rd_ck "mkbootfs: fifo" grep -q "^p 0600 0 0 0 - dev/pipe$" rd_mkbootfs/ramdisk.meta
rd_ck "mkbootfs: link" grep -q "^l 0777 0 0 0 - etc$" rd_mkbootfs/ramdisk.meta
rd_ck "mkbootfs: the link's target" test "$(rd_link rd_mkbootfs/ramdisk/etc)" = "/system/etc"
rd_ck "mkbootfs: defaults for what is new" grep -qx "newmode file=0644 exec=0755 dir=0755 link=0777" rd_mkbootfs/ramdisk.meta
rd_done "ramdisk directory: the metadata says what the directory cannot (magic, digit case, inodes, order, fill, device numbers, the owner defaults of what is new)"
if [ "$RD_WINE" = 0 ]; then
    rd_ck "quoted backslash" grep -q '^f 0644 0 0 0 - "res/back\\\\slash"$' rd_weird/ramdisk.meta
    rd_ck "quoted tab" grep -q '^f 0644 0 0 0 - "res/tab\\there"$' rd_weird/ramdisk.meta
    rd_ck "a quote inside a name needs no quoting" grep -qx 'f 0644 0 0 0 - res/"quoted".txt' rd_weird/ramdisk.meta
    rd_ck "a leading space needs none either" grep -qx 'f 0644 0 0 0 - res/ leading' rd_weird/ramdisk.meta
    rd_ck "space" test "$(cat "rd_weird/ramdisk/res/with space.txt")" = "1"
    rd_ck "UTF-8" test "$(cat "rd_weird/ramdisk/res/ünï cödé.txt")" = "5ü"
    rd_done "ramdisk directory: names with spaces, quotes, backslashes, tabs and UTF-8 are quoted in the metadata and read back"
fi

# A real `find . | cpio -R 0:0 -H newc -o`, which is how Android Image Kitchen packs a ramdisk. GNU cpio
# writes the digits of its headers in upper case and numbers inodes as the file system does.
rd_size_multiple() { [ $(($(wc -c <"$1") % $2)) = 0 ]; }  # <file> <n>: the size is a multiple of n
if [ "$HAVE_GNU_CPIO" = 1 ]; then
    rm -rf gnu_src gnu_src2 && mkdir -p gnu_src/sbin gnu_src/dev gnu_src/lib/modules gnu_src/proc gnu_src2/overlay.d/sbin gnu_src2/.backup
    printf 'on init\n' >gnu_src/init.rc
    printf '#!/bin/sh\n' >gnu_src/sbin/adbd && chmod 755 gnu_src/sbin/adbd
    head -c 70000 /dev/urandom >gnu_src/lib/modules/big.ko
    : >gnu_src/empty
    ln -s ../init.rc gnu_src/sbin/rc
    printf 'KEEPVERITY=true\n' >gnu_src2/.backup/.magisk
    printf '#!/system/bin/sh\n' >gnu_src2/overlay.d/sbin/magisk && chmod 755 gnu_src2/overlay.d/sbin/magisk
    for fmt in newc crc; do
        (cd gnu_src && find . | cpio --quiet -R 0:0 -H "$fmt" -o) >"gnu_$fmt.cpio" 2>/dev/null
        rd_image "gnu_$fmt" "gnu_$fmt.cpio"
        rd_unpack "rdimg_gnu_$fmt.img" "rd_gnu_$fmt"
        "$ABR" repack "rd_gnu_$fmt" -o "rd_gnu_$fmt.out" >/dev/null 2>&1
        rd_ck "directory" grep -qx "ramdisk_tree=ramdisk" "rd_gnu_$fmt/manifest.txt"
        rd_ck "exact" cmp -s "rdimg_gnu_$fmt.img" "rd_gnu_$fmt.out"
        rd_ck "no warning" test -z "$(grep '^warning' "rd_gnu_$fmt.log")"
        rd_ck "upper case digits" grep -qx "hex upper" "rd_gnu_$fmt/ramdisk.meta"
        rd_ck "512-byte blocks" grep -qx "tail align 512" "rd_gnu_$fmt/ramdisk.meta"
        rd_ck "the link" test "$(rd_link "rd_gnu_$fmt/ramdisk/sbin/rc")" = "../init.rc"
        rd_ck "GNU cpio" rd_oracle "rd_gnu_$fmt"
        rd_done "ramdisk directory: an archive written by GNU cpio itself (find . | cpio -H $fmt) becomes a directory, round-trips exactly, and cpio agrees"
    done
    # Two of them one after the other.
    (cd gnu_src2 && find . | cpio --quiet -R 0:0 -H newc -o) >gnu_second.cpio 2>/dev/null
    cat gnu_newc.cpio gnu_second.cpio >gnu_vol.cpio
    rd_image gnu_vol gnu_vol.cpio
    rd_unpack rdimg_gnu_vol.img rd_gnu_vol
    "$ABR" repack rd_gnu_vol -o rd_gnu_vol.out >/dev/null 2>&1
    rd_ck "two archives" grep -qx "ramdisk_tree_volumes=2" rd_gnu_vol/manifest.txt
    rd_ck "exact" cmp -s rdimg_gnu_vol.img rd_gnu_vol.out
    rd_ck "second directory" test -f rd_gnu_vol/ramdisk.vol2/.backup/.magisk
    rd_ck "GNU cpio, both archives" rd_oracle rd_gnu_vol
    rd_done "ramdisk directory: two archives written by GNU cpio one after the other are two directories, round-trip exactly, and cpio agrees with each"

    # ... and what abr builds is something GNU cpio extracts as the directory says.
    rm -rf gnu_edit && cp -a rd_gnu_newc gnu_edit
    printf 'on init\n    start x\n' >gnu_edit/ramdisk/init.rc
    rm gnu_edit/ramdisk/empty
    printf 'new\n' >gnu_edit/ramdisk/sbin/newtool
    "$ABR" repack gnu_edit -o gnu_edit.img >/dev/null 2>&1
    "$ABR" unpack gnu_edit.img -o gnu_edit_re >/dev/null 2>&1
    rm -rf gnu_x && mkdir -p gnu_x && (cd gnu_x && cpio --quiet -idm <../gnu_edit_re/ramdisk.cpio) 2>/dev/null
    rd_ck "GNU cpio agrees" rd_oracle gnu_edit_re
    rd_ck "changed file" test "$(cat gnu_x/init.rc)" = "$(printf 'on init\n    start x')"
    rd_ck "deleted file" test ! -e gnu_x/empty
    rd_ck "new file" test "$(cat gnu_x/sbin/newtool)" = "new"
    rd_ck "link untouched" test "$(readlink gnu_x/sbin/rc)" = "../init.rc"
    rd_ck "new file's mode" rd_has gnu_edit_re/ramdisk.cpio "^f 0644 0 0 4 .* 1 sbin/newtool$"
    rd_ck "still upper case" grep -qx "hex upper" gnu_edit_re/ramdisk.meta
    rd_ck "still in 512-byte blocks" rd_size_multiple gnu_edit_re/ramdisk.cpio 512
    rd_done "ramdisk directory: an edited AIK-style ramdisk extracts with GNU cpio as the edit says (changed, deleted and new file, the link untouched), in upper case digits and 512-byte blocks as before"
else
    echo "note: GNU cpio not installed; its cross-checks are skipped"
fi

# ---- archives that cannot be a directory stay files, with the reason
rd_bad_ok=1
rd_bad_names=""
while IFS='|' read -r style why; do
    [ -n "$style" ] || continue
    if ! rd_image "$style"; then rd_bad_ok=0; rd_bad_names="$rd_bad_names $style(fixture)"; continue; fi
    rd_unpack "rdimg_$style.img" "rd_$style"
    "$ABR" repack "rd_$style" -o "rd_$style.out" >/dev/null 2>&1
    if grep -q "ramdisk.cpio stays a file only" "rd_$style.log" && grep -q -F -- "$why" "rd_$style.log" &&
        ! grep -q "_tree" "rd_$style/manifest.txt" && [ ! -e "rd_$style/ramdisk" ] && [ ! -e "rd_$style/ramdisk.meta" ] &&
        [ ! -e "rd_$style/ramdisk.vol2" ] && cmp -s "rdimg_$style.cpio" "rd_$style/ramdisk.cpio" &&
        cmp -s "rdimg_$style.img" "rd_$style.out"; then
        :
    else
        rd_bad_ok=0
        rd_bad_names="$rd_bad_names $style"
    fi
done <<'EOF'
hardlink|hard links
dup|occurs twice
dotdot|goes through
absolute|absolute path
nodir|without (or before) its directory
junk|neither zero fill nor another cpio archive
junk2|neither zero fill nor another cpio archive
offbound|not at a multiple of 4
odc|old kind
trunc|runs past the end
linkbreak|line break
mixed|are mixed
mixcase|upper case in some records
EOF
[ "$rd_bad_ok" = 1 ] &&
    pass "ramdisk directory: hard links, a name twice, '..', an absolute name, a missing parent, junk after the end or between two archives, an archive off its boundary, odc, a cut-short archive, a link target with a line break and mixed magics or digit cases stay files, with the reason, and round-trip exactly" ||
    fail "ramdisk directory: archives that cannot be a directory are not handled:$rd_bad_names"
# An image whose ramdisk is no archive at all is not worth a word.
rm -rf rd_nocpio && "$ABR" unpack fx/boot_v0_rawid.img -o rd_nocpio >rd_nocpio.log 2>&1
if ! grep -q "stays a file only" rd_nocpio.log && ! grep -q "_tree" rd_nocpio/manifest.txt; then
    pass "ramdisk directory: a ramdisk that is no cpio archive is left alone without a message"
else
    fail "ramdisk directory: a ramdisk that is no cpio archive got a message or a directory ($(cat rd_nocpio.log))"
fi

# ---- editing the directory
rd_unpack rdimg_mkbootfs.img rd_base

rm -rf rd_e1 && cp -a rd_base rd_e1 && printf '# added\n' >>rd_e1/ramdisk/init.rc
rd_ck "repack" rd_repack_unpack rd_e1 rd_e1o
rd_ck "two lines differ" test "$(changed_lines rd_base/ramdisk.cpio rd_e1o_re/ramdisk.cpio)" = 2
d="$(diff <(rd_list rd_base/ramdisk.cpio) <(rd_list rd_e1o_re/ramdisk.cpio) || true)"
rd_ck "it is init.rc" grep -q "init.rc" <<<"$d"
rd_ck "the directory comes back as it was" rd_same_tree rd_e1/ramdisk rd_e1o_re/ramdisk
rd_ck "the metadata is the same" cmp -s rd_base/ramdisk.meta rd_e1o_re/ramdisk.meta
rd_ck "the message" grep -q "built from the directory ramdisk/" rd_e1o.rlog
rd_done "ramdisk directory: an edited file lands in the image (only its size changes), nothing else moves, the metadata is the same"

rm -rf rd_e2 && cp -a rd_base rd_e2 && rm -r rd_e2/ramdisk/lib/modules rd_e2/ramdisk/sepolicy
rd_ck "repack" rd_repack_unpack rd_e2 rd_e2o
names="$(rd_names rd_e2o_re/ramdisk.cpio)"
rd_ck "gone" test -z "$(grep -E 'lib/modules|sepolicy' <<<"$names")"
rd_ck "the directory they were in stays" grep -qx "lib" <<<"$names"
rd_ck "17 records" test "$(wc -l <<<"$names" | tr -d ' ')" = 17
rd_ck "inodes are counted again" test "$(rd_list rd_e2o_re/ramdisk.cpio | awk '{print $6}' | tr '\n' ' ')" = "$(seq 300000 300016 | tr '\n' ' ')"
rd_ck "GNU cpio" rd_oracle rd_e2o_re
rd_done "ramdisk directory: a deleted directory and a deleted file are gone from the image, the inodes are counted again$RD_GNU"

rm -rf rd_e3 && cp -a rd_base rd_e3
printf 'hi\n' >rd_e3/ramdisk/new_file
mkdir rd_e3/ramdisk/newdir && printf '#!/bin/sh\n' >rd_e3/ramdisk/newdir/tool
printf '/system/bin/sh' >rd_e3/ramdisk/sbin/sh   # a text file where there is no metadata line: a plain file
rd_ck "repack" rd_repack_unpack rd_e3 rd_e3o
rd_ck "new file" rd_has rd_e3o_re/ramdisk.cpio "^f 0644 0 0 3 .* 1 new_file$"
rd_ck "new directory" rd_has rd_e3o_re/ramdisk.cpio "^d 0755 0 0 0 .* 1 newdir$"
rd_ck "text file that looks like a link target" rd_has rd_e3o_re/ramdisk.cpio "^f 0644 0 0 14 .* 1 sbin/sh$"
rd_ck "script in the new directory" rd_has rd_e3o_re/ramdisk.cpio "^f 0755 0 0 10 .* 1 newdir/tool$"
rd_ck "sorted as mkbootfs sorts" test "$(rd_names rd_e3o_re/ramdisk.cpio | tr '\n' ' ')" = "$(rd_names rd_e3o_re/ramdisk.cpio | LC_ALL=C sort -t/ -k1,1 | tr '\n' ' ')"
rd_ck "GNU cpio" rd_oracle rd_e3o_re
rd_done "ramdisk directory: a new file, directory and file inside it join the archive in their place with the defaults (root, 0755 directory, 0644 file, 0755 for a #! script)$RD_GNU"

rm -rf rd_e4 && cp -a rd_base rd_e4
sed -i 's/^f 0750 0 0 0 - init.rc$/f 6755 1000 2000 1700000000 - init.rc/; s/^d 0500 0 0 0 - config$/d 1777 0 0 0 - config/' rd_e4/ramdisk.meta
rd_ck "repack" rd_repack_unpack rd_e4 rd_e4o
rd_ck "setuid file with owners" rd_has rd_e4o_re/ramdisk.cpio "^f 6755 1000 2000 .* init.rc$"
rd_ck "sticky directory" rd_has rd_e4o_re/ramdisk.cpio "^d 1777 0 0 0 .* config$"
rd_ck "nothing else moved" test "$(changed_lines rd_base/ramdisk.cpio rd_e4o_re/ramdisk.cpio)" = 4
rd_ck "the time" grep -qx "f 6755 1000 2000 1700000000 - init.rc" rd_e4o_re/ramdisk.meta
rd_done "ramdisk directory: a mode, owner and time edited in ramdisk.meta (setuid, sticky ...) reach the image"

# The metadata gone: warned about, everything made up like mkbootfs does.
rm -rf rd_e5 && cp -a rd_base rd_e5 && rm rd_e5/ramdisk.meta
rd_ck "repack" rd_repack_unpack rd_e5 rd_e5o
rd_ck "warned" grep -q "no ramdisk.meta" rd_e5o.rlog
rd_ck "a device node is a plain file then" rd_has rd_e5o_re/ramdisk.cpio "^f 0644 0 0 0 .* dev/console$"
rd_ck "22 records" test "$(rd_count rd_e5o_re/ramdisk.cpio)" = 22
rd_done "ramdisk directory: without ramdisk.meta repack warns and makes owners, modes and order up (a device node is a plain file then)"

# ---- editing ramdisk.cpio instead, or both
rm -rf rd_e6 && cp -a rd_base rd_e6 && python3 "$RDG" owners rd_e6/ramdisk.cpio
rd_ck "repack" rd_repack_unpack rd_e6 rd_e6o
rd_ck "the archive file is what the image got" cmp -s rd_e6o_re/ramdisk.cpio rd_e6/ramdisk.cpio
rd_ck "the directory was not used" test -z "$(grep 'built from the director' rd_e6o.rlog)"
rd_done "ramdisk directory: when only ramdisk.cpio was replaced, the image gets that archive, not the (untouched) directory"
rm -rf rd_e7 && cp -a rd_base rd_e7 && python3 "$RDG" owners rd_e7/ramdisk.cpio && printf 'more\n' >>rd_e7/ramdisk/init.rc
if ! "$ABR" repack rd_e7 -o rd_e7.img >rd_e7.log 2>&1 && grep -q "ramdisk-from" rd_e7.log && [ ! -s rd_e7.img ]; then
    pass "ramdisk directory: when both ramdisk.cpio and the directory were changed, repack stops and says how to choose"
else
    fail "ramdisk directory: both changed was not refused ($(cat rd_e7.log))"
fi
"$ABR" repack rd_e7 -o rd_e7t.img --ramdisk-from tree >/dev/null 2>&1 && "$ABR" unpack rd_e7t.img -o rd_e7t_re >/dev/null 2>&1
"$ABR" repack rd_e7 -o rd_e7c.img --ramdisk-from cpio >/dev/null 2>&1 && "$ABR" unpack rd_e7c.img -o rd_e7c_re >/dev/null 2>&1
if rd_same_tree rd_e7/ramdisk rd_e7t_re/ramdisk && cmp -s rd_e7c_re/ramdisk.cpio rd_e7/ramdisk.cpio && rd_differ rd_e7t.img rd_e7c.img; then
    pass "ramdisk directory: --ramdisk-from tree builds from the directory, --ramdisk-from cpio takes ramdisk.cpio"
else
    fail "ramdisk directory: --ramdisk-from"
fi
if ! "$ABR" repack rd_e7 -o rd_e7x.img --ramdisk-from both >/dev/null 2>rd_e7x.err && grep -q "'tree' or 'cpio'" rd_e7x.err; then
    pass "ramdisk directory: --ramdisk-from with anything but tree or cpio is refused"
else
    fail "ramdisk directory: --ramdisk-from with a wrong value"
fi
# The directory is deleted by hand: the archive file is what is left.
rm -rf rd_e7d && cp -a rd_base rd_e7d && rm -rf rd_e7d/ramdisk && "$ABR" repack rd_e7d -o rd_e7d.img >/dev/null 2>&1
if cmp -s rd_e7d.img rdimg_mkbootfs.img; then
    pass "ramdisk directory: a directory that was removed is not missed (ramdisk.cpio is used)"
else
    fail "ramdisk directory: a removed directory"
fi

# ---- --tree-only and --no-tree
rm -rf rd_to && "$ABR" unpack rdimg_mkbootfs.img -o rd_to --tree-only >rd_to.log 2>&1
"$ABR" repack rd_to -o rd_to.img >/dev/null 2>&1
if [ ! -e rd_to/ramdisk.cpio ] && [ -d rd_to/ramdisk ] && cmp -s rd_to.img rdimg_mkbootfs.img; then
    pass "unpack --tree-only: no ramdisk.cpio, and the untouched directory still repacks to the identical image"
else
    fail "unpack --tree-only"
fi
printf 'x\n' >>rd_to/ramdisk/init.rc
if rd_repack_unpack rd_to rd_to2 && [ "$(changed_lines rd_base/ramdisk.cpio rd_to2_re/ramdisk.cpio)" = 2 ]; then
    pass "unpack --tree-only: an edit of the directory works without the archive file"
else
    fail "unpack --tree-only: editing"
fi
rm -rf rd_to3 && "$ABR" unpack rdimg_hardlink.img -o rd_to3 --tree-only >rd_to3.log 2>&1
if [ -f rd_to3/ramdisk.cpio ] && cmp -s rd_to3/ramdisk.cpio rdimg_hardlink.cpio; then
    pass "unpack --tree-only: an archive that cannot be a directory keeps its ramdisk.cpio"
else
    fail "unpack --tree-only: a refused archive lost its file"
fi
rm -rf rd_nt && "$ABR" unpack rdimg_mkbootfs.img -o rd_nt --no-tree >rd_nt.log 2>&1
"$ABR" repack rd_nt -o rd_nt.img >/dev/null 2>&1
if [ ! -e rd_nt/ramdisk ] && [ ! -e rd_nt/ramdisk.meta ] && ! grep -q _tree rd_nt/manifest.txt && cmp -s rd_nt.img rdimg_mkbootfs.img; then
    pass "unpack --no-tree: only ramdisk.cpio, as before"
else
    fail "unpack --no-tree"
fi
if ! "$ABR" unpack rdimg_mkbootfs.img -o rd_bad --no-tree --tree-only >/dev/null 2>&1 && ! "$ABR" unpack rdimg_mkbootfs.img -o rd_bad2 --tre >/dev/null 2>&1; then
    pass "unpack: contradicting or unknown options are refused"
else
    fail "unpack: options"
fi

# ---- somebody else's ramdisk/ is not touched; an earlier unpack's is replaced
rm -rf rd_alien && mkdir -p rd_alien/ramdisk && printf 'precious\n' >rd_alien/ramdisk/mine.txt
"$ABR" unpack rdimg_mkbootfs.img -o rd_alien >rd_alien.log 2>&1
"$ABR" repack rd_alien -o rd_alien.img >/dev/null 2>&1
if [ "$(cat rd_alien/ramdisk/mine.txt)" = "precious" ] && ! grep -q _tree rd_alien/manifest.txt && grep -q "is not an empty directory" rd_alien.log &&
    cmp -s rd_alien.img rdimg_mkbootfs.img; then
    pass "unpack: a ramdisk/ that is not from an earlier unpack is left alone (the ramdisk stays a file, with a message)"
else
    fail "unpack: a foreign ramdisk/ was touched or ignored silently ($(cat rd_alien.log))"
fi
rm -rf rd_empty && mkdir -p rd_empty/ramdisk && "$ABR" unpack rdimg_mkbootfs.img -o rd_empty >/dev/null 2>&1
grep -q _tree rd_empty/manifest.txt && pass "unpack: an empty ramdisk/ is no obstacle" || fail "unpack: an empty ramdisk/ was treated as foreign"
rm -rf rd_again && cp -a rd_base rd_again && printf 'junk\n' >rd_again/ramdisk/leftover && printf 'junk\n' >>rd_again/ramdisk/init.rc
"$ABR" unpack rdimg_mkbootfs.img -o rd_again >/dev/null 2>&1
if [ ! -e rd_again/ramdisk/leftover ] && rd_same_tree rd_base/ramdisk rd_again/ramdisk && cmp -s rd_base/ramdisk.meta rd_again/ramdisk.meta; then
    pass "unpack: unpacking again over an earlier unpack replaces the directory (no leftovers, no old edits)"
else
    fail "unpack: unpacking over an earlier unpack"
fi
rm -rf rd_gone && cp -a rd_base rd_gone && "$ABR" unpack rdimg_mkbootfs.img -o rd_gone --no-tree >/dev/null 2>&1
if [ ! -e rd_gone/ramdisk ] && [ ! -e rd_gone/ramdisk.meta ]; then
    pass "unpack --no-tree over an earlier unpack removes its directory (it would be a trap, the repack would ignore it)"
else
    fail "unpack --no-tree left the old directory behind"
fi
rm -rf rd_refused && cp -a rd_base rd_refused && "$ABR" unpack rdimg_hardlink.img -o rd_refused >/dev/null 2>&1
if [ ! -e rd_refused/ramdisk ] && [ ! -e rd_refused/ramdisk.meta ] && ! grep -q _tree rd_refused/manifest.txt; then
    pass "unpack: an archive that cannot be a directory does not leave the directory of an earlier unpack behind"
else
    fail "unpack: a stale directory survived a refused archive"
fi

# ---- AIK-style: new entries go where the archive's own order puts them
rm -rf rd_e17 && cp -a rd_aik rd_e17
printf 'hi\n' >rd_e17/ramdisk/newfile && printf 'more\n' >>rd_e17/ramdisk/init.rc
mkdir rd_e17/ramdisk/lib/newdir && printf 'z\n' >rd_e17/ramdisk/lib/newdir/z
rd_ck "repack" rd_repack_unpack rd_e17 rd_e17o
names="$(rd_names rd_e17o_re/ramdisk.cpio)"
last_module="$(grep -n '^\./lib/modules/' <<<"$names" | tail -n 1 | cut -d: -f1)"
rd_ck "the new directory follows its sibling's last record" test "$(rd_idx "$names" ./lib/newdir)" = "$((last_module + 1))"
rd_ck "its file follows it" test "$(rd_idx "$names" ./lib/newdir/z)" = "$((last_module + 2))"
rd_ck "the new file of the root goes last" test "$(tail -n 1 <<<"$names")" = "./newfile"
rd_ck "lib's link count follows the new subdirectory" rd_has rd_e17o_re/ramdisk.cpio "^d 0755 0 0 0 [0-9]* 4 ./lib$"
rd_ck "the root is where it was, with its link count" test "$(rd_list rd_e17o_re/ramdisk.cpio | head -n 1 | awk '{print $8, $7}')" = ". 11"
rd_ck "upper case digits kept" grep -qx "hex upper" rd_e17o_re/ramdisk.meta
rd_ck "GNU cpio" rd_oracle rd_e17o_re
rd_done "ramdisk directory: new entries of an AIK-style archive go behind their directory's last record, link counts follow the new subdirectories$RD_GNU"

# ---- permissions: what a file that is put into the unpacked ramdisk gets. The metadata is the only
# authority for what was unpacked (Windows has no owners or modes, so nothing is read from the file system
# about those); what is new gets the defaults of the metadata's header; an executable one is told by a
# #! line or an ELF header (everywhere) or by the executable bit (where the system has one).
rm -rf rd_p1 && cp -a rd_base rd_p1
printf 'data\n' >rd_p1/ramdisk/plain.txt
printf '#!/system/bin/sh\necho hi\n' >rd_p1/ramdisk/script
printf '\177ELF\002\001\001\000 program' >rd_p1/ramdisk/prog
printf '\177ELF\002\001\001\000 library' >rd_p1/ramdisk/libx.so
printf '\177ELF\002\001\001\000 module' >rd_p1/ramdisk/mod.ko
printf 'executable by its bit\n' >rd_p1/ramdisk/chmodx.txt && chmod 755 rd_p1/ramdisk/chmodx.txt
printf 'private by its bits\n' >rd_p1/ramdisk/chmod600.txt && chmod 600 rd_p1/ramdisk/chmod600.txt
mkdir rd_p1/ramdisk/newdir && printf 'x' >rd_p1/ramdisk/newdir/inner.cfg
printf 'junk' >rd_p1/ramdisk/.DS_Store && printf 'junk' >rd_p1/ramdisk/newdir/Thumbs.db
chmod 777 rd_p1/ramdisk/init.rc  # a file of the unpack: the metadata decides, not this
rd_ck "repack" rd_repack_unpack rd_p1 rd_p1o
L=rd_p1o_re/ramdisk.cpio
rd_ck "plain data: 0644, root" rd_has $L "^f 0644 0 0 5 .* 1 plain.txt$"
rd_ck "#! script: 0755" rd_has $L "^f 0755 0 0 25 .* 1 script$"
rd_ck "ELF program: 0755" rd_has $L "^f 0755 0 0 .* 1 prog$"
rd_ck "ELF library: 0644" rd_has $L "^f 0644 0 0 .* 1 libx.so$"
rd_ck "kernel module: 0644" rd_has $L "^f 0644 0 0 .* 1 mod.ko$"
rd_ck "new directory: 0755" rd_has $L "^d 0755 0 0 0 .* 1 newdir$"
rd_ck "file in it: 0644" rd_has $L "^f 0644 0 0 1 .* 1 newdir/inner.cfg$"
if [ "$RD_WINE" = 0 ]; then
    rd_ck "executable bit: 0755" rd_has $L "^f 0755 0 0 22 .* 1 chmodx.txt$"
else
    rd_ck "no executable bit on Windows: 0644" rd_has $L "^f 0644 0 0 22 .* 1 chmodx.txt$"
fi
rd_ck "only the executable bit counts: 0644" rd_has $L "^f 0644 0 0 20 .* 1 chmod600.txt$"
rd_ck "an entry of the unpack keeps its mode from the metadata" rd_has $L "^f 0750 0 0 .* 1 init.rc$"
rd_ck "file manager leftovers stay out" test -z "$(rd_names $L | grep -E 'DS_Store|Thumbs')"
rd_ck "the note names the new entries and their modes" grep -q "9 new entries not in ramdisk.meta, with its default owner 0:0 and these modes: " rd_p1o.rlog
rd_ck "the note: a script" grep -q "script f 0755" rd_p1o.rlog
rd_ck "the note: a library" grep -q "libx.so f 0644" rd_p1o.rlog
rd_ck "the note: the leftovers" grep -q "'.DS_Store' is a leftover of a file manager" rd_p1o.rlog
rd_ck "GNU cpio" rd_oracle rd_p1o_re
rd_done "ramdisk permissions: files put into the directory get root, 0644 or 0755 (a #! script, an ELF program, the executable bit where there is one), a directory 0755; an entry of the unpack keeps its mode from ramdisk.meta whatever the file system says; the repack lists the new ones$RD_GNU"

# What a new entry gets is what the header of the metadata says, and a line of its own beats that.
rm -rf rd_p2 && cp -a rd_base rd_p2
printf 'data\n' >rd_p2/ramdisk/plain.txt
printf '#!/bin/sh\n' >rd_p2/ramdisk/script
mkdir rd_p2/ramdisk/newdir
printf 'own line\n' >rd_p2/ramdisk/own.txt
rd_meta_sub rd_p2/ramdisk.meta "default uid=0 gid=0 mtime=0 dev=0:0" "default uid=1000 gid=2000 mtime=1234 dev=0:0"
rd_meta_sub rd_p2/ramdisk.meta "newmode file=0644 exec=0755 dir=0755 link=0777" "newmode file=0640 exec=0700 dir=0750 link=0755"
rd_meta_add rd_p2/ramdisk.meta "f 0600 5 6 7 - own.txt"
rd_ck "the header was edited" grep -qx "newmode file=0640 exec=0700 dir=0750 link=0755" rd_p2/ramdisk.meta
rd_ck "repack" rd_repack_unpack rd_p2 rd_p2o
L=rd_p2o_re/ramdisk.cpio
rd_ck "new file: the default owner and mode" rd_has $L "^f 0640 1000 2000 5 .* 1 plain.txt$"
rd_ck "new script: the default for an executable" rd_has $L "^f 0700 1000 2000 10 .* 1 script$"
rd_ck "new directory: the default" rd_has $L "^d 0750 1000 2000 0 .* 1 newdir$"
rd_ck "the time" grep -q "^f 0640 1000 2000 1234 - plain.txt$" rd_p2o_re/ramdisk.meta
rd_ck "a line of its own wins" rd_has $L "^f 0600 5 6 9 .* 1 own.txt$"
rd_ck "and is not called new" test -z "$(grep 'own.txt f' rd_p2o.rlog)"
rd_ck "an entry of the unpack is unaffected" rd_has $L "^f 0750 0 0 .* 1 init.rc$"
rd_done "ramdisk permissions: what is new gets the owner, time and modes that the header of ramdisk.meta says (edit them there), and a line of its own in ramdisk.meta gives a path whatever it should have"

# An entry that changed its kind is new: the old line (a mode of a directory) does not carry over to a file.
rm -rf rd_p3 && cp -a rd_base rd_p3
rm -r rd_p3/ramdisk/config && printf 'x' >rd_p3/ramdisk/config   # a 0500 directory becomes a file
rd_ck "repack" rd_repack_unpack rd_p3 rd_p3o
rd_ck "a file with the default mode, not the directory's" rd_has rd_p3o_re/ramdisk.cpio "^f 0644 0 0 1 .* 1 config$"
rd_ck "and the repack says it is new" grep -q "config f 0644" rd_p3o.rlog
rd_done "ramdisk permissions: a directory replaced by a file is a new file (default mode), not a file with the directory's mode"

# A file that is gone is gone, and the repack says so.
rm -rf rd_p4 && cp -a rd_base rd_p4 && rm rd_p4/ramdisk/init.rc rd_p4/ramdisk/sepolicy
rd_ck "repack" rd_repack_unpack rd_p4 rd_p4o
rd_ck "the note names them" grep -q "2 entries of ramdisk.meta are not in the directory and left out of the ramdisk: init.rc, sepolicy" rd_p4o.rlog
rd_done "ramdisk permissions: the repack names the entries of the metadata that were deleted from the directory"

# ---- symbolic links: a link where the system has them, the file Cygwin and MSYS2 use ("!<symlink>",
# FF FE, the target in UTF-16LE, 00 00; on Windows with the System attribute) where it has not -- no
# administrator rights needed -- and every form is read back as a link, wherever the tree was carried.
if [ "$RD_WINE" = 0 ]; then
    rd_ck "etc is a link" test -L rd_base/ramdisk/etc
    rd_ck "sbin/ueventd is a link" test -L rd_base/ramdisk/sbin/ueventd
    rd_ck "its target" test "$(readlink rd_base/ramdisk/sbin/ueventd)" = "../init"
else
    rd_ck "etc is a Cygwin link file" rd_is_cyg rd_base/ramdisk/etc
    rd_ck "sbin/ueventd is a Cygwin link file" rd_is_cyg rd_base/ramdisk/sbin/ueventd
    rd_ck "etc: not a real link" test ! -L rd_base/ramdisk/etc
    rd_ck "etc: UTF-16LE target, two zero bytes" test "$(od -An -tx1 -j12 rd_base/ramdisk/etc | tr -d ' \n')" = "$(python3 -c 'print("/system/etc".encode("utf-16-le").hex() + "0000")')"
    rd_ck "etc: it starts with !<symlink> and the FF FE mark" test "$(head -c 12 rd_base/ramdisk/etc | od -An -tx1 | tr -d ' \n')" = "213c73796d6c696e6b3efffe"
fi
rd_ck "what a link points at, whichever form" test "$(rd_link rd_base/ramdisk/sbin/ueventd)" = "../init"
rd_done "ramdisk symlinks: a link in the directory is a real link where the system has them and a Cygwin link file ('!<symlink>', UTF-16LE) on Windows"

rm -rf rd_l1 && cp -a rd_base rd_l1
rd_cyg rd_l1/ramdisk/cyg_ascii "/system/bin/sh"
rd_cyg rd_l1/ramdisk/cyg_utf8 "$(printf 'caf\303\251/\360\237\230\200')"
printf '!<symlink>legacy/utf8\0' >rd_l1/ramdisk/cyg_legacy                  # the older, UTF-8 form
printf '../textual\r\n' >rd_l1/ramdisk/text_link                              # a text file: a link when its line says l
rd_meta_add rd_l1/ramdisk.meta "l 0755 7 8 9 - text_link"
rd_cyg rd_l1/ramdisk/init.rc "/not/a/link"                                    # a file as far as the metadata says: stays one
if [ "$RD_WINE" = 0 ]; then
    ln -s lib rd_l1/ramdisk/dir_link                                          # a link to a directory is a link, not the directory
    ln -s /does/not/exist rd_l1/ramdisk/dangling
    ln -s "target with spaces" rd_l1/ramdisk/spaced
fi
rd_ck "repack" rd_repack_unpack rd_l1 rd_l1o
L=rd_l1o_re/ramdisk.cpio
rd_ck "Cygwin link file" rd_has $L "^l 0777 0 0 14 .* 1 cyg_ascii$"
rd_ck "its target" test "$(rd_link rd_l1o_re/ramdisk/cyg_ascii)" = "/system/bin/sh"
rd_ck "Cygwin link file with UTF-16 surrogates" rd_has $L "^l 0777 0 0 10 .* 1 cyg_utf8$"
rd_ck "its UTF-8 target" test "$(rd_link rd_l1o_re/ramdisk/cyg_utf8)" = "$(printf 'caf\303\251/\360\237\230\200')"
rd_ck "the older UTF-8 form" rd_has $L "^l 0777 0 0 11 .* 1 cyg_legacy$"
rd_ck "text file where the metadata says l" rd_has $L "^l 0755 7 8 10 .* 1 text_link$"
rd_ck "its target without the line break" test "$(rd_link rd_l1o_re/ramdisk/text_link)" = "../textual"
rd_ck "a file whose line says f stays a file, link-like or not" rd_has $L "^f 0750 0 0 36 .* 1 init.rc$"
rd_ck "and the repack says why" grep -q "'init.rc' looks like a symbolic link file" rd_l1o.rlog
if [ "$RD_WINE" = 0 ]; then
    rd_ck "link to a directory" rd_has $L "^l 0777 0 0 3 .* 1 dir_link$"
    rd_ck "not followed" test -z "$(rd_names $L | grep '^dir_link/')"
    rd_ck "dangling link" rd_has $L "^l 0777 0 0 15 .* 1 dangling$"
    rd_ck "target with spaces" rd_has $L "^l 0777 0 0 18 .* 1 spaced$"
fi
rd_ck "GNU cpio agrees with every link" rd_oracle rd_l1o_re
rd_done "ramdisk symlinks: real links, Cygwin link files (ASCII, UTF-8 beyond the first plane, the older UTF-8 form) and text files are all links in the archive; a file the metadata calls a file stays one$RD_GNU"

# A link file that cannot be read stops the repack, with the file's name and the reason.
rm -rf rd_l2 && cp -a rd_base rd_l2 && printf '!<symlink>\377\376\000\334\0\0' >rd_l2/ramdisk/badlink
rm -f rd_l2.img
if ! "$ABR" repack rd_l2 -o rd_l2.img >rd_l2.log 2>&1 && grep -q "the link file 'badlink' cannot be read" rd_l2.log && [ ! -s rd_l2.img ]; then
    pass "ramdisk symlinks: a link file with broken UTF-16 stops the repack and names the file (nothing is written)"
else
    fail "ramdisk symlinks: a broken link file ($(cat rd_l2.log))"
fi
rm -rf rd_l3 && cp -a rd_base rd_l3 && printf '!<symlink>\377\376\0\0' >rd_l3/ramdisk/emptylink
rm -f rd_l3.img
if ! "$ABR" repack rd_l3 -o rd_l3.img >rd_l3.log 2>&1 && grep -q "the link file 'emptylink' cannot be read: it has no target" rd_l3.log && [ ! -s rd_l3.img ]; then
    pass "ramdisk symlinks: a link file without a target stops the repack"
else
    fail "ramdisk symlinks: an empty link file ($(cat rd_l3.log))"
fi

# The tree travels: made by `unpack` here (links), repacked from a copy where every link is a Cygwin file
# (as on Windows) or a text file -- the same ramdisk comes out of any of them.
rm -rf rd_l4 && cp -a rd_base rd_l4
for l in etc sbin/ueventd; do
    t="$(rd_link "rd_l4/ramdisk/$l")"
    rm "rd_l4/ramdisk/$l"
    rd_cyg "rd_l4/ramdisk/$l" "$t"
done
"$ABR" repack rd_l4 -o rd_l4.img >/dev/null 2>&1
rm -rf rd_l5 && cp -a rd_base rd_l5
for l in etc sbin/ueventd; do
    t="$(rd_link "rd_l5/ramdisk/$l")"
    rm "rd_l5/ramdisk/$l"
    printf '%s\n' "$t" >"rd_l5/ramdisk/$l"
done
"$ABR" repack rd_l5 -o rd_l5.img >/dev/null 2>&1
if cmp -s rd_l4.img rdimg_mkbootfs.img && cmp -s rd_l5.img rdimg_mkbootfs.img; then
    pass "ramdisk symlinks: a tree whose links became Cygwin link files (Windows) or text files (git without symlinks) repacks to the identical image"
else
    fail "ramdisk symlinks: a tree carried to another system does not repack to the same image"
fi

# ---- several archives one after the other (what Magisk's cpio makes: the ramdisk, then an archive of its
# own with the backup and overlay.d): a directory and a metadata file for each, ramdisk/ and ramdisk.vol2/ ...
# rd_volumes2 is the unpack of an image whose ramdisk is an mkbootfs archive (22 records) followed by a small
# one (6 records); rd_volumes3 has three archives of three kinds (crc, `find . | cpio` style, mkbootfs).
python3 "$RDG" split rd_volumes2/ramdisk.cpio rd_vsplit
python3 "$RDG" split rd_volumes3/ramdisk.cpio rd_v3split
rd_ck "the second archive's records are in the second directory" test -f rd_volumes2/ramdisk.vol2/.backup/.magisk
rd_ck "...and are the only ones" test "$(rd_count rd_vsplit.1.cpio)" = 6
rd_ck "the first has its own 22" test "$(rd_count rd_vsplit.0.cpio)" = 22
rd_ck "three archives, three directories" test -f rd_volumes3/ramdisk.vol3/overlay.d/sbin/magisk
rd_ck "three kinds of archive, three metadata files" test "$(grep -h '^format\|^hex\|^names' rd_volumes3/ramdisk.meta rd_volumes3/ramdisk.vol2.meta rd_volumes3/ramdisk.vol3.meta | tr '\n' ' ')" = "format crc hex lower names plain format newc hex upper names dotslash format newc hex lower names plain "
rd_ck "each has the position of its own zero fill" grep -q "^tail " rd_volumes3/ramdisk.vol3.meta
rd_done "ramdisk volumes: every archive of a stream of several has its own directory and metadata (magic, digit case, names and fill are those of that archive)"

# An edit in the second one changes the second archive and nothing else.
rm -rf rd_m1 && cp -a rd_volumes2 rd_m1
printf 'KEEPVERITY=false\n' >rd_m1/ramdisk.vol2/.backup/.magisk
printf 'new\n' >rd_m1/ramdisk.vol2/overlay.d/new.rc
rd_ck "repack" rd_repack_unpack rd_m1 rd_m1o
python3 "$RDG" split rd_m1o_re/ramdisk.cpio rd_m1s
rd_ck "still two archives" test "$(ls rd_m1s.*.cpio | wc -l | tr -d ' ')" = 2
rd_ck "the first archive: the same bytes" cmp -s rd_vsplit.0.cpio rd_m1s.0.cpio
rd_ck "the second archive: not" rd_differ rd_vsplit.1.cpio rd_m1s.1.cpio
rd_ck "the second has the new file (the defaults of its metadata)" rd_has rd_m1s.1.cpio "^f 0644 0 0 4 .* 1 overlay.d/new.rc$"
rd_ck "the second has 7 records, the first 22" test "$(rd_count rd_m1s.1.cpio) $(rd_count rd_m1s.0.cpio)" = "7 22"
rd_ck "the edited file" test "$(cat rd_m1o_re/ramdisk.vol2/.backup/.magisk)" = "KEEPVERITY=false"
rd_ck "the first directory comes back as it was" rd_same_tree rd_volumes2/ramdisk rd_m1o_re/ramdisk
rd_ck "the second as it was edited" rd_same_tree rd_m1/ramdisk.vol2 rd_m1o_re/ramdisk.vol2
rd_ck "the first metadata is the same" cmp -s rd_volumes2/ramdisk.meta rd_m1o_re/ramdisk.meta
rd_ck "the manifest still says two" grep -qx "ramdisk_tree_volumes=2" rd_m1o_re/manifest.txt
rd_ck "the note names the volume of the new file" grep -q "ramdisk.vol2/: 1 new entry not in ramdisk.vol2.meta" rd_m1o.rlog
rd_ck "...and says where the ramdisk comes from" grep -q "built from the directories ramdisk/ and ramdisk.vol2/ (2 cpio archives one after the other, " rd_m1o.rlog
rd_ck "GNU cpio agrees with both" rd_oracle rd_m1o_re
rd_done "ramdisk volumes: an edit in ramdisk.vol2/ rebuilds the second archive only (the first keeps its exact bytes), the new file is listed with its volume$RD_GNU"

# ... in the first one, and the second archive keeps its bytes.
rm -rf rd_m2 && cp -a rd_volumes2 rd_m2 && printf '# added\n' >>rd_m2/ramdisk/init.rc
rd_ck "repack" rd_repack_unpack rd_m2 rd_m2o
python3 "$RDG" split rd_m2o_re/ramdisk.cpio rd_m2s
rd_ck "the second archive: the same bytes" cmp -s rd_vsplit.1.cpio rd_m2s.1.cpio
rd_ck "the first archive: not" rd_differ rd_vsplit.0.cpio rd_m2s.0.cpio
rd_ck "the second directory comes back as it was" rd_same_tree rd_volumes2/ramdisk.vol2 rd_m2o_re/ramdisk.vol2
rd_ck "the second metadata is the same" cmp -s rd_volumes2/ramdisk.vol2.meta rd_m2o_re/ramdisk.vol2.meta
rd_ck "GNU cpio agrees with both" rd_oracle rd_m2o_re
rd_done "ramdisk volumes: an edit in ramdisk/ rebuilds the first archive only$RD_GNU"

# A deletion in one, a new file in the other, a mode in the metadata of the second.
rm -rf rd_m3 && cp -a rd_volumes2 rd_m3
rm rd_m3/ramdisk.vol2/overlay.d/sbin/magisk.xz
printf 'x\n' >rd_m3/ramdisk/newfile
rd_meta_sub rd_m3/ramdisk.vol2.meta "f 0755 0 0 0 - overlay.d/sbin/magisk" "f 4755 1000 1000 1700000000 - overlay.d/sbin/magisk"
rd_ck "repack" rd_repack_unpack rd_m3 rd_m3o
L=rd_m3o_re/ramdisk.cpio
rd_ck "the deleted file is gone" test -z "$(rd_names $L | grep 'magisk.xz')"
rd_ck "its neighbour is not" rd_has $L "^f 4755 1000 1000 .* 1 overlay.d/sbin/magisk$"
rd_ck "the new file is in the first" rd_has $L "^f 0644 0 0 2 .* 1 newfile$"
rd_ck "the note names the deleted file and its metadata" grep -q "ramdisk.vol2/: 1 entry of ramdisk.vol2.meta is not in the directory and left out of the ramdisk: overlay.d/sbin/magisk.xz" rd_m3o.rlog
rd_ck "the note names the new file and its metadata" grep -q "ramdisk/: 1 new entry not in ramdisk.meta" rd_m3o.rlog
rd_ck "28 records in all (one gone, one new)" test "$(rd_count $L)" = 28
rd_ck "GNU cpio agrees with both" rd_oracle rd_m3o_re
rd_done "ramdisk volumes: a file deleted from one directory, a file added to another and a mode edited in the second metadata each land in their archive$RD_GNU"

# Each archive has the defaults of its own metadata for what is new.
rm -rf rd_m4 && cp -a rd_volumes2 rd_m4
rd_meta_sub rd_m4/ramdisk.vol2.meta "default uid=0 gid=0 mtime=0 dev=0:0" "default uid=7 gid=8 mtime=9 dev=0:0"
rd_meta_sub rd_m4/ramdisk.vol2.meta "newmode file=0644 exec=0755 dir=0755 link=0777" "newmode file=0600 exec=0700 dir=0700 link=0700"
printf 'a\n' >rd_m4/ramdisk.vol2/overlay.d/a.txt
printf 'b\n' >rd_m4/ramdisk/b.txt
rd_ck "repack" rd_repack_unpack rd_m4 rd_m4o
rd_ck "the second: its defaults" rd_has rd_m4o_re/ramdisk.cpio "^f 0600 7 8 2 .* 1 overlay.d/a.txt$"
rd_ck "the first: its own" rd_has rd_m4o_re/ramdisk.cpio "^f 0644 0 0 2 .* 1 b.txt$"
rd_ck "GNU cpio agrees with both" rd_oracle rd_m4o_re
rd_done "ramdisk volumes: what is new gets the owner and modes of the metadata of its own archive$RD_GNU"

# A metadata file that is gone: warned about, for that archive only.
rm -rf rd_m5 && cp -a rd_volumes2 rd_m5 && rm rd_m5/ramdisk.vol2.meta
printf 'n\n' >rd_m5/ramdisk.vol2/overlay.d/n.txt
rd_ck "repack" rd_repack_unpack rd_m5 rd_m5o
rd_ck "warned, naming the file" grep -q "no ramdisk.vol2.meta" rd_m5o.rlog
rd_ck "not about the other" test -z "$(grep 'no ramdisk.meta' rd_m5o.rlog)"
python3 "$RDG" split rd_m5o_re/ramdisk.cpio rd_m5s
rd_ck "the first archive is untouched" cmp -s rd_vsplit.0.cpio rd_m5s.0.cpio
rd_done "ramdisk volumes: a missing ramdisk.vol2.meta is warned about by its name and concerns that archive only"

# A directory that is gone leaves its archive out of the ramdisk.
rm -rf rd_m6 && cp -a rd_volumes2 rd_m6 && rm -rf rd_m6/ramdisk.vol2
rd_ck "repack" rd_repack_unpack rd_m6 rd_m6o
rd_ck "the image has the first archive only" test "$(rd_count rd_m6o_re/ramdisk.cpio)" = 22
rd_ck "the second archive is gone: no volume any more" test -z "$(grep _tree_volumes rd_m6o_re/manifest.txt)"
rd_ck "the first directory is the first directory" rd_same_tree rd_volumes2/ramdisk rd_m6o_re/ramdisk
rd_ck "and it was said" grep -q "ramdisk.vol2/: the directory is not there, so that archive is left out of the ramdisk" rd_m6o.rlog
rd_ck "built from the directory ramdisk/ alone" grep -q "built from the directory ramdisk/ (" rd_m6o.rlog
rd_ck "the first archive: the same bytes" cmp -s rd_vsplit.0.cpio rd_m6o_re/ramdisk.cpio
rd_done "ramdisk volumes: deleting ramdisk.vol2/ leaves the second archive out of the image (and says so)"
rm -rf rd_m7 && cp -a rd_volumes2 rd_m7 && rm -rf rd_m7/ramdisk
rd_ck "repack" rd_repack_unpack rd_m7 rd_m7o
rd_ck "the image has the second archive only" test "$(rd_count rd_m7o_re/ramdisk.cpio)" = 6
rd_ck "it is the first directory now" rd_same_tree rd_volumes2/ramdisk.vol2 rd_m7o_re/ramdisk
rd_ck "and it was said" grep -q "ramdisk/: the directory is not there, so that archive is left out of the ramdisk" rd_m7o.rlog
rd_done "ramdisk volumes: deleting ramdisk/ (the first) leaves the first archive out; what is left is the second archive"
rm -rf rd_m8 && cp -a rd_volumes2 rd_m8 && rm -rf rd_m8/ramdisk rd_m8/ramdisk.vol2
"$ABR" repack rd_m8 -o rd_m8.img >rd_m8.log 2>&1
rd_ck "every directory gone: ramdisk.cpio is used, the image is the original" cmp -s rd_m8.img rdimg_volumes2.img
rd_done "ramdisk volumes: with every directory deleted the repack takes ramdisk.cpio, as with one directory"

# A directory beyond the last one is not part of the ramdisk: a warning, and it is left alone.
rm -rf rd_m9 && cp -a rd_volumes2 rd_m9 && mkdir rd_m9/ramdisk.vol3 && printf 'x\n' >rd_m9/ramdisk.vol3/x
"$ABR" repack rd_m9 -o rd_m9.img >rd_m9.log 2>&1
rd_ck "warned" grep -q "ramdisk.vol3/ is not part of this ramdisk (the unpack had 2 archives) and is ignored" rd_m9.log
rd_ck "the image is the original" cmp -s rd_m9.img rdimg_volumes2.img
rd_ck "the directory is left in place" test -f rd_m9/ramdisk.vol3/x
rd_done "ramdisk volumes: a ramdisk.vol3/ that the unpack did not make is warned about and ignored (a new archive is made by ramdisk.cpio, not by a directory)"

# Both the archive file and a directory changed: say which, as with one.
rm -rf rd_m10 && cp -a rd_volumes2 rd_m10 && python3 "$RDG" owners rd_m10/ramdisk.cpio && printf 'k\n' >>rd_m10/ramdisk.vol2/.backup/.magisk
if ! "$ABR" repack rd_m10 -o rd_m10.img >rd_m10.log 2>&1 && grep -q "ramdisk-from" rd_m10.log; then
    pass "ramdisk volumes: ramdisk.cpio and a volume's directory both changed: repack stops and says how to choose"
else
    fail "ramdisk volumes: both changed was not refused ($(cat rd_m10.log))"
fi
"$ABR" repack rd_m10 -o rd_m10t.img --ramdisk-from tree >/dev/null 2>&1 && "$ABR" unpack rd_m10t.img -o rd_m10t_re >/dev/null 2>&1
"$ABR" repack rd_m10 -o rd_m10c.img --ramdisk-from cpio >/dev/null 2>&1 && "$ABR" unpack rd_m10c.img -o rd_m10c_re >/dev/null 2>&1
if rd_same_tree rd_m10/ramdisk.vol2 rd_m10t_re/ramdisk.vol2 && cmp -s rd_m10c_re/ramdisk.cpio rd_m10/ramdisk.cpio; then
    pass "ramdisk volumes: --ramdisk-from tree builds all the archives from their directories, --ramdisk-from cpio takes ramdisk.cpio"
else
    fail "ramdisk volumes: --ramdisk-from"
fi

# Three archives of three kinds: the middle one, written like GNU cpio does, is edited.
rm -rf rd_m11 && cp -a rd_volumes3 rd_m11
printf 'more\n' >>rd_m11/ramdisk.vol2/init.rc
printf 'hi\n' >rd_m11/ramdisk.vol2/newfile
rd_ck "repack" rd_repack_unpack rd_m11 rd_m11o
python3 "$RDG" split rd_m11o_re/ramdisk.cpio rd_m11s
rd_ck "the first archive (crc): the same bytes" cmp -s rd_v3split.0.cpio rd_m11s.0.cpio
rd_ck "the third archive: the same bytes" cmp -s rd_v3split.2.cpio rd_m11s.2.cpio
rd_ck "the second archive: not" rd_differ rd_v3split.1.cpio rd_m11s.1.cpio
rd_ck "its new file is named as its archive names them" rd_has rd_m11s.1.cpio "^f 0644 0 0 3 .* 1 ./newfile$"
rd_ck "the first is still crc" grep -qx "format crc" rd_m11o_re/ramdisk.meta
rd_ck "the second is still upper case with ./ names" grep -qx "hex upper" rd_m11o_re/ramdisk.vol2.meta
rd_ck "the third is lower case" grep -qx "hex lower" rd_m11o_re/ramdisk.vol3.meta
rd_ck "GNU cpio agrees with all three" rd_oracle rd_m11o_re
rd_done "ramdisk volumes: in three archives of three kinds the edited one keeps its own magic, digit case, names and fill, and the other two their exact bytes$RD_GNU"

# No fill between the archives, the whole padded to a block at the end: edited in the first.
rm -rf rd_m12 && cp -a rd_volumes_tail rd_m12 && printf 'q\n' >>rd_m12/ramdisk/init.rc && printf 'z\n' >rd_m12/ramdisk/zzz
rd_ck "repack" rd_repack_unpack rd_m12 rd_m12o
rd_ck "512-byte blocks at the end, as before" rd_size_multiple rd_m12o_re/ramdisk.cpio 512
rd_ck "two archives" grep -qx "ramdisk_tree_volumes=2" rd_m12o_re/manifest.txt
rd_ck "the second directory is the same" rd_same_tree rd_volumes_tail/ramdisk.vol2 rd_m12o_re/ramdisk.vol2
rd_ck "GNU cpio agrees with both" rd_oracle rd_m12o_re
rd_done "ramdisk volumes: archives with no fill between them (padded together at the end) are rebuilt the same way when the first one grows$RD_GNU"

# ---- unpacking again, or differently, over a directory of an earlier unpack
rm -rf rd_u1 && cp -a rd_volumes3 rd_u1 && "$ABR" unpack rdimg_volumes2.img -o rd_u1 >/dev/null 2>&1
rd_ck "the third archive's directory is gone" test ! -e rd_u1/ramdisk.vol3
rd_ck "... and its metadata" test ! -e rd_u1/ramdisk.vol3.meta
rd_ck "the second is the one of this image" rd_same_tree rd_volumes2/ramdisk.vol2 rd_u1/ramdisk.vol2
rd_ck "the first is too" rd_same_tree rd_volumes2/ramdisk rd_u1/ramdisk
rd_ck "the manifest says two" grep -qx "ramdisk_tree_volumes=2" rd_u1/manifest.txt
"$ABR" repack rd_u1 -o rd_u1.img >/dev/null 2>&1
rd_ck "and it repacks to the image" cmp -s rd_u1.img rdimg_volumes2.img
rd_done "unpack: over an earlier unpack with three archives, an image with two replaces two directories and removes the third (and its metadata)"
rm -rf rd_u2 && cp -a rd_volumes3 rd_u2 && "$ABR" unpack rdimg_mkbootfs.img -o rd_u2 >/dev/null 2>&1
rd_ck "no volume directories" test ! -e rd_u2/ramdisk.vol2 -a ! -e rd_u2/ramdisk.vol3
rd_ck "no volume metadata" test ! -e rd_u2/ramdisk.vol2.meta -a ! -e rd_u2/ramdisk.vol3.meta
rd_ck "no volumes in the manifest" test -z "$(grep _tree_volumes rd_u2/manifest.txt)"
rd_ck "the one directory is the new one" rd_same_tree rd_mkbootfs/ramdisk rd_u2/ramdisk
rd_done "unpack: over an earlier unpack with three archives, an image with one leaves one directory"
rm -rf rd_u3 && cp -a rd_volumes3 rd_u3 && "$ABR" unpack rdimg_volumes3.img -o rd_u3 --no-tree >/dev/null 2>&1
rd_ck "no directory" test ! -e rd_u3/ramdisk -a ! -e rd_u3/ramdisk.vol2 -a ! -e rd_u3/ramdisk.vol3
rd_ck "no metadata" test ! -e rd_u3/ramdisk.meta -a ! -e rd_u3/ramdisk.vol2.meta -a ! -e rd_u3/ramdisk.vol3.meta
rd_ck "no tree in the manifest" test -z "$(grep _tree rd_u3/manifest.txt)"
"$ABR" repack rd_u3 -o rd_u3.img >/dev/null 2>&1
rd_ck "the image is the original" cmp -s rd_u3.img rdimg_volumes3.img
rd_done "unpack --no-tree: removes the directories and metadata of every archive of an earlier unpack"
rm -rf rd_u4 && cp -a rd_volumes3 rd_u4 && "$ABR" unpack rdimg_hardlink.img -o rd_u4 >/dev/null 2>&1
rd_ck "no directory" test ! -e rd_u4/ramdisk -a ! -e rd_u4/ramdisk.vol2 -a ! -e rd_u4/ramdisk.vol3
rd_ck "no metadata" test ! -e rd_u4/ramdisk.meta -a ! -e rd_u4/ramdisk.vol2.meta -a ! -e rd_u4/ramdisk.vol3.meta
rd_ck "no tree in the manifest" test -z "$(grep _tree rd_u4/manifest.txt)"
rd_done "unpack: an archive that cannot be a directory removes the directories of every archive of an earlier unpack"

# Somebody else's ramdisk.vol2/ stops the whole directory (an archive half in a directory would be a trap).
rm -rf rd_u5 && mkdir -p rd_u5/ramdisk.vol2 && printf 'precious\n' >rd_u5/ramdisk.vol2/mine.txt
"$ABR" unpack rdimg_volumes2.img -o rd_u5 >rd_u5.log 2>&1
"$ABR" repack rd_u5 -o rd_u5.img >/dev/null 2>&1
rd_ck "mine.txt is untouched" test "$(cat rd_u5/ramdisk.vol2/mine.txt)" = "precious"
rd_ck "the first archive got no directory either" test ! -e rd_u5/ramdisk -a ! -e rd_u5/ramdisk.meta
rd_ck "no tree in the manifest" test -z "$(grep _tree rd_u5/manifest.txt)"
rd_ck "said why, naming the directory" grep -q "ramdisk.vol2 exists and is not an empty directory" rd_u5.log
rd_ck "ramdisk.cpio is there" cmp -s rd_u5/ramdisk.cpio rdimg_volumes2.cpio
rd_ck "the image is the original" cmp -s rd_u5.img rdimg_volumes2.img
rd_done "unpack: a ramdisk.vol2/ that is not from an earlier unpack is left alone, and then no archive of the ramdisk becomes a directory (the ramdisk stays a file, with a message)"
rm -rf rd_u6 && mkdir -p rd_u6/ramdisk.vol3 && "$ABR" unpack rdimg_volumes2.img -o rd_u6 >/dev/null 2>&1
rd_ck "an empty directory is no obstacle" grep -qx "ramdisk_tree_volumes=2" rd_u6/manifest.txt
rd_done "unpack: an empty ramdisk.vol3/ beyond the archives is nothing to be afraid of"

# --tree-only with volumes: no archive file, and the directories are enough.
rm -rf rd_to2 && "$ABR" unpack rdimg_volumes2.img -o rd_to2 --tree-only >rd_to2.log 2>&1
"$ABR" repack rd_to2 -o rd_to2.img >/dev/null 2>&1
rd_ck "no ramdisk.cpio" test ! -e rd_to2/ramdisk.cpio
rd_ck "both directories and metadata" test -d rd_to2/ramdisk -a -d rd_to2/ramdisk.vol2 -a -f rd_to2/ramdisk.meta -a -f rd_to2/ramdisk.vol2.meta
rd_ck "the untouched directories repack to the identical image" cmp -s rd_to2.img rdimg_volumes2.img
printf 'x\n' >rd_to2/ramdisk.vol2/overlay.d/x
rd_ck "an edit works without the archive file" rd_repack_unpack rd_to2 rd_to2e
rd_ck "and is in the second archive" test -f rd_to2e_re/ramdisk.vol2/overlay.d/x
rd_done "unpack --tree-only: an image with two archives needs only the directories and the metadata"

# ---- vendor_boot: every ramdisk fragment is a ramdisk of its own, with its directory (ramdisk0/, ramdisk1/ ...)
# and, when a fragment is several archives one after the other, ramdisk0.vol2/ ... as well.
dtc -I dts -O dtb -o rd_v.dtb v2.dts 2>/dev/null
python3 "$RDG" crc rd_frag0.cpio && python3 "$RDG" aik rd_frag1.cpio && gzip -9n -c rd_frag0.cpio >rd_frag0.gz
zstd -q -19 -f rd_frag1.cpio -o rd_frag1.zst 2>/dev/null || gzip -9n -c rd_frag1.cpio >rd_frag1.zst
python3 "$MKBOOTIMG" >/dev/null --header_version 4 --dtb rd_v.dtb --vendor_cmdline "x=y" \
    --ramdisk_type platform --ramdisk_name "" --vendor_ramdisk_fragment rd_frag0.gz \
    --ramdisk_type dlkm --ramdisk_name dlkm_frag --board_id0 7 --vendor_ramdisk_fragment rd_frag1.zst \
    --vendor_boot rd_vb.img
rd_unpack rd_vb.img rd_vbu
"$ABR" repack rd_vbu -o rd_vb.out >/dev/null 2>&1
rd_ck "a directory for each fragment" test -d rd_vbu/ramdisk0 -a -d rd_vbu/ramdisk1
rd_ck "...and its metadata" test -f rd_vbu/ramdisk0.meta -a -f rd_vbu/ramdisk1.meta
rd_ck "the manifest" grep -qx "ramdisk1_tree=ramdisk1" rd_vbu/manifest.txt
rd_ck "one archive each: no volumes" test -z "$(grep _tree_volumes rd_vbu/manifest.txt)"
rd_ck "the first fragment's archive" cmp -s rd_frag0.cpio rd_vbu/ramdisk0.cpio
rd_ck "the second fragment's archive" cmp -s rd_frag1.cpio rd_vbu/ramdisk1.cpio
rd_ck "an untouched repack is byte-identical" cmp -s rd_vb.img rd_vb.out
rd_ck "GNU cpio, first fragment" rd_oracle rd_vbu ramdisk0
rd_ck "GNU cpio, second fragment" rd_oracle rd_vbu ramdisk1
rd_done "ramdisk directory: a vendor_boot with two ramdisk fragments gets a directory for each (ramdisk0/, ramdisk1/), untouched repack is byte-identical$RD_GNU"
rm -rf rd_vbe && cp -a rd_vbu rd_vbe && printf 'edited\n' >rd_vbe/ramdisk1/init.rc
rd_ck "repack" rd_repack_unpack rd_vbe rd_vbeo
rd_ck "the other fragment keeps its exact compressed bytes" cmp -s rd_vbu/.abr_raw/ramdisk0.cpio.raw rd_vbeo_re/.abr_raw/ramdisk0.cpio.raw
rd_ck "the edited one does not" rd_differ rd_vbu/.abr_raw/ramdisk1.cpio.raw rd_vbeo_re/.abr_raw/ramdisk1.cpio.raw
rd_ck "the other fragment's directory is the same" rd_same_tree rd_vbu/ramdisk0 rd_vbeo_re/ramdisk0
rd_ck "the edit" test "$(cat rd_vbeo_re/ramdisk1/init.rc)" = "edited"
rd_ck "name survives" grep -qx "ramdisk1_name=dlkm_frag" rd_vbeo_re/manifest.txt
rd_ck "type survives" grep -qx "ramdisk1_type=dlkm" rd_vbeo_re/manifest.txt
rd_ck "GNU cpio, second fragment" rd_oracle rd_vbeo_re ramdisk1
rd_ck "GNU cpio, first fragment" rd_oracle rd_vbeo_re ramdisk0
rd_done "ramdisk directory: editing one vendor_boot fragment's directory rebuilds that fragment only (the other keeps its exact compressed bytes, names and types survive)$RD_GNU"
for j in 1 2 4 8; do "$ABR" -j$j repack rd_vbe -o rd_vbe.j$j.img >/dev/null 2>&1; done
if cmp -s rd_vbe.j1.img rd_vbe.j2.img && cmp -s rd_vbe.j1.img rd_vbe.j4.img && cmp -s rd_vbe.j1.img rd_vbe.j8.img && cmp -s rd_vbe.j1.img rd_vbeo.img; then
    pass "ramdisk directory: repacking from edited directories gives the same bytes with 1, 2, 4 and 8 threads"
else
    fail "ramdisk directory: the result depends on the number of threads"
fi
rm -rf rd_tj1 rd_tj4 && "$ABR" -j1 unpack rd_vb.img -o rd_tj1 >/dev/null 2>&1 && "$ABR" -j4 unpack rd_vb.img -o rd_tj4 >/dev/null 2>&1
if diff -r --no-dereference -x manifest.txt rd_tj1 rd_tj4 >/dev/null && diff <(tail -n +2 rd_tj1/manifest.txt) <(tail -n +2 rd_tj4/manifest.txt) >/dev/null; then
    pass "ramdisk directory: unpacking gives the same directories and manifest with 1 and 4 threads"
else
    fail "ramdisk directory: unpack depends on the number of threads"
fi

# A fragment that is several archives (a Magisk-patched vendor ramdisk, say) and another that is three.
python3 "$RDG" volumes2 rd_fragv0.cpio && python3 "$RDG" volumes3 rd_fragv1.cpio
gzip -9n -c rd_fragv0.cpio >rd_fragv0.gz
zstd -q -19 -f rd_fragv1.cpio -o rd_fragv1.zst 2>/dev/null || gzip -9n -c rd_fragv1.cpio >rd_fragv1.zst
python3 "$MKBOOTIMG" >/dev/null --header_version 4 --dtb rd_v.dtb --vendor_cmdline "x=y" \
    --ramdisk_type platform --ramdisk_name "" --vendor_ramdisk_fragment rd_fragv0.gz \
    --ramdisk_type dlkm --ramdisk_name dlkm_frag --board_id0 7 --vendor_ramdisk_fragment rd_fragv1.zst \
    --vendor_boot rd_vv.img
rd_unpack rd_vv.img rd_vvu
"$ABR" repack rd_vvu -o rd_vv.out >/dev/null 2>&1
rd_ck "volumes of the first fragment" grep -qx "ramdisk0_tree_volumes=2" rd_vvu/manifest.txt
rd_ck "volumes of the second" grep -qx "ramdisk1_tree_volumes=3" rd_vvu/manifest.txt
rd_ck "directories" test -d rd_vvu/ramdisk0 -a -d rd_vvu/ramdisk0.vol2 -a -d rd_vvu/ramdisk1 -a -d rd_vvu/ramdisk1.vol2 -a -d rd_vvu/ramdisk1.vol3
rd_ck "metadata" test -f rd_vvu/ramdisk0.vol2.meta -a -f rd_vvu/ramdisk1.vol2.meta -a -f rd_vvu/ramdisk1.vol3.meta
rd_ck "no volume too many" test ! -e rd_vvu/ramdisk0.vol3 -a ! -e rd_vvu/ramdisk1.vol4
rd_ck "the log counts them" grep -q "in 2 cpio archives one after the other -> rd_vvu/ramdisk0/, rd_vvu/ramdisk0.vol2/" rd_vvu.log
rd_ck "an untouched repack is byte-identical" cmp -s rd_vv.img rd_vv.out
rd_ck "GNU cpio, every archive of both fragments" rd_oracle_frags rd_vvu ramdisk0 ramdisk1
rd_done "ramdisk directory: a vendor_boot fragment that is several cpio archives one after the other gets a directory for each (ramdisk0.vol2/ ...), and an untouched repack is byte-identical$RD_GNU"
python3 "$RDG" split rd_vvu/ramdisk0.cpio rd_vv0s
python3 "$RDG" split rd_vvu/ramdisk1.cpio rd_vv1s
rm -rf rd_vve && cp -a rd_vvu rd_vve
printf 'KEEPVERITY=false\n' >rd_vve/ramdisk0.vol2/.backup/.magisk     # fragment 0, its second archive
printf 'more\n' >>rd_vve/ramdisk1.vol3/overlay.d/sbin/magisk.xz       # fragment 1, its third
rd_ck "repack" rd_repack_unpack rd_vve rd_vveo
python3 "$RDG" split rd_vveo_re/ramdisk0.cpio rd_vve0s
python3 "$RDG" split rd_vveo_re/ramdisk1.cpio rd_vve1s
rd_ck "fragment 0: the first archive keeps its bytes" cmp -s rd_vv0s.0.cpio rd_vve0s.0.cpio
rd_ck "fragment 0: the second does not" rd_differ rd_vv0s.1.cpio rd_vve0s.1.cpio
rd_ck "fragment 1: the first archive keeps its bytes" cmp -s rd_vv1s.0.cpio rd_vve1s.0.cpio
rd_ck "fragment 1: the second archive keeps its bytes" cmp -s rd_vv1s.1.cpio rd_vve1s.1.cpio
rd_ck "fragment 1: the third does not" rd_differ rd_vv1s.2.cpio rd_vve1s.2.cpio
rd_ck "the volumes are still there" grep -qx "ramdisk1_tree_volumes=3" rd_vveo_re/manifest.txt
rd_ck "the edits" test "$(cat rd_vveo_re/ramdisk0.vol2/.backup/.magisk)" = "KEEPVERITY=false"
rd_ck "GNU cpio, both fragments" rd_oracle_frags rd_vveo_re ramdisk0 ramdisk1
rd_done "ramdisk directory: edits in the second archive of one fragment and the third of another rebuild those archives only$RD_GNU"
for j in 1 2 4 8; do "$ABR" -j$j repack rd_vve -o rd_vve.j$j.img >/dev/null 2>&1; done
if cmp -s rd_vve.j1.img rd_vve.j2.img && cmp -s rd_vve.j1.img rd_vve.j4.img && cmp -s rd_vve.j1.img rd_vve.j8.img && cmp -s rd_vve.j1.img rd_vveo.img; then
    pass "ramdisk directory: fragments of several archives repack to the same bytes with 1, 2, 4 and 8 threads"
else
    fail "ramdisk directory: the result depends on the number of threads (fragments of several archives)"
fi
# One archive of a fragment taken out, in one fragment only.
rm -rf rd_vvl && cp -a rd_vvu rd_vvl && rm -rf rd_vvl/ramdisk1.vol3
rd_ck "repack" rd_repack_unpack rd_vvl rd_vvlo
rd_ck "fragment 1 has two archives now" grep -qx "ramdisk1_tree_volumes=2" rd_vvlo_re/manifest.txt
rd_ck "fragment 0 has the exact bytes it had" cmp -s rd_vvu/.abr_raw/ramdisk0.cpio.raw rd_vvlo_re/.abr_raw/ramdisk0.cpio.raw
python3 "$RDG" split rd_vvlo_re/ramdisk1.cpio rd_vvl1s
rd_ck "fragment 1's first archive is the same" cmp -s rd_vv1s.0.cpio rd_vvl1s.0.cpio
rd_ck "fragment 1's second archive is the same" cmp -s rd_vv1s.1.cpio rd_vvl1s.1.cpio
rd_ck "and it has no third" test ! -e rd_vvl1s.2.cpio
rd_ck "it was said, with the name of the directory" grep -q "ramdisk1.vol3/: the directory is not there, so that archive is left out of the ramdisk" rd_vvlo.rlog
rd_done "ramdisk directory: deleting ramdisk1.vol3/ of a vendor_boot leaves that archive out of fragment 1 and touches nothing else"
rm -rf rd_vvj1 rd_vvj4 && "$ABR" -j1 unpack rd_vv.img -o rd_vvj1 >/dev/null 2>&1 && "$ABR" -j4 unpack rd_vv.img -o rd_vvj4 >/dev/null 2>&1
if diff -r --no-dereference -x manifest.txt rd_vvj1 rd_vvj4 >/dev/null && diff <(tail -n +2 rd_vvj1/manifest.txt) <(tail -n +2 rd_vvj4/manifest.txt) >/dev/null; then
    pass "ramdisk directory: unpacking fragments of several archives gives the same directories with 1 and 4 threads"
else
    fail "ramdisk directory: unpack of fragments of several archives depends on the number of threads"
fi

# ---- images of your own: ABR_REAL_IMAGES=<directory> tests/run_tests.sh <abr> checks every file of it the way
# the fixtures above are checked -- an untouched repack is identical, every ramdisk archive is a directory that
# GNU cpio agrees with, and a file put into a directory lands in the image. (Files abr does not take, an ext4
# image say, are listed; nothing is asserted about them.)
if [ -n "${ABR_REAL_IMAGES:-}" ] && [ -d "$ABR_REAL_IMAGES" ]; then
    echo "note: checking the images of $ABR_REAL_IMAGES"
    for img in "$ABR_REAL_IMAGES"/*; do
        [ -f "$img" ] || continue
        rb="$(basename "$img")"
        rw="real_$(printf '%s' "$rb" | tr -c 'A-Za-z0-9_.-' '_')"
        rm -rf "$rw" "$rw.out" "$rw.edit" "$rw.edit.img" "$rw.edit_re"
        if ! "$ABR" unpack "$img" -o "$rw" >"$rw.log" 2>&1; then
            echo "note: $rb is not an image abr unpacks ($(tail -n 1 "$rw.log"))"
            continue
        fi
        "$ABR" repack "$rw" -o "$rw.out" >/dev/null 2>&1
        rd_ck "untouched repack is identical" cmp -s "$img" "$rw.out"
        prefixes="$(sed -n 's/^\(ramdisk[0-9]*\)_tree=.*/\1/p;s/^ramdisk_tree=.*/ramdisk/p' "$rw/manifest.txt")"
        for p in $prefixes; do
            rd_ck "$p: GNU cpio" rd_oracle "$rw" "$p"
            vols="$(sed -n "s/^${p}_tree_volumes=//p" "$rw/manifest.txt")"
            rd_ck "$p: the volumes the manifest counts are there" test "$(ls -d "$rw/$p" "$rw/$p".vol* 2>/dev/null | grep -c -v '\.meta$')" = "${vols:-1}"
        done
        if [ -n "$prefixes" ]; then
            first="$(sed -n '1p' <<<"$prefixes")"
            cp -a "$rw" "$rw.edit" && printf 'abr test\n' >"$rw.edit/$first/abr_test_file"
            "$ABR" repack "$rw.edit" -o "$rw.edit.img" >/dev/null 2>&1 && "$ABR" unpack "$rw.edit.img" -o "$rw.edit_re" >/dev/null 2>&1
            rd_ck "$first: a file put into the directory is in the image" test "$(cat "$rw.edit_re/$first/abr_test_file" 2>/dev/null)" = "abr test"
            rd_ck "$first: nothing else changed" rd_same_tree_x "$rw/$first" "$rw.edit_re/$first" abr_test_file
            rd_ck "the image is the same size or larger by a little" test "$(wc -c <"$rw.edit.img")" -ge "$(wc -c <"$img")"
        fi
        rd_done "real image $rb: ${prefixes:+ramdisk directories (${prefixes//$'\n'/, }), }untouched repack identical$RD_GNU"
    done
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
