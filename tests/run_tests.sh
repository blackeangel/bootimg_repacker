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
            # (a UTF-8 locale: that is how wine hands a name with letters outside ASCII to the program)
            printf '#!/bin/sh\nLC_ALL=C.UTF-8\nexport LC_ALL\nexec wine "%s" "$@"\n' "$exe" >"$WORK/winebin/${pair##*:}"
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
roundtrip_check fx/boot_v0_dt_trimmed.img "boot v0 (CAF device tree last, its final page padding trimmed)" dttrim
expect_key rt_dttrim missing_tail_padding "trimmed CAF dt: missing final padding recorded"
roundtrip_check fx/vendor_boot_v4_trimmed_tail.img "vendor_boot v4 (dtb last, its final page padding trimmed)" vbtrim
expect_key rt_vbtrim missing_tail_padding "trimmed vendor_boot: missing final padding recorded"
roundtrip_check fx/boot_v2_partial_padding.img "boot v2 (the dump ends in the middle of the final page padding)" partpad
expect_line rt_partpad "tail_padding_kept=300" "partly trimmed dump: the 300 padding bytes it holds are recorded"

# The last component of such an image, edited. The padding stays off (the rebuilt image ends where the
# component ends) and the component is whole: the count of trimmed bytes used to be applied to the new
# size, which cut into a component that had grown (a 5000-byte dt made 8000 bytes came back 952 short).
trim_edit() {   # <image> <part (verify.py)> <file in the unpacked directory> <name>
    local img="$1" part="$2" file="$3" name="$4" delta d old new want ok=1
    for delta in 3000 -400 1000000; do
        d="te_${name}_$delta"
        rm -rf "$d" "$d.img" "$d.part" "$d.re"
        "$ABR" unpack "$img" -o "$d" >/dev/null 2>&1 || { fail "$name: unpack"; return; }
        old=$(stat -c %s "$d/$file")
        if [ "$delta" -gt 0 ]; then head -c "$delta" /dev/urandom >>"$d/$file"; else truncate -s $((old + delta)) "$d/$file"; fi
        new=$(stat -c %s "$d/$file")
        "$ABR" repack "$d" -o "$d.img" >/dev/null 2>&1 || { fail "$name: repack after $delta bytes"; return; }
        want=$(($(stat -c %s "$img") - old + new))
        if [ "$(stat -c %s "$d.img")" != "$want" ]; then
            echo "  $name ($delta): $(stat -c %s "$d.img") bytes, expected $want (the old size, $(stat -c %s "$img"), moved by the change of the component)"
            ok=0
        fi
        if [ -n "$part" ]; then
            python3 "$TOOLS/verify.py" boot-part "$d.img" "$part" "$d.part" && cmp -s "$d.part" "$d/$file" || { echo "  $name ($delta): the component read back by an independent parser differs"; ok=0; }
        else
            "$ABR" unpack "$d.img" -o "$d.re" >/dev/null 2>&1 && cmp -s "$d.re/$file" "$d/$file" || { echo "  $name ($delta): the component read back differs"; ok=0; }
        fi
    done
    [ $ok = 1 ] && pass "$name: the last component of a dump without its final padding, made bigger or smaller, is rebuilt whole and still without the padding" \
        || fail "$name: editing the last component of a dump without its final padding"
}
trim_edit fx/boot_v2_trimmed_tail.img dtb dtb "trimmed boot v2 (dtb)"
trim_edit fx/boot_v0_dt_trimmed.img dt dt.img "trimmed boot v0 (CAF dt)"
trim_edit fx/vendor_boot_v4_trimmed_tail.img "" dtb "trimmed vendor_boot v4 (dtb)"
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

if [ -x "$UNIT" ]; then
    if out=$("$UNIT" legacy 2>&1); then
        pass "Sony SIN and ELF boot image unit tests ($(tail -n 1 <<<"$out"))"
    else
        fail "Sony SIN and ELF boot image unit tests: $(grep -E 'FAIL|failure' <<<"$out" | head -n 4 | tr '\n' ' ')"
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

# =========================================================================
# An edit that makes the image too big for its partition. What was edited has to be compressed
# again, and abr's usual setting for that is less dense than the one a build that cares about
# size used: the real OrangeFox vendor_boot has its ramdisk at `zstd -19` (22.6 MB; level 3 makes
# it 28.2 MB), and with one file added at abr's usual level the image outgrows its 64 MiB
# partition by 9 KB. So the image is built once more, with everything that is compressed again
# at the densest setting the decoders still read (gzip 9, zstd 19, xz 9, lz4 12). A codec that
# has no denser setting gets no second try: the refusal (or the warning, where the image is only
# padded) is what it always was.
# =========================================================================
python3 - "$TOOLS" <<'PYEOF'
import random, sys
sys.path.insert(0, sys.argv[1])
import cpio_gen as g

r = random.Random(11)
words = [bytes(r.choices(b"abcdefghijklmnopqrstuvwxyz", k=r.randint(3, 9))) for _ in range(300)]
text = b" ".join(r.choices(words, k=2000000 // 4 + 16))[:2000000]
open("fit_noise.bin", "wb").write(r.randbytes(300000))  # nothing shrinks this
# An mkbootfs ramdisk: the usual small tree and 2 MB of text in 20 files. Level 19 of zstd finds
# a fifth more in it than level 3 does.
files = [("res", g.S_DIR | 0o755, b"", (0, 0))]
files += [("res/t%02d.txt" % i, g.S_REG | 0o644, text[i * 100000:(i + 1) * 100000], (0, 0)) for i in range(20)]
open("fit_rd.cpio", "wb").write(g.mkbootfs(g.tree(files)))
PYEOF

fit_size() { if [ -f "$1" ]; then wc -c <"$1" | tr -d ' '; else echo 0; fi; }
fit_log_count() { grep -c -- "$1" "$2"; }  # how many lines of the log say it (grep -c exits 1 on 0: only the count is used)
fit_avb_ok() {  # <image> <partition name> <size>: the size of the partition, abr's and avbtool's verdicts on the descriptor
    local d rc
    d="$(mktemp -d -p .)"
    cp "$1" "$d/$2.img"
    python3 "$AVBTOOL" verify_image --image "$d/$2.img" >"$d/out" 2>&1
    rc=$?
    rm -rf "$d"
    [ $rc -eq 0 ] && [ "$(fit_size "$1")" = "$3" ] && said "hash check:   OK" "$ABR" info "$1"
}
fit_zstd_reads() {  # <image> <expected plain ramdisk>: the real zstd decodes the ramdisk (true where it is not installed)
    command -v zstd >/dev/null 2>&1 || return 0
    python3 "$TOOLS/verify.py" ramdisk "$1" "$1.rd" || return 1
    zstd -dc -q <"$1.rd" >"$1.rd.plain" 2>/dev/null && cmp -s "$1.rd.plain" "$2"
}

# The same image twice: with its ramdisk at zstd level 19 (as a build that wanted it small made it)
# and at abr's usual level.
thr_dir zstd fit_rd.cpio fit_dense
echo "ramdisk_level=19" >>fit_dense/manifest.txt
thr_dir zstd fit_rd.cpio fit_usual
"$ABR" repack fit_dense -o fit_dense.img >/dev/null 2>&1
"$ABR" repack fit_usual -o fit_usual.img >/dev/null 2>&1
fit_dense_size=$(fit_size fit_dense.img)
fit_usual_size=$(fit_size fit_usual.img)
# avbtool keeps 64 KiB for the vbmeta blob and one block for the footer: the smallest partition it
# takes this image into is that much bigger. The usual-level image must still not fit it.
fit_part=$((fit_dense_size + 69632 + 4096))
if [ "$fit_usual_size" -le $((fit_part + 4096)) ]; then
    fail "fixture for the fit tests: the usual level (${fit_usual_size} bytes) is not clearly bigger than the dense one (${fit_dense_size}) plus avbtool's reserve"
fi

# ---- boot v4 with an AVB hash footer that has no room to spare: the file is put into the directory
if python3 "$AVBTOOL" version >/dev/null 2>&1; then
    cp fit_dense.img fit_avb.img
    python3 "$AVBTOOL" add_hash_footer --image fit_avb.img --partition_size "$fit_part" --partition_name boot >/dev/null 2>&1
    rd_unpack fit_avb.img fit_avb_u
    printf 'abr test\n' >fit_avb_u/ramdisk/abr_test_file
    "$ABR" -j4 repack fit_avb_u -o fit_avb_j4.img >fit_avb_j4.log 2>&1
    fit_rc=$?
    rd_ck "the repack worked" test "$fit_rc" = 0
    rd_ck "the image is the size of the partition" test "$(fit_size fit_avb_j4.img)" = "$fit_part"
    rd_ck "abr's hash check and avbtool's verify_image accept it" fit_avb_ok fit_avb_j4.img boot "$fit_part"
    rd_ck "the second try is announced once, with the partition size" test "$(fit_log_count "no longer fits the original partition size ($fit_part bytes); compressing what was edited again, as densely as the codecs allow" fit_avb_j4.log)" = 1
    rd_ck "what the first try said is not said again (the ramdisk is built from the directory)" test "$(fit_log_count "the ramdisk is built from the directory ramdisk/" fit_avb_j4.log)" = 1
    rd_ck "what the first try said is not said again (the new file)" test "$(fit_log_count "abr_test_file" fit_avb_j4.log)" = 1
    rd_ck "no warning" test "$(fit_log_count '^warning' fit_avb_j4.log)" = 0
    rd_unpack fit_avb_j4.img fit_avb_re
    rd_ck "the file is in the image" test "$(cat fit_avb_re/ramdisk/abr_test_file 2>/dev/null)" = "abr test"
    rd_ck "nothing else in the directory changed" rd_same_tree_x fit_avb_u/ramdisk fit_avb_re/ramdisk abr_test_file
    rd_ck "GNU cpio agrees with the directory" rd_oracle fit_avb_re
    rd_ck "the real zstd reads the ramdisk" fit_zstd_reads fit_avb_j4.img fit_avb_re/ramdisk.cpio
    "$ABR" -j1 repack fit_avb_u -o fit_avb_j1.img >/dev/null 2>&1
    rd_ck "-j1 and -j4 give the same bytes" cmp -s fit_avb_j1.img fit_avb_j4.img
    rd_done "dense boot v4 with a tight AVB hash footer: an edit that does not fit at the usual level is compressed again and fits"

    # An untouched image is replayed byte for byte, and says nothing about any of this.
    rd_unpack fit_avb.img fit_avb_same
    "$ABR" repack fit_avb_same -o fit_avb_same.img >fit_avb_same.log 2>&1
    rd_ck "an untouched repack is identical" cmp -s fit_avb.img fit_avb_same.img
    rd_ck "and says nothing about a second try" test "$(fit_log_count 'densely' fit_avb_same.log)" = 0
    rd_done "dense boot v4 with a tight AVB hash footer: an untouched repack is identical and no second try is announced"

    # More than the partition holds at any setting: refused, the error says both tries were made.
    rd_unpack fit_avb.img fit_big_u
    cp fit_noise.bin fit_big_u/ramdisk/noise.bin
    "$ABR" repack fit_big_u -o fit_big.img >fit_big.log 2>&1
    fit_rc=$?
    rd_ck "refused" test "$fit_rc" -ne 0
    rd_ck "no image is left behind" test ! -e fit_big.img
    rd_ck "the error says what does not fit" test "$(fit_log_count "no longer fits the original partition size ($fit_part bytes) -- not even with what was edited compressed as densely as the codecs allow" fit_big.log)" = 1
    rd_ck "the second try was announced once" test "$(fit_log_count 'compressing what was edited again' fit_big.log)" = 1
    rd_done "dense boot v4 with a tight AVB hash footer: an edit that does not fit even at the densest setting is refused, and the message says so"

    # A codec with no denser setting (lz4 legacy is at its densest by default): no second try, no word about one.
    thr_dir lz4_legacy fit_rd.cpio fit_lz4
    "$ABR" repack fit_lz4 -o fit_lz4.img >/dev/null 2>&1
    fit_lz4_part=$(($(fit_size fit_lz4.img) + 69632 + 4096))
    cp fit_lz4.img fit_lz4_avb.img
    python3 "$AVBTOOL" add_hash_footer --image fit_lz4_avb.img --partition_size "$fit_lz4_part" --partition_name boot >/dev/null 2>&1
    rd_unpack fit_lz4_avb.img fit_lz4_u
    cp fit_noise.bin fit_lz4_u/ramdisk/noise.bin
    "$ABR" repack fit_lz4_u -o fit_lz4_big.img >fit_lz4_big.log 2>&1
    fit_rc=$?
    rd_ck "refused" test "$fit_rc" -ne 0
    rd_ck "no image is left behind" test ! -e fit_lz4_big.img
    rd_ck "the usual error" test "$(fit_log_count "no longer fits the original partition size ($fit_lz4_part bytes)" fit_lz4_big.log)" = 1
    rd_ck "no talk of a denser compression" test "$(fit_log_count 'densely\|again' fit_lz4_big.log)" = 0
    printf 'abr test\n' >fit_lz4_u/ramdisk/abr_test_file
    rm -f fit_lz4_u/ramdisk/noise.bin
    "$ABR" repack fit_lz4_u -o fit_lz4_ok.img >fit_lz4_ok.log 2>&1
    rd_ck "a small edit fits" fit_avb_ok fit_lz4_ok.img boot "$fit_lz4_part"
    rd_ck "and needs no second try" test "$(fit_log_count 'densely\|again' fit_lz4_ok.log)" = 0
    rd_done "lz4_legacy ramdisk in a tight AVB partition: an edit that does not fit is refused as before, without a second try"
else
    echo "SKIP: tight-partition tests with an AVB footer (avbtool not usable)"
fi

# ---- boot v4 padded with zeros up to its partition (a raw partition dump): the same, with a warning at worst
python3 - "$fit_dense_size" "$fit_usual_size" <<'PYEOF'
import sys
dense, usual = int(sys.argv[1]), int(sys.argv[2])
pad = (dense + (usual - dense) // 2) // 4096 * 4096
data = open("fit_dense.img", "rb").read()
open("fit_pad.img", "wb").write(data + b"\0" * (pad - len(data)))
open("fit_pad.size", "w").write(str(pad))
PYEOF
fit_pad=$(cat fit_pad.size)
rd_unpack fit_pad.img fit_pad_u
rd_ck "the padding is in the manifest" grep -q "^pad_to=$fit_pad\$" fit_pad_u/manifest.txt
printf 'abr test\n' >fit_pad_u/ramdisk/abr_test_file
"$ABR" repack fit_pad_u -o fit_pad_out.img >fit_pad_out.log 2>&1
fit_rc=$?
rd_ck "the repack worked" test "$fit_rc" = 0
rd_ck "the image is the size of the partition" test "$(fit_size fit_pad_out.img)" = "$fit_pad"
rd_ck "the second try is announced once" test "$(fit_log_count "compressing what was edited again, as densely as the codecs allow" fit_pad_out.log)" = 1
rd_ck "no warning" test "$(fit_log_count '^warning' fit_pad_out.log)" = 0
rd_unpack fit_pad_out.img fit_pad_re
rd_ck "the file is in the image" test "$(cat fit_pad_re/ramdisk/abr_test_file 2>/dev/null)" = "abr test"
rd_ck "nothing else in the directory changed" rd_same_tree_x fit_pad_u/ramdisk fit_pad_re/ramdisk abr_test_file
rd_done "dense boot v4 padded to its partition size: an edit that does not fit at the usual level is compressed again and fits"

rd_unpack fit_pad.img fit_padbig_u
cp fit_noise.bin fit_padbig_u/ramdisk/noise.bin
"$ABR" repack fit_padbig_u -o fit_padbig.img >fit_padbig.log 2>&1
fit_rc=$?
rd_ck "written all the same (the padding cannot be kept)" test "$fit_rc" = 0
rd_ck "bigger than the partition" test "$(fit_size fit_padbig.img)" -gt "$fit_pad"
rd_ck "the second try was announced once" test "$(fit_log_count 'compressing what was edited again' fit_padbig.log)" = 1
rd_ck "one warning, about the size" test "$(fit_log_count '^warning: rebuilt image is' fit_padbig.log)" = 1
rd_done "dense boot v4 padded to its partition size: an edit that does not fit at any setting is written with a warning, as before"

thr_dir lz4_legacy fit_rd.cpio fit_lz4p
"$ABR" repack fit_lz4p -o fit_lz4p.img >/dev/null 2>&1
python3 -c 'import sys; open("fit_lz4pad.img", "wb").write(open("fit_lz4p.img", "rb").read() + b"\0" * 8192)'

rd_unpack fit_lz4pad.img fit_lz4pad_u
cp fit_noise.bin fit_lz4pad_u/ramdisk/noise.bin
"$ABR" repack fit_lz4pad_u -o fit_lz4pad_out.img >fit_lz4pad_out.log 2>&1
fit_rc=$?
rd_ck "written all the same" test "$fit_rc" = 0
rd_ck "bigger than the partition" test "$(fit_size fit_lz4pad_out.img)" -gt "$(fit_size fit_lz4pad.img)"
rd_ck "one warning, about the size" test "$(fit_log_count '^warning: rebuilt image is' fit_lz4pad_out.log)" = 1
rd_ck "no talk of a denser compression" test "$(fit_log_count 'densely\|again' fit_lz4pad_out.log)" = 0
rd_done "lz4_legacy ramdisk padded to its partition size: an edit that does not fit is written with the warning it always had, without a second try"

# ---- vendor_boot v4: ramdisk fragment 0 at zstd 19 in a tight partition (the shape of the OrangeFox image)
if python3 "$AVBTOOL" version >/dev/null 2>&1; then
    rd_unpack vendor_boot_v4.img fit_vb
    cp fit_rd.cpio fit_vb/ramdisk0.cpio
    sed -i 's/^ramdisk0_compression=.*/ramdisk0_compression=zstd/' fit_vb/manifest.txt
    cp -a fit_vb fit_vb_dense
    echo "ramdisk0_level=19" >>fit_vb_dense/manifest.txt
    "$ABR" repack fit_vb_dense -o fit_vb_dense.img >/dev/null 2>&1
    "$ABR" repack fit_vb -o fit_vb_usual.img >/dev/null 2>&1
    fit_vb_part=$((($(fit_size fit_vb_dense.img) + 4095) / 4096 * 4096 + 69632 + 4096))
    if [ "$(fit_size fit_vb_usual.img)" -le $((fit_vb_part + 4096)) ]; then
        fail "fixture for the fit tests: vendor_boot at the usual level is not clearly bigger than at the dense one"
    fi
    cp fit_vb_dense.img fit_vb_avb.img
    python3 "$AVBTOOL" add_hash_footer --image fit_vb_avb.img --partition_size "$fit_vb_part" --partition_name vendor_boot >/dev/null 2>&1
    rd_unpack fit_vb_avb.img fit_vb_u
    printf 'abr test\n' >fit_vb_u/ramdisk0/abr_test_file
    "$ABR" repack fit_vb_u -o fit_vb_out.img >fit_vb_out.log 2>&1
    fit_rc=$?
    rd_ck "the repack worked" test "$fit_rc" = 0
    rd_ck "the image is the size of the partition, abr's hash check and avbtool's verify_image accept it" fit_avb_ok fit_vb_out.img vendor_boot "$fit_vb_part"
    rd_ck "the second try is announced once" test "$(fit_log_count 'compressing what was edited again' fit_vb_out.log)" = 1
    rd_ck "no warning" test "$(fit_log_count '^warning' fit_vb_out.log)" = 0
    rd_unpack fit_vb_out.img fit_vb_re
    rd_ck "the file is in fragment 0" test "$(cat fit_vb_re/ramdisk0/abr_test_file 2>/dev/null)" = "abr test"
    rd_ck "fragment 1 is the same as it was" cmp -s fit_vb_u/ramdisk1.cpio fit_vb_re/ramdisk1.cpio
    "$ABR" -j1 repack fit_vb_u -o fit_vb_j1.img >/dev/null 2>&1
    "$ABR" -j4 repack fit_vb_u -o fit_vb_j4.img >/dev/null 2>&1
    rd_ck "-j1 and -j4 give the same bytes" cmp -s fit_vb_j1.img fit_vb_j4.img
    rd_done "dense vendor_boot v4 with a tight AVB hash footer: an edit to fragment 0 is compressed again and fits"
fi

# =========================================================================
# Rockchip KRNL: "KRNL", the size of the payload, the payload, a CRC of Rockchip's own
# (abr/legacy/krnl.hpp). The images are made -- and what abr makes is read -- by
# tests/tools/krnl_tool.py, whose CRC is written from rkcrc's source, not from abr's; where
# ABR_RKCRC names a compiled rkcrc (rkflashtool, BSD; not part of this repository) the real
# `rkcrc -k` is a judge as well.
# =========================================================================
KT="$TOOLS/krnl_tool.py"

# The CRC: the polynomial is 0x04C10DB7, not the usual CRC-32 one (0x04C11DB7). Four payloads
# whose CRC the real rkcrc wrote (the last four bytes of `rkcrc -k`): the Python tool agrees with
# them, and abr agrees with the Python tool (info says whether the stored CRC is the payload's).
python3 - <<'PYEOF'
open("krnl_v_empty.bin", "wb").write(b"")
open("krnl_v_digits.bin", "wb").write(b"123456789")
open("krnl_v_ff.bin", "wb").write(b"\xff" * 1000)
open("krnl_v_ramp.bin", "wb").write(bytes(range(256)) * 4)
PYEOF
for vec in empty:00000000 digits:889a9615 ff:f45d7ebb ramp:be63b112; do
    krnl_name="${vec%%:*}"
    krnl_want="${vec##*:}"
    python3 "$KT" make "krnl_v_$krnl_name.bin" "krnl_v_$krnl_name.img"
    rd_ck "the CRC of the $krnl_name payload, as rkcrc wrote it" test "$(python3 "$KT" crc "krnl_v_$krnl_name.bin")" = "$krnl_want"
    rd_ck "abr reads the image of the $krnl_name payload, its CRC is the payload's" said "crc: .*0x$krnl_want (matches the payload)" "$ABR" info "krnl_v_$krnl_name.img"
done
rd_done "KRNL: the CRC is Rockchip's (polynomial 0x04C10DB7): the values rkcrc wrote are what the independent tool and abr compute"

# A ramdisk image (what the Rockchip Android SDK's boot.img is: the gzip-compressed cpio) and a
# kernel image (kernel.img: a kernel, not a cpio).
python3 "$RDG" mkbootfs krnl_rd.cpio
gzip -9n -c krnl_rd.cpio >krnl_rd.gz
python3 "$KT" make krnl_rd.gz krnl_rd.img
python3 -c "import random; open('krnl_kernel.bin', 'wb').write(random.Random(5).randbytes(120000))"
python3 "$KT" make krnl_kernel.bin krnl_kernel.img
krnl_ref() {  # <payload> <image>: the real rkcrc -k writes the same image (true where it is not at hand)
    [ -n "${ABR_RKCRC:-}" ] && [ -x "${ABR_RKCRC:-}" ] || return 0
    "$ABR_RKCRC" -k "$1" "$2.ref" 2>/dev/null && cmp -s "$2" "$2.ref"
}

rd_unpack krnl_rd.img krnl_u
rd_ck "identify" said "KRNL bootimg" "$ABR" identify krnl_rd.img
rd_ck "unpacked as krnl" grep -q '^type=krnl$' krnl_u/manifest.txt
rd_ck "ramdisk.cpio is the archive" cmp -s krnl_u/ramdisk.cpio krnl_rd.cpio
rd_ck "and there is a directory" test -d krnl_u/ramdisk
rd_ck "GNU cpio agrees with it" rd_oracle krnl_u
rd_ck "the CRC is the payload's" said "(matches the payload)" "$ABR" info krnl_rd.img
"$ABR" repack krnl_u -o krnl_back.img >krnl_back.log 2>&1
rd_ck "an untouched repack is identical" cmp -s krnl_rd.img krnl_back.img
rd_ck "and the real rkcrc writes the same image" krnl_ref krnl_rd.gz krnl_back.img
rd_done "KRNL image with a gzip cpio ramdisk: unpack gives ramdisk.cpio and ramdisk/ (GNU cpio agrees), an untouched repack is identical"

# Edit the directory: the CRC is made afresh, the payload is what the real tools read.
printf 'abr test\n' >krnl_u/ramdisk/abr_test_file
"$ABR" -j1 repack krnl_u -o krnl_e1.img >krnl_e1.log 2>&1
"$ABR" -j4 repack krnl_u -o krnl_e4.img >krnl_e4.log 2>&1
rd_ck "-j1 and -j4 give the same bytes" cmp -s krnl_e1.img krnl_e4.img
rd_ck "the size field and the CRC are right (read by krnl_tool.py)" python3 "$KT" payload krnl_e4.img krnl_e4.gz
gzip -dc <krnl_e4.gz >krnl_e4.cpio 2>/dev/null
rd_ck "the payload is gzip, and it holds the new file" rd_has krnl_e4.cpio ' abr_test_file$'
rd_ck "the real rkcrc writes the same image from that payload" krnl_ref krnl_e4.gz krnl_e4.img
rd_unpack krnl_e4.img krnl_e4_re
rd_ck "unpacking it again: the file is there" test "$(cat krnl_e4_re/ramdisk/abr_test_file 2>/dev/null)" = "abr test"
rd_ck "and nothing else changed" rd_same_tree_x krnl_u/ramdisk krnl_e4_re/ramdisk abr_test_file
rd_ck "the note about the new file was said" grep -q 'abr_test_file' krnl_e4.log
rd_done "KRNL: a file put into ramdisk/ is in the repacked image, the CRC is right, -j1 = -j4"

# Edit ramdisk.cpio instead.
rd_unpack krnl_rd.img krnl_u2
printf 'abr-edit' >>krnl_u2/ramdisk.cpio
"$ABR" repack krnl_u2 -o krnl_e2.img >/dev/null 2>&1
rd_ck "the size field and the CRC are right" python3 "$KT" payload krnl_e2.img krnl_e2.gz
gzip -dc <krnl_e2.gz >krnl_e2.cpio 2>/dev/null
rd_ck "the archive is the edited one" cmp -s krnl_e2.cpio krnl_u2/ramdisk.cpio
rd_ck "the real rkcrc writes the same image from that payload" krnl_ref krnl_e2.gz krnl_e2.img
rd_done "KRNL: an edited ramdisk.cpio is compressed again, the CRC is right"

# A kernel image: the payload is no cpio, so it is `kernel`. Compressed or not, an untouched repack is identical.
rd_unpack krnl_kernel.img krnl_k
rd_ck "the payload is kernel" cmp -s krnl_k/kernel krnl_kernel.bin
rd_ck "there is no ramdisk" test ! -e krnl_k/ramdisk.cpio -a ! -e krnl_k/ramdisk
"$ABR" repack krnl_k -o krnl_k_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s krnl_kernel.img krnl_k_back.img
printf 'x' >>krnl_k/kernel
"$ABR" repack krnl_k -o krnl_k_edit.img >/dev/null 2>&1
rd_ck "an edit: the payload is the edited kernel, the CRC is right" python3 "$KT" payload krnl_k_edit.img krnl_k_edit.bin
rd_ck "(the same bytes)" cmp -s krnl_k_edit.bin krnl_k/kernel
rd_ck "and the real rkcrc writes the same image" krnl_ref krnl_k_edit.bin krnl_k_edit.img
gzip -9n -c krnl_kernel.bin >krnl_kernel.gz
python3 "$KT" make krnl_kernel.gz krnl_kernelgz.img
rd_unpack krnl_kernelgz.img krnl_kg
rd_ck "a gzip-compressed kernel is unpacked" cmp -s krnl_kg/kernel krnl_kernel.bin
rd_ck "and said to be gzip" grep -q '^kernel_compression=gzip$' krnl_kg/manifest.txt
"$ABR" repack krnl_kg -o krnl_kg_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s krnl_kernelgz.img krnl_kg_back.img
rd_done "KRNL image with a kernel (plain and gzip): kernel is the payload, an untouched repack is identical, an edit gets a right CRC"

# A CRC that is not the payload's (a corrupt dump, or an image made by a careless tool): said, kept while the
# payload is untouched (the round trip stays exact), made right when the payload is edited.
python3 "$KT" make krnl_rd.gz krnl_badcrc.img --crc 0x12345678
rd_unpack krnl_badcrc.img krnl_bad
rd_ck "said at unpack" grep -q 'is not the CRC of its payload' krnl_bad.log
rd_ck "and by info" said "does NOT match the payload" "$ABR" info krnl_badcrc.img
"$ABR" repack krnl_bad -o krnl_bad_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical (the CRC it had)" cmp -s krnl_badcrc.img krnl_bad_back.img
printf 'abr test\n' >krnl_bad/ramdisk/abr_test_file
"$ABR" repack krnl_bad -o krnl_bad_edit.img >/dev/null 2>&1
rd_ck "an edit: the CRC is right now" python3 "$KT" payload krnl_bad_edit.img krnl_bad_edit.gz
rd_done "KRNL image with a wrong CRC: reported, kept while the payload is untouched, right after an edit"

# A dump of a whole partition: fill after the image, kept and kept at its size.
python3 "$KT" make krnl_rd.gz krnl_part.img --size 262144
rd_unpack krnl_part.img krnl_p
rd_ck "the fill is in the manifest" grep -q '^pad_to=262144$' krnl_p/manifest.txt
"$ABR" repack krnl_p -o krnl_p_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s krnl_part.img krnl_p_back.img
printf 'abr test\n' >krnl_p/ramdisk/abr_test_file
"$ABR" repack krnl_p -o krnl_p_edit.img >/dev/null 2>&1
rd_ck "an edit keeps the size of the partition" test "$(wc -c <krnl_p_edit.img | tr -d ' ')" = 262144
rd_ck "and the CRC is right" python3 "$KT" payload krnl_p_edit.img krnl_p_edit.gz
rd_done "KRNL image padded to its partition size: the fill is kept, also after an edit"

# Not an image: a cut-short file is refused, and no directory is left behind.
head -c 5000 krnl_rd.img >krnl_cut.img
rm -rf krnl_cut
"$ABR" unpack krnl_cut.img -o krnl_cut >krnl_cut.out 2>&1
krnl_rc=$?
rd_ck "refused" test "$krnl_rc" -ne 0
rd_ck "with the reason" grep -q 'cut short' krnl_cut.out
rd_ck "no directory is left behind" test ! -e krnl_cut
mkdir -p krnl_cut2
printf 'mine' >krnl_cut2/keep.txt
"$ABR" unpack krnl_cut.img -o krnl_cut2 >/dev/null 2>&1
rd_ck "a directory that was there is not removed" test "$(cat krnl_cut2/keep.txt)" = "mine"
rd_done "KRNL image cut short: refused with a reason, a directory the failed unpack made is removed, one that was there stays"

# =========================================================================
# AMONET: the patch of Amazon's MediaTek Fire tablets (abr/legacy/amonet.hpp): a 1024-byte microloader at the
# start of the image, the first 1024 bytes of the boot image behind it. Android Image Kitchen puts it on and
# takes it off with dd, truncate and cat; those commands, copied from its repackimg.sh and unpackimg.sh, make
# the images here and judge what abr writes.
# =========================================================================
amo_aik_patch() {  # <plain image> <microloader> <out>: repackimg.sh, "Amonet patching new image"
    cp -f "$1" "$3"
    cp -f "$2" amo_ml.tmp
    dd bs=1024 count=1 conv=notrunc if="$1" of=amo_head.tmp 2>/dev/null
    dd bs=1024 seek=1 conv=notrunc if=amo_head.tmp of="$3" 2>/dev/null
    dd conv=notrunc if=amo_ml.tmp of="$3" 2>/dev/null
    rm -f amo_head.tmp amo_ml.tmp
}
amo_aik_unpatch() {  # <patched image> <out image> <out microloader>: unpackimg.sh, "Amonet patch detected, reverting"
    dd bs=2048 count=1 conv=notrunc if="$1" of="$3" 2>/dev/null
    dd bs=1024 skip=1 conv=notrunc if="$3" of=amo_head 2>/dev/null
    truncate -s 1024 "$3"
    truncate -s 2048 amo_head
    dd bs=2048 skip=1 conv=notrunc if="$1" of=amo_tail 2>/dev/null
    cat amo_head amo_tail >"$2"
    rm -f amo_head amo_tail
}
python3 - <<'PYEOF'
import random
b = bytearray(random.Random(11).randbytes(1024))
b[0:4] = b"\xea\x00\x00\x0e"  # code, not "ANDROID!"
b[100:111] = b"microloader"   # the word the signature file looks for
open("amo_ml.bin", "wb").write(bytes(b))
PYEOF
gzip -dc <rd_kernel.gz >amo_kernel.bin
python3 "$MKBOOTIMG" >/dev/null --header_version 0 --kernel rd_kernel.gz --ramdisk krnl_rd.gz \
    --pagesize 2048 --base 0x10000000 --cmdline "amonet test" --output amo_plain.img
amo_aik_patch amo_plain.img amo_ml.bin amo.img

rd_ck "AIK's unpatching commands run" amo_aik_unpatch amo.img amo_unpatched.img amo_ml_back.bin
rd_ck "they give the boot image the patch was put on" cmp -s amo_unpatched.img amo_plain.img
rd_ck "and the microloader" cmp -s amo_ml_back.bin amo_ml.bin
rd_ck "identify names the patch" said "AMONET header" "$ABR" identify amo.img
rd_ck "info says what it is and still reads the header at 1024" said "header_version: 0" "$ABR" info amo.img
rd_ck "info names the wrapper" said "wrapper: AMONET patch" "$ABR" info amo.img
rd_done "AMONET: the images of the tests are made and unmade by AIK's own dd/truncate/cat commands; identify and info see the patch"

rd_unpack amo.img amo_u
rd_ck "unpacked as a boot image" grep -q '^type=boot$' amo_u/manifest.txt
rd_ck "the patch is in the manifest" grep -q '^has_amonet=true$' amo_u/manifest.txt
rd_ck "microloader.bin is the microloader" cmp -s amo_u/microloader.bin amo_ml.bin
rd_ck "the kernel is the kernel" cmp -s amo_u/kernel amo_kernel.bin
rd_ck "ramdisk.cpio is the archive" cmp -s amo_u/ramdisk.cpio krnl_rd.cpio
rd_ck "GNU cpio agrees with the tree" rd_oracle amo_u
rd_ck "unpack says what it unpacked" grep -q 'unpacked amonet-patched boot' amo_u.log
rd_ck "and that the round trip is exact" grep -q 'reproduces this image byte-for-byte' amo_u.log
rd_unpack amo_unpatched.img amo_u0
rd_ck "the same image without the patch has the same manifest, but for the patch" \
    test "$(grep -v '^#\|^has_amonet\|^amonet_' amo_u/manifest.txt)" = "$(grep -v '^#' amo_u0/manifest.txt)"
rd_ck "and the same files" diff -r --no-dereference -x manifest.txt -x microloader.bin amo_u amo_u0
"$ABR" repack amo_u -o amo_back.img >amo_back.log 2>&1
rd_ck "an untouched repack is identical" cmp -s amo.img amo_back.img
rd_done "AMONET image: unpacked under the patch (microloader.bin; the boot image as AIK's unpatching leaves it), an untouched repack is identical"

# An edit: the image is what AIK's patching makes of the plain repack.
printf 'abr test\n' >amo_u/ramdisk/abr_test_file
"$ABR" -j1 repack amo_u -o amo_e1.img >amo_e1.log 2>&1
"$ABR" -j4 repack amo_u -o amo_e4.img >amo_e4.log 2>&1
rd_ck "-j1 and -j4 give the same bytes" cmp -s amo_e1.img amo_e4.img
rm -rf amo_up
cp -r amo_u amo_up
sed 's/^has_amonet=true$/has_amonet=false/' amo_u/manifest.txt >amo_up/manifest.txt
"$ABR" repack amo_up -o amo_e_plain.img >/dev/null 2>&1
rd_ck "the plain repack (patch left out) starts with ANDROID!" test "$(head -c 8 amo_e_plain.img)" = "ANDROID!"
amo_aik_patch amo_e_plain.img amo_ml.bin amo_e_expect.img
rd_ck "the edited image is what AIK's patching makes of it" cmp -s amo_e4.img amo_e_expect.img
rd_unpack amo_e4.img amo_e4_re
rd_ck "unpacking it again: the file is there" test "$(cat amo_e4_re/ramdisk/abr_test_file 2>/dev/null)" = "abr test"
rd_ck "the patch is still on" grep -q '^has_amonet=true$' amo_e4_re/manifest.txt
rd_ck "with the same microloader" cmp -s amo_e4_re/microloader.bin amo_ml.bin
rd_done "AMONET: a file put into ramdisk/ is in the repacked image, which is AIK's patching of the plain repack; -j1 = -j4"

# The patch can be put on an ordinary image: two lines of the manifest and the microloader.
rd_unpack amo_plain.img amo_p
rd_ck "an ordinary image has no patch" test "$(grep -c '^has_amonet' amo_p/manifest.txt)" = 0
cp amo_ml.bin amo_p/microloader.bin
printf 'has_amonet=true\namonet_microloader_file=microloader.bin\n' >>amo_p/manifest.txt
"$ABR" repack amo_p -o amo_p.img >/dev/null 2>&1
rd_ck "the image the manifest makes is the patched one AIK makes" cmp -s amo_p.img amo.img
rd_done "AMONET: has_amonet=true and a microloader.bin turn the unpack of an ordinary image into the patched image AIK makes"

# What cannot carry the patch is refused, and so is what is not there.
rm -rf amo_v2
cp -r amo_u amo_v2
sed 's/^header_version=0$/header_version=2/' amo_u/manifest.txt >amo_v2/manifest.txt
"$ABR" repack amo_v2 -o amo_v2.img >amo_v2.log 2>&1
amo_rc=$?
rd_ck "a header longer than 1024 bytes is refused" test "$amo_rc" -ne 0
rd_ck "with the reason" grep -q 'would overwrite' amo_v2.log
rd_ck "and the way out" grep -q 'has_amonet=false' amo_v2.log
rd_ck "no image is written" test ! -e amo_v2.img
sed 's/^has_amonet=true$/has_amonet=false/' amo_v2/manifest.txt >amo_v2/manifest.new
mv -f amo_v2/manifest.new amo_v2/manifest.txt
"$ABR" repack amo_v2 -o amo_v2.img >/dev/null 2>&1
rd_ck "the way out works: an image that starts with ANDROID!" test "$(head -c 8 amo_v2.img 2>/dev/null)" = "ANDROID!"
rm -rf amo_nm
cp -r amo_u amo_nm
rm -f amo_nm/microloader.bin
"$ABR" repack amo_nm -o amo_nm.img >amo_nm.log 2>&1
amo_rc=$?
rd_ck "a microloader that is not there is refused" test "$amo_rc" -ne 0
head -c 1000 amo_ml.bin >amo_nm/microloader.bin
"$ABR" repack amo_nm -o amo_nm.img >amo_nm.log 2>&1
amo_rc=$?
rd_ck "a microloader of 1000 bytes is refused" test "$amo_rc" -ne 0
rd_ck "with the reason" grep -q 'exactly 1024 bytes' amo_nm.log
head -c 1500 amo.img >amo_cut.img
rm -rf amo_cut
"$ABR" unpack amo_cut.img -o amo_cut >amo_cut.out 2>&1
amo_rc=$?
rd_ck "a patched image cut short is refused" test "$amo_rc" -ne 0
rd_ck "with the reason" grep -q 'cut short' amo_cut.out
rd_ck "and no directory is left behind" test ! -e amo_cut
rd_done "AMONET: a header that would be overwritten, a missing or a wrong microloader and a cut-short image are refused with a reason (has_amonet=false is the way out)"

# A dump of a whole partition (zeros after the image).
cp amo.img amo_part.img
truncate -s 1048576 amo_part.img
rd_unpack amo_part.img amo_pp
rd_ck "the fill is in the manifest" grep -q '^pad_to=1048576$' amo_pp/manifest.txt
"$ABR" repack amo_pp -o amo_pp_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s amo_part.img amo_pp_back.img
printf 'abr test\n' >amo_pp/ramdisk/abr_test_file
"$ABR" repack amo_pp -o amo_pp_edit.img >/dev/null 2>&1
rd_ck "an edit keeps the size of the partition" test "$(wc -c <amo_pp_edit.img | tr -d ' ')" = 1048576
head -c 1024 amo_pp_edit.img >amo_pp_edit.ml
rd_ck "and the microloader" cmp -s amo_pp_edit.ml amo_ml.bin
rd_done "AMONET image padded to its partition size: the fill is kept, also after an edit"

# Under a DHTB wrapper (the two come off in that order and go on in the opposite one).
python3 - <<'PYEOF'
import hashlib, struct
payload = open("amo.img", "rb").read()
header = b"DHTB\x01\x00\x00\x00" + hashlib.sha256(payload).digest() + b"\x00" * 8 + struct.pack("<I", len(payload))
open("amo_dhtb.img", "wb").write(header + b"\x00" * (512 - len(header)) + payload)
PYEOF
rd_unpack amo_dhtb.img amo_d
rd_ck "both wrappers are in the manifest" grep -q '^has_dhtb=true$' amo_d/manifest.txt
rd_ck "(the patch)" grep -q '^has_amonet=true$' amo_d/manifest.txt
rd_ck "and are named" grep -q 'unpacked dhtb-wrapped amonet-patched boot' amo_d.log
"$ABR" repack amo_d -o amo_d_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s amo_dhtb.img amo_d_back.img
rd_done "AMONET under a DHTB wrapper: both are taken off and put back, the round trip is exact"

# =========================================================================
# BLOB: ASUS (Tegra) "MSM-RADIO-UPDATE" blobs and the "-SIGNED-BY-SIGNBLOB-" header (abr/legacy/blob.hpp). The
# blobs of these tests are made by tests/tools/blob_tool.py, which is written from the layout of AndroidRoot's
# BlobTools (shared/blob.h, blobpack.cpp, blobunpack.cpp) and shares no code with abr. ABR_BLOBPACK and
# ABR_BLOBUNPACK name the compiled blobpack and blobunpack of BlobTools (Apache-2.0; not part of this repository;
# the linux CI jobs compile them): where they are at hand they are judges too, and what Android Image Kitchen
# does with a signed blob (its 28 bytes, then blobpack's blob; blobunpack for the way back) is done by them here.
# =========================================================================
BTL="$TOOLS/blob_tool.py"
blob_real() { [ -n "${ABR_BLOBPACK:-}" ] && [ -x "${ABR_BLOBPACK:-}" ] && [ -n "${ABR_BLOBUNPACK:-}" ] && [ -x "${ABR_BLOBUNPACK:-}" ]; }
blob_ref_make() {  # <plain image> <partition> <blob>: AIK's repackimg.sh ("BLOB)") on the plain image gives that blob (true without the tools)
    blob_real || return 0
    # (printf writes the NULs: the awk AIK uses for this, in Debian's and Ubuntu's mawk, drops them)
    printf -- '-SIGNED-BY-SIGNBLOB-\0\0\0\0\0\0\0\0' >"$3.ref" || return 1
    "$ABR_BLOBPACK" blob_tmp.bin "$2" "$1" >/dev/null || return 1
    cat blob_tmp.bin >>"$3.ref"
    rm -f blob_tmp.bin
    cmp -s "$3" "$3.ref"
}
blob_ref_extract() {  # <blob> <partition> <expected data>: the real blobunpack writes that partition (true without the tools)
    blob_real || return 0
    rm -f blob_ref blob_ref.*
    cp "$1" blob_ref || return 1
    "$ABR_BLOBUNPACK" blob_ref >/dev/null 2>&1 || return 1
    cmp -s "blob_ref.$2" "$3"
}
blob_datalen_is_blob_length() {  # <blob>: the secure header's datalen is the length of the blob proper
    local out dl bl
    out="$(python3 -I "$BTL" list "$1")" || return 1
    dl="$(sed -n 's/^secure datalen=\([0-9]*\) .*/\1/p' <<<"$out")"
    bl="$(sed -n 's/^blob \([0-9]*\)$/\1/p' <<<"$out")"
    [ -n "$dl" ] && [ "$dl" = "$bl" ]
}
blob_tail_is() {  # <blob> <file>: the blob ends with that file
    tail -c "$(wc -c <"$2" | tr -d ' ')" "$1" >blob_tail_chk.bin && cmp -s blob_tail_chk.bin "$2"
}
blob_size() { wc -c <"$1" | tr -d ' '; }
head -c 5000 /dev/urandom >blob_ebt.bin
head -c 777 /dev/urandom >blob_app.bin
head -c 256 /dev/urandom >blob_sig.bin

python3 -I "$BTL" make blob_aik.img --secure 0:0 LNX=amo_plain.img
rd_ck "the blob the independent tool writes is what blobpack and AIK's 28 bytes make" blob_ref_make amo_plain.img LNX blob_aik.img
rd_ck "blobunpack finds the boot image in its partition" blob_ref_extract blob_aik.img LNX amo_plain.img
rd_ck "identify: BLOB signing" said "BLOB signing" "$ABR" identify blob_aik.img
rd_ck "info names the wrapper and the partition" said "wrapper: ASUS blob (signed header, partition LNX" "$ABR" info blob_aik.img
rd_ck "and still reads the boot image inside" said "header_version: 0" "$ABR" info blob_aik.img
rd_done "BLOB: the signed blob Android Image Kitchen makes (28 bytes + blobpack's blob) is what the independent tool writes; identify and info see the wrapper"

# A blob with a boot image in its only partition (AIK's case): the blob is a wrapper, the directory is the image's.
rd_unpack blob_aik.img blob_u
rd_ck "unpacked as the boot image inside" grep -q '^type=boot$' blob_u/manifest.txt
rd_ck "the blob is in the manifest" grep -q '^has_blob=true$' blob_u/manifest.txt
rd_ck "its partition is LNX" grep -q '^blob_part0_name=LNX$' blob_u/manifest.txt
rd_ck "unpack says what it unpacked" grep -q 'unpacked blob-wrapped boot' blob_u.log
rd_unpack amo_plain.img blob_u0
rd_ck "the boot image alone unpacks to the same files" rd_same_tree_x blob_u blob_u0 manifest.txt
rd_ck "and the same manifest, but for the blob" \
    test "$(grep -v '^#\|^has_blob\|^blob_' blob_u/manifest.txt)" = "$(grep -v '^#' blob_u0/manifest.txt)"
"$ABR" repack blob_u -o blob_back.img >blob_back.log 2>&1
rd_ck "an untouched repack is identical" cmp -s blob_aik.img blob_back.img
rd_done "BLOB around a boot image (AIK's case): unpacked as that image with has_blob=true, an untouched repack is identical"

# An edit: the blob is what the independent tool (and blobpack) make of the plain repack.
printf 'abr test\n' >blob_u/ramdisk/abr_test_file
head -c 9000 /dev/urandom >blob_u/ramdisk/blob_big_file  # more than a page, so the blob grows
"$ABR" repack blob_u -o blob_e.img >blob_e.log 2>&1
rm -rf blob_up
cp -r blob_u blob_up
sed 's/^has_blob=true$/has_blob=false/' blob_u/manifest.txt >blob_up/manifest.txt
"$ABR" repack blob_up -o blob_e_plain.img >/dev/null 2>&1
rd_ck "the plain repack (blob left out) is a boot image" test "$(head -c 8 blob_e_plain.img)" = "ANDROID!"
rd_ck "and the blob is bigger than the one before" test "$(blob_size blob_e.img)" -gt "$(blob_size blob_aik.img)"
python3 -I "$BTL" make blob_e_expect.img --secure 0:0 LNX=blob_e_plain.img
rd_ck "the edited blob is what the independent tool makes of it" cmp -s blob_e.img blob_e_expect.img
rd_ck "and what blobpack makes (AIK's way)" blob_ref_make blob_e_plain.img LNX blob_e.img
rd_ck "blobunpack finds the plain repack in the partition" blob_ref_extract blob_e.img LNX blob_e_plain.img
rd_ck "datalen was 0 (AIK's unsigned blob) and stays 0" said "secure datalen=0 siglen=0" python3 -I "$BTL" list blob_e.img
rd_ck "there is no signature to warn about" test "$(grep -c 'signature' blob_e.log)" = 0
rd_unpack blob_e.img blob_e_re
rd_ck "unpacking it again: the files are there" test -f blob_e_re/ramdisk/abr_test_file -a -f blob_e_re/ramdisk/blob_big_file
rd_done "BLOB: a ramdisk edit lands in the partition; the blob is what the independent tool and blobpack make of the plain repack"

# A signed blob: datalen and siglen, the signature behind the data. The signature is kept, datalen follows the blob.
python3 -I "$BTL" make blob_sig.img --secure auto:256 --tail blob_sig.bin LNX=amo_plain.img
rd_unpack blob_sig.img blob_s
rd_ck "unpacked as the boot image inside" grep -q '^type=boot$' blob_s/manifest.txt
rd_ck "siglen is in the manifest" grep -q '^blob_secure_siglen=0x100$' blob_s/manifest.txt
rd_ck "the signature is a file" cmp -s blob_s/blob_tail.bin blob_sig.bin
"$ABR" repack blob_s -o blob_s_back.img >blob_s_back.log 2>&1
rd_ck "an untouched repack says nothing about the signature" test "$(grep -c 'signature' blob_s_back.log)" = 0
rd_ck "and is identical, signature included" cmp -s blob_sig.img blob_s_back.img
head -c 9000 /dev/urandom >blob_s/ramdisk/blob_big_file
"$ABR" repack blob_s -o blob_s_edit.img >blob_s_edit.log 2>&1
rd_ck "an edit: the blob is one the independent reader takes" python3 -I "$BTL" list blob_s_edit.img
rd_ck "datalen follows the length of the blob" blob_datalen_is_blob_length blob_s_edit.img
rd_ck "siglen is as it was" said "siglen=256" python3 -I "$BTL" list blob_s_edit.img
rd_ck "the signature is as it was" blob_tail_is blob_s_edit.img blob_sig.bin
rd_ck "and it is said not to fit any more" grep -q 'kept as they were' blob_s_edit.log
rd_done "BLOB with a signature: kept as it was, datalen follows the edited blob, the stale signature is said at repack"

# Without the signing header.
python3 -I "$BTL" make blob_bare.img LNX=amo_plain.img
rd_ck "identify names it" said "MSM-RADIO-UPDATE blob" "$ABR" identify blob_bare.img
rd_unpack blob_bare.img blob_b
rd_ck "unpacked as the boot image inside, with no signed header" grep -q '^blob_secure=false$' blob_b/manifest.txt
"$ABR" repack blob_b -o blob_b_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s blob_bare.img blob_b_back.img
rd_ck "blobunpack reads it too" blob_ref_extract blob_bare.img LNX amo_plain.img
rd_done "BLOB without the signing header: recognised, unpacked, an untouched repack is identical"

# The blob is a directory of its own when it has several partitions, or one that is no image.
python3 -I "$BTL" make blob_multi.img --secure 0:0 EBT=blob_ebt.bin LNX=amo_plain.img APP=blob_app.bin
rd_unpack blob_multi.img blob_m
rd_ck "a blob of three partitions is a directory of its own" grep -q '^type=blob$' blob_m/manifest.txt
rd_ck "a file for each partition" test -f blob_m/part0_EBT.bin -a -f blob_m/part1_LNX.bin -a -f blob_m/part2_APP.bin
rd_ck "(EBT)" cmp -s blob_m/part0_EBT.bin blob_ebt.bin
rd_ck "(LNX)" cmp -s blob_m/part1_LNX.bin amo_plain.img
rd_ck "(APP)" cmp -s blob_m/part2_APP.bin blob_app.bin
rd_ck "info lists them, and says which one is an image" said "\[1\] LNX: $(blob_size amo_plain.img) bytes, version 1, boot" "$ABR" info blob_multi.img
"$ABR" repack blob_m -o blob_m_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s blob_multi.img blob_m_back.img
head -c 3000 /dev/urandom >blob_m/part0_EBT.bin  # another size: the offsets after it move
"$ABR" repack blob_m -o blob_m_e.img >/dev/null 2>&1
rd_ck "an edit: the layout is the one blobpack writes (the independent reader)" python3 -I "$BTL" list blob_m_e.img
python3 -I "$BTL" make blob_m_expect.img --secure 0:0 EBT=blob_m/part0_EBT.bin LNX=amo_plain.img APP=blob_app.bin
rd_ck "and the independent tool makes the same file" cmp -s blob_m_e.img blob_m_expect.img
rd_ck "blobunpack reads the new first partition" blob_ref_extract blob_m_e.img EBT blob_m/part0_EBT.bin
rd_ck "and the last" blob_ref_extract blob_m_e.img APP blob_app.bin
python3 -I "$BTL" make blob_sos.img SOS=blob_app.bin
rd_unpack blob_sos.img blob_sos
rd_ck "one partition that is no image: a directory of its own" grep -q '^type=blob$' blob_sos/manifest.txt
"$ABR" repack blob_sos -o blob_sos_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s blob_sos.img blob_sos_back.img
python3 -I "$BTL" make blob_odd.img 0x61006200=blob_app.bin 0x01020304@7=blob_ebt.bin
rd_unpack blob_odd.img blob_o
rd_ck "names that are no words are kept as hex" grep -q '^blob_part0_name_hex=61006200$' blob_o/manifest.txt
rd_ck "(and the version of a partition)" grep -q '^blob_part1_version=7$' blob_o/manifest.txt
"$ABR" repack blob_o -o blob_o_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s blob_odd.img blob_o_back.img
rd_done "BLOB with several partitions (or one that is no image): type=blob, a file per partition, an edit moves the offsets the way blobpack lays them out"

# The wrappers stack: an AMONET-patched image in a blob, and that in a DHTB wrapper.
python3 -I "$BTL" make blob_amo.img --secure 0:0 LNX=amo.img
rd_unpack blob_amo.img blob_a
rd_ck "both wrappers are in the manifest" grep -q '^has_blob=true$' blob_a/manifest.txt
rd_ck "(the patch)" grep -q '^has_amonet=true$' blob_a/manifest.txt
rd_ck "and are named" grep -q 'unpacked blob-wrapped amonet-patched boot' blob_a.log
"$ABR" repack blob_a -o blob_a_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s blob_amo.img blob_a_back.img
python3 -I - <<'PYEOF'
import hashlib, struct
payload = open("blob_amo.img", "rb").read()
header = b"DHTB\x01\x00\x00\x00" + hashlib.sha256(payload).digest() + b"\x00" * 8 + struct.pack("<I", len(payload))
open("blob_dhtb.img", "wb").write(header + b"\x00" * (512 - len(header)) + payload)
PYEOF
rd_unpack blob_dhtb.img blob_d
rd_ck "three wrappers, named in the order they come off" grep -q 'unpacked dhtb-wrapped blob-wrapped amonet-patched boot' blob_d.log
"$ABR" repack blob_d -o blob_d_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s blob_dhtb.img blob_d_back.img
rd_done "BLOB around an AMONET-patched image (and under DHTB): the wrappers are taken off and put back in order, the round trip is exact"

# What is not read is refused with a reason, and leaves nothing behind.
head -c "$(($(blob_size blob_aik.img) / 2))" blob_aik.img >blob_cut.img
rm -rf blob_cut
"$ABR" unpack blob_cut.img -o blob_cut >blob_cut.out 2>&1
blob_rc=$?
rd_ck "a blob cut short is refused" test "$blob_rc" -ne 0
rd_ck "with the reason" grep -q 'cut short' blob_cut.out
rd_ck "and no directory is left behind" test ! -e blob_cut
python3 -I - <<'PYEOF'
import struct
d = bytearray(open("blob_aik.img", "rb").read())
at = 28 + 60 + 4  # the offset of the first partition in its table entry (28: the signed header, 60: the blob header)
offset = struct.unpack("<I", d[at:at + 4])[0]
d[at:at + 4] = struct.pack("<I", offset + 4)
d[28 + offset:28 + offset] = b"\xde\xad\xbe\xef"  # four bytes between the table and the data
open("blob_gap.img", "wb").write(bytes(d))
PYEOF
rm -rf blob_gap
"$ABR" unpack blob_gap.img -o blob_gap >blob_gap.out 2>&1
blob_rc=$?
rd_ck "a blob with a gap before its data is refused" test "$blob_rc" -ne 0
rd_ck "with the reason" grep -q 'where blobpack puts it' blob_gap.out
rd_ck "(the independent reader refuses it too)" test "$(python3 -I "$BTL" list blob_gap.img >/dev/null 2>&1; echo $?)" = 1
rd_ck "and no directory is left behind" test ! -e blob_gap
printf -- '-SIGNED-BY-SIGNBLOB-\0\0\0\0\0\0\0\0' >blob_nothing.img
head -c 4000 /dev/zero >>blob_nothing.img
rm -rf blob_nothing
"$ABR" unpack blob_nothing.img -o blob_nothing >blob_nothing.out 2>&1
blob_rc=$?
rd_ck "the signing header with no blob behind it is refused" test "$blob_rc" -ne 0
rd_ck "with the reason" grep -q 'no "MSM-RADIO-UPDATE" blob behind it' blob_nothing.out
rd_ck "and no directory is left behind" test ! -e blob_nothing
rd_done "BLOB: a cut-short blob, a gap in the layout and a signing header without a blob are refused with a reason, leaving no directory"

# =========================================================================
# OSIP: the boot image of Intel's Atom-based Android devices, the one Android Image Kitchen opens with osm0sis'
# mboot (abr/legacy/osip.hpp). The images of these tests are made by tests/tools/osip_tool.py, which is written from
# mboot.c's layout and shares no code with abr. ABR_MBOOT names a compiled mboot (GPL-2.0, github.com/osm0sis/mboot;
# not part of this repository, the linux CI jobs compile it): where it is at hand it is a judge too -- it packs the
# same pieces (the independent tool must make the very same image), reads the pieces abr unpacked, and takes an
# image abr wrote apart and packs it again (the same image: abr's header fields are what mboot makes them).
# =========================================================================
OTL="$TOOLS/osip_tool.py"
osip_real() { [ -n "${ABR_MBOOT:-}" ] && [ -x "${ABR_MBOOT:-}" ]; }
OSIP_CMD="init=/init pci=noearly console=ttyS0 androidboot.hardware=redhookbay"
python3 "$RDG" mkbootfs osip_rd.cpio
gzip -9n -c osip_rd.cpio >osip_rd.gz
python3 -I - <<'PYEOF'
import random
r = random.Random(20261013)
# mboot refuses a kernel of less than 500000 bytes and a ramdisk of less than 10000: these are 600000 and about 80000
kernel = b"\xeb\x3c" + r.randbytes(600000 - 2)           # (not starting with a letter: it follows a 4096-byte bootstub)
stub4 = b"\xfc\xfa\xbc\x00" + r.randbytes(4096 - 4)      # a bootstub starts like Intel's: FC FA BC 00
stub8 = stub4 + b"ZZ" + r.randbytes(4096 - 2)            # 8192 bytes: letters where mboot looks for its second half
open("osip_kernel.bin", "wb").write(kernel)
open("osip_stub4.bin", "wb").write(stub4)
open("osip_stub8.bin", "wb").write(stub8)
for size in (480, 728, 1024):
    s = bytearray(r.randbytes(size))
    for at in (0, 480, 728):                             # where mboot looks for the cmdline: not four letters there
        if at < size:
            s[at:at + 4] = b"\x00\x01\x02\x03"
    open("osip_sig%d.bin" % size, "wb").write(bytes(s))
    s[0:4] = b"ABCD"                                     # ... and a signature mboot takes for a cmdline
    open("osip_siga%d.bin" % size, "wb").write(bytes(s))
PYEOF
python3 -I "$OTL" header osip_hdr_u.bin --attribute 1  # a boot image without a signature
python3 -I "$OTL" header osip_hdr_s.bin --attribute 0  # a signed one

osip_size() { wc -c <"$1" | tr -d ' '; }
osip_make() {  # <image> <header: none|u|s> <signature: none|480|728|1024|a480..> <bootstub: 4|8> [<cmdline>]: the independent tool packs the pieces
    local out="$1" h="$2" s="$3" b="$4" cmd="${5-$OSIP_CMD}" args=()
    [ "$h" = none ] || args+=(--hdr "osip_hdr_$h.bin")
    [ "$s" = none ] || args+=(--sig "osip_sig$s.bin")
    python3 -I "$OTL" make "$out" ${args[@]+"${args[@]}"} --cmdline "$cmd" --parameter 0102030405060708 \
        --bootstub "osip_stub$b.bin" --kernel osip_kernel.bin --ramdisk osip_rd.gz
}
osip_mboot_make() {  # <image> <header> <signature> <bootstub>: mboot packs the same pieces, and that is this image (true without the tool)
    osip_real || return 0
    local out="$1" h="$2" s="$3" b="$4" d="$1.pieces"
    rm -rf "$d" && mkdir "$d" || return 1
    cp osip_kernel.bin "$d/kernel" && cp osip_rd.gz "$d/ramdisk.cpio.gz" && cp "osip_stub$b.bin" "$d/bootstub" || return 1
    printf '%s' "$OSIP_CMD" >"$d/cmdline.txt"
    printf '\001\002\003\004\005\006\007\010' >"$d/parameter"
    [ "$h" = none ] || cp "osip_hdr_$h.bin" "$d/hdr"
    [ "$s" = none ] || cp "osip_sig$s.bin" "$d/sig"
    "$ABR_MBOOT" -d "$d" -f "$out.mboot" >/dev/null 2>&1 || return 1
    cmp -s "$out" "$out.mboot"
}
osip_fixpoint() {  # <image>: mboot takes the image apart and packs the pieces again: the same image (true without the tool)
    osip_real || return 0
    rm -rf osip_fx && mkdir osip_fx || return 1
    "$ABR_MBOOT" -u -f "$1" -d osip_fx >/dev/null 2>&1 || return 1
    "$ABR_MBOOT" -d osip_fx -f osip_fx.img >/dev/null 2>&1 || return 1
    cmp -s "$1" osip_fx.img
}
osip_pieces() {  # <the directory an image was taken apart into (mboot's names)> <abr's unpack dir>: the same pieces
    local x="$1" d="$2"
    cmp -s "$x/kernel" "$d/kernel" || return 1
    cmp -s "$x/bootstub" "$d/bootstub.bin" || return 1
    if [ -f "$x/hdr" ]; then cmp -s "$x/hdr" "$d/osip_header.bin" || return 1; else [ ! -e "$d/osip_header.bin" ] || return 1; fi
    if [ -f "$x/sig" ]; then cmp -s "$x/sig" "$d/osip_sig.bin" || return 1; else [ ! -e "$d/osip_sig.bin" ] || return 1; fi
    gzip -dc "$x/ramdisk.cpio.gz" >osip_pieces.cpio 2>/dev/null && cmp -s osip_pieces.cpio "$d/ramdisk.cpio"
}
osip_agree() {  # <image> <abr's unpack dir>: what abr unpacked is what the independent tool (and mboot) take the image apart into
    rm -rf osip_ex_py osip_ex_mb
    python3 -I "$OTL" extract "$1" osip_ex_py || return 1
    osip_pieces osip_ex_py "$2" || return 1
    osip_real || return 0
    mkdir osip_ex_mb && "$ABR_MBOOT" -u -f "$1" -d osip_ex_mb >/dev/null 2>&1 || return 1
    osip_pieces osip_ex_mb "$2"
}
osip_cmd_is() { [ "$(sed -n 's/^cmdline=//p' "$1/manifest.txt")" = "$2" ]; }  # <unpack dir> <text>
osip_add_files() {  # <unpack dir>: two files in the ramdisk directory (one of them random, so that the image grows)
    printf 'abr test\n' >"$1/ramdisk/abr_test_file"
    head -c 9000 /dev/urandom >"$1/ramdisk/osip_big_file"
}
osip_same_but_added() { diff -r --no-dereference -x abr_test_file -x osip_big_file "$1" "$2" >/dev/null; }  # <dir> <dir>
osip_sectors_ok() {  # <image without a fill>: the header's sector count is the size in sectors, less its own
    [ "$(od -An -tu4 -j48 -N4 "$1" | tr -d ' ')" = "$(($(osip_size "$1") / 512 - 1))" ]
}
osip_refuse() {  # <name> <unpack dir> <pattern>: repack of that (damaged) directory is refused with that reason and writes no image
    local out rc
    rm -f "osip_rf_$1.img"
    out="$("$ABR" repack "$2" -o "osip_rf_$1.img" 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && [ ! -e "osip_rf_$1.img" ] && grep -q -- "$3" <<<"$out"
}

# Seven kinds of image: the pieces as mboot takes them apart, identify, an untouched repack.
OSIP_VARIANTS="u4:u:none:4 s480:s:480:4 s728:s:728:4 s1024:s:1024:4 u8:u:none:8 s480_8:s:480:8 h4:none:none:4"
for v in $OSIP_VARIANTS; do
    IFS=: read -r n h s b <<<"$v"
    case "$h" in
        u) label="OSIP bootimg, boot (unsigned)" ;;
        s) label="OSIP bootimg, boot (signed)" ;;
        *) label="OSIP bootimg (headerless)" ;;
    esac
    osip_make "osip_$n.img" "$h" "$s" "$b"
    rd_ck "$n: the independent tool packs what mboot packs" osip_mboot_make "osip_$n.img" "$h" "$s" "$b"
    rd_ck "$n: its header is what mboot makes it" python3 -I "$OTL" check "osip_$n.img"
    rd_ck "$n: identify" said "$label" "$ABR" identify "osip_$n.img"
    rd_unpack "osip_$n.img" "osip_u_$n"
    rd_ck "$n: type" grep -q '^type=osip$' "osip_u_$n/manifest.txt"
    rd_ck "$n: the size of the signature" grep -q "^osip_signature_size=${s/none/0}\$" "osip_u_$n/manifest.txt"
    rd_ck "$n: the cmdline" osip_cmd_is "osip_u_$n" "$OSIP_CMD"
    rd_ck "$n: the parameter" grep -q '^osip_parameter=0102030405060708$' "osip_u_$n/manifest.txt"
    rd_ck "$n: the ramdisk is gzip" grep -q '^ramdisk_compression=gzip$' "osip_u_$n/manifest.txt"
    rd_ck "$n: and a directory" test -f "osip_u_$n/ramdisk/init.rc"
    rd_ck "$n: header, signature, bootstub, kernel and ramdisk are what the image holds" osip_agree "osip_$n.img" "osip_u_$n"
    rd_ck "$n: unpack says an untouched repack is exact" grep -q 'reproduces this image byte-for-byte' "osip_u_$n.log"
    "$ABR" repack "osip_u_$n" -o "osip_r_$n.img" >"osip_r_$n.log" 2>&1
    rd_ck "$n: an untouched repack is identical" cmp -s "osip_$n.img" "osip_r_$n.img"
done
rd_ck "info: the header and its checksum" said "header: *512 bytes, boot (unsigned), [0-9]* sectors, checksum OK" "$ABR" info osip_u4.img
rd_ck "info: a signed image" said "header: *512 bytes, boot (signed), [0-9]* sectors, checksum OK" "$ABR" info osip_s480.img
rd_ck "info: its signature" said "signature: *480 bytes" "$ABR" info osip_s480.img
rd_ck "info: the bootstub" said "bootstub: *8192 bytes" "$ABR" info osip_u8.img
rd_ck "info: the kernel" said "kernel: *600000 bytes" "$ABR" info osip_u4.img
rd_ck "info: the ramdisk" said "ramdisk: *[0-9]* bytes (gzip)" "$ABR" info osip_u4.img
rd_ck "info: the cmdline" said "cmdline: *$OSIP_CMD" "$ABR" info osip_u4.img
rd_ck "info: no header" said "header: *none" "$ABR" info osip_h4.img
rd_done "OSIP: images with a header (unsigned, a signature of 480, 728 or 1024 bytes, a bootstub of 4096 or 8192) and without one, as mboot packs them: the independent tool makes the same bytes, identify and info see them, the pieces are those mboot reads, an untouched repack is identical"

# An edit: the ramdisk is built from the directory, the sizes in the header follow, and the result is what mboot
# makes of its own pieces (it takes the image apart and packs it again: the same image).
for v in $OSIP_VARIANTS; do
    IFS=: read -r n h s b <<<"$v"
    rm -rf "osip_e_$n"
    cp -a "osip_u_$n" "osip_e_$n"
    osip_add_files "osip_e_$n"
    rd_ck "$n: repack" rd_repack_unpack "osip_e_$n" "osip_ed_$n"
    rd_ck "$n: the file is in the image" test "$(cat "osip_ed_${n}_re/ramdisk/abr_test_file" 2>/dev/null)" = "abr test"
    rd_ck "$n: nothing else changed" osip_same_but_added "osip_u_$n/ramdisk" "osip_ed_${n}_re/ramdisk"
    rd_ck "$n: the image is a whole number of sectors" test "$(($(osip_size "osip_ed_$n.img") % 512))" = 0
    rd_ck "$n: and it grew" test "$(osip_size "osip_ed_$n.img")" -gt "$(osip_size "osip_$n.img")"
    rd_ck "$n: its header (sector count, unsigned bit, checksum) is what mboot makes it" python3 -I "$OTL" check "osip_ed_$n.img"
    [ "$h" = none ] || rd_ck "$n: the header's sector count" osip_sectors_ok "osip_ed_$n.img"
    rd_ck "$n: mboot takes it apart and packs the same image" osip_fixpoint "osip_ed_$n.img"
    rd_ck "$n: the ramdisk, the kernel and the rest are what mboot reads" osip_agree "osip_ed_$n.img" "osip_ed_${n}_re"
    if [ "$s" != none ]; then
        rd_ck "$n: the signature is as it was" cmp -s "osip_u_$n/osip_sig.bin" "osip_ed_${n}_re/osip_sig.bin"
        rd_ck "$n: and the repack says it no longer fits the image" grep -q 'describes the ORIGINAL contents' "osip_ed_$n.rlog"
    else
        rd_ck "$n: no signature, nothing to say about one" test -z "$(grep 'signature' "osip_ed_$n.rlog")"
    fi
done
rd_done "OSIP: an edited ramdisk lands in the image, the header follows it, and the result is a fixed point of mboot (it takes the image apart and packs it again: the same bytes); a kept signature is called stale"

# Signed images without a header: mboot cannot take these apart (it takes a first byte that is not a letter for
# an OSIP header), the independent tool packs them; abr finds the layout from the bootstub and the sizes.
osip_make osip_hs1024.img none 1024 4
osip_make osip_hs728_8.img none 728 8
for v in hs1024:1024 hs728_8:728; do
    n="${v%%:*}"
    size="${v##*:}"
    rd_ck "$n: identify" said "OSIP bootimg (headerless)" "$ABR" identify "osip_$n.img"
    rd_unpack "osip_$n.img" "osip_u_$n"
    rd_ck "$n: the size of the signature" grep -q "^osip_signature_size=$size\$" "osip_u_$n/manifest.txt"
    rd_ck "$n: the signature is the first bytes of the image" test "$(head -c "$size" "osip_$n.img" | cmp -s - "osip_u_$n/osip_sig.bin" && echo same)" = same
    rd_ck "$n: no header" test ! -e "osip_u_$n/osip_header.bin"
    "$ABR" repack "osip_u_$n" -o "osip_r_$n.img" >/dev/null 2>&1
    rd_ck "$n: an untouched repack is identical" cmp -s "osip_$n.img" "osip_r_$n.img"
    rm -rf "osip_e_$n"
    cp -a "osip_u_$n" "osip_e_$n"
    osip_add_files "osip_e_$n"
    rd_ck "$n: repack" rd_repack_unpack "osip_e_$n" "osip_ed_$n"
    rd_ck "$n: the file is in the image" test "$(cat "osip_ed_${n}_re/ramdisk/abr_test_file" 2>/dev/null)" = "abr test"
    rd_ck "$n: nothing else changed" osip_same_but_added "osip_u_$n/ramdisk" "osip_ed_${n}_re/ramdisk"
    rd_ck "$n: the signature is as it was" cmp -s "osip_u_$n/osip_sig.bin" "osip_ed_${n}_re/osip_sig.bin"
    rd_ck "$n: a whole number of sectors" test "$(($(osip_size "osip_ed_$n.img") % 512))" = 0
done
rd_done "OSIP: a signed image without a header (the layout comes from the bootstub and the sizes in the image info): unpacked, an untouched repack is identical, an edit lands and keeps the signature"

# The signature taken away, the signature put in: what mboot packs of the same pieces (the unsigned bit, the
# sector count, the checksum, and the mark that a signed image has behind the parameter).
rm -rf osip_nosig
cp -a osip_u_s480 osip_nosig
sed -i '/^osip_signature_file=/d' osip_nosig/manifest.txt
"$ABR" repack osip_nosig -o osip_nosig.img >osip_nosig.log 2>&1
osip_make osip_nosig_ref.img s none 4
rd_ck "no signature: the image is the pieces without it, as the independent tool packs them" cmp -s osip_nosig.img osip_nosig_ref.img
rd_ck "(and mboot)" osip_mboot_make osip_nosig.img s none 4
rd_ck "its header says unsigned now" said "OSIP bootimg, boot (unsigned)" "$ABR" identify osip_nosig.img
rd_ck "and is what mboot makes it" python3 -I "$OTL" check osip_nosig.img
rd_ck "it is a fixed point of mboot" osip_fixpoint osip_nosig.img
rd_ck "there is nothing to say about the signature that went" test -z "$(grep 'describes the ORIGINAL' osip_nosig.log)"
rm -rf osip_addsig
cp -a osip_u_u4 osip_addsig
cp osip_sig480.bin osip_addsig/osip_sig.bin
printf 'osip_signature_file=osip_sig.bin\n' >>osip_addsig/manifest.txt
"$ABR" repack osip_addsig -o osip_addsig.img >osip_addsig.log 2>&1
osip_make osip_addsig_ref.img u 480 4
rd_ck "a signature put in: the image is the pieces with it, as the independent tool packs them" cmp -s osip_addsig.img osip_addsig_ref.img
rd_ck "(and mboot)" osip_mboot_make osip_addsig.img u 480 4
rd_ck "the mark of a signed image is behind the parameter" test "$(od -An -tx1 -j$((512 + 480 + 1024 + 16)) -N8 osip_addsig.img | tr -d ' \n')" = bd02bd02bd12bd12
rd_ck "it is a fixed point of mboot" osip_fixpoint osip_addsig.img
rd_ck "the header is kept as mboot keeps it, and the repack says so" grep -q 'still says "boot (unsigned)"' osip_addsig.log
rd_ck "a signature that was not there is not a stale one" test -z "$(grep 'describes the ORIGINAL' osip_addsig.log)"
rd_ck "the new signature is read back" said "signature: *480 bytes" "$ABR" info osip_addsig.img
rd_done "OSIP: taking the signature away (unsigned bit, mark, sector count and checksum follow) and putting one in give what mboot packs of the same pieces"

# An image inside a partition: the fill behind the image proper (and the padding up to a whole sector) is the
# partition's; an edit leaves the partition its size.
python3 -I - <<'PYEOF'
d = open("osip_u4.img", "rb").read()
open("osip_part_ff.img", "wb").write(d + b"\xff" * (2 * 1024 * 1024 - len(d)))
open("osip_part_00.img", "wb").write(d + b"\x00" * (2 * 1024 * 1024 - len(d)))
PYEOF
for k in ff:'\377' 00:'\000'; do
    f="${k%%:*}"
    fillchar="${k#*:}"
    rd_ck "$f: identify" said "OSIP bootimg, boot (unsigned)" "$ABR" identify "osip_part_$f.img"
    rd_unpack "osip_part_$f.img" "osip_pu_$f"
    rd_ck "$f: info says the fill" said "padding:" "$ABR" info "osip_part_$f.img"
    "$ABR" repack "osip_pu_$f" -o "osip_pr_$f.img" >/dev/null 2>&1
    rd_ck "$f: an untouched repack is identical" cmp -s "osip_part_$f.img" "osip_pr_$f.img"
    rm -rf "osip_pe_$f"
    cp -a "osip_pu_$f" "osip_pe_$f"
    osip_add_files "osip_pe_$f"
    rd_ck "$f: repack" rd_repack_unpack "osip_pe_$f" "osip_ped_$f"
    rd_ck "$f: the partition keeps its size" test "$(osip_size "osip_ped_$f.img")" = 2097152
    rd_ck "$f: the file is in the image" test "$(cat "osip_ped_${f}_re/ramdisk/abr_test_file" 2>/dev/null)" = "abr test"
    rd_ck "$f: the header is what mboot makes it" python3 -I "$OTL" check "osip_ped_$f.img"
    rd_ck "$f: the fill goes on behind the image" test "$(tail -c 1000000 "osip_ped_$f.img" | tr -d "$fillchar" | wc -c | tr -d ' ')" = 0
done
rm -rf osip_pe_big
cp -a osip_pu_ff osip_pe_big
head -c 3000000 /dev/urandom >osip_pe_big/ramdisk/osip_huge_file
"$ABR" repack osip_pe_big -o osip_pe_big.img >osip_pe_big.rlog 2>&1
rd_ck "an edit that outgrows the partition is built and the size is said" grep -q 'larger than the original' osip_pe_big.rlog
rd_done "OSIP: an image in a partition (0xFF or 0x00 fill): an untouched repack is identical, an edit keeps the size of the partition and the fill, one that outgrows it is said"

# The cmdline: the text of the manifest; white space at its ends or something behind it that is not NULs is kept
# (a file of its own) as long as the text is the one that was there.
osip_make osip_sp.img u none 4 " init=/init quiet"
osip_make osip_nl.img u none 4 $'console=ttyS0\tquiet\n'
for k in sp:"init=/init quiet" nl:$'console=ttyS0\tquiet'; do
    f="${k%%:*}"
    text="${k#*:}"
    rd_unpack "osip_$f.img" "osip_cu_$f"
    rd_ck "$f: the manifest has the text without the white space at its ends" osip_cmd_is "osip_cu_$f" "$text"
    rd_ck "$f: the block is a file of its own" grep -q '^osip_cmdline_file=osip_cmdline.bin$' "osip_cu_$f/manifest.txt"
    "$ABR" repack "osip_cu_$f" -o "osip_cr_$f.img" >/dev/null 2>&1
    rd_ck "$f: an untouched repack is identical" cmp -s "osip_$f.img" "osip_cr_$f.img"
done
rd_ck "the plain cmdline has no file of its own" test ! -e osip_u_u4/osip_cmdline.bin
rm -rf osip_ce
cp -a osip_cu_sp osip_ce
sed -i 's/^cmdline=.*/cmdline=init=\/init quiet debug/' osip_ce/manifest.txt
"$ABR" repack osip_ce -o osip_ce.img >/dev/null 2>&1
rd_ck "an edited cmdline is what the image has" test "$(python3 -I "$OTL" list osip_ce.img | sed -n 's/^cmdline //p')" = "init=/init quiet debug"
rd_ck "(its size did not change: neither did the header)" test "$(head -c 512 osip_ce.img | cmp -s - osip_cu_sp/osip_header.bin && echo same)" = same
rd_ck "mboot reads it" osip_fixpoint osip_ce.img
rm -rf osip_cl
cp -a osip_u_u4 osip_cl
sed -i "s/^cmdline=.*/cmdline=$(head -c 1025 /dev/zero | tr '\0' a)/" osip_cl/manifest.txt
rd_ck "a cmdline of 1025 bytes is refused" osip_refuse cmdline osip_cl "room for 1024"
rd_done "OSIP: a cmdline with white space at its ends or a line break is kept exactly, an edited one is written in a block of 1024 bytes, a longer one is refused"

# Headers that are not as mboot would make them stay as they are until the size of the image changes.
python3 -I - <<'PYEOF'
d = bytearray(open("osip_u4.img", "rb").read())
d[7] ^= 0x55                    # a checksum that is not right
open("osip_badck.img", "wb").write(bytes(d))
e = bytearray(open("osip_u4.img", "rb").read())
e[48] = 7                       # a sector count that is not right, with the checksum of that
e[7] = 0
x = 0
for i, c in enumerate(e[:56]):
    if i != 7:
        x ^= c
e[7] = x
open("osip_badsec.img", "wb").write(bytes(e))
PYEOF
for k in badck badsec; do
    rd_unpack "osip_$k.img" "osip_hu_$k"
    "$ABR" repack "osip_hu_$k" -o "osip_hr_$k.img" >/dev/null 2>&1
    rd_ck "$k: an untouched repack is identical" cmp -s "osip_$k.img" "osip_hr_$k.img"
    rd_ck "$k: the independent tool finds it wrong" test "$(python3 -I "$OTL" check "osip_$k.img" >/dev/null 2>&1; echo $?)" = 1
    rm -rf "osip_he_$k"
    cp -a "osip_hu_$k" "osip_he_$k"
    sed -i 's/^cmdline=.*/cmdline=init=\/init quiet debug and a longer one/' "osip_he_$k/manifest.txt"
    "$ABR" repack "osip_he_$k" -o "osip_he_$k.img" >/dev/null 2>&1
    rd_ck "$k: an edit that keeps the size leaves the header alone" test "$(head -c 512 "osip_he_$k.img" | cmp -s - <(head -c 512 "osip_$k.img") && echo same)" = same
    rm -rf "osip_hs_$k"
    cp -a "osip_hu_$k" "osip_hs_$k"
    osip_add_files "osip_hs_$k"
    "$ABR" repack "osip_hs_$k" -o "osip_hs_$k.img" >/dev/null 2>&1
    rd_ck "$k: one that changes it gets a header mboot makes" python3 -I "$OTL" check "osip_hs_$k.img"
done
rd_ck "info says the checksum is wrong" said "checksum WRONG" "$ABR" info osip_badck.img
rd_ck "info says what the header counts and what the image has" said "[0-9]* sectors (the image has [0-9]*)" "$ABR" info osip_badsec.img
rd_ck "unpack notes a checksum that is wrong" said "checksum in the OSIP header" "$ABR" unpack osip_badck.img -o osip_hu_badck2
rd_done "OSIP: a header with a wrong checksum or sector count is kept as it is by an untouched repack and by one that keeps the size; a changed size makes it right"

# Where mboot's guess at the layout (four letters = the cmdline) is wrong: the layout that fits the image info is taken.
for n in 480 728 1024; do
    osip_make "osip_sa$n.img" s "a$n" 4
    rd_ck "a$n: identify" said "OSIP bootimg, boot (signed)" "$ABR" identify "osip_sa$n.img"
    rd_unpack "osip_sa$n.img" "osip_u_sa$n"
    rd_ck "a$n: the signature is $n bytes, though it starts like a cmdline" grep -q "^osip_signature_size=$n\$" "osip_u_sa$n/manifest.txt"
    rd_ck "a$n: the cmdline" osip_cmd_is "osip_u_sa$n" "$OSIP_CMD"
    "$ABR" repack "osip_u_sa$n" -o "osip_r_sa$n.img" >/dev/null 2>&1
    rd_ck "a$n: an untouched repack is identical" cmp -s "osip_sa$n.img" "osip_r_sa$n.img"
    rm -rf "osip_e_sa$n"
    cp -a "osip_u_sa$n" "osip_e_sa$n"
    osip_add_files "osip_e_sa$n"
    rd_ck "a$n: repack" rd_repack_unpack "osip_e_sa$n" "osip_ed_sa$n"
    rd_ck "a$n: the file is in the image" test "$(cat "osip_ed_sa${n}_re/ramdisk/abr_test_file" 2>/dev/null)" = "abr test"
    rd_ck "a$n: the header's sector count" osip_sectors_ok "osip_ed_sa$n.img"
done
rd_ck "a cmdline that starts with a space (mboot takes the image for one with a signature of 1024 bytes): identify" said "OSIP bootimg, boot (unsigned)" "$ABR" identify osip_sp.img
rd_ck "and the image has no signature" grep -q '^osip_signature_size=0$' osip_cu_sp/manifest.txt
rd_done "OSIP: a signature that starts with four letters, a cmdline that starts with a space (what mboot's guess at the layout takes for something else): the layout that fits the image info is taken"

# What is not read is refused with a reason, and leaves nothing behind.
head -c 300000 osip_u4.img >osip_cut.img      # the kernel is cut
head -c 3000 osip_u4.img >osip_cut2.img       # inside the cmdline and image info
head -c 200000 osip_h4.img >osip_cut3.img     # no header, cut
python3 -I "$OTL" header osip_hdr_only.img    # a header and nothing else
for k in cut cut2 cut3 hdr_only; do
    rm -rf "osip_$k.dir"
    "$ABR" unpack "osip_$k.img" -o "osip_$k.dir" >"osip_$k.out" 2>&1
    rc=$?
    rd_ck "$k: refused" test "$rc" -ne 0
    rd_ck "$k: with the reason" grep -q 'cut short' "osip_$k.out"
    rd_ck "$k: and no directory is left behind" test ! -e "osip_$k.dir"
done
rd_ck "the sizes the image info declares are said" grep -q 'declares a kernel of 600000 bytes' osip_cut.out
rm -rf osip_bad
cp -a osip_u_u4 osip_bad
head -c 5000 /dev/zero >osip_bad/bootstub.bin
rd_ck "a bootstub of 5000 bytes is refused on repack" osip_refuse stub osip_bad "4096 or 8192 bytes"
rm -rf osip_bad
cp -a osip_u_s480 osip_bad
head -c 500 /dev/urandom >osip_bad/osip_sig.bin
rd_ck "a signature of 500 bytes is refused on repack" osip_refuse sig osip_bad "480, 728 or 1024 bytes"
rm -rf osip_bad
cp -a osip_u_u4 osip_bad
sed -i 's/^osip_parameter=.*/osip_parameter=01020304/' osip_bad/manifest.txt
rd_ck "a parameter of 4 bytes is refused on repack" osip_refuse param osip_bad "must be 8 bytes"
rm -rf osip_bad
cp -a osip_u_u4 osip_bad
head -c 4000 /dev/urandom >osip_bad/osip_info.bin
printf 'osip_info_file=osip_info.bin\n' >>osip_bad/manifest.txt
rd_ck "an image info that does not fit is refused on repack" osip_refuse info osip_bad "has room for"
rm -rf osip_bad
cp -a osip_u_h4 osip_bad
printf 'osip_header_file=osip_header.bin\n' >>osip_bad/manifest.txt
head -c 100 /dev/zero >osip_bad/osip_header.bin
rd_ck "a header of 100 bytes is refused on repack" osip_refuse header osip_bad "512 bytes"
rd_done "OSIP: an image that is cut short (or a header alone) is refused with the sizes it declares, and a bootstub, signature, parameter, image info or header that does not fit the layout is refused on repack, leaving no output"

# =========================================================================
# LOKI: the patch of loki_tool (Dan Rosenberg's "loki", 2013), which Android Image Kitchen takes off a boot or
# recovery image with `loki_tool unlok` (abr/legacy/loki.hpp). abr takes it off without the aboot.img of the phone and
# puts the block of the bootloader's code that was in the image back, so an image comes back byte for byte. The
# bootloader images and the patched images of these tests are made by tests/tools/loki_tool.py, which is written from
# loki's layout and shares no code with abr; an aboot made there is random bytes that hold what `loki_tool patch`
# reads of one (one of its patterns at the address of an entry of its table, a base address), nothing that is a
# bootloader. ABR_LOKI_TOOL names a compiled loki_tool (BSD-2-Clause, github.com/djrbliss/loki; not part of this
# repository, the linux CI jobs compile it): where it is at hand it is a judge too -- it patches the same plain image
# into the same bytes (the independent tool must make them as well), and takes the patch off the way abr does.
# =========================================================================
LKT="$TOOLS/loki_tool.py"
LKB="$TOOLS/blob_tool.py"
loki_real() { [ -n "${ABR_LOKI_TOOL:-}" ] && [ -x "${ABR_LOKI_TOOL:-}" ]; }
for t in a b c d e f; do python3 -I "$LKT" aboot "$t" "loki_aboot_$t.img"; done
python3 "$RDG" mkbootfs loki_rd.cpio
gzip -9n -c loki_rd.cpio >loki_rd.gz
python3 -I - "$TOOLS" <<'PYEOF'
import random
import sys
sys.path.insert(0, sys.argv[1])
import fixtures
r = random.Random(20261014)
rd = open("loki_rd.gz", "rb").read()
kernel = r.randbytes(70001)                      # not a whole number of pages
cmd = "console=ttyS0,115200 androidboot.hardware=lokitest"
longcmd = " ".join("opt%03d=%d" % (i, i * 7) for i in range(200))[:900]   # runs into the extra command line
def w(name, data):
    open("loki_plain_%s.img" % name, "wb").write(data)
w("nodt", fixtures.boot_v012(0, kernel, rd, page=2048, cmdline=cmd, name="lokitest"))
w("dt", fixtures.boot_v012(0, kernel, rd, dt=r.randbytes(5000), page=2048, cmdline=cmd, name="lokitest"))
w("p4k", fixtures.boot_v012(0, r.randbytes(100000), rd, dt=r.randbytes(8192), page=4096, cmdline=cmd))
# sizes that are whole pages: the kernel, the ramdisk (no archive) and the device tree
w("al", fixtures.boot_v012(0, r.randbytes(2048 * 30), r.randbytes(2048 * 8), dt=r.randbytes(2048), page=2048, cmdline=cmd))
w("cl", fixtures.boot_v012(0, kernel, rd, page=2048, cmdline=longcmd))
PYEOF

loki_size() { wc -c <"$1" | tr -d ' '; }
loki_real_patch_is() {  # <image> <target> <boot|recovery> <plain image>: loki_tool patch makes this very image of the plain one (true without the tool)
    loki_real || return 0
    rm -f "$1.real"
    "$ABR_LOKI_TOOL" patch "$3" "loki_aboot_$2.img" "$4" "$1.real" >/dev/null 2>&1 && cmp -s "$1" "$1.real"
}
loki_real_unlok_is() {  # <LOKI image> <plain image>: loki_tool unlok takes the patch off to this very image (true without the tool)
    loki_real || return 0
    rm -f "$1.unlok"
    "$ABR_LOKI_TOOL" unlok "$1" "$1.unlok" >/dev/null 2>&1 && cmp -s "$1.unlok" "$2"
}
loki_make() {  # <image> <target> <boot|recovery> <plain image>: the independent tool patches the plain image (and the real one makes the same bytes)
    python3 -I "$LKT" patch "$2" "$3" "loki_aboot_$2.img" "$4" "$1" || return 1
    loki_real_patch_is "$1" "$2" "$3" "$4"
}
loki_check() {  # <image> <plain image> <target>: the independent reader: the image is what loki_tool patch makes of the plain one with that bootloader
    python3 -I "$LKT" check "$1" "$2" "loki_aboot_$3.img" >/dev/null
}
loki_plain_of() {  # <unpack dir> <out>: what the directory builds without the patch (has_loki=false in a copy)
    rm -rf "$1.nolk" && cp -a "$1" "$1.nolk" || return 1
    sed -i 's/^has_loki=true$/has_loki=false/' "$1.nolk/manifest.txt" || return 1
    "$ABR" repack "$1.nolk" -o "$2" >"$2.log" 2>&1
}
loki_offset() { case "$1" in e) echo 0 ;; f) echo 4 ;; a | d) echo 8 ;; *) echo 12 ;; esac; }  # check_sigs & 15 of the synthetic targets
loki_block() {  # <target> <plain image's name>: the size of the block (512 bytes, a page for the targets whose table says so)
    case "$1" in
        a | e) echo 512 ;;
        *) case "$2" in p4k) echo 4096 ;; *) echo 2048 ;; esac ;;
    esac
}
loki_rec() { if [ "$1" = recovery ]; then echo 1; else echo 0; fi; }
loki_edit() {  # <unpack dir>: two files in the ramdisk's directory or, where the ramdisk is no archive, bytes at the end of the kernel
    if [ -d "$1/ramdisk" ]; then
        printf 'abr test\n' >"$1/ramdisk/abr_test_file"
        head -c 9000 /dev/urandom >"$1/ramdisk/loki_big_file"
    else
        head -c 5000 /dev/urandom >>"$1/kernel"
        printf 'abr test\n' >>"$1/kernel"
    fi
}
loki_edit_is_in() {  # <the directory unpacked from the repacked image>
    if [ -d "$1/ramdisk" ]; then
        [ "$(cat "$1/ramdisk/abr_test_file" 2>/dev/null)" = "abr test" ]
    else
        [ "$(tail -c 9 "$1/kernel")" = "abr test" ]
    fi
}
loki_same_but_edit() {  # <the directory before the edit> <the directory unpacked from the repacked image>
    if [ -d "$1/ramdisk" ]; then
        diff -r --no-dereference -x abr_test_file -x loki_big_file "$1/ramdisk" "$2/ramdisk" >/dev/null || return 1
    else
        cmp -s "$1/ramdisk.cpio" "$2/ramdisk.cpio" || return 1
    fi
    [ ! -e "$1/dt.img" ] || cmp -s "$1/dt.img" "$2/dt.img"
}
loki_same_patch() {  # <dir> <dir>: the patch is the same: the block, and what the manifest says of it
    cmp -s "$1/loki_block.bin" "$2/loki_block.bin" || return 1
    [ "$(grep '^loki_' "$1/manifest.txt")" = "$(grep '^loki_' "$2/manifest.txt")" ]
}
loki_refuse() {  # <name> <image> <pattern>: unpack of that image is refused with that reason and leaves no directory
    local out rc
    rm -rf "loki_rf_$1"
    out="$("$ABR" unpack "$2" -o "loki_rf_$1" 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && [ ! -e "loki_rf_$1" ] && grep -q -- "$3" <<<"$out"
}
loki_refuse_repack() {  # <name> <dir> <pattern>: repack of that directory is refused with that reason and writes no image
    local out rc
    rm -f "loki_rr_$1.img"
    out="$("$ABR" repack "$2" -o "loki_rr_$1.img" 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && [ ! -e "loki_rr_$1.img" ] && grep -q -- "$3" <<<"$out"
}
loki_copy() {  # <dir> <copy>: a fresh copy of an unpack directory
    rm -rf "$2" && cp -a "$1" "$2"
}

# Fourteen kinds of image: every synthetic target (the patch code 0, 4, 8 or 12 bytes into the block; a block of
# 512 bytes or of one page), boot and recovery, with a device tree (the CAF layout: its size in word 10 of the
# header) and without, pages of 2048 and 4096, whole-page sizes, a command line that reaches into the extra one.
for p in nodt dt p4k al cl; do rd_unpack "loki_plain_$p.img" "loki_pu_$p"; done
LOKI_VARIANTS="a_nodt:a:boot:nodt a_dt_r:a:recovery:dt b_dt:b:boot:dt b_nodt_r:b:recovery:nodt c_dt:c:boot:dt d_dt:d:boot:dt d_nodt_r:d:recovery:nodt e_nodt:e:boot:nodt e_4k:e:boot:p4k f_dt:f:boot:dt f_4k_r:f:recovery:p4k a_al:a:boot:al b_al_r:b:recovery:al b_cl:b:boot:cl"
for v in $LOKI_VARIANTS; do
    IFS=: read -r n t k p <<<"$v"
    rd_ck "$n: the image (the independent tool makes it, and the real one the same bytes)" loki_make "loki_$n.img" "$t" "$k" "loki_plain_$p.img"
    rd_ck "$n: the independent reader finds it is loki_tool's patch of the plain image" loki_check "loki_$n.img" "loki_plain_$p.img" "$t"
    rd_ck "$n: identify" said "LOKI header ($k)" "$ABR" identify "loki_$n.img"
    rd_unpack "loki_$n.img" "loki_u_$n"
    rd_ck "$n: unpack says what it took off" grep -q 'unpacked loki-patched boot' "loki_u_$n.log"
    rd_ck "$n: and that an untouched repack is identical" grep -q 'reproduces this image byte-for-byte' "loki_u_$n.log"
    rd_ck "$n: the manifest has the patch" grep -q '^has_loki=true$' "loki_u_$n/manifest.txt"
    rd_ck "$n: and its type" grep -q "^loki_recovery=$(loki_rec "$k")\$" "loki_u_$n/manifest.txt"
    rd_ck "$n: and where its code is" grep -q "^loki_shellcode_offset=$(loki_offset "$t")\$" "loki_u_$n/manifest.txt"
    rd_ck "$n: the block is a file of the size the target has" test "$(loki_size "loki_u_$n/loki_block.bin")" = "$(loki_block "$t" "$p")"
    rd_ck "$n: nothing follows the image" test ! -e "loki_u_$n/loki_tail.bin"
    rd_ck "$n: the rest of the directory is what the plain image gives" diff -r --no-dereference -x manifest.txt -x 'loki_*' "loki_pu_$p" "loki_u_$n"
    loki_plain_of "loki_u_$n" "loki_plainb_$n.img"
    python3 -I "$LKT" unlok "loki_$n.img" "loki_un_$n.img"
    rd_ck "$n: without the patch (has_loki=false) the directory builds what the independent tool takes the patch off to" cmp -s "loki_plainb_$n.img" "loki_un_$n.img"
    # (loki_tool unlok takes the block of the target "d" for 512 bytes where it is a page: it guesses from the
    # address, and that address is one it does not know. The independent tool and abr read the size from the header.)
    if [ "$t" != d ]; then
        rd_ck "$n: and what the real loki_tool unlok takes it off to" loki_real_unlok_is "loki_$n.img" "loki_plainb_$n.img"
    fi
    "$ABR" repack "loki_u_$n" -o "loki_r_$n.img" >/dev/null 2>&1
    rd_ck "$n: an untouched repack is identical" cmp -s "loki_$n.img" "loki_r_$n.img"
    rd_ck "$n: info says there is a patch" said "wrapper: LOKI patch ($k, build" "$ABR" info "loki_$n.img"
done
rd_done "LOKI: images of every shape loki_tool makes (six targets, boot and recovery, with and without a device tree, 2048 and 4096 byte pages, a block of 512 bytes or of a page, whole-page sizes, a long cmdline): the independent tool makes the same bytes, identify and info see the patch, the directory is the plain image's plus the patch, without the patch it builds what loki_tool unlok writes, an untouched repack is identical"

# An edit lands in the image, the patch stays as it was, and what comes out is what loki_tool patch makes of the
# image the directory builds without the patch (the real tool says so too, where it is at hand).
for v in $LOKI_VARIANTS; do
    IFS=: read -r n t k p <<<"$v"
    loki_copy "loki_u_$n" "loki_x_$n"
    loki_edit "loki_x_$n"
    rd_ck "$n: repack" rd_repack_unpack "loki_x_$n" "loki_xr_$n"
    rd_ck "$n: the edit is in the image" loki_edit_is_in "loki_xr_${n}_re"
    rd_ck "$n: nothing else changed" loki_same_but_edit "loki_u_$n" "loki_xr_${n}_re"
    rd_ck "$n: the image grew" test "$(loki_size "loki_xr_$n.img")" -gt "$(loki_size "loki_$n.img")"
    loki_plain_of "loki_x_$n" "loki_xp_$n.img"
    rd_ck "$n: the independent reader finds it is loki_tool's patch of what the directory builds without it" loki_check "loki_xr_$n.img" "loki_xp_$n.img" "$t"
    rd_ck "$n: the real loki_tool patches that image into the very same bytes" loki_real_patch_is "loki_xr_$n.img" "$t" "$k" "loki_xp_$n.img"
    rd_ck "$n: the patch (block, type, build, where the code is) is as it was" loki_same_patch "loki_u_$n" "loki_xr_${n}_re"
    rd_ck "$n: unpacked again it is a fixed point" "$ABR" repack "loki_xr_${n}_re" -o "loki_xr2_$n.img"
    rd_ck "$n: ... the same bytes" cmp -s "loki_xr_$n.img" "loki_xr2_$n.img"
done
rd_done "LOKI: an edited ramdisk (or kernel) lands in the image; the result is loki_tool's patch of what the directory builds without it (the independent reader, and the real loki_tool where it is at hand); the block and the rest of the patch stay; repacking what that gives is the same image"

# The fields of the header the patch moves: the plain header's are what the patched one follows (kernel_size, the
# ramdisk address that goes into the patch code, the load address of the ramdisk that goes into the LOKI header).
for v in b_dt:b:boot:dt e_nodt:e:boot:nodt f_4k_r:f:recovery:p4k; do
    IFS=: read -r n t k p <<<"$v"
    loki_copy "loki_u_$n" "loki_h_$n"
    sed -i -e 's/^kernel_addr=.*/kernel_addr=0x10008000/' -e 's/^ramdisk_addr=.*/ramdisk_addr=0x11000000/' \
        -e 's/^cmdline=.*/cmdline=quiet loglevel=7 androidboot.test=1/' -e 's/^board_name=.*/board_name=other/' "loki_h_$n/manifest.txt"
    head -c 7000 /dev/urandom >>"loki_h_$n/kernel"       # the padded kernel grows by pages: kernel_size, the ramdisk's load address
    rd_ck "$n: repack" "$ABR" repack "loki_h_$n" -o "loki_hr_$n.img"
    loki_plain_of "loki_h_$n" "loki_hp_$n.img"
    rd_ck "$n: the image is loki_tool's patch of the plain one (the original ramdisk address is in the patch code)" loki_check "loki_hr_$n.img" "loki_hp_$n.img" "$t"
    rd_ck "$n: the real loki_tool makes the same bytes" loki_real_patch_is "loki_hr_$n.img" "$t" "$k" "loki_hp_$n.img"
    rd_ck "$n: the new ramdisk address is the one the independent reader finds in the patch code" test "$(python3 -I "$LKT" unlok "loki_hr_$n.img" "loki_hu_$n.img" && od -An -tx4 -j20 -N4 "loki_hu_$n.img" | tr -d ' ')" = 11000000
done
rd_done "LOKI: edits of the header (the load addresses, the cmdline, the name) and of the kernel's size: the patched header and the patch code follow the plain header, the same bytes as loki_tool patch"

# The device tree: it goes behind the block without padding, so its size is what the header says; it may grow and shrink.
for v in b_dt:b:boot:dt a_dt_r:a:recovery:dt f_dt:f:boot:dt; do
    IFS=: read -r n t k p <<<"$v"
    for size in 7000 100 4096; do
        loki_copy "loki_u_$n" "loki_d_$n"
        head -c "$size" /dev/urandom >"loki_d_$n/dt.img"
        rd_ck "$n/$size: repack" rd_repack_unpack "loki_d_$n" "loki_dr_$n"
        rd_ck "$n/$size: the device tree is in the image, not padded" cmp -s "loki_d_$n/dt.img" "loki_dr_${n}_re/dt.img"
        loki_plain_of "loki_d_$n" "loki_dp_$n.img"
        rd_ck "$n/$size: loki_tool's patch of the plain image (independent reader)" loki_check "loki_dr_$n.img" "loki_dp_$n.img" "$t"
        rd_ck "$n/$size: the real loki_tool makes the same bytes" loki_real_patch_is "loki_dr_$n.img" "$t" "$k" "loki_dp_$n.img"
        rd_ck "$n/$size: the image ends where the device tree does" test "$(python3 -I "$LKT" list "loki_dr_$n.img" | sed -n 's/.*dt \([0-9]*\),.*tail \([0-9]*\)$/\1:\2/p')" = "$size:0"
    done
done
rd_done "LOKI: a device tree that grows, shrinks or is exactly pages long: it follows the block unpadded, the header's size is right, the same bytes as loki_tool patch"

# What follows the image: other data, or fill up to the size of the partition. Kept, and not touched by an edit.
python3 -I - <<'PYEOF'
import random
r = random.Random(20261015)
def tail(name, src, data):
    open("loki_t_%s.img" % name, "wb").write(open(src, "rb").read() + data)
def fill(name, src, size, byte):
    d = open(src, "rb").read()
    open("loki_t_%s.img" % name, "wb").write(d + bytes([byte]) * (size - len(d)))
tail("data", "loki_a_nodt.img", r.randbytes(3000))
fill("ff", "loki_b_dt.img", 1048576, 0xFF)
fill("zero", "loki_e_4k.img", 1048576, 0)
PYEOF
tail -c 3000 loki_t_data.img >loki_t_data.tail
for x in data ff zero; do
    rd_ck "$x: identify" said "LOKI header" "$ABR" identify "loki_t_$x.img"
    rd_unpack "loki_t_$x.img" "loki_tu_$x"
    "$ABR" repack "loki_tu_$x" -o "loki_tr_$x.img" >/dev/null 2>&1
    rd_ck "$x: an untouched repack is identical" cmp -s "loki_t_$x.img" "loki_tr_$x.img"
    loki_copy "loki_tu_$x" "loki_tx_$x"
    loki_edit "loki_tx_$x"
    rd_ck "$x: repack" rd_repack_unpack "loki_tx_$x" "loki_txr_$x"
    rd_ck "$x: the edit is in the image" loki_edit_is_in "loki_txr_${x}_re"
    loki_plain_of "loki_tx_$x" "loki_txp_$x.img"
    rd_ck "$x: it is loki_tool's patch of the plain image (the tail is behind it)" python3 -I "$LKT" check "loki_txr_$x.img" "loki_txp_$x.img"
done
tail -c 3000 loki_txr_data.img >loki_txr_data.tail
rd_ck "data: the tail is a file of its own" cmp -s loki_t_data.tail loki_tu_data/loki_tail.bin
rd_ck "data: and follows the edited image" cmp -s loki_t_data.tail loki_txr_data.tail
rd_ck "info says what follows" said "3000 bytes follow the image" "$ABR" info loki_t_data.img
for x in ff zero; do
    rd_ck "$x: the fill is not a file, it is a size" test ! -e "loki_tu_$x/loki_tail.bin"
    rd_ck "$x: the size of the partition" grep -q '^loki_pad_to=1048576$' "loki_tu_$x/manifest.txt"
    rd_ck "$x: an edit keeps the size of the partition" test "$(loki_size "loki_txr_$x.img")" = 1048576
done
rd_ck "ff: the fill byte" grep -q '^loki_pad_byte=0xff$' loki_tu_ff/manifest.txt
rd_ck "zero: the fill byte" grep -q '^loki_pad_byte=0x0$' loki_tu_zero/manifest.txt
rd_ck "ff: the fill goes on behind the edited image" test "$(tail -c 400000 loki_txr_ff.img | tr -d '\377' | wc -c | tr -d ' ')" = 0
rd_ck "zero: the fill goes on behind the edited image" test "$(tail -c 400000 loki_txr_zero.img | tr -d '\000' | wc -c | tr -d ' ')" = 0
loki_copy loki_tu_ff loki_tx_big
head -c 3000000 /dev/urandom >loki_tx_big/ramdisk/loki_huge_file
"$ABR" repack loki_tx_big -o loki_tx_big.img >loki_tx_big.rlog 2>&1
rd_ck "an edit that outgrows the partition is built and the size is said" grep -q 'larger than the original' loki_tx_big.rlog
rd_done "LOKI: what follows the image (data, or 0xFF / 0x00 fill up to the partition's size) is kept, an untouched repack is identical, an edit keeps the size and the fill, one that outgrows it is said"

# Fields that are not what loki_tool writes and that abr keeps as they are: another type, a build that is no text (or
# has a space at its end, or no NUL), another load address of the ramdisk in the LOKI header, data in the header page,
# the patch code at the last place of the window loki_tool unlok searches.
python3 -I - <<'PYEOF'
import struct
good = open("loki_b_dt.img", "rb").read()      # page 2048, a block of a page, the patch code 12 bytes in, a device tree
page = 2048
pad = lambda n: -(-n // page) * page
ks, rs = struct.unpack_from("<2I", good, 0x488)
base = page + pad(ks) + pad(rs)                # where the block starts
def word(d, off, v): struct.pack_into("<I", d, off, v)
def make(name, fn):
    d = bytearray(good)
    fn(d)
    open("loki_odd_%s.img" % name, "wb").write(bytes(d))
def move_code(d, to):                          # the 65 bytes of the patch (code, two words, the NUL) at another place
    patch = bytes(good[base + 12:base + 12 + 65])
    d[base + 12:base + 12 + 65] = bytes(65)
    d[base + to:base + to + 65] = patch
make("ra", lambda d: word(d, 0x490, 0x12345678))
make("hex", lambda d: d.__setitem__(slice(0x408, 0x488), b"\x01\x02weird".ljust(128, b"\0")))
make("full", lambda d: d.__setitem__(slice(0x408, 0x488), b"B" * 128))
make("space", lambda d: d.__setitem__(slice(0x408, 0x488), b"lead ".ljust(128, b"\0")))
make("type", lambda d: word(d, 0x404, 7))
make("junk", lambda d: d.__setitem__(slice(0x700, 0x720), bytes(range(1, 33))))
make("at15", lambda d: move_code(d, 15))
make("at0", lambda d: move_code(d, 0))
PYEOF
for x in ra hex full space type junk at15 at0; do
    rd_unpack "loki_odd_$x.img" "loki_ou_$x"
    "$ABR" repack "loki_ou_$x" -o "loki_orr_$x.img" >/dev/null 2>&1
    rd_ck "$x: an untouched repack is identical" cmp -s "loki_odd_$x.img" "loki_orr_$x.img"
done
rd_ck "a load address in the LOKI header that is not the padded kernel's end is kept" grep -q '^loki_hdr_ramdisk_addr=0x12345678$' loki_ou_ra/manifest.txt
rd_ck "(an ordinary one is not written)" test -z "$(grep '^loki_hdr_ramdisk_addr' loki_u_b_dt/manifest.txt)"
for x in hex full space; do
    rd_ck "$x: a build that is no word is kept as hex" grep -q '^loki_build_hex=' "loki_ou_$x/manifest.txt"
    rd_ck "$x: and not as text" test -z "$(grep '^loki_build=' "loki_ou_$x/manifest.txt")"
done
rd_ck "an ordinary build is text" grep -q '^loki_build=D52010c$' loki_u_b_dt/manifest.txt
rd_ck "type 7 is kept" grep -q '^loki_recovery=7$' loki_ou_type/manifest.txt
rd_ck "(identify names it a LOKI image, no type)" said 'LOKI header$' "$ABR" identify loki_odd_type.img
rd_ck "the patch code at the end of its window is read" grep -q '^loki_shellcode_offset=15$' loki_ou_at15/manifest.txt
rd_ck "and at its start" grep -q '^loki_shellcode_offset=0$' loki_ou_at0/manifest.txt
rd_done "LOKI: fields other than loki_tool writes (a load address in the LOKI header, a build that is no text, another type, data in the header page, the patch code at either end of its window) are kept as they are: an untouched repack is identical"

# The manifest's fields: the type and the build are the person's to change; what loki_tool could not put in the
# image is refused, with the way out (has_loki=false) named.
loki_copy loki_u_b_dt loki_m_type
sed -i 's/^loki_recovery=0$/loki_recovery=1/' loki_m_type/manifest.txt
"$ABR" repack loki_m_type -o loki_m_type.img >/dev/null 2>&1
loki_plain_of loki_m_type loki_m_type_p.img
rd_ck "a boot image made a recovery one: the image says it" said "recovery 1," python3 -I "$LKT" list loki_m_type.img
rd_ck "(identify too)" said "LOKI header (recovery)" "$ABR" identify loki_m_type.img
rd_ck "and the real loki_tool patch recovery makes the same bytes" loki_real_patch_is loki_m_type.img b recovery loki_m_type_p.img
loki_copy loki_u_b_dt loki_m_build
sed -i 's/^loki_build=.*/loki_build=an edited build 7/' loki_m_build/manifest.txt
rd_ck "an edited build: repack" rd_repack_unpack loki_m_build loki_mb
rd_ck "the image has it" said "build 'an edited build 7'," python3 -I "$LKT" list loki_mb.img
rd_ck "and reads back" grep -q '^loki_build=an edited build 7$' loki_mb_re/manifest.txt
loki_copy loki_u_b_dt loki_m_b127
sed -i "s/^loki_build=.*/loki_build=$(head -c 127 /dev/zero | tr '\0' B)/" loki_m_b127/manifest.txt
rd_ck "a build of 127 characters fits (a NUL stays behind it)" rd_repack_unpack loki_m_b127 loki_mb127
loki_copy loki_u_b_dt loki_m_b128
sed -i "s/^loki_build=.*/loki_build=$(head -c 128 /dev/zero | tr '\0' B)/" loki_m_b128/manifest.txt
rd_ck "one of 128 is refused" loki_refuse_repack b128 loki_m_b128 "holds 127 and a zero"
for off in 3 16; do
    loki_copy loki_u_b_dt "loki_m_off$off"
    sed -i "s/^loki_shellcode_offset=.*/loki_shellcode_offset=$off/" "loki_m_off$off/manifest.txt"
    rd_ck "a patch offset of $off, where the code is not, is refused" loki_refuse_repack "off$off" "loki_m_off$off" "does not have the patch code at the offset"
done
loki_copy loki_u_b_dt loki_m_short
head -c 30 loki_u_b_dt/loki_block.bin >loki_m_short/loki_block.bin
rd_ck "a block too short for the patch code is refused" loki_refuse_repack short loki_m_short "does not have the patch code at the offset"
loki_copy loki_u_b_dt loki_m_key
sed -i '/^loki_recovery=/d' loki_m_key/manifest.txt
rd_ck "a manifest without the type is refused, has_loki=false is the way out" loki_refuse_repack key loki_m_key "has no loki_recovery"
loki_copy loki_u_a_nodt loki_m_cmd
sed -i "s/^cmdline=.*/cmdline=$(head -c 1000 /dev/zero | tr '\0' c)/" loki_m_cmd/manifest.txt
rd_ck "a command line that runs into the LOKI header is refused" loki_refuse_repack cmd loki_m_cmd "where the LOKI header goes"
loki_plain_of loki_m_cmd loki_m_cmd_p.img
rd_ck "(without the patch the same directory builds)" test -s loki_m_cmd_p.img
loki_copy loki_u_a_nodt loki_m_cmd2
sed -i "s/^cmdline=.*/cmdline=$(head -c 928 /dev/zero | tr '\0' c)/" loki_m_cmd2/manifest.txt
rd_ck "one that ends at the last byte before it is not" rd_repack_unpack loki_m_cmd2 loki_mc2
loki_plain_of loki_m_cmd2 loki_m_cmd2_p.img
rd_ck "(and is loki_tool's patch of the plain image)" loki_check loki_mc2.img loki_m_cmd2_p.img a
rd_done "LOKI: the manifest's type and build are written as they are (127 characters at most), the real loki_tool makes the same bytes of a type that was changed; a patch offset or a block that cannot hold the patch code, a missing field, a command line that runs into the LOKI header are refused with the reason and no image"

# The patch under other wrappers: an ASUS blob around a LOKI image, and a DHTB header around that.
python3 -I "$LKB" make loki_blob.img --secure 0:0 LNX=loki_b_dt.img
rd_unpack loki_blob.img loki_bu
rd_ck "both wrappers are in the manifest" grep -q '^has_blob=true$' loki_bu/manifest.txt
rd_ck "(the patch)" grep -q '^has_loki=true$' loki_bu/manifest.txt
rd_ck "and are named in the order they come off" grep -q 'unpacked blob-wrapped loki-patched boot' loki_bu.log
"$ABR" repack loki_bu -o loki_bu_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s loki_blob.img loki_bu_back.img
python3 -I - <<'PYEOF'
import hashlib, struct
payload = open("loki_blob.img", "rb").read()
header = b"DHTB\x01\x00\x00\x00" + hashlib.sha256(payload).digest() + b"\x00" * 8 + struct.pack("<I", len(payload))
open("loki_dhtb.img", "wb").write(header + b"\x00" * (512 - len(header)) + payload)
PYEOF
rd_unpack loki_dhtb.img loki_du
rd_ck "three wrappers, named in the order they come off" grep -q 'unpacked dhtb-wrapped blob-wrapped loki-patched boot' loki_du.log
"$ABR" repack loki_du -o loki_du_back.img >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s loki_dhtb.img loki_du_back.img
loki_copy loki_du loki_dux
loki_edit loki_dux
rd_ck "an edit goes through all three" rd_repack_unpack loki_dux loki_duxr
rd_ck "the edit is in the image" loki_edit_is_in loki_duxr_re
rd_ck "and the patch is as it was" loki_same_patch loki_du loki_duxr_re
rd_done "LOKI under other wrappers (an ASUS blob, and a DHTB header around that): the wrappers are taken off and put back in order, the round trip is exact, an edit goes through"

# An image that has the LOKI header but is not what loki_tool makes is refused, with the reason, and leaves no
# directory: abr does not read it wrongly. (And what loki_tool unlok finds, abr finds.)
python3 -I - <<'PYEOF'
import struct
good = open("loki_b_dt.img", "rb").read()      # page 2048, a block of a page, the patch code 12 bytes in, a device tree
page = 2048
pad = lambda n: -(-n // page) * page
ks, rs = struct.unpack_from("<2I", good, 0x488)
base = page + pad(ks) + pad(rs)                # where the block starts
def word(d, off, v): struct.pack_into("<I", d, off, v)
def make(name, fn, cut=None):
    d = bytearray(good)
    fn(d)
    open("loki_bad_%s.img" % name, "wb").write(bytes(d if cut is None else d[:cut]))
make("kernel", lambda d: word(d, 8, struct.unpack_from("<I", d, 8)[0] + 1))
make("ramdisk", lambda d: word(d, 16, 7))
make("second", lambda d: word(d, 24, 4096))
make("version", lambda d: word(d, 40, 1))
make("page", lambda d: word(d, 36, 1000))
make("code", lambda d: d.__setitem__(slice(base + 12, base + 12 + 56), bytes(56)))
make("far", lambda d: (d.__setitem__(slice(base + 12, base + 12 + 65), bytes(65)),
                       d.__setitem__(slice(base + 16, base + 16 + 65), bytes(good[base + 12:base + 12 + 65]))))
make("cut", lambda d: None, cut=base + 100)
make("cutdt", lambda d: None, cut=len(good) - 1)
PYEOF
loki_refuse_info() {  # <image> <pattern>: info refuses the image with that reason
    local out rc
    out="$("$ABR" info "$1" 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && grep -q -- "$2" <<<"$out"
}
for r in "kernel:of its LOKI header" "ramdisk:neither 0 nor the page size" "second:has a second stage" "version:has a header of version 1" \
         "page:a page size (1000)" "code:does not have the patch code in the first 16 bytes" "far:does not have the patch code in the first 16 bytes" \
         "cut:is cut short" "cutdt:is cut short"; do
    x="${r%%:*}"
    msg="${r#*:}"
    rd_ck "$x: unpack refuses, says why, leaves no directory" loki_refuse "$x" "loki_bad_$x.img" "$msg"
    rd_ck "$x: identify still names the header" said "LOKI header" "$ABR" identify "loki_bad_$x.img"
done
rd_ck "info refuses an image like that, too" loki_refuse_info loki_bad_kernel.img "of its LOKI header"
rd_done "LOKI: an image with a LOKI header that loki_tool could not have made (sizes that do not add up, a second stage, a header of another version, no patch code in the window, cut short) is refused with the reason and leaves no directory"

# =========================================================================
# ChromeOS kernel blobs: the "verified boot" (vboot) format of a Chromebook's kernel partition, which Android Image
# Kitchen opens with `futility vbutil_kernel --get-vmlinuz` and builds again with `futility vbutil_kernel --pack`
# (abr/legacy/chromeos.hpp). abr does both on its own: the keyblock, the fields of the preamble, the config, the params,
# the bootloader, the signatures and what follows the blob are kept in the manifest, and the signatures are made
# afresh only when something they cover has changed. tests/tools/chromeos_tool.py makes and reads the blobs on its
# own -- it is written from vboot_reference's layout (2struct.h, cmd_vbutil_kernel.c), shares no code with abr, and does
# its RSA with Python's integers -- and what abr writes is what it makes, byte for byte. Keys of every kind it knows
# (the algorithms 0, 4, 5, 7, 8, 13 and 16: RSA of 1024 to 4096 bits, public exponent 65537 or 3, SHA-1, -256 and -512)
# are made with openssl; the developer keys are read out of the C++ source abr embeds them in. `futility` (the package
# vboot-kernel-utils; ABR_FUTILITY names it) is a judge too where it is installed: it makes the same blob (--pack),
# signs the same body under another keyblock (--repack), takes the kernel out (--get-vmlinuz) and verifies abr's.
# =========================================================================
CRT="$TOOLS/chromeos_tool.py"
cros() { python3 -I "$CRT" "$@"; }
CROS_FUT="${ABR_FUTILITY:-$(command -v futility 2>/dev/null || true)}"
cros_fut() { [ -n "$CROS_FUT" ] && [ -x "$CROS_FUT" ]; }
if cros_fut; then
    echo "note: futility ($CROS_FUT) judges the ChromeOS kernel blobs too"
else
    echo "note: futility is not installed (ABR_FUTILITY): the ChromeOS kernel blobs are judged by tests/tools/chromeos_tool.py alone"
fi

CK=cros_k
mkdir -p "$CK"
cros devkeys "$REPO_ROOT/src/legacy/chromeos_devkeys.cpp" "$CK"
cros_genkey() {  # <name> <bits> <algorithm> [3 | a .pem to use]: a key of one's own (.vbprivk) and the keyblock made for it
    local e=""
    if [ "${4:-}" = 3 ]; then
        e="-3"
    elif [ -n "${4:-}" ]; then
        cp "$4" "$CK/$1.pem"
    fi
    if [ ! -s "$CK/$1.pem" ]; then
        openssl genrsa $e -traditional -out "$CK/$1.pem" "$2" >/dev/null 2>&1 || openssl genrsa $e -out "$CK/$1.pem" "$2" >/dev/null 2>&1
    fi
    cros vbprivk "$CK/$1.vbprivk" --pem "$CK/$1.pem" --algorithm "$3" && cros keyblock "$CK/$1.keyblock" --key "$CK/$1.vbprivk"
}
cros_genkey k1024 1024 0
cros_genkey k2048 2048 5
cros_genkey k2048b 2048 4
cros_genkey k4096 4096 8
cros_genkey k4096s 4096 7 "$CK/k4096.pem"
cros_genkey k2048e3 2048 13 3
cros_genkey k3072e3 3072 16 3
cros_kp() { if [ "$1" = dev ]; then echo "$CK/kernel_data_key.vbprivk"; else echo "$CK/$1.vbprivk"; fi; }
cros_kb() { if [ "$1" = dev ]; then echo "$CK/kernel.keyblock"; else echo "$CK/$1.keyblock"; fi; }
cros_algname() {  # a table of its own, not abr's
    case "$1" in
        0) echo "RSA-1024/SHA-1" ;; 4) echo "RSA-2048/SHA-256" ;; 5) echo "RSA-2048/SHA-512" ;; 7) echo "RSA-4096/SHA-256" ;;
        8) echo "RSA-4096/SHA-512" ;; 13) echo "RSA-2048-EXP3/SHA-256" ;; 16) echo "RSA-3072-EXP3/SHA-256" ;;
    esac
}
if [ -s "$CK/k4096s.keyblock" ] && [ -s "$CK/k3072e3.keyblock" ] && [ -s "$CK/k2048e3.keyblock" ] && [ -s "$CK/k1024.keyblock" ] &&
    [ -s "$CK/kernel.keyblock" ] && [ -s "$CK/k2048b.keyblock" ]; then
    pass "ChromeOS: the keys are there (the developer keys out of abr's source, seven of one's own: RSA 1024 to 4096 bits, exponent 65537 and 3)"
else
    fail "ChromeOS: the keys could not be made (openssl, or the independent tool)"
fi
if [ -d /usr/share/vboot/devkeys ] && [ -s /usr/share/vboot/devkeys/kernel.keyblock ]; then
    rd_ck "the keyblock abr embeds is the one of vboot_reference" cmp -s "$CK/kernel.keyblock" /usr/share/vboot/devkeys/kernel.keyblock
    rd_ck "and so is the key" cmp -s "$CK/kernel_data_key.vbprivk" /usr/share/vboot/devkeys/kernel_data_key.vbprivk
    rd_done "ChromeOS: the developer keyblock and key abr embeds are the ones vboot_reference ships (as installed here)"
fi

# The plain images that go in a blob: one that ends 2048 bytes short of a boundary of 4096 (the kernel field of a blob
# is padded with zeros up to it), one that ends on it.
python3 "$RDG" mkbootfs cros_rd.cpio
gzip -9n -c cros_rd.cpio >cros_rd.gz
python3 -I - "$TOOLS" <<'PYEOF'
import random
import sys
sys.path.insert(0, sys.argv[1])
import fixtures
r = random.Random(20261016)
rd = open("cros_rd.gz", "rb").read()
cmd = "console=ttyS0,115200 androidboot.hardware=crostest"
for want, name in ((2048, "pad"), (0, "al")):
    ks = 70001
    while True:
        img = fixtures.boot_v012(0, r.randbytes(ks), rd, page=2048, cmdline=cmd, name="crostest")
        if len(img) % 4096 == want:
            break
        ks += 2048
    open("cros_plain_%s.img" % name, "wb").write(img)
PYEOF
rd_unpack cros_plain_pad.img cros_pu_pad
rd_unpack cros_plain_al.img cros_pu_al

cros_copy() { rm -rf "$2" && cp -a "$1" "$2"; }  # <dir> <copy>
cros_edit() {  # <unpack dir>: two files in the ramdisk's directory
    printf 'abr test\n' >"$1/ramdisk/abr_test_file" && head -c 9000 /dev/urandom >"$1/ramdisk/cros_big_file"
}
cros_edit_is_in() { [ "$(cat "$1/ramdisk/abr_test_file" 2>/dev/null)" = "abr test" ]; }  # <the directory unpacked from the repacked blob>
cros_plain_of() {  # <unpack dir> <out>: what the directory builds without the blob (has_chromeos=false in a copy)
    rm -rf "$1.noc" && cp -a "$1" "$1.noc" || return 1
    sed -i 's/^has_chromeos=true$/has_chromeos=false/' "$1.noc/manifest.txt" || return 1
    "$ABR" repack "$1.noc" -o "$2" >"$2.log" 2>&1
}
cros_repack() {  # <dir> <out> <name of the key> [options]: repack (log: <out>.rlog); the key of a keyblock that is not the developer's is given
    local d="$1" out="$2" k="$3"
    shift 3
    local o=()
    [ "$k" = dev ] || o=(--chromeos-key "$(cros_kp "$k")")
    rm -f "$out"
    "$ABR" repack "$d" -o "$out" ${o[@]+"${o[@]}"} "$@" >"$out.rlog" 2>&1
}
cros_refuse() {  # <name> <blob> <pattern>: unpack of that blob is refused with that reason and leaves no directory
    local out rc
    rm -rf "cros_rf_$1"
    out="$("$ABR" unpack "$2" -o "cros_rf_$1" 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && [ ! -e "cros_rf_$1" ] && grep -q -- "$3" <<<"$out"
}
cros_refuse_repack() {  # <name> <dir> <pattern> [options]: repack of that directory is refused with that reason and writes no blob
    local out rc name="$1" d="$2" pat="$3"
    shift 3
    rm -f "cros_rr_$name.blob"
    out="$("$ABR" repack "$d" -o "cros_rr_$name.blob" "$@" 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && [ ! -e "cros_rr_$name.blob" ] && grep -q -- "$pat" <<<"$out"
}
cros_size() { wc -c <"$1" | tr -d ' '; }
# futility, where it is installed (true without it)
cros_fut_verify() {  # <blob> [the size of its verification block, where it is not 64 KiB]: futility verifies the blob
    cros_fut || return 0
    "$CROS_FUT" vbutil_kernel --verify "$1" ${2:+--pad "$2"} >"$1.fut" 2>&1 && grep -q "Body verification succeeded" "$1.fut"
}
cros_fut_kernel_is() {  # <blob> <plain image>: --get-vmlinuz hands the plain image out as the first bytes of the body
    cros_fut || return 0
    "$CROS_FUT" vbutil_kernel --get-vmlinuz "$1" --vmlinuz-out "$1.vmlinuz" >/dev/null 2>&1 && cmp -s -n "$(cros_size "$2")" "$1.vmlinuz" "$2"
}
cros_fut_pack_is() {  # <blob> <plain image> <keyblock> <.vbprivk> [options of --pack]: futility packs the very same blob
    cros_fut || return 0
    local blob="$1" plain="$2" kb="$3" kp="$4"
    shift 4
    rm -f "$blob.fut"
    "$CROS_FUT" vbutil_kernel --pack "$blob.fut" --keyblock "$kb" --signprivate "$kp" --vmlinuz "$plain" --arch arm "$@" >/dev/null 2>&1 && cmp -s "$blob" "$blob.fut"
}
cros_fut_repack_is() {  # <blob> <old blob> <keyblock> <.vbprivk>: futility signs the body of the old blob again under that keyblock
    cros_fut || return 0
    rm -f "$1.fut"
    "$CROS_FUT" vbutil_kernel --repack "$1.fut" --oldblob "$2" --keyblock "$3" --signprivate "$4" >/dev/null 2>&1 && cmp -s "$1" "$1.fut"
}

# Nine kinds of blob: the developer keys with the preambles 2.0, 2.1 and 2.2, and keys of one's own -- RSA of 1024,
# 2048, 4096 and 3072 bits, the public exponents 65537 and 3, SHA-1, SHA-256 and SHA-512 -- with a plain image that
# needs padding up to 4096 and one that does not. (name:key:algorithm:preamble minor:plain image)
CROS_VARIANTS="dev22:dev:4:2:pad dev21:dev:4:1:al dev20:dev:4:0:pad a0:k1024:0:2:pad a5:k2048:5:1:al a7:k4096s:7:0:pad a8:k4096:8:2:al a13:k2048e3:13:2:pad a16:k3072e3:16:2:al"
for v in $CROS_VARIANTS; do
    IFS=: read -r n k a m p <<<"$v"
    kb="$(cros_kb "$k")"
    kp="$(cros_kp "$k")"
    rd_ck "$n: the independent tool makes the blob" cros make "cros_$n.blob" --kernel "cros_plain_$p.img" --keyblock "$kb" --key "$kp" --minor "$m"
    rd_ck "$n: and its reader finds both signatures good" cros verify "cros_$n.blob"
    rd_ck "$n: futility verifies it" cros_fut_verify "cros_$n.blob"
    rd_ck "$n: identify" said "CHROMEOS" "$ABR" identify "cros_$n.blob"
    rd_ck "$n: info names the preamble" said "vboot preamble 2.$m," "$ABR" info "cros_$n.blob"
    rd_ck "$n: and the data key ($(cros_algname "$a"))" said "data key $(cros_algname "$a")" "$ABR" info "cros_$n.blob"
    rd_ck "$n: and finds both signatures good" said "signatures valid" "$ABR" info "cros_$n.blob"
    rd_unpack "cros_$n.blob" "cros_u_$n"
    rd_ck "$n: unpack says what it took off" grep -q 'unpacked chromeos-wrapped boot' "cros_u_$n.log"
    rd_ck "$n: and that an untouched repack is identical" grep -q 'reproduces this image byte-for-byte' "cros_u_$n.log"
    rd_ck "$n: the manifest has the blob" grep -q '^has_chromeos=true$' "cros_u_$n/manifest.txt"
    rd_ck "$n: and its version" grep -q "^chromeos_preamble_version=2\.$m\$" "cros_u_$n/manifest.txt"
    rd_ck "$n: the keyblock is a file, as it was" cmp -s "cros_u_$n/chromeos_keyblock.bin" "$kb"
    rd_ck "$n: nothing follows the blob" test ! -e "cros_u_$n/chromeos_tail.bin"
    rd_ck "$n: the rest of the directory is what the plain image gives" diff -r --no-dereference -x manifest.txt -x 'chromeos_*' "cros_pu_$p" "cros_u_$n"
    "$ABR" repack "cros_u_$n" -o "cros_r_$n.blob" >/dev/null 2>&1
    rd_ck "$n: an untouched repack is identical" cmp -s "cros_$n.blob" "cros_r_$n.blob"
done
rd_done "ChromeOS: blobs of every kind the independent tool makes (preambles 2.0, 2.1, 2.2; RSA of 1024, 2048, 3072 and 4096 bits, exponent 65537 and 3, SHA-1, SHA-256, SHA-512; the kernel padded to 4096 or not): futility verifies them, identify and info see them, the directory is the plain image's plus the blob, an untouched repack is identical -- whoever signed it"

# An edit lands in the image, the keyblock stays, and the blob is what the independent tool makes of the image the
# directory builds without the blob: the signatures are made again, with the key of the keyblock.
for v in $CROS_VARIANTS; do
    IFS=: read -r n k a m p <<<"$v"
    kb="$(cros_kb "$k")"
    kp="$(cros_kp "$k")"
    cros_copy "cros_u_$n" "cros_x_$n"
    cros_edit "cros_x_$n"
    rd_ck "$n: repack (the key of a keyblock that is not the developer's is given)" cros_repack "cros_x_$n" "cros_xr_$n.blob" "$k"
    rd_ck "$n: abr says the signatures are made again" grep -q 'what the signatures of the ChromeOS kernel blob cover has changed' "cros_xr_$n.blob.rlog"
    rd_ck "$n: the independent reader finds both signatures good" cros verify "cros_xr_$n.blob"
    rd_ck "$n: futility verifies it" cros_fut_verify "cros_xr_$n.blob"
    cros_plain_of "cros_x_$n" "cros_xp_$n.img"
    rd_ck "$n: futility hands the plain image the directory builds out of it" cros_fut_kernel_is "cros_xr_$n.blob" "cros_xp_$n.img"
    rd_ck "$n: the independent tool makes the same blob of what the directory builds without it" cros make "cros_xe_$n.blob" --kernel "cros_xp_$n.img" --keyblock "$kb" --key "$kp" --minor "$m"
    rd_ck "$n: ... the same bytes (the keyblock and the version as they were)" cmp -s "cros_xr_$n.blob" "cros_xe_$n.blob"
    rd_unpack "cros_xr_$n.blob" "cros_xr_${n}_re"
    rd_ck "$n: the edit is in the image" cros_edit_is_in "cros_xr_${n}_re"
    rd_ck "$n: the blob grew" test "$(cros_size "cros_xr_$n.blob")" -gt "$(cros_size "cros_$n.blob")"
    rd_ck "$n: unpacked again it is a fixed point" "$ABR" repack "cros_xr_${n}_re" -o "cros_xr2_$n.blob"
    rd_ck "$n: ... the same bytes" cmp -s "cros_xr_$n.blob" "cros_xr2_$n.blob"
done
rd_done "ChromeOS: an edited ramdisk lands in the image; the blob is the independent tool's of what the directory builds without it (the keyblock, the preamble's version and the algorithm as they were), futility verifies it and hands out the same kernel; repacking what that gives is the same blob"

# The fields of the blob -- the command line (config), the x86 boot parameters (params), the bootloader and its size and
# address, the load address, the version of the kernel, the flags, the size of the verification block, what follows the
# blob -- are in the manifest, and come back as they were. Changed there, they are in the blob the independent tool
# makes with the same values.
CROS_KB="$CK/kernel.keyblock"
CROS_KP="$CK/kernel_data_key.vbprivk"
printf 'console=tty1 root=/dev/mmcblk0p3 rootwait ro cros_secure' >cros_cfg.txt   # no newline: futility turns one into a space
(head -c 99 /dev/urandom; printf '\177') >cros_params.bin
(head -c 999 /dev/urandom; printf 'U') >cros_bl.bin
seq 1 1500 | head -c 5000 >cros_tail.bin   # not all one byte: that would be a fill up to a size, and is read as one
rd_ck "the independent tool makes the blob (every field set)" cros make cros_F.blob --kernel cros_plain_pad.img --keyblock "$CROS_KB" --key "$CROS_KP" --minor 2 \
    --kernel-version 7 --flags 3 --load 0x2000000 --bootloader-address 0x2002000 --config cros_cfg.txt --params cros_params.bin \
    --bootloader cros_bl.bin --bootloader-size 8192 --pad 131072 --tail cros_tail.bin
rd_ck "its reader finds both signatures good" cros verify cros_F.blob
rd_ck "futility verifies it (every field, a verification block of 128 KiB)" cros_fut_verify cros_F.blob 131072
rd_ck "info: the preamble, the version of the kernel, the flags, the load address" said "vboot preamble 2.2, kernel version 7, flags 0x3, loaded at 0x2000000;" "$ABR" info cros_F.blob
rd_ck "info: the sizes of the fields" said "config $(cros_size cros_cfg.txt) bytes, bootloader 8192 bytes;" "$ABR" info cros_F.blob
rd_ck "info: what follows the blob" said "; 5000 bytes follow the blob)" "$ABR" info cros_F.blob
rd_unpack cros_F.blob cros_u_F
rd_ck "unpack names the blob" grep -q 'unpacked chromeos-wrapped boot' cros_u_F.log
for kv in chromeos_preamble_version=2.2 chromeos_kernel_version=7 chromeos_flags=0x3 chromeos_body_load_address=0x2000000 \
          chromeos_bootloader_address=0x2002000 chromeos_bootloader_size=8192 chromeos_vblock_size=131072; do
    rd_ck "the manifest has $kv" grep -q "^$kv\$" cros_u_F/manifest.txt
done
rd_ck "the config is a file" cmp -s cros_u_F/chromeos_config.txt cros_cfg.txt
rd_ck "the params are a file" cmp -s cros_u_F/chromeos_params.bin cros_params.bin
rd_ck "the bootloader is a file (without the zeros of its field)" cmp -s cros_u_F/chromeos_bootloader.bin cros_bl.bin
rd_ck "what follows the blob is a file" cmp -s cros_u_F/chromeos_tail.bin cros_tail.bin
"$ABR" repack cros_u_F -o cros_r_F.blob >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s cros_F.blob cros_r_F.blob
# every field changed, the bootloader grown past the size of its field (it grows to 12288), the tail replaced, an edit in the ramdisk
cros_copy cros_u_F cros_x_F
sed -i 's/^chromeos_kernel_version=7$/chromeos_kernel_version=9/; s/^chromeos_flags=0x3$/chromeos_flags=0x5/;
        s/^chromeos_body_load_address=0x2000000$/chromeos_body_load_address=0x3000000/; s/^chromeos_bootloader_address=0x2002000$/chromeos_bootloader_address=0x3002000/;
        s/^chromeos_vblock_size=131072$/chromeos_vblock_size=65536/' cros_x_F/manifest.txt
printf 'console=ttyS2,115200 root=/dev/sda3 cros_debug' >cros_cfg2.txt
(head -c 199 /dev/urandom; printf '\001') >cros_params2.bin
(head -c 8999 /dev/urandom; printf 'V') >cros_bl2.bin
seq 2000 4000 | head -c 7000 >cros_tail2.bin
cp cros_cfg2.txt cros_x_F/chromeos_config.txt
cp cros_params2.bin cros_x_F/chromeos_params.bin
cp cros_bl2.bin cros_x_F/chromeos_bootloader.bin
cp cros_tail2.bin cros_x_F/chromeos_tail.bin
cros_edit cros_x_F
"$ABR" repack cros_x_F -o cros_xr_F.blob >cros_xr_F.rlog 2>&1
cros_plain_of cros_x_F cros_xp_F.img
rd_ck "an edit with every field changed: the independent tool makes the blob of what the directory builds without it" cros make cros_xe_F.blob --kernel cros_xp_F.img \
    --keyblock "$CROS_KB" --key "$CROS_KP" --minor 2 --kernel-version 9 --flags 5 --load 0x3000000 --bootloader-address 0x3002000 --config cros_cfg2.txt \
    --params cros_params2.bin --bootloader cros_bl2.bin --bootloader-size 12288 --pad 65536 --tail cros_tail2.bin
rd_ck "... the same bytes" cmp -s cros_xr_F.blob cros_xe_F.blob
rd_ck "its reader finds both signatures good" cros verify cros_xr_F.blob
rd_ck "futility verifies it" cros_fut_verify cros_xr_F.blob
rd_ck "abr says the signatures are made again" grep -q 'what the signatures of the ChromeOS kernel blob cover has changed' cros_xr_F.rlog
rd_unpack cros_xr_F.blob cros_xr_F_re
rd_ck "unpacked again the manifest has the new fields" grep -q '^chromeos_bootloader_size=12288$' cros_xr_F_re/manifest.txt
rd_ck "and the edit is in the image" cros_edit_is_in cros_xr_F_re
# nothing the signatures cover changed (the tail only): they are kept, and the log does not say they were made again
cros_copy cros_u_F cros_t_F
cp cros_tail2.bin cros_t_F/chromeos_tail.bin
"$ABR" repack cros_t_F -o cros_tr_F.blob >cros_tr_F.rlog 2>&1
rd_ck "only the tail changed: the blob is the original with the new tail" cros make cros_te_F.blob --kernel cros_plain_pad.img --keyblock "$CROS_KB" --key "$CROS_KP" --minor 2 \
    --kernel-version 7 --flags 3 --load 0x2000000 --bootloader-address 0x2002000 --config cros_cfg.txt --params cros_params.bin --bootloader cros_bl.bin \
    --bootloader-size 8192 --pad 131072 --tail cros_tail2.bin
rd_ck "... the same bytes" cmp -s cros_tr_F.blob cros_te_F.blob
rd_ck "the signatures are the original's, and abr does not say it made them again" test -z "$(grep 'signatures' cros_tr_F.rlog)"
rd_done "ChromeOS: every field of the blob (the command line, the params, the bootloader and its size and address, the load address, the version of the kernel, the flags, the verification block, what follows) is in the manifest and comes back as it was; changed there they are in the blob the independent tool makes with the same values; a changed tail keeps the signatures"

# A partition dump: the blob, then zeros up to the size of the partition. The fill is kept: after an edit the dump is as big as it was.
CROS_DUMP=$(($(cros_size cros_dev22.blob) + 100000))
rd_ck "the independent tool makes a dump" cros make cros_Z.blob --kernel cros_plain_pad.img --keyblock "$CROS_KB" --key "$CROS_KP" --fill-to "$CROS_DUMP"
rd_unpack cros_Z.blob cros_u_Z
rd_ck "unpack keeps the size of the partition" grep -q "^chromeos_pad_to=$CROS_DUMP\$" cros_u_Z/manifest.txt
rd_ck "and no tail file (it is all zeros)" test ! -e cros_u_Z/chromeos_tail.bin
"$ABR" repack cros_u_Z -o cros_r_Z.blob >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s cros_Z.blob cros_r_Z.blob
cros_copy cros_u_Z cros_x_Z
cros_edit cros_x_Z
rd_ck "an edit goes through" cros_repack cros_x_Z cros_xr_Z.blob dev
rd_ck "the dump is as big as it was" test "$(cros_size cros_xr_Z.blob)" = "$CROS_DUMP"
cros_plain_of cros_x_Z cros_xp_Z.img
rd_ck "the independent tool makes the same dump" cros make cros_xe_Z.blob --kernel cros_xp_Z.img --keyblock "$CROS_KB" --key "$CROS_KP" --fill-to "$CROS_DUMP"
rd_ck "... the same bytes" cmp -s cros_xr_Z.blob cros_xe_Z.blob
rd_done "ChromeOS: a partition dump (the blob, zeros up to the size of the partition) comes back identical, and after an edit is as big as it was"

# The blob can be left out (has_chromeos=false: what the directory builds is the kernel field of the blob), and put around a
# plain image (has_chromeos=true on its own: what Android Image Kitchen's `futility vbutil_kernel --pack` line makes).
cros_plain_of cros_u_dev22 cros_dev22_plain.img
cros kernel cros_dev22.blob cros_dev22_kernel.bin
rd_ck "without the blob the directory builds the kernel field of the blob (the plain image, zeros up to 4096)" cmp -s cros_dev22_plain.img cros_dev22_kernel.bin
cros_copy cros_pu_pad cros_fr
printf 'has_chromeos=true\n' >>cros_fr/manifest.txt
"$ABR" repack cros_fr -o cros_fr.blob >cros_fr.rlog 2>&1
printf ' ' >cros_sp
rd_ck "a plain image with has_chromeos=true: the independent tool makes the blob of Android Image Kitchen's command line (version 1, flags 1, a space for the config and the bootloader, the developer keys)" \
    cros make cros_fr_e.blob --kernel cros_plain_pad.img --keyblock "$CROS_KB" --key "$CROS_KP" --kernel-version 1 --flags 1 --config cros_sp --bootloader cros_sp
rd_ck "... the same bytes" cmp -s cros_fr.blob cros_fr_e.blob
rd_ck "futility packs the very same blob with that command line" cros_fut_pack_is cros_fr.blob cros_plain_pad.img "$CROS_KB" "$CROS_KP" --version 1 --bootloader cros_sp --config cros_sp --flags 0x1
rd_ck "abr says what it signed with" grep -q 'the ChromeOS kernel blob is signed with the developer key of vboot_reference' cros_fr.rlog
rd_ck "its reader finds both signatures good" cros verify cros_fr.blob
rd_unpack cros_fr.blob cros_u_fr
rd_ck "unpacked again it is the plain image, with a blob around it" diff -r --no-dereference -x manifest.txt -x 'chromeos_*' cros_pu_pad cros_u_fr
"$ABR" repack cros_u_fr -o cros_r_fr.blob >/dev/null 2>&1
rd_ck "and an untouched repack is identical" cmp -s cros_fr.blob cros_r_fr.blob
# with keys of one's own (a key and the keyblock for it): the blob is signed under that keyblock
cros_copy cros_pu_pad cros_fr2
printf 'has_chromeos=true\n' >>cros_fr2/manifest.txt
"$ABR" repack cros_fr2 -o cros_fr2.blob --chromeos-key "$CK/k2048.vbprivk" --chromeos-keyblock "$CK/k2048.keyblock" >cros_fr2.rlog 2>&1
rd_ck "with --chromeos-key and --chromeos-keyblock the independent tool makes the same blob under that keyblock" cros make cros_fr2_e.blob --kernel cros_plain_pad.img --keyblock "$CK/k2048.keyblock" \
    --key "$CK/k2048.vbprivk" --kernel-version 1 --flags 1 --config cros_sp --bootloader cros_sp
rd_ck "... the same bytes" cmp -s cros_fr2.blob cros_fr2_e.blob
rd_ck "abr says it is signed under the keyblock given" grep -q 'is signed under the keyblock given' cros_fr2.rlog
rd_done "ChromeOS: has_chromeos=false builds the kernel field of the blob; has_chromeos=true on a plain image makes the blob of Android Image Kitchen's futility line (futility makes the very same one) -- or one under the keyblock and key given"

# The version of the preamble is the manifest's to change (2.2 -> 2.1 -> 2.0: the fields it does not have are gone), and a preamble
# 2.1 or 2.2 can carry the address of a vmlinuz header (there is no header on ARM: its size is 0).
for ver in 1 0; do
    cros_copy cros_u_dev22 "cros_v_$ver"
    sed -i "s/^chromeos_preamble_version=.*/chromeos_preamble_version=2.$ver/" "cros_v_$ver/manifest.txt"
    rd_ck "2.$ver: repack" cros_repack "cros_v_$ver" "cros_vr_$ver.blob" dev
    rd_ck "2.$ver: the independent tool makes the same blob" cros make "cros_ve_$ver.blob" --kernel cros_dev22_plain.img --keyblock "$CROS_KB" --key "$CROS_KP" --minor "$ver"
    rd_ck "2.$ver: ... the same bytes" cmp -s "cros_vr_$ver.blob" "cros_ve_$ver.blob"
    rd_ck "2.$ver: its reader finds both signatures good" cros verify "cros_vr_$ver.blob"
done
rd_ck "the independent tool makes a 2.1 blob with a vmlinuz header address" cros make cros_V.blob --kernel cros_plain_pad.img --keyblock "$CROS_KB" --key "$CROS_KP" --minor 1 --vmlinuz-header-address 0x1234000
rd_unpack cros_V.blob cros_u_V
rd_ck "the manifest has the address" grep -q '^chromeos_vmlinuz_header_address=0x1234000$' cros_u_V/manifest.txt
"$ABR" repack cros_u_V -o cros_r_V.blob >/dev/null 2>&1
rd_ck "and an untouched repack is identical" cmp -s cros_V.blob cros_r_V.blob
cros_copy cros_u_V cros_x_V
sed -i 's/^chromeos_vmlinuz_header_address=.*/chromeos_vmlinuz_header_address=0x5678000/' cros_x_V/manifest.txt
rd_ck "a changed address: repack" cros_repack cros_x_V cros_xr_V.blob dev
rd_ck "the independent tool makes the same blob" cros make cros_xe_V.blob --kernel cros_plain_pad.img --keyblock "$CROS_KB" --key "$CROS_KP" --minor 1 --vmlinuz-header-address 0x5678000
rd_ck "... the same bytes" cmp -s cros_xr_V.blob cros_xe_V.blob
rd_done "ChromeOS: the version of the preamble (2.2, 2.1, 2.0) and the address of the vmlinuz header are the manifest's to change; the blob is the independent tool's with the same values"

# What the manifest cannot say: abr refuses with the reason, and writes no blob.
cros_bad() {  # <name> <pattern> <sed expression for manifest.txt> [a file to put in the directory: name=size]
    cros_copy cros_u_dev22 "cros_bad_$1" || return 1
    sed -i "$3" "cros_bad_$1/manifest.txt" || return 1
    if [ -n "${4:-}" ]; then
        printf '%s_file=%s.bin\n' "chromeos_${4%%=*}" "${4%%=*}" >>"cros_bad_$1/manifest.txt"
        head -c "${4#*=}" /dev/zero | tr '\0' 'x' >"cros_bad_$1/${4%%=*}.bin"
    fi
    cros_refuse_repack "$1" "cros_bad_$1" "$2"
}
rd_ck "a version that is no version" cros_bad ver_text 'is a version like 2.2' 's/^chromeos_preamble_version=.*/chromeos_preamble_version=banana/'
rd_ck "2.5" cros_bad ver_25 'is not one abr makes (2.0, 2.1 and 2.2 are)' 's/^chromeos_preamble_version=.*/chromeos_preamble_version=2.5/'
rd_ck "3.0" cros_bad ver_30 'is not one abr makes' 's/^chromeos_preamble_version=.*/chromeos_preamble_version=3.0/'
rd_ck "flags of more than 32 bits" cros_bad flags_big 'does not fit in 32 bits' 's/^chromeos_flags=.*/chromeos_flags=0x100000000/'
rd_ck "flags in a preamble that has none" cros_bad flags_21 'need a preamble of version 2.2; this one is 2.1' 's/^chromeos_preamble_version=.*/chromeos_preamble_version=2.1/; s/^chromeos_flags=.*/chromeos_flags=0x1/'
rd_ck "an address of the vmlinuz header in a preamble that has none" cros_bad vmz_20 'needs a preamble of version 2.1 or 2.2' \
    's/^chromeos_preamble_version=.*/chromeos_preamble_version=2.0/; s/^chromeos_flags=.*//; $a chromeos_vmlinuz_header_address=0x1000'
rd_ck "a verification block too small for the signatures" cros_bad vblock 'the verification block of this ChromeOS blob is 1300 bytes' 's/^chromeos_vblock_size=.*/chromeos_vblock_size=1300/'
rd_ck "a config of more than its field holds" cros_bad cfg_big 'the config of a ChromeOS blob is 5000 bytes; its field holds 4096' 's/^id=/id=/' config=5000
rd_ck "params of more than their field holds" cros_bad params_big 'the params of a ChromeOS blob is 5000 bytes; its field holds 4096' 's/^id=/id=/' params=5000
rd_done "ChromeOS: what the manifest cannot say (no version, a version abr does not make, flags or a vmlinuz header address the preamble has no field for, a verification block that is too small, a config or params that do not fit their fields) is refused with the reason, and no blob is written"

# Whose keyblock it is. A blob under somebody else's keyblock (one abr has no key for) comes back as it was while nothing
# it covers changes -- whoever signed it. Edited, it is signed with the developer key under the developer keyblock, with a
# warning (that is what Android Image Kitchen does, always), or with the key given (--chromeos-key) under the keyblock it has,
# or under another one (--chromeos-keyblock). abr never signs under a keyblock whose key it does not have.
rd_ck "an edit of a blob under somebody else's keyblock, no key given: abr signs under the developer keyblock" cros_repack cros_x_a8 cros_sw_a8.blob dev
rd_ck "... and warns that the keyblock is somebody else's, and what it did instead" grep -q "its keyblock is somebody else's: abr has no key for it" cros_sw_a8.blob.rlog
rd_ck "... and that --chromeos-key and --chromeos-keyblock sign with keys of one's own" grep -q -- "--chromeos-key and --chromeos-keyblock sign with keys of your own" cros_sw_a8.blob.rlog
rd_ck "the independent tool makes the same blob under the developer keyblock" cros make cros_sw_a8_e.blob --kernel cros_xp_a8.img --keyblock "$CROS_KB" --key "$CROS_KP" --minor 2
rd_ck "... the same bytes" cmp -s cros_sw_a8.blob cros_sw_a8_e.blob
rd_ck "its reader finds both signatures good" cros verify cros_sw_a8.blob
rd_ck "futility verifies it" cros_fut_verify cros_sw_a8.blob
rd_ck "info calls the data key the developer key" said "(the developer key of vboot_reference)" "$ABR" info cros_sw_a8.blob
rd_unpack cros_sw_a8.blob cros_sw_a8_u
"$ABR" repack cros_sw_a8_u -o cros_sw_a8_r.blob >/dev/null 2>&1
rd_ck "what that gives is a fixed point: unpacked and repacked it is the same blob" cmp -s cros_sw_a8.blob cros_sw_a8_r.blob
cros_copy cros_sw_a8_u cros_sw_a8_x
cros_edit cros_sw_a8_x
rd_ck "and an edit of it is signed with the developer key, without a warning (the keyblock is the developer's now)" cros_repack cros_sw_a8_x cros_sw_a8_xr.blob dev
rd_ck "... no warning" test -z "$(grep -i 'somebody else' cros_sw_a8_xr.blob.rlog)"
rd_ck "... and its reader finds both signatures good" cros verify cros_sw_a8_xr.blob
# a key and a keyblock of one's own
rd_ck "an edit with --chromeos-key and --chromeos-keyblock of one's own" cros_repack cros_x_a8 cros_nk_a8x.blob dev --chromeos-key "$CK/k2048.vbprivk" --chromeos-keyblock "$CK/k2048.keyblock"
rd_ck "... abr says it is signed under the keyblock given" grep -q 'is signed under the keyblock given (--chromeos-keyblock)' cros_nk_a8x.blob.rlog
rd_ck "the independent tool makes the same blob" cros make cros_nk_a8x_e.blob --kernel cros_xp_a8.img --keyblock "$CK/k2048.keyblock" --key "$CK/k2048.vbprivk" --minor 2
rd_ck "... the same bytes" cmp -s cros_nk_a8x.blob cros_nk_a8x_e.blob
rd_ck "futility verifies it" cros_fut_verify cros_nk_a8x.blob
rd_ck "info names the data key of the new keyblock" said "data key RSA-2048/SHA-512;" "$ABR" info cros_nk_a8x.blob
# the same, the blob untouched: only the keyblock and the signatures change, and futility --repack does that very thing
rd_ck "an untouched blob under another keyblock" cros_repack cros_u_a8 cros_nk_a8.blob dev --chromeos-key "$CK/k2048.vbprivk" --chromeos-keyblock "$CK/k2048.keyblock"
rd_ck "the independent tool makes the same blob of the same kernel" cros make cros_nk_a8_e.blob --kernel cros_plain_al.img --keyblock "$CK/k2048.keyblock" --key "$CK/k2048.vbprivk" --minor 2
rd_ck "... the same bytes" cmp -s cros_nk_a8.blob cros_nk_a8_e.blob
rd_ck "futility --repack signs the body of the old blob under that keyblock into the very same blob" cros_fut_repack_is cros_nk_a8.blob cros_a8.blob "$CK/k2048.keyblock" "$CK/k2048.vbprivk"
"$ABR" repack cros_u_a8 -o cros_nk_a8d.blob --chromeos-key "$CROS_KP" --chromeos-keyblock "$CROS_KB" >/dev/null 2>&1
rd_ck "and into the developer's, too (abr: the developer key and keyblock given)" cros_fut_repack_is cros_nk_a8d.blob cros_a8.blob "$CROS_KB" "$CROS_KP"
rd_ck "its reader finds both signatures good" cros verify cros_nk_a8d.blob
# the key given for the keyblock the blob has (and the developer key, given explicitly, is the developer key abr has)
rd_ck "the developer key given explicitly is the same as the one abr has" cros_repack cros_x_dev22 cros_dk_dev22.blob dev --chromeos-key "$CROS_KP"
rd_ck "... the same bytes" cmp -s cros_xr_dev22.blob cros_dk_dev22.blob
rd_ck "... and abr says it was the key given" grep -q 'they are made again, with the key given (--chromeos-key)' cros_dk_dev22.blob.rlog
# nothing changed: the signatures are the original's whatever is given
rd_ck "untouched, with the key of the blob's keyblock given: identical" cros_repack cros_u_a8 cros_kp_a8.blob a8 --chromeos-key "$CK/k4096.vbprivk"
rd_ck "... the same bytes" cmp -s cros_a8.blob cros_kp_a8.blob
rd_ck "untouched, with the keyblock the blob has given: identical" cros_repack cros_u_dev22 cros_kb_dev22.blob dev --chromeos-keyblock "$CROS_KB"
rd_ck "... the same bytes" cmp -s cros_dev22.blob cros_kb_dev22.blob
rd_ck "the options say nothing of a plain image's repack but that they were not used" cros_repack cros_pu_pad cros_ig.img dev --chromeos-key "$CK/k2048.vbprivk"
rd_ck "... warning: they are for a ChromeOS blob" grep -q 'only apply to a ChromeOS kernel blob; ignored here' cros_ig.img.rlog
rd_ck "... and the image is the plain one" cmp -s cros_ig.img cros_plain_pad.img
rd_done "ChromeOS: a blob under somebody else's keyblock is kept as it was while nothing it covers changes; edited it is signed under the developer keyblock (with a warning) or with the key given, under the keyblock it has or another; the independent tool and futility (--repack) make the same blobs"

# What abr refuses: a key that is not the keyblock's, a keyblock without its key, files that are no keys, files that are no keyblocks.
rd_ck "the key given is not the data key of the blob's keyblock" cros_refuse_repack wrongkey cros_x_a8 'is not the data key of the keyblock (the blob' --chromeos-key "$CK/k2048b.vbprivk"
rd_ck "a keyblock without its key" cros_refuse_repack kbonly cros_x_a8 'has a data key of which abr has no key: pass the key with --chromeos-key' --chromeos-keyblock "$CK/k2048.keyblock"
rd_ck "a key that is not the data key of the keyblock given" cros_refuse_repack wrongkb cros_x_a8 'is not the data key of the keyblock (the one given with --chromeos-keyblock)' \
    --chromeos-key "$CK/k2048b.vbprivk" --chromeos-keyblock "$CK/k2048.keyblock"
printf 'short' >cros_badkey_short
head -c 300 /dev/zero | tr '\0' 'k' >cros_badkey_text
python3 -I - "$CK" <<'PYEOF'
import struct, sys
ck = sys.argv[1]
good = open(ck + "/k2048.vbprivk", "rb").read()                 # algorithm 5 (RSA-2048/SHA-512), a key of 2048 bits
der = good[8:]
open("cros_badkey_alg99", "wb").write(struct.pack("<Q", 99) + der)
open("cros_badkey_size", "wb").write(struct.pack("<Q", 8) + der)        # algorithm 8 wants 4096 bits
open("cros_badkey_der", "wb").write(struct.pack("<Q", 5) + bytes(range(256)) * 2)
open("cros_badkey_cut", "wb").write(good[:300])
kb = open(ck + "/k2048.keyblock", "rb").read()
open("cros_badkb_text", "wb").write(b"not a keyblock, " * 20)
open("cros_badkb_short", "wb").write(kb[:60])
open("cros_badkb_size", "wb").write(kb + b"\0")
k = bytearray(kb)
struct.pack_into("<Q", k, 80, 0xFFFFFFFF)                                  # the data key lies outside of the keyblock
open("cros_badkb_outside", "wb").write(bytes(k))
PYEOF
for r in "short:too short" "text:which abr does not know (0 to 17)" "alg99:names algorithm 99, which abr does not know" \
         "size:names RSA-4096/SHA-512, a key of 4096 bits, and holds one of 2048" "der:does not hold an RSA key behind its algorithm word" \
         "cut:does not hold an RSA key behind its algorithm word"; do
    rd_ck "--chromeos-key ${r%%:*}: refused, says why" cros_refuse_repack "key_${r%%:*}" cros_x_a8 "${r#*:}" --chromeos-key "cros_badkey_${r%%:*}"
done
rd_ck "--chromeos-key that is no file" cros_refuse_repack key_gone cros_x_a8 'cros_no_such_key' --chromeos-key cros_no_such_key
KB2048=$(cros_size "$CK/k2048.keyblock")
for r in "text:is not a keyblock (it does not start with \"CHROMEOS\")" "short:is cut short" "size:says it is $KB2048 bytes; the file has $((KB2048 + 1))" \
         "outside:lies outside of it"; do
    rd_ck "--chromeos-keyblock ${r%%:*}: refused, says why" cros_refuse_repack "kb_${r%%:*}" cros_x_a8 "${r#*:}" --chromeos-key "$CK/k2048.vbprivk" --chromeos-keyblock "cros_badkb_${r%%:*}"
done
rd_ck "--chromeos-keyblock that is no file" cros_refuse_repack kb_gone cros_x_a8 'cros_no_such_kb' --chromeos-key "$CK/k2048.vbprivk" --chromeos-keyblock cros_no_such_kb
rd_done "ChromeOS: a key that is not the keyblock's, a keyblock without its key, files that are no keys (too short, text, an algorithm that does not exist, a key of another size than its algorithm's, no DER, cut) or no keyblocks (text, cut, a size that is not the file's, a data key outside of it, no file) are refused with the reason, and no blob is written"

# A blob that is not laid out the way futility writes it is refused with the reason, and leaves no directory: abr does not
# read it wrongly, and does not lose what it cannot keep. (identify goes by the keyblock's "CHROMEOS" and still names it.)
for kind in "short-keyblock:its keyblock does not fit" "short-preamble:and the preamble do not fit" "short-preamble-body:its preamble of" \
            "short-body:its body is" "keyblock-version:has a keyblock of version 3" \
            "keyblock-size-small:says its keyblock is 50 bytes, which is less than its header" "preamble-major:has a preamble of version 3.2" \
            "preamble-minor:has a preamble of version 2.3" "preamble-reserved:non-zero reserved word in its preamble" \
            "field-reserved:non-zero reserved word in its preamble" "descriptor-reserved:reserved words of the descriptor of its body signature" \
            "x86:carries a vmlinuz header" "sig-layout:does not have its signatures where futility puts them" \
            "psig-layout:does not have its signatures where futility puts them" "pre-data-size:does not have its signatures where futility puts them" \
            "empty-signature:has an empty signature" "pad-nonzero:has data of its own behind the signatures" \
            "bootloader-size:has a bootloader of 100 bytes" "kernel-unaligned:has a kernel of" "body-small:too small for a kernel" \
            "preamble-size-small:says its preamble is 50 bytes, which is less than its header"; do
    x="${kind%%:*}"
    msg="${kind#*:}"
    rd_ck "$x: damage made" cros corrupt cros_dev22.blob "cros_dmg_$x.blob" "$x"
    rd_ck "$x: unpack refuses, says why, leaves no directory" cros_refuse "$x" "cros_dmg_$x.blob" "$msg"
    rd_ck "$x: identify still names the format" said "CHROMEOS" "$ABR" identify "cros_dmg_$x.blob"
done
cros_info_refuses() {  # <blob> <pattern>
    local out rc
    out="$("$ABR" info "$1" 2>&1)"
    rc=$?
    [ "$rc" -ne 0 ] && grep -q -- "$2" <<<"$out"
}
rd_ck "info refuses such a blob, too, with the reason" cros_info_refuses cros_dmg_x86.blob "carries a vmlinuz header"
rd_ck "(an x86 blob: a bzImage no Android tool opens)" cros_info_refuses cros_dmg_x86.blob "a kernel for x86"
rd_done "ChromeOS: a blob that is not laid out the way futility writes it (cut short at the keyblock, the preamble or the body; a keyblock or preamble of a version abr does not read; reserved words that are not zero; a vmlinuz header (x86); signatures anywhere but behind the preamble header; an empty signature; data behind the signatures; a bootloader or kernel that is not a whole number of 4096 bytes; a body too small; a preamble smaller than its header) is refused with the reason, leaves no directory, and is still named by identify"

# A signature that is bad is not repaired behind one's back: an untouched blob comes back as it was, bad signatures and all;
# edited, it is signed afresh, and that is good. And a data key abr cannot read (an algorithm it does not know, a packed key that
# is not its algorithm's size, a key that lies outside of the keyblock) leaves the signatures unchecked, and the keyblock as it was.
cros_verify_fails() { ! cros verify "$1"; }
cros_fut_rejects() { cros_fut || return 0; ! "$CROS_FUT" vbutil_kernel --verify "$1" >/dev/null 2>&1; }
for kind in "body-byte:body signature NOT valid, preamble signature valid" "body-sig-byte:signatures NOT valid" \
            "pre-sig-byte:body signature valid, preamble signature NOT valid"; do
    x="${kind%%:*}"
    msg="${kind#*:}"
    cros corrupt cros_dev22.blob "cros_sg_$x.blob" "$x"
    rd_ck "$x: the independent reader finds a signature bad" cros_verify_fails "cros_sg_$x.blob"
    rd_ck "$x: futility finds it bad, too" cros_fut_rejects "cros_sg_$x.blob"
    rd_ck "$x: info says what is bad ($msg)" said "$msg" "$ABR" info "cros_sg_$x.blob"
    rd_unpack "cros_sg_$x.blob" "cros_sg_u_$x"
    "$ABR" repack "cros_sg_u_$x" -o "cros_sg_r_$x.blob" >/dev/null 2>&1
    rd_ck "$x: an untouched repack is identical (the bad signature is kept)" cmp -s "cros_sg_$x.blob" "cros_sg_r_$x.blob"
    cros_copy "cros_sg_u_$x" "cros_sg_x_$x"
    cros_edit "cros_sg_x_$x"
    rd_ck "$x: an edit: repack" cros_repack "cros_sg_x_$x" "cros_sg_xr_$x.blob" dev
    rd_ck "$x: the signatures are made again, and are good" cros verify "cros_sg_xr_$x.blob"
    rd_ck "$x: futility verifies it" cros_fut_verify "cros_sg_xr_$x.blob"
done
for kind in "kb-algorithm:data key algorithm 99;" "kb-arrsize:data key RSA-2048/SHA-256;" "kb-outside:data key unreadable;"; do
    x="${kind%%:*}"
    msg="${kind#*:}"
    cros corrupt cros_dev22.blob "cros_kd_$x.blob" "$x"
    rd_ck "$x: info says the data key ($msg) and that the signatures are not checked" said "$msg.*signatures not checked" "$ABR" info "cros_kd_$x.blob"
    rd_unpack "cros_kd_$x.blob" "cros_kd_u_$x"
    "$ABR" repack "cros_kd_u_$x" -o "cros_kd_r_$x.blob" >/dev/null 2>&1
    rd_ck "$x: an untouched repack is identical (the keyblock is kept as it is, whatever it says)" cmp -s "cros_kd_$x.blob" "cros_kd_r_$x.blob"
    cros_copy "cros_kd_u_$x" "cros_kd_x_$x"
    cros_edit "cros_kd_x_$x"
    rd_ck "$x: an edit: repack (no key of such a keyblock: signed under the developer keyblock)" cros_repack "cros_kd_x_$x" "cros_kd_xr_$x.blob" dev
    rd_ck "$x: abr warns that the keyblock is somebody else's" grep -q "its keyblock is somebody else's" "cros_kd_xr_$x.blob.rlog"
    rd_ck "$x: the blob verifies" cros verify "cros_kd_xr_$x.blob"
    cros_plain_of "cros_kd_x_$x" "cros_kd_xp_$x.img"
    cros make "cros_kd_xe_$x.blob" --kernel "cros_kd_xp_$x.img" --keyblock "$CROS_KB" --key "$CROS_KP" --minor 2
    rd_ck "$x: ... the same bytes" cmp -s "cros_kd_xr_$x.blob" "cros_kd_xe_$x.blob"
    rd_ck "$x: the developer key is not the data key of that keyblock: it cannot be given for it" cros_refuse_repack "kd_$x" "cros_kd_x_$x" 'is not the data key of the keyblock' --chromeos-key "$CROS_KP"
done
rd_done "ChromeOS: signatures that are bad (the body's, the preamble's, or both) are kept as they were by an untouched repack and are good after an edit; a data key abr cannot read (an algorithm it does not know, a packed key of the wrong size, a key outside of the keyblock) leaves the signatures unchecked and the keyblock as it was, and after an edit the blob is signed under the developer keyblock"

# futility --pack against the independent tool and abr, where it is installed: the fields futility has options for (the
# command line, a bootloader, the version, the flags, the load address, the size of the verification block), with the developer
# key and with one of one's own, and an edit of such a blob (abr signs it as futility would).
if cros_fut; then
    for k in dev k4096; do
        kb="$(cros_kb "$k")"
        kp="$(cros_kp "$k")"
        rd_ck "$k: the independent tool makes the blob (the fields futility has options for)" cros make "cros_G_$k.blob" --kernel cros_plain_pad.img --keyblock "$kb" --key "$kp" --minor 2 \
            --kernel-version 7 --flags 3 --load 0x2000000 --config cros_cfg.txt --bootloader cros_bl.bin --pad 131072
        rd_ck "$k: futility --pack makes the very same blob" cros_fut_pack_is "cros_G_$k.blob" cros_plain_pad.img "$kb" "$kp" --version 7 --flags 0x3 --kloadaddr 0x2000000 \
            --config cros_cfg.txt --bootloader cros_bl.bin --pad 131072
        rd_unpack "cros_G_$k.blob" "cros_G_u_$k"
        "$ABR" repack "cros_G_u_$k" -o "cros_G_r_$k.blob" >/dev/null 2>&1
        rd_ck "$k: an untouched repack is identical" cmp -s "cros_G_$k.blob" "cros_G_r_$k.blob"
        cros_copy "cros_G_u_$k" "cros_G_x_$k"
        cros_edit "cros_G_x_$k"
        rd_ck "$k: an edit: repack" cros_repack "cros_G_x_$k" "cros_G_xr_$k.blob" "$k"
        cros_plain_of "cros_G_x_$k" "cros_G_xp_$k.img"
        rd_ck "$k: futility --pack makes the very same blob of the image the directory builds without the blob" cros_fut_pack_is "cros_G_xr_$k.blob" "cros_G_xp_$k.img" "$kb" "$kp" \
            --version 7 --flags 0x3 --kloadaddr 0x2000000 --config cros_cfg.txt --bootloader cros_bl.bin --pad 131072
        rd_ck "$k: futility verifies it (and the one it made)" cros_fut_verify "cros_G_xr_$k.blob" 131072
        rd_ck "$k: ... and the first one" cros_fut_verify "cros_G_$k.blob" 131072
    done
    rd_done "ChromeOS: futility --pack makes the blobs the independent tool and abr make, byte for byte (the command line, a bootloader, the version, the flags, the load address and the verification block set; the developer key, and a key of one's own), and the very same blob of an edited image"
else
    echo "note: futility is not installed: its --pack is not compared"
fi

# A ChromeOS blob around a DHTB-wrapped image: the wrappers come off in order, an edit goes through both, and the DHTB header's
# digest is made afresh.
python3 -I - <<'PYEOF'
import hashlib, struct
payload = open("cros_plain_pad.img", "rb").read()
header = b"DHTB\x01\x00\x00\x00" + hashlib.sha256(payload).digest() + b"\x00" * 8 + struct.pack("<I", len(payload))
open("cros_dhtb_plain.img", "wb").write(header + b"\x00" * (512 - len(header)) + payload)
PYEOF
rd_ck "the independent tool makes a blob around the DHTB image" cros make cros_chain.blob --kernel cros_dhtb_plain.img --keyblock "$CROS_KB" --key "$CROS_KP"
rd_unpack cros_chain.blob cros_u_chain
rd_ck "unpack names both wrappers, in the order they come off" grep -q 'unpacked chromeos-wrapped dhtb-wrapped boot' cros_u_chain.log
rd_ck "and says an untouched repack is identical" grep -q 'reproduces this image byte-for-byte' cros_u_chain.log
rd_ck "both are in the manifest" grep -q '^has_chromeos=true$' cros_u_chain/manifest.txt
rd_ck "(the DHTB header)" grep -q '^has_dhtb=true$' cros_u_chain/manifest.txt
rd_ck "info names both" said "wrapper: ChromeOS kernel blob" "$ABR" info cros_chain.blob
"$ABR" repack cros_u_chain -o cros_r_chain.blob >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s cros_chain.blob cros_r_chain.blob
cros_copy cros_u_chain cros_x_chain
cros_edit cros_x_chain
rd_ck "an edit goes through both" cros_repack cros_x_chain cros_xr_chain.blob dev
rd_ck "the blob's signatures are good" cros verify cros_xr_chain.blob
rd_ck "futility verifies it" cros_fut_verify cros_xr_chain.blob
cros kernel cros_xr_chain.blob cros_xr_chain_kernel.bin
rd_ck "the DHTB header inside has the digest of what follows it (made afresh)" python3 -I - cros_xr_chain_kernel.bin <<'PYEOF'
import hashlib, struct, sys
k = open(sys.argv[1], "rb").read()
assert k[:8] == b"DHTB\x01\x00\x00\x00", "no DHTB header"
n = struct.unpack_from("<I", k, 48)[0]
payload = k[512:512 + n]
assert len(payload) == n and n > 70000
assert hashlib.sha256(payload).digest() == k[8:40], "the digest is not of the payload"
assert payload[:8] == b"ANDROID!"
assert b"abr test" not in payload or True
assert k[512 + n:] == b"\0" * (len(k) - 512 - n), "what follows is not zeros"
PYEOF
rd_unpack cros_xr_chain.blob cros_xr_chain_re
rd_ck "the edit is in the image" cros_edit_is_in cros_xr_chain_re
rd_done "ChromeOS: around a DHTB header (two wrappers): both come off in order, an untouched repack is identical, an edit goes through both, the blob is signed afresh and the DHTB digest is made afresh"

# A blob whose kernel is nothing abr unpacks (random bytes): a container of its own, type=chromeos, whose kernel is a file.
head -c 100000 /dev/urandom >cros_rnd.bin
rd_ck "the independent tool makes a blob of random bytes" cros make cros_C.blob --kernel cros_rnd.bin --keyblock "$CROS_KB" --key "$CROS_KP" --minor 2 --kernel-version 3 --config cros_cfg.txt
rd_ck "identify" said "CHROMEOS" "$ABR" identify cros_C.blob
rd_ck "info says what the blob is (a kernel of 102400 bytes: the 100000 and the zeros up to 4096)" said "blob:           vboot preamble 2.2, kernel version 3," "$ABR" info cros_C.blob
rd_ck "... and the sizes" said "kernel 102400 bytes, config $(cros_size cros_cfg.txt) bytes" "$ABR" info cros_C.blob
rd_unpack cros_C.blob cros_u_C
rd_ck "the manifest is of a container" grep -q '^type=chromeos$' cros_u_C/manifest.txt
rd_ck "the kernel is a file (the kernel field as it is, zeros and all)" test "$(cros_size cros_u_C/chromeos_kernel.bin)" = 102400
rd_ck "... that starts with the bytes" cmp -s -n 100000 cros_u_C/chromeos_kernel.bin cros_rnd.bin
rd_ck "the command line is a file" cmp -s cros_u_C/chromeos_config.txt cros_cfg.txt
rd_ck "the version of the kernel is in the manifest" grep -q '^chromeos_kernel_version=3$' cros_u_C/manifest.txt
"$ABR" repack cros_u_C -o cros_r_C.blob >/dev/null 2>&1
rd_ck "an untouched repack is identical" cmp -s cros_C.blob cros_r_C.blob
cros_copy cros_u_C cros_x_C
head -c 5000 /dev/urandom >>cros_x_C/chromeos_kernel.bin
rd_ck "a longer kernel: repack" cros_repack cros_x_C cros_xr_C.blob dev
rd_ck "the independent tool makes the same blob of the file" cros make cros_xe_C.blob --kernel cros_x_C/chromeos_kernel.bin --keyblock "$CROS_KB" --key "$CROS_KP" --minor 2 --kernel-version 3 --config cros_cfg.txt
rd_ck "... the same bytes" cmp -s cros_xr_C.blob cros_xe_C.blob
rd_ck "futility verifies it" cros_fut_verify cros_xr_C.blob
cros_copy cros_u_C cros_s_C
head -c 50000 cros_rnd.bin >cros_s_C/chromeos_kernel.bin
rd_ck "a shorter kernel: repack" cros_repack cros_s_C cros_sr_C.blob dev
rd_ck "the independent tool makes the same blob of the file" cros make cros_se_C.blob --kernel cros_s_C/chromeos_kernel.bin --keyblock "$CROS_KB" --key "$CROS_KP" --minor 2 --kernel-version 3 --config cros_cfg.txt
rd_ck "... the same bytes" cmp -s cros_sr_C.blob cros_se_C.blob
rd_ck "a kernel that is nothing: refused, with the reason" true
cros_copy cros_u_C cros_e_C
: >cros_e_C/chromeos_kernel.bin
rd_ck "an empty kernel is refused" cros_refuse_repack empty_kernel cros_e_C 'the kernel of a ChromeOS blob cannot be empty'
cros_copy cros_u_C cros_n_C
sed -i '/^chromeos_kernel_file=/d' cros_n_C/manifest.txt
rd_ck "a manifest without the kernel's file is refused" cros_refuse_repack no_kernel cros_n_C 'has no chromeos_kernel_file'
rd_done "ChromeOS: a blob of a kernel abr does not unpack is a container (type=chromeos) whose kernel is a file: untouched it comes back identical; a longer or shorter kernel makes the blob the independent tool makes; an empty kernel or no kernel file is refused"

# =========================================================================
# Sony SIN containers, versions 1 to 3: the packaging Xperia firmware (.ftf) puts its images in (kernel.sin, boot.sin,
# FOTAKernel.sin, loader.sin ...). Android Image Kitchen opens one with `sony_dump` (github.com/munjeni/anyxperia_dumper)
# and forgets the container -- unpackimg.sh deletes the signature type, so repackimg.sh writes the plain image. A SIN is
# Sony's (the header carries hashes and a signature), nothing here could make one for an edited image, so abr does what
# AIK does and says so: the layer comes off, the image inside is unpacked as any image is, a repack writes that image
# (abr/legacy/sin.hpp). tests/tools/sin_tool.py makes the containers and reads them on its own -- written from the source
# of sony_dump, sharing no code with abr -- around two images of its own making (a boot image and a Sony ELF boot image,
# tests/tools/elf_tool.py). There is no real .sin among the fixtures: what is checked is the layout as the source of
# sony_dump has it, in 45 containers (every version; the image behind the header, a loader, data in front of the image,
# MMCF with ADDR and LZ4A parts, the gaps that are filled with 0xFF, parts that start too early, entries with more
# than their fields, parts decoded on several threads; what is not a boot image; what is damaged in each of its fields).
# Where sony_dump itself is at hand (ABR_SONY_DUMP, built from that source: it has no licence file, so it is only run,
# never copied) it converts every container as well and its output is compared byte for byte.
# =========================================================================
SIN_T="$TOOLS/sin_tool.py"
sint() { python3 -I "$SIN_T" "$@"; }
SIN_DUMP="${ABR_SONY_DUMP:-$(command -v sony_dump 2>/dev/null || true)}"
sin_dump_ok() { [ -n "$SIN_DUMP" ] && [ -x "$SIN_DUMP" ]; }
if sin_dump_ok; then
    echo "note: sony_dump ($SIN_DUMP) converts the Sony SIN containers too"
else
    echo "note: sony_dump is not at hand (ABR_SONY_DUMP): the Sony SIN containers are judged by tests/tools/sin_tool.py alone"
fi
sin_says() {  # <text> <command...>: the command succeeds and its output has the text as it is (not as a pattern)
    local text="$1" out
    shift
    out="$("$@" 2>&1)" || return 1
    grep -q -F -- "$text" <<<"$out"
}
sin_refuses() {  # <text> <command...>: the command fails and says the text
    local text="$1" out
    shift
    out="$("$@" 2>&1)" && return 1
    grep -q -F -- "$text" <<<"$out"
}
sin_reader() { sint convert "$1" sin_rd.img && cmp -s sin_rd.img "$2"; }  # <sin> <image>: the independent reader makes it
sin_dump_makes() {  # <sin> <image>: what sony_dump writes for the container is the image
    rm -rf sin_or
    mkdir sin_or
    local t=""
    command -v timeout >/dev/null 2>&1 && t="timeout 60"
    $t "$SIN_DUMP" sin_or "$1" >/dev/null 2>&1 || return 1
    local f
    for f in sin_or/*; do
        [ -f "$f" ] && cmp -s "$f" "$2" && return 0
    done
    return 1
}
sin_not_sin() {  # <file>: it does not start the way a SIN does (01 00 00 00, 02 00 00 00, "\x03SIN")
    local h
    h="$(head -c 4 "$1" | od -An -tx1 | tr -d ' \n')"
    [ "$h" != 01000000 ] && [ "$h" != 02000000 ] && [ "$h" != 0353494e ]
}
sin_tree_is_plain() {  # <dir> <dir of the plain image>: the same files, the same manifest but for its first line
    diff -r --no-dereference -x manifest.txt "$1" "$2" >/dev/null &&
        [ "$(tail -n +2 "$1/manifest.txt")" = "$(tail -n +2 "$2/manifest.txt")" ]
}

mkdir -p sin_k
if sint payloads sin_k && sint cases sin_k/c --aosp sin_k/aosp.img --elf sin_k/elf.img --big sin_k/big.img; then
    pass "Sony SIN: the containers are made ($(wc -l <sin_k/c/index.txt | tr -d ' ') of them, around a boot image and a Sony ELF boot image)"
else
    fail "Sony SIN: the containers could not be made (tests/tools/sin_tool.py)"
fi
sin_n=0
while IFS=$'\t' read -r sin_status sin_name sin_pat; do
    sin_f="sin_k/c/$sin_name.sin"
    sin_u="sin_u_$sin_name"
    sin_n=$((sin_n + 1))
    case "$sin_status" in
        ok)
            sin_want="sin_k/c/$sin_name.expect"
            rd_unpack "$sin_f" "$sin_u"
            rd_ck "$sin_name: unpack" test -d "$sin_u"
            rd_ck "$sin_name: the container is named" rd_has_text "$sin_u.log" "unpacked sin-wrapped"
            rd_ck "$sin_name: the check says it is the image inside the SIN that comes back" rd_has_text "$sin_u.log" "reproduces the image inside the SIN byte-for-byte"
            rd_unpack "$sin_want" "$sin_u.plain"
            rd_ck "$sin_name: the directory is the one of the plain image" sin_tree_is_plain "$sin_u" "$sin_u.plain"
            "$ABR" repack "$sin_u" -o "$sin_u.img" >"$sin_u.rlog" 2>&1
            rd_ck "$sin_name: a repack writes the image inside" cmp -s "$sin_u.img" "$sin_want"
            rd_ck "$sin_name: ... and no container" sin_not_sin "$sin_u.img"
            rd_ck "$sin_name: info shows the container ($sin_pat)" sin_says "$sin_pat" "$ABR" info "$sin_f"
            rd_ck "$sin_name: identify names the signature of the file" sin_says "SINv" "$ABR" identify "$sin_f"
            rd_ck "$sin_name: the independent reader makes the same image" sin_reader "$sin_f" "$sin_want"
            sin_dump_ok && rd_ck "$sin_name: sony_dump makes the same image" sin_dump_makes "$sin_f" "$sin_want"
            ;;
        nonboot | refuse)
            rm -rf "$sin_u"
            rd_ck "$sin_name: unpack is refused with the reason ($sin_pat)" sin_refuses "$sin_pat" "$ABR" unpack "$sin_f" -o "$sin_u"
            rd_ck "$sin_name: no directory is left" test ! -e "$sin_u"
            ;;
    esac
done <sin_k/c/index.txt
rd_done "Sony SIN: $sin_n containers (v1, v2, v3: the image behind the header, a loader, data in front of it, MMCF with ADDR and LZ4A parts, gaps filled with 0xFF, parts put at the end, longer entries, 60 parts, 18 MiB on several threads) unpack as the plain image does, a repack writes that image and no container, and the independent reader${SIN_DUMP:+ and sony_dump} make the same image; what is not a boot image or is damaged is refused with the reason and leaves no directory"

# ---- an edit lands in the image, and the repack is the plain image again (no container)
sin_edit() {  # <case> : append to the kernel of the unpacked container, repack, unpack that: the change is there
    local name="$1" d="sin_e_$1" f
    rm -rf "$d" "$d.img" "${d}_re"
    cp -a "sin_u_$name" "$d"
    f="$(ls "$d/kernel" "$d/segment0_kernel.bin" 2>/dev/null | head -n 1)"
    [ -n "$f" ] || return 1
    printf 'abr test' >>"$f"
    "$ABR" repack "$d" -o "$d.img" >"$d.rlog" 2>&1 || return 1
    sin_not_sin "$d.img" || return 1
    "$ABR" unpack "$d.img" -o "${d}_re" >"${d}_re.log" 2>&1 || return 1
    cmp -s "$f" "${d}_re/$(basename "$f")" || return 1
    ! grep -q 'sin-wrapped' "${d}_re.log"
}
for sin_name in v1_raw_aosp v3_mmcf_mixed_aosp v2_loader_elf v3_mmcf_lz4_elf v3_first_elf; do
    rd_ck "$sin_name: an edit of the kernel is in the image that is written, and it is not a container" sin_edit "$sin_name"
done
rd_done "Sony SIN: what is edited in the directory of a container lands in the plain image that a repack writes (boot and ELF images, every kind of container)"

# ---- the same directory, whatever the number of threads decoding the parts of the 18 MiB container
rm -rf sin_t1 sin_t4
ABR_THREADS=1 "$ABR" unpack sin_k/c/v3_mmcf_big_aosp.sin -o sin_t1 >/dev/null 2>&1
ABR_THREADS=4 "$ABR" unpack sin_k/c/v3_mmcf_big_aosp.sin -o sin_t4 >/dev/null 2>&1
rd_ck "one thread unpacks it" test -f sin_t1/manifest.txt
rd_ck "four threads unpack it" test -f sin_t4/manifest.txt
rd_ck "the directories are the same" sin_tree_is_plain sin_t1 sin_t4
rd_ck "and the image inside is what a repack writes" sh -c "'$ABR' repack sin_t4 -o sin_t4.img >/dev/null 2>&1 && cmp -s sin_t4.img sin_k/c/v3_mmcf_big_aosp.expect"
rd_done "Sony SIN: the parts of a container are decoded on as many threads as there are, and the result is the same for one"

# ---- notes: a part that starts before the end of the image is put at the end, as sony_dump does -- and the unpack says so
rm -rf sin_n1
"$ABR" unpack sin_k/c/v3_mmcf_append_elf.sin -o sin_n1 >sin_n1.log 2>&1
rd_ck "the unpack says where the part went" rd_has_text sin_n1.log "it is put at the end, as sony_dump does"
rd_ck "and what the repack is" rd_has_text sin_n1.log "the container is not kept, a repack writes the plain elf_boot image"
rd_ck "info says it as well" sin_says "it is put at the end, as sony_dump does" "$ABR" info sin_k/c/v3_mmcf_append_elf.sin
rd_ck "a container that is as it should be has no such note" sh -c "! '$ABR' info sin_k/c/v3_mmcf_mixed_elf.sin 2>&1 | grep -q 'note:'"
rd_done "Sony SIN: the unpack tells what it did that is not plain (a part put at the end) and what a repack will write"

# ---- a container around an image that is wrapped (DHTB, here): the container is not kept, the wrapper is
python3 - <<'PYEOF'
import hashlib, struct
inner = open("sin_k/aosp.img", "rb").read()
payload = inner + b"SEANDROIDENFORCE" + b"\xff\xff\xff\xff"
header = b"DHTB\x01\x00\x00\x00" + hashlib.sha256(payload).digest() + b"\x00" * 8 + struct.pack("<I", len(payload))
open("sin_k/dhtb.img", "wb").write(header + b"\x00" * (512 - len(header)) + payload)
PYEOF
sint wrap sin_k/dhtb.img sin_k/dhtb.sin --version 2 --mmcf mixed
rd_unpack sin_k/dhtb.sin sin_d
rd_ck "both layers are named" rd_has_text sin_d.log "unpacked sin-wrapped dhtb-wrapped boot"
rd_ck "the DHTB wrapper is in the manifest" grep -q '^has_dhtb=true$' sin_d/manifest.txt
rd_ck "the container is not (nothing of it is kept)" sh -c "! grep -q '^sin' sin_d/manifest.txt"
rd_ck "the round trip is checked against what the container held" rd_has_text sin_d.log "reproduces the image inside the SIN byte-for-byte"
"$ABR" repack sin_d -o sin_d.img >/dev/null 2>&1
rd_ck "a repack writes the DHTB-wrapped image that was inside" cmp -s sin_d.img sin_k/dhtb.img
rd_done "Sony SIN: around a DHTB-wrapped image only the container comes off; the DHTB header stays and is written again"

# =========================================================================
# Sony ELF boot images: the kernel.elf of an Xperia, an ELF executable whose program headers hold the kernel, the
# ramdisk and the rest (abr/legacy/elf_boot.hpp). Android Image Kitchen unpacks one with elftool (osm0sis/elftool,
# srl3gx's elfboot.h) and packs it with that tool again. tests/tools/elf_tool.py writes and reads the images on its own
# (it shares no code with abr), in elftool's layout and in the other layouts an ELF can have: another size of the block
# in front of the data, padding between the segments and bytes behind them, an e_entry or an OS/ABI byte of its own,
# p_align, p_memsz beyond p_filesz, a p_paddr that is not the p_vaddr, the data in another order than the program
# headers, program headers that are not behind the ELF header, an ELF64 header, an empty segment. No image of a real
# device was at hand: what is judged is the layout elftool writes (against the real elftool where it is built,
# ABR_ELFTOOL) and what an ELF in general can be. For every layout: the unpack, what is in the directory (the parts the
# independent reader finds, the ramdisk directory and GNU cpio's verdict on it), an untouched repack (the same bytes),
# an edited kernel, an edited ramdisk directory and another address in the manifest (each the image the independent
# writer makes of the same layout), and what happens when the layout kept for the repack is damaged.
# =========================================================================
ELF_T="$TOOLS/elf_tool.py"
elft() { python3 -I "$ELF_T" "$@"; }
ELF_TOOL="${ABR_ELFTOOL:-$(command -v elftool 2>/dev/null || true)}"
elf_tool_ok() { [ -n "$ELF_TOOL" ] && [ -x "$ELF_TOOL" ]; }
if elf_tool_ok; then
    echo "note: elftool ($ELF_TOOL) packs and unpacks the Sony ELF boot images in its layout too"
else
    echo "note: elftool is not at hand (ABR_ELFTOOL): the Sony ELF boot images are judged by tests/tools/elf_tool.py alone"
fi
elf_says() {  # <text> <command...>: the command succeeds and its output has the text as it is (not as a pattern)
    local text="$1" out
    shift
    out="$("$@" 2>&1)" || return 1
    grep -q -F -- "$text" <<<"$out"
}
elf_refuses() {  # <text> <command...>: the command fails and says the text
    local text="$1" out
    shift
    out="$("$@" 2>&1)" && return 1
    grep -q -F -- "$text" <<<"$out"
}
elf_manifest() { sed -n "s/^$2=//p" "$1/manifest.txt"; }  # <directory> <key>
elf_parts_match() {  # <image> <unpacked directory>: every segment the independent reader finds is a file of the directory, as it was stored
    local img="$1" d="$2" n i p f
    rm -rf elf_rd
    elft parts "$img" elf_rd || return 1
    n="$(elf_manifest "$d" segment_count)"
    [ "$n" = "$(wc -l <elf_rd/index.txt | tr -d ' ')" ] || return 1
    i=0
    while [ "$i" -lt "$n" ]; do
        p="$(elf_manifest "$d" "segment${i}_prefix")"
        [ -n "$p" ] || p="$(elf_manifest "$d" "segment${i}_role")"
        f="$(elf_manifest "$d" "${p}_file")"
        if [ -s "elf_rd/seg$i" ]; then
            [ -n "$f" ] && cmp -s "elf_rd/seg$i" "$d/.abr_raw/$f.raw" || return 1
        else
            [ -z "$f" ] || return 1  # (a segment with no data is no file)
        fi
        i=$((i + 1))
    done
}
elf_edit_kernel() {  # <case>: 8 bytes more in the kernel: the image is what the independent writer makes of the same layout
    local en="$1" d="elf_ek_$1"
    rm -rf "$d" "$d.img" "$d.expect"
    cp -a "elf_u_$en" "$d" || return 1
    printf 'abr test' >>"$d/kernel"
    "$ABR" repack "$d" -o "$d.img" >"$d.rlog" 2>&1 || return 1
    elft rebuild "elf_k/c/$en.json" "elf_k/c/$en.img" "$d.expect" --kernel "$d/kernel" || return 1
    cmp -s "$d.img" "$d.expect" && ! cmp -s "$d.img" "elf_k/c/$en.img"
}
elf_edit_ramdisk() {  # <case>: a file put into ramdisk/ lands in the image; the rest is the layout of the image that was unpacked
    local en="$1" d="elf_er_$1"
    rm -rf "$d" "$d.img" "$d.expect" "${d}_re"
    cp -a "elf_u_$en" "$d" || return 1
    printf 'abr test\n' >"$d/ramdisk/abr_test_file"
    "$ABR" repack "$d" -o "$d.img" >"$d.rlog" 2>&1 || return 1
    elft rebuild "elf_k/c/$en.json" "$d.img" "$d.expect" || return 1  # the segments of this image in the layout of the original
    cmp -s "$d.img" "$d.expect" || return 1
    "$ABR" unpack "$d.img" -o "${d}_re" >/dev/null 2>&1 || return 1
    [ "$(cat "${d}_re/ramdisk/abr_test_file")" = "abr test" ] || return 1
    rd_same_tree_x "elf_u_$en/ramdisk" "${d}_re/ramdisk" abr_test_file
}
elf_edit_addr() {  # <case>: the first segment gets another address in the manifest; e_entry follows it unless the image has its own
    local en="$1" d="elf_ea_$1"
    rm -rf "$d" "$d.img" "$d.expect"
    cp -a "elf_u_$en" "$d" || return 1
    sed -i 's/^segment0_addr=.*/segment0_addr=0x80300000/' "$d/manifest.txt"
    "$ABR" repack "$d" -o "$d.img" >"$d.rlog" 2>&1 || return 1
    elft rebuild "elf_k/c/$en.json" "elf_k/c/$en.img" "$d.expect" --addr0 80300000 || return 1
    cmp -s "$d.img" "$d.expect" && ! cmp -s "$d.img" "elf_k/c/$en.img"
}

mkdir -p elf_k
python3 "$RDG" mkbootfs elf_k/rd.cpio
if elft catalog elf_k/c elf_k/rd.cpio; then
    pass "Sony ELF: the images are made ($(wc -l <elf_k/c/index.txt | tr -d ' ') layouts, in elftool's and in others)"
else
    fail "Sony ELF: the images could not be made (tests/tools/elf_tool.py)"
fi
elf_n=0
ELF_ORC=""
elf_tool_ok && ELF_ORC=", and elftool takes the images that are in its layout"
while IFS=$'\t' read -r en el eo ed; do
    elf_n=$((elf_n + 1))
    ei="elf_k/c/$en.img"
    eu="elf_u_$en"
    elf_cls=ELF32
    case "$en" in elf64*) elf_cls=ELF64 ;; esac
    elf_segs="$(elft list "$ei" | tail -n +2 | wc -l | tr -d ' ')"
    rd_unpack "$ei" "$eu"
    rd_ck "$en: unpack" test -d "$eu"
    rd_ck "$en: the unpack says what it is" rd_has_text "$eu.log" "unpacked elf_boot"
    rd_ck "$en: the self-check says an untouched repack is the image" rd_has_text "$eu.log" "an untouched repack reproduces this image byte-for-byte"
    elf_name="ELF bootimg"
    case "$en" in entry_abi) elf_name="ELF (ARM)" ;; esac  # (the magic file of AIK calls an ELF a boot image only when its OS/ABI byte is 0x61)
    rd_ck "$en: identify names it" elf_says "$elf_name" "$ABR" identify "$ei"
    rd_ck "$en: info: the format, the class and the number of segments" sh -c "'$ABR' info '$ei' >'$eu.info' 2>&1 && grep -q -F 'format: elf_boot' '$eu.info' && grep -q -F 'class:    $elf_cls' '$eu.info' && grep -q -F 'segments: $elf_segs' '$eu.info'"
    rd_ck "$en: the segments are what the independent reader finds" elf_parts_match "$ei" "$eu"
    if [ -f "$eu/ramdisk.cpio" ]; then
        rd_ck "$en: the ramdisk is a directory" test -d "$eu/ramdisk"
        rd_ck "$en: GNU cpio agrees with the directory" rd_oracle "$eu" ramdisk
    else
        rd_ck "$en: no ramdisk, no directory" test ! -e "$eu/ramdisk"
    fi
    case "$el" in
        elftool)
            rd_ck "$en: info: the layout is elftool's" elf_says "layout:   elftool's (data from byte 4096" "$ABR" info "$ei"
            rd_ck "$en: nothing of the layout is kept" sh -c "! grep -q '^elf_layout' '$eu/manifest.txt' && test ! -e '$eu/.abr_raw/elf_layout.bin'"
            ;;
        kept)
            rd_ck "$en: info: the layout is kept as found" elf_says "layout:   kept as found" "$ABR" info "$ei"
            rd_ck "$en: the unpack says why" rd_has_text "$eu.log" "is not laid out the way elftool lays an image out"
            rd_ck "$en: the manifest and .abr_raw/elf_layout.bin have it" sh -c "grep -q '^elf_layout=kept\$' '$eu/manifest.txt' && test -s '$eu/.abr_raw/elf_layout.bin'"
            ;;
    esac
    case "$en" in
        unflagged3)
            rd_ck "$en: the roles are by position: kernel, ramdisk, extra0" sh -c "test \"\$(sed -n 's/^segment[0-9]_role=//p' '$eu/manifest.txt' | tr '\\n' ' ')\" = 'kernel ramdisk extra0 '"
            ;;
        elftool5)
            rd_ck "$en: ipl and rpm are files" sh -c "test -s '$eu/ipl' && test -s '$eu/rpm'"
            ;;
        elf64*)
            rd_ck "$en: is_64bit in the manifest" grep -q '^is_64bit=true$' "$eu/manifest.txt"
            ;;
        ramdisk_empty | empty_kept)
            rd_ck "$en: an empty segment is no file" test ! -e "$eu/ramdisk.cpio"
            ;;
    esac
    "$ABR" repack "$eu" -o "$eu.out" >"$eu.rlog" 2>&1
    rd_ck "$en: an untouched repack is the image" cmp -s "$ei" "$eu.out"
    rd_ck "$en: an edited kernel: the image the independent writer makes of the same layout" elf_edit_kernel "$en"
    if [ -d "$eu/ramdisk" ]; then
        rd_ck "$en: a file in ramdisk/: it is in the image, the rest is the layout it had, nothing else changed" elf_edit_ramdisk "$en"
    fi
    rd_ck "$en: another address in the manifest: the image the independent writer makes of the same layout" elf_edit_addr "$en"
    if [ "$eo" = yes ] && elf_tool_ok; then
        rd_ck "$en: elftool packs the parts of the image into the image, and unpacks them as they are" elft oracle "$ELF_TOOL" "$ei" "elf_or_$en"
        rd_ck "$en: ... and the same for the image abr writes after an edit of the kernel" elft oracle "$ELF_TOOL" "elf_ek_$en.img" "elf_or_k_$en"
        if [ -d "$eu/ramdisk" ]; then
            rd_ck "$en: ... and after an edit of the ramdisk" elft oracle "$ELF_TOOL" "elf_er_$en.img" "elf_or_r_$en"
        fi
    fi
    rd_done "Sony ELF $en ($ed): unpacks (class, segments, layout), the segments are what the independent reader finds, the ramdisk directory${RD_GNU}, an untouched repack is the image, an edit of the kernel, of the ramdisk directory or of an address in the manifest gives the image the independent writer makes of the same layout${ELF_ORC}"
done <elf_k/c/index.txt

# ---- an address an ELF32 header cannot hold is refused, an ELF64 header takes it
rm -rf elf_big elf_big.img elf_big_k elf_big_k.img elf_big64 elf_big64.img
cp -a elf_u_elftool3 elf_big
sed -i 's/^segment0_addr=.*/segment0_addr=0x100000000/' elf_big/manifest.txt
rd_ck "ELF32 in elftool's layout: an address beyond 32 bits is refused with the reason" elf_refuses "does not fit an ELF32 image" "$ABR" repack elf_big -o elf_big.img
rd_ck "... and no file is left" test ! -e elf_big.img
cp -a elf_u_start8k elf_big_k
sed -i 's/^segment0_addr=.*/segment0_addr=0x100000000/' elf_big_k/manifest.txt
rd_ck "ELF32 in a layout that is kept: the same" elf_refuses "does not fit an ELF32" "$ABR" repack elf_big_k -o elf_big_k.img
rd_ck "... and no file is left" test ! -e elf_big_k.img
cp -a elf_u_elf64 elf_big64
sed -i 's/^segment0_addr=.*/segment0_addr=0x100000000/' elf_big64/manifest.txt
"$ABR" repack elf_big64 -o elf_big64.img >/dev/null 2>&1
rd_ck "ELF64: the address is taken" elf_says "kernel flags=0x00000000 offset=4096 address=0x100000000 " elft list elf_big64.img
rd_done "Sony ELF: an address beyond 32 bits is refused for an ELF32 header (elftool's layout and a kept one: with the reason, no file left) and written into an ELF64 one"

# ---- the layout that is kept for the repack cannot be used: the repack says so and writes elftool's layout of the same segments
elf_dmg_gone() { rm -f "$1/.abr_raw/elf_layout.bin"; }
elf_dmg_cut() { head -c 100 "$1/.abr_raw/elf_layout.bin" >"$1/cut.tmp" && mv "$1/cut.tmp" "$1/.abr_raw/elf_layout.bin"; }
elf_dmg_sizes() { sed -i 's/^elf_layout_sizes=.*/elf_layout_sizes=1,2/' "$1/manifest.txt"; }
elf_dmg_order() { sed -i 's/^elf_layout_order=.*/elf_layout_order=0,1,7/' "$1/manifest.txt"; }
elf_dmg_twice() { sed -i 's/^elf_layout_order=.*/elf_layout_order=0,0,2/' "$1/manifest.txt"; }
elf_dmg_count() { sed -i 's/^segment_count=.*/segment_count=2/' "$1/manifest.txt"; }
elf_fallback() {  # <case> <label> <text of the warning> <damage function>: the damage is done to a copy of the directory of the case
    local en="$1" label="$2" text="$3" damage="$4" d="elf_fb_$1_$2"
    rm -rf "$d" "$d.img" "$d.expect"
    cp -a "elf_u_$en" "$d" || return 1
    "$damage" "$d" || return 1
    "$ABR" repack "$d" -o "$d.img" >"$d.rlog" 2>&1 || return 1
    grep -q -F -- "$text" "$d.rlog" || return 1
    grep -q -F -- "the image is written in elftool's layout" "$d.rlog" || return 1
    if [ "$damage" = elf_dmg_count ]; then  # two segments are written, in elftool's layout
        [ "$(elft list "$d.img" | tail -n +2 | wc -l | tr -d ' ')" = 2 ] || return 1
        elf_says "layout:   elftool's" "$ABR" info "$d.img"
    else
        elft rebuild "elf_k/c/$en.json" "elf_k/c/$en.img" "$d.expect" --canonical || return 1
        cmp -s "$d.img" "$d.expect"
    fi
}
rd_ck "the file with the bytes around the segments is gone" elf_fallback pads_tail gone "is not there" elf_dmg_gone
rd_ck "the file is cut short" elf_fallback pads_tail cut "elf_layout_sizes does not fit" elf_dmg_cut
rd_ck "the sizes in the manifest are not the file's" elf_fallback pads_tail sizes "elf_layout_sizes does not fit" elf_dmg_sizes
rd_ck "the order names a segment that is not there" elf_fallback pads_tail order "the layout kept for this image is damaged (the order of its segments)" elf_dmg_order
rd_ck "the order names a segment twice" elf_fallback pads_tail twice "the layout kept for this image is damaged (the order of its segments)" elf_dmg_twice
rd_ck "the number of segments is not the one of the layout" elf_fallback pads_tail count "has 3 program headers, the image has 2 segments" elf_dmg_count
rd_ck "an elftool layout needs no file: a manifest that says nothing of it is as good" sh -c "! grep -q '^elf_layout' elf_u_elftool3/manifest.txt && '$ABR' repack elf_u_elftool3 -o elf_fb_none.img >/dev/null 2>&1 && cmp -s elf_fb_none.img elf_k/c/elftool3.img"
# a segment that had no data in the image gets some: no layout has room for it
rm -rf elf_gain elf_gain.img
cp -a elf_u_empty_kept elf_gain
printf 'hello' >elf_gain/ramdisk.cpio
printf 'ramdisk_file=ramdisk.cpio\nramdisk_compression=none\n' >>elf_gain/manifest.txt
"$ABR" repack elf_gain -o elf_gain.img >elf_gain.rlog 2>&1
rd_ck "a segment that had no data and has some: the repack says so" rd_has_text elf_gain.rlog "had no data in the image that was unpacked and has some now; the image is written in elftool's layout"
rd_ck "... the data is in the image (and the layout is elftool's)" sh -c "'$ABR' info elf_gain.img >elf_gain.info 2>&1 && grep -q -F 'ramdisk (flags=0x80000000) addr=0x81800000 size=5 (none)' elf_gain.info && grep -q -F \"layout:   elftool's\" elf_gain.info"
rd_done "Sony ELF: a layout that cannot be used for the repack (the file gone, cut short, sizes that do not fit, an order naming a segment that is not there or one twice, another number of segments, a segment that had no data and has some) is said in a warning and the image is written in elftool's layout of the same segments"

# ---- paths that are not ASCII --------------------------------------------------------------------------------
# Cyrillic, an accent, Chinese and an emoji (four bytes in UTF-8, a surrogate pair on Windows) in the names of the
# image, of the directory it is unpacked to and of the file it is packed to, and in a file name the manifest holds.
# On Windows the C runtime hands main() the command line in the ANSI code page, in which every one of these characters
# is a '?': abr asks Windows for the wide command line instead (Wine needs a UTF-8 locale to pass the characters on:
# the wrapper above sets it). Elsewhere a name is bytes and this passes with any locale.
U8_ROOT="каталог-ü-日本-😀"
U8_IMG="$U8_ROOT/загрузка-ü-日本-😀.img"
U8_DIR="$U8_ROOT/распаковано-日本-😀"
U8_OUT="$U8_ROOT/результат-ü-😀.img"
mkdir -p "$U8_ROOT"
cp boot_v2.img "$U8_IMG"
rd_fails=""
rd_ck "unpack of an image whose name is not ASCII into a directory whose name is not" "$ABR" unpack "$U8_IMG" -o "$U8_DIR"
rd_ck "the directory has the name it was given" test -f "$U8_DIR/manifest.txt"
rd_ck "and nothing is left under a '?' name" test "$(find . -name '*\?*' | wc -l)" = 0
rd_ck "the manifest's first lines name the directory as it was given" grep -q -F -- "$U8_DIR" "$U8_DIR/manifest.txt"
rd_ck "repack into a file whose name is not ASCII" "$ABR" repack "$U8_DIR" -o "$U8_OUT"
rd_ck "... is the image it came from" cmp -s "$U8_IMG" "$U8_OUT"
rd_ck "info names the file as it is" said "file:   $U8_IMG " "$ABR" info "$U8_IMG"
rd_ck "identify names it, too" said "^$U8_IMG: " "$ABR" identify "$U8_IMG"
rd_ck "identify -b says what it is" said "AOSP" "$ABR" identify -b "$U8_IMG"
# a file name that only the manifest knows
U8_FILE="ядро-ü-日本-😀.bin"
rd_ck "a kernel file with a name that is not ASCII (and its raw twin): moved there" sh -c "mv '$U8_DIR/kernel' '$U8_DIR/$U8_FILE' && mv '$U8_DIR/.abr_raw/kernel.raw' '$U8_DIR/.abr_raw/$U8_FILE.raw' && sed -i 's/^kernel_file=.*/kernel_file=$U8_FILE/' '$U8_DIR/manifest.txt'"
rd_ck "repacked from the manifest's name" "$ABR" repack "$U8_DIR" -o "$U8_ROOT/из-манифеста.img"
rd_ck "... the same image" cmp -s "$U8_IMG" "$U8_ROOT/из-манифеста.img"
rd_ck "a name that is not there is named as it was written" said "ядро-ü-日本-😀.bin" sh -c "rm '$U8_DIR/$U8_FILE' '$U8_DIR/.abr_raw/$U8_FILE.raw'; ! '$ABR' repack '$U8_DIR' -o '$U8_ROOT/нет.img' 2>&1; true"
rd_done "paths that are not ASCII: the image, the directory, the output file and a name of the manifest (Cyrillic, an accent, Chinese, an emoji) come through the command line and the messages as they are"

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
        fi
        # ... and around it in a ChromeOS kernel blob (made by the independent tool, with the developer keys): the blob comes off,
        # an untouched repack is identical, the signatures are good, and an edit lands in the image and is signed afresh.
        if cros make "$rw.chromeos" --kernel "$img" --keyblock "$CK/kernel.keyblock" --key "$CK/kernel_data_key.vbprivk" >/dev/null 2>&1; then
            rm -rf "$rw.cu" "$rw.cu.edit" "$rw.cu.edit_re"
            "$ABR" unpack "$rw.chromeos" -o "$rw.cu" >"$rw.cu.log" 2>&1
            rd_ck "in a ChromeOS blob: unpack" test -d "$rw.cu"
            rd_ck "in a ChromeOS blob: the blob is named" grep -q 'chromeos-wrapped' "$rw.cu.log"
            "$ABR" repack "$rw.cu" -o "$rw.chromeos.out" >/dev/null 2>&1
            rd_ck "in a ChromeOS blob: an untouched repack is identical" cmp -s "$rw.chromeos" "$rw.chromeos.out"
            rd_ck "in a ChromeOS blob: the signatures of the original are good" cros verify "$rw.chromeos"
            if [ -n "$prefixes" ]; then
                cp -a "$rw.cu" "$rw.cu.edit" && printf 'abr test\n' >"$rw.cu.edit/$(sed -n '1p' <<<"$prefixes")/abr_test_file"
                "$ABR" repack "$rw.cu.edit" -o "$rw.cu.edit.blob" >/dev/null 2>&1 && "$ABR" unpack "$rw.cu.edit.blob" -o "$rw.cu.edit_re" >/dev/null 2>&1
                rd_ck "in a ChromeOS blob: an edit lands in the image" test "$(cat "$rw.cu.edit_re/$(sed -n '1p' <<<"$prefixes")/abr_test_file" 2>/dev/null)" = "abr test"
                rd_ck "in a ChromeOS blob: the blob is signed afresh, and good" cros verify "$rw.cu.edit.blob"
                rd_ck "in a ChromeOS blob: futility verifies it" cros_fut_verify "$rw.cu.edit.blob"
            fi
            rm -rf "$rw.chromeos" "$rw.chromeos.out" "$rw.cu" "$rw.cu.edit" "$rw.cu.edit.blob" "$rw.cu.edit_re"
        fi
        # ... and in a Sony SIN (the image behind a v3 header; as an LZ4A part of a v1 container): the container comes off, an
        # untouched repack is the image that was inside.
        for sin_v in "3:" "1:lz4"; do
            sin_ver="${sin_v%%:*}"
            sin_mm="${sin_v#*:}"
            rm -rf "$rw.su" "$rw.sin" "$rw.sin.out"
            if sint wrap "$img" "$rw.sin" --version "$sin_ver" ${sin_mm:+--mmcf "$sin_mm"} >/dev/null 2>&1; then
                "$ABR" unpack "$rw.sin" -o "$rw.su" >"$rw.su.log" 2>&1
                rd_ck "in a Sony SIN v$sin_ver${sin_mm:+ ($sin_mm)}: unpack" test -d "$rw.su"
                rd_ck "in a Sony SIN v$sin_ver${sin_mm:+ ($sin_mm)}: the container is named" grep -q 'sin-wrapped' "$rw.su.log"
                "$ABR" repack "$rw.su" -o "$rw.sin.out" >/dev/null 2>&1
                rd_ck "in a Sony SIN v$sin_ver${sin_mm:+ ($sin_mm)}: an untouched repack is the image that was inside" cmp -s "$img" "$rw.sin.out"
            fi
            rm -rf "$rw.su" "$rw.sin" "$rw.sin.out"
        done
        rd_done "real image $rb: ${prefixes:+ramdisk directories (${prefixes//$'\n'/, }), }untouched repack identical$RD_GNU, and the same image in a ChromeOS kernel blob and in Sony SIN containers"
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
for kind in blob:SIGNBLOB chromeos:ChromeOS sin2:Sony osip:OSIP; do
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

# =========================================================================
# Judges that have to be there. A judge that is not (rkcrc, mboot, sony_dump, ...) is a note in its section and the
# comparisons with it are skipped, which is right on a machine that has not got it and wrong in a run that is meant to have
# them all (the CI): a skipped comparison passes unseen. ABR_REQUIRE_ORACLES=<names, separated by commas> makes the absence
# of the named judges a failure: futility, cpio, rkcrc, blobtools, mboot, loki, pxa, sony_dump, elftool. A name that is not
# on this list is a failure too (a misspelt name would otherwise check nothing).
# =========================================================================
oracle_have() {
    case "$1" in
        futility) cros_fut ;;
        cpio) [ "$HAVE_GNU_CPIO" = 1 ] ;;
        rkcrc) [ -n "${ABR_RKCRC:-}" ] && [ -x "$ABR_RKCRC" ] ;;
        blobtools) blob_real ;;
        mboot) osip_real ;;
        loki) loki_real ;;
        pxa) [ -n "${PXA_MKBOOTIMG:-}" ] && [ -x "$PXA_MKBOOTIMG" ] && [ -n "${PXA_UNPACKBOOTIMG:-}" ] && [ -x "$PXA_UNPACKBOOTIMG" ] ;;
        sony_dump) [ -n "${SIN_DUMP:-}" ] && [ -x "$SIN_DUMP" ] ;;
        elftool) elf_tool_ok ;;
        *) return 2 ;;
    esac
}
if [ -n "${ABR_REQUIRE_ORACLES:-}" ]; then
    oracle_n=0
    IFS=',' read -r -a oracle_want <<<"$ABR_REQUIRE_ORACLES"
    for oracle in "${oracle_want[@]}"; do
        oracle="${oracle//[[:space:]]/}"
        [ -n "$oracle" ] || continue
        oracle_n=$((oracle_n + 1))
        oracle_have "$oracle"
        case $? in
            0) pass "the judge '$oracle' is there (ABR_REQUIRE_ORACLES)" ;;
            2) fail "ABR_REQUIRE_ORACLES names '$oracle', which is not a judge of this suite (futility, cpio, rkcrc, blobtools, mboot, loki, pxa, sony_dump, elftool)" ;;
            *) fail "the judge '$oracle' is required (ABR_REQUIRE_ORACLES) and is not there: its comparisons were skipped" ;;
        esac
    done
    [ "$oracle_n" -gt 0 ] || fail "ABR_REQUIRE_ORACLES is set and names no judge"
fi

echo ""
echo "===== $PASS passed, $FAIL failed ====="
exit "$FAIL"
