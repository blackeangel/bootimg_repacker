#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Do the judges notice? Runs the live drivers that judge the small firmware images (MediaTek, Qualcomm MBN, splash and logo pictures, QCDT, AML_, dtb) against the
# real abr and against two sabotaged copies of it (tests/tools/abr_sabotage.py): one that changes ONE byte of the image `pack` wrote, one that changes ONE byte
# of the biggest file `unpack` wrote. A driver has to pass with the real abr and to fail with both; one that passes with a sabotaged abr judges nothing.
# Then the driver of kernel_info/ (kinfo_live.py) against a third sabotaged copy, once for every kind of file and every field of summary.txt that `unpack` writes
# there: it changes ONE byte of that file, and the driver has to notice every one.
#
#   tests/tools/sabotage_check.sh <abr> <work directory> [<boot_lk2nd.img, the real QCDT image> [<TWRP Recovery Amlogic S9xx.img, the real AML_ image>
#                                                          [<the directory of the real images, for the kernels>]]]
#
# It needs what the suite needs for these drivers (python3 with Pillow and cryptography, dtc, the reference tools of tests/reference). Prints one line for every
# driver and ends with status 0 when every driver behaved so (1 when one did not, 2 when something could not be set up). ABR_LIVE_MUTANTS (default 2) is the
# number of damaged images each driver makes; the logs are <work directory>/<driver>.<real|pack|unpack>.log and, for kernel_info/, <work directory>/kinfo_*.log.
# (It runs for some minutes.)
set -u
if [ $# -lt 2 ]; then
    echo "usage: $0 <abr> <work directory> [<real QCDT image> [<real AML_ image>]]" >&2
    exit 2
fi
ABR=$(realpath "$1")
mkdir -p "$2" || exit 2
WORK=$(cd "$2" && pwd)
REAL_QCDT=${3:--}
REAL_AML=${4:--}
REAL_DIR=${5:--}
HERE=$(cd "$(dirname "$0")" && pwd)
SABOTAGE=$HERE/abr_sabotage.py
MKBOOTIMG=$HERE/../reference/mkbootimg/mkbootimg.py
AVBTOOL=$HERE/../reference/avb/avbtool.py
export ABR_LIVE_MUTANTS=${ABR_LIVE_MUTANTS:-2} NO_COLOR=1 ABR_PROGRESS=0
[ -x "$ABR" ] || { echo "$ABR is not an executable" >&2; exit 2; }
[ -x "$SABOTAGE" ] || { echo "$SABOTAGE is not executable" >&2; exit 2; }

gen() { # gen <label> <command...>: the images the drivers are given, made by the independent writers
    local label=$1
    shift
    "$@" >"$WORK/gen_$label.log" 2>&1 || { echo "the generator '$label' failed (see $WORK/gen_$label.log)" >&2; exit 2; }
}
# ABR_SABOTAGE_ONLY=kinfo: only the driver of kernel_info/ (the others need Pillow, cryptography and the reference tools; this one needs cpio, dtc, openssl, ...)
if [ "${ABR_SABOTAGE_ONLY:-}" = kinfo ]; then
    drivers=()
else
    drivers=(splash rle mbn mtk qcdt aml dtb)
    rm -rf "$WORK/gen_splash" "$WORK/gen_mbn" "$WORK/gen_mtk_cont" "$WORK/gen_mtk_gfh" "$WORK/gen_mtk_boot"
    gen splash python3 -I "$HERE/mk_splash.py" gen "$WORK/gen_splash"
    gen mbn python3 -I "$HERE/mk_mbn.py" make "$WORK/gen_mbn"
    gen mtk_cont python3 -I "$HERE/mk_mtk.py" make "$WORK/gen_mtk_cont"
    gen mtk_gfh python3 -I "$HERE/mk_gfh.py" "$WORK/gen_mtk_gfh"
    gen mtk_boot python3 -I "$HERE/mk_mtk.py" boot "$WORK/gen_mtk_boot" "$MKBOOTIMG"
fi

drive() { # drive <driver> <the abr to give it> <its work directory>
    case $1 in
    splash) python3 -I "$HERE/splash_live.py" "$2" "$WORK/gen_splash" "$3" ;;
    rle) python3 -I "$HERE/rle_parity.py" "$2" "$3" ;;
    mbn) python3 -I "$HERE/mbn_live.py" "$2" "$WORK/gen_mbn" "$3" ;;
    mtk) python3 -I "$HERE/mtk_live.py" "$2" "$WORK/gen_mtk_cont" "$WORK/gen_mtk_gfh" "$WORK/gen_mtk_boot" "$3" ;;
    qcdt) python3 -I "$HERE/qcdt_live.py" "$2" "$3" "$REAL_QCDT" ;;
    aml) python3 -I "$HERE/aml_live.py" "$2" "$3" "$REAL_AML" ;;
    dtb) python3 -I "$HERE/dtb_live.py" "$2" "$AVBTOOL" "$3" ;;
    esac
}

bad=0
[ ${#drivers[@]} -eq 0 ] || printf '%-8s %-14s %-22s %-22s\n' driver "real abr" "pack: one byte" "unpack: one byte"
for name in "${drivers[@]}"; do
    rm -rf "$WORK/run_$name.real"
    drive "$name" "$ABR" "$WORK/run_$name.real" >"$WORK/$name.real.log" 2>&1
    rc_real=$?
    verdict_real="passes"
    if [ $rc_real -ne 0 ]; then
        verdict_real="FAILS ($rc_real)"
        bad=1
    fi
    cells=()
    for mode in pack unpack; do
        rm -rf "$WORK/run_$name.$mode"
        ABR_REAL="$ABR" SAB=$mode drive "$name" "$SABOTAGE" "$WORK/run_$name.$mode" >"$WORK/$name.$mode.log" 2>&1
        rc=$?
        fails=$(grep -c -E '^FAIL|DIFFERENT|^Traceback|^AssertionError' "$WORK/$name.$mode.log")
        unfound=$(grep -c '^abr_sabotage:' "$WORK/$name.$mode.log")
        if [ $rc -eq 0 ]; then
            cells+=("NOT NOTICED")
            bad=1
        else
            cells+=("notices ($fails lines, $unfound unfound)")
        fi
    done
    printf '%-8s %-14s %-22s %s\n' "$name" "$verdict_real" "${cells[0]}" "${cells[1]}"
done

# ---- kernel_info/: one byte of every kind of file that `unpack` writes in it. "label|the file (a pattern for the path below the folder)|what to change (a regular
# expression whose first group is the byte; empty: the middle of the file)". summary.txt is told field by field: the middle of it is a line of the config
# that the driver does not read, which is no reason to say that the fields are not judged. initramfs.meta is the writer of the ramdisk folders, which the
# ramdisk drivers judge.
kinfo_targets=(
    "config|config|"
    "kallsyms.txt|kallsyms.txt|"
    "kallsyms.txt: the first line|kallsyms.txt|^(\w)"
    "payload.bin (zImage, bzImage)|payload.bin|"
    "initramfs.cpio|initramfs.cpio|"
    "initramfs/: a file|initramfs/etc/fstab|"
    "initramfs/: a file of the second|initramfs2/res/images/logo.bin|"
    "initramfs2.cpio (gzip in the kernel)|initramfs2.cpio|"
    "certs: the DER certificate|certs/*.der|"
    "certs: the PEM certificate|certs/01-*.pem|"
    "certs: the PEM key|certs/02-*.pem|"
    "certs: text, subject|certs/00-*.txt|subject:\\s+(\\w)"
    "certs: text, serial|certs/00-*.txt|serial:\\s+(\\w)"
    "certs: text, valid|certs/00-*.txt|valid:\\s+(\\d)"
    "certs: text, signature|certs/00-*.txt|signature:\\s+(\\w)"
    "certs: text, EC key|certs/00-*.txt|key:\\s+(\\w)"
    "certs: text, sha256|certs/00-*.txt|sha256:\\s+(\\w)"
    "certs: text, RSA key|certs/01-*.txt|key:\\s+RSA (\\d)"
    "certs: text of the key|certs/02-*.txt|(p)rivate key"
    "binaries: a tree|binaries/00_dtb_5000.dtb|"
    "binaries: the source of a tree|binaries/00_dtb_5000.dts|"
    "binaries: an ELF file|binaries/*.elf|"
    "binaries: a tree out of gzip|binaries/*_from_gzip.dtb|"
    "binaries: its source|binaries/*_from_gzip.dts|"
    "README.txt|README.txt|^(a)br kernel_info"
    "summary: kind and size|summary.txt|kind\\s+(\\w)"
    "summary: text_offset|summary.txt|text_offset\\s+0x(\\w)"
    "summary: image_size|summary.txt|image_size\\s+0x(\\w)"
    "summary: flags|summary.txt|flags\\s+0x(\\w)"
    "summary: release|summary.txt|release\\s+(\\S)"
    "summary: built by|summary.txt|built by\\s+(\\S)"
    "summary: compiler|summary.txt|compiler\\s+(\\S)"
    "summary: build|summary.txt|build\\s+(\\S)"
    "summary: vermagic|summary.txt|vermagic\\s+(\\S)"
    "summary: where the banner is|summary.txt|banner\\s+at 0x(\\w)"
    "summary: the banner|summary.txt|banner\\s+at 0x\\w+: (\\w)"
    "summary: an androidboot parameter|summary.txt|androidboot.verifiedbootstate(=)"
    "summary: where the config is|summary.txt|gzip stream at 0x(\\w)"
    "summary: the options of the config|summary.txt|(\\d+) options"
    "summary: the symbols|summary.txt|(\\d)\\d+ symbols;"
    "summary: byte order of the symbols|summary.txt|symbols; (l)ittle endian"
    "summary: the base of the offsets|summary.txt|offsets from the base 0x(\\w)"
    "summary: the kind of table|summary.txt|offsets (f)rom the base"
    "summary: symbols of text|summary.txt|(\\d+) of text"
    "summary: symbols of data|summary.txt|text \\(T t\\), (\\d)"
    "summary: the address of _text|summary.txt|  _text\\s+0x(\\w)"
    "summary: the address of linux_banner|summary.txt|linux_banner\\s+0x(\\w)"
    "summary: the model of a tree|summary.txt|model \"(\\w)"
    "summary: where the tables are|summary.txt|names at 0x(\\w)"
    "summary: where the initramfs is|summary.txt|INITRAMFS\\n  at 0x(\\w)"
    "summary: the kind of archive|summary.txt|at 0x\\w+: (c)pio archive"
    "summary: where a certificate is|summary.txt|at 0x(\\w+): DER CERTIFICATE"
    "summary: the size of a certificate|summary.txt|DER CERTIFICATE, (\\d)"
    "summary: where the PEM key is|summary.txt|at 0x(\\w+): PEM PRIVATE KEY"
    "summary: where a tree is|summary.txt|  at 0x(\\w+), \\d+ bytes: device tree"
    "summary: the ELF file|summary.txt|ELF 64-bit (l)ittle endian"
    "summary: a tree out of gzip|summary.txt|gzip stream of \\d+ bytes that holds a (d)evice tree"
)
if [ -n "${ABR_SABOTAGE_KINFO:-1}" ]; then
    printf '\n%-46s %s\n' "kernel_info/ (kinfo_live.py): one byte of" "the driver"
    rm -rf "$WORK/run_kinfo.real"
    python3 -I "$HERE/kinfo_live.py" "$ABR" "$WORK/run_kinfo.real" "$REAL_DIR" >"$WORK/kinfo_real.log" 2>&1
    if [ $? -ne 0 ]; then
        printf '%-46s %s\n' "the real abr" "FAILS (see $WORK/kinfo_real.log)"
        bad=1
    else
        printf '%-46s %s\n' "the real abr" "passes ($(tail -n 1 "$WORK/kinfo_real.log"))"
    fi
    n=0
    for target in "${kinfo_targets[@]}"; do
        IFS='|' read -r label file find <<<"$target"
        n=$((n + 1))
        # ABR_SABOTAGE_FILTER: an extended regular expression; only the targets whose label it matches are run (the logs keep the number of the whole list)
        if [ -n "${ABR_SABOTAGE_FILTER:-}" ] && ! grep -q -E -- "$ABR_SABOTAGE_FILTER" <<<"$label"; then continue; fi
        d="$WORK/run_kinfo.$n"
        rm -rf "$d"
        : >"$WORK/kinfo_$n.sab"
        ABR_REAL="$ABR" SAB=kinfo SAB_FILE="$file" SAB_FIND="$find" SAB_LOG="$WORK/kinfo_$n.sab" \
            python3 -I "$HERE/kinfo_live.py" "$SABOTAGE" "$d" - >"$WORK/kinfo_$n.log" 2>&1
        rc=$?
        changed=$(wc -l <"$WORK/kinfo_$n.sab")
        fails=$(grep -c -E '^FAIL|^Traceback|^AssertionError' "$WORK/kinfo_$n.log")
        if [ "$changed" -eq 0 ]; then
            printf '%-46s %s\n' "$label" "NOT APPLIED (no such file in any unpack: the pattern '$file' is wrong, or the driver does not make it)"
            bad=1
        elif [ $rc -eq 0 ]; then
            printf '%-46s %s\n' "$label" "NOT NOTICED ($changed bytes changed)"
            bad=1
        else
            printf '%-46s %s\n' "$label" "notices ($changed bytes changed, $fails lines)"
        fi
    done
fi

if [ $bad -eq 0 ]; then
    echo "every driver passes with the real abr and fails with the sabotaged ones"
else
    echo "NOT every driver behaved so: a driver that passes with a sabotaged abr, or fails with the real one, has to be looked at (logs in $WORK)"
fi
exit $bad
