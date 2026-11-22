#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Do the judges notice? Runs the live drivers that judge the small firmware images (MediaTek, Qualcomm MBN, splash and logo pictures, QCDT, AML_, dtb) against the
# real abr and against two sabotaged copies of it (tests/tools/abr_sabotage.py): one that changes ONE byte of the image `pack` wrote, one that changes ONE byte
# of the biggest file `unpack` wrote. A driver has to pass with the real abr and to fail with both; one that passes with a sabotaged abr judges nothing.
#
#   tests/tools/sabotage_check.sh <abr> <work directory> [<boot_lk2nd.img, the real QCDT image> [<TWRP Recovery Amlogic S9xx.img, the real AML_ image>]]
#
# It needs what the suite needs for these drivers (python3 with Pillow and cryptography, dtc, the reference tools of tests/reference). Prints one line for every
# driver and ends with status 0 when every driver behaved so (1 when one did not, 2 when something could not be set up). ABR_LIVE_MUTANTS (default 2) is the
# number of damaged images each driver makes; the logs are <work directory>/<driver>.<real|pack|unpack>.log. (It runs for some minutes.)
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
rm -rf "$WORK/gen_splash" "$WORK/gen_mbn" "$WORK/gen_mtk_cont" "$WORK/gen_mtk_gfh" "$WORK/gen_mtk_boot"
gen splash python3 -I "$HERE/mk_splash.py" gen "$WORK/gen_splash"
gen mbn python3 -I "$HERE/mk_mbn.py" make "$WORK/gen_mbn"
gen mtk_cont python3 -I "$HERE/mk_mtk.py" make "$WORK/gen_mtk_cont"
gen mtk_gfh python3 -I "$HERE/mk_gfh.py" "$WORK/gen_mtk_gfh"
gen mtk_boot python3 -I "$HERE/mk_mtk.py" boot "$WORK/gen_mtk_boot" "$MKBOOTIMG"

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
printf '%-8s %-14s %-22s %-22s\n' driver "real abr" "pack: one byte" "unpack: one byte"
for name in splash rle mbn mtk qcdt aml dtb; do
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
if [ $bad -eq 0 ]; then
    echo "every driver passes with the real abr and fails with both sabotaged ones"
else
    echo "NOT every driver behaved so: a driver that passes with a sabotaged abr, or fails with the real one, has to be looked at (logs in $WORK)"
fi
exit $bad
