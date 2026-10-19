#!/usr/bin/env bash
# The judges of the test suite, fetched and compiled from their sources.
#
# tests/run_tests.sh compares abr with the programs Android Image Kitchen runs for the formats abr opens by itself: rkcrc
# (Rockchip), blobpack and blobunpack (ASUS blobs), mboot (Intel OSIP), loki_tool (LOKI), pxa-mkbootimg and pxa-unpackbootimg
# (Marvell PXA), sony_dump (Sony SIN) and elftool (Sony ELF boot images). None of them is part of this repository, and several
# have no licence file: they are fetched at the commits the tests were written against, compiled here, and the suite only runs
# them -- nothing of them goes into abr.
#
#     .github/scripts/build_oracles.sh <directory> [name ...]
#
# builds into <directory>/bin (every one, or the names given: rkcrc blobtools mboot loki pxa sony_dump elftool) and prints one
# VARIABLE=/path line on stdout for each program that was built -- the variables tests/run_tests.sh reads (ABR_RKCRC, ABR_BLOBPACK,
# ABR_BLOBUNPACK, ABR_MBOOT, ABR_LOKI_TOOL, PXA_MKBOOTIMG, PXA_UNPACKBOOTIMG, ABR_SONY_DUMP, ABR_ELFTOOL). In GitHub Actions:
#
#     .github/scripts/build_oracles.sh "$RUNNER_TEMP/oracles" | tee -a "$GITHUB_ENV"
#
# What goes wrong is said on stderr, and the exit status is 1 if any of them could not be built; the others are built all the same.
# (Needs git, gcc, g++, make and the zlib headers.)
set -u

out="$(realpath -m "${1:?usage: build_oracles.sh <directory> [name ...]}")"
shift
mkdir -p "$out/bin" "$out/src" || exit 1
failed=0

say() { echo "build_oracles: $*" >&2; }

# fetch <name> <url> <commit>: the sources of the repository at that commit, in $out/src/<name>
fetch() {
    local dir="$out/src/$1"
    rm -rf "$dir" && mkdir -p "$dir" &&
        git -C "$dir" init -q &&
        git -C "$dir" fetch -q --depth 1 "$2" "$3" &&
        git -C "$dir" checkout -q FETCH_HEAD
}

# done_with <name> <VARIABLE=file>...: say what was built (the files have to be there)
announce() {
    local name="$1" pair
    shift
    for pair in "$@"; do
        [ -x "${pair#*=}" ] || {
            say "$name: ${pair#*=} was not made"
            return 1
        }
    done
    for pair in "$@"; do echo "$pair"; done
    say "$name: built"
}

build_rkcrc() {  # rkflashtool (BSD)
    fetch rkflashtool https://github.com/linux-rockchip/rkflashtool.git fc2181c577ef3fb1e821818dfd07e0dac0575b74 &&
        gcc -O2 -w -o "$out/bin/rkcrc" "$out/src/rkflashtool/rkcrc.c" &&
        announce rkcrc "ABR_RKCRC=$out/bin/rkcrc"
}

build_blobtools() {  # AndroidRoot/BlobTools (Apache-2.0)
    local s="$out/src/BlobTools"
    fetch BlobTools https://github.com/AndroidRoot/BlobTools.git 6186e33baa10ce6f1c738d7b91eb5153743105af &&
        g++ -O2 -w -I "$s/shared" -o "$out/bin/blobpack" "$s/src/blobpack.cpp" &&
        g++ -O2 -w -I "$s/shared" -o "$out/bin/blobunpack" "$s/src/blobunpack.cpp" &&
        announce blobtools "ABR_BLOBPACK=$out/bin/blobpack" "ABR_BLOBUNPACK=$out/bin/blobunpack"
}

build_mboot() {  # osm0sis/mboot (GPL-2.0)
    fetch mboot https://github.com/osm0sis/mboot.git 39f59a4f1b6a754c8953172fb80cb2ea1221ed20 &&
        gcc -O2 -w -o "$out/bin/mboot" "$out/src/mboot/mboot.c" &&
        announce mboot "ABR_MBOOT=$out/bin/mboot"
}

build_loki() {  # djrbliss/loki (BSD-2-Clause)
    fetch loki https://github.com/djrbliss/loki.git 784e86f981b7b1c30bd0d6b401f071e47e738eb8 &&
        (cd "$out/src/loki" && gcc -O2 -w -o "$out/bin/loki_tool" main.c loki_flash.c loki_find.c loki_patch.c loki_unlok.c) &&
        announce loki "ABR_LOKI_TOOL=$out/bin/loki_tool"
}

build_pxa() {  # osm0sis/pxa-mkbootimg
    local s="$out/src/pxa-mkbootimg"
    fetch pxa-mkbootimg https://github.com/osm0sis/pxa-mkbootimg.git 97d9e1fc9222f820eb434fae2c93b892eef3805d &&
        make -s -C "$s" pxa-mkbootimg pxa-unpackbootimg CFLAGS=-w >&2 &&
        cp "$s/pxa-mkbootimg" "$s/pxa-unpackbootimg" "$out/bin/" &&
        announce pxa "PXA_MKBOOTIMG=$out/bin/pxa-mkbootimg" "PXA_UNPACKBOOTIMG=$out/bin/pxa-unpackbootimg"
}

build_sony_dump() {  # munjeni/anyxperia_dumper (no licence file)
    local s="$out/src/anyxperia_dumper"
    fetch anyxperia_dumper https://github.com/munjeni/anyxperia_dumper.git 2171258c9df50aba139b4bd1aa93295cd14d2262 &&
        (cd "$s" && gcc -O2 -w -Iinclude -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE=1 \
            sony_dump.c lz4.c unpackbootimg.c untar.c -lz -o "$out/bin/sony_dump") &&
        announce sony_dump "ABR_SONY_DUMP=$out/bin/sony_dump"
}

build_elftool() {  # osm0sis/elftool (srl3gx's; no licence text in its sources)
    fetch elftool https://github.com/osm0sis/elftool.git 363653ee89d7b4e1cd5e1f2c878d71acd75fc072 &&
        g++ -O2 -w -o "$out/bin/elftool" "$out/src/elftool/elftool.cpp" &&
        announce elftool "ABR_ELFTOOL=$out/bin/elftool"
}

names=("$@")
[ ${#names[@]} -gt 0 ] || names=(rkcrc blobtools mboot loki pxa sony_dump elftool)
for n in "${names[@]}"; do
    case "$n" in
        rkcrc | blobtools | mboot | loki | pxa | sony_dump | elftool) ;;
        *)
            say "unknown name: $n"
            failed=1
            continue
            ;;
    esac
    if ! "build_$n"; then
        say "$n: could not be built"
        failed=1
    fi
done
exit "$failed"
