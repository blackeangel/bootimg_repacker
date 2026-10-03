# Cross-compilation toolchain for Windows x86_64 that can build C++26:
# Clang targeting x86_64-w64-mingw32, on top of the distribution's mingw-w64
# headers, C runtime and libstdc++ (posix thread model, so std::thread works).
#
# Why not simply the mingw-w64 GCC? Debian/Ubuntu ship GCC 13 for it, and
# GCC only has a C++26 mode from version 14; Clang has had one since 17, and
# it is happy to compile against libstdc++ 13's headers. Everything stays in
# one apt install -- no toolchain download:
#
#   sudo apt-get install clang-20 lld-20 mingw-w64 g++-mingw-w64-x86-64-posix
#
# Usage:
#   cmake -S . -B build-windows -G Ninja \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64-clang.cmake \
#     -DCMAKE_BUILD_TYPE=Release -DABR_STATIC_BINARY=ON
#
# The result is a single static .exe (no MinGW runtime DLLs); tests/run_tests.sh
# can run it under wine -- see the README. cmake/toolchains/mingw-w64.cmake is
# the plain GCC variant, for -DABR_CXX_STANDARD=23.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(ABR_MINGW_TRIPLE x86_64-w64-mingw32)
set(ABR_MINGW_SYSROOT /usr/${ABR_MINGW_TRIPLE} CACHE PATH "mingw-w64 sysroot (headers + C runtime)")

# The newest posix-model GCC runtime directory: libstdc++ headers, libstdc++.a,
# libgcc.a. (The win32-model one has no std::thread.)
file(GLOB _abr_gcc_dirs "/usr/lib/gcc/${ABR_MINGW_TRIPLE}/*-posix")
if(NOT _abr_gcc_dirs)
  message(FATAL_ERROR
    "No /usr/lib/gcc/${ABR_MINGW_TRIPLE}/*-posix directory: install g++-mingw-w64-x86-64-posix "
    "(Debian/Ubuntu: sudo apt-get install mingw-w64 g++-mingw-w64-x86-64-posix).")
endif()
list(SORT _abr_gcc_dirs COMPARE NATURAL)
list(GET _abr_gcc_dirs -1 ABR_MINGW_GCC_DIR)

find_program(ABR_CLANG   NAMES clang-22 clang-21 clang-20 clang-19 clang-18 clang)
find_program(ABR_CLANGXX NAMES clang++-22 clang++-21 clang++-20 clang++-19 clang++-18 clang++)
if(NOT ABR_CLANG OR NOT ABR_CLANGXX)
  message(FATAL_ERROR "clang/clang++ not found (Debian/Ubuntu: sudo apt-get install clang-20 lld-20)")
endif()

set(CMAKE_C_COMPILER   ${ABR_CLANG})
set(CMAKE_CXX_COMPILER ${ABR_CLANGXX})
set(CMAKE_C_COMPILER_TARGET   ${ABR_MINGW_TRIPLE})
set(CMAKE_CXX_COMPILER_TARGET ${ABR_MINGW_TRIPLE})
set(CMAKE_SYSROOT ${ABR_MINGW_SYSROOT})

set(CMAKE_AR     ${ABR_MINGW_TRIPLE}-ar     CACHE FILEPATH "")
set(CMAKE_RANLIB ${ABR_MINGW_TRIPLE}-ranlib CACHE FILEPATH "")

# Clang does not find the mingw libstdc++ by itself, so say where it is.
set(CMAKE_CXX_FLAGS_INIT
    "-nostdinc++ -isystem ${ABR_MINGW_GCC_DIR}/include/c++ -isystem ${ABR_MINGW_GCC_DIR}/include/c++/${ABR_MINGW_TRIPLE} -isystem ${ABR_MINGW_GCC_DIR}/include/c++/backward")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld -B${ABR_MINGW_GCC_DIR} -L${ABR_MINGW_GCC_DIR}")

set(CMAKE_FIND_ROOT_PATH ${ABR_MINGW_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# The .exe runs under wine, so the unit-test driver is worth building too.
