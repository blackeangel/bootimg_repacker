# Cross-compilation toolchain for Windows x86_64 via the mingw-w64 GCC.
#
# The primary Windows build is cmake/toolchains/mingw-w64-clang.cmake (C++26).
# This one is the plain-GCC variant for when GCC is what you have: Debian and
# Ubuntu ship GCC 13 for mingw-w64, which has no C++26 mode, so it defaults to
# C++23 (nothing in abr needs more; override with -DABR_CXX_STANDARD=26 on a
# GCC >= 14 mingw toolchain).
#
# Usage:
#   cmake -S . -B build-windows \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64.cmake \
#     -DABR_STATIC_BINARY=ON
#
# Expects the mingw-w64 cross toolchain to be installed and on PATH
# (Debian/Ubuntu: `apt-get install mingw-w64 g++-mingw-w64-x86-64-posix`).
# The *posix* thread model is required: the default "win32" one has no
# std::thread.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(ABR_MINGW_PREFIX x86_64-w64-mingw32)

set(ABR_CXX_STANDARD "23" CACHE STRING "C++ standard to build abr with (26 needs a GCC >= 14 mingw toolchain)")

set(CMAKE_C_COMPILER   ${ABR_MINGW_PREFIX}-gcc-posix)
set(CMAKE_CXX_COMPILER ${ABR_MINGW_PREFIX}-g++-posix)
set(CMAKE_RC_COMPILER  ${ABR_MINGW_PREFIX}-windres)
set(CMAKE_AR           ${ABR_MINGW_PREFIX}-ar CACHE FILEPATH "")
set(CMAKE_RANLIB       ${ABR_MINGW_PREFIX}-ranlib CACHE FILEPATH "")

# Where the cross sysroot's own libraries/headers live, so FetchContent-built
# dependencies and any find_package() calls resolve mingw versions of things
# rather than accidentally picking up host (x86_64-linux-gnu) libraries.
set(CMAKE_FIND_ROOT_PATH /usr/${ABR_MINGW_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# The unit-test driver (abr_unit_tests.exe) is built too: tests/run_tests.sh
# runs the .exe files under wine.
