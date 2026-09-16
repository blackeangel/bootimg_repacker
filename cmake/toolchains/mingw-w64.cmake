# Cross-compilation toolchain for Windows x86_64 via mingw-w64.
#
# Usage:
#   cmake -S . -B build-windows \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64.cmake \
#     -DABR_STATIC_BINARY=ON
#
# Expects the mingw-w64 cross toolchain to be installed and on PATH
# (Debian/Ubuntu: `apt-get install mingw-w64`, package `g++-mingw-w64-x86-64`).

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(ABR_MINGW_PREFIX x86_64-w64-mingw32)

set(CMAKE_C_COMPILER   ${ABR_MINGW_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${ABR_MINGW_PREFIX}-g++)
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

# OpenSSL is not vendored/cross-built for Windows in this project (see
# PROGRESS.md) -- disable it here rather than let a stray host libcrypto.so
# get found and silently produce a binary that can't actually load on
# Windows. AVB RSA re-signing (--avb-key) is simply unavailable on this
# build; everything else (including AVB passthrough repack) is unaffected.
set(ABR_WITH_OPENSSL OFF CACHE BOOL "" FORCE)
