# Cross-compilation toolchain for Android arm64-v8a.
#
# This wraps (rather than replaces) the Android NDK's own toolchain
# file, which is the correct way to target Android from CMake -- it
# already handles sysroot paths, clang target triples, and API-level
# flags correctly, and re-deriving that by hand is a common source of
# subtle bugs. This file just centralizes *this project's* choices on
# top of it.
#
# Usage:
#   cmake -S . -B build-android \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/android-arm64.cmake \
#     -DANDROID_NDK_HOME=/path/to/android-ndk \
#     -DABR_STATIC_BINARY=ON
# (or set the ANDROID_NDK_HOME *environment* variable instead of -D)
#
# Reminder (see PROGRESS.md): bionic has no static libc, so there is no
# such thing as a fully statically linked Android executable, and that
# is expected/correct, not a build failure to chase away. ABR_STATIC_BINARY
# on this target only adds -static-libstdc++; ANDROID_STL=c++_static
# below is what actually keeps the C++ runtime self-contained.

if(NOT ANDROID_NDK_HOME)
  set(ANDROID_NDK_HOME "$ENV{ANDROID_NDK_HOME}")
endif()
if(NOT ANDROID_NDK_HOME)
  message(FATAL_ERROR
    "ANDROID_NDK_HOME is not set. Pass -DANDROID_NDK_HOME=/path/to/android-ndk "
    "or export it in the environment before configuring.")
endif()

set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-24)   # first API level with full 64-bit ABI support
set(ANDROID_STL c++_static)        # statically link libc++; bionic libc itself is always shared

include(${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake)

# OpenSSL is not vendored/cross-built for Android in this project (see
# PROGRESS.md) -- disabled here for the same reason as the mingw
# toolchain file. AVB RSA re-signing (--avb-key) is unavailable on this
# build; everything else, including AVB passthrough repack, still works.
set(ABR_WITH_OPENSSL OFF CACHE BOOL "" FORCE)
