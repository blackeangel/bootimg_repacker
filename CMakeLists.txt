cmake_minimum_required(VERSION 3.20)
project(bootimg_repacker LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)

# Some vendored third-party CMakeLists.txt files (zlib/lz4/zstd/xz all
# have a long history) still declare an old cmake_minimum_required.
# CMake >= 4.0 hard-errors on anything below 3.5 unless told otherwise.
# This is a no-op (unrecognized cache variable) on older CMake, so it's
# safe to set unconditionally rather than only under a version guard.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)

# ---------------------------------------------------------------------------
# C++ language level.
#
# abr is a C++26 project. CMake's own CXX_STANDARD cannot be used for that: a
# release only maps "26" to a compiler flag once it knows the compiler, and
# CMake 3.28 does not know GCC's -std=c++26 at all (GCC itself accepts it from
# version 14; GCC 13 and older reject both -std=c++26 and -std=c++2c). So the
# flag is probed here, which also works unchanged for the cross toolchains.
#
#   -DABR_CXX_STANDARD=26   (default) GCC >= 14, Clang >= 17 (Android NDK r27+
#                           is Clang 18), MSVC with /std:c++latest
#   -DABR_CXX_STANDARD=23   for a toolchain that cannot do 26 yet (GCC 13 ...);
#                           nothing in abr needs a C++26-only feature, and the
#                           test suite is the same.
#
# The vendored C libraries are untouched (the flag is C++-only).
# ---------------------------------------------------------------------------
set(ABR_CXX_STANDARD "26" CACHE STRING
    "C++ standard to build abr with: 26 (baseline) or 23 (for compilers that cannot do 26 yet)")
set_property(CACHE ABR_CXX_STANDARD PROPERTY STRINGS 26 23)

include(CheckCXXCompilerFlag)
if(MSVC)
  set(_abr_std_candidates "/std:c++latest")
elseif(ABR_CXX_STANDARD STREQUAL "26")
  set(_abr_std_candidates "-std=gnu++26" "-std=gnu++2c")
elseif(ABR_CXX_STANDARD STREQUAL "23")
  set(_abr_std_candidates "-std=gnu++23" "-std=gnu++2b")
else()
  message(FATAL_ERROR "ABR_CXX_STANDARD must be 26 or 23, not '${ABR_CXX_STANDARD}'")
endif()
set(ABR_CXX_STD_FLAG "")
foreach(_flag IN LISTS _abr_std_candidates)
  string(MAKE_C_IDENTIFIER "ABR_ACCEPTS_${_flag}" _var)
  check_cxx_compiler_flag("${_flag}" ${_var})
  if(${_var})
    set(ABR_CXX_STD_FLAG "${_flag}")
    break()
  endif()
endforeach()
if(NOT ABR_CXX_STD_FLAG)
  message(FATAL_ERROR
    "abr is built as C++${ABR_CXX_STANDARD}, and this compiler (${CMAKE_CXX_COMPILER_ID} "
    "${CMAKE_CXX_COMPILER_VERSION}) accepts none of: ${_abr_std_candidates}.\n"
    "Use GCC >= 14, Clang >= 17 (the Android NDK r27+ qualifies) or MSVC, e.g. "
    "-DCMAKE_CXX_COMPILER=g++-14 (Ubuntu 24.04: apt install g++-14); or, if only an older "
    "compiler is at hand, configure with -DABR_CXX_STANDARD=23.")
endif()
message(STATUS "abr: C++ language level ${ABR_CXX_STANDARD} via ${ABR_CXX_STD_FLAG}")
add_library(abr_cxx_std INTERFACE)
target_compile_options(abr_cxx_std INTERFACE "$<$<COMPILE_LANGUAGE:CXX>:${ABR_CXX_STD_FLAG}>")

option(ABR_BUILD_TESTS
       "Build abr_unit_tests, the driver tests/run_tests.sh uses to check the self-contained crypto (BigInt/RSA/DER/SHA), the thread helper and the cpio/ramdisk-directory code. Off for cross builds." ON)
option(ABR_VENDOR_DEPS
       "Fetch and statically build zlib/lz4/zstd/xz/bzip2 from source (the shipping default). Turn OFF to use system dev packages instead, for fast local iteration." ON)
option(ABR_STATIC_BINARY
       "Link the abr executable statically (-static on Linux; -static-libgcc/-static-libstdc++ on Windows/Android, since bionic has no static libc to link against in the first place)." OFF)

include(FetchContent)

set(ABR_ZLIB_VERSION   "1.3.2"  CACHE STRING "")
set(ABR_LZ4_VERSION    "1.10.0" CACHE STRING "")
set(ABR_ZSTD_VERSION   "1.5.7"  CACHE STRING "")
set(ABR_XZ_VERSION     "5.8.4"  CACHE STRING "")
set(ABR_BZIP2_VERSION  "1.0.8"  CACHE STRING "")

if(ABR_VENDOR_DEPS)
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/vendor_deps.cmake)
else()
  find_package(ZLIB REQUIRED)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LZ4 REQUIRED IMPORTED_TARGET liblz4)
  pkg_check_modules(ZSTD REQUIRED IMPORTED_TARGET libzstd)
  pkg_check_modules(LZMA REQUIRED IMPORTED_TARGET liblzma)
  pkg_check_modules(BZIP2 REQUIRED IMPORTED_TARGET bzip2)
  pkg_check_modules(LZO REQUIRED IMPORTED_TARGET lzo2)
  add_library(abr_zlib_iface INTERFACE)
  target_link_libraries(abr_zlib_iface INTERFACE ZLIB::ZLIB)
  add_library(abr_lz4_iface INTERFACE)
  target_link_libraries(abr_lz4_iface INTERFACE PkgConfig::LZ4)
  add_library(abr_zstd_iface INTERFACE)
  target_link_libraries(abr_zstd_iface INTERFACE PkgConfig::ZSTD)
  add_library(abr_lzma_iface INTERFACE)
  target_link_libraries(abr_lzma_iface INTERFACE PkgConfig::LZMA)
  add_library(abr_bz2_iface INTERFACE)
  target_link_libraries(abr_bz2_iface INTERFACE PkgConfig::BZIP2)
  add_library(abr_lzo_iface INTERFACE)
  target_link_libraries(abr_lzo_iface INTERFACE PkgConfig::LZO)
endif()

add_library(abr_core STATIC
  src/byte_io.cpp
  src/compression.cpp
  src/parallel.cpp
  src/sha.cpp
  src/boot_image.cpp
  src/vendor_boot.cpp
  src/dtbo.cpp
  src/dtb.cpp
  src/vbmeta.cpp
  src/uimage.cpp
  src/manifest.cpp
  src/envelope.cpp
  src/cpio.cpp
  src/ramdisk_tree.cpp
  src/identify.cpp
  src/bigint.cpp
  src/asn1.cpp
  src/rsa.cpp
  src/legacy/mtk.cpp
  src/legacy/dhtb.cpp
  src/legacy/elf_boot.cpp
  src/legacy/avb1.cpp
  src/legacy/avb1_aosp_key.cpp
)
target_include_directories(abr_core PUBLIC include)
target_link_libraries(abr_core PUBLIC
  abr_cxx_std
  abr_zlib_iface
  abr_lz4_iface
  abr_zstd_iface
  abr_lzma_iface
  abr_bz2_iface
  abr_lzo_iface
)

# Threads: abr runs independent work (decompressing / hashing / compressing the
# components of an image) on several cores, see include/abr/parallel.hpp.
# glibc >= 2.34, bionic and the macOS libc need no extra library; the MinGW
# runtime keeps std::thread in winpthread, which -- statically linked -- must be
# pulled in whole or its thread-exit (TLS destructor) hook is dropped.
if(WIN32 AND NOT MSVC)
  target_link_libraries(abr_core PUBLIC -Wl,--whole-archive winpthread -Wl,--no-whole-archive)
else()
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
  target_link_libraries(abr_core PUBLIC Threads::Threads)
  if(ABR_STATIC_BINARY AND UNIX AND NOT ANDROID AND NOT APPLE)
    # A static glibc older than 2.34 keeps pthread in libpthread.a, whose weak
    # references a plain -static link leaves unresolved (std::thread then fails
    # at run time with "Enable multithreading to use std::thread"). Newer glibc
    # and musl ship an empty libpthread.a, so pulling it in whole is harmless.
    find_library(ABR_STATIC_PTHREAD NAMES libpthread.a)
    if(ABR_STATIC_PTHREAD)
      target_link_libraries(abr_core PUBLIC -Wl,--whole-archive ${ABR_STATIC_PTHREAD} -Wl,--no-whole-archive)
    endif()
  endif()
endif()

# One place for what "static" means per platform.
function(abr_link_statically target)
  if(NOT ABR_STATIC_BINARY)
    return()
  endif()
  if(WIN32)
    target_link_options(${target} PRIVATE -static -static-libgcc -static-libstdc++)
  elseif(ANDROID)
    # Bionic itself is never statically linked (there is no static libc on
    # Android) -- ANDROID_STL=c++_static (set via the NDK toolchain file)
    # is what actually makes this "static" in the sense that matters:
    # no dependency on any .so beyond what every Android system provides.
    target_link_options(${target} PRIVATE -static-libstdc++)
  else()
    target_link_options(${target} PRIVATE -static)
  endif()
endfunction()

add_executable(abr src/main.cpp)
target_link_libraries(abr PRIVATE abr_core)
abr_link_statically(abr)

if(ABR_BUILD_TESTS)
  add_executable(abr_unit_tests tests/unit/crypto_test.cpp tests/unit/par_test.cpp tests/unit/cpio_test.cpp)
  target_link_libraries(abr_unit_tests PRIVATE abr_core)
  abr_link_statically(abr_unit_tests)
endif()

install(TARGETS abr RUNTIME DESTINATION bin)
