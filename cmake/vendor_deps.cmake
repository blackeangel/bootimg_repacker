# Vendors zlib, lz4, zstd, xz (liblzma), bzip2 and LZO as static libraries
# built from source, so the final `abr` binary doesn't depend on any
# system shared library for these. Each block sets that library's own
# CMake options *before* FetchContent_MakeAvailable so it never has a
# chance to build (or link against) a shared library instead. The
# versions are in cmake/dependency_versions.cmake (LZO's, 2.10, is the
# copy in third_party/lzo).
#
# Target names below (zlibstatic, lz4_static, libzstd_static, liblzma)
# come from each project's own CMakeLists.txt and were confirmed by an
# actual local FetchContent+build run in the Claude sandbox against the
# pinned versions in the parent CMakeLists -- if a future version
# renames one, `cmake --build` will fail with an "unknown target" error
# pointing straight at the line to fix here.

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

# -DABR_DEPS_LATEST=ON: the newest release that `repo` tags, in place of the version of cmake/dependency_versions.cmake. A release is a tag of
# `tag_prefix` and a version of two or three numbers (v1.4, v1.11.1, bzip2-1.0.8); what has anything else in it (v1.5.7-kernel, v5.7.2beta,
# v1.3.1.2 -- zlib's snapshots between two releases) is not one. A repository that cannot be asked leaves the version as it is, with a warning.
# (tools/check_deps.py asks the same way, and says which library of cmake/dependency_versions.cmake is behind.)
function(abr_newest_version var repo tag_prefix)
  if(NOT ABR_DEPS_LATEST)
    return()
  endif()
  find_package(Git REQUIRED)
  execute_process(COMMAND "${GIT_EXECUTABLE}" ls-remote --tags --refs "${repo}"
                  OUTPUT_VARIABLE _tags ERROR_VARIABLE _err RESULT_VARIABLE _rc TIMEOUT 120)
  if(NOT _rc EQUAL 0)
    message(WARNING "abr: cannot ask ${repo} for its releases (${_err}); ${var} stays ${${var}}")
    return()
  endif()
  string(REPLACE "\n" ";" _lines "${_tags}")
  set(_versions "")
  foreach(_line IN LISTS _lines)
    if(_line MATCHES "refs/tags/${tag_prefix}([0-9]+(\\.[0-9]+(\\.[0-9]+)?))$")
      list(APPEND _versions "${CMAKE_MATCH_1}")
    endif()
  endforeach()
  if(NOT _versions)
    message(WARNING "abr: ${repo} tags no release named ${tag_prefix}<version>; ${var} stays ${${var}}")
    return()
  endif()
  list(SORT _versions COMPARE NATURAL)
  list(GET _versions -1 _newest)
  message(STATUS "abr: ${var} ${_newest} (the newest release of ${repo}; cmake/dependency_versions.cmake has ${${var}})")
  set(${var} "${_newest}" PARENT_SCOPE)
endfunction()

# ------------------------------------------------------------------ zlib --
abr_newest_version(ABR_ZLIB_VERSION https://github.com/madler/zlib.git v)
FetchContent_Declare(zlib_vendor
  GIT_REPOSITORY https://github.com/madler/zlib.git
  GIT_TAG        v${ABR_ZLIB_VERSION}
  GIT_SHALLOW    TRUE
)
set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZLIB_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zlib_vendor)
# Older zlib CMakeLists use directory-scoped include_directories() rather
# than target_include_directories(), which doesn't reliably propagate to
# consumers outside that subdirectory -- set it explicitly ourselves so
# it works regardless. zconf.h is generated into the binary dir.
target_include_directories(zlibstatic PUBLIC
  $<BUILD_INTERFACE:${zlib_vendor_SOURCE_DIR}>
  $<BUILD_INTERFACE:${zlib_vendor_BINARY_DIR}>
)
add_library(abr_zlib_iface INTERFACE)
target_link_libraries(abr_zlib_iface INTERFACE zlibstatic)

# ------------------------------------------------------------------- lz4 --
abr_newest_version(ABR_LZ4_VERSION https://github.com/lz4/lz4.git v)
FetchContent_Declare(lz4_vendor
  GIT_REPOSITORY https://github.com/lz4/lz4.git
  GIT_TAG        v${ABR_LZ4_VERSION}
  GIT_SHALLOW    TRUE
  SOURCE_SUBDIR  build/cmake
)
set(LZ4_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LZ4_BUILD_LEGACY_LZ4C OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
# lz4 1.11 compresses a frame on several threads (LZ4F_preferences_t.nbWorkers); its static library is built without that unless it is
# asked to (the option does not exist before 1.11, where it does nothing). The frame is the same for any number of workers and with or
# without the support -- see src/compression.cpp.
set(LZ4_STATIC_MULTITHREAD ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(lz4_vendor)
target_include_directories(lz4_static PUBLIC $<BUILD_INTERFACE:${lz4_vendor_SOURCE_DIR}/lib>)
add_library(abr_lz4_iface INTERFACE)
target_link_libraries(abr_lz4_iface INTERFACE lz4_static)

# ------------------------------------------------------------------ zstd --
abr_newest_version(ABR_ZSTD_VERSION https://github.com/facebook/zstd.git v)
FetchContent_Declare(zstd_vendor
  GIT_REPOSITORY https://github.com/facebook/zstd.git
  GIT_TAG        v${ABR_ZSTD_VERSION}
  GIT_SHALLOW    TRUE
  SOURCE_SUBDIR  build/cmake
)
set(ZSTD_BUILD_STATIC ON  CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)
# zstd can compress one frame on several threads (ZSTD_c_nbWorkers). The output
# for nbWorkers >= 1 does not depend on how many workers there are, which is what
# lets abr use it without making its output depend on the machine -- see
# src/compression.cpp and the thread-count checks in tests/run_tests.sh.
set(ZSTD_MULTITHREAD_SUPPORT ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd_vendor)
target_include_directories(libzstd_static PUBLIC $<BUILD_INTERFACE:${zstd_vendor_SOURCE_DIR}/lib>)
add_library(abr_zstd_iface INTERFACE)
target_link_libraries(abr_zstd_iface INTERFACE libzstd_static)

# ------------------------------------------------------------ xz/liblzma --
abr_newest_version(ABR_XZ_VERSION https://github.com/tukaani-project/xz.git v)
FetchContent_Declare(xz_vendor
  GIT_REPOSITORY https://github.com/tukaani-project/xz.git
  GIT_TAG        v${ABR_XZ_VERSION}
  GIT_SHALLOW    TRUE
)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_NLS OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_XZ OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_XZDEC OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_LZMADEC OFF CACHE BOOL "" FORCE)
set(XZ_TOOL_LZMAINFO OFF CACHE BOOL "" FORCE)
set(XZ_NLS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(xz_vendor)
target_include_directories(liblzma PUBLIC
  $<BUILD_INTERFACE:${xz_vendor_SOURCE_DIR}/src/liblzma/api>)
add_library(abr_lzma_iface INTERFACE)
target_link_libraries(abr_lzma_iface INTERFACE liblzma)

# ----------------------------------------------------------------- bzip2 --
# bzip2 (this mirror at least) ships no CMakeLists.txt at all, so we
# populate the source only and compile the handful of library .c files
# ourselves -- also sidesteps the "old cmake_minimum_required" problem
# entirely since we never run bzip2's own build system.
abr_newest_version(ABR_BZIP2_VERSION https://github.com/libarchive/bzip2.git bzip2-)
FetchContent_Declare(bzip2_vendor
  GIT_REPOSITORY https://github.com/libarchive/bzip2.git
  GIT_TAG        bzip2-${ABR_BZIP2_VERSION}
  GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(bzip2_vendor)
if(NOT bzip2_vendor_POPULATED)
  FetchContent_Populate(bzip2_vendor)
endif()
add_library(bz2_static STATIC
  ${bzip2_vendor_SOURCE_DIR}/blocksort.c
  ${bzip2_vendor_SOURCE_DIR}/huffman.c
  ${bzip2_vendor_SOURCE_DIR}/crctable.c
  ${bzip2_vendor_SOURCE_DIR}/randtable.c
  ${bzip2_vendor_SOURCE_DIR}/compress.c
  ${bzip2_vendor_SOURCE_DIR}/decompress.c
  ${bzip2_vendor_SOURCE_DIR}/bzlib.c
)
target_include_directories(bz2_static PUBLIC $<BUILD_INTERFACE:${bzip2_vendor_SOURCE_DIR}>)
add_library(abr_bz2_iface INTERFACE)
target_link_libraries(abr_bz2_iface INTERFACE bz2_static)

# ------------------------------------------------------------------ lzo --
# The LZO1X family of LZO 2.10, the library's latest release, is committed under third_party/lzo/ rather than fetched (see its README.md):
# the library has no repository, only release tarballs, and the files are what a GPL-2.0-or-later library puts in a GPL-3.0-or-later
# project. The compressors LZO1X-1, LZO1X-1(15) and LZO1X-999 (levels 1 to 9), the optimizer of compressed blocks (lzo1x_optimize, which `lzop`
# runs on the blocks of the dense compressor) and the decompressors; not the other families of LZO.
set(ABR_LZO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lzo)
add_library(lzo_static STATIC
  ${ABR_LZO_DIR}/src/lzo_init.c
  ${ABR_LZO_DIR}/src/lzo_ptr.c
  ${ABR_LZO_DIR}/src/lzo_str.c
  ${ABR_LZO_DIR}/src/lzo_util.c
  ${ABR_LZO_DIR}/src/lzo1x_1.c
  ${ABR_LZO_DIR}/src/lzo1x_1o.c
  ${ABR_LZO_DIR}/src/lzo1x_9x.c
  ${ABR_LZO_DIR}/src/lzo1x_o.c
  ${ABR_LZO_DIR}/src/lzo1x_d1.c
  ${ABR_LZO_DIR}/src/lzo1x_d2.c)
target_include_directories(lzo_static
  PUBLIC  $<BUILD_INTERFACE:${ABR_LZO_DIR}/include>
  PRIVATE ${ABR_LZO_DIR}/src)
add_library(abr_lzo_iface INTERFACE)
target_link_libraries(abr_lzo_iface INTERFACE lzo_static)
