# Vendors zlib, lz4, zstd, xz (liblzma) and bzip2 as static libraries
# built from source, so the final `abr` binary doesn't depend on any
# system shared library for these. Each block sets that library's own
# CMake options *before* FetchContent_MakeAvailable so it never has a
# chance to build (or link against) a shared library instead.
#
# Target names below (zlibstatic, lz4_static, libzstd_static, liblzma)
# come from each project's own CMakeLists.txt and were confirmed by an
# actual local FetchContent+build run in the Claude sandbox against the
# pinned versions in the parent CMakeLists -- if a future version
# renames one, `cmake --build` will fail with an "unknown target" error
# pointing straight at the line to fix here.

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

# ------------------------------------------------------------------ zlib --
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
FetchContent_MakeAvailable(lz4_vendor)
target_include_directories(lz4_static PUBLIC $<BUILD_INTERFACE:${lz4_vendor_SOURCE_DIR}/lib>)
add_library(abr_lz4_iface INTERFACE)
target_link_libraries(abr_lz4_iface INTERFACE lz4_static)

# ------------------------------------------------------------------ zstd --
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
set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd_vendor)
target_include_directories(libzstd_static PUBLIC $<BUILD_INTERFACE:${zstd_vendor_SOURCE_DIR}/lib>)
add_library(abr_zstd_iface INTERFACE)
target_link_libraries(abr_zstd_iface INTERFACE libzstd_static)

# ------------------------------------------------------------ xz/liblzma --
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
add_library(abr_lzma_iface INTERFACE)
target_link_libraries(abr_lzma_iface INTERFACE liblzma)

# ----------------------------------------------------------------- bzip2 --
# bzip2 (this mirror at least) ships no CMakeLists.txt at all, so we
# populate the source only and compile the handful of library .c files
# ourselves -- also sidesteps the "old cmake_minimum_required" problem
# entirely since we never run bzip2's own build system.
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
# miniLZO is committed directly under third_party/minilzo/ rather than
# fetched (see third_party/minilzo/README.md for why): it's small,
# stable, and has no CMakeLists.txt of its own either way, so there's
# no FetchContent step to gain by pulling it over the network here.
add_library(lzo_static STATIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/minilzo/minilzo.c)
target_include_directories(lzo_static PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/minilzo>)
add_library(abr_lzo_iface INTERFACE)
target_link_libraries(abr_lzo_iface INTERFACE lzo_static)
