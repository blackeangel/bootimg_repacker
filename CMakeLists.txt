cmake_minimum_required(VERSION 3.20)
project(bootimg_repacker LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)

# Some vendored third-party CMakeLists.txt files (zlib/lz4/zstd/xz all
# have a long history) still declare an old cmake_minimum_required.
# CMake >= 4.0 hard-errors on anything below 3.5 unless told otherwise.
# This is a no-op (unrecognized cache variable) on older CMake, so it's
# safe to set unconditionally rather than only under a version guard.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)

option(ABR_WITH_OPENSSL
       "Enable OpenSSL for AVB RSA re-signing (--avb-key). Hashing (boot id, AVB digest) always uses the bundled dependency-free SHA-1/256/512 and does not need this." ON)
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
  src/sha.cpp
  src/boot_image.cpp
  src/vendor_boot.cpp
  src/dtbo.cpp
  src/dtb.cpp
  src/vbmeta.cpp
  src/uimage.cpp
  src/manifest.cpp
  src/legacy/mtk.cpp
  src/legacy/dhtb.cpp
)
target_include_directories(abr_core PUBLIC include)
target_link_libraries(abr_core PUBLIC
  abr_zlib_iface
  abr_lz4_iface
  abr_zstd_iface
  abr_lzma_iface
  abr_bz2_iface
  abr_lzo_iface
)

if(ABR_WITH_OPENSSL)
  if(ABR_STATIC_BINARY)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
  endif()
  find_package(OpenSSL QUIET)
  if(OpenSSL_FOUND)
    target_compile_definitions(abr_core PUBLIC ABR_WITH_OPENSSL=1)
    target_link_libraries(abr_core PUBLIC OpenSSL::Crypto)
    message(STATUS "bootimg_repacker: OpenSSL found -- AVB RSA re-signing (--avb-key) enabled")
  else()
    message(STATUS "bootimg_repacker: OpenSSL not found -- building without AVB RSA re-signing "
                    "(everything else, including AVB passthrough repack, is unaffected)")
  endif()
endif()

add_executable(abr src/main.cpp)
target_link_libraries(abr PRIVATE abr_core)

if(ABR_STATIC_BINARY)
  if(WIN32)
    target_link_options(abr PRIVATE -static -static-libgcc -static-libstdc++)
  elseif(ANDROID)
    # Bionic itself is never statically linked (there is no static libc on
    # Android) -- ANDROID_STL=c++_static (set via the NDK toolchain file)
    # is what actually makes this "static" in the sense that matters:
    # no dependency on any .so beyond what every Android system provides.
    target_link_options(abr PRIVATE -static-libstdc++)
  else()
    target_link_options(abr PRIVATE -static)
  endif()
endif()

install(TARGETS abr RUNTIME DESTINATION bin)
