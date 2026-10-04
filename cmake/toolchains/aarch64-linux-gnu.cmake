# Cross-compilation toolchain for GNU/Linux on aarch64 (glibc). Its job is to
# let an x86-64 machine build *and run* the arm64 code -- the ARMv8 SHA
# instructions, NEON paths and the 64-bit ARM ABI the Android build uses --
# through qemu-user, without a device:
#
#   sudo apt-get install g++-14-aarch64-linux-gnu qemu-user
#   cmake -S . -B build-arm64 -G Ninja \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
#     -DCMAKE_BUILD_TYPE=Release -DABR_STATIC_BINARY=ON
#   ABR_RUNNER="qemu-aarch64 -cpu max" tests/run_tests.sh build-arm64/abr
#
# (-cpu max gives qemu the SHA1/SHA2 extensions; a plain `qemu-aarch64` makes
# abr fall back to its portable code, which is worth running too.)
#
# C++26 needs GCC >= 14 (Ubuntu 24.04: g++-14-aarch64-linux-gnu); with the
# default GCC 13 cross compiler add -DABR_CXX_STANDARD=23.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(ABR_A64_TRIPLE aarch64-linux-gnu)
find_program(ABR_A64_GCC NAMES ${ABR_A64_TRIPLE}-gcc-15 ${ABR_A64_TRIPLE}-gcc-14 ${ABR_A64_TRIPLE}-gcc-13 ${ABR_A64_TRIPLE}-gcc)
find_program(ABR_A64_GXX NAMES ${ABR_A64_TRIPLE}-g++-15 ${ABR_A64_TRIPLE}-g++-14 ${ABR_A64_TRIPLE}-g++-13 ${ABR_A64_TRIPLE}-g++)
if(NOT ABR_A64_GCC OR NOT ABR_A64_GXX)
  message(FATAL_ERROR "aarch64-linux-gnu-g++ not found (Debian/Ubuntu: sudo apt-get install g++-14-aarch64-linux-gnu)")
endif()
set(CMAKE_C_COMPILER   ${ABR_A64_GCC})
set(CMAKE_CXX_COMPILER ${ABR_A64_GXX})

set(CMAKE_FIND_ROOT_PATH /usr/${ABR_A64_TRIPLE})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
