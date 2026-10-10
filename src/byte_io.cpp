// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/byte_io.hpp"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <cstdio>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace abr {

Bytes read_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw FormatError("cannot open file for reading: " + path.string());
    std::streamsize n = f.tellg();
    if (n < 0) throw FormatError("cannot stat file: " + path.string());
    f.seekg(0);
    Bytes out(static_cast<size_t>(n));
    if (n > 0 && !f.read(reinterpret_cast<char*>(out.data()), n))
        throw FormatError("short read on file: " + path.string());
    return out;
}

void write_file(const std::filesystem::path& path, const uint8_t* data, size_t size) {
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw FormatError("cannot open file for writing: " + path.string());
    if (size > 0) f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!f) throw FormatError("short write on file: " + path.string());
}

void write_file(const std::filesystem::path& path, const Bytes& data) {
    write_file(path, data.data(), data.size());
}

void set_binary_stdio() {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
#endif
}

bool mark_system_file(const std::filesystem::path& path) {
#ifdef _WIN32
    const DWORD now = GetFileAttributesW(path.c_str());
    if (now == INVALID_FILE_ATTRIBUTES) return false;
    return SetFileAttributesW(path.c_str(), now | FILE_ATTRIBUTE_SYSTEM) != 0;
#else
    (void)path;
    return true;
#endif
}

}  // namespace abr
