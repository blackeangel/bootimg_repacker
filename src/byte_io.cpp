// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/byte_io.hpp"

#include "abr/textquote.hpp"

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
#include <shellapi.h>
#endif

namespace abr {

void require_regular_file(const std::filesystem::path& path) {
    std::error_code ec;
    const std::filesystem::file_status st = std::filesystem::status(path, ec);  // (through a symbolic link)
    if (ec) return;  // not there (or not to be looked at): opening it says what is wrong
    if (st.type() == std::filesystem::file_type::directory)
        throw FormatError(textquote::quote_shown(path.string()) + " is a directory, not a file");
    if (st.type() != std::filesystem::file_type::regular && st.type() != std::filesystem::file_type::not_found)
        throw FormatError(textquote::quote_shown(path.string()) + " is not a regular file (a device, a fifo or a socket)");
}

Bytes read_file(const std::filesystem::path& path) {
    require_regular_file(path);
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw FormatError("cannot open file for reading: " + path.string());
    std::streamsize n = f.tellg();
    if (n < 0) throw FormatError("cannot stat file: " + path.string());
    if (static_cast<uint64_t>(n) > kMaxReadFile)
        throw FormatError(textquote::quote_shown(path.string()) + " is too big (" + std::to_string(n) + " bytes; abr reads at most 2 GiB of a file)");
    f.seekg(0);
    Bytes out(static_cast<size_t>(n));
    if (n > 0 && !f.read(reinterpret_cast<char*>(out.data()), n))
        throw FormatError("short read on file: " + path.string());
    return out;
}

void write_file(const std::filesystem::path& path, const uint8_t* data, size_t size) {
    // (a name that ends in a slash, or none: the parent below would be made a directory of that name, and the file never opens)
    if (!path.has_filename())
        throw FormatError(textquote::quote_shown(path.string()) + " is not the name of a file (it is empty or ends in a slash)");
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

std::vector<std::string> command_line_utf8(int argc, char** argv) {
    std::vector<std::string> narrow(argv + (argc > 0 ? 1 : 0), argv + (argc > 0 ? argc : 0));
#ifdef _WIN32
    int words = 0;
    LPWSTR* wide = CommandLineToArgvW(GetCommandLineW(), &words);
    if (!wide) return narrow;
    std::vector<std::string> utf8;
    bool ok = words == argc;  // the same number of words, or something is off and the narrow ones stay
    for (int i = 1; ok && i < words; ++i) {
        const int len = WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0) {
            ok = false;
            break;
        }
        std::string one(static_cast<size_t>(len), '\0');
        if (WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, one.data(), len, nullptr, nullptr) <= 0) {
            ok = false;
            break;
        }
        one.resize(static_cast<size_t>(len) - 1);  // the terminating NUL it counted
        utf8.push_back(std::move(one));
    }
    LocalFree(wide);
    if (ok) return utf8;
#endif
    return narrow;
}

Utf8Console::Utf8Console() {
#ifdef _WIN32
    DWORD mode = 0;
    if (GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) || GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode)) {
        const UINT now = GetConsoleOutputCP();
        if (now != 0 && now != CP_UTF8 && SetConsoleOutputCP(CP_UTF8)) saved_ = now;
    }
#endif
}

Utf8Console::~Utf8Console() {
#ifdef _WIN32
    if (saved_ != 0) SetConsoleOutputCP(saved_);
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
