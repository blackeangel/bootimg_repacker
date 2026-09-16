// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/byte_io.hpp"

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

}  // namespace abr
