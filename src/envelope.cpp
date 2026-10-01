// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/envelope.hpp"

#include <algorithm>

namespace abr {

size_t find_magic(const Bytes& data, const char* magic, size_t magic_len, size_t limit) {
    if (data.size() < magic_len) return std::string::npos;
    size_t last = std::min(data.size() - magic_len, limit);
    for (size_t i = 0; i <= last; ++i)
        if (std::memcmp(data.data() + i, magic, magic_len) == 0) return i;
    return std::string::npos;
}

Envelope Envelope::capture(const Bytes& host, size_t core_off, size_t core_len) {
    Envelope e;
    core_off = std::min(core_off, host.size());
    size_t core_end = std::min(host.size(), core_off + core_len);
    e.prefix.assign(host.begin(), host.begin() + static_cast<long>(core_off));

    size_t tail_len = host.size() - core_end;
    if (tail_len == 0) return e;

    uint8_t last = host.back();
    size_t run = 0;
    while (run < tail_len && host[host.size() - 1 - run] == last) ++run;
    if (run >= kMinPadRun) {
        e.pad_byte = last;
        e.pad_to = host.size();
        tail_len -= run;
    }
    e.tail.assign(host.begin() + static_cast<long>(core_end),
                  host.begin() + static_cast<long>(core_end + tail_len));
    return e;
}

Bytes Envelope::assemble(const Bytes& core, std::string* note) const {
    Bytes out;
    out.reserve(std::max<uint64_t>(pad_to, prefix.size() + core.size() + tail.size()));
    out.insert(out.end(), prefix.begin(), prefix.end());
    out.insert(out.end(), core.begin(), core.end());
    out.insert(out.end(), tail.begin(), tail.end());
    if (pad_to) {
        if (out.size() < pad_to)
            out.resize(static_cast<size_t>(pad_to), pad_byte);
        else if (out.size() > pad_to && note)
            *note = "rebuilt image is " + std::to_string(out.size()) +
                    " bytes, larger than the original " + std::to_string(pad_to) +
                    " bytes it was padded to (it may no longer fit its partition)";
    }
    return out;
}

}  // namespace abr
