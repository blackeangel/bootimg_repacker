// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::pages -- the page arithmetic of the containers that lay their device trees out one behind the other, each at a multiple of a page
// size that the container does not say: the QCDT table of Qualcomm (qcdt.hpp) and the "AML_" container of Amlogic (aml.hpp), both made by a
// dtbTool that is told the page size of the boot image the table goes into. What the container has is offsets and sizes, and a page size that
// divides all of them is what they allow.
#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

namespace abr::pages {

// What dtbTool pads with: up to the next multiple of the page size, and a whole page of zeros when the length already is one.
inline uint64_t padded(uint64_t length, uint64_t page) { return length + (page - length % page); }

// The page sizes that the offsets and sizes of a container allow -- each divides `common`, the greatest common divisor of all of them -- up to
// `max_page`: the one asked for first (`hint`, the page size of the boot image the container is in; 0: none), then the usual ones, then the rest from
// the smallest. A container is laid out for the first of them that gives its offsets and sizes.
inline std::vector<uint32_t> candidates(uint64_t common, uint32_t hint, uint32_t max_page) {
    std::vector<uint32_t> divisors;
    for (uint64_t d = 1; d * d <= common; ++d) {
        if (common % d != 0) continue;
        if (d <= max_page) divisors.push_back(static_cast<uint32_t>(d));
        const uint64_t other = common / d;
        if (other != d && other <= max_page) divisors.push_back(static_cast<uint32_t>(other));
    }
    std::sort(divisors.begin(), divisors.end());
    std::vector<uint32_t> order;
    const auto take = [&](uint32_t p) {
        if (p != 0 && std::binary_search(divisors.begin(), divisors.end(), p) && std::find(order.begin(), order.end(), p) == order.end())
            order.push_back(p);
    };
    take(hint);
    for (const uint32_t p : {2048u, 4096u, 8192u, 16384u, 1024u, 512u, 32768u, 65536u, 131072u, 262144u, 524288u, 1048576u}) take(p);
    for (const uint32_t d : divisors) take(d);
    return order;
}

}  // namespace abr::pages
