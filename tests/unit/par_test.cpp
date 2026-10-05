// SPDX-License-Identifier: GPL-3.0-or-later
//
// Checks of abr::par, the fork/join helper (include/abr/parallel.hpp). Run by
// tests/run_tests.sh as `abr_unit_tests par`.
//
// For several thread limits (1 = no extra thread at all, 2, 3, 8, and back to 2
// so that lowering the limit after workers exist is covered) it checks that
//   * every index runs exactly once, and with limit 1 on the calling thread;
//   * of several failing jobs the lowest index is the one reported, errors
//     travel out of nested regions, and the pool stays usable afterwards;
//   * nested regions -- the shape of a repack: components -> LZ4 blocks --
//     complete with the right result and never run more jobs at the same time
//     than the limit allows, yet do run in parallel when they may;
//   * Leases (what the zstd library's own workers are accounted with) never
//     push the total above the limit and are given back;
//   * thousands of tiny regions in a row neither hang nor lose a job.
// A watchdog turns a deadlock into a failure instead of a CI timeout.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "abr/parallel.hpp"

using namespace abr;
using namespace std::chrono_literals;

namespace {

int g_failures = 0;

#define EXPECT(cond)                                                              \
    do {                                                                          \
        if (!(cond)) {                                                            \
            ++g_failures;                                                         \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                         \
    } while (0)

// Counts how many "cores' worth of work" run at the same moment.
struct Gauge {
    std::atomic<int> now{0};
    std::atomic<int> peak{0};
    void enter() {
        const int v = now.fetch_add(1) + 1;
        int p = peak.load();
        while (v > p && !peak.compare_exchange_weak(p, v)) {
        }
    }
    void leave() { now.fetch_sub(1); }
};

// Occupies one core (as far as the gauge is concerned) for `ms` milliseconds.
void busy(Gauge& g, int ms) {
    g.enter();
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    g.leave();
}

void test_each(unsigned limit) {
    constexpr size_t N = 257;
    std::vector<std::atomic<int>> hits(N);
    std::vector<std::thread::id> who(N);
    par::for_each(N, [&](size_t i) {
        hits[i].fetch_add(1);
        who[i] = std::this_thread::get_id();
    });
    size_t wrong = 0;
    for (auto& h : hits)
        if (h.load() != 1) ++wrong;
    EXPECT(wrong == 0);
    if (limit == 1) {
        size_t elsewhere = 0;
        for (const auto& id : who)
            if (id != std::this_thread::get_id()) ++elsewhere;
        EXPECT(elsewhere == 0);  // -j1: nothing but the calling thread works
    }

    par::for_each(0, [&](size_t) { ++g_failures; });  // never called
    int single = 0;
    par::for_each(1, [&](size_t i) { single += 1 + static_cast<int>(i); });
    EXPECT(single == 1);

    int a = 0, b = 0, c = 0;
    par::run_all({[&] { a = 1; }, [&] { b = 2; }, [&] { c = 3; }});
    EXPECT(a == 1 && b == 2 && c == 3);
}

void test_errors() {
    for (int round = 0; round < 3; ++round) {  // the pool must stay usable after an error
        std::string what;
        try {
            par::for_each(40, [&](size_t i) {
                if (i == 5) {
                    std::this_thread::sleep_for(30ms);  // 9 fails first; 5 must still win
                    throw std::runtime_error("job 5");
                }
                if (i == 9) throw std::runtime_error("job 9");
                std::this_thread::sleep_for(1ms);
            });
        } catch (const std::runtime_error& e) {
            what = e.what();
        }
        EXPECT(what == "job 5");
    }

    std::string nested;  // an error in a nested region comes out of the outer one
    try {
        par::for_each(4, [&](size_t i) {
            par::for_each(6, [&](size_t j) {
                if (i == 1 && j == 3) throw std::logic_error("inner 1/3");
                std::this_thread::sleep_for(1ms);
            });
        });
    } catch (const std::logic_error& e) {
        nested = e.what();
    }
    EXPECT(nested == "inner 1/3");

    int odd = 0;  // anything throwable, not only std::exception
    try {
        par::for_each(8, [&](size_t i) {
            if (i == 2) throw 42;
        });
    } catch (int v) {
        odd = v;
    }
    EXPECT(odd == 42);

    std::atomic<int> after{0};  // and it still works
    par::for_each(20, [&](size_t) { after.fetch_add(1); });
    EXPECT(after == 20);
}

void test_nested(unsigned limit) {
    Gauge g;
    std::atomic<long> sum{0};
    constexpr size_t outer = 6, inner = 10;
    par::for_each(outer, [&](size_t i) {
        par::for_each(inner, [&](size_t j) {
            busy(g, 8);
            sum.fetch_add(static_cast<long>(i * 100 + j));
        });
    });
    long want = 0;
    for (size_t i = 0; i < outer; ++i)
        for (size_t j = 0; j < inner; ++j) want += static_cast<long>(i * 100 + j);
    EXPECT(sum == want);
    EXPECT(g.peak.load() <= static_cast<int>(limit));
    if (limit >= 2) EXPECT(g.peak.load() >= 2);  // sleeping jobs overlap on any machine

    // The shape of an image with an uneven ramdisk: one big job that fans out,
    // next to a job that is over at once. The idle thread must pick up the blocks.
    Gauge g2;
    std::atomic<int> blocks{0};
    par::for_each(2, [&](size_t i) {
        if (i == 0) {
            par::for_each(16, [&](size_t) {
                busy(g2, 10);
                blocks.fetch_add(1);
            });
        }
    });
    EXPECT(blocks == 16);
    EXPECT(g2.peak.load() <= static_cast<int>(limit));
    if (limit >= 2) EXPECT(g2.peak.load() >= 2);
}

void test_lease(unsigned limit) {
    {
        par::Lease a(100);
        EXPECT(a.threads() == limit - 1);  // everything there is to give
        par::Lease b(1);
        EXPECT(b.threads() == 0);
    }
    {
        par::Lease again(2);
        EXPECT(again.threads() == std::min(2u, limit - 1));  // handed back by the scope above
    }
    {
        par::Lease held(1);
        EXPECT(held.threads() == 1);
        Gauge g;  // one place is spoken for: the pool may use limit - 1 threads
        par::for_each(12, [&](size_t) { busy(g, 8); });
        EXPECT(g.peak.load() <= static_cast<int>(limit) - 1);
    }

    // The zstd shape: each job asks for helpers, and the job itself then only
    // waits while lease + 1 workers compute. Whatever the interleaving, the
    // workers computing at one moment must stay within the limit.
    Gauge g;
    par::for_each(6, [&](size_t) {
        par::Lease lease(par::max_threads() - 1);
        const unsigned units = lease.threads() + 1;
        std::vector<std::thread> workers;
        for (unsigned u = 0; u < units; ++u) workers.emplace_back([&] { busy(g, 15); });
        for (auto& w : workers) w.join();
    });
    EXPECT(g.peak.load() <= static_cast<int>(limit));
}

void test_churn() {
    for (int round = 0; round < 300; ++round) {
        const size_t outer = 1 + static_cast<size_t>(round % 7), inner = 1 + static_cast<size_t>(round % 5);
        std::atomic<size_t> n{0};
        par::for_each(outer, [&](size_t) { par::for_each(inner, [&](size_t) { n.fetch_add(1); }); });
        EXPECT(n == outer * inner);
    }
}

}  // namespace

int run_par_tests() {
    std::thread([] {
        std::this_thread::sleep_for(std::chrono::seconds(120));
        std::fputs("par: still running after 120 s -- a deadlock?\n", stderr);
        std::_Exit(3);
    }).detach();

    for (unsigned limit : {1u, 2u, 3u, 8u, 2u}) {
        par::set_max_threads(limit);
        std::printf("limit %u\n", limit);
        EXPECT(par::max_threads() == limit);
        test_each(limit);
        test_errors();
        test_nested(limit);
        if (limit >= 2) test_lease(limit);
        test_churn();
    }
    par::set_max_threads(0);
    EXPECT(par::max_threads() >= 1);

    if (g_failures == 0) std::puts("par: ok");
    else std::printf("par: %d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
