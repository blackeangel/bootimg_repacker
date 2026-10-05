// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::par -- the little multithreading abr does.
//
// What is worth running on several cores here is a handful of big, independent
// jobs: the components of one image (kernel, ramdisk, each vendor ramdisk
// fragment ... decoded, hashed and written separately), the 8 MiB blocks of an
// LZ4 legacy stream, the jobs of a zstd frame. So this is a fork/join helper,
// not a task scheduler: for_each() returns when all of its jobs have finished.
//
// There is one small pool for the whole process: at most max_threads() - 1
// worker threads, started the first time there is something for them to do and
// ended with the process. The thread that calls for_each() works too, and a
// thread that has to wait for its jobs does not sit idle: it runs jobs of any
// for_each() that still has one nobody has started. That is what makes nesting
// cheap and safe -- the ramdisk job of an image compressing its own LZ4 blocks
// borrows every thread that has nothing else to do, never occupies a thread
// just by waiting, and can never wait for work that nobody is running. The
// threads running jobs never outnumber max_threads(), however deep the nesting.
//
// Results never depend on the number of threads. Work is split by the data
// (fixed block sizes, a fixed number of components), never by the thread count,
// and results are collected in index order; the test suite repacks with
// -j1 and with many threads and requires byte-identical output.
#pragma once

#include <cstddef>
#include <functional>
#include <initializer_list>

namespace abr::par {

// The most threads abr may run at once, the calling thread included (>= 1).
// Decided from, in order: set_max_threads(), the ABR_THREADS environment
// variable, the number of hardware threads (at most 16: the jobs are few and
// big, more threads would only cost memory).
unsigned max_threads();

// 0 restores the automatic choice, 1 makes everything run on the calling
// thread. Call it before any parallel work (it is not meant to be changed while
// a for_each() is running).
void set_max_threads(unsigned n);

// Runs fn(0) ... fn(n-1) and returns when all have finished. Indices are handed
// out in increasing order, so put the biggest jobs first. If any job throws,
// no new job is started, the running ones finish, and the exception of the
// lowest failing index is rethrown (the same one a serial run would meet first).
void for_each(size_t n, const std::function<void(size_t)>& fn);

// Runs every job (in the same way) and waits for all of them.
void run_all(std::initializer_list<std::function<void()>> jobs);

// A claim on up to `want` extra threads from the budget, for code that starts
// threads of its own (the zstd library's workers) and should not oversubscribe
// the machine. threads() is how many were granted (possibly none); they are
// handed back when the Lease goes out of scope.
class Lease {
public:
    explicit Lease(unsigned want);
    ~Lease();
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;
    unsigned threads() const { return n_; }

private:
    unsigned n_;
};

}  // namespace abr::par
