// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/parallel.hpp"

#include <algorithm>
#include <condition_variable>
#include <cstdlib>
#include <exception>
#include <mutex>
#include <system_error>
#include <thread>
#include <vector>

// A small pool with "help while waiting":
//
//  * max_threads() - 1 worker threads, started when there is something for them
//    to do and kept until the process ends. Together with the thread that calls
//    for_each() that is the most cores abr ever occupies.
//  * A for_each() puts its jobs on a shared list and then does jobs itself --
//    first its own, and when those are all taken, those of any other region --
//    until its own are finished. A worker that runs a job which starts a region
//    of its own (the ramdisk job starts one per LZ4 block) therefore never waits
//    for a core while another thread has nothing to do, and no thread ever blocks
//    for work that nobody is running: a region only waits for jobs that some
//    thread has already started.
//  * One mutex guards all bookkeeping. Jobs are big (milliseconds to seconds),
//    so taking it once per job costs nothing, and it keeps the reasoning simple.

namespace abr::par {

namespace {

constexpr unsigned kAutoCap = 16;

// One for_each() in progress. Everything but `fn` and `n` is guarded by Shared::mu.
struct Region {
    const std::function<void(size_t)>& fn;
    const size_t n;
    size_t next = 0;      // next index to hand out
    size_t finished = 0;  // jobs completed
    bool failed = false;  // a job threw: hand out no more
    std::exception_ptr error;
    size_t error_index = 0;

    Region(const std::function<void(size_t)>& f, size_t count) : fn(f), n(count) {}
    bool has_work() const { return !failed && next < n; }
    bool done() const { return finished == next && !has_work(); }
};

struct Shared {
    std::mutex mu;
    std::condition_variable cv;  // work appeared, a region finished, capacity changed, stop
    std::vector<Region*> regions;
    std::vector<std::thread> threads;
    bool threads_refused = false;  // the system would not start another thread
    unsigned limit = 0;            // max_threads(); 0 = not decided yet
    unsigned leased = 0;           // places held by Leases
    unsigned active = 0;           // worker threads running a job right now
    bool stop = false;

    ~Shared() {
        {
            std::lock_guard<std::mutex> lk(mu);
            stop = true;
        }
        cv.notify_all();
        for (auto& t : threads) t.join();
    }

    void decide_locked(unsigned n) { limit = std::clamp(n, 1u, 256u); }

    unsigned limit_locked() {
        if (limit == 0) decide_locked(automatic_limit());
        return limit;
    }

    static unsigned automatic_limit() {
        if (const char* e = std::getenv("ABR_THREADS")) {
            char* end = nullptr;
            unsigned long v = std::strtoul(e, &end, 10);
            if (end != e && *end == '\0' && v >= 1) return static_cast<unsigned>(std::min<unsigned long>(v, 256));
        }
        return std::clamp(std::thread::hardware_concurrency(), 1u, kAutoCap);
    }

    // How many worker threads may run jobs now: all but the places Leases hold.
    unsigned allowed_locked() {
        const unsigned workers = limit_locked() - 1;
        return workers > leased ? workers - leased : 0;
    }

    // The first region that still has a job to hand out; takes that job.
    Region* take_locked(size_t& index) {
        for (Region* r : regions) {
            if (r->has_work()) {
                index = r->next++;
                return r;
            }
        }
        return nullptr;
    }

    // Starts workers so that the jobs now waiting have a thread each (the caller of
    // for_each takes one itself), up to max_threads() - 1 in all.
    void grow_locked(size_t waiting_jobs) {
        const size_t want = std::min<size_t>(limit_locked() - 1, waiting_jobs > 0 ? waiting_jobs - 1 : 0);
        while (!threads_refused && threads.size() < want) {
            try {
                threads.emplace_back([this] { worker_main(); });
            } catch (const std::system_error&) {
                threads_refused = true;  // the threads we have share the work
            }
        }
    }

    size_t waiting_jobs_locked() const {
        size_t total = 0;
        for (const Region* r : regions)
            if (r->has_work()) total += r->n - r->next;
        return total;
    }

    // Runs one job without holding the lock; returns what it threw.
    static std::exception_ptr run(Region& r, size_t index) {
        try {
            r.fn(index);
        } catch (...) {
            return std::current_exception();
        }
        return nullptr;
    }

    void finish_locked(Region& r, size_t index, std::exception_ptr error) {
        ++r.finished;
        if (error) {
            if (!r.error || index < r.error_index) {
                r.error = error;
                r.error_index = index;
            }
            r.failed = true;
        }
        if (r.done()) cv.notify_all();
    }

    void worker_main() {
        std::unique_lock<std::mutex> lk(mu);
        for (;;) {
            if (stop) return;
            size_t index = 0;
            Region* r = active < allowed_locked() ? take_locked(index) : nullptr;
            if (!r) {
                cv.wait(lk);
                continue;
            }
            ++active;
            lk.unlock();
            std::exception_ptr error = run(*r, index);
            lk.lock();
            --active;
            finish_locked(*r, index, error);
            cv.notify_all();  // this thread has a core to give again
        }
    }
};

Shared& shared() {
    static Shared s;
    return s;
}

}  // namespace

unsigned max_threads() {
    Shared& s = shared();
    std::lock_guard<std::mutex> lk(s.mu);
    return s.limit_locked();
}

void set_max_threads(unsigned n) {
    Shared& s = shared();
    std::lock_guard<std::mutex> lk(s.mu);
    s.decide_locked(n == 0 ? Shared::automatic_limit() : n);
    s.cv.notify_all();
}

void for_each(size_t n, const std::function<void(size_t)>& fn) {
    if (n == 0) return;
    if (n == 1 || max_threads() == 1) {
        for (size_t i = 0; i < n; ++i) fn(i);
        return;
    }

    Shared& s = shared();
    Region r(fn, n);
    std::unique_lock<std::mutex> lk(s.mu);
    s.regions.push_back(&r);
    s.grow_locked(s.waiting_jobs_locked());
    s.cv.notify_all();

    for (;;) {
        size_t index = 0;
        Region* job_region = nullptr;
        if (r.has_work()) {
            job_region = &r;
            index = r.next++;
        } else {
            job_region = s.take_locked(index);  // our own are all taken: help another region
        }
        if (job_region) {
            lk.unlock();
            std::exception_ptr error = Shared::run(*job_region, index);
            lk.lock();
            s.finish_locked(*job_region, index, error);
            continue;
        }
        if (r.done()) break;
        s.cv.wait(lk);
    }
    s.regions.erase(std::find(s.regions.begin(), s.regions.end(), &r));
    lk.unlock();
    if (r.error) std::rethrow_exception(r.error);
}

Lease::Lease(unsigned want) : n_(0) {
    if (want == 0) return;
    Shared& s = shared();
    std::lock_guard<std::mutex> lk(s.mu);
    const unsigned workers = s.limit_locked() - 1;
    const unsigned taken = s.leased + s.active;
    const unsigned free_places = workers > taken ? workers - taken : 0;
    n_ = std::min(want, free_places);
    s.leased += n_;
}

Lease::~Lease() {
    if (n_ == 0) return;
    Shared& s = shared();
    {
        std::lock_guard<std::mutex> lk(s.mu);
        s.leased -= n_;
    }
    s.cv.notify_all();
}

void run_all(std::initializer_list<std::function<void()>> jobs) {
    const std::function<void()>* list = jobs.begin();
    for_each(jobs.size(), [list](size_t i) { list[i](); });
}

}  // namespace abr::par
