// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/progress.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <utility>

namespace abr::progress {

namespace {

constexpr size_t kNoStage = static_cast<size_t>(-1);

struct State {
    std::mutex mu;  // guards everything but the two counters
    bool active = false;
    std::string command;
    std::vector<Stage> plan;
    double total_weight = 0;
    size_t current = kNoStage;  // the index in `plan` of the stage in progress; kNoStage before the first
    std::string stage_label;  // the name of the stage in progress
    std::chrono::steady_clock::time_point started;
    std::vector<std::pair<uint64_t, std::string>> activities;  // the jobs in progress, in the order they started
    uint64_t next_activity = 1;
    std::atomic<uint64_t> units{0};  // the work of the stage in progress, 0: not known
    std::atomic<uint64_t> done{0};   // what is done of it
};

State& state() {
    static State s;
    return s;
}

// The names of the jobs in progress as one text: the first two and how many more.
std::string join_activities(const std::vector<std::pair<uint64_t, std::string>>& list) {
    std::string out;
    size_t shown = 0;
    for (const auto& a : list) {
        if (shown == 2) break;
        if (!out.empty()) out += ", ";
        out += a.second;
        ++shown;
    }
    if (list.size() > shown) out += " +" + std::to_string(list.size() - shown);
    return out;
}

}  // namespace

void begin(std::string_view command, std::vector<Stage> plan) {
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    s.active = true;
    s.command = std::string(command);
    s.plan = std::move(plan);
    s.total_weight = 0;
    for (const Stage& st : s.plan) s.total_weight += std::max(st.weight, 0.0);
    s.current = kNoStage;
    s.stage_label.clear();
    s.started = std::chrono::steady_clock::now();
    s.activities.clear();
    s.units = 0;
    s.done = 0;
}

void enter(std::string_view name, uint64_t units) {
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    if (!s.active) return;
    // (from where the last one was: a stage is entered once, and the ones that were not entered before it are done)
    const size_t from = s.current == kNoStage ? 0 : s.current;
    for (size_t i = from; i < s.plan.size(); ++i) {
        if (s.plan[i].name != name) continue;
        if (i == s.current) {
            s.units += units;  // the stage again (one more batch of its work): what was done stays done
            return;
        }
        s.current = i;
        s.stage_label = std::string(name);
        s.units = units;
        s.done = 0;
        return;
    }
}

void advance(uint64_t units) { state().done.fetch_add(units, std::memory_order_relaxed); }

void end() {
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    s.active = false;
    s.activities.clear();
}

Activity::Activity(std::string what) {
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    id_ = s.next_activity++;
    s.activities.emplace_back(id_, std::move(what));
}

Activity::~Activity() {
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    s.activities.erase(std::remove_if(s.activities.begin(), s.activities.end(), [&](const auto& a) { return a.first == id_; }),
                       s.activities.end());
}

Snapshot snapshot() {
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    Snapshot out;
    out.active = s.active;
    if (!s.active) return out;
    out.command = s.command;
    out.stage = s.stage_label;
    out.activity = join_activities(s.activities);
    out.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - s.started).count();
    double before = 0;
    for (size_t i = 0; s.current != kNoStage && i < s.current && i < s.plan.size(); ++i) before += std::max(s.plan[i].weight, 0.0);
    double inside = 0;
    const uint64_t units = s.units.load(std::memory_order_relaxed);
    if (s.current != kNoStage && s.current < s.plan.size() && units > 0) {
        out.determinate = true;
        inside = std::min(1.0, static_cast<double>(s.done.load(std::memory_order_relaxed)) / static_cast<double>(units)) *
                 std::max(s.plan[s.current].weight, 0.0);
    }
    // (a command that is not over is not shown as done: `end()` is what says it is)
    out.fraction = s.total_weight > 0 ? std::clamp((before + inside) / s.total_weight, 0.0, 0.99) : 0.0;
    return out;
}

}  // namespace abr::progress
