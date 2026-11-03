// SPDX-License-Identifier: GPL-3.0-or-later
//
// abr::progress -- how far a command has got, for the bar the console draws (abr/console.hpp).
//
// A command says what it is going to go through -- stages, each with a weight (its share of the whole, relative to the others) -- and
// reports as it goes: which stage it is in, how much work that stage has when that is known (bytes, say), how much of it is done. The
// bar shows the weights of the stages that are done plus the part of the stage in progress that is done; a stage whose work is not
// known (units 0) holds the bar where it is until the stage ends, and the bar shows that something is going on in another way. It
// never shows more than there is: a stage that reports more work than it said stops at its end.
//
// Everything here may be called from any thread, and costs next to nothing where no console is drawing: a library user (a unit test)
// that never calls begin() has no progress at all.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace abr::progress {

struct Stage {
    std::string name;
    double weight = 1;
};

// A command starts: `command` is shown at the left of the bar ("unpack"), `plan` is the stages it goes through, in order.
void begin(std::string_view command, std::vector<Stage> plan);

// The stage called `name` starts (the stages before it that were not entered are done). `units`: the work it has, when known.
// A name that is not in the plan changes nothing.
void enter(std::string_view name, uint64_t units = 0);

// `units` of the work of the stage in progress are done.
void advance(uint64_t units);

// The command is over (the bar goes away). Calling it twice, or without begin(), is fine.
void end();

// begin() and end() as a scope: end() also when an exception leaves.
class Scope {
public:
    Scope(std::string_view command, std::vector<Stage> plan) { begin(command, std::move(plan)); }
    ~Scope() { end(); }
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;
};

// A job in progress, named for as long as this object lives; the bar shows the names of the jobs that are (a few of them). The name is
// text of abr's own or text of an image that was made safe to show; anything that a terminal would act on is replaced when it is drawn.
class Activity {
public:
    explicit Activity(std::string what);
    ~Activity();
    Activity(const Activity&) = delete;
    Activity& operator=(const Activity&) = delete;

private:
    uint64_t id_;
};

// What the console draws.
struct Snapshot {
    bool active = false;       // a command is in progress
    std::string command;       // "unpack"
    std::string stage;         // "decode"
    std::string activity;      // "kernel, ramdisk" (the jobs in progress)
    double fraction = 0;       // 0 to 1: how much of the whole is done
    bool determinate = false;  // the stage in progress has a known amount of work (when it has not, `fraction` holds where it started)
    double seconds = 0;        // since begin()
};
Snapshot snapshot();

}  // namespace abr::progress
