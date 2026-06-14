#pragma once

#include <memory>
#include <vector>

#include "events.h"

namespace https_guard {

class Action {
public:
    virtual ~Action() = default;
    virtual void execute(const hg_event& event) = 0;
};

class ActionLoop {
public:
    void add_action(std::unique_ptr<Action> action);
    void handle(const hg_event& event);

private:
    std::vector<std::unique_ptr<Action>> actions_;
};

}  // namespace https_guard
