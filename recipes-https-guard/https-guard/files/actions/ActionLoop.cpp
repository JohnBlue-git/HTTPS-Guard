#include "ActionLoop.hpp"

namespace https_guard {

void ActionLoop::add_action(std::unique_ptr<Action> action)
{
    actions_.push_back(std::move(action));
}

void ActionLoop::handle(const hg_event& event)
{
    for (const auto& action : actions_) {
        action->execute(event);
    }
}

}  // namespace https_guard
