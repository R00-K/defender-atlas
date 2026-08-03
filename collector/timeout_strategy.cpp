/// \file timeout_strategy.cpp
/// \brief Implementation of TimeoutCompletionStrategy.

#include "timeout_strategy.h"

#include <thread>

namespace defenderatlas {

TimeoutCompletionStrategy::TimeoutCompletionStrategy(
    std::chrono::milliseconds timeout)
    : timeout_(timeout) {}

std::string TimeoutCompletionStrategy::Name() const {
    return "timeout";
}

bool TimeoutCompletionStrategy::Wait() {
    const auto milliseconds = timeout_.count();
    if (milliseconds <= 0) {
        return true;
    }
    std::this_thread::sleep_for(timeout_);
    return true;
}

} // namespace defenderatlas
