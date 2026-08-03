#pragma once

/// \file timeout_strategy.h
/// \brief Timeout-based completion strategy.
///
/// Waits a fixed wall-clock duration after the trigger fires. This is the
/// initial, simplest completion heuristic: it is correct for reproducible
/// scan durations and deliberately ignores Defender internals.
///
/// The duration comes from configuration (trigger_timeout_ms), never from a
/// hardcoded value inside the Collector.

#include "istrategy.h"

#include <chrono>

namespace defenderatlas {

/// Completion strategy that waits a fixed amount of time and reports success.
class TimeoutCompletionStrategy : public ICompletionStrategy {
public:
    explicit TimeoutCompletionStrategy(std::chrono::milliseconds timeout);

    std::string Name() const override;
    bool Wait() override;

private:
    std::chrono::milliseconds timeout_;
};

} // namespace defenderatlas
