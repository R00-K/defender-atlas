#pragma once

/// \file istrategy.h
/// \brief Completion strategy abstraction for the DefenderAtlas Collector.
///
/// After a trigger fires, the Collector must decide when Defender has finished
/// its scan so ProcMon can be stopped. Rather than hardcoding a sleep inside
/// the Collector, this interface is injected and the Collector only ever calls
/// Wait().
///
/// Initial implementation: TimeoutCompletionStrategy. Planned strategies that
/// plug in without touching the Collector:
///   - ProcMonActivityCompletionStrategy (scan until ProcMon goes idle)
///   - ETWCompletionStrategy (scan until an MpEngine ETW event signals done)
///   - KernelEventCompletionStrategy

#include <string>

namespace defenderatlas {

/// Interface implemented by every completion strategy.
class ICompletionStrategy {
public:
    virtual ~ICompletionStrategy() = default;

    /// Stable short name recorded in experiment metadata, e.g. "timeout".
    virtual std::string Name() const = 0;

    /// Block until the strategy considers the Defender scan finished.
    /// Returns true when completion was observed, false on failure/timeout.
    virtual bool Wait() = 0;
};

} // namespace defenderatlas
