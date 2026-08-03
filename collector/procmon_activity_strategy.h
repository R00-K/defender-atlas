#pragma once

/// \file procmon_activity_strategy.h
/// \brief Placeholder completion strategy based on ProcMon activity.
///
/// Long-term goal: instead of waiting a fixed wall-clock duration, watch the
/// running capture and consider the scan finished once MsMpEng activity on the
/// sample file has gone quiet (see ProcmonFilter). This would make scan
/// completion adaptive instead of timer based.
///
/// The implementation is intentionally not functional yet: Wait() reports
/// "not implemented" and returns false. It exists so the architecture already
/// supports switching completion strategies through config.json
/// ("completion_strategy": "procmon_activity") without touching the Collector,
/// which only ever talks to the ICompletionStrategy interface.

#include "istrategy.h"

namespace defenderatlas {

/// Completion strategy that will detect scan completion from capture activity.
class ProcMonActivityCompletionStrategy : public ICompletionStrategy {
public:
    std::string Name() const override;
    bool Wait() override;
};

} // namespace defenderatlas
