/// \file procmon_activity_strategy.cpp
/// \brief Implementation of the placeholder activity-based strategy.

#include "procmon_activity_strategy.h"

#include "log.h"

namespace defenderatlas {

std::string ProcMonActivityCompletionStrategy::Name() const {
    return "procmon_activity";
}

bool ProcMonActivityCompletionStrategy::Wait() {
    log_error("ProcMonActivityCompletionStrategy is not implemented yet; "
              "switch \"completion_strategy\" back to \"timeout\"");
    return false;
}

} // namespace defenderatlas
