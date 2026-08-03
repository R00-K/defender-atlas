#pragma once

/// \file subprocess_trigger.h
/// \brief Trigger that executes the attachment trigger in a worker process.
///
/// IAttachmentExecute::Save() schedules shell32 background threads that can
/// crash the hosting process at a non-deterministic point after Save() returns
/// (observed on the DefenderAtlas test environment). Because the Collector must
/// never terminate because a single sample failed, the trigger is isolated in a
/// short-lived worker process (trigger_worker.exe) that performs exactly one
/// Save() and exits immediately — the process lifecycle that was verified with
/// the original trigger_test.cpp.
///
/// SubprocessTrigger implements ITrigger so the Collector keeps depending only
/// on the abstraction. The trigger semantics are unchanged: the worker is the
/// verbatim IAttachmentExecute refactor.

#include "itrigger.h"

#include <filesystem>
#include <string>

namespace defenderatlas {

/// Trigger that spawns trigger_worker.exe per call and reports its outcome.
class SubprocessTrigger : public ITrigger {
public:
    /// \param worker_exe Path to trigger_worker.exe.
    /// \param source_url URL reported as the download origin.
    /// \param timeout_ms  Maximum time to wait for the worker to finish.
    SubprocessTrigger(std::filesystem::path worker_exe, std::string source_url,
                      std::uint64_t timeout_ms);

    std::string Name() const override;

    /// Run the worker against \p local_path and wait for it to finish.
    TriggerResult Run(const std::filesystem::path& local_path) override;

private:
    std::filesystem::path worker_exe_;
    std::wstring source_url_;
    std::uint64_t timeout_ms_;
};

} // namespace defenderatlas
