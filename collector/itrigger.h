#pragma once

/// \file itrigger.h
/// \brief Trigger abstraction for the DefenderAtlas Collector.
///
/// A trigger is the component that reproduces a "new download" event for a PE
/// file so that Microsoft Defender reacts the way it does after a browser
/// download. The Collector depends only on this interface and never on a
/// concrete trigger implementation.
///
/// Future triggers (BrowserTrigger, ShellExecuteTrigger, SmartScreenTrigger,
/// ExplorerTrigger, CloudTrigger, ...) implement ITrigger and can be swapped in
/// without touching the Collector.

#include <filesystem>
#include <string>

namespace defenderatlas {

/// Outcome of running a trigger against a sample.
struct TriggerResult {
    /// True when the trigger call completed without an error.
    bool success = false;

    /// Human readable detail (operation, HRESULT, reason) for logging and
    /// metadata diagnostics.
    std::string message;
};

/// Interface implemented by every trigger.
class ITrigger {
public:
    virtual ~ITrigger() = default;

    /// Stable short name recorded in experiment metadata, e.g. "attachment".
    virtual std::string Name() const = 0;

    /// Reproduce the download event for the PE file at \p local_path.
    /// Returns a TriggerResult describing the outcome.
    virtual TriggerResult Run(const std::filesystem::path& local_path) = 0;
};

} // namespace defenderatlas
