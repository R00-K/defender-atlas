/// \file subprocess_trigger.cpp
/// \brief Implementation of the worker-subprocess trigger.

#include "subprocess_trigger.h"

#include "util.h"

#include <string>
#include <utility>

namespace defenderatlas {

namespace {

/// Strip trailing whitespace and newlines.
std::string trim(std::string text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' ||
                             text.back() == ' ' || text.back() == '\t')) {
        text.pop_back();
    }
    return text;
}

} // namespace

SubprocessTrigger::SubprocessTrigger(std::filesystem::path worker_exe,
                                     std::string source_url,
                                     std::uint64_t timeout_ms)
    : worker_exe_(std::move(worker_exe)),
      source_url_(from_utf8(source_url)),
      timeout_ms_(timeout_ms) {}

std::string SubprocessTrigger::Name() const {
    return "attachment";
}

TriggerResult SubprocessTrigger::Run(const std::filesystem::path& local_path) {
    if (!file_exists(worker_exe_)) {
        return TriggerResult{false,
                             "trigger worker not found: " + worker_exe_.string()};
    }

    const ProcessResult process =
        run_process(worker_exe_, {local_path.wstring(), source_url_}, timeout_ms_);
    if (!process.started) {
        return TriggerResult{false,
                             "failed to start trigger worker: " + process.error};
    }
    if (process.timed_out) {
        return TriggerResult{false,
                             "trigger worker timed out after " +
                                 std::to_string(timeout_ms_) + " ms"};
    }

    const std::string message = trim(process.stdout_text);
    if (process.exit_code != 0) {
        const std::string detail =
            message.empty() ? std::string("(no output)") : message;
        return TriggerResult{false,
                             "trigger worker exited with code " +
                                 std::to_string(process.exit_code) + ": " + detail};
    }

    return TriggerResult{
        true, message.empty()
                  ? std::string("IAttachmentExecute::Save completed successfully")
                  : message};
}

} // namespace defenderatlas
