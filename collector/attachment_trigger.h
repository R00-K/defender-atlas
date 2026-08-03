#pragma once

/// \file attachment_trigger.h
/// \brief IAttachmentExecute based trigger.
///
/// This trigger reproduces the Defender scan pattern observed after a browser
/// download by driving the COM Attachment Services API:
///
///     CoInitializeEx
///     CoCreateInstance(CLSID_AttachmentServices, ...)
///     SetLocalPath(file)
///     SetSource(url)
///     Save()
///
/// The call sequence is a verbatim refactor of the experimentally verified
/// trigger/trigger_test.cpp implementation; the logic has not been changed.

#include "itrigger.h"

#include <string>

namespace defenderatlas {

/// Trigger that uses IAttachmentExecute::Save() to emulate a new download.
class AttachmentTrigger : public ITrigger {
public:
    /// \param source_url URL reported as the download origin to SetSource().
    explicit AttachmentTrigger(std::string source_url);

    std::string Name() const override;

    /// Drive IAttachmentExecute against \p local_path. Returns success when
    /// Save() completes successfully.
    TriggerResult Run(const std::filesystem::path& local_path) override;

private:
    std::wstring source_url_;
};

} // namespace defenderatlas
