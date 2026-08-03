/// \file attachment_trigger.cpp
/// \brief Implementation of the IAttachmentExecute trigger.
///
/// This is a verbatim refactor of trigger/trigger_test.cpp. The COM call
/// sequence, argument order and error handling are unchanged so the
/// experimentally verified Defender scan reproduction is preserved.

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#ifndef INITGUID
#define INITGUID
#endif

#include "attachment_trigger.h"

#include "util.h"

#include <windows.h>
#include <shobjidl.h>

#include <cstdio>

namespace defenderatlas {

namespace {

/// Format an HRESULT as "0x%08lX" for diagnostics.
std::string format_hr(HRESULT hr) {
    char buffer[32] = {};
    std::snprintf(buffer, sizeof(buffer), "0x%08lX",
                  static_cast<unsigned long>(hr));
    return std::string(buffer);
}

} // namespace

AttachmentTrigger::AttachmentTrigger(std::string source_url)
    : source_url_(from_utf8(source_url)) {}

std::string AttachmentTrigger::Name() const {
    return "attachment";
}

TriggerResult AttachmentTrigger::Run(const std::filesystem::path& local_path) {
    // IAttachmentExecute::Save expects the file to already exist at the path
    // supplied to SetLocalPath.
    DWORD attributes = ::GetFileAttributesW(local_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return TriggerResult{false, "file does not exist: " + local_path.string()};
    }

    ComInitializer com;
    if (!com.ok()) {
        return TriggerResult{false,
                             "CoInitializeEx failed: " + format_hr(com.hr())};
    }

    ComPtr<IAttachmentExecute> attachment;
    HRESULT hr = ::CoCreateInstance(
        CLSID_AttachmentServices, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(attachment.put()));
    if (FAILED(hr)) {
        return TriggerResult{false, "CoCreateInstance failed: " + format_hr(hr)};
    }

    // Required for Save().
    hr = attachment->SetLocalPath(local_path.c_str());
    if (FAILED(hr)) {
        return TriggerResult{false, "SetLocalPath failed: " + format_hr(hr)};
    }

    // Tell Attachment Services where the file originated.
    hr = attachment->SetSource(source_url_.c_str());
    if (FAILED(hr)) {
        return TriggerResult{false, "SetSource failed: " + format_hr(hr)};
    }

    hr = attachment->Save();
    if (FAILED(hr)) {
        return TriggerResult{false, "Save failed: " + format_hr(hr)};
    }

    return TriggerResult{true, "IAttachmentExecute::Save completed successfully"};
}

} // namespace defenderatlas
