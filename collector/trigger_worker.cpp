/// \file trigger_worker.cpp
/// \brief Standalone, single-shot IAttachmentExecute trigger worker.
///
/// Runs one trigger against one file and exits immediately. This is the exact
/// process lifecycle that was experimentally verified with trigger_test.cpp:
/// one Save() per process, then a fast exit.
///
/// The Collector never performs the trigger in-process. Instead it spawns this
/// worker per experiment (see SubprocessTrigger). Running the shell's
/// IAttachmentExecute machinery in a short-lived process has two advantages:
///
///   1. It matches the verified deployment, and
///   2. It crash-isolates the trigger: shell32 background threads spawned by
///      Save() can crash this process, but the Collector keeps running and
///      records the experiment as failed.
///
/// Protocol with the parent process:
///   - exit code 0          -> trigger completed successfully
///   - exit code 1          -> trigger failed (see message on stdout)
///   - exit code 2          -> bad arguments
///   - stdout               -> human readable result message (UTF-8)
///
/// Usage:
///     trigger_worker.exe <local_path> [source_url]

#include "attachment_trigger.h"
#include "util.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2 || argc > 3) {
        std::printf("usage: trigger_worker.exe <local_path> [source_url]\n");
        return 2;
    }

    const std::filesystem::path local_path(argv[1]);
    std::string source_url = "https://example.com/download";
    if (argc > 2) {
        source_url = defenderatlas::to_utf8(argv[2]);
    }

    defenderatlas::AttachmentTrigger trigger(std::move(source_url));
    const defenderatlas::TriggerResult result = trigger.Run(local_path);

    std::printf("%s\n", result.message.c_str());
    std::fflush(stdout);
    return result.success ? 0 : 1;
}
