#pragma once

/// \file procmon.h
/// \brief Process Monitor (Sysinternals) controller.
///
/// Wraps the lifecycle of a Procmon.exe capture:
///
///   1. Start()   — launch Procmon capturing to a PML backing file
///   2. WaitUntilReady() — block until capture is known to be active
///   3. Stop()    — terminate the capture gracefully and wait for exit
///   4. ExportCsv() — convert the recorded PML to CSV
///
/// All child processes are created with CreateProcess (never system()) and
/// every handle is RAII-managed. The ProcMon executable path comes from
/// configuration.

#include <windows.h>

#include <chrono>
#include <filesystem>

namespace defenderatlas {

/// Owns and controls one ProcMon capture session.
class ProcmonController {
public:
    /// \param procmon_path Path to Procmon64.exe / Procmon.exe.
    explicit ProcmonController(std::filesystem::path procmon_path);

    ProcmonController(const ProcmonController&) = delete;
    ProcmonController& operator=(const ProcmonController&) = delete;

    /// Safety net: best-effort Stop() if the session is still running.
    ~ProcmonController();

    /// Launch ProcMon with a PML backing file at \p pml_path.
    /// Returns false when the process could not be created.
    bool Start(const std::filesystem::path& pml_path);

    /// Block until the capture is considered active, up to \p timeout.
    /// Returns false when the process dies or the timeout elapses without the
    /// backing file appearing.
    bool WaitUntilReady(std::chrono::milliseconds timeout);

    /// Stop the capture and wait for the ProcMon process to exit, up to
    /// \p timeout. A graceful /Terminate is attempted first, with a hard
    /// TerminateProcess fallback.
    bool Stop(std::chrono::milliseconds timeout);

    /// Convert \p pml_path into \p csv_path using the /OpenLog /SaveAs
    /// switches. Returns false on launch failure, timeout or missing output.
    bool ExportCsv(const std::filesystem::path& pml_path,
                   const std::filesystem::path& csv_path,
                   std::chrono::milliseconds timeout);

    /// True while the captured ProcMon process is still alive.
    bool IsRunning() const;

private:
    /// Run ProcMon with \p arguments (already quoted where needed), wait for
    /// exit up to \p timeout and report success.
    bool RunAndWait(const std::wstring& arguments,
                    std::chrono::milliseconds timeout);

    std::filesystem::path procmon_path_;
    std::filesystem::path pml_path_;
    HANDLE process_handle_ = nullptr;
};

} // namespace defenderatlas
