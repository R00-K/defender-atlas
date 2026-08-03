/// \file procmon.cpp
/// \brief Implementation of the Process Monitor controller.

#include "procmon.h"

#include "log.h"
#include "util.h"

#include <chrono>
#include <thread>
#include <vector>

namespace defenderatlas {

namespace {

constexpr std::chrono::milliseconds kPollInterval(100);
constexpr std::chrono::milliseconds kReadinessGracePeriod(200);
constexpr std::chrono::milliseconds kHardTerminateGrace(5000);

/// Build a mutable command line for CreateProcess from the executable path and
/// pre-quoted arguments.
std::vector<wchar_t> build_command_line(const std::filesystem::path& exe,
                                        const std::wstring& arguments) {
    std::wstring full = L"\"" + exe.wstring() + L"\" " + arguments;
    std::vector<wchar_t> buffer(full.begin(), full.end());
    buffer.push_back(L'\0');
    return buffer;
}

} // namespace

ProcmonController::ProcmonController(std::filesystem::path procmon_path)
    : procmon_path_(std::move(procmon_path)) {}

ProcmonController::~ProcmonController() {
    if (IsRunning()) {
        log_warning("ProcMon still running at shutdown; terminating");
        Stop(std::chrono::seconds(10));
    }
    if (process_handle_ != nullptr && process_handle_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(process_handle_);
    }
}

bool ProcmonController::Start(const std::filesystem::path& pml_path) {
    pml_path_ = pml_path;

    std::wstring arguments =
        L"/AcceptEula /Quiet /Minimized /BackingFile \"" + pml_path.wstring() +
        L"\"";
    std::vector<wchar_t> command_line =
        build_command_line(procmon_path_, arguments);

    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process_info = {};
    const BOOL created = ::CreateProcessW(
        procmon_path_.c_str(), command_line.data(), nullptr, nullptr, FALSE, 0,
        nullptr, nullptr, &startup, &process_info);
    if (!created) {
        log_error("Failed to start ProcMon: ", last_win32_error_string());
        return false;
    }

    ::CloseHandle(process_info.hThread);
    if (process_handle_ != nullptr && process_handle_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(process_handle_);
    }
    process_handle_ = process_info.hProcess;

    log_info("ProcMon started (pid ", process_info.dwProcessId, ")");
    return true;
}

bool ProcmonController::WaitUntilReady(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (!IsRunning()) {
            log_error("ProcMon exited before becoming ready");
            return false;
        }
        std::error_code ec;
        if (std::filesystem::exists(pml_path_, ec) && !ec) {
            // Small grace period so ProcMon has finished wiring up its capture
            // loop before the trigger fires.
            std::this_thread::sleep_for(kReadinessGracePeriod);
            return true;
        }
        std::this_thread::sleep_for(kPollInterval);
    }
    log_error("Timed out waiting for ProcMon to become ready: ",
              pml_path_.string());
    return false;
}

bool ProcmonController::Stop(std::chrono::milliseconds timeout) {
    bool graceful = RunAndWait(L"/AcceptEula /Terminate",
                               std::chrono::milliseconds(timeout));

    if (process_handle_ != nullptr && process_handle_ != INVALID_HANDLE_VALUE) {
        const DWORD wait =
            ::WaitForSingleObject(process_handle_, static_cast<DWORD>(timeout.count()));
        if (wait != WAIT_OBJECT_0) {
            log_warning("ProcMon did not exit gracefully; forcing termination");
            ::TerminateProcess(process_handle_, 0);
            ::WaitForSingleObject(process_handle_,
                                  static_cast<DWORD>(kHardTerminateGrace.count()));
            graceful = false;
        }
    }
    return graceful;
}

bool ProcmonController::ExportCsv(const std::filesystem::path& pml_path,
                                  const std::filesystem::path& csv_path,
                                  std::chrono::milliseconds timeout) {
    std::error_code ec;
    std::filesystem::remove(csv_path, ec);

    std::wstring arguments = L"/AcceptEula /OpenLog \"" + pml_path.wstring() +
                             L"\" /SaveAs \"" + csv_path.wstring() + L"\"";
    const bool ran = RunAndWait(arguments, timeout);
    if (!ran) {
        log_error("ProcMon export process failed");
        return false;
    }

    if (!std::filesystem::exists(csv_path, ec) || ec) {
        log_error("ProcMon export produced no CSV: ", csv_path.string());
        return false;
    }
    const std::uintmax_t size = std::filesystem::file_size(csv_path, ec);
    if (ec || size == 0) {
        log_error("ProcMon export produced an empty CSV: ", csv_path.string());
        return false;
    }
    return true;
}

bool ProcmonController::IsRunning() const {
    if (process_handle_ == nullptr || process_handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    const DWORD wait = ::WaitForSingleObject(process_handle_, 0);
    return wait == WAIT_TIMEOUT;
}

bool ProcmonController::RunAndWait(const std::wstring& arguments,
                                   std::chrono::milliseconds timeout) {
    std::vector<wchar_t> command_line =
        build_command_line(procmon_path_, arguments);

    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process_info = {};
    const BOOL created = ::CreateProcessW(
        procmon_path_.c_str(), command_line.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process_info);
    if (!created) {
        log_error("Failed to launch ProcMon helper: ", last_win32_error_string());
        return false;
    }

    UniqueHandle process(process_info.hProcess);
    UniqueHandle thread(process_info.hThread);

    const DWORD wait = ::WaitForSingleObject(
        process.get(), static_cast<DWORD>(timeout.count()));
    if (wait != WAIT_OBJECT_0) {
        log_error("ProcMon helper timed out");
        ::TerminateProcess(process.get(), 1);
        ::WaitForSingleObject(process.get(),
                              static_cast<DWORD>(kHardTerminateGrace.count()));
        return false;
    }

    DWORD exit_code = 0;
    ::GetExitCodeProcess(process.get(), &exit_code);
    if (exit_code != 0) {
        log_error("ProcMon helper exited with code ", exit_code);
        return false;
    }
    return true;
}

} // namespace defenderatlas
