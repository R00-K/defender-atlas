#pragma once

/// \file util.h
/// \brief Shared, reusable helpers for the DefenderAtlas Collector.
///
/// This module contains platform helpers (Win32 + std::filesystem) that are
/// deliberately trigger/collector agnostic so they can be reused by any
/// future component (ETW capture, analyzers, etc.).
///
/// It intentionally has no global state: every helper is a free function or a
/// small RAII type.

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <type_traits>
#include <vector>

namespace defenderatlas {

// ---------------------------------------------------------------------------
// Text / path conversion
// ---------------------------------------------------------------------------

/// Convert a UTF-8 encoded narrow string to a UTF-16 wide string.
std::wstring from_utf8(const std::string& text);

/// Convert a UTF-16 wide string to a UTF-8 encoded narrow string.
std::string to_utf8(const std::wstring& text);

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

/// Return true if \p path exists (file or directory).
bool path_exists(const std::filesystem::path& path);

/// Return true if \p path exists and is a regular file.
bool file_exists(const std::filesystem::path& path);

/// Create \p path and any missing parents. Never throws.
void ensure_directory(const std::filesystem::path& path);

/// Read the entire contents of \p path as UTF-8 text.
/// Throws std::runtime_error when the file cannot be opened or read.
std::string read_text_file(const std::filesystem::path& path);

/// Write \p text to \p path as UTF-8 (overwrites existing content).
/// Throws std::runtime_error when the file cannot be written.
void write_text_file(const std::filesystem::path& path, const std::string& text);

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Compute the lowercase hex-encoded SHA-256 digest of \p path.
/// Returns an empty string when the file cannot be read.
std::string sha256_file(const std::filesystem::path& path);

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Return true when \p path carries a valid signature as judged by Windows:
/// either an embedded Authenticode signature or membership in a trusted
/// Windows catalog (catalog-signed inbox binaries). Unsigned or tampered files
/// return false.
bool is_signed_pe(const std::filesystem::path& path);

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Return the current UTC time as an ISO 8601 string with milliseconds,
/// e.g. "2026-08-02T12:34:56.789Z".
std::string utc_timestamp_iso8601();

// ---------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------

/// Outcome of running a child process.
struct ProcessResult {
    /// True when the child process was created successfully.
    bool started = false;

    /// True when the process was still running when the timeout elapsed and
    /// had to be terminated.
    bool timed_out = false;

    /// The process exit code (valid when started and not timed out).
    DWORD exit_code = 0;

    /// Captured standard output (UTF-8) when capture_output was requested.
    std::string stdout_text;

    /// Human readable error when the process could not be started.
    std::string error;
};

/// Run \p executable with \p arguments and wait up to \p timeout_ms.
///
/// When \p capture_output is true, standard output (and standard error) are
/// merged into ProcessResult::stdout_text. The caller must keep the expected
/// output small (well below the pipe buffer) because output is only drained
/// after the process exits. When false, the child inherits the parent console
/// and no pipe is created (safe for output-heavy tools).
///
/// On timeout the child is force-terminated. Never throws.
ProcessResult run_process(const std::filesystem::path& executable,
                          const std::vector<std::wstring>& arguments,
                          std::uint64_t timeout_ms,
                          bool capture_output = true);

// ---------------------------------------------------------------------------
// Win32 error handling
// ---------------------------------------------------------------------------

/// Format a Win32 error code (GetLastError style) as a human readable string.
std::string win32_error_string(DWORD error_code);

/// Format the last error of the calling thread.
std::string last_win32_error_string();

// ---------------------------------------------------------------------------
// RAII helpers
// ---------------------------------------------------------------------------

/// RAII wrapper around a Win32 HANDLE. Closes the handle on destruction.
/// Never auto-closes on move, never copied. Safe with INVALID_HANDLE_VALUE.
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : handle_(handle) {}

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = NULL;
    }
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    ~UniqueHandle() { close(); }

    /// True when the wrapped handle is a valid, usable handle.
    explicit operator bool() const { return is_valid(); }

    HANDLE get() const { return handle_; }

    /// Release ownership and return the raw handle without closing it.
    HANDLE release() {
        HANDLE raw = handle_;
        handle_ = NULL;
        return raw;
    }

    /// Replace the wrapped handle, closing the previous one.
    void reset(HANDLE handle = NULL) {
        if (handle_ != handle) {
            close();
            handle_ = handle;
        }
    }

private:
    bool is_valid() const { return handle_ != NULL && handle_ != INVALID_HANDLE_VALUE; }
    void close() {
        if (is_valid()) {
            ::CloseHandle(handle_);
        }
        handle_ = NULL;
    }

    HANDLE handle_ = NULL;
};

/// RAII initializer for COM. Calls CoInitializeEx on construction and
/// CoUninitialize on destruction. Report whether initialization succeeded
/// via ok() / hr().
class ComInitializer {
public:
    ComInitializer() {
        hr_ = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        ok_ = SUCCEEDED(hr_);
    }

    ComInitializer(const ComInitializer&) = delete;
    ComInitializer& operator=(const ComInitializer&) = delete;

    ~ComInitializer() {
        if (ok_) {
            ::CoUninitialize();
        }
    }

    /// True when COM was initialized successfully.
    bool ok() const { return ok_; }

    /// The HRESULT returned by CoInitializeEx.
    HRESULT hr() const { return hr_; }

private:
    HRESULT hr_ = S_OK;
    bool ok_ = false;
};

/// Minimal RAII smart pointer for COM interface pointers.
/// Calls Release() on destruction; single ownership, move-only.
template <typename Interface>
class ComPtr {
    static_assert(std::is_pointer<Interface*>::value, "Interface must be a COM interface type");

public:
    ComPtr() = default;
    explicit ComPtr(Interface* pointer) : pointer_(pointer) {}

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ComPtr(ComPtr&& other) noexcept : pointer_(other.pointer_) {
        other.pointer_ = nullptr;
    }
    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    ~ComPtr() { reset(); }

    /// True when a non-null interface pointer is held.
    explicit operator bool() const { return pointer_ != nullptr; }

    Interface* get() const { return pointer_; }
    Interface* operator->() const { return pointer_; }

    /// Release the current pointer (if any) and return an address suitable for
    /// passing to CoCreateInstance / QueryInterface as a T** out parameter.
    Interface** put() {
        reset();
        return &pointer_;
    }

    /// Take ownership of \p pointer, releasing any previous one.
    void reset(Interface* pointer = nullptr) {
        if (pointer_ != pointer) {
            if (pointer_ != nullptr) {
                pointer_->Release();
            }
            pointer_ = pointer;
        }
    }

    /// Release ownership without calling Release(); the caller owns the pointer.
    Interface* release() {
        Interface* raw = pointer_;
        pointer_ = nullptr;
        return raw;
    }

private:
    Interface* pointer_ = nullptr;
};

} // namespace defenderatlas
