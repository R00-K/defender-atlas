#pragma once

/// \file log.h
/// \brief Thread-safe, leveled logging for the DefenderAtlas Collector.
///
/// Messages are printed to standard output prefixed with an ISO 8601 UTC
/// timestamp and a level tag, e.g.:
///
///     [2026-08-02T12:34:56.789Z] [INFO] Starting ProcMon
///
/// An optional log file can be configured with log_set_file(); when set, every
/// line is also appended there. The logger is lazily initialized on first use
/// and holds no global state visible to the rest of the code base.

#include <filesystem>
#include <sstream>
#include <string>

namespace defenderatlas {

enum class LogLevel {
    Info,
    Warning,
    Error,
};

/// Write every subsequent log line to \p path as well as to the console.
/// Empty path disables file logging. Never throws.
void log_set_file(const std::filesystem::path& path);

/// Emit a single formatted message at \p level.
void log_level(LogLevel level, const std::string& message);

/// Append the string representation of each argument to \p stream.
inline void append_args(std::ostringstream&) {}

template <typename First, typename... Rest>
void append_args(std::ostringstream& stream, const First& first,
                 const Rest&... rest) {
    stream << first;
    append_args(stream, rest...);
}

/// Build a single string from any number of ostream-printable arguments.
template <typename... Args>
std::string format_args(const Args&... args) {
    std::ostringstream stream;
    append_args(stream, args...);
    return stream.str();
}

template <typename... Args>
void log_info(const Args&... args) {
    log_level(LogLevel::Info, format_args(args...));
}

template <typename... Args>
void log_warning(const Args&... args) {
    log_level(LogLevel::Warning, format_args(args...));
}

template <typename... Args>
void log_error(const Args&... args) {
    log_level(LogLevel::Error, format_args(args...));
}

} // namespace defenderatlas
