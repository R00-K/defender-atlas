/// \file log.cpp
/// \brief Implementation of the leveled logger declared in log.h.

#include "log.h"

#include "util.h"

#include <windows.h>

#include <cstdio>
#include <fstream>
#include <mutex>

namespace defenderatlas {

namespace {

/// Function-local singleton state so the module has no global variables.
struct LogState {
    std::mutex mutex;
    std::filesystem::path file_path;
    bool file_open = false;
};

LogState& state() {
    static LogState instance;
    return instance;
}

const char* level_tag(LogLevel level) {
    switch (level) {
        case LogLevel::Info:
            return "INFO";
        case LogLevel::Warning:
            return "WARNING";
        case LogLevel::Error:
            return "ERROR";
    }
    return "INFO";
}

std::string format_line(LogLevel level, const std::string& message) {
    return "[" + utc_timestamp_iso8601() + "] [" + level_tag(level) + "] " +
           message;
}

void append_to_file(LogState& st, const std::string& line) {
    if (st.file_path.empty() || !st.file_open) {
        return;
    }
    std::ofstream output(st.file_path, std::ios::app);
    if (!output.is_open()) {
        st.file_open = false;
        return;
    }
    output << line << '\n';
    output.flush();
}

} // namespace

void log_set_file(const std::filesystem::path& path) {
    LogState& st = state();
    std::lock_guard<std::mutex> lock(st.mutex);
    st.file_path = path;
    if (!path.empty()) {
        ensure_directory(path.parent_path());
    }
    st.file_open = st.file_path.empty();
}

void log_level(LogLevel level, const std::string& message) {
    LogState& st = state();
    const std::string line = format_line(level, message);
    std::lock_guard<std::mutex> lock(st.mutex);
    std::puts(line.c_str());
    std::fflush(stdout);
    append_to_file(st, line);
}

} // namespace defenderatlas
