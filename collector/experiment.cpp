/// \file experiment.cpp
/// \brief Implementation of the experiment directory manager.

#include "experiment.h"

#include "util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <system_error>

namespace defenderatlas {

namespace {

/// Format a numeric ID as a zero-padded 6-digit directory name.
std::string format_id(std::uint32_t id) {
    char buffer[16] = {};
    std::snprintf(buffer, sizeof(buffer), "%06u", static_cast<unsigned>(id));
    return std::string(buffer);
}

bool is_numeric_directory_name(const std::string& name) {
    if (name.size() != 6) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c)) != 0;
    });
}

} // namespace

std::uint32_t ExperimentDirectory::NextId(
    const std::filesystem::path& experiment_root) {
    ensure_directory(experiment_root);

    std::uint32_t highest = 0;
    std::error_code ec;
    std::filesystem::directory_iterator iterator(experiment_root, ec);
    if (ec) {
        return 1;
    }
    for (const auto& entry : iterator) {
        std::error_code entry_ec;
        if (!entry.is_directory(entry_ec) || entry_ec) {
            continue;
        }
        const std::string name = entry.path().filename().string();
        if (!is_numeric_directory_name(name)) {
            continue;
        }
        std::uint32_t value = 0;
        try {
            value = static_cast<std::uint32_t>(std::stoul(name));
        } catch (...) {
            continue;
        }
        highest = std::max(highest, value);
    }
    return highest + 1;
}

ExperimentDirectory::ExperimentDirectory(std::filesystem::path experiment_root) {
    id_ = NextId(experiment_root);
    path_ = experiment_root / format_id(id_);
    ensure_directory(path_);
}

} // namespace defenderatlas
