/// \file config.cpp
/// \brief Implementation of the configuration module declared in config.h.

#include "config.h"

#include "json.h"
#include "util.h"

#include <stdexcept>

namespace defenderatlas {

namespace {

/// Resolve \p value relative to \p base_directory when it is not absolute.
std::filesystem::path resolve_path(const std::filesystem::path& base_directory,
                                   const std::filesystem::path& value) {
    if (value.empty()) {
        return value;
    }
    if (value.is_absolute()) {
        return value;
    }
    return (base_directory / value).lexically_normal();
}

} // namespace

Config default_config() {
    Config config;
    config.procmon_path = L"C:\\Tools\\Procmon64.exe";
    config.dataset_root = L"datasets";
    config.experiment_root = L"experiments";
    config.working_directory = L"C:\\Users\\cruiz\\Downloads";
    config.trigger_timeout_ms = 8000;
    config.trigger_worker_timeout_ms = 30000;
    config.completion_strategy = "timeout";
    config.procmon_filter_profile = "minimal";
    config.analyzer_path = L"defenderatlas_analyzer.exe";
    config.analyzer_timeout_ms = 60000;
    config.source_url = "https://example.com/download";
    config.trigger_worker_path = L"trigger_worker.exe";
    config.procmon_ready_timeout_ms = 15000;
    config.procmon_stop_timeout_ms = 15000;
    config.procmon_export_timeout_ms = 120000;
    return config;
}

Config load_config(const std::filesystem::path& path) {
    std::string text;
    try {
        text = read_text_file(path);
    } catch (const std::runtime_error& e) {
        throw ConfigError("failed to read config file '" + path.string() +
                          "': " + e.what());
    }

    JsonValue root;
    try {
        root = parse_json(text);
    } catch (const JsonError& e) {
        throw ConfigError("invalid JSON in config file '" + path.string() +
                          "': " + e.what());
    }
    if (root.type() != JsonValue::Type::Object) {
        throw ConfigError("config file '" + path.string() +
                          "' must contain a JSON object");
    }

    Config config = default_config();
    const auto as_string = [&](const std::string& key,
                               const std::string& fallback) -> std::string {
        return root.has(key) ? root.at(key).as_string(fallback) : fallback;
    };
    const auto as_u64 = [&](const std::string& key,
                            std::uint64_t fallback) -> std::uint64_t {
        if (!root.has(key)) {
            return fallback;
        }
        const std::int64_t value = root.at(key).as_integer(
            static_cast<std::int64_t>(fallback));
        return value >= 0 ? static_cast<std::uint64_t>(value) : fallback;
    };

    config.procmon_path = as_string("procmon_path", config.procmon_path.string());
    config.dataset_root = as_string("dataset_root", config.dataset_root.string());
    config.experiment_root =
        as_string("experiment_root", config.experiment_root.string());
    config.working_directory =
        as_string("working_directory", config.working_directory.string());
    config.source_url = as_string("source_url", config.source_url);
    config.trigger_worker_path =
        as_string("trigger_worker_path", config.trigger_worker_path.string());
    config.trigger_timeout_ms = as_u64("trigger_timeout_ms", config.trigger_timeout_ms);
    config.trigger_worker_timeout_ms =
        as_u64("trigger_worker_timeout_ms", config.trigger_worker_timeout_ms);
    config.completion_strategy =
        as_string("completion_strategy", config.completion_strategy);
    config.procmon_filter_profile =
        as_string("procmon_filter_profile", config.procmon_filter_profile);
    config.analyzer_path = as_string("analyzer_path", config.analyzer_path.string());
    config.analyzer_timeout_ms =
        as_u64("analyzer_timeout_ms", config.analyzer_timeout_ms);
    config.procmon_ready_timeout_ms =
        as_u64("procmon_ready_timeout_ms", config.procmon_ready_timeout_ms);
    config.procmon_stop_timeout_ms =
        as_u64("procmon_stop_timeout_ms", config.procmon_stop_timeout_ms);
    config.procmon_export_timeout_ms =
        as_u64("procmon_export_timeout_ms", config.procmon_export_timeout_ms);

    // Resolve relative paths against the config file's own directory so the
    // Collector can run from any working directory.
    const std::filesystem::path config_dir =
        path.has_parent_path() ? path.parent_path()
                               : std::filesystem::path(L".");
    config.procmon_path = resolve_path(config_dir, config.procmon_path);
    config.dataset_root = resolve_path(config_dir, config.dataset_root);
    config.experiment_root = resolve_path(config_dir, config.experiment_root);
    config.working_directory = resolve_path(config_dir, config.working_directory);
    config.trigger_worker_path = resolve_path(config_dir, config.trigger_worker_path);
    config.analyzer_path = resolve_path(config_dir, config.analyzer_path);

    return config;
}

void save_config(const std::filesystem::path& path, const Config& config) {
    JsonValue root = JsonValue::Object();
    root.set("procmon_path", JsonValue::String(config.procmon_path.string()));
    root.set("dataset_root", JsonValue::String(config.dataset_root.string()));
    root.set("experiment_root", JsonValue::String(config.experiment_root.string()));
    root.set("working_directory", JsonValue::String(config.working_directory.string()));
    root.set("trigger_timeout_ms", JsonValue::Integer(
                                       static_cast<std::int64_t>(config.trigger_timeout_ms)));
    root.set("trigger_worker_timeout_ms",
             JsonValue::Integer(
                 static_cast<std::int64_t>(config.trigger_worker_timeout_ms)));
    root.set("completion_strategy", JsonValue::String(config.completion_strategy));
    root.set("procmon_filter_profile",
             JsonValue::String(config.procmon_filter_profile));
    root.set("analyzer_path", JsonValue::String(config.analyzer_path.string()));
    root.set("analyzer_timeout_ms",
             JsonValue::Integer(
                 static_cast<std::int64_t>(config.analyzer_timeout_ms)));
    root.set("source_url", JsonValue::String(config.source_url));
    root.set("trigger_worker_path",
             JsonValue::String(config.trigger_worker_path.string()));
    root.set("procmon_ready_timeout_ms",
             JsonValue::Integer(
                 static_cast<std::int64_t>(config.procmon_ready_timeout_ms)));
    root.set("procmon_stop_timeout_ms",
             JsonValue::Integer(
                 static_cast<std::int64_t>(config.procmon_stop_timeout_ms)));
    root.set("procmon_export_timeout_ms",
             JsonValue::Integer(
                 static_cast<std::int64_t>(config.procmon_export_timeout_ms)));

    try {
        write_text_file(path, serialize_json(root, 4) + "\n");
    } catch (const std::runtime_error& e) {
        throw ConfigError("failed to write config file '" + path.string() +
                          "': " + e.what());
    }
}

} // namespace defenderatlas
