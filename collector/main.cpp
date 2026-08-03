/// \file main.cpp
/// \brief DefenderAtlas Collector entry point.
///
/// Usage:
///     defenderatlas_collector.exe [config.json]
///
/// When the config path is omitted, "./config.json" is used. If the config
/// file does not exist, a default template is written and the process exits so
/// the operator can set the real ProcMon path before the first run.

#include "collector.h"
#include "config.h"
#include "istrategy.h"
#include "itrigger.h"
#include "log.h"
#include "procmon_activity_strategy.h"
#include "subprocess_trigger.h"
#include "timeout_strategy.h"
#include "util.h"

#include <chrono>
#include <filesystem>
#include <memory>

using namespace defenderatlas;

int wmain(int argc, wchar_t* argv[]) {
    const std::filesystem::path config_path =
        (argc > 1) ? std::filesystem::path(argv[1]) : std::filesystem::path(L"config.json");

    log_set_file(L"defenderatlas_collector.log");
    log_info("DefenderAtlas Collector starting");

    if (!path_exists(config_path)) {
        try {
            save_config(config_path, default_config());
        } catch (const std::exception& e) {
            log_error("Could not write default config: ", e.what());
            return 2;
        }
        log_error("No configuration file found; wrote default template to ",
                  config_path.string(),
                  ". Edit it (especially procmon_path) and rerun.");
        return 2;
    }

    Config config;
    try {
        config = load_config(config_path);
    } catch (const std::exception& e) {
        log_error("Failed to load configuration: ", e.what());
        return 1;
    }

    log_info("Configuration loaded from ", config_path.string());
    log_info("  procmon_path:      ", config.procmon_path.string());
    log_info("  dataset_root:      ", config.dataset_root.string());
    log_info("  experiment_root:   ", config.experiment_root.string());
    log_info("  working_directory: ", config.working_directory.string());
    log_info("  trigger_timeout:   ", config.trigger_timeout_ms, " ms");
    log_info("  worker_timeout:    ", config.trigger_worker_timeout_ms, " ms");
    log_info("  trigger_worker:    ", config.trigger_worker_path.string());
    log_info("  completion_strategy: ", config.completion_strategy);
    log_info("  filter_profile:    ", config.procmon_filter_profile);
    log_info("  analyzer_path:     ", config.analyzer_path.string());

    if (!file_exists(config.procmon_path)) {
        log_warning("ProcMon executable not found at: ",
                    config.procmon_path.string());
    }
    if (!file_exists(config.trigger_worker_path)) {
        log_warning("Trigger worker not found at: ",
                    config.trigger_worker_path.string());
    }

    auto trigger = std::make_unique<SubprocessTrigger>(
        config.trigger_worker_path, config.source_url,
        config.trigger_worker_timeout_ms);

    std::unique_ptr<ICompletionStrategy> completion;
    if (config.completion_strategy == "procmon_activity") {
        completion = std::make_unique<ProcMonActivityCompletionStrategy>();
    } else {
        if (config.completion_strategy != "timeout") {
            log_warning("Unknown completion strategy '",
                        config.completion_strategy,
                        "'; falling back to 'timeout'");
        }
        completion = std::make_unique<TimeoutCompletionStrategy>(
            std::chrono::milliseconds(config.trigger_timeout_ms));
    }

    Collector collector(std::move(config), std::move(trigger), std::move(completion));
    const bool ok = collector.Run();

    log_info(ok ? "DefenderAtlas Collector finished successfully"
                : "DefenderAtlas Collector finished with failures");
    return ok ? 0 : 1;
}
