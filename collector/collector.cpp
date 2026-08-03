/// \file collector.cpp
/// \brief Implementation of the collection engine.

#include "collector.h"

#include "experiment.h"
#include "log.h"
#include "metadata.h"
#include "procmon.h"
#include "procmon_filter.h"
#include "util.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace defenderatlas {

namespace {

/// RAII guard that removes a directory tree on scope exit (best effort).
class RemoveDirectoryOnExit {
public:
    explicit RemoveDirectoryOnExit(std::filesystem::path path)
        : path_(std::move(path)) {}
    ~RemoveDirectoryOnExit() {
        if (path_.empty()) {
            return;
        }
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    void cancel() { path_.clear(); }

private:
    std::filesystem::path path_;
};

/// Subdirectory under the working directory used as the trigger target.
std::filesystem::path working_copy_directory(const Config& config,
                                             std::uint32_t experiment_id) {
    char id[16] = {};
    std::snprintf(id, sizeof(id), "%06u", static_cast<unsigned>(experiment_id));
    return config.working_directory / (std::string("defenderatlas_") + id);
}

/// Write a basic markdown report so every experiment ends with a report.md
/// even when the configured analyzer is missing or fails.
void write_fallback_report(const ExperimentDirectory& experiment,
                           const Sample& sample, const ProcmonFilter& filter,
                           const CsvFilterStats& stats) {
    std::string report;
    report += "# Experiment " + std::to_string(experiment.id()) +
              " — Analysis Report (auto-generated)\n\n";
    report += "- Sample: " + sample.path.filename().string() + "\n";
    report += "- SHA-256: " + sample.sha256 + "\n";
    report += "- ProcMon profile: " + filter.profile_name() + "\n";
    report += "- Dynamic path filter: " + filter.sample_filename() + "\n";
    report += "- Raw capture rows: " + std::to_string(stats.input_rows) + "\n";
    report += "- Filtered rows: " + std::to_string(stats.output_rows) + "\n";
    report += "- Generated: " + utc_timestamp_iso8601() + "\n";
    write_text_file(experiment.report_path(), report);
}

/// Run the configured analyzer on the experiment's filtered.csv and return the
/// analysis outcome: "completed", "failed" or "skipped". Never throws.
std::string run_analyzer(const Config& config, const ExperimentDirectory& experiment,
                         const Sample& sample, const ProcmonFilter& filter,
                         const CsvFilterStats& stats) {
    const auto generate_fallback = [&]() {
        try {
            write_fallback_report(experiment, sample, filter, stats);
        } catch (const std::exception& e) {
            log_error("Could not write fallback report: ", e.what());
        }
    };

    if (config.analyzer_path.empty()) {
        log_info("No analyzer configured; generating report.md");
        generate_fallback();
        return "skipped";
    }
    if (!file_exists(config.analyzer_path)) {
        log_warning("Analyzer not found at: ", config.analyzer_path.string(),
                    "; generating report.md");
        generate_fallback();
        return "skipped";
    }

    log_info("Launching DefenderAtlas Analyzer: ", config.analyzer_path.string());
    const ProcessResult process = run_process(
        config.analyzer_path,
        {experiment.filtered_csv_path().wstring(), experiment.report_path().wstring()},
        config.analyzer_timeout_ms, /*capture_output=*/false);
    if (!process.started) {
        log_error("Failed to launch analyzer: ", process.error);
        generate_fallback();
        return "failed";
    }
    if (process.timed_out) {
        log_error("Analyzer timed out after ", config.analyzer_timeout_ms, " ms");
        generate_fallback();
        return "failed";
    }
    if (process.exit_code != 0) {
        log_error("Analyzer exited with code ", process.exit_code);
        generate_fallback();
        return "failed";
    }

    std::error_code ec;
    if (!std::filesystem::exists(experiment.report_path(), ec) || ec) {
        log_warning("Analyzer produced no report; generating report.md");
        generate_fallback();
    }
    return "completed";
}

} // namespace

Collector::Collector(Config config, std::unique_ptr<ITrigger> trigger,
                     std::unique_ptr<ICompletionStrategy> completion)
    : config_(std::move(config)),
      trigger_(std::move(trigger)),
      completion_(std::move(completion)) {}

bool Collector::Run() {
    const std::vector<Sample> samples = DatasetEnumerator::Enumerate(config_.dataset_root);
    if (samples.empty()) {
        log_warning("No samples discovered under: ", config_.dataset_root.string());
        return false;
    }
    log_info("Discovered ", samples.size(), " samples under ",
             config_.dataset_root.string());

    std::size_t succeeded = 0;
    std::size_t failed = 0;
    for (const auto& sample : samples) {
        log_info("Processing sample: ", sample.relativePath, " (",
                 sample.size, " bytes, signed=",
                 sample.signedFile ? "yes" : "no", ")");
        if (CollectSample(sample)) {
            ++succeeded;
        } else {
            ++failed;
            log_warning("Sample failed, continuing with next sample");
        }
        log_info("Progress: ", succeeded, " succeeded, ", failed, " failed");
    }

    log_info("Collection finished: ", succeeded, " succeeded, ", failed,
             " failed out of ", samples.size());
    return failed == 0;
}

bool Collector::CollectSample(const Sample& sample) {
    // Allocating the directory early means even a crash-level failure still has
    // a home for a metadata.json with result=failed.
    ExperimentDirectory experiment(config_.experiment_root);
    const std::string result_failed = "failed";
    const std::string sample_filename = sample.path.filename().string();
    const ProcmonFilter filter(config_.procmon_filter_profile, sample_filename);
    bool success = false;
    bool trigger_ok = false;
    std::string trigger_message = "not triggered";
    std::string analysis = "failed";

    try {
        log_info("Experiment ", experiment.id(), " started for ",
                 sample.relativePath);

        // 1. Apply the ProcMon filter profile for this experiment. The dynamic
        //    path filter is derived from the sample file name, never hardcoded.
        log_info("Applying ProcMon filter profile: ", filter.profile_name());
        log_info("Generated dynamic path filter: ", sample_filename);
        try {
            filter.WriteConfig(experiment.pmc_path());
        } catch (const std::exception& e) {
            log_error("Could not write ProcMon filter config: ", e.what());
        }

        // 2. Copy the sample into the experiment directory (canonical artifact).
        std::filesystem::copy_file(sample.path, experiment.sample_path(),
                                   std::filesystem::copy_options::overwrite_existing);

        // 3. Copy the sample into the working directory (the "Downloads" area)
        //    that the trigger presents to Attachment Services as a new file.
        //    The working copy keeps the sample's original file name so the
        //    dynamic path filter matches the events Defender generates.
        const std::filesystem::path work_dir =
            working_copy_directory(config_, experiment.id());
        ensure_directory(work_dir);
        RemoveDirectoryOnExit cleanup(work_dir);
        const std::filesystem::path trigger_path = work_dir / sample_filename;
        std::filesystem::copy_file(sample.path, trigger_path,
                                   std::filesystem::copy_options::overwrite_existing);

        // 4. Start ProcMon capturing into the experiment directory.
        ProcmonController procmon(config_.procmon_path);
        const bool started = procmon.Start(experiment.pml_path());

        // 5. Wait until ProcMon is ready (best effort; still trigger when the
        //    readiness probe times out so the scan is never skipped).
        const bool ready =
            started && procmon.WaitUntilReady(std::chrono::milliseconds(
                           config_.procmon_ready_timeout_ms));
        if (!ready) {
            log_warning("ProcMon did not confirm readiness; triggering anyway");
        }

        // 6. Reproduce the download event.
        log_info("Triggering sample (", trigger_->Name(), "): ",
                 sample.relativePath);
        const TriggerResult trigger_result = trigger_->Run(trigger_path);
        trigger_ok = trigger_result.success;
        trigger_message = trigger_result.message;
        if (trigger_ok) {
            log_info("Trigger completed: ", trigger_result.message);
        } else {
            log_warning("Trigger failed: ", trigger_result.message);
        }

        // 7. Wait for the completion strategy.
        log_info("Waiting for completion (strategy: ", completion_->Name(), ")");
        const bool waited = completion_->Wait();
        if (!waited) {
            log_warning("Completion strategy reported failure");
        }

        // 8. Stop ProcMon.
        log_info("Stopping ProcMon");
        const bool stopped = procmon.Stop(std::chrono::milliseconds(
            config_.procmon_stop_timeout_ms));
        if (!stopped) {
            log_warning("ProcMon did not stop cleanly");
        }

        // 9. Export the raw CSV capture.
        log_info("Exporting CSV");
        const bool exported = started &&
                              procmon.ExportCsv(experiment.pml_path(),
                                                experiment.csv_path(),
                                                std::chrono::milliseconds(
                                                    config_.procmon_export_timeout_ms));
        if (!exported) {
            log_error("ProcMon CSV export failed for experiment ",
                      experiment.id());
        }

        // 10. Generate the profile-filtered CSV (capture.csv stays raw).
        CsvFilterStats filter_stats;
        if (exported) {
            try {
                log_info("Exporting filtered CSV");
                filter_stats =
                    filter_csv(experiment.csv_path(), experiment.filtered_csv_path(), filter);
            } catch (const std::exception& e) {
                log_error("Filtered CSV generation failed for experiment ",
                          experiment.id(), ": ", e.what());
            }
        }

        // 11. Run the analyzer on filtered.csv; report.md always exists after.
        try {
            analysis = run_analyzer(config_, experiment, sample, filter, filter_stats);
        } catch (const std::exception& e) {
            log_error("Analysis step failed for experiment ", experiment.id(),
                      ": ", e.what());
            analysis = "failed";
        }

        // 12. Write metadata, manifest and trigger parameters.
        success = ready && trigger_ok && exported;
        const std::string result = success ? "success" : result_failed;
        const ExperimentMetadata metadata =
            BuildMetadata(experiment, sample, result, filter.profile_name(), analysis);
        write_metadata(experiment.metadata_path(), metadata);
        try {
            write_manifest(experiment.manifest_path(), experiment.id(),
                           success ? "completed" : "failed", sample_filename,
                           experiment.pml_path(), experiment.csv_path(),
                           experiment.filtered_csv_path(), experiment.report_path());
            write_trigger_info(experiment.trigger_info_path(), trigger_->Name(),
                               config_.source_url, sample_filename,
                               completion_->Name(), filter.profile_name());
        } catch (const std::exception& e) {
            log_error("Could not write manifest/trigger info: ", e.what());
        }
        log_info("Experiment ", experiment.id(), " completed: ", result);
        if (success) {
            log_info("Experiment completed successfully");
        }
        return success;
    } catch (const std::exception& e) {
        log_error("Experiment ", experiment.id(), " aborted: ", e.what());
    }

    // Best-effort artifacts even when the pipeline threw.
    try {
        const ExperimentMetadata metadata = BuildMetadata(
            experiment, sample, result_failed, filter.profile_name(), analysis);
        write_metadata(experiment.metadata_path(), metadata);
        write_manifest(experiment.manifest_path(), experiment.id(), "failed",
                       sample_filename, experiment.pml_path(), experiment.csv_path(),
                       experiment.filtered_csv_path(), experiment.report_path());
        write_trigger_info(experiment.trigger_info_path(), trigger_->Name(),
                           config_.source_url, sample_filename,
                           completion_->Name(), filter.profile_name());
    } catch (const std::exception& e) {
        log_error("Could not write failed artifacts for experiment ",
                  experiment.id(), ": ", e.what());
    }
    return false;
}

ExperimentMetadata Collector::BuildMetadata(const ExperimentDirectory& experiment,
                                            const Sample& sample,
                                            const std::string& result,
                                            const std::string& procmon_profile,
                                            const std::string& analysis) const {
    ExperimentMetadata metadata;
    metadata.experiment_id = experiment.id();
    metadata.sample = sample.path.filename().string();
    metadata.relative_path = sample.relativePath;
    metadata.sha256 = sample.sha256;
    metadata.size = sample.size;
    metadata.trigger = trigger_->Name();
    metadata.completion_strategy = completion_->Name();
    metadata.procmon_profile = procmon_profile;
    metadata.signedFile = sample.signedFile;
    metadata.category = sample.category;
    metadata.analysis = analysis;
    metadata.timestamp = utc_timestamp_iso8601();
    metadata.result = result;
    return metadata;
}

} // namespace defenderatlas
