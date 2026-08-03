#pragma once

/// \file metadata.h
/// \brief Experiment metadata, manifest and trigger-info generation.
///
/// Every experiment ends with three JSON artifacts:
///
///   - metadata.json  — the experiment descriptor (sample identity, trigger,
///                      completion strategy, capture outcome, analysis status)
///   - manifest.json  — a short index of the artifacts produced for the
///                      experiment (capture.pml/capture.csv/filtered.csv and
///                      report.md)
///   - trigger.json   — the exact trigger parameters, so the experiment can be
///                      reproduced later
///
/// The metadata schema is the contract consumed by the DefenderAtlas Analyzer,
/// so it is kept stable and only ever extended.

#include <cstdint>
#include <filesystem>
#include <string>

namespace defenderatlas {

/// Collector version stamped into every experiment's JSON artifacts.
inline constexpr const char* kCollectorVersion = "1.1";

/// Fields written to a metadata.json file.
struct ExperimentMetadata {
    /// Experiment ID (matches the enclosing directory name).
    std::uint32_t experiment_id = 0;

    /// File name of the captured sample, e.g. "mspaint.exe".
    std::string sample;

    /// Sample path relative to the dataset root, e.g.
    /// "signed/medium/mspaint.exe".
    std::string relative_path;

    /// Lowercase hex SHA-256 of the sample.
    std::string sha256;

    /// Sample size in bytes.
    std::uint64_t size = 0;

    /// Trigger name, e.g. "attachment".
    std::string trigger;

    /// Completion strategy name, e.g. "timeout".
    std::string completion_strategy;

    /// ProcMon filter profile used for this experiment, e.g. "minimal".
    std::string procmon_profile;

    /// True when the sample carries a valid Authenticode signature.
    bool signedFile = false;

    /// Sample category derived from the dataset layout, e.g. "signed".
    std::string category;

    /// Outcome of the analysis step: "completed", "failed" or "skipped".
    std::string analysis;

    /// ISO 8601 UTC timestamp of metadata generation.
    std::string timestamp;

    /// Outcome: "success" or "failed".
    std::string result;
};

/// Serialize \p metadata to pretty-printed JSON and write it to \p path.
/// Throws std::runtime_error on failure.
void write_metadata(const std::filesystem::path& path,
                    const ExperimentMetadata& metadata);

/// Write a manifest.json index for one experiment to \p path. \p pml/csv/
/// filtered/report are the artifact paths; only their file names are recorded.
/// Throws std::runtime_error on failure.
void write_manifest(const std::filesystem::path& path, std::uint32_t experiment_id,
                    const std::string& status, const std::string& sample,
                    const std::filesystem::path& pml,
                    const std::filesystem::path& csv,
                    const std::filesystem::path& filtered,
                    const std::filesystem::path& report);

/// Write a trigger.json describing the exact trigger parameters of an
/// experiment to \p path. Throws std::runtime_error on failure.
void write_trigger_info(const std::filesystem::path& path,
                        const std::string& trigger, const std::string& source_url,
                        const std::string& working_copy,
                        const std::string& completion_strategy,
                        const std::string& procmon_profile);

} // namespace defenderatlas
