#pragma once

/// \file experiment.h
/// \brief Experiment directory management.
///
/// Each sample collection run produces one experiment directory:
///
///     experiments/
///        000001/
///            sample.exe
///            capture.pml
///            capture.csv
///            filtered.csv
///            procmon_filter.pmc
///            report.md
///            manifest.json
///            trigger.json
///            metadata.json
///        000002/
///            ...
///
/// Experiment IDs auto-increment and are never reused: ID allocation scans the
/// experiment root for the highest existing numeric directory and returns the
/// next value, so existing experiments are never overwritten.

#include <cstdint>
#include <filesystem>

namespace defenderatlas {

/// Describes a single, freshly allocated experiment directory.
class ExperimentDirectory {
public:
    /// Allocate the next free experiment ID and create its directory.
    /// Throws std::runtime_error when the root cannot be created.
    explicit ExperimentDirectory(std::filesystem::path experiment_root);

    ExperimentDirectory(const ExperimentDirectory&) = delete;
    ExperimentDirectory& operator=(const ExperimentDirectory&) = delete;

    /// The zero-padded experiment ID (1 -> "000001").
    std::uint32_t id() const { return id_; }

    /// Absolute path of the experiment directory.
    std::filesystem::path path() const { return path_; }

    /// Path of the copied sample (sample.exe).
    std::filesystem::path sample_path() const { return path_ / L"sample.exe"; }

    /// Path of the raw ProcMon capture (capture.pml).
    std::filesystem::path pml_path() const { return path_ / L"capture.pml"; }

    /// Path of the exported ProcMon CSV (capture.csv).
    std::filesystem::path csv_path() const { return path_ / L"capture.csv"; }

    /// Path of the profile-filtered ProcMon CSV (filtered.csv).
    std::filesystem::path filtered_csv_path() const { return path_ / L"filtered.csv"; }

    /// Path of the ProcMon filter configuration (.pmc) used for this experiment.
    std::filesystem::path pmc_path() const { return path_ / L"procmon_filter.pmc"; }

    /// Path of the analysis report (report.md).
    std::filesystem::path report_path() const { return path_ / L"report.md"; }

    /// Path of the experiment manifest (manifest.json).
    std::filesystem::path manifest_path() const { return path_ / L"manifest.json"; }

    /// Path of the trigger parameters (trigger.json).
    std::filesystem::path trigger_info_path() const { return path_ / L"trigger.json"; }

    /// Path of the experiment metadata file (metadata.json).
    std::filesystem::path metadata_path() const { return path_ / L"metadata.json"; }

    /// Scan \p experiment_root and return the next free ID (max numeric
    /// directory name + 1), starting at 1.
    static std::uint32_t NextId(const std::filesystem::path& experiment_root);

private:
    std::uint32_t id_ = 0;
    std::filesystem::path path_;
};

} // namespace defenderatlas
