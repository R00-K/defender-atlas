#pragma once

/// \file procmon_filter.h
/// \brief ProcMon filter profiles and CSV filtering.
///
/// The Collector captures a *raw* ProcMon trace and produces both the raw
/// export (capture.csv) and a profile-filtered export (filtered.csv). This
/// module owns the filter model:
///
///   - Three predefined profiles (minimal, extended, full) that select which
///     MsMpEng.exe operations are interesting.
///   - A dynamic path filter: every experiment filters on "Path contains
///     <sample filename>", so the filter is never hardcoded and always matches
///     the exact file that was triggered.
///   - Serialization to a ProcMon filter configuration file (.pmc) so the
///     applied profile can be reviewed or loaded into ProcMon later.
///   - filter_csv(), which applies the profile to the raw capture.csv and
///     writes filtered.csv (this becomes the input for the DefenderAtlas
///     Analyzer).
///
/// The actual capture is never filtered (that would destroy the raw capture);
/// filtering is applied only when producing filtered.csv.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace defenderatlas {

/// Named ProcMon filter profiles.
enum class ProcmonProfile {
    /// Process Name == MsMpEng.exe; Operation == CreateFile/ReadFile.
    Minimal,
    /// Minimal plus QueryInformationFile/QueryStandardInformationFile/CloseFile.
    Extended,
    /// Process Name == MsMpEng.exe; no operation filtering.
    Full,
};

/// Map a configuration string ("minimal"/"extended"/"full") to a profile.
/// Unknown names fall back to Minimal so a bad config never breaks collection.
ProcmonProfile parse_procmon_profile(const std::string& name);

/// Canonical lowercase name of \p profile, e.g. "minimal".
std::string procmon_profile_name(ProcmonProfile profile);

/// Operations selected by \p profile (empty = all operations).
const std::vector<std::string>& procmon_profile_operations(ProcmonProfile profile);

/// A profile-specific filter bound to one sample filename.
class ProcmonFilter {
public:
    /// \param profile_name Config string naming the profile.
    /// \param sample_filename File name of the triggered sample; the filter
    ///        matches only paths that contain it.
    ProcmonFilter(std::string profile_name, std::string sample_filename);

    /// Canonical profile name, e.g. "minimal".
    std::string profile_name() const;

    /// The sample file name this filter was built for.
    std::string sample_filename() const;

    /// Return true when a ProcMon record (process name, operation, path) is
    /// kept by this profile.
    bool Matches(const std::string& process_name, const std::string& operation,
                 const std::string& path) const;

    /// Write a ProcMon filter configuration file (.pmc) describing this
    /// profile for the given sample. Throws std::runtime_error on write
    /// failure.
    void WriteConfig(const std::filesystem::path& pmc_path) const;

private:
    ProcmonProfile profile_;
    std::string profile_name_;
    std::string sample_filename_lower_;
};

/// Row counts produced by filter_csv().
struct CsvFilterStats {
    /// Number of data rows read from the raw CSV.
    std::uint64_t input_rows = 0;
    /// Number of rows kept in the filtered CSV.
    std::uint64_t output_rows = 0;
};

/// Filter the raw ProcMon CSV at \p input_path into \p output_path using
/// \p filter. The header line is copied verbatim; only matching data rows are
/// kept. Throws std::runtime_error on I/O failure. Malformed individual rows
/// are skipped, never fatal.
CsvFilterStats filter_csv(const std::filesystem::path& input_path,
                          const std::filesystem::path& output_path,
                          const ProcmonFilter& filter);

} // namespace defenderatlas
