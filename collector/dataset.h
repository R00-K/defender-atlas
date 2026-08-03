#pragma once

/// \file dataset.h
/// \brief Dataset enumeration for the DefenderAtlas Collector.
///
/// Recursively walks the configured dataset root and discovers every PE sample
/// (*.exe / *.sys). For each sample it computes the SHA-256 digest, the file
/// size, the Authenticode signature status, a stable category derived from the
/// directory layout and the path relative to the dataset root.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace defenderatlas {

/// A single discovered PE sample.
struct Sample {
    /// Absolute path to the sample on disk.
    std::filesystem::path path;

    /// Lowercase hex SHA-256 of the file contents.
    std::string sha256;

    /// File size in bytes.
    std::uint64_t size = 0;

    /// True when the file carries a valid Authenticode signature.
    bool signedFile = false;

    /// Category derived from the first path component under the dataset root,
    /// e.g. "signed", "unsigned" or "drivers".
    std::string category;

    /// Path of the sample relative to the dataset root, forward slashes,
    /// e.g. "signed/medium/mspaint.exe".
    std::string relativePath;
};

/// Discovers samples under a dataset root.
class DatasetEnumerator {
public:
    /// Recursively enumerate \p dataset_root.
    ///
    /// Returns samples sorted by relative path for reproducible ordering.
    /// Entries whose metadata cannot be computed (missing files, hash errors)
    /// are skipped and never abort the whole enumeration.
    static std::vector<Sample> Enumerate(const std::filesystem::path& dataset_root);
};

} // namespace defenderatlas
