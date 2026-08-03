/// \file dataset.cpp
/// \brief Implementation of the dataset enumerator declared in dataset.h.

#include "dataset.h"

#include "log.h"
#include "util.h"

#include <algorithm>
#include <cctype>
#include <system_error>

namespace defenderatlas {

namespace {

bool is_pe_extension(const std::filesystem::path& path) {
    const std::string extension = path.extension().string();
    return extension == ".exe" || extension == ".sys";
}

std::string path_to_forward_slashes(const std::filesystem::path& path) {
    std::string text = path.generic_string();
    return text;
}

void collect_recursive(const std::filesystem::path& dataset_root,
                       const std::filesystem::path& directory,
                       std::vector<Sample>& samples) {
    std::error_code ec;
    std::filesystem::directory_iterator iterator(directory, ec);
    if (ec) {
        log_warning("Cannot read directory: ", directory.string());
        return;
    }
    for (const auto& entry : iterator) {
        std::error_code entry_ec;
        if (entry.is_directory(entry_ec)) {
            collect_recursive(dataset_root, entry.path(), samples);
            continue;
        }
        if (entry_ec) {
            continue;
        }
        if (!entry.is_regular_file(entry_ec) || entry_ec) {
            continue;
        }
        if (!is_pe_extension(entry.path())) {
            continue;
        }

        Sample sample;
        sample.path = entry.path();
        sample.size = entry.file_size(entry_ec);
        if (entry_ec) {
            continue;
        }
        sample.sha256 = sha256_file(sample.path);
        if (sample.sha256.empty()) {
            log_warning("Cannot hash sample, skipping: ", entry.path().string());
            continue;
        }
        sample.signedFile = is_signed_pe(sample.path);

        const std::filesystem::path relative =
            std::filesystem::relative(entry.path(), dataset_root, entry_ec);
        if (entry_ec) {
            sample.relativePath = entry.path().filename().string();
        } else {
            sample.relativePath = path_to_forward_slashes(relative);
        }

        const std::size_t separator = sample.relativePath.find('/');
        sample.category = separator == std::string::npos
                              ? std::string()
                              : sample.relativePath.substr(0, separator);

        samples.push_back(std::move(sample));
    }
}

} // namespace

std::vector<Sample> DatasetEnumerator::Enumerate(
    const std::filesystem::path& dataset_root) {
    std::vector<Sample> samples;
    std::error_code ec;
    if (!std::filesystem::exists(dataset_root, ec) || ec) {
        log_warning("Dataset root does not exist: ", dataset_root.string());
        return samples;
    }
    collect_recursive(dataset_root, dataset_root, samples);
    std::sort(samples.begin(), samples.end(),
              [](const Sample& a, const Sample& b) {
                  return a.relativePath < b.relativePath;
              });
    return samples;
}

} // namespace defenderatlas
