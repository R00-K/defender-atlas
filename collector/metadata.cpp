/// \file metadata.cpp
/// \brief Implementation of experiment metadata, manifest and trigger-info
///        generation.

#include "metadata.h"

#include "json.h"
#include "util.h"

namespace defenderatlas {

void write_metadata(const std::filesystem::path& path,
                    const ExperimentMetadata& metadata) {
    JsonValue root = JsonValue::Object();
    root.set("experiment_id",
             JsonValue::Integer(static_cast<std::int64_t>(metadata.experiment_id)));
    root.set("sample", JsonValue::String(metadata.sample));
    root.set("relative_path", JsonValue::String(metadata.relative_path));
    root.set("sha256", JsonValue::String(metadata.sha256));
    root.set("size", JsonValue::Integer(static_cast<std::int64_t>(metadata.size)));
    root.set("trigger", JsonValue::String(metadata.trigger));
    root.set("completion_strategy",
             JsonValue::String(metadata.completion_strategy));
    root.set("collector_version", JsonValue::String(kCollectorVersion));
    root.set("procmon_profile", JsonValue::String(metadata.procmon_profile));
    root.set("signed", JsonValue::Bool(metadata.signedFile));
    root.set("category", JsonValue::String(metadata.category));
    root.set("analysis", JsonValue::String(metadata.analysis));
    root.set("timestamp", JsonValue::String(metadata.timestamp));
    root.set("result", JsonValue::String(metadata.result));

    write_text_file(path, serialize_json(root, 4) + "\n");
}

void write_manifest(const std::filesystem::path& path, std::uint32_t experiment_id,
                    const std::string& status, const std::string& sample,
                    const std::filesystem::path& pml,
                    const std::filesystem::path& csv,
                    const std::filesystem::path& filtered,
                    const std::filesystem::path& report) {
    JsonValue capture = JsonValue::Object();
    capture.set("pml", JsonValue::String(pml.filename().string()));
    capture.set("csv", JsonValue::String(csv.filename().string()));
    capture.set("filtered", JsonValue::String(filtered.filename().string()));

    JsonValue analysis = JsonValue::Object();
    analysis.set("report", JsonValue::String(report.filename().string()));

    JsonValue root = JsonValue::Object();
    root.set("experiment",
             JsonValue::Integer(static_cast<std::int64_t>(experiment_id)));
    root.set("status", JsonValue::String(status));
    root.set("sample", JsonValue::String(sample));
    root.set("capture", std::move(capture));
    root.set("analysis", std::move(analysis));

    write_text_file(path, serialize_json(root, 4) + "\n");
}

void write_trigger_info(const std::filesystem::path& path,
                        const std::string& trigger, const std::string& source_url,
                        const std::string& working_copy,
                        const std::string& completion_strategy,
                        const std::string& procmon_profile) {
    JsonValue root = JsonValue::Object();
    root.set("trigger", JsonValue::String(trigger));
    root.set("source_url", JsonValue::String(source_url));
    root.set("working_copy", JsonValue::String(working_copy));
    root.set("completion_strategy", JsonValue::String(completion_strategy));
    root.set("procmon_profile", JsonValue::String(procmon_profile));
    root.set("collector_version", JsonValue::String(kCollectorVersion));

    write_text_file(path, serialize_json(root, 4) + "\n");
}

} // namespace defenderatlas
