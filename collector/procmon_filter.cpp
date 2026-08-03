/// \file procmon_filter.cpp
/// \brief Implementation of ProcMon filter profiles and CSV filtering.

#include "procmon_filter.h"

#include "util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <stdexcept>

namespace defenderatlas {

namespace {

/// The Defender process of interest for every profile.
constexpr const char* kDefenderProcess = "msmpeng.exe";

/// Normalize a string to lowercase ASCII for case-insensitive matching.
std::string to_lower_ascii(const std::string& text) {
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lower;
}

std::string trim(const std::string& text) {
    std::size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return std::string();
    }
    std::size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

/// Escape a string for inclusion in a .pmc XML file.
std::string xml_escape(const std::string& text) {
    std::string escaped;
    escaped.reserve(text.size());
    for (const char c : text) {
        switch (c) {
            case '&': escaped += "&amp;"; break;
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '"': escaped += "&quot;"; break;
            default: escaped += c; break;
        }
    }
    return escaped;
}

/// Split one CSV record into fields, honouring double-quoted fields and
/// escaped quotes ("" inside a quoted field).
std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    bool in_quotes = false;
    std::size_t i = 0;
    while (i < line.size()) {
        const char c = line[i];
        if (c == '"') {
            if (in_quotes && i + 1 < line.size() && line[i + 1] == '"') {
                field += '"';
                i += 2;
                continue;
            }
            in_quotes = !in_quotes;
            ++i;
        } else if (c == ',' && !in_quotes) {
            fields.push_back(field);
            field.clear();
            ++i;
        } else {
            field += c;
            ++i;
        }
    }
    fields.push_back(field);
    for (std::string& value : fields) {
        value = trim(value);
    }
    return fields;
}

/// Find the column index for \p name in the CSV header; returns -1 when absent.
int find_column(const std::vector<std::string>& header, const std::string& name) {
    const std::string lower = to_lower_ascii(name);
    for (std::size_t i = 0; i < header.size(); ++i) {
        if (to_lower_ascii(header[i]) == lower) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

} // namespace

// ---------------------------------------------------------------------------
// Profile mapping
// ---------------------------------------------------------------------------

ProcmonProfile parse_procmon_profile(const std::string& name) {
    const std::string lower = to_lower_ascii(name);
    if (lower == "extended") {
        return ProcmonProfile::Extended;
    }
    if (lower == "full") {
        return ProcmonProfile::Full;
    }
    return ProcmonProfile::Minimal;
}

std::string procmon_profile_name(ProcmonProfile profile) {
    switch (profile) {
        case ProcmonProfile::Extended: return "extended";
        case ProcmonProfile::Full: return "full";
        case ProcmonProfile::Minimal:
        default: return "minimal";
    }
}

const std::vector<std::string>& procmon_profile_operations(ProcmonProfile profile) {
    static const std::vector<std::string> kMinimal = {"CreateFile", "ReadFile"};
    static const std::vector<std::string> kExtended = {
        "CreateFile", "ReadFile", "QueryInformationFile",
        "QueryStandardInformationFile", "CloseFile"};
    static const std::vector<std::string> kEmpty;
    switch (profile) {
        case ProcmonProfile::Extended: return kExtended;
        case ProcmonProfile::Full: return kEmpty;
        case ProcmonProfile::Minimal:
        default: return kMinimal;
    }
}

// ---------------------------------------------------------------------------
// ProcmonFilter
// ---------------------------------------------------------------------------

ProcmonFilter::ProcmonFilter(std::string profile_name, std::string sample_filename)
    : profile_(parse_procmon_profile(profile_name)),
      profile_name_(procmon_profile_name(profile_)),
      sample_filename_lower_(to_lower_ascii(sample_filename)) {}

std::string ProcmonFilter::profile_name() const {
    return profile_name_;
}

std::string ProcmonFilter::sample_filename() const {
    return sample_filename_lower_;
}

bool ProcmonFilter::Matches(const std::string& process_name,
                            const std::string& operation,
                            const std::string& path) const {
    if (to_lower_ascii(process_name) != kDefenderProcess) {
        return false;
    }
    if (!sample_filename_lower_.empty()) {
        const std::string path_lower = to_lower_ascii(path);
        if (path_lower.find(sample_filename_lower_) == std::string::npos) {
            return false;
        }
    }
    const std::vector<std::string>& operations =
        procmon_profile_operations(profile_);
    if (operations.empty()) {
        return true;
    }
    const std::string operation_lower = to_lower_ascii(operation);
    return std::any_of(operations.begin(), operations.end(),
                       [&](const std::string& expected) {
                           return to_lower_ascii(expected) == operation_lower;
                       });
}

void ProcmonFilter::WriteConfig(const std::filesystem::path& pmc_path) const {
    std::string xml;
    xml += "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    xml += "<ProcmonFilters>\n";
    xml += "  <Filter>\n";
    xml += "    <Column>Process Name</Column>\n";
    xml += "    <Relation>is</Relation>\n";
    xml += "    <Value>MsMpEng.exe</Value>\n";
    xml += "    <Action>Include</Action>\n";
    xml += "  </Filter>\n";
    if (!sample_filename_lower_.empty()) {
        xml += "  <Filter>\n";
        xml += "    <Column>Path</Column>\n";
        xml += "    <Relation>contains</Relation>\n";
        xml += "    <Value>" + xml_escape(sample_filename_lower_) + "</Value>\n";
        xml += "    <Action>Include</Action>\n";
        xml += "  </Filter>\n";
    }
    for (const std::string& operation : procmon_profile_operations(profile_)) {
        xml += "  <Filter>\n";
        xml += "    <Column>Operation</Column>\n";
        xml += "    <Relation>is</Relation>\n";
        xml += "    <Value>" + xml_escape(operation) + "</Value>\n";
        xml += "    <Action>Include</Action>\n";
        xml += "  </Filter>\n";
    }
    xml += "</ProcmonFilters>\n";

    write_text_file(pmc_path, xml);
}

// ---------------------------------------------------------------------------
// CSV filtering
// ---------------------------------------------------------------------------

CsvFilterStats filter_csv(const std::filesystem::path& input_path,
                          const std::filesystem::path& output_path,
                          const ProcmonFilter& filter) {
    std::ifstream input(input_path, std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("cannot open CSV for filtering: " +
                                 input_path.string());
    }
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        throw std::runtime_error("cannot open filtered CSV for writing: " +
                                 output_path.string());
    }

    CsvFilterStats stats;

    std::string line;
    bool have_header = false;
    int process_column = -1;
    int operation_column = -1;
    int path_column = -1;

    while (std::getline(input, line)) {
        if (!have_header) {
            const std::vector<std::string> header = split_csv_line(line);
            process_column = find_column(header, "Process Name");
            operation_column = find_column(header, "Operation");
            path_column = find_column(header, "Path");
            if (process_column < 0 || operation_column < 0 || path_column < 0) {
                throw std::runtime_error(
                    "unrecognized ProcMon CSV header in " + input_path.string());
            }
            output.write(line.data(), static_cast<std::streamsize>(line.size()));
            output.put('\n');
            have_header = true;
            continue;
        }

        if (trim(line).empty()) {
            continue;
        }

        const std::vector<std::string> fields = split_csv_line(line);
        if (static_cast<int>(fields.size()) <=
            std::max(process_column, std::max(operation_column, path_column))) {
            continue; // truncated / malformed row
        }
        ++stats.input_rows;

        if (!filter.Matches(fields[process_column], fields[operation_column],
                            fields[path_column])) {
            continue;
        }
        output.write(line.data(), static_cast<std::streamsize>(line.size()));
        output.put('\n');
        ++stats.output_rows;
    }

    output.flush();
    if (!output.good()) {
        throw std::runtime_error("error while writing filtered CSV: " +
                                 output_path.string());
    }
    return stats;
}

} // namespace defenderatlas
