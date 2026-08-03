#pragma once

/// \file json.h
/// \brief Minimal, dependency-free JSON value model, parser and serializer.
///
/// The DefenderAtlas Collector uses JSON for its configuration file and for
/// experiment metadata. This module intentionally implements the small JSON
/// subset the Collector needs (objects, arrays, strings, numbers, booleans,
/// null) instead of pulling in a third-party library, keeping the build
/// self-contained and auditable.
///
/// Objects preserve insertion order, which keeps generated metadata.json files
/// stable and readable across runs.

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace defenderatlas {

/// Thrown for any JSON parse or access error.
class JsonError : public std::runtime_error {
public:
    explicit JsonError(const std::string& message) : std::runtime_error(message) {}
};

/// A single JSON value.
///
/// The type is selected by the factory constructors; use type() to inspect it
/// and the accessor methods to read typed values. Unknown keys / wrong types
/// fall back to provided defaults instead of throwing, which keeps config
/// loading tolerant of missing fields.
class JsonValue {
public:
    enum class Type {
        Null,
        Bool,
        Integer,
        Real,
        String,
        Array,
        Object,
    };

    using Member = std::pair<std::string, JsonValue>;
    using Members = std::vector<Member>;

    /// Construct a JSON null value.
    JsonValue();

    /// Construct a boolean value.
    explicit JsonValue(bool value);

    /// Construct an integer value.
    explicit JsonValue(std::int64_t value);

    /// Construct a real (floating point) value.
    explicit JsonValue(double value);

    /// Construct a string value.
    explicit JsonValue(const char* value);

    /// Construct a string value.
    explicit JsonValue(std::string value);

    /// Construct an array value.
    explicit JsonValue(std::vector<JsonValue> value);

    /// Construct an object value, preserving member insertion order.
    explicit JsonValue(Members value);

    // -- Factory helpers (readable at call sites) ---------------------------

    static JsonValue Null();
    static JsonValue Bool(bool value);
    static JsonValue Integer(std::int64_t value);
    static JsonValue Real(double value);
    static JsonValue String(std::string value);
    static JsonValue Array();
    static JsonValue Object();

    // -- Type inspection ----------------------------------------------------

    Type type() const;

    bool is_null() const { return type() == Type::Null; }

    // -- Typed accessors (return \p fallback on type mismatch) --------------

    bool as_bool(bool fallback = false) const;
    std::int64_t as_integer(std::int64_t fallback = 0) const;
    double as_real(double fallback = 0.0) const;
    std::string as_string(const std::string& fallback = std::string()) const;

    /// Return the array payload; throws JsonError if the value is not an array.
    const std::vector<JsonValue>& array() const;
    std::vector<JsonValue>& array();

    /// Return the ordered members; throws JsonError if not an object.
    const Members& members() const;
    Members& members();

    /// True when \p key exists in this object.
    bool has(const std::string& key) const;

    /// Return the member for \p key; throws JsonError when missing.
    const JsonValue& at(const std::string& key) const;

    /// Get-or-create the member for \p key (object only).
    JsonValue& operator[](const std::string& key);

    /// Insert or replace \p key; replacement keeps the original position so
    /// metadata files stay stable.
    void set(const std::string& key, JsonValue value);

    /// Append \p value to an array.
    void push(JsonValue value);

private:
    using Variant = std::variant<std::nullptr_t, bool, std::int64_t, double,
                                 std::string, std::vector<JsonValue>, Members>;

    Variant data_;
};

/// Parse \p text as a JSON document. Throws JsonError on malformed input.
JsonValue parse_json(const std::string& text);

/// Serialize \p value as pretty-printed JSON with \p indent spaces per level.
std::string serialize_json(const JsonValue& value, int indent = 4);

} // namespace defenderatlas
