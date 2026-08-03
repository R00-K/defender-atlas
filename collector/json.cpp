/// \file json.cpp
/// \brief Implementation of the minimal JSON module declared in json.h.

#include "json.h"

#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

namespace defenderatlas {

namespace {

bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

std::string escape_string(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 2);
    out.push_back('"');
    for (unsigned char c : value) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20) {
                    char buffer[8] = {};
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                    out += buffer;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
    return out;
}

// -- Recursive-descent parser -------------------------------------------------

class Parser {
public:
    explicit Parser(const std::string& text) : text_(text) {}

    JsonValue parse() {
        skip_whitespace();
        JsonValue value = parse_value();
        skip_whitespace();
        if (position_ != text_.size()) {
            fail("unexpected trailing content");
        }
        return value;
    }

private:
    [[noreturn]] void fail(const std::string& message) const {
        throw JsonError("JSON parse error at offset " + std::to_string(position_) +
                        ": " + message);
    }

    char peek() const {
        if (position_ >= text_.size()) {
            fail("unexpected end of input");
        }
        return text_[position_];
    }

    char take() {
        if (position_ >= text_.size()) {
            fail("unexpected end of input");
        }
        return text_[position_++];
    }

    bool consume(char expected) {
        if (position_ < text_.size() && text_[position_] == expected) {
            ++position_;
            return true;
        }
        return false;
    }

    void skip_whitespace() {
        while (position_ < text_.size() && is_space(text_[position_])) {
            ++position_;
        }
    }

    void expect(const char* token) {
        for (const char* p = token; *p != '\0'; ++p) {
            if (position_ >= text_.size() || text_[position_] != *p) {
                fail(std::string("expected '") + token + "'");
            }
            ++position_;
        }
    }

    JsonValue parse_value() {
        switch (peek()) {
            case '{':
                return parse_object();
            case '[':
                return parse_array();
            case '"':
                return JsonValue(parse_string());
            case 't':
                expect("true");
                return JsonValue(true);
            case 'f':
                expect("false");
                return JsonValue(false);
            case 'n':
                expect("null");
                return JsonValue();
            default:
                return parse_number();
        }
    }

    JsonValue parse_object() {
        expect("{");
        JsonValue::Members members;
        skip_whitespace();
        if (consume('}')) {
            return JsonValue(std::move(members));
        }
        while (true) {
            skip_whitespace();
            if (peek() != '"') {
                fail("expected object key string");
            }
            std::string key = parse_string();
            skip_whitespace();
            if (!consume(':')) {
                fail("expected ':' after object key");
            }
            skip_whitespace();
            members.emplace_back(std::move(key), parse_value());
            skip_whitespace();
            if (consume('}')) {
                break;
            }
            if (!consume(',')) {
                fail("expected ',' or '}' in object");
            }
        }
        return JsonValue(std::move(members));
    }

    JsonValue parse_array() {
        expect("[");
        std::vector<JsonValue> items;
        skip_whitespace();
        if (consume(']')) {
            return JsonValue(std::move(items));
        }
        while (true) {
            skip_whitespace();
            items.push_back(parse_value());
            skip_whitespace();
            if (consume(']')) {
                break;
            }
            if (!consume(',')) {
                fail("expected ',' or ']' in array");
            }
        }
        return JsonValue(std::move(items));
    }

    std::string parse_string() {
        expect("\"");
        std::string out;
        while (true) {
            const char c = take();
            if (c == '"') {
                break;
            }
            if (c == '\\') {
                const char escape = take();
                switch (escape) {
                    case '"':
                        out.push_back('"');
                        break;
                    case '\\':
                        out.push_back('\\');
                        break;
                    case '/':
                        out.push_back('/');
                        break;
                    case 'b':
                        out.push_back('\b');
                        break;
                    case 'f':
                        out.push_back('\f');
                        break;
                    case 'n':
                        out.push_back('\n');
                        break;
                    case 'r':
                        out.push_back('\r');
                        break;
                    case 't':
                        out.push_back('\t');
                        break;
                    case 'u': {
                        unsigned int code = 0;
                        for (int i = 0; i < 4; ++i) {
                            const char hex = take();
                            code <<= 4;
                            if (hex >= '0' && hex <= '9') {
                                code |= static_cast<unsigned int>(hex - '0');
                            } else if (hex >= 'a' && hex <= 'f') {
                                code |= static_cast<unsigned int>(hex - 'a' + 10);
                            } else if (hex >= 'A' && hex <= 'F') {
                                code |= static_cast<unsigned int>(hex - 'A' + 10);
                            } else {
                                fail("invalid \\u escape");
                            }
                        }
                        if (code <= 0x7F) {
                            out.push_back(static_cast<char>(code));
                        } else if (code <= 0x7FF) {
                            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        } else {
                            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                            out.push_back(
                                static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        }
                        break;
                    }
                    default:
                        fail("invalid escape sequence");
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    JsonValue parse_number() {
        const size_t start = position_;
        consume('-');
        while (position_ < text_.size() &&
               (std::isdigit(static_cast<unsigned char>(text_[position_])) ||
                text_[position_] == '.' || text_[position_] == 'e' ||
                text_[position_] == 'E' || text_[position_] == '+' ||
                text_[position_] == '-')) {
            ++position_;
        }
        const std::string token = text_.substr(start, position_ - start);
        if (token.empty()) {
            fail("invalid number");
        }
        const bool is_integer = token.find_first_of(".eE") == std::string::npos;
        if (is_integer) {
            std::int64_t value = 0;
            const auto result = std::from_chars(token.data(),
                                                token.data() + token.size(), value);
            if (result.ec == std::errc::result_out_of_range) {
                return JsonValue(std::strtod(token.c_str(), nullptr));
            }
            return JsonValue(value);
        }
        return JsonValue(std::strtod(token.c_str(), nullptr));
    }

    const std::string& text_;
    size_t position_ = 0;
};

// -- Serializer -----------------------------------------------------------------

std::string serialize_value(const JsonValue& value, int indent, int level) {
    std::string out;
    switch (value.type()) {
        case JsonValue::Type::Null:
            return "null";
        case JsonValue::Type::Bool:
            return value.as_bool() ? "true" : "false";
        case JsonValue::Type::Integer:
            return std::to_string(value.as_integer());
        case JsonValue::Type::Real: {
            char buffer[64] = {};
            std::snprintf(buffer, sizeof(buffer), "%.17g", value.as_real());
            std::string text(buffer);
            if (text.find_first_of(".eE") == std::string::npos) {
                text += ".0";
            }
            return text;
        }
        case JsonValue::Type::String:
            return escape_string(value.as_string());
        case JsonValue::Type::Array: {
            const auto& items = value.array();
            if (items.empty()) {
                return "[]";
            }
            out = "[\n";
            const std::string pad(static_cast<size_t>(indent) * (level + 1), ' ');
            for (size_t i = 0; i < items.size(); ++i) {
                out += pad + serialize_value(items[i], indent, level + 1);
                out += (i + 1 < items.size()) ? ",\n" : "\n";
            }
            out += std::string(static_cast<size_t>(indent) * level, ' ') + "]";
            return out;
        }
        case JsonValue::Type::Object: {
            const auto& members = value.members();
            if (members.empty()) {
                return "{}";
            }
            out = "{\n";
            const std::string pad(static_cast<size_t>(indent) * (level + 1), ' ');
            for (size_t i = 0; i < members.size(); ++i) {
                out += pad + escape_string(members[i].first) + ": " +
                       serialize_value(members[i].second, indent, level + 1);
                out += (i + 1 < members.size()) ? ",\n" : "\n";
            }
            out += std::string(static_cast<size_t>(indent) * level, ' ') + "}";
            return out;
        }
    }
    return "null";
}

} // namespace

// -----------------------------------------------------------------------------
// JsonValue
// -----------------------------------------------------------------------------

JsonValue::JsonValue() : data_(nullptr) {}
JsonValue::JsonValue(bool value) : data_(value) {}
JsonValue::JsonValue(std::int64_t value) : data_(value) {}
JsonValue::JsonValue(double value) : data_(value) {}
JsonValue::JsonValue(const char* value) : data_(std::string(value)) {}
JsonValue::JsonValue(std::string value) : data_(std::move(value)) {}
JsonValue::JsonValue(std::vector<JsonValue> value) : data_(std::move(value)) {}
JsonValue::JsonValue(Members value) : data_(std::move(value)) {}

JsonValue JsonValue::Null() { return JsonValue(); }
JsonValue JsonValue::Bool(bool value) { return JsonValue(value); }
JsonValue JsonValue::Integer(std::int64_t value) { return JsonValue(value); }
JsonValue JsonValue::Real(double value) { return JsonValue(value); }
JsonValue JsonValue::String(std::string value) { return JsonValue(std::move(value)); }
JsonValue JsonValue::Array() { return JsonValue(std::vector<JsonValue>()); }
JsonValue JsonValue::Object() { return JsonValue(Members()); }

JsonValue::Type JsonValue::type() const {
    switch (data_.index()) {
        case 0:
            return Type::Null;
        case 1:
            return Type::Bool;
        case 2:
            return Type::Integer;
        case 3:
            return Type::Real;
        case 4:
            return Type::String;
        case 5:
            return Type::Array;
        case 6:
            return Type::Object;
        default:
            return Type::Null;
    }
}

bool JsonValue::as_bool(bool fallback) const {
    if (const bool* v = std::get_if<bool>(&data_)) {
        return *v;
    }
    return fallback;
}

std::int64_t JsonValue::as_integer(std::int64_t fallback) const {
    if (const std::int64_t* v = std::get_if<std::int64_t>(&data_)) {
        return *v;
    }
    if (const double* v = std::get_if<double>(&data_)) {
        return static_cast<std::int64_t>(*v);
    }
    return fallback;
}

double JsonValue::as_real(double fallback) const {
    if (const double* v = std::get_if<double>(&data_)) {
        return *v;
    }
    if (const std::int64_t* v = std::get_if<std::int64_t>(&data_)) {
        return static_cast<double>(*v);
    }
    return fallback;
}

std::string JsonValue::as_string(const std::string& fallback) const {
    if (const std::string* v = std::get_if<std::string>(&data_)) {
        return *v;
    }
    return fallback;
}

const std::vector<JsonValue>& JsonValue::array() const {
    if (const auto* v = std::get_if<std::vector<JsonValue>>(&data_)) {
        return *v;
    }
    throw JsonError("JSON value is not an array");
}

std::vector<JsonValue>& JsonValue::array() {
    if (auto* v = std::get_if<std::vector<JsonValue>>(&data_)) {
        return *v;
    }
    throw JsonError("JSON value is not an array");
}

const JsonValue::Members& JsonValue::members() const {
    if (const auto* v = std::get_if<Members>(&data_)) {
        return *v;
    }
    throw JsonError("JSON value is not an object");
}

JsonValue::Members& JsonValue::members() {
    if (auto* v = std::get_if<Members>(&data_)) {
        return *v;
    }
    throw JsonError("JSON value is not an object");
}

bool JsonValue::has(const std::string& key) const {
    if (type() != Type::Object) {
        return false;
    }
    for (const auto& member : members()) {
        if (member.first == key) {
            return true;
        }
    }
    return false;
}

const JsonValue& JsonValue::at(const std::string& key) const {
    for (const auto& member : members()) {
        if (member.first == key) {
            return member.second;
        }
    }
    throw JsonError("JSON object has no member '" + key + "'");
}

JsonValue& JsonValue::operator[](const std::string& key) {
    Members& object = members();
    for (auto& member : object) {
        if (member.first == key) {
            return member.second;
        }
    }
    object.emplace_back(key, JsonValue());
    return object.back().second;
}

void JsonValue::set(const std::string& key, JsonValue value) {
    Members& object = members();
    for (auto& member : object) {
        if (member.first == key) {
            member.second = std::move(value);
            return;
        }
    }
    object.emplace_back(key, std::move(value));
}

void JsonValue::push(JsonValue value) {
    array().push_back(std::move(value));
}

// -----------------------------------------------------------------------------
// Parse / serialize free functions
// -----------------------------------------------------------------------------

JsonValue parse_json(const std::string& text) {
    Parser parser(text);
    return parser.parse();
}

std::string serialize_json(const JsonValue& value, int indent) {
    if (indent < 0) {
        indent = 0;
    }
    return serialize_value(value, indent, 0);
}

} // namespace defenderatlas
