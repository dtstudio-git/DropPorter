#pragma once

#include <windows.h>

#include <charconv>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dropporter {

struct JsonValue {
    enum class Kind { Null, Boolean, Number, String, Array, Object } kind = Kind::Null;
    std::string text;
    std::vector<JsonValue> array;
    std::map<std::string, JsonValue> object;
};

class JsonParser {
public:
    explicit JsonParser(std::string_view input) : input_(input) {}

    bool Parse(JsonValue& value) {
        if (input_.size() > 64 * 1024 || !IsValidUtf8(input_)) return false;
        if (!ParseValue(value, 0)) return false;
        SkipWhitespace();
        return position_ == input_.size();
    }

private:
    static bool IsValidUtf8(std::string_view value) {
        if (value.empty()) return true;
        return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0) > 0;
    }

    void SkipWhitespace() {
        while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\t' ||
            input_[position_] == '\r' || input_[position_] == '\n')) ++position_;
    }

    bool Consume(char value) {
        if (position_ >= input_.size() || input_[position_] != value) return false;
        ++position_;
        return true;
    }

    bool ParseValue(JsonValue& value, unsigned depth) {
        if (depth > 16 || ++nodes_ > 4096) return false;
        SkipWhitespace();
        if (position_ >= input_.size()) return false;
        const char ch = input_[position_];
        if (ch == '"') {
            value.kind = JsonValue::Kind::String;
            return ParseString(value.text);
        }
        if (ch == '{') return ParseObject(value, depth + 1);
        if (ch == '[') return ParseArray(value, depth + 1);
        if (ch == 't') return ParseLiteral(value, "true", JsonValue::Kind::Boolean);
        if (ch == 'f') return ParseLiteral(value, "false", JsonValue::Kind::Boolean);
        if (ch == 'n') return ParseLiteral(value, "null", JsonValue::Kind::Null);
        if (ch == '-' || (ch >= '0' && ch <= '9')) return ParseNumber(value);
        return false;
    }

    bool ParseLiteral(JsonValue& value, std::string_view literal, JsonValue::Kind kind) {
        if (input_.substr(position_, literal.size()) != literal) return false;
        position_ += literal.size();
        value.kind = kind;
        value.text.assign(literal);
        return true;
    }

    bool ParseNumber(JsonValue& value) {
        const auto start = position_;
        if (Consume('-') && position_ >= input_.size()) return false;
        if (Consume('0')) {
            if (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') return false;
        } else {
            if (position_ >= input_.size() || input_[position_] < '1' || input_[position_] > '9') return false;
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
        }
        if (Consume('.')) {
            const auto fractionStart = position_;
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
            if (fractionStart == position_) return false;
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) ++position_;
            const auto exponentStart = position_;
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
            if (exponentStart == position_) return false;
        }
        value.kind = JsonValue::Kind::Number;
        value.text.assign(input_.substr(start, position_ - start));
        return true;
    }

    bool ParseObject(JsonValue& value, unsigned depth) {
        ++position_;
        value.kind = JsonValue::Kind::Object;
        SkipWhitespace();
        if (Consume('}')) return true;
        for (;;) {
            SkipWhitespace();
            std::string key;
            if (!ParseString(key)) return false;
            SkipWhitespace();
            if (!Consume(':')) return false;
            JsonValue child;
            if (!ParseValue(child, depth)) return false;
            if (!value.object.emplace(std::move(key), std::move(child)).second) return false;
            SkipWhitespace();
            if (Consume('}')) return true;
            if (!Consume(',')) return false;
        }
    }

    bool ParseArray(JsonValue& value, unsigned depth) {
        ++position_;
        value.kind = JsonValue::Kind::Array;
        SkipWhitespace();
        if (Consume(']')) return true;
        for (;;) {
            JsonValue child;
            if (!ParseValue(child, depth)) return false;
            value.array.push_back(std::move(child));
            SkipWhitespace();
            if (Consume(']')) return true;
            if (!Consume(',')) return false;
        }
    }

    bool ParseHex4(std::uint32_t& value) {
        if (input_.size() - position_ < 4) return false;
        value = 0;
        for (int index = 0; index < 4; ++index) {
            const char ch = input_[position_++];
            value <<= 4;
            if (ch >= '0' && ch <= '9') value |= static_cast<std::uint32_t>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') value |= static_cast<std::uint32_t>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') value |= static_cast<std::uint32_t>(ch - 'A' + 10);
            else return false;
        }
        return true;
    }

    static void AppendUtf8(std::string& output, std::uint32_t codePoint) {
        if (codePoint <= 0x7f) output.push_back(static_cast<char>(codePoint));
        else if (codePoint <= 0x7ff) {
            output.push_back(static_cast<char>(0xc0 | (codePoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
        } else if (codePoint <= 0xffff) {
            output.push_back(static_cast<char>(0xe0 | (codePoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
        } else {
            output.push_back(static_cast<char>(0xf0 | (codePoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
        }
    }

    bool ParseString(std::string& output) {
        if (!Consume('"')) return false;
        output.clear();
        while (position_ < input_.size()) {
            const unsigned char ch = static_cast<unsigned char>(input_[position_++]);
            if (ch == '"') return output.size() <= 8192;
            if (ch < 0x20) return false;
            if (ch != '\\') {
                output.push_back(static_cast<char>(ch));
                if (output.size() > 8192) return false;
                continue;
            }
            if (position_ >= input_.size()) return false;
            switch (input_[position_++]) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            case 'u': {
                std::uint32_t codePoint = 0;
                if (!ParseHex4(codePoint)) return false;
                if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
                    if (input_.size() - position_ < 6 || input_[position_] != '\\' || input_[position_ + 1] != 'u') return false;
                    position_ += 2;
                    std::uint32_t low = 0;
                    if (!ParseHex4(low) || low < 0xdc00 || low > 0xdfff) return false;
                    codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00);
                } else if (codePoint >= 0xdc00 && codePoint <= 0xdfff) return false;
                AppendUtf8(output, codePoint);
                break;
            }
            default: return false;
            }
            if (output.size() > 8192) return false;
        }
        return false;
    }

    std::string_view input_;
    std::size_t position_ = 0;
    std::size_t nodes_ = 0;
};

inline const JsonValue* JsonMember(const JsonValue& value, std::string_view name) {
    if (value.kind != JsonValue::Kind::Object) return nullptr;
    const auto found = value.object.find(std::string(name));
    return found == value.object.end() ? nullptr : &found->second;
}

inline std::optional<std::string> JsonString(const JsonValue& value, std::string_view name) {
    const auto* member = JsonMember(value, name);
    if (!member || member->kind != JsonValue::Kind::String) return std::nullopt;
    return member->text;
}

inline std::optional<std::uint64_t> JsonUnsigned(const JsonValue& value, std::string_view name) {
    const auto* member = JsonMember(value, name);
    if (!member || member->kind != JsonValue::Kind::Number || member->text.empty() || member->text.front() == '-')
        return std::nullopt;
    std::uint64_t number = 0;
    const auto parsed = std::from_chars(member->text.data(), member->text.data() + member->text.size(), number);
    if (parsed.ec != std::errc{} || parsed.ptr != member->text.data() + member->text.size()) return std::nullopt;
    return number;
}

}
