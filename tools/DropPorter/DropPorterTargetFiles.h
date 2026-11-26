#pragma once

#include <charconv>
#include <optional>
#include <string>
#include <string_view>

namespace dropporter::target_files {

inline constexpr wchar_t ListName[] = L"targets.txt";
inline constexpr wchar_t CommittedSelectionName[] = L"target-selection.request";
inline constexpr char SelectionExpired[] = "target_selection_expired";
inline constexpr std::string_view Round = "round=";
inline constexpr std::string_view Refresh = "refresh=";
inline constexpr char RefreshContent[] = "1";
inline constexpr char RowSeparator = '\t';
inline constexpr char Named = '1', Unnamed = '0';
inline constexpr unsigned MaxRound = 1000, MaxTargetId = 256, MaxRows = 32;

inline std::wstring RefreshName(unsigned generation) {
    return L"refresh-" + std::to_wstring(generation) + L".request";
}

inline std::wstring SelectionName(unsigned round) {
    return L"target-" + std::to_wstring(round) + L".request";
}

inline std::optional<unsigned> ParseNumber(std::string_view text, unsigned max) {
    if (text.empty()) return std::nullopt;
    unsigned value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        value == 0 || value > max) return std::nullopt;
    return value;
}

}
