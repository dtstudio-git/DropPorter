#pragma once
#include <windows.h>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace tx10ub::send_files {
inline constexpr std::size_t MaxFiles = 100;
inline constexpr std::uint64_t MaxBytes = 0x1ffffffffULL;
inline constexpr std::size_t MaxPathChars = 32767;
inline constexpr std::size_t MaxPathListChars = MaxFiles * (MaxPathChars + 1);
inline constexpr std::size_t MaxRequestBytes = 12 * 1024 * 1024;

inline bool ValidPath(std::wstring_view path) {
    return !path.empty() && path.size() <= MaxPathChars &&
        path.find(L'\0') == path.npos && path.find_first_of(L"\r\n") == path.npos;
}

inline std::vector<std::filesystem::path> PathsFromLines(std::wstring_view input) {
    std::vector<std::filesystem::path> paths;
    while (!input.empty()) {
        const auto separator = input.find(L'\n');
        const auto path = input.substr(0, separator);
        if (!ValidPath(path)) throw std::invalid_argument("Invalid send file list");
        if (paths.size() == MaxFiles) throw std::length_error("Too many send files");
        paths.emplace_back(path);
        if (separator == input.npos) break;
        input.remove_prefix(separator + 1);
    }
    return paths;
}

inline bool SameFileName(std::wstring_view left, std::wstring_view right) {
    return CompareStringOrdinal(left.data(), static_cast<int>(left.size()), right.data(),
        static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}
}
