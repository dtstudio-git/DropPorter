#pragma once

#include "DropPorterTargetFiles.h"
#include "../Tx10ub/Tx10ubSendFiles.h"

#include <algorithm>
#include <memory>

namespace dropporter::send_selection {

inline constexpr auto MaxBytes = tx10ub::send_files::MaxRequestBytes;
inline constexpr char InvalidReason[] = "send_selection_invalid";

struct Selection {
    unsigned target;
    std::vector<std::filesystem::path> files;
};

// A target ID followed by LF-separated UTF-8 absolute paths in the same file.
inline Selection Parse(std::string_view text) {
    const auto separator = text.find('\n');
    if (text.size() > MaxBytes || separator == text.npos || separator > 3)
        throw std::invalid_argument(InvalidReason);
    const auto target = target_files::ParseNumber(text.substr(0, separator), target_files::MaxTargetId);
    text.remove_prefix(separator + 1);
    if (!target || text.empty()) throw std::invalid_argument(InvalidReason);

    const auto length = static_cast<int>(text.size());
    const auto chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0);
    if (chars <= 0 || static_cast<std::size_t>(chars) > tx10ub::send_files::MaxPathListChars)
        throw std::invalid_argument(InvalidReason);
    std::wstring paths(chars, L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, paths.data(), chars) != chars)
        throw std::invalid_argument(InvalidReason);
    auto files = tx10ub::send_files::PathsFromLines(paths);
    if (files.empty() || !std::all_of(files.begin(), files.end(), [](const auto& path) { return path.is_absolute(); }))
        throw std::invalid_argument(InvalidReason);
    return {*target, std::move(files)};
}

inline std::optional<std::string> Read(const std::filesystem::path& path) {
    const HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (raw == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return std::nullopt;
        throw std::invalid_argument(InvalidReason);
    }
    const std::unique_ptr<void, decltype(&CloseHandle)> input(raw, &CloseHandle);
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileType(input.get()) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(input.get(), &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        info.nFileSizeHigh != 0 || info.nFileSizeLow == 0 || info.nFileSizeLow > MaxBytes)
        throw std::invalid_argument(InvalidReason);
    std::string text(info.nFileSizeLow, '\0');
    DWORD bytes = 0;
    if (!ReadFile(input.get(), text.data(), info.nFileSizeLow, &bytes, nullptr) ||
        bytes != info.nFileSizeLow) throw std::invalid_argument(InvalidReason);
    return text;
}

}
