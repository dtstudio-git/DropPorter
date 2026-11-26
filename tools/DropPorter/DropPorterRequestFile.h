#pragma once

#include <algorithm>
#include <string>
#include <string_view>

namespace dropporter::request_file {

inline constexpr wchar_t FileName[] = L"request.json";
inline constexpr char FilePath[] = "filePath";
inline constexpr char FilePaths[] = "filePaths";
inline constexpr char CandidateName[] = "candidateName";
inline constexpr char OwnerPid[] = "ownerPid";
inline constexpr char Mode[] = "mode";
inline constexpr char Transport[] = "transport";
inline constexpr char WideChannelMhz[] = "wideChannelMhz";
inline constexpr char ReceiveAckRateMbps[] = "receiveAckRateMbps";
// 1: keep the adapter in its transfer state after this transfer for the next one.
inline constexpr char KeepRadio[] = "keepRadio";
inline constexpr char UsbTransport[] = "usb";
inline constexpr char NdiscapTransport[] = "ndiscap";
inline constexpr char ReceiveMode[] = "receive";
inline constexpr char SendMode[] = "send";
inline constexpr std::wstring_view CandidatePrefix = L"tx10ub-ui-";
inline constexpr std::wstring_view DirectorySuffix = L"-request";
inline constexpr std::size_t TokenLength = 32;

inline std::wstring Candidate(std::wstring_view token) {
    return std::wstring(CandidatePrefix) + std::wstring(token);
}

inline std::wstring Directory(std::wstring_view token) {
    return Candidate(token) + std::wstring(DirectorySuffix);
}

inline bool ValidDirectory(std::wstring_view name) {
    if (name.size() != CandidatePrefix.size() + TokenLength + DirectorySuffix.size() ||
        !name.starts_with(CandidatePrefix) || !name.ends_with(DirectorySuffix)) return false;
    const auto token = name.substr(CandidatePrefix.size(), TokenLength);
    return std::all_of(token.begin(), token.end(), [](wchar_t ch) {
        return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
    });
}

inline std::string Field(std::string_view name) {
    return "\"" + std::string(name) + "\": ";
}

}
