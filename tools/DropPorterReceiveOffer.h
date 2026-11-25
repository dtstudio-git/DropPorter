#pragma once

#include <algorithm>
#include <string>
#include <string_view>

namespace dropporter::receive_offer {

inline constexpr wchar_t FileName[] = L"incoming.json";
inline constexpr char HasPreviewField[] = "hasPreview";
inline constexpr unsigned MaxFiles = 100;

inline bool ValidToken(std::string_view token) {
    return token.size() == 32 && std::all_of(token.begin(), token.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

inline std::wstring DecisionName(std::string_view token) {
    return L"decision-" + std::wstring(token.begin(), token.end()) + L".txt";
}

inline std::wstring PreviewName(std::string_view token) {
    return L"preview-" + std::wstring(token.begin(), token.end()) + L".img";
}

enum class Decision { Accept, Reject, Invalid, Expired };
inline constexpr std::string_view AcceptValue = "accept";
inline constexpr std::string_view RejectValue = "reject";

inline std::string EncodeDecision(bool accept) {
    return std::string(accept ? AcceptValue : RejectValue) + '\n';
}

inline Decision ParseDecision(std::string_view text) {
    if (text.ends_with("\r\n")) text.remove_suffix(2);
    else if (text.ends_with('\n')) text.remove_suffix(1);
    if (text == AcceptValue) return Decision::Accept;
    if (text == RejectValue) return Decision::Reject;
    return Decision::Invalid;
}

}
