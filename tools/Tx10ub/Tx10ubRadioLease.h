#pragma once

#include <sstream>
#include <string>
#include <string_view>

namespace tx10ub::radio_lease {

inline constexpr wchar_t FileName[] = L"radio.state";
inline constexpr wchar_t MutexName[] = L"Local\\AWDLWin-TX10UB-Radio-State";
inline constexpr unsigned MutexWaitMs = 500;
inline constexpr unsigned MaxAgeMs = 2000;

inline std::string Encode(unsigned long pid, unsigned long long tick) {
    std::ostringstream state;
    state << pid << ' ' << tick << '\n';
    return state.str();
}

inline bool Decode(std::string_view text, unsigned long& pid, unsigned long long& tick) {
    std::istringstream state{std::string(text)};
    return static_cast<bool>(state >> pid >> tick);
}

}
