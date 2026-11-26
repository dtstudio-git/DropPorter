#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace dropporter::discovery_timing {
inline constexpr wchar_t ClientLogFileName[] = L"discovery-timing.txt";

// Same MSVC steady clock as the probe's mDNS timestamps on this machine.
inline std::int64_t NowUs() noexcept {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

inline std::string Line(std::string_view stage,std::int64_t at = NowUs()) {
    return "send_discovery_timing stage=" + std::string(stage) + " steady_us=" + std::to_string(at);
}
}
