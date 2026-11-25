#pragma once

#include <cstdint>
#include <cstddef>

namespace tx10ub::receive_worker_protocol {
inline constexpr std::size_t MaxFrameBytes = 65536;
inline constexpr std::size_t MaxConnections = 4;
inline constexpr std::uint8_t OrderlyTlsClose = 1;
// Worker-to-probe close notification after files were published successfully.
inline constexpr std::uint8_t UploadCommitted = 2;
inline constexpr std::uint8_t FinalizingProgress = 5;
}
