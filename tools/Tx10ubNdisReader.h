#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "Tx10ubNdisFrames.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>

namespace tx10ub::ndiscap {

enum class TcpActivity { idle, active, uploading };

struct TimingSummary {
    std::uint64_t samples{}, totalUs{}, maxUs{};
    void add(std::uint64_t elapsedUs) noexcept {
        ++samples;
        totalUs += elapsedUs;
        if (elapsedUs > maxUs) maxUs = elapsedUs;
    }
};

struct ReceiveTiming {
    TimingSummary dataDelivery;
    TimingSummary flush;
};

namespace detail {
enum class PollWake { queue, owner_completion, timeout, failure };

inline PollWake classify_poll_wake(DWORD waitResult, bool ownerHandleFirst) noexcept {
    if (waitResult == WAIT_FAILED) return PollWake::failure;
    if (waitResult == WAIT_TIMEOUT) return PollWake::timeout;
    if (waitResult == WAIT_OBJECT_0)
        return ownerHandleFirst ? PollWake::owner_completion : PollWake::queue;
    if (ownerHandleFirst && waitResult == WAIT_OBJECT_0 + 1) return PollWake::queue;
    return PollWake::failure;
}
}

class Reader {
public:
    using FrameCallback = std::function<void(
        std::span<const std::uint8_t> rawMpdu, std::uint64_t unixMicroseconds)>;

    Reader(std::wstring sessionName, unsigned interfaceIndex,
           awdlwin::wire::MacAddress self);
    ~Reader();

    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;
    Reader(Reader&&) = delete;
    Reader& operator=(Reader&&) = delete;

    // Attaches a real-time consumer to an existing NDIS PacketCapture session.
    // The trace session itself remains owned by its controller.
    bool begin();
    bool healthy() const noexcept;
    void set_tcp_activity(TcpActivity activity) noexcept;
    DWORD error_code() const noexcept;
    std::uint64_t flush_count() const noexcept;
    std::uint64_t out_of_order_count() const noexcept;
    // Capture-to-callback delay of incoming AWDL data and time spent in ETW
    // flushes started while transfer TCP is active.
    ReceiveTiming receive_timing() const;

    // Stops the consumer and releases only this reader's OpenTrace resources.
    // The ETW session is not stopped or otherwise modified here.
    bool close() noexcept;

    // Delivers a frozen FIFO batch on the calling thread. A separate worker
    // flushes the ETW session so it cannot hold up queued frames or owner completions.
    bool poll(DWORD maxWaitMs, HANDLE ownerCompletion,
              const FrameCallback& callback);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tx10ub::ndiscap
