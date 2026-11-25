#include "Tx10ubNdisReader.h"

#include <evntrace.h>
#include <evntcons.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

namespace tx10ub::ndiscap {
namespace {
constexpr GUID packetProvider{0x2ed6006e, 0x4729, 0x4609,
    {0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef}};
constexpr std::uint16_t packetFragmentEventId = 1001;
constexpr std::uint8_t packetFragmentVersion = 0;
constexpr std::uint64_t fileTimeUnixEpoch = 116444736000000000ULL;
constexpr DWORD idleFlushMs = 50;
constexpr DWORD receiveTcpFlushMs = 5;
constexpr DWORD uploadFlushMs = 5;
constexpr std::size_t maxMpduBytes = 16 * 1024;
constexpr std::size_t maxQueueFrames = 512;
constexpr std::size_t maxQueueBytes = 4 * 1024 * 1024;

struct TraceProperties {
    EVENT_TRACE_PROPERTIES properties{};
    wchar_t loggerName[1025]{};
    wchar_t logFileName[1025]{};

    TraceProperties() noexcept {
        properties.Wnode.BufferSize = sizeof(*this);
        properties.LoggerNameOffset = offsetof(TraceProperties, loggerName);
        properties.LogFileNameOffset = offsetof(TraceProperties, logFileName);
    }
};

std::uint64_t nowFileTime() noexcept {
    FILETIME value{};
    GetSystemTimePreciseAsFileTime(&value);
    return (std::uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}
}

class Reader::Impl {
public:
    Impl(std::wstring sessionName, unsigned interfaceIndex,
         awdlwin::wire::MacAddress self)
        : sessionName_(std::move(sessionName)), interfaceIndex_(interfaceIndex), self_(self) {}

    ~Impl() { (void)close(); }

    bool begin() {
        if (startedOnce_ || closing_.load() || closed_.load() || sessionName_.empty()) {
            fail(ERROR_INVALID_STATE);
            return false;
        }
        startedOnce_ = true;

        queueEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!queueEvent_) {
            fail(GetLastError());
            return false;
        }

        startFileTime_ = nowFileTime();
        EVENT_TRACE_LOGFILEW logFile{};
        logFile.LoggerName = sessionName_.data();
        logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = &Impl::eventRecord;
        logFile.BufferCallback = &Impl::buffer;
        logFile.Context = this;

        trace_ = OpenTraceW(&logFile);
        if (trace_ == INVALID_PROCESSTRACE_HANDLE) {
            const auto status = GetLastError();
            trace_ = INVALID_PROCESSTRACE_HANDLE;
            fail(status == ERROR_SUCCESS ? ERROR_GEN_FAILURE : status);
            close_event();
            return false;
        }

        nextFlush_ = Clock::now() + std::chrono::milliseconds(flushIntervalMs_.load());
        const auto trace = trace_;
        workerJoined_ = false;
        try {
            worker_ = std::thread([this, trace] { process(trace); });
            flushWorker_ = std::jthread([this](std::stop_token stop) { run_flushes(stop); });
        } catch (...) {
            workerJoined_ = !worker_.joinable();
            fail(ERROR_NOT_ENOUGH_MEMORY);
            close();
            return false;
        }
        started_ = true;
        return true;
    }

    bool healthy() const noexcept {
        return started_.load() && !closing_.load() && errorCode_.load() == ERROR_SUCCESS &&
            !workerDone_.load();
    }

    DWORD error_code() const noexcept { return errorCode_.load(); }
    std::uint64_t flush_count() const noexcept { return flushCount_.load(); }
    std::uint64_t out_of_order_count() const noexcept { return outOfOrderCount_.load(); }
    ReceiveTiming receive_timing() const {
        std::scoped_lock lock(queueMutex_, flushMutex_);
        return {tcpDataDelivery_, tcpFlushTime_};
    }

    void set_tcp_activity(TcpActivity activity) noexcept {
        const DWORD interval = activity == TcpActivity::uploading ? uploadFlushMs :
            activity == TcpActivity::active ? receiveTcpFlushMs : idleFlushMs;
        if (flushIntervalMs_ == interval) return;
        {
            std::lock_guard lock(flushMutex_);
            flushIntervalMs_ = interval;
            nextFlush_ = std::min(nextFlush_, Clock::now() + std::chrono::milliseconds(interval));
        }
        flushChanged_.notify_one();
    }

    bool close() noexcept {
        std::unique_lock closeLock(closeMutex_, std::try_to_lock);
        if (!closeLock.owns_lock()) return false;
        if (closed_.load()) return closeSucceeded_.load();
        {
            std::lock_guard pollLock(pollLifecycleMutex_);
            closing_ = true;
            if (queueEvent_ && !SetEvent(queueEvent_)) fail(GetLastError());
        }

        bool succeeded = true;
        if (flushWorker_.joinable()) {
            flushWorker_.request_stop();
            flushWorker_.join();
        }
        if (trace_ != INVALID_PROCESSTRACE_HANDLE) {
            const auto status = CloseTrace(trace_);
            trace_ = INVALID_PROCESSTRACE_HANDLE;
            if (status != ERROR_SUCCESS && status != ERROR_CTX_CLOSE_PENDING) {
                fail(status);
                succeeded = false;
            }
        }

        if (worker_.joinable()) {
            try {
                worker_.join();
                workerJoined_ = true;
            } catch (...) {
                fail(ERROR_GEN_FAILURE);
                succeeded = false;
            }
        }

        {
            std::unique_lock pollLock(pollLifecycleMutex_);
            if (workerJoined_.load() && pollThread_ != std::this_thread::get_id())
                pollLifecycleChanged_.wait(pollLock, [this] { return activePolls_ == 0; });
            if (workerJoined_.load() && activePolls_ == 0 && !close_event()) succeeded = false;
        }
        if (!succeeded && errorCode_.load() == ERROR_SUCCESS) fail(ERROR_GEN_FAILURE);
        closeSucceeded_ = succeeded;
        closed_ = true;
        return succeeded;
    }

    bool poll(DWORD maxWaitMs, HANDLE ownerCompletion, const Reader::FrameCallback& callback) {
        if (!callback) {
            fail(ERROR_INVALID_PARAMETER);
            return false;
        }
        if (!healthy()) return false;
        if (!claimPollThread()) return false;
        {
            std::lock_guard pollLock(pollLifecycleMutex_);
            if (closing_.load() || !healthy() || !queueEvent_) return false;
            ++activePolls_;
        }
        struct PollScope {
            Impl* owner;
            ~PollScope() { owner->release_poll(); }
        } pollScope{this};

        const auto startedAt = GetTickCount64();
        const bool infinite = maxWaitMs == INFINITE;
        const auto deadline = infinite ? UINT64_MAX : startedAt + maxWaitMs;

        for (;;) {
            if (!healthy()) return false;
            if (ownerCompletion) {
                const auto ownerState = detail::classify_poll_wake(
                    WaitForSingleObject(ownerCompletion, 0), true);
                if (ownerState == detail::PollWake::owner_completion) return healthy();
                if (ownerState == detail::PollWake::failure) {
                    fail(GetLastError());
                    return false;
                }
            }

            std::deque<Frame> batch;
            {
                std::lock_guard queueLock(queueMutex_);
                if (!queue_.empty()) batch.swap(queue_);
                queueBytes_ = 0;
                if (queue_.empty() && !ResetEvent(queueEvent_)) {
                    fail(GetLastError());
                    return false;
                }
            }

            if (!batch.empty()) {
                for (const auto& frame : batch) {
                    try {
                        callback(frame.bytes, frame.unixMicroseconds);
                    } catch (...) {
                        fail(ERROR_UNHANDLED_EXCEPTION);
                        return false;
                    }
                }
                return healthy();
            }

            if (!healthy()) return false;
            const auto now = GetTickCount64();
            if (!infinite && now >= deadline) return healthy();
            const auto waitMs = infinite ? INFINITE : static_cast<DWORD>(deadline - now);

            std::array<HANDLE, 2> waits{};
            DWORD waitCount = 0;
            bool ownerIsFirst = false;
            if (ownerCompletion) {
                waits[waitCount++] = ownerCompletion;
                ownerIsFirst = true;
            }
            waits[waitCount++] = queueEvent_;
            const auto result = WaitForMultipleObjects(waitCount, waits.data(), FALSE, waitMs);
            const auto wake = detail::classify_poll_wake(result, ownerIsFirst);
            if (wake == detail::PollWake::failure) {
                fail(GetLastError());
                return false;
            }
            if (wake == detail::PollWake::owner_completion || wake == detail::PollWake::timeout)
                return healthy();
        }
    }

private:
    using Clock = std::chrono::steady_clock;
    struct Frame {
        std::vector<std::uint8_t> bytes;
        std::uint64_t unixMicroseconds{};
    };

    static VOID WINAPI eventRecord(EVENT_RECORD* record) noexcept {
        if (!record || !record->UserContext) return;
        static_cast<Impl*>(record->UserContext)->consume(*record);
    }

    static ULONG WINAPI buffer(EVENT_TRACE_LOGFILEW* logFile) noexcept {
        if (!logFile || !logFile->Context) return TRUE;
        auto& self = *static_cast<Impl*>(logFile->Context);
        if (logFile->EventsLost != 0) self.fail(ERROR_BUFFER_OVERFLOW);
        return TRUE;
    }

    void consume(const EVENT_RECORD& record) noexcept {
        if (errorCode_.load() != ERROR_SUCCESS || closing_.load()) return;
        if (!IsEqualGUID(record.EventHeader.ProviderId, packetProvider) ||
            record.EventHeader.EventDescriptor.Id != packetFragmentEventId) return;
        if (record.EventHeader.EventDescriptor.Version != packetFragmentVersion) {
            fail(ERROR_REVISION_MISMATCH);
            return;
        }
        if (!record.UserData || record.UserDataLength < 12) return;

        const auto event = std::span<const std::uint8_t>(
            static_cast<const std::uint8_t*>(record.UserData), record.UserDataLength);
        const auto mpdu = select_incoming_awdl_mpdu(interfaceIndex_, self_,
            record.EventHeader.EventDescriptor.Keyword, event);
        if (mpdu.empty()) return;
        if (mpdu.size() > maxMpduBytes) {
            fail(ERROR_BUFFER_OVERFLOW);
            return;
        }

        const auto timestamp = record.EventHeader.TimeStamp.QuadPart;
        if (timestamp < 0) {
            fail(ERROR_INVALID_TIME);
            return;
        }
        const auto fileTime = static_cast<std::uint64_t>(timestamp);
        if (fileTime < startFileTime_) return;
        if (fileTime < fileTimeUnixEpoch) {
            fail(ERROR_INVALID_TIME);
            return;
        }
        const auto unixMicroseconds = (fileTime - fileTimeUnixEpoch) / 10;
        const auto callbackTime = (flushIntervalMs_ != idleFlushMs && mpdu[0] != 0xd0)
            ? nowFileTime() : 0;

        try {
            Frame frame;
            frame.bytes.assign(mpdu.begin(), mpdu.end());
            frame.unixMicroseconds = unixMicroseconds;

            std::lock_guard queueLock(queueMutex_);
            if (errorCode_.load() != ERROR_SUCCESS || closing_.load()) return;
            if (lastTimestamp_ && unixMicroseconds < *lastTimestamp_) {
                ++outOfOrderCount_;
                return;
            }
            if (queue_.size() >= maxQueueFrames || mpdu.size() > maxQueueBytes - queueBytes_) {
                fail(ERROR_BUFFER_OVERFLOW);
                return;
            }
            queueBytes_ += mpdu.size();
            queue_.push_back(std::move(frame));
            if (callbackTime >= fileTime) tcpDataDelivery_.add((callbackTime - fileTime) / 10);
            lastTimestamp_ = unixMicroseconds;
            if (!SetEvent(queueEvent_)) fail(GetLastError());
        } catch (...) {
            fail(ERROR_NOT_ENOUGH_MEMORY);
        }
    }

    void process(TRACEHANDLE trace) noexcept {
        auto handle = trace;
        const auto status = ProcessTrace(&handle, 1, nullptr, nullptr);
        workerDone_ = true;
        if (!closing_.load()) fail(status == ERROR_SUCCESS ? ERROR_OPERATION_ABORTED : status);
        else if (status != ERROR_SUCCESS && status != ERROR_CANCELLED &&
                 status != ERROR_WMI_INSTANCE_NOT_FOUND) fail(status);
        if (queueEvent_) SetEvent(queueEvent_);
    }

    void run_flushes(std::stop_token stop) {
        std::unique_lock lock(flushMutex_);
        while (!stop.stop_requested() && !workerDone_ && errorCode_ == ERROR_SUCCESS) {
            const auto due = nextFlush_;
            flushChanged_.wait_until(lock, stop, due, [this, due] { return nextFlush_ != due; });
            if (stop.stop_requested() || closing_ || workerDone_ || errorCode_ != ERROR_SUCCESS) return;
            if (Clock::now() < nextFlush_) continue;
            const auto intervalMs = flushIntervalMs_.load();
            nextFlush_ += std::chrono::milliseconds(intervalMs);
            lock.unlock();
            const auto start = Clock::now();
            if (!flush_session()) return;
            const auto end = Clock::now();
            lock.lock();
            if (intervalMs != idleFlushMs)
                tcpFlushTime_.add(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
            // Skip expired periods when a flush itself took longer than the interval.
            const auto now = Clock::now();
            const auto interval = std::chrono::milliseconds(flushIntervalMs_.load());
            if (nextFlush_ <= now) nextFlush_ += ((now - nextFlush_) / interval + 1) * interval;
        }
    }

    bool flush_session() noexcept {
        TraceProperties traceProperties;
        const auto status = ControlTraceW(0, sessionName_.c_str(),
            &traceProperties.properties, EVENT_TRACE_CONTROL_FLUSH);
        if (status != ERROR_SUCCESS) {
            fail(status);
            return false;
        }
        flushCount_++;
        if (traceProperties.properties.EventsLost != 0 ||
            traceProperties.properties.LogBuffersLost != 0 ||
            traceProperties.properties.RealTimeBuffersLost != 0) {
            fail(ERROR_BUFFER_OVERFLOW);
            return false;
        }
        return true;
    }

    bool claimPollThread() noexcept {
        std::lock_guard ownerLock(pollLifecycleMutex_);
        const auto current = std::this_thread::get_id();
        if (pollThread_ == std::thread::id{}) {
            pollThread_ = current;
            return true;
        }
        if (pollThread_ == current) return true;
        fail(ERROR_INVALID_THREAD_ID);
        return false;
    }

    void release_poll() noexcept {
        std::lock_guard pollLock(pollLifecycleMutex_);
        if (activePolls_ != 0) --activePolls_;
        if (activePolls_ == 0) {
            if (closing_.load() && workerJoined_.load()) (void)close_event();
            pollLifecycleChanged_.notify_all();
        }
    }

    void fail(DWORD status) noexcept {
        if (status == ERROR_SUCCESS) status = ERROR_GEN_FAILURE;
        DWORD expected = ERROR_SUCCESS;
        (void)errorCode_.compare_exchange_strong(expected, status);
        if (queueEvent_) SetEvent(queueEvent_);
    }

    bool close_event() noexcept {
        bool succeeded = true;
        if (queueEvent_) {
            if (!CloseHandle(queueEvent_)) {
                fail(GetLastError());
                succeeded = false;
            }
            queueEvent_ = nullptr;
        }
        return succeeded;
    }

    std::wstring sessionName_;
    unsigned interfaceIndex_{};
    awdlwin::wire::MacAddress self_{};
    TRACEHANDLE trace_{INVALID_PROCESSTRACE_HANDLE};
    HANDLE queueEvent_{};
    std::thread worker_;
    std::atomic<bool> started_{};
    std::atomic<bool> startedOnce_{};
    std::atomic<bool> closing_{};
    std::atomic<bool> workerDone_{};
    std::atomic<bool> closed_{};
    std::atomic<bool> closeSucceeded_{true};
    std::atomic<DWORD> errorCode_{ERROR_SUCCESS};
    std::atomic<std::uint64_t> flushCount_{};
    std::atomic<std::uint64_t> outOfOrderCount_{};
    std::uint64_t startFileTime_{};
    std::jthread flushWorker_;
    mutable std::mutex flushMutex_;
    TimingSummary tcpFlushTime_;
    std::condition_variable_any flushChanged_;
    Clock::time_point nextFlush_{};
    std::atomic<DWORD> flushIntervalMs_{idleFlushMs};
    mutable std::mutex queueMutex_;
    TimingSummary tcpDataDelivery_;
    std::deque<Frame> queue_;
    std::size_t queueBytes_{};
    std::optional<std::uint64_t> lastTimestamp_;
    std::thread::id pollThread_{};
    std::atomic<bool> workerJoined_{true};
    std::mutex pollLifecycleMutex_;
    std::condition_variable pollLifecycleChanged_;
    std::size_t activePolls_{};
    std::mutex closeMutex_;
};

Reader::Reader(std::wstring sessionName, unsigned interfaceIndex,
               awdlwin::wire::MacAddress self)
    : impl_(std::make_unique<Impl>(std::move(sessionName), interfaceIndex, self)) {}

Reader::~Reader() = default;

bool Reader::begin() { return impl_->begin(); }
bool Reader::healthy() const noexcept { return impl_->healthy(); }
void Reader::set_tcp_activity(TcpActivity activity) noexcept { impl_->set_tcp_activity(activity); }
DWORD Reader::error_code() const noexcept { return impl_->error_code(); }
std::uint64_t Reader::flush_count() const noexcept { return impl_->flush_count(); }
std::uint64_t Reader::out_of_order_count() const noexcept { return impl_->out_of_order_count(); }
ReceiveTiming Reader::receive_timing() const { return impl_->receive_timing(); }
bool Reader::close() noexcept { return impl_->close(); }
bool Reader::poll(DWORD maxWaitMs, HANDLE ownerCompletion,
                  const FrameCallback& callback) {
    return impl_->poll(maxWaitMs, ownerCompletion, callback);
}

} // namespace tx10ub::ndiscap
