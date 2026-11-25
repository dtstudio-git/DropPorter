#pragma once

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <atomic>
#include <cstring>
#include <thread>

// Consumer of the trial's existing logger. The controller owns the session.
class Tx10ubScanIdle {
public:
    bool open(wchar_t* logger) {
        EVENT_TRACE_LOGFILEW input{};
        input.LoggerName = logger;
        input.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        input.Context = this;
        input.EventRecordCallback = record;
        input.BufferCallback = buffer;
        trace_ = OpenTraceW(&input);
        if (trace_ == INVALID_PROCESSTRACE_HANDLE) return false;
        worker_ = std::thread([this] {
            ProcessTrace(&trace_, 1, nullptr, nullptr);
            failed_.store(true);
        });
        return true;
    }

    ~Tx10ubScanIdle() {
        if (trace_ != INVALID_PROCESSTRACE_HANDLE) CloseTrace(trace_);
        if (worker_.joinable()) worker_.join();
    }

    void arm(ULONGLONG scanStart) { start_.store(scanStart); }
    bool healthy() const { return !failed_.load(); }
    ULONGLONG empty_time() const { return healthy() ? empty_.load() : 0; }

private:
    static ULONG WINAPI buffer(EVENT_TRACE_LOGFILEW* log) {
        if (log->EventsLost) static_cast<Tx10ubScanIdle*>(log->Context)->failed_.store(true);
        return TRUE;
    }
    static void WINAPI record(EVENT_RECORD* event) {
        static constexpr GUID scheduler{0x88867b47,0x55ed,0x3e3d,{0x9d,0x43,0x53,0x04,0xda,0x4b,0x30,0xd7}};
        const auto& header = event->EventHeader;
        if (!(header.Flags & EVENT_HEADER_FLAG_TRACE_MESSAGE) || !IsEqualGUID(header.ProviderId, scheduler)) return;
        const auto id = header.EventDescriptor.Id;
        if (id != 0x2d && id != 0x2e) return;
        auto& self = *static_cast<Tx10ubScanIdle*>(event->UserContext);
        const auto start = self.start_.load();
        const auto time = static_cast<ULONGLONG>(header.TimeStamp.QuadPart);
        if (!start || time < start) return;
        if (time < self.last_ || event->UserDataLength != (id == 0x2d ? 8 : 0)) {
            self.failed_.store(true);
            return;
        }
        self.last_ = time;
        if (id == 0x2d) {
            self.empty_.store(0);
            ULONG fields[2]{};
            std::memcpy(fields, event->UserData, sizeof(fields));
            self.tailScan_ = fields[1] == 5;
        } else if (self.tailScan_) {
            self.empty_.store(time);
            self.tailScan_ = false;
        }
    }
    TRACEHANDLE trace_ = INVALID_PROCESSTRACE_HANDLE;
    std::thread worker_;
    std::atomic<ULONGLONG> start_{0}, empty_{0};
    std::atomic_bool failed_{false};
    ULONGLONG last_ = 0;
    bool tailScan_ = false;
};
