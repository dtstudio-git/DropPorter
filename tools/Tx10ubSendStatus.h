#pragma once
#include "Tx10ubProbeEvents.h"
#include "Tx10ubUploadQueue.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iostream>
#include <optional>

namespace tx10ub::airdrop {
// TLS ciphertext offsets include the handshake and HTTP framing on this TCP
// connection. Credit only file bytes in completely acknowledged TLS records.
class UploadAckProgress {
    struct Boundary { std::uint64_t wireEnd, fileEnd; };
    std::deque<Boundary> pending_;
    std::uint64_t wireEnd_{}, fileEnd_{}, confirmed_{};
public:
    void produced(std::size_t wireBytes,std::uint64_t fileBytes) {
        wireEnd_+=wireBytes;
        if(fileBytes>fileEnd_) {
            pending_.push_back({wireEnd_,fileBytes});
            fileEnd_=fileBytes;
        }
    }
    std::uint64_t acknowledged(std::uint64_t wireBytes) {
        while(!pending_.empty()&&pending_.front().wireEnd<=wireBytes) {
            confirmed_=pending_.front().fileEnd;
            pending_.pop_front();
        }
        return confirmed_;
    }
};
// Cumulative upload timings. Only the USB owner updates these counters.
struct UploadTiming {
    using Duration = std::chrono::microseconds;
    using Time = std::chrono::time_point<std::chrono::steady_clock, Duration>;
    std::uint64_t framesStarted{}, framesCompleted{}, permitAttempts{};
    std::uint64_t queuedGaps{}, emptyGaps{};
    Duration queuedGap{}, emptyGap{}, sendTotal{}, workerLaunch{}, windowWait{}, permitWake{};
    Duration macRead{}, ihvCall{}, usbFence{}, driverConfirmation{};
    bool driverSubmission{};

    void begin_frame(Time now) {
        ++framesStarted;
        if (!lastReport_) lastReport_ = now;
        if (!lastCompletion_) return;
        const auto gap = now - *lastCompletion_;
        if (lastQueueState_==tcp::UploadQueueState::queued) { ++queuedGaps; queuedGap += gap; }
        else {
            ++emptyGaps; emptyGap += gap;
            stateTime_[static_cast<std::size_t>(lastQueueState_)]+=gap;
        }
    }
    void completed_frame(Time now, tcp::UploadQueueState state) {
        ++framesCompleted;
        lastCompletion_ = now;
        lastQueueState_ = state;
        if (now - *lastReport_ >= std::chrono::seconds{5}) {
            report(false);
            lastReport_ = now;
        }
    }
    ~UploadTiming() { if (framesStarted) report(true); }
private:
    std::optional<Time> lastCompletion_, lastReport_;
    tcp::UploadQueueState lastQueueState_=tcp::UploadQueueState::other;
    std::array<Duration,static_cast<std::size_t>(tcp::UploadQueueState::other)+1> stateTime_{};
    void report(bool final) const {
        std::wcout << L"airdrop_upload_timing final=" << int(final)
            << L" frames_started=" << framesStarted << L" frames_completed=" << framesCompleted
            << L" gap_queued_count=" << queuedGaps << L" gap_queued_us=" << queuedGap.count()
            << L" gap_empty_count=" << emptyGaps << L" gap_empty_us=" << emptyGap.count()
            << L" gap_local_buf_us=" << stateTime_[static_cast<std::size_t>(tcp::UploadQueueState::localBuffer)].count()
            << L" gap_peer_wnd_us=" << stateTime_[static_cast<std::size_t>(tcp::UploadQueueState::peerWindow)].count()
            << L" gap_cwnd_us=" << stateTime_[static_cast<std::size_t>(tcp::UploadQueueState::congestionWindow)].count()
            << L" gap_both_wnd_us=" << stateTime_[static_cast<std::size_t>(tcp::UploadQueueState::bothWindows)].count()
            << L" gap_other_us=" << stateTime_[static_cast<std::size_t>(tcp::UploadQueueState::other)].count()
            << L" send_total_us=" << sendTotal.count() << L" permit_attempts=" << permitAttempts
            << L" worker_launch_us=" << workerLaunch.count() << L" window_us=" << windowWait.count()
            << L" permit_wake_us=" << permitWake.count() << L" mac_read_us=" << macRead.count()
            << L" ihv_call_us=" << ihvCall.count();
        if(driverSubmission)
            std::wcout << L" driver_confirmation_us=" << driverConfirmation.count();
        else
            std::wcout << L" usb_fence_us=" << usbFence.count();
        std::wcout << L'\n' << std::flush;
    }
};

// Status output only: never changes transport admission, cleanup or exit codes.
class TransferStatus {
    const wchar_t* stage_ = probe_events::WideConnect.data();
    bool finished_ = false;
    bool output_ = true;
    bool driverSubmission_ = false;
    std::uint64_t packets_ = 0, bytes_ = 0;
    std::uint64_t rate24Packets_ = 0;
    std::uint64_t progressAt_ = 0;
    bool haveProgress_ = false;
    bool reportedAllBytes_ = false;
public:
    explicit TransferStatus(bool output=true,bool driverSubmission=false)
        :output_(output),driverSubmission_(driverSubmission) { stage(stage_); }
    ~TransferStatus() {
        if (!finished_) fail(L"interrupted", 4);
        if(output_)std::wcout << L"airdrop_transport_totals "
            << (driverSubmission_?L"driver_submitted_packets=":L"usb_out_packets=") << packets_
            << L" mpdu_bytes=" << bytes_ << L" requested_rate24_packets=" << rate24Packets_
            << L" requested_rate12_packets=" << packets_-rate24Packets_ << L'\n' << std::flush;
    }
    void sent(std::size_t bytes,bool rate24=false) { ++packets_; bytes_ += bytes; if(rate24)++rate24Packets_; }
    void progress(std::uint64_t processed, std::uint64_t total, std::uint64_t elapsedMs) {
        const bool firstFull=processed==total&&!reportedAllBytes_;
        if(haveProgress_&&elapsedMs-progressAt_<250&&!firstFull)return;
        if(processed==total)reportedAllBytes_=true;
        haveProgress_=true;progressAt_=elapsedMs;
        if(output_)std::wcout << probe_events::ProgressPrefix.data() << probe_events::ProcessedKey << L'=' << processed
            << L' ' << probe_events::TotalKey << L'=' << total
            << L' ' << probe_events::ElapsedKey << L'=' << elapsedMs << L'\n' << std::flush;
    }
    void stage(const wchar_t* value) {
        stage_ = value;
        if(output_)std::wcout << probe_events::StagePrefix.data() << stage_ << L'\n' << std::flush;
    }
    int fail(const wchar_t* reason, int exitCode, unsigned httpStatus = 0) {
        if (!finished_) {
            finished_ = true;
            if(output_)std::wcout << probe_events::FailurePrefix.data() << stage_ << probe_events::FailureReason.data() << reason
                << probe_events::FailureHttpStatus.data() << httpStatus << L'\n' << std::flush;
        }
        return exitCode;
    }
    void complete() { finished_ = true; }
};

struct AttemptFailure {
    const wchar_t* reason=nullptr;
    unsigned httpStatus=0;
    bool retryable=false;
    bool certificateRejected=false;
    int record(const wchar_t* value,int exitCode,unsigned http=0,bool transient=false) {
        if(!reason){reason=value;httpStatus=http;retryable=transient;}
        return exitCode;
    }
};

// Four attempts share one 20-second discovery budget. The caller additionally
// requires the same fresh endpoint and a healthy USB/control owner.
class DiscoveryRetry {
    std::uint64_t began_;
    unsigned attempts_=0;
public:
    explicit DiscoveryRetry(std::uint64_t now):began_(now){}
    std::uint64_t deadline()const{return began_+20'000'000;}
    std::uint64_t begin_attempt(std::uint64_t now) {
        ++attempts_;
        return (std::min)(deadline(),now+5'000'000);
    }
    bool allowed(std::uint64_t now,const AttemptFailure& failure)const {
        return failure.retryable&&attempts_<4&&now>=began_&&now<deadline();
    }
};
}
