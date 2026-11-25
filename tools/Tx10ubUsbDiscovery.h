#pragma once
#include "Tx10ubUsbReader.h"
#include "Tx10ubNdisReader.h"
#include "Tx10ubUsbSession.h"
#include "Tx10ubUsbTxTiming.h"
#include "Tx10ubUsbDataTiming.h"
#include "Tx10ubTcpStream.h"
#include <iostream>
#include <iomanip>
#include <memory>
#include <functional>
#include <limits>
#include <thread>
#include <array>

namespace tx10ub::usb {
inline awdlwin::tx10ub::usb_clock::Observation observe_clock() {
    using namespace awdlwin::tx10ub::usb_clock;
    auto acquired=acquire_observation([] {
        const auto before=awdlwin::discovery::monotonic_now();
        FILETIME time{};GetSystemTimePreciseAsFileTime(&time);
        const auto after=awdlwin::discovery::monotonic_now();
        const auto ticks=(std::uint64_t(time.dwHighDateTime)<<32)|time.dwLowDateTime;
        constexpr std::uint64_t epoch=11644473600000000ull;
        if(ticks/10<epoch)throw std::runtime_error("usb_utc_before_unix_epoch");
        return Observation{ticks/10-epoch,before,after};
    },discovery_budget);
    if(const auto* failure=std::get_if<Failure>(&acquired))
        throw std::runtime_error(failure->error==ClockError::invalid_observation?
            "usb_clock_invalid_observation":"usb_clock_bracket_too_wide");
    return std::get<Observation>(std::move(acquired));
}
inline awdlwin::discovery::MonotonicTime clock_midpoint(
    const awdlwin::tx10ub::usb_clock::Observation& first) {
    return first.steady_before+(first.steady_after-first.steady_before)/2;
}
class DiscoveryReceiver {
    std::function<bool()> maintain_receive_;
    Reader reader_;
    std::unique_ptr<ndiscap::Reader> ndis_reader_;
    bool ndis_stopped_=false;
    std::unique_ptr<Session> session_;
    Decoder decoder_;
    TxTiming tx_timing_;
    DataTiming data_timing_;
    using Time=awdlwin::discovery::MonotonicTime;
    std::optional<std::pair<Time,Time>> data_submit_bounds_;
    std::optional<awdlwin::wire::Bytes> data_query_identity_;
    std::optional<Time> data_query_submitted_at_;
    bool data_query_out_observed_=false;
    bool driver_submission_accepted_=false;
    std::optional<tx10ub::tcp::ConnectCheck> tcp_check_;
    std::optional<Time> tcp_submitted_at_;
    std::unique_ptr<tx10ub::tcp::Stream> tcp_stream_;
    std::array<tx10ub::tcp::Stream*,4> name_streams_{};
    std::function<void(const awdlwin::wire::MacAddress&,std::span<const std::uint8_t>)> receive_application_;
    std::function<void(const Session::Datagram&,bool)> discovery_observer_;
    std::wstring trace_path_;
    HANDLE trace_=INVALID_HANDLE_VALUE;
    std::uint64_t trace_bytes_=0;
    bool failed_=false,closed_=false;
    bool verboseLog_=true;
    bool logCoexistenceFrames_=false;
    std::optional<awdlwin::wire::MacAddress> receivePeer_;
    // The decoder has already verified the MPDU and its trailing FCS here.
    static void log_capture_identity(const wchar_t* type, const awdlwin::wire::MacAddress& source,
        unsigned sequence, std::span<const std::uint8_t> mpdu, std::uint64_t utc) {
        std::wcout << L"coexistence_usb_in=" << type << L" utc_us=" << utc << L" source=";
        for (const auto byte : source)
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << unsigned(byte);
        std::wcout << std::dec << L" seq=" << sequence << L" bytes_with_fcs=" << mpdu.size()
                   << L" fcs=0x" << std::hex << std::setw(8) << le32(mpdu, mpdu.size()-4)
                   << std::dec << std::setfill(L' ') << L'\n';
    }
    bool discoveryRetry_=false;
    std::optional<awdlwin::discovery::MonotonicTime> last_response_observation_;
    std::uint64_t accepted_=0,rejected_=0,sync_applied_=0,stale_events_=0,duplicate_data_frames_=0;
    std::uint64_t unicast_windows_=0;
    std::uint64_t name_syn_acks_decoded_{}, name_syn_acks_delivered_{};
    std::chrono::microseconds unicast_wait_total_{},unicast_wait_max_{};
    std::uint64_t data_fences_=0;
    std::chrono::microseconds data_fence_wait_total_{},data_fence_wait_max_{};
    void log_unicast_window_totals()const {
        if(unicast_windows_) {
            std::wcout<<L"tcp_unicast_window_totals selected="<<unicast_windows_
                <<L" wait_total_us="<<unicast_wait_total_.count()
                <<L" wait_max_us="<<unicast_wait_max_.count()<<L'\n';
        }
    }
    bool window_retry_peer_current(const awdlwin::wire::MacAddress& expected,Time now)const {
        const auto& core=session_->core();
        const auto& state=core.state();
        const auto* peer=core.peers().find(expected);
        return state.election.height!=0&&state.election.sync_address==expected&&peer&&peer->metadata_ready()&&
            std::holds_alternative<awdlwin::discovery::AvailabilityWindow>(core.availability(now));
    }
    void count_stale_event()noexcept {
        if(stale_events_!=(std::numeric_limits<std::uint64_t>::max)())++stale_events_;
    }
    void accept_tx(const TxObservation& observed) {
        const auto time=session_->transport_event_time(observed.capture_utc_us);
        if(!time)return;
        const auto sample=tx_timing_.observe(observed.source_mac,observed.exact_action_body,*time);
        if(!sample)return;
        if(!verboseLog_)return;
        std::wcout<<L"usb_action_delay_us="<<sample->actual_delay.count();
        if(sample->prediction_error)std::wcout<<L" prediction_error_us="<<sample->prediction_error->count();
        if(const auto spread=tx_timing_.sample_spread(*time))
            std::wcout<<L" sample_spread_us="<<spread->count();
        std::wcout<<L'\n';
    }
    void accept_data_tx(const DataTxObservation& observed) {
        const auto time=session_->transport_event_time(observed.capture_utc_us);
        if(!time)return;
        if(data_query_identity_&&data_query_submitted_at_&&*time>=*data_query_submitted_at_&&
           DataTiming::matches(*data_query_identity_,observed.exact_mpdu))data_query_out_observed_=true;
        if(const auto delay=data_timing_.observe(observed.exact_mpdu,*time);delay&&verboseLog_)
            std::wcout<<L"usb_data_submit_delay_us="<<delay->count()<<L'\n';
    }
    void accept_data(const DataFrame& frame) {
        if (logCoexistenceFrames_&&!uses_ndiscap())
            log_capture_identity(L"data",frame.data.source,frame.data.sequence,frame.mpdu,frame.capture_utc_us);
        if (receivePeer_ && frame.data.source != *receivePeer_) return;
        const auto checkEvent=tcp_check_&&tcp_submitted_at_?
            session_->transport_event_time(frame.capture_utc_us):std::nullopt;
        const bool checkConsumer=checkEvent&&*checkEvent>=*tcp_submitted_at_;
        const bool consumer=receive_application_||tcp_stream_||checkConsumer||
            std::any_of(name_streams_.begin(),name_streams_.end(),[](const auto* stream){return stream!=nullptr;});
        auto result=session_->ingest_data(frame,consumer);
        if(const auto* error=std::get_if<std::string>(&result)) {
            std::wcerr<<(uses_ndiscap()?L"ndiscap_data_clock_error=":L"usb_data_clock_error=")<<error->c_str()<<L'\n';failed_=true;return;
        }
        if(const auto* rejected=std::get_if<Session::DataReject>(&result)) {
            if(*rejected==Session::DataReject::stale_event){count_stale_event();return;}
            if(*rejected==Session::DataReject::duplicate_frame){++duplicate_data_frames_;return;}
            if(verboseLog_)std::wcout<<(uses_ndiscap()?L"ndiscap_data_rejected=":L"usb_data_rejected=")<<unsigned(*rejected)<<L'\n';
            return;
        }
        const auto& accepted=std::get<Session::DataReceipt>(result);
        if(discovery_observer_)
            for(const auto& d:accepted.datagrams)discovery_observer_(d,static_cast<bool>(receive_application_));
        if(receive_application_) {
            for(const auto& d:accepted.datagrams)receive_application_(d.source,d.ipv6);
        }
        if(tcp_stream_) {
            for(const auto& d:accepted.datagrams)tcp_stream_->receive(d.source,d.ipv6);
        }
        if(std::any_of(name_streams_.begin(),name_streams_.end(),[](const auto* stream){return stream!=nullptr;})) {
            for(const auto& d:accepted.datagrams) {
                const auto tcp = d.packet.protocol == IPPROTO_TCP ? tx10ub::tcp::parse(d.ipv6) : std::nullopt;
                const bool synAck = tcp && (tcp->flags & 0x12) == 0x12;
                if (synAck) ++name_syn_acks_decoded_;
                for(auto* stream:name_streams_) {
                    if(!stream || !stream->receive(d.source,d.ipv6)) continue;
                    if (synAck) ++name_syn_acks_delivered_;
                    break;
                }
            }
        }
        if(tcp_check_&&tcp_submitted_at_&&accepted.event_at>=*tcp_submitted_at_) {
            for(const auto& d:accepted.datagrams)
                if(tcp_check_->receive(d.source,d.ipv6))
                    std::wcout<<L"tcp_correlated_reply=1 syn_ack="<<tcp_check_->syn_ack_received()
                        <<L" reset="<<tcp_check_->refused()<<L'\n';
        }
        if(!verboseLog_)return; // Ingestion, TCP delivery and USB timing remain active.
        std::size_t udp=0,mdns=0,airdrop=0;
        for(const auto& datagram:accepted.datagrams) {
            if(datagram.packet.udp)++udp;
            if(!datagram.mdns)continue;
            ++mdns;
            const auto& message=*datagram.mdns;
            for(const auto& q:message.questions)if(awdlwin::ip::is_airdrop_name(q.name))++airdrop;
            for(const auto* section:{&message.answers,&message.authorities,&message.additionals})
                for(const auto& r:*section)if(awdlwin::ip::is_airdrop_name(r.name)||
                    (r.target&&awdlwin::ip::is_airdrop_name(*r.target)))++airdrop;
        }
        // Keep service names / TXT data out of diagnostics. Typed owned DNS
        // messages feed the source-scoped, expiring passive service cache.
        const auto services=session_->airdrop_services(accepted.event_at);
        std::wcout<<(uses_ndiscap()?L"ndiscap_data_received ipv6=":L"usb_data_received ipv6=")<<accepted.datagrams.size()<<L" udp="<<udp
            <<L" mdns="<<mdns<<L" airdrop_entries="<<airdrop
            <<L" airdrop_resolved_endpoints="<<services.endpoints.size()
            <<L" service_snapshot_truncated="<<services.truncated
            <<L" event_steady_us="<<accepted.event_at.time_since_epoch().count()<<L'\n';
    }
    static std::unique_ptr<Session> make_session(awdlwin::discovery::TransmitState initial,
        const awdlwin::tx10ub::usb_clock::Observation& first) {
        // Explicit experiment policy, not a claim of measured hardware precision.
        const auto& budget=awdlwin::tx10ub::usb_clock::discovery_budget;
        auto made=Session::create(std::move(initial),first,budget,10'000'000);
        if(const auto* error=std::get_if<std::string>(&made))throw std::runtime_error(*error);
        return std::make_unique<Session>(std::move(std::get<Session>(made)));
    }
    void accept(const Frame& frame) {
        if (logCoexistenceFrames_&&!uses_ndiscap())
            log_capture_identity(L"action",frame.action.source,frame.action.sequence,frame.mpdu,frame.capture_utc_us);
        if (receivePeer_ && frame.action.source != *receivePeer_) return;
        auto receipt=session_->ingest(frame);
        if(const auto* error=std::get_if<std::string>(&receipt)) {
            std::wcerr<<(uses_ndiscap()?L"ndiscap_session_clock_error=":L"usb_session_clock_error=")<<error->c_str()<<L'\n';failed_=true;return;
        }
        if(std::holds_alternative<Session::StaleEvent>(receipt)){count_stale_event();return;}
        const auto& accepted=std::get<Session::Receipt>(receipt);
        if(const auto* failure=std::get_if<awdlwin::discovery::SessionFailure>(&accepted.update)) {
            ++rejected_;
            if(verboseLog_)std::wcout<<(uses_ndiscap()?L"ndiscap_session_rejected=":L"usb_session_rejected=")<<unsigned(failure->error)<<L'\n';
            return;
        }
        ++accepted_;
        const bool synced=std::holds_alternative<awdlwin::discovery::AppliedSync>(
            std::get<awdlwin::discovery::SessionUpdate>(accepted.update).sync);
        if(synced)++sync_applied_;
        if(!verboseLog_)return;
        const auto& state=session_->core().state();
        const auto processedAt=awdlwin::discovery::monotonic_now();
        std::wcout<<(uses_ndiscap()?L"ndiscap_session_received subtype=":L"usb_session_received subtype=")<<unsigned(frame.action.body.header.subtype)
            <<L" body_bytes="<<frame.body_bytes<<L" event_steady_us="<<accepted.event_at.time_since_epoch().count()
            <<L" processed_steady_us="<<processedAt.time_since_epoch().count()
            <<L" clock_error_policy_us="<<accepted.clock_uncertainty_us<<L" sync_applied="<<synced
            <<L" election_height="<<state.election.height<<L" master_metric="<<state.election.master_metric
            <<L" sequence_control="<<le16(frame.mpdu,22);
        if(frame.fcs==Fcs::present)std::wcout<<L" frame_fcs="<<le32(frame.mpdu,frame.mpdu.size()-4);
        std::wcout<<L'\n';
        const auto now=awdlwin::discovery::monotonic_now();
        const auto psf=session_->generate(awdlwin::wire::ActionSubtype::psf,now);
        const auto mif=session_->generate(awdlwin::wire::ActionSubtype::mif,now);
        std::wcout<<(uses_ndiscap()?L"ndiscap_session_generated_psf_bytes=":L"usb_session_generated_psf_bytes=")
            <<(std::holds_alternative<awdlwin::wire::Bytes>(psf)?std::get<awdlwin::wire::Bytes>(psf).size():0)
            <<(uses_ndiscap()?L"\nndiscap_session_generated_mif_bytes=":L"\nusb_session_generated_mif_bytes=")
            <<(std::holds_alternative<awdlwin::wire::Bytes>(mif)?std::get<awdlwin::wire::Bytes>(mif).size():0)<<L'\n';
    }
    void accept_ndis(std::span<const std::uint8_t> mpdu,std::uint64_t utc) {
        const bool hasFcs=valid_fcs(mpdu);
        const auto fcs=hasFcs?Fcs::present:Fcs::stripped_by_ndis;
        if(mpdu.empty())return;
        if(mpdu[0]==0xd0) {
            auto action=awdlwin::wire::parse_action_mpdu(mpdu,hasFcs);
            if(!action)return;
            const auto body=mpdu.subspan(24,mpdu.size()-24-(hasFcs?4:0));
            auto encoded=awdlwin::wire::serialize_action_body(action.value().body);
            if(!encoded||!std::equal(body.begin(),body.end(),encoded.value().begin(),encoded.value().end()))return;
            accept(Frame{std::move(action.value()),body.size(),utc,{mpdu.begin(),mpdu.end()},fcs});
        } else {
            auto data=awdlwin::wire::parse_awdl_data_mpdu(mpdu,hasFcs);
            if(data)accept_data(DataFrame{std::move(data.value()),utc,{mpdu.begin(),mpdu.end()},fcs});
        }
    }
    bool sample_clock() {
        if(!session_->observe(observe_clock())) {
            std::wcerr<<L"receive_clock_observe_error="<<session_->clock_error()<<L'\n';
            failed_=true;
        }
        return !failed_;
    }
    bool advance_watermark() {
        if(!failed_&&!session_->advance_receive_watermark()){
            std::wcerr<<L"receive_watermark_failed=1\n";failed_=true;
        }
        return !failed_;
    }
    bool poll_ndis(DWORD maxWaitMs,HANDLE ownerCompletion) {
        try {
            bool sampled=false;
            if(!ndis_reader_->poll(maxWaitMs,ownerCompletion,[&](auto mpdu,std::uint64_t utc){
                if(failed_)return;
                if(!sampled){if(!sample_clock())return;sampled=true;}
                accept_ndis(mpdu,utc);
            })) {
                std::wcerr<<L"ndiscap_read_error="<<ndis_reader_->error_code()<<L'\n';
                failed_=true;return false;
            }
            if(!sampled&&!sample_clock())return false;
            return advance_watermark();
        }catch(const std::exception& error){std::wcerr<<L"ndiscap_receive_error="<<error.what()<<L'\n';failed_=true;return false;}
    }
    bool feed(std::span<const std::uint8_t> bytes) {
        try {
            if(trace_!=INVALID_HANDLE_VALUE&&!bytes.empty()) {
                DWORD written=0;
                if(!WriteFile(trace_,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)||written!=bytes.size()) {
                    std::wcerr<<L"usb_trace_write_error="<<GetLastError()<<L'\n';failed_=true;return false;
                }
                trace_bytes_+=written;
            }
            if(!sample_clock())return false;
            decoder_.feed(bytes);
            if(decoder_.counts.rejected!=0)failed_=true;
            advance_watermark();
        }catch(const std::exception& error){std::wcerr<<L"usb_receive_error="<<error.what()<<L'\n';failed_=true;}
        return !failed_;
    }
public:
    void set_verbose_logging(bool enabled) { verboseLog_=enabled; }
    void log_coexistence_frames(bool enabled) { logCoexistenceFrames_=enabled; }
    void select_receive_peer(std::optional<awdlwin::wire::MacAddress> peer) { receivePeer_=peer; }
    void allow_discovery_retry(bool enabled) { discoveryRetry_=enabled; }
    bool uses_ndiscap()const noexcept {return ndis_reader_!=nullptr;}
    bool retry_receive_healthy()const { return !failed_&&!closed_&&(uses_ndiscap()?ndis_reader_->healthy():reader_.healthy()); }
    bool retryable_tcp_failure()const {
        return discoveryRetry_&&retry_receive_healthy()&&tcp_stream_&&tcp_stream_->retryable_error();
    }
    DiscoveryReceiver(std::wstring hub,unsigned address,awdlwin::discovery::TransmitState initial,
                      const awdlwin::tx10ub::usb_clock::Observation& first,const wchar_t* tracePath=nullptr,
                      std::function<bool()> maintainReceive={},std::wstring ndisSession={},unsigned ifIndex=0)
        :maintain_receive_(std::move(maintainReceive)),reader_(std::move(hub),address),
         ndis_reader_(ndisSession.empty()?nullptr:std::make_unique<ndiscap::Reader>(std::move(ndisSession),ifIndex,initial.self_address)),
         session_(make_session(std::move(initial),first)),
         decoder_(address,[this](const Frame& frame){if(!failed_)accept(frame);},
            [this](const DataFrame& frame){if(!failed_)accept_data(frame);},
            [this](const TxObservation& frame){if(!failed_)accept_tx(frame);},
            [this](const DataTxObservation& frame){if(!failed_)accept_data_tx(frame);}),trace_path_(tracePath?tracePath:L""){}
    DiscoveryReceiver(const DiscoveryReceiver&)=delete;
    DiscoveryReceiver& operator=(const DiscoveryReceiver&)=delete;
    ~DiscoveryReceiver(){close();}
    bool begin() {
        if(uses_ndiscap()) {
            if(!trace_path_.empty()||!ndis_reader_->begin()) {
                std::wcerr<<L"ndiscap_open_error="<<ndis_reader_->error_code()<<L'\n';failed_=true;return false;
            }
            std::wcout<<L"ndiscap_receive_started=1\n";
            return poll_ndis(0,nullptr);
        }
        if(!trace_path_.empty()) {
            trace_=CreateFileW(trace_path_.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,
                CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
            if(trace_==INVALID_HANDLE_VALUE) {
                std::wcerr<<L"usb_trace_open_error="<<GetLastError()<<L'\n';failed_=true;return false;
            }
        }
        if(!reader_.begin()) {
            std::wcerr<<L"usb_open_error="<<reader_.error_code()<<L'\n';failed_=true;return false;
        }
        std::wcout<<L"usb_receive_started=1\nusb_clock_max_age_us=250000\nusb_peer_lifetime_us=10000000\n"
            L"usb_radio_latency=uncalibrated\nusb_channel_policy=fixed_local\n";
        return feed({});
    }
    bool poll(DWORD maxWaitMs=0,HANDLE ownerCompletion=nullptr) {
        if(failed_||closed_)return false;
        if(maintain_receive_&&!maintain_receive_()) {
            std::wcerr<<L"usb_receive_control_failed=1\n";failed_=true;return false;
        }
        if(tcp_stream_) {
            tcp_stream_->tick(static_cast<std::uint64_t>(awdlwin::discovery::monotonic_now().time_since_epoch().count()));
            if(!tcp_stream_->healthy()){
                std::wcerr<<L"tcp_stream_error="<<tcp_stream_->error()<<L'\n';
                // Only a pre-approval discovery owner can recover a remote TCP failure.
                // Reader/control/decoder failures keep their existing permanent latch.
                if(!retryable_tcp_failure())failed_=true;
                return false;
            }
        }
        const auto nameNow=static_cast<std::uint64_t>(awdlwin::discovery::monotonic_now().time_since_epoch().count());
        for(auto* stream:name_streams_)if(stream) {
            stream->tick(nameNow);
            if(!stream->healthy()&&!stream->retryable_error()) {
                std::wcerr<<L"name_tcp_stream_error="<<stream->error()<<L'\n';failed_=true;return false;
            }
        }
        if(uses_ndiscap())return poll_ndis(maxWaitMs,ownerCompletion);
        const auto bytes=reader_.poll(maxWaitMs,ownerCompletion);
        if(!reader_.healthy()){
            std::wcerr<<L"usb_reader_error="<<reader_.error_code()<<L" reason="
                <<reader_.error_name()<<L'\n';failed_=true;return false;
        }
        return feed(bytes);
    }
    // Keep the same owner and minimum TX delay while draining receive events.
    // Waiting on the read event avoids both a worker race and a busy spin.
    bool wait(DWORD durationMs) {
        const auto started=GetTickCount64();
        for(;;) {
            const auto elapsed=GetTickCount64()-started;
            if(elapsed>=durationMs)return !failed_&&!closed_;
            const auto remaining=static_cast<DWORD>(durationMs-elapsed);
            if(!poll((std::min)(DWORD{10},remaining)))return false;
        }
    }
    int await_unicast_window(unsigned channel,DWORD timeoutMs,
                             const std::function<int()>& maintainAction,
                             const awdlwin::wire::MacAddress& target,bool fixedUpload=false) {
        data_submit_bounds_.reset();
        const auto expected=target;
        const auto entered=awdlwin::discovery::monotonic_now();
        const auto deadline=entered+std::chrono::milliseconds{timeoutMs};
        DWORD pollWaitMs=0;
        do {
            // Recheck after one read or wait timeout. wait(1) can pump
            // repeatedly before the coarse Windows tick advances.
            if(!poll(pollWaitMs))return 4;
            pollWaitMs=1;
            const auto now=awdlwin::discovery::monotonic_now();
            if(now>=deadline||!session_->target_peer_present(expected,now))break;
            if(tx_timing_.pending_count()!=0) {
                if(tx_timing_.pending_timed_out(now))return 4;
                continue;
            }
            const auto predicted=data_timing_.prediction(now);
            const auto delay=predicted.value_or(std::chrono::microseconds{0});
            if(const auto window=session_->peer_unicast_window(now,channel,delay,&expected,fixedUpload)) {
                const auto elapsed=now-entered;
                ++unicast_windows_;
                unicast_wait_total_+=elapsed;
                unicast_wait_max_=(std::max)(unicast_wait_max_,elapsed);
                data_submit_bounds_=std::pair{window->submit_begin,window->submit_end};
                if(verboseLog_)std::wcout<<L"tcp_unicast_window slot="<<unsigned(window->decision.sequence_slot)
                    <<L" modeled_steady_us="<<now.time_since_epoch().count()
                    <<L" submit_end_us="<<window->submit_end.time_since_epoch().count()
                    <<L" predicted_data_delay_us="<<delay.count()
                    <<L" data_delay_calibrated="<<predicted.has_value()<<L'\n';
                return 0;
            }
            // Do not insert a blocking Action into the leading/trailing guard
            // of a currently matching channel. Keep the one USB reader active.
            const auto ticks=now.time_since_epoch().count();
            if(delay.count()>=0&&ticks>=0&&delay.count()<=(std::numeric_limits<std::int64_t>::max)()-ticks&&
               session_->target_channel_window(expected,now+delay,channel,fixedUpload)) {
                continue;
            }
            if(maintainAction) {
                const auto error=maintainAction();if(error)return error;
            }
        }while(awdlwin::discovery::monotonic_now()<deadline);
        std::wcerr<<L"tcp_unicast_window_unavailable=1\n";return 4;
    }
    int await_multicast_window(unsigned channel,DWORD timeoutMs=2000,
                               const std::function<int()>& maintainAction={},
                               std::chrono::microseconds pairedRfLead={},bool guardedReply=false,
                               std::optional<Time> browseUntil=std::nullopt) {
        data_submit_bounds_.reset();
        if(pairedRfLead.count()<0||pairedRfLead.count()>Session::maximum_paired_rf_lead_us)return 4;
        const auto enteredAt=awdlwin::discovery::monotonic_now();
        auto deadline=enteredAt+std::chrono::milliseconds{timeoutMs};
        if(browseUntil)deadline=(std::min)(deadline,*browseUntil);
        const auto retryBudgetEnd=browseUntil?deadline:deadline+std::chrono::seconds{3};
        const auto retryPeer=session_->core().state().election.sync_address;
        constexpr unsigned retryLimit=2;
        unsigned retries=0;
        std::optional<Time> previousCheck,previousCenter,previousSync;
        std::uint64_t checks=0,eligibleChecks=0,approachingChecks=0,candidateChecks=0;
        std::int64_t maxPollUs=0,maxCheckGapUs=0,crossedCenterUs=-1,crossedBeforeUs=-1,crossedAfterUs=-1;
        std::int64_t maxWaitUs=0,maxActionUs=0;
        const auto waitForNextCheck=[&] {
            const auto before=awdlwin::discovery::monotonic_now();
            // Recheck the send window after one USB poll. wait(1) can pump
            // several reads until the coarse Windows tick advances.
            const bool ok=poll(1);
            maxWaitUs=(std::max)(maxWaitUs,(awdlwin::discovery::monotonic_now()-before).count());
            return ok;
        };
        bool crossedSyncChanged=false;
        const auto reportWindowTrace=[&](bool selected,Time now) {
            // Summarize once, rather than writing on every narrow-window poll.
            // Predictions are diagnostics; they never grant a send permit.
            std::wcout<<L"mdns_window_trace selected="<<selected
                <<L" start_steady_us="<<enteredAt.time_since_epoch().count()
                <<L" end_steady_us="<<now.time_since_epoch().count()
                <<L" timeout_ms="<<timeoutMs<<L" checks="<<checks<<L" eligible_checks="<<eligibleChecks
                <<L" approaching_checks="<<approachingChecks<<L" candidate_checks="<<candidateChecks
                <<L" max_poll_us="<<maxPollUs<<L" max_check_gap_us="<<maxCheckGapUs
                <<L" max_wait_us="<<maxWaitUs<<L" max_action_us="<<maxActionUs
                <<L" last_predicted_center_us="<<(previousCenter?previousCenter->time_since_epoch().count():-1)
                <<L" crossed_center_us="<<crossedCenterUs<<L" crossed_before_us="<<crossedBeforeUs
                <<L" crossed_after_us="<<crossedAfterUs<<L" crossed_sync_changed="<<crossedSyncChanged<<L'\n';
        };
        const auto pendingAtSelection=tx_timing_.pending_count();
        if(!uses_ndiscap())std::wcout<<L"mdns_action_out_pending_at_window_selection="<<pendingAtSelection<<L'\n';
        std::optional<std::size_t> reportedPending;
        const auto reportPendingWait=[&](std::size_t pending) {
            if(pending==0) {
                if(reportedPending)std::wcout<<L"mdns_action_out_wait_complete=1 pending_count=0\n";
                reportedPending.reset();
            } else if(!reportedPending||*reportedPending!=pending) {
                std::wcout<<L"mdns_action_out_wait_pending="<<pending<<L'\n';
                reportedPending=pending;
            }
        };
        reportPendingWait(pendingAtSelection);
        for(;;) {
        do {
            const auto pollStarted=awdlwin::discovery::monotonic_now();
            if(!poll())return 4;
            const auto now=awdlwin::discovery::monotonic_now();
            if(now>=retryBudgetEnd)break;
            if(retries&&!window_retry_peer_current(retryPeer,now)) {
                std::wcerr<<L"mdns_window_retry_peer_unavailable=1\n";return 4;
            }
            ++checks;
            maxPollUs=(std::max)(maxPollUs,(now-pollStarted).count());
            if(previousCheck)maxCheckGapUs=(std::max)(maxCheckGapUs,(now-*previousCheck).count());
            const auto syncObserved=session_->core().last_sync_observation();
            if(previousCheck&&previousCenter&&*previousCheck<*previousCenter&&
               now>*previousCenter+std::chrono::microseconds{Session::multicast_center_tolerance_us}) {
                crossedCenterUs=previousCenter->time_since_epoch().count();
                crossedBeforeUs=previousCheck->time_since_epoch().count();
                crossedAfterUs=now.time_since_epoch().count();
                crossedSyncChanged=previousSync!=syncObserved;
            }
            previousCheck=now;previousSync=syncObserved;
            const auto pending=tx_timing_.pending_count();
            reportPendingWait(pending);
            if(pending!=0) {
                if(tx_timing_.pending_timed_out(now)) {
                    std::wcerr<<L"mdns_action_out_timeout=1 pending_count="<<pending<<L'\n';
                    return 4;
                }
                // The selected Data schedule follows every tracked Action
                // submission. Keep receiving its USB OUT record, but don't
                // send another Action while that identity is unresolved.
                if(!waitForNextCheck())return 4;
                continue;
            }
            const auto predicted=data_timing_.prediction(now);
            const auto delay=predicted.value_or(std::chrono::microseconds{0});
            if(guardedReply||browseUntil) {
                if(const auto window=session_->peer_multicast_window(now,channel,delay+pairedRfLead)) {
                    const auto& decision=window->decision;
                    data_submit_bounds_=std::pair{window->submit_begin,window->submit_end};
                    std::wcout<<(browseUntil?L"mdns_query_window slot=":L"mdns_reply_window slot=")<<unsigned(decision.sequence_slot)
                        <<L" elapsed_us="<<decision.elapsed_in_eaw_us
                        <<L" remaining_us="<<decision.remaining_eaw_us
                        <<L" permit_us="<<(window->submit_end-window->submit_begin).count()
                        <<L" predicted_data_delay_us="<<delay.count()
                        <<L" data_delay_calibrated="<<predicted.has_value()<<L'\n';
                    return 0;
                }
            } else if(const auto decision=session_->peer_multicast_center(now,channel,delay,pairedRfLead)) {
                ++eligibleChecks;
                const auto center=(static_cast<std::int64_t>(decision->elapsed_in_eaw_us)+
                                   decision->remaining_eaw_us)/2;
                const auto submitCenter=now+std::chrono::microseconds{
                    center-static_cast<std::int64_t>(decision->elapsed_in_eaw_us)};
                const auto tolerance=std::chrono::microseconds{Session::multicast_center_tolerance_us};
                data_submit_bounds_=std::pair{submitCenter-tolerance,submitCenter+tolerance};
                std::wcout<<L"mdns_peer_window aw_counter="<<decision->aw_counter
                    <<L" eaw_counter="<<decision->eaw_counter<<L" slot="<<unsigned(decision->sequence_slot)
                    <<L" elapsed_us="<<decision->elapsed_in_eaw_us<<L" remaining_us="<<decision->remaining_eaw_us
                    <<L" peer_age_us="<<decision->peer_age_us<<L" primary="<<unsigned(decision->primary_channel)
                    <<L" center="<<unsigned(decision->center_channel)
                    <<L" advertised_width_mhz="<<(decision->width_mhz?unsigned(*decision->width_mhz):0)
                    <<L" encoding="<<unsigned(decision->encoding)<<L" raw_flags="<<unsigned(decision->raw_flags)
                    <<L" modeled_steady_us="<<now.time_since_epoch().count()
                    <<L" predicted_data_delay_us="<<delay.count()
                    <<L" paired_rf_lead_us="<<pairedRfLead.count()
                    <<L" data_delay_calibrated="<<predicted.has_value()<<L'\n';
                return 0;
            }
            // Within the leading guard's eligible interval, keep draining USB
            // without a millisecond timer or a blocking Action submission that
            // could jump over the narrow center. This lasts at most half an EAW.
            if(const auto approaching=session_->peer_multicast_decision(now+delay+pairedRfLead,channel);
               approaching&&approaching->elapsed_in_eaw_us<approaching->remaining_eaw_us) {
                ++approachingChecks;
                std::this_thread::yield();
                continue;
            }
            const auto projectedLead=delay+pairedRfLead;
            const auto nowUs=now.time_since_epoch().count();
            if(nowUs>=0&&projectedLead.count()>=0&&
               nowUs<=(std::numeric_limits<std::int64_t>::max)()-projectedLead.count()) {
                // Do not start a blocking Action while a validated next
                // channel center is waiting for this Data query. Re-evaluate
                // after each poll so newer peer Sync and freshness govern it.
                if(const auto next=session_->next_peer_multicast_center(now+projectedLead,channel)) {
                    ++candidateChecks;
                    previousCenter=next->transmit_at-projectedLead;
                    if(!waitForNextCheck())return 4;
                    continue;
                }
            }
            if(maintainAction) {
                const auto before=awdlwin::discovery::monotonic_now();
                const auto maintenanceError=maintainAction();
                maxActionUs=(std::max)(maxActionUs,(awdlwin::discovery::monotonic_now()-before).count());
                if(maintenanceError!=0)return maintenanceError;
                reportPendingWait(tx_timing_.pending_count());
            }
            if(!waitForNextCheck())return 4;
        }while(awdlwin::discovery::monotonic_now()<deadline);
        if(const auto pending=tx_timing_.pending_count();pending!=0) {
            std::wcerr<<L"mdns_action_out_wait_timeout=window pending_count="<<pending<<L'\n';
            return 4;
        }
        const auto retryAt=awdlwin::discovery::monotonic_now();
        reportWindowTrace(false,retryAt);
        if(retries>=retryLimit||retryAt>=retryBudgetEnd||!window_retry_peer_current(retryPeer,retryAt))break;
        const auto delay=data_timing_.prediction(retryAt).value_or(std::chrono::microseconds{0});
        const auto lead=delay+pairedRfLead;
        const auto next=session_->next_peer_multicast_center(retryAt+lead,channel);
        if(!next)break;
        const auto submitCenter=next->transmit_at-lead;
        const auto nextDeadline=submitCenter+std::chrono::microseconds{Session::multicast_center_tolerance_us};
        if(nextDeadline<=retryAt||nextDeadline>retryBudgetEnd)break;
        deadline=nextDeadline;++retries;
        std::wcout<<L"mdns_window_retry="<<retries<<L" max_retries="<<retryLimit
            <<L" next_submit_center_us="<<submitCenter.time_since_epoch().count()
            <<L" total_deadline_us="<<retryBudgetEnd.time_since_epoch().count()<<L'\n';
        // Only extend the pre-send wait. The next loop polls USB/control and
        // re-evaluates the current peer/Sync/center before granting permission.
        }
        if(browseUntil)return WAIT_TIMEOUT; // No frame was submitted. The browse owns the remaining time.
        std::wcerr<<L"mdns_multicast_window_unavailable=1\n";return 4;
    }
    std::optional<std::pair<Time,Time>> data_submit_bounds()const{return data_submit_bounds_;}
    std::optional<unsigned> preferred_data_channel(const awdlwin::wire::MacAddress& target,bool receiving,bool* wide44=nullptr)const {
        if(failed_||closed_)return std::nullopt;
        return session_->preferred_data_channel(target,awdlwin::discovery::monotonic_now(),receiving,wide44);
    }
    bool target_action_after(const awdlwin::wire::MacAddress& target,Time after)const {
        if(failed_||closed_)return false;
        return session_->target_action_after(target,after,awdlwin::discovery::monotonic_now());
    }
    bool target_peer_present(const awdlwin::wire::MacAddress& target)const {
        return !failed_&&!closed_&&session_->target_peer_present(target,awdlwin::discovery::monotonic_now());
    }
    bool set_fixed_channel(unsigned channel) {
        const auto now=awdlwin::discovery::monotonic_now();
        const bool noDataQuery=!data_query_identity_&&!data_query_submitted_at_&&
            !data_query_out_observed_&&!driver_submission_accepted_&&!data_timing_.has_pending_query();
        const bool completedDataQuery=data_query_identity_&&data_query_submitted_at_&&
            (data_query_out_observed_||driver_submission_accepted_)&&!data_timing_.has_pending_query();
        if(failed_||closed_||!session_||now.time_since_epoch().count()<0||
           tcp_check_||tcp_submitted_at_||tcp_stream_||
           std::any_of(name_streams_.begin(),name_streams_.end(),[](const auto* stream){return stream!=nullptr;})||
           receive_application_||tx_timing_.pending_count()!=0||
           (!noDataQuery&&!completedDataQuery)||!session_->set_fixed_channel(channel,now))return false;
        tx_timing_=TxTiming{};
        data_timing_=DataTiming{};
        data_submit_bounds_.reset();
        data_query_identity_.reset();
        data_query_submitted_at_.reset();
        data_query_out_observed_=false;
        driver_submission_accepted_=false;
        return true;
    }
    bool track_data_query(std::span<const std::uint8_t> mpdu,Time submittedAt) {
        if(failed_||closed_||!data_timing_.register_query(mpdu,submittedAt))return false;
        data_query_identity_=awdlwin::wire::Bytes(mpdu.begin(),mpdu.end());
        if(data_query_identity_->size()<24)return false;
        (*data_query_identity_)[22]=0;(*data_query_identity_)[23]=0;
        data_query_submitted_at_=submittedAt;
        data_query_out_observed_=false;
        driver_submission_accepted_=false;
        return true;
    }
    bool confirm_driver_submission() {
        if(!uses_ndiscap()||failed_||closed_||!data_query_identity_||!data_timing_.has_pending_query())return false;
        data_timing_.cancel_query();
        driver_submission_accepted_=true;
        return true;
    }
    void cancel_data_query(){
        data_timing_.cancel_query();data_query_identity_.reset();data_query_submitted_at_.reset();
        data_query_out_observed_=false;driver_submission_accepted_=false;
    }
    bool await_data_query_out_fence(DWORD timeoutMs=1000) {
        if(failed_||closed_||!data_query_identity_)return false;
        if(uses_ndiscap())return driver_submission_accepted_;
        const auto entered=awdlwin::discovery::monotonic_now();
        const auto deadline=entered+std::chrono::milliseconds{timeoutMs};
        DWORD pollWaitMs=0;
        for(;;) {
            const auto now=awdlwin::discovery::monotonic_now();
            if(data_query_out_observed_) {
                const auto elapsed=now-entered;
                ++data_fences_;
                data_fence_wait_total_+=elapsed;
                data_fence_wait_max_=(std::max)(data_fence_wait_max_,elapsed);
                return true;
            }
            if(now>=deadline)break;
            // Check each completed read for the matching OUT, even if the
            // Windows millisecond tick has not advanced.
            if(!poll(pollWaitMs))return false;
            pollWaitMs=1;
        }
        std::wcerr<<L"mdns_data_out_fence_timeout=1\n";return false;
    }
    // No wait: nullopt is an RX/tracking failure, false is still in flight.
    std::optional<bool> action_out_ready() {
        if(!poll())return std::nullopt;
        if(tx_timing_.pending_count()==0)return true;
        if(tx_timing_.pending_timed_out(awdlwin::discovery::monotonic_now())) {
            std::wcerr<<L"usb_action_out_fence_timeout=1 pending_count="
                <<tx_timing_.pending_count()<<L'\n';
            return std::nullopt;
        }
        return false;
    }
    bool try_response_observation(awdlwin::discovery::MonotonicTime& received)const {
        if(const auto candidate=session_->response_observation(
                awdlwin::discovery::monotonic_now(),last_response_observation_)) {
            received=*candidate;return true;
        }
        return false;
    }
    bool await_action_out_fence(DWORD timeoutMs=1000) {
        if(failed_||closed_)return false;
        const auto deadline=GetTickCount64()+timeoutMs;
        do {
            if(!poll())return false;
            const auto pending=tx_timing_.pending_count();
            if(pending==0)return true;
            if(tx_timing_.pending_timed_out(awdlwin::discovery::monotonic_now()))break;
            if(GetTickCount64()>=deadline)break;
            if(!wait(1))return false;
        }while(GetTickCount64()<deadline);
        std::wcerr<<L"usb_action_out_fence_timeout=1 pending_count="
            <<tx_timing_.pending_count()<<L'\n';return false;
    }
    bool await_response_observation(awdlwin::discovery::MonotonicTime& received,
                                    DWORD timeoutMs=2000) {
        const auto deadline=GetTickCount64()+timeoutMs;
        do {
            if(!poll())return false;
            const auto now=awdlwin::discovery::monotonic_now();
            if(const auto candidate=session_->response_observation(now,last_response_observation_)) {
                received=*candidate;return true;
            }
            if(!wait(1))return false;
        }while(GetTickCount64()<deadline);
        std::wcerr<<L"live_response_context_unavailable=1\n";return false;
    }
    void mark_response_accepted(awdlwin::discovery::MonotonicTime received) {
        last_response_observation_=received;
    }
    bool response_observation_current(awdlwin::discovery::MonotonicTime received)const {
        return response_observation_current(received,awdlwin::discovery::monotonic_now());
    }
    bool response_observation_current(awdlwin::discovery::MonotonicTime received,
        awdlwin::discovery::MonotonicTime at)const {
        if(failed_||closed_)return false;
        const auto candidate=session_->response_observation(at,last_response_observation_);
        return candidate&&*candidate==received;
    }
    std::optional<awdlwin::discovery::MonotonicTime> predicted_action_out(
        awdlwin::discovery::MonotonicTime generatedAt)const {
        const auto delay=tx_timing_.prediction(generatedAt);
        const auto ticks=generatedAt.time_since_epoch().count();
        if(!delay||delay->count()<0||ticks<0||
           ticks>(std::numeric_limits<std::int64_t>::max)()-delay->count())return std::nullopt;
        return generatedAt+*delay;
    }
    std::optional<Session::PeerChannelWindowDecision> peer_action_channel_window(
        awdlwin::discovery::MonotonicTime observedAt,
        awdlwin::discovery::MonotonicTime predictedOut,unsigned channel)const {
        if(!response_observation_current(observedAt))return std::nullopt;
        return session_->peer_action_channel_window(predictedOut,channel);
    }
    std::optional<Session::PeerChannelWindowDecision> peer_action_channel_window(
        awdlwin::discovery::MonotonicTime predictedOut,unsigned channel)const {
        if(failed_||closed_)return std::nullopt;
        return session_->peer_action_channel_window(predictedOut,channel);
    }
    bool register_browse_query(const awdlwin::mdns::BrowseQuery& query,
                               std::optional<Time> deadline=std::nullopt) {
        return !failed_&&session_->register_browse_query(query,awdlwin::discovery::monotonic_now(),deadline);
    }
    void clear_browse_query(){session_->clear_browse_query();}
    void clear_discovered_services(){session_->clear_discovered_services();}
    bool browse_window_open()const{return session_->browse_window_open(awdlwin::discovery::monotonic_now());}
    awdlwin::mdns::Snapshot airdrop_services()const {
        return session_->airdrop_services(awdlwin::discovery::monotonic_now());
    }
    std::string peer_name(const awdlwin::wire::MacAddress& target)const { return session_->peer_name(target); }
    awdlwin::mdns::Snapshot browse_services()const {
        return session_->browse_services(awdlwin::discovery::monotonic_now());
    }
    bool begin_tcp_connect(const awdlwin::wire::MacAddress& self,const awdlwin::mdns::Endpoint& endpoint,
                           std::uint16_t port,std::uint32_t isn) {
        const auto now=awdlwin::discovery::monotonic_now();
        if(failed_||closed_||tcp_check_||tcp_stream_||
           std::any_of(name_streams_.begin(),name_streams_.end(),[](const auto* stream){return stream!=nullptr;})||
           now.time_since_epoch().count()<0||
           endpoint.expires_at_us<=static_cast<std::uint64_t>(now.time_since_epoch().count())||
           !session_->target_peer_current(endpoint.peer,now))return false;
        tcp_check_.emplace(self,endpoint,port,isn);tcp_submitted_at_.reset();
        if(!tcp_check_->valid()){tcp_check_.reset();return false;}
        session_->clear_data_retry_history();return true;
    }
    void mark_tcp_submitted(Time at){if(!tcp_submitted_at_)tcp_submitted_at_=at;}
    const std::optional<tx10ub::tcp::ConnectCheck>& tcp_connect()const{return tcp_check_;}
    bool tcp_peer_current()const {
        const auto now=awdlwin::discovery::monotonic_now().time_since_epoch().count();
        return !failed_&&!closed_&&tcp_check_&&now>=0&&
            tcp_check_->endpoint().expires_at_us>static_cast<std::uint64_t>(now)&&
            session_->target_peer_current(tcp_check_->endpoint().peer,
                awdlwin::discovery::MonotonicTime{std::chrono::microseconds{now}});
    }
    void clear_tcp_connect(){tcp_check_.reset();tcp_submitted_at_.reset();cancel_data_query();}
    bool begin_tcp_stream(const awdlwin::wire::MacAddress& self,const awdlwin::mdns::Endpoint& endpoint,
                          std::uint16_t port) {
        const auto now=awdlwin::discovery::monotonic_now();
        if(failed_||closed_||tcp_check_||tcp_stream_||
           std::any_of(name_streams_.begin(),name_streams_.end(),[](const auto* stream){return stream!=nullptr;})||
           !session_->target_peer_present(endpoint.peer,now)||
           endpoint.expires_at_us<=static_cast<std::uint64_t>(now.time_since_epoch().count()))return false;
        tcp_stream_=std::make_unique<tx10ub::tcp::Stream>(self,endpoint,port,
            static_cast<std::uint64_t>(now.time_since_epoch().count()));
        session_->clear_data_retry_history();
        if(!tcp_stream_->healthy())return false;
        // The sender also needs prompt delivery of the peer's TCP ACKs.
        set_receive_tcp_active(true);
        return true;
    }
    tx10ub::tcp::Stream* tcp_stream(){return tcp_stream_.get();}
    bool tcp_stream_peer_current()const {
        // A master election can temporarily lack fresh Sync while this peer
        // is still present. Every DATA send separately requires a valid window.
        return !failed_&&!closed_&&tcp_stream_&&session_->target_peer_present(
            tcp_stream_->endpoint().peer,awdlwin::discovery::monotonic_now());
    }
    void clear_tcp_stream(){
        tcp_stream_.reset();
        set_receive_tcp_active(false);
        cancel_data_query();
    }
    bool attach_name_stream(tx10ub::tcp::Stream& stream) {
        if(failed_||closed_||tcp_stream_||tcp_check_)return false;
        if(std::find(name_streams_.begin(),name_streams_.end(),&stream)!=name_streams_.end())return false;
        for (auto*& slot : name_streams_) {
            if (slot) continue;
            session_->clear_data_retry_history();
            slot = &stream;
            // SYN-ACK and TLS replies for /Discover need the same delivery
            // cadence as transfer TCP while the name lookup is running.
            set_receive_tcp_active(true);
            return true;
        }
        return false;
    }
    void observe_receive_discovery(std::function<void(const Session::Datagram&,bool)> observer) {
        discovery_observer_=std::move(observer);
    }
    void receive_application(std::function<void(const awdlwin::wire::MacAddress&,std::span<const std::uint8_t>)> callback) {
        session_->clear_data_retry_history();
        if(!callback)set_receive_tcp_active(false);
        receive_application_=std::move(callback);
    }
    void set_receive_tcp_active(bool active) {
        if(ndis_reader_)ndis_reader_->set_tcp_activity(active?ndiscap::TcpActivity::active:ndiscap::TcpActivity::idle);
    }
    void begin_upload_ack_delivery() {
        if(ndis_reader_)ndis_reader_->set_tcp_activity(ndiscap::TcpActivity::uploading);
    }
    void detach_name_stream(tx10ub::tcp::Stream& stream) {
        const auto entry = std::find(name_streams_.begin(), name_streams_.end(), &stream);
        if (entry == name_streams_.end()) return;
        *entry = nullptr;
        if (std::none_of(name_streams_.begin(), name_streams_.end(), [](const auto* slot) { return slot != nullptr; }))
            set_receive_tcp_active(false);
    }
    bool name_peer_current(const awdlwin::mdns::Endpoint& endpoint)const {
        const auto now=awdlwin::discovery::monotonic_now();
        return !failed_&&!closed_&&now.time_since_epoch().count()>=0&&
            endpoint.expires_at_us>static_cast<std::uint64_t>(now.time_since_epoch().count())&&
            session_->target_peer_present(endpoint.peer,now);
    }
    bool name_send_ready(const awdlwin::mdns::Endpoint& endpoint,unsigned channel,bool fixed44=false)const {
        const auto now=awdlwin::discovery::monotonic_now();
        if(!name_peer_current(endpoint)||tx_timing_.pending_count()!=0)return false;
        const auto delay=data_timing_.prediction(now).value_or(std::chrono::microseconds{0});
        return session_->peer_unicast_window(now,channel,delay,&endpoint.peer,fixed44).has_value();
    }
    bool name_peer_on_channel(const awdlwin::mdns::Endpoint& endpoint,unsigned channel)const {
        const auto now=awdlwin::discovery::monotonic_now();
        const auto delay=data_timing_.prediction(now).value_or(std::chrono::microseconds{0});
        return name_peer_current(endpoint)&&session_->target_channel_window(endpoint.peer,now+delay,channel).has_value();
    }
    bool track_action(const awdlwin::wire::MacAddress& source,std::span<const std::uint8_t> body,
                      awdlwin::discovery::MonotonicTime generatedAt,
                      std::optional<awdlwin::discovery::MonotonicTime> predictedUsbAt) {
        if(failed_||closed_)return false;
        std::optional<std::chrono::microseconds> delay;
        if(predictedUsbAt)delay=*predictedUsbAt-generatedAt;
        return tx_timing_.register_action(source,body,generatedAt,delay);
    }
    void cancel_action(const awdlwin::wire::MacAddress& source,std::span<const std::uint8_t> body) {
        tx_timing_.cancel(source,body);
    }
    bool generate(awdlwin::wire::ActionSubtype subtype,awdlwin::discovery::MonotonicTime& now,
                  awdlwin::wire::Bytes& output,bool predictSync=false,
                  std::optional<awdlwin::discovery::MonotonicTime>* predictedUsbAt=nullptr,
                  bool waitForSync=true,bool* deferred=nullptr) {
        if(deferred)*deferred=false;
        if(failed_)return false;
        std::optional<awdlwin::discovery::MonotonicTime> target;
        const auto produce=[&]() {
            target.reset();
            if(predictSync)target=predicted_action_out(now);
            // Project only the pure transmit snapshot. RX anchor, election
            // evidence and the inbound event timeline stay unchanged.
            return session_->generate(subtype,target.value_or(now));
        };
        auto generated=produce();
        // At most the declared 250ms receive-age window separates fresh-Sync
        // expiry from safe peer expiry. Poll through that gap without TX or
        // relabeling queued events; the existing core performs self fallback.
        const auto deadline=awdlwin::discovery::monotonic_now()+std::chrono::milliseconds{500};
        bool waited=false;
        while(const auto* failure=std::get_if<awdlwin::discovery::SessionFailure>(&generated)) {
            if(!waitForSync&&failure->error==awdlwin::discovery::SessionError::awaiting_fresh_sync) {
                if(deferred)*deferred=true;
                return false;
            }
            if(failure->error!=awdlwin::discovery::SessionError::awaiting_fresh_sync||
               awdlwin::discovery::monotonic_now()>=deadline)break;
            if(!wait(10))return false;
            now=awdlwin::discovery::monotonic_now();
            generated=produce();
            waited=true;
        }
        if(const auto* failure=std::get_if<awdlwin::discovery::SessionFailure>(&generated)) {
            std::wcerr<<(uses_ndiscap()?L"ndiscap_session_generation_error=":L"usb_session_generation_error=")<<unsigned(failure->error)<<L'\n';return false;
        }
        output=std::move(std::get<awdlwin::wire::Bytes>(generated));
        if(predictedUsbAt)*predictedUsbAt=target;
        if(waited)std::wcout<<(uses_ndiscap()?L"ndiscap_freshness_wait_finished=1\n":L"usb_freshness_wait_finished=1\n");
        return true;
    }
    bool stopped()const noexcept {return closed_&&(uses_ndiscap()?ndis_stopped_:reader_.stop_succeeded());}
    bool close()noexcept {
        if(closed_)return !failed_;
        closed_=true;
        if(uses_ndiscap()) {
            if(!ndis_reader_->healthy())failed_=true;
            ndis_stopped_=ndis_reader_->close();
            if(!ndis_stopped_||ndis_reader_->error_code()!=ERROR_SUCCESS)failed_=true;
            const auto timing=ndis_reader_->receive_timing();
            const auto& delivery=timing.dataDelivery;
            std::wcout<<L"ndiscap_receive_stopped="<<ndis_stopped_<<L" ndiscap_actions_accepted="<<accepted_
                <<L" ndiscap_sync_applied="<<sync_applied_<<L" ndiscap_stale_events="<<stale_events_
                <<L" ndiscap_out_of_order="<<ndis_reader_->out_of_order_count()
                <<L" ndiscap_flushes="<<ndis_reader_->flush_count()<<L'\n';
            if(delivery.samples)
                std::wcout<<L"ndiscap_tcp_data_delivery samples="<<delivery.samples
                    <<L" mean_us="<<delivery.totalUs/delivery.samples
                    <<L" max_us="<<delivery.maxUs<<L'\n';
            if(timing.flush.samples)
                std::wcout<<L"ndiscap_tcp_flush samples="<<timing.flush.samples
                    <<L" total_us="<<timing.flush.totalUs<<L" max_us="<<timing.flush.maxUs<<L'\n';
            std::wcout<<L"ndiscap_name_syn_ack decoded="<<name_syn_acks_decoded_
                <<L" delivered_to_tcp="<<name_syn_acks_delivered_<<L'\n';
            log_unicast_window_totals();
            return !failed_;
        }
        const auto tail=reader_.stop();
        if(reader_.stop_succeeded()&&!failed_)feed(tail);
        if(!reader_.stop_succeeded()||!reader_.healthy()||!decoder_.complete())failed_=true;
        if(trace_!=INVALID_HANDLE_VALUE) {
            const bool traceClosed=CloseHandle(trace_)!=FALSE;
            trace_=INVALID_HANDLE_VALUE;
            if(!traceClosed)failed_=true;
            std::wcout<<L"usb_trace_bytes="<<trace_bytes_<<L" usb_trace_closed="<<traceClosed<<L'\n';
        }
        std::wcout<<L"usb_receive_stopped="<<reader_.stop_succeeded()<<L" usb_session_accepted="<<accepted_
            <<L" usb_session_rejected="<<rejected_<<L" usb_sync_applied="<<sync_applied_
            <<L" usb_stale_events_skipped="<<stale_events_
            <<L" usb_awdl="<<decoder_.counts.awdl<<L" usb_decode_rejected="<<decoder_.counts.rejected
            <<L" usb_codec_rejected="<<decoder_.counts.codec_rejected
            <<L" usb_awdl_candidates="<<decoder_.counts.awdl_candidates
            <<L" usb_fcs_rejected="<<decoder_.counts.fcs_rejected
            <<L" usb_parse_rejected="<<decoder_.counts.parse_rejected
            <<L" usb_roundtrip_rejected="<<decoder_.counts.roundtrip_rejected
            <<L" usb_data_frames="<<decoder_.counts.data_frames<<L" usb_data_msdus="<<decoder_.counts.data_msdus
            <<L" usb_data_fcs_rejected="<<decoder_.counts.data_fcs_rejected
            <<L" usb_data_parse_rejected="<<decoder_.counts.data_parse_rejected<<L'\n';
        std::wcout<<L"usb_data_retries_suppressed="<<duplicate_data_frames_<<L'\n';
        log_unicast_window_totals();
        if(data_fences_) {
            std::wcout<<L"usb_data_out_fence_totals confirmed="<<data_fences_
                <<L" wait_total_us="<<data_fence_wait_total_.count()
                <<L" wait_max_us="<<data_fence_wait_max_.count()<<L'\n';
        }
        return !failed_;
    }
};
}
