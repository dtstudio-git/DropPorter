#pragma once

#include "awdl_receive.h"
#include "awdl_sync_election.h"
#include "awdl_availability.h"
#include "awdl_schedule.h"

namespace awdlwin::discovery {

enum class SessionError {
    invalid_time, self_source, receive_rejected, election_failed, sync_rejected,
    awaiting_fresh_sync, frame_generation_failed, availability_failed,
    channel_rejected, awaiting_fresh_channels, schedule_failed
};
struct SessionFailure {
    SessionError error;
    std::variant<std::monostate, receive::ReceiveFailure, wire::CodecFailure> detail{};
};
enum class NoSyncReason { no_frame, not_selected, missing_tlv };
struct AppliedSync {};
// Explicit AWDLWin offline policy. Fixed local preserves the existing path;
// following adopts only a validated sequence paired with selected-source Sync.
// This is not an automatic adoption feature claimed for pinned OWL core.c.
enum class ChannelPolicy { fixed_local, follow_sync_source };
// Sync application failure rejects the entire staged frame as SessionFailure.
// A successful transition reports either applied Sync or why none was applied.
using SyncOutcome = std::variant<NoSyncReason, AppliedSync>;
struct SessionUpdate {
    std::optional<wire::MacAddress> source; // Absent for explicit advance().
    std::size_t expired_peers;
    bool election_changed;
    SyncOutcome sync;
    bool channels_adopted{};
};
using SessionResult = std::variant<SessionUpdate, SessionFailure>;
using SessionFrameResult = std::variant<wire::Bytes, SessionFailure>;
using SessionAvailabilityResult = std::variant<AvailabilityWindow, SessionFailure>;
using SessionScheduleResult = std::variant<ScheduleDecision, SessionFailure>;

// The Sync address may identify the elected root (OWL) or the immediate
// parent advertised in the same frame by an Apple peer.
bool sync_address_matches_election(const wire::MacAddress& sync_address,
                                   const wire::MacAddress& elected_root,
                                   const wire::ActionBody& frame);

// Serialized OFFLINE owner, with no clocks, timers, IOCTLs or radio operations.
// Input events and advance() must have nondecreasing same-session steady times.
// Caller verifies log ABI/adapter/sequence and supplies correlated event times.
// ReceiveReplay handles saved V1 logs with an explicit clock correlation;
// ReceiveCapture samples Windows clocks without calibrating their precision;
// ReceiveRuntime connects bounded reads/replay to this owner. UTC/TSFT
// conversion, continuous timers and hardware sync remain pending.
// It stages a bounded PeerTable copy for atomic transitions, not a live RX fast
// path. Allocation exceptions propagate with the original session unchanged.
class DiscoverySession {
public:
    // Start with explicit valid self-master state and a nonzero caller-chosen
    // peer/sync-observation lifetime, in microseconds. No OWL timeout is guessed.
    static wire::CodecResult<DiscoverySession> create(
        TransmitState initial, MonotonicTime started_at, std::uint64_t timeout_us,
        ChannelPolicy channel_policy = ChannelPolicy::fixed_local);
    DiscoverySession(const DiscoverySession&) = delete;
    DiscoverySession& operator=(const DiscoverySession&) = delete;
    DiscoverySession(DiscoverySession&&) = default;
    DiscoverySession& operator=(DiscoverySession&&) = delete;

    SessionResult ingest_logged_wdi(const receive::LoggedWdiInput& input,
                                   std::uint16_t expected_port, MonotonicTime received_at);
    SessionResult ingest_mpdu(std::span<const std::uint8_t> mpdu,
                             bool has_fcs, MonotonicTime received_at);
    // Returning to self-master continues the current schedule's EAW anchor,
    // counter, period and presence mode, including a previously adopted phase.
    // Remote Sync/channel evidence is cleared while the local channel sequence
    // is retained. No anchor=now reset or restoration of the initialization
    // schedule (OWL election.c).
    SessionResult advance(MonotonicTime now);

    // Update the local fixed-channel transmit configuration without advancing
    // the receive-event timeline or touching election/peer/Sync evidence.
    bool set_fixed_channel(OpClassChannel channel, MonotonicTime now);

    // Generates only an offline body. A remote selection requires a currently
    // valid Sync observation for that selected master/source/counter; cached
    // Peer::sync is never reapplied. Self-master continues the retained schedule;
    // this is not a claim of ongoing synchronization to a lost remote master.
    // Inspection is const and does not advance the event timeline or expire peers.
    // Following channels also requires a fresh same-frame phase/sequence pair.
    // This policy is NOT WDI TX admission or radio synchronization.
    SessionFrameResult generate(wire::ActionSubtype subtype, MonotonicTime now) const;
    // Same time/freshness policy as generate(), without allocating a frame.
    // Inspects local channel_sequence (explicitly adopted in follow mode).
    // NULL is not a send opportunity. No state/clock/radio work.
    SessionAvailabilityResult availability(MonotonicTime now) const;
    // Offline DATA schedule decisions, not PSF/MIF scheduling or TX admission.
    // Unicast only to the selected sync source whose fresh paired sequence is
    // aligned by the last accepted Sync; arbitrary-peer offsets are not guessed.
    SessionScheduleResult unicast_schedule(MonotonicTime now) const;
    SessionScheduleResult multicast_schedule(MonotonicTime now) const;
    const TransmitState& state() const noexcept { return state_; }
    const peer_state::PeerTable& peers() const noexcept { return peers_; }
    MonotonicTime last_event_at() const noexcept { return last_event_at_; }
    std::optional<MonotonicTime> last_sync_observation() const noexcept { return last_sync_at_; }
    std::optional<MonotonicTime> last_channel_observation() const noexcept { return last_channels_at_; }

private:
    DiscoverySession(TransmitState initial, MonotonicTime started_at, std::uint64_t timeout_us,
                     ChannelPolicy channel_policy);
    bool time_valid(MonotonicTime now) const noexcept;
    std::optional<SessionFailure> snapshot_failure(MonotonicTime now) const;
    SessionResult finish(peer_state::PeerTable candidate,
                         const receive::ReceivedAction* frame,
                         std::size_t expired, MonotonicTime now);
    TransmitState state_;
    peer_state::PeerTable peers_;
    MonotonicTime last_event_at_;
    std::optional<MonotonicTime> last_sync_at_;
    std::optional<MonotonicTime> last_channels_at_;
    std::optional<PeerSchedule> sync_source_schedule_;
    std::uint64_t timeout_us_;
    ChannelPolicy channel_policy_;
};

} // namespace awdlwin::discovery
