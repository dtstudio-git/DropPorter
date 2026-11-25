#include "awdl_discovery_session.h"

#include <tuple>
#include <type_traits>
#include <algorithm>

namespace awdlwin::discovery {
namespace {
bool same_election(const TransmitElection& a, const TransmitElection& b) noexcept {
    return std::tie(a.master_address, a.sync_address, a.height, a.master_metric,
                    a.self_metric, a.master_counter, a.self_counter) ==
           std::tie(b.master_address, b.sync_address, b.height, b.master_metric,
                    b.self_metric, b.master_counter, b.self_counter);
}
std::uint64_t count_us(MonotonicTime time) noexcept {
    return static_cast<std::uint64_t>(time.time_since_epoch().count());
}
wire::CodecResult<std::array<OpClassChannel, 16>> paired_channels(
    const wire::ChannelSequence& standalone, const wire::ChannelSequence& embedded,
    const TransmitSync& sync, MonotonicTime now) {
    auto profile = [](const wire::ChannelSequence& c) {
        return c.encoding == 3 && c.count == 16 && c.duplicate_count == 0 &&
               c.step_count == 3 && c.fill_channel == 0xffff && c.entries.size() == 32;
    };
    if (!profile(standalone) || !profile(embedded) || standalone.entries != embedded.entries)
        return wire::CodecResult<std::array<OpClassChannel, 16>>::failure(wire::CodecError::malformed_tlv);
    std::array<OpClassChannel, 16> channels;
    for (std::size_t i = 0; i < channels.size(); ++i)
        channels[i] = {standalone.entries[i * 2], standalone.entries[i * 2 + 1]};
    const auto valid = inspect_owl_availability(sync, channels, now);
    if (!valid) return wire::CodecResult<std::array<OpClassChannel, 16>>::failure(valid.error(), valid.offset());
    return wire::CodecResult<std::array<OpClassChannel, 16>>::success(channels);
}
} // namespace

bool sync_address_matches_election(const wire::MacAddress& sync_address,
                                   const wire::MacAddress& elected_root,
                                   const wire::ActionBody& frame) {
    if (sync_address == elected_root) return true;
    const auto tlv = std::find_if(frame.tlvs.begin(), frame.tlvs.end(),
        [](const wire::Tlv& t) { return t.type == 24; });
    if (tlv == frame.tlvs.end()) return false;
    const auto election = wire::decode_election_v2(*tlv);
    return election && election.value().distance_to_master != 0 &&
           election.value().master_address == elected_root &&
           election.value().sync_address == sync_address;
}

DiscoverySession::DiscoverySession(TransmitState initial, MonotonicTime started_at,
                                   std::uint64_t timeout_us, ChannelPolicy channel_policy)
    : state_(std::move(initial)), last_event_at_(started_at), timeout_us_(timeout_us),
      channel_policy_(channel_policy) {}

wire::CodecResult<DiscoverySession> DiscoverySession::create(
    TransmitState initial, MonotonicTime started_at, std::uint64_t timeout_us,
    ChannelPolicy channel_policy) {
    // Reuse the authoritative state/profile validator, not a second layout check.
    const auto validated = generate_owl_discovery(initial, wire::ActionSubtype::psf, started_at);
    if (!validated || timeout_us == 0 || initial.election.height != 0 ||
        (channel_policy != ChannelPolicy::fixed_local && channel_policy != ChannelPolicy::follow_sync_source))
        return wire::CodecResult<DiscoverySession>::failure(wire::CodecError::malformed_tlv);
    return wire::CodecResult<DiscoverySession>::success(
        DiscoverySession(std::move(initial), started_at, timeout_us, channel_policy));
}

bool DiscoverySession::time_valid(MonotonicTime now) const noexcept {
    return now.time_since_epoch().count() >= 0 && now >= last_event_at_;
}

bool DiscoverySession::set_fixed_channel(OpClassChannel channel, MonotonicTime now) {
    if (channel_policy_ != ChannelPolicy::fixed_local || !time_valid(now) ||
        !((channel.channel == 6 && channel.opclass == 0x51) ||
          (channel.channel == 44 && channel.opclass == 0x80)))
        return false;
    state_.current_channel = channel;
    state_.channel_sequence.fill(channel);
    return true;
}

SessionResult DiscoverySession::ingest_logged_wdi(const receive::LoggedWdiInput& input,
                                                 std::uint16_t expected_port,
                                                 MonotonicTime received_at) {
    if (!time_valid(received_at)) return SessionFailure{SessionError::invalid_time};
    auto candidate = peers_;
    const auto expired = candidate.expire(count_us(received_at), timeout_us_);
    auto received = receive::ingest_logged_wdi(candidate, input, expected_port, received_at);
    if (const auto* failure = std::get_if<receive::ReceiveFailure>(&received))
        return SessionFailure{SessionError::receive_rejected, *failure};
    return finish(std::move(candidate), &std::get<receive::ReceivedAction>(received), expired, received_at);
}

SessionResult DiscoverySession::ingest_mpdu(std::span<const std::uint8_t> mpdu,
                                          bool has_fcs, MonotonicTime received_at) {
    if (!time_valid(received_at)) return SessionFailure{SessionError::invalid_time};
    auto candidate = peers_;
    const auto expired = candidate.expire(count_us(received_at), timeout_us_);
    auto received = receive::ingest_mpdu(candidate, mpdu, has_fcs, received_at);
    if (const auto* failure = std::get_if<receive::ReceiveFailure>(&received))
        return SessionFailure{SessionError::receive_rejected, *failure};
    return finish(std::move(candidate), &std::get<receive::ReceivedAction>(received), expired, received_at);
}

SessionResult DiscoverySession::advance(MonotonicTime now) {
    if (!time_valid(now)) return SessionFailure{SessionError::invalid_time};
    auto candidate = peers_;
    const auto expired = candidate.expire(count_us(now), timeout_us_);
    return finish(std::move(candidate), nullptr, expired, now);
}

SessionResult DiscoverySession::finish(peer_state::PeerTable candidate,
                                      const receive::ReceivedAction* frame,
                                      std::size_t expired, MonotonicTime now) {
    // OWL rx.c ignores frames from self. Staging keeps this rejection atomic.
    if (frame && frame->source == state_.self_address)
        return SessionFailure{SessionError::self_source};
    const auto elected = choose_owl_election(state_, candidate);
    if (!elected) return SessionFailure{SessionError::election_failed,
                                       wire::CodecFailure{elected.error(), elected.offset()}};
    const auto& selection = elected.value();
    const bool changed = !same_election(state_.election, selection);
    auto last_sync = last_sync_at_;
    if (changed || (last_sync && count_us(now) - count_us(*last_sync) >= timeout_us_))
        last_sync.reset();
    // Election changes, including return to self, retain the current EAW phase.
    // OWL election.c resets roles/metrics without reinitializing sync.c's clock.
    auto sync = state_.sync;
    auto channels = state_.channel_sequence;
    auto master_channel = state_.master_channel;
    auto peer_schedule = sync_source_schedule_;
    auto last_channels = last_channels_at_;
    if (changed || (last_channels && count_us(now) - count_us(*last_channels) >= timeout_us_)) {
        peer_schedule.reset();
        last_channels.reset();
    }
    bool adopted = false;
    SyncOutcome outcome = NoSyncReason::no_frame;
    if (frame) {
        outcome = NoSyncReason::not_selected;
        if (selection.height != 0 && selection.sync_address == frame->source) {
            outcome = NoSyncReason::missing_tlv;
            if (!frame->fresh_sync && std::any_of(frame->body.tlvs.begin(), frame->body.tlvs.end(),
                    [](const wire::Tlv& t) { return t.type == 18; })) {
                // A channel-only refresh is not proof that the new sequence
                // uses our retained phase. Wait for a fresh paired frame.
                peer_schedule.reset();
                last_channels.reset();
            }
            if (frame->fresh_sync) {
                // Fresh timing must agree with the selected election.
                const auto& fresh = *frame->fresh_sync;
                if (!sync_address_matches_election(fresh.master_address, selection.master_address,
                                                   frame->body)) {
                    return SessionFailure{SessionError::sync_rejected,
                                          wire::CodecFailure{wire::CodecError::malformed_tlv, 0}};
                } else {
                    const auto updated = update_owl_sync(sync, selection.sync_address,
                                                         frame->source, fresh, now);
                    if (updated) {
                        sync = updated.value();
                        last_sync = now;
                        outcome = AppliedSync{};
                        // Never splice a newly adopted phase together with an
                        // older peer's channel advertisement. TLV 18 and Sync's
                        // embedded sequence must agree in this same frame.
                        peer_schedule.reset();
                        last_channels.reset();
                        const auto tlv = std::find_if(frame->body.tlvs.begin(), frame->body.tlvs.end(),
                            [](const wire::Tlv& t) { return t.type == 18; });
                        if (tlv != frame->body.tlvs.end()) {
                            const auto decoded = wire::decode_channel_sequence(*tlv);
                            if (!decoded) return SessionFailure{SessionError::channel_rejected,
                                wire::CodecFailure{decoded.error(), decoded.offset()}};
                            const auto paired = paired_channels(decoded.value(), fresh.channels, sync, now);
                            const bool master_supported = fresh.master_channel == 6 ||
                                fresh.master_channel == 44 || fresh.master_channel == 149;
                            if ((!paired || !master_supported) && channel_policy_ == ChannelPolicy::follow_sync_source)
                                return SessionFailure{SessionError::channel_rejected,
                                    wire::CodecFailure{wire::CodecError::malformed_tlv, 0}};
                            if (paired && master_supported) {
                                // This zero offset belongs only to this selected
                                // source/phase pair; it is not a peer default.
                                peer_schedule = PeerSchedule{paired.value(), 0};
                                last_channels = now;
                                if (channel_policy_ == ChannelPolicy::follow_sync_source) {
                                    channels = paired.value();
                                    master_channel = {fresh.master_channel,
                                        static_cast<std::uint8_t>(fresh.master_channel == 6 ? 0x51 : 0x80)};
                                    adopted = true;
                                }
                            }
                        }
                    } else {
                        // Discard staged metadata, expiry, election and timing
                        // together. An invalid frame cannot refresh a peer or
                        // invalidate the original session's valid Sync evidence.
                        return SessionFailure{SessionError::sync_rejected,
                                              wire::CodecFailure{updated.error(), updated.offset()}};
                    }
                }
            }
        }
    }
    SessionUpdate update{frame ? std::optional{frame->source} : std::nullopt,
                         expired, changed, outcome, adopted};
    // No allocation/throwing work after the first commit write.
    static_assert(std::is_nothrow_move_assignable_v<peer_state::PeerTable>);
    static_assert(std::is_nothrow_move_constructible_v<SessionUpdate>);
    static_assert(std::is_nothrow_copy_assignable_v<std::optional<PeerSchedule>>);
    peers_ = std::move(candidate);
    state_.election = selection;
    state_.sync = sync;
    state_.channel_sequence = channels;
    state_.master_channel = master_channel;
    sync_source_schedule_ = peer_schedule;
    last_channels_at_ = last_channels;
    last_sync_at_ = last_sync;
    last_event_at_ = now;
    return update;
}

std::optional<SessionFailure> DiscoverySession::snapshot_failure(MonotonicTime now) const {
    if (!time_valid(now)) return SessionFailure{SessionError::invalid_time};
    if (state_.election.height != 0) {
        const auto* selected = peers_.find(state_.election.sync_address);
        if (!last_sync_at_ || !selected ||
            count_us(now) - count_us(*last_sync_at_) >= timeout_us_ ||
            count_us(now) - selected->last_seen_us >= timeout_us_)
            return SessionFailure{SessionError::awaiting_fresh_sync};
        if (channel_policy_ == ChannelPolicy::follow_sync_source &&
            (!last_channels_at_ || !sync_source_schedule_ ||
             count_us(now) - count_us(*last_channels_at_) >= timeout_us_))
            return SessionFailure{SessionError::awaiting_fresh_channels};
    }
    return std::nullopt;
}

SessionFrameResult DiscoverySession::generate(wire::ActionSubtype subtype, MonotonicTime now) const {
    if (const auto failure = snapshot_failure(now)) return *failure;
    auto generated = generate_owl_discovery(state_, subtype, now);
    if (!generated) return SessionFailure{SessionError::frame_generation_failed,
                                         wire::CodecFailure{generated.error(), generated.offset()}};
    return std::move(generated.value());
}

SessionAvailabilityResult DiscoverySession::availability(MonotonicTime now) const {
    if (const auto failure = snapshot_failure(now)) return *failure;
    const auto position = inspect_owl_availability(state_.sync, state_.channel_sequence, now);
    if (!position) return SessionFailure{SessionError::availability_failed,
                                        wire::CodecFailure{position.error(), position.offset()}};
    return position.value();
}

SessionScheduleResult DiscoverySession::unicast_schedule(MonotonicTime now) const {
    if (const auto failure = snapshot_failure(now)) return *failure;
    if (state_.election.height == 0 || !last_channels_at_ || !sync_source_schedule_ ||
        count_us(now) - count_us(*last_channels_at_) >= timeout_us_)
        return SessionFailure{SessionError::awaiting_fresh_channels};
    const auto decision = inspect_owl_unicast_schedule(state_.sync, state_.channel_sequence,
                                                      *sync_source_schedule_, now);
    if (!decision) return SessionFailure{SessionError::schedule_failed,
                                         wire::CodecFailure{decision.error(), decision.offset()}};
    return decision.value();
}

SessionScheduleResult DiscoverySession::multicast_schedule(MonotonicTime now) const {
    if (const auto failure = snapshot_failure(now)) return *failure;
    const auto decision = inspect_owl_multicast_schedule(state_.sync, state_.channel_sequence, now);
    if (!decision) return SessionFailure{SessionError::schedule_failed,
                                         wire::CodecFailure{decision.error(), decision.offset()}};
    return decision.value();
}

} // namespace awdlwin::discovery
