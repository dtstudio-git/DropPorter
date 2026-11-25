#include "awdl_schedule.h"

#include <limits>

namespace awdlwin::discovery {
namespace {

constexpr std::uint16_t supported_aw_period_tu = 16;
constexpr std::uint8_t supported_presence_mode = 4;
constexpr std::int64_t microseconds_per_tu = 1024;
constexpr std::int64_t eaw_us = 64 * microseconds_per_tu;
constexpr std::int64_t unicast_guard_us = 3 * microseconds_per_tu;
constexpr std::int64_t multicast_guard_us = 16 * microseconds_per_tu;

bool supported_profile(const TransmitSync& sync) {
    return sync.aw_period_tu == supported_aw_period_tu &&
           sync.presence_mode == supported_presence_mode;
}

bool is_null(OpClassChannel channel) {
    return channel.channel == 0;
}

bool same_nonzero_channel(OpClassChannel left, OpClassChannel right) {
    return !is_null(left) && !is_null(right) && left.channel == right.channel &&
           left.opclass == right.opclass;
}

bool add_offset(MonotonicTime now, std::int64_t offset_us, MonotonicTime& adjusted) {
    const auto now_us = now.time_since_epoch().count();
    const auto min = std::numeric_limits<std::int64_t>::min();
    const auto max = std::numeric_limits<std::int64_t>::max();

    if (offset_us < 0) {
        if (offset_us == min || now_us < -offset_us) return false;
    } else if (now_us > max - offset_us) {
        return false;
    }

    adjusted = MonotonicTime{std::chrono::microseconds{now_us + offset_us}};
    return true;
}

wire::CodecResult<ScheduleDecision> malformed_schedule() {
    return wire::CodecResult<ScheduleDecision>::failure(wire::CodecError::malformed_tlv);
}

std::int64_t owl_guard_delay(const AvailabilityWindow& position, std::int64_t guard_us) {
    const auto remaining = static_cast<std::int64_t>(position.remaining_eaw_us);
    if (remaining < guard_us) return -(guard_us - remaining);

    const auto elapsed = eaw_us - remaining;
    if (elapsed < guard_us) return guard_us - elapsed;
    return 0;
}

bool same_peer_channel(const std::array<OpClassChannel, 16>& local,
                       const AvailabilityWindow& local_position,
                       const std::array<OpClassChannel, 16>& peer,
                       const AvailabilityWindow& peer_position,
                       int adjacent_delta) {
    const auto local_slot = static_cast<int>(local_position.sequence_slot);
    const auto peer_slot = static_cast<int>(peer_position.sequence_slot);
    const auto local_adjacent = (local_slot + adjacent_delta + 16) % 16;
    const auto peer_adjacent = (peer_slot + adjacent_delta + 16) % 16;
    return same_nonzero_channel(local[static_cast<std::size_t>(local_adjacent)],
                                peer[static_cast<std::size_t>(peer_adjacent)]);
}

} // namespace

wire::CodecResult<ScheduleDecision> inspect_owl_unicast_schedule(
    const TransmitSync& sync, const std::array<OpClassChannel, 16>& local,
    const PeerSchedule& peer, MonotonicTime now) {
    if (!supported_profile(sync)) return malformed_schedule();

    const auto local_result = inspect_owl_availability(sync, local, now);
    if (!local_result) return malformed_schedule();

    MonotonicTime peer_now;
    if (!add_offset(now, peer.sync_offset_us, peer_now)) return malformed_schedule();
    const auto peer_result = inspect_owl_availability(sync, peer.channel_sequence, peer_now);
    if (!peer_result) return malformed_schedule();

    const auto& position = local_result.value();
    const auto& peer_position = peer_result.value();
    const auto local_channel = position.sequence_channel;
    const auto peer_channel = peer_position.sequence_channel;

    if (is_null(local_channel) || is_null(peer_channel)) {
        return wire::CodecResult<ScheduleDecision>::success(
            {position, ScheduleReason::null_channel,
             static_cast<std::int64_t>(position.remaining_eaw_us)});
    }
    if (!same_nonzero_channel(local_channel, peer_channel)) {
        return wire::CodecResult<ScheduleDecision>::success(
            {position, ScheduleReason::channel_mismatch,
             static_cast<std::int64_t>(position.remaining_eaw_us)});
    }

    const auto remaining = static_cast<std::int64_t>(position.remaining_eaw_us);
    if (remaining < unicast_guard_us) {
        if (same_peer_channel(local, position, peer.channel_sequence, peer_position, 1)) {
            return wire::CodecResult<ScheduleDecision>::success(
                {position, ScheduleReason::eligible, 0});
        }
        return wire::CodecResult<ScheduleDecision>::success(
            {position, ScheduleReason::end_guard, -(unicast_guard_us - remaining)});
    }

    const auto elapsed = eaw_us - remaining;
    if (elapsed < unicast_guard_us) {
        if (same_peer_channel(local, position, peer.channel_sequence, peer_position, -1)) {
            return wire::CodecResult<ScheduleDecision>::success(
                {position, ScheduleReason::eligible, 0});
        }
        return wire::CodecResult<ScheduleDecision>::success(
            {position, ScheduleReason::start_guard, unicast_guard_us - elapsed});
    }

    return wire::CodecResult<ScheduleDecision>::success(
        {position, ScheduleReason::eligible, 0});
}

wire::CodecResult<ScheduleDecision> inspect_owl_multicast_schedule(
    const TransmitSync& sync, const std::array<OpClassChannel, 16>& local,
    MonotonicTime now) {
    if (!supported_profile(sync)) return malformed_schedule();

    const auto availability = inspect_owl_availability(sync, local, now);
    if (!availability) return malformed_schedule();

    const auto& position = availability.value();
    const auto guard_delay = owl_guard_delay(position, multicast_guard_us);
    if (position.sequence_slot != 0 && position.sequence_slot != 10) {
        return wire::CodecResult<ScheduleDecision>::success(
            {position, ScheduleReason::not_multicast_slot, guard_delay});
    }
    if (is_null(position.sequence_channel)) {
        return wire::CodecResult<ScheduleDecision>::success(
            {position, ScheduleReason::null_channel, guard_delay});
    }
    if (guard_delay < 0) {
        return wire::CodecResult<ScheduleDecision>::success(
            {position, ScheduleReason::end_guard, guard_delay});
    }
    if (guard_delay > 0) {
        return wire::CodecResult<ScheduleDecision>::success(
            {position, ScheduleReason::start_guard, guard_delay});
    }
    return wire::CodecResult<ScheduleDecision>::success(
        {position, ScheduleReason::eligible, 0});
}

} // namespace awdlwin::discovery
