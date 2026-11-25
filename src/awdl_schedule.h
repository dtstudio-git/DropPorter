#pragma once

#include "awdl_availability.h"

#include <array>
#include <cstdint>

namespace awdlwin::discovery {

// A caller-supplied peer channel schedule and its phase relative to the local
// monotonic clock. The offset is never inferred from a discovery packet.
struct PeerSchedule {
    std::array<OpClassChannel, 16> channel_sequence;
    std::int64_t sync_offset_us;
};

enum class ScheduleReason {
    eligible,
    null_channel,
    channel_mismatch,
    start_guard,
    end_guard,
    not_multicast_slot
};

struct ScheduleDecision {
    AvailabilityWindow position;
    ScheduleReason reason;
    // OWL's signed guard/retry expression in microseconds. This is a relative
    // schedule result, not an absolute deadline or radio admission decision.
    std::int64_t guard_delay_us;
};

// Pure offline data-schedule decision using OWL da255a70...schedule.c guard
// and channel-continuity rules. eligible describes this modeled schedule only;
// it does not establish Discovery Action timing, WDI/M4 admission, or hardware
// capability. The supported OWL profile is period 16 TU and presence 4.
wire::CodecResult<ScheduleDecision> inspect_owl_unicast_schedule(
    const TransmitSync& sync, const std::array<OpClassChannel, 16>& local,
    const PeerSchedule& peer, MonotonicTime now);

// Pure multicast data-schedule decision. OWL multicast slots are EAW slots 0
// and 10; a NULL channel is ineligible even when its guard delay is zero.
wire::CodecResult<ScheduleDecision> inspect_owl_multicast_schedule(
    const TransmitSync& sync, const std::array<OpClassChannel, 16>& local,
    MonotonicTime now);

} // namespace awdlwin::discovery
