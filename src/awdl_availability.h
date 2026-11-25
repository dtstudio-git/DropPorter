#pragma once

#include "awdl_discovery_state.h"

namespace awdlwin::discovery {

// Offline position in the caller's local schedule; no timer or radio decision.
// OWL da255a70... sync.c and daemon/core.c::awdl_switch_channel.
struct AvailabilityWindow {
    std::uint16_t aw_counter;  // Wrapped 16-bit AW counter.
    std::uint16_t eaw_counter; // Wrapped AW counter / presence mode.
    std::uint8_t sequence_slot; // EAW counter % 16, NOT AW counter % 16.
    OpClassChannel sequence_channel; // {0,0} means a NULL slot, not channel 0 tuning.
    std::uint32_t elapsed_in_eaw_us;
    std::uint32_t remaining_aw_us;
    std::uint32_t remaining_eaw_us; // Exact microseconds, unlike wire TU rounding.
    std::uint16_t tx_down_counter_tu; // OWL's floor(elapsed_us / 1024) wire calculation.
};

// Pure inspection of explicit same-clock inputs. Current OPCLASS profile only:
// presence 4, EAW base aligned, 16 entries of 6/0x51, 44/0x80, 149/0x80 or NULL.
// At an exact boundary, remaining time is a full NEW window (never zero).
// Returns durations rather than absolute deadlines, avoiding time_point overflow.
// The sequence is local, not copied from a peer. No adoption, guard interval,
// TX admission, channel availability/regulatory check or hardware state implied.
wire::CodecResult<AvailabilityWindow> inspect_owl_availability(
    const TransmitSync& sync, const std::array<OpClassChannel, 16>& sequence,
    MonotonicTime now);

} // namespace awdlwin::discovery
