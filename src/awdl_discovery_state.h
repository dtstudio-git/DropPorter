#pragma once

#include "awdl_discovery.h"
#include <chrono>

namespace awdlwin::discovery {

// Explicit offline input, not a radio configuration or an elected/synchronized
// node. The caller owns identity, election and monotonic timing observations.
// Both anchor and generation time MUST originate from this same steady_clock
// epoch in the current process/session. Never relabel UTC, PCAP wall time,
// another device's TSFT, or persisted timestamps as this type. Only offline
// fixtures construct synthetic time_points; runtime initialization/updates use
// monotonic_now() or time_point_cast<microseconds>(steady_clock::now()).
using MonotonicTime = std::chrono::time_point<std::chrono::steady_clock, std::chrono::microseconds>;
static_assert(std::chrono::steady_clock::is_steady);
inline MonotonicTime monotonic_now() {
    return std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::steady_clock::now());
}
struct OpClassChannel { std::uint8_t channel; std::uint8_t opclass; };
struct TransmitSync {
    // Start of an EAW in the same clock domain as generation time. At initial
    // local scheduling, now can define this boundary with counter 0. A later
    // update must supply a corresponding EAW boundary/counter pair, not merely
    // overwrite anchor with receipt time or an arbitrary current AW position.
    MonotonicTime anchor;
    std::uint16_t aw_counter; // EAW base: divisible by presence_mode (4 here).
    std::uint16_t aw_period_tu;
    std::uint8_t presence_mode;
};
struct TransmitElection {
    // Caller initializes/updates an elected snapshot; no election algorithm
    // runs here. Height 0 is self-master: both addresses refer to self and
    // master metric/counter equal self metric/counter. Height >0 must not
    // refer to self as master/sync source. Generator validates these roles;
    // it cannot prove a remote multi-hop tree from a single snapshot.
    wire::MacAddress master_address;
    wire::MacAddress sync_address;
    std::uint32_t height;
    std::uint32_t master_metric;
    std::uint32_t self_metric;
    std::uint32_t master_counter;
    std::uint32_t self_counter;
};
struct TransmitState {
    wire::MacAddress self_address;
    std::string name;
    std::uint8_t version;
    std::uint8_t device_class;
    std::uint16_t psf_interval_tu;
    TransmitSync sync;
    TransmitElection election;
    OpClassChannel current_channel;
    OpClassChannel master_channel;
    std::array<OpClassChannel, 16> channel_sequence; // Exactly 16; never variable-length.
};

// OWL da255a70... tx.c reference profile: OPCLASS, 16 entries, presence 4.
// Its reserved/unknown, service, HT and data-path constants reproduce OWL's
// offline output; they are NOT measured TX10UB capabilities or live defaults.
// One same-clock timestamp drives the header and all timing fields. No state
// mutation, clock reads, scheduler, election, MAC header or WDI submission.
// Invalid/inconsistent input returns malformed_tlv; invalid subtype retains
// unsupported_subtype. Nonnegative microsecond epoch coordinates are required
// by this OWL unsigned-time profile. Unaligned EAW counters are rejected,
// never silently rounded. This builder emits each TLV exactly once.
wire::CodecResult<wire::Bytes> generate_owl_discovery(
    const TransmitState& state, wire::ActionSubtype subtype, MonotonicTime now);

} // namespace awdlwin::discovery
