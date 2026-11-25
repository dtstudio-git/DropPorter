#include "awdl_availability.h"

#include <algorithm>

namespace awdlwin::discovery {

wire::CodecResult<AvailabilityWindow> inspect_owl_availability(
    const TransmitSync& sync, const std::array<OpClassChannel, 16>& sequence,
    MonotonicTime now) {
    const auto eaw_tu = static_cast<std::uint32_t>(sync.aw_period_tu) * sync.presence_mode;
    const bool channels_valid = std::all_of(sequence.begin(), sequence.end(), [](OpClassChannel c) {
        return (c.channel == 0 && c.opclass == 0) || (c.channel == 6 && c.opclass == 0x51) ||
               ((c.channel == 44 || c.channel == 149) && c.opclass == 0x80);
    });
    if (sync.presence_mode != 4 || sync.aw_period_tu == 0 || eaw_tu > 0xffff ||
        sync.aw_counter % 4 != 0 || sync.anchor.time_since_epoch().count() < 0 ||
        now.time_since_epoch().count() < 0 || now < sync.anchor || !channels_valid)
        return wire::CodecResult<AvailabilityWindow>::failure(wire::CodecError::malformed_tlv);

    const auto elapsed_us = static_cast<std::uint64_t>((now - sync.anchor).count());
    const auto elapsed_tu = elapsed_us / 1024;
    const auto aw_us = static_cast<std::uint32_t>(sync.aw_period_tu) * 1024;
    const auto eaw_us = eaw_tu * 1024;
    // Equivalent to sync.c's within-EAW + completed-EAW terms; wrap happens
    // before current_eaw divides, as in OWL. 65536 AWs is a multiple of 16 EAWs.
    const auto aw = static_cast<std::uint16_t>(sync.aw_counter + elapsed_tu / sync.aw_period_tu);
    const auto eaw = static_cast<std::uint16_t>(aw / sync.presence_mode);
    const auto slot = static_cast<std::uint8_t>(eaw % sequence.size());
    return wire::CodecResult<AvailabilityWindow>::success(AvailabilityWindow{
        aw, eaw, slot, sequence[slot],
        static_cast<std::uint32_t>(elapsed_us % eaw_us),
        static_cast<std::uint32_t>(aw_us - elapsed_us % aw_us),
        static_cast<std::uint32_t>(eaw_us - elapsed_us % eaw_us),
        static_cast<std::uint16_t>(eaw_tu - elapsed_tu % eaw_tu)});
}

} // namespace awdlwin::discovery
