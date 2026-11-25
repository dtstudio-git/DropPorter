#include "awdl_receive.h"

#include <algorithm>
#include <type_traits>

namespace awdlwin::receive {
namespace {
std::uint16_t read16(std::span<const std::uint8_t> b, std::size_t at) {
    return static_cast<std::uint16_t>(b[at] | (static_cast<unsigned>(b[at + 1]) << 8));
}
std::uint32_t read32(std::span<const std::uint8_t> b, std::size_t at) {
    std::uint32_t n = 0;
    for (unsigned i = 0; i != 4; ++i) n |= static_cast<std::uint32_t>(b[at + i]) << (8 * i);
    return n;
}
bool supported_channel(ChannelObservation c) {
    // Offline receive profile, not an exhaustive WDI/regulatory channel map.
    // SDK wditypes.hpp: WDI_BAND_ID_2400 = 1, WDI_BAND_ID_5000 = 2.
    // 5 GHz is limited to the channels in our OWL transmit state profile.
    return (c.band_id == 1 && c.channel >= 1 && c.channel <= 14) ||
           (c.band_id == 2 && (c.channel == 44 || c.channel == 149));
}
ReceiveFailure bad_action(const wire::CodecFailure& failure) {
    return {ReceiveError::invalid_action, failure.offset, failure.error};
}
ReceiveResult accept(peer_state::PeerTable& peers, ReceivedAction action,
                     std::span<const std::uint8_t> raw_body) {
    for (const auto& tlv : action.body.tlvs) {
        if (tlv.type != 4) continue;
        const auto sync = wire::decode_sync(tlv);
        if (!sync) return bad_action({sync.error(), sync.offset()});
        action.fresh_sync = sync.value();
    }
    // A duplicate singleton or invalid source is rejected by PeerTable before
    // any update, even if raw codec parsing succeeded above.
    const auto result = peers.ingest(action.source, raw_body,
        static_cast<std::uint64_t>(action.received_at.time_since_epoch().count()));
    if (!result) return ReceiveFailure{ReceiveError::peer_rejected, result.offset,
                                     result.codec_error, result.error};
    static_assert(std::is_nothrow_move_constructible_v<ReceivedAction>);
    return action;
}
} // namespace

ReceiveResult ingest_logged_wdi(peer_state::PeerTable& peers, const LoggedWdiInput& input,
                                std::uint16_t expected_port, discovery::MonotonicTime received_at) {
    if (received_at.time_since_epoch().count() < 0)
        return ReceiveFailure{ReceiveError::invalid_time};
    if (input.status_code != wdi_action_frame_received)
        return ReceiveFailure{ReceiveError::wrong_indication};
    const auto b = input.prefix;
    // A valid partial prefix must never become a valid complete Action input.
    if (b.size() > logged_prefix_capacity || b.size() != input.original_length)
        return ReceiveFailure{ReceiveError::incomplete_log};
    if (b.size() < 16) return ReceiveFailure{ReceiveError::malformed_wdi};
    const auto port = read16(b, 0);
    if (expected_port == 0xffff || port != expected_port)
        return ReceiveFailure{ReceiveError::wrong_port};
    // Bytes 2..3 are WDI_MESSAGE_HEADER::Reserved. Microsoft Learn and SDK
    // dot11wdi.h do not prescribe a receive value; ignore rather than assume 0.
    // NDIS_STATUS_SUCCESS and unsolicited transaction for this notification.
    if (read32(b, 4) != 0 || read32(b, 8) != 0)
        return ReceiveFailure{ReceiveError::malformed_wdi, 4};

    std::optional<wire::MacAddress> source;
    std::optional<ChannelObservation> channel;
    std::optional<std::span<const std::uint8_t>> body;
    for (std::size_t at = 16; at < b.size();) {
        if (b.size() - at < 4) return ReceiveFailure{ReceiveError::malformed_wdi, at};
        const auto type = read16(b, at);
        const auto length = read16(b, at + 2);
        const auto start = at + 4;
        if (length > b.size() - start) return ReceiveFailure{ReceiveError::malformed_wdi, at};
        const auto value = b.subspan(start, length);
        switch (type) {
        case 0x0002: // SourceAddress in ACTION_FRAME_RECEIVED_PARAMETERS.
            if (source || length != 6) return ReceiveFailure{ReceiveError::malformed_wdi, at};
            source.emplace();
            std::copy(value.begin(), value.end(), source->begin());
            break;
        case 0x003a:
            if (channel || length != 8) return ReceiveFailure{ReceiveError::malformed_wdi, at};
            channel = ChannelObservation{read32(value, 0), read32(value, 4)};
            if (!supported_channel(*channel))
                return ReceiveFailure{ReceiveError::malformed_wdi, at};
            break;
        case 0x00be:
            if (body) return ReceiveFailure{ReceiveError::malformed_wdi, at};
            body = value;
            break;
        default: break; // Unknown WDI metadata is not an AWDL TLV.
        }
        at = start + length;
    }
    if (!source || !channel || !body) return ReceiveFailure{ReceiveError::malformed_wdi, 16};
    auto parsed = wire::parse_action_body(*body);
    if (!parsed) return bad_action({parsed.error(), parsed.offset()});
    ReceivedAction action{*source, std::move(parsed.value()), received_at, {}, channel, port,
                          {}, {}, {}, {}, false};
    return accept(peers, std::move(action), *body);
}

ReceiveResult ingest_mpdu(peer_state::PeerTable& peers, std::span<const std::uint8_t> mpdu,
                          bool has_fcs, discovery::MonotonicTime received_at) {
    if (received_at.time_since_epoch().count() < 0)
        return ReceiveFailure{ReceiveError::invalid_time};
    auto parsed = wire::parse_action_mpdu(mpdu, has_fcs);
    if (!parsed) return bad_action({parsed.error(), parsed.offset()});
    auto& frame = parsed.value();
    ReceivedAction action{frame.source, std::move(frame.body), received_at, {}, {}, {},
                          frame.destination, frame.bssid, frame.sequence, frame.retry, has_fcs};
    return accept(peers, std::move(action), mpdu.subspan(24, mpdu.size() - 24 - (has_fcs ? 4 : 0)));
}
} // namespace awdlwin::receive
