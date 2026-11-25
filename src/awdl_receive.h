#pragma once

#include "awdl_discovery.h"
#include "awdl_discovery_state.h"
#include "awdl_peer_state.h"
#include <optional>

namespace awdlwin::receive {

inline constexpr std::uint32_t wdi_action_frame_received = 0x40050067;
inline constexpr std::size_t wdi_header_size = 16;
inline constexpr std::size_t wdi_source_address_tlv_size = 4 + 6;
inline constexpr std::size_t wdi_channel_info_tlv_size = 4 + 8;
inline constexpr std::size_t wdi_action_body_tlv_header_size = 4;
// Bounded budget for the maximum supported Action body plus the WDI header
// and required SourceAddress, ChannelInfo and ActionBody TLV overhead.
inline constexpr std::size_t logged_prefix_capacity = wire::max_action_body_size +
    wdi_header_size + wdi_source_address_tlv_size + wdi_channel_info_tlv_size +
    wdi_action_body_tlv_header_size;

enum class ReceiveError {
    wrong_indication, incomplete_log, malformed_wdi, wrong_port,
    invalid_time, invalid_action, peer_rejected
};
struct ReceiveFailure {
    ReceiveError error;
    std::size_t offset{};
    wire::CodecError codec_error{wire::CodecError::none};
    peer_state::PeerStateError peer_error{peer_state::PeerStateError::none};
};
struct ChannelObservation { std::uint32_t channel; std::uint32_t band_id; };
struct ReceivedAction {
    wire::MacAddress source;
    wire::ActionBody body;
    discovery::MonotonicTime received_at;
    // Only from this frame, never a retained Peer::sync from an earlier frame.
    std::optional<wire::SyncInfo> fresh_sync;
    std::optional<ChannelObservation> channel;
    std::optional<std::uint16_t> port_id;
    // WDI Action notification does not supply Address 1/3 or sequence/FCS.
    std::optional<wire::MacAddress> destination;
    std::optional<wire::MacAddress> bssid;
    std::optional<std::uint16_t> sequence;
    std::optional<bool> retry;
    bool fcs_stripped{}; // Never CRC verification or proof of radio reception.
};
using ReceiveResult = std::variant<ReceivedAction, ReceiveFailure>;
struct LoggedWdiInput {
    std::uint32_t status_code;
    std::uint32_t original_length;
    // Exactly CopiedLength bytes from the existing status log, not its padded
    // storage. Owner must check log ABI, target adapter and record sequence.
    std::span<const std::uint8_t> prefix;
};

// Offline serialized input adapters. All validation/allocation precedes the
// atomic PeerTable update. Neither polls IOCTLs nor starts a live capture.
// received_at MUST be the event's timestamp in the same steady_clock epoch as
// local sync/generation. Do not use drain time, PCAP UTC/TSFT or relabel the
// logger's KeQueryInterruptTime as steady_clock. ReceiveReplay can map saved
// V1 logs using an explicit same-capture correlation; live acquisition of that
// correlation and its timing accuracy remain unverified.
// WDI layouts: SDK 10.0.28000.0 dot11wdi.h, wditypes.hpp and wlan/1.0/
// WABIModel.xml + TlvGenerated_.hpp. In THIS indication TLV 0x0002 is named
// SourceAddress, not Address 3. Its actual TX10UB behavior remains unverified.
// ChannelInfo receive profile: BandId 1 / channels 1..14, or BandId 2 /
// channels 44 and 149 (current OWL profile). Zero, unknown/ANY/custom bands,
// band/channel mismatches and other channels are rejected before peer update.
// This is a supported-input policy, not radio/regulatory capability validation.
// Header Reserved is ignored: the SDK/official receive contract specifies no
// mandatory value. IhvSpecificId is a debug ID and is also not forced to zero.
ReceiveResult ingest_logged_wdi(peer_state::PeerTable& peers, const LoggedWdiInput& input,
                                std::uint16_t expected_port, discovery::MonotonicTime received_at);
// radiotap already removed; explicit FCS presence. Strip only, no CRC check.
ReceiveResult ingest_mpdu(peer_state::PeerTable& peers, std::span<const std::uint8_t> mpdu,
                          bool has_fcs, discovery::MonotonicTime received_at);

} // namespace awdlwin::receive
