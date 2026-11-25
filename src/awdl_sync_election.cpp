#include "awdl_sync_election.h"

#include <algorithm>
#include <cstdint>
#include <utility>
#include <variant>

namespace awdlwin::discovery {
namespace {

bool unicast(const wire::MacAddress& address) noexcept {
    return (address[0] & 0x01u) == 0 &&
        std::any_of(address.begin(), address.end(), [](std::uint8_t b) { return b != 0; });
}

bool election_roles_consistent(const peer_state::Peer& peer,
                               const wire::ElectionV2Info& election,
                               const wire::MacAddress& local_address) noexcept {
    if (!unicast(peer.source) || peer.source == local_address ||
        !unicast(election.master_address) ||
        !unicast(election.sync_address) || election.master_address == local_address ||
        election.sync_address == local_address) {
        return false;
    }

    if (election.distance_to_master == 0) {
        return election.master_address == peer.source &&
            election.sync_address == peer.source &&
            election.master_metric == election.self_metric &&
            election.master_counter == election.self_counter;
    }

    // A non-root cannot name itself as either the root or its own parent.
    return election.master_address != peer.source && election.sync_address != peer.source;
}

bool better_candidate(const wire::ElectionV2Info& candidate,
                      const wire::MacAddress& candidate_source,
                      std::uint32_t best_counter,
                      std::uint32_t best_metric,
                      std::uint32_t best_height,
                      const wire::MacAddress& best_source) noexcept {
    if (candidate.master_counter != best_counter)
        return candidate.master_counter > best_counter;
    if (candidate.master_metric != best_metric)
        return candidate.master_metric > best_metric;
    if (candidate.distance_to_master != best_height)
        return candidate.distance_to_master < best_height;
    return candidate_source > best_source;
}

wire::CodecResult<TransmitElection> malformed_election() {
    return wire::CodecResult<TransmitElection>::failure(wire::CodecError::malformed_tlv);
}

wire::CodecResult<TransmitSync> malformed_sync() {
    return wire::CodecResult<TransmitSync>::failure(wire::CodecError::malformed_tlv);
}

} // namespace

wire::CodecResult<TransmitElection> choose_owl_election(
    const TransmitState& local, const peer_state::PeerTable& peers) {
    if (!unicast(local.self_address)) return malformed_election();

    // OWL resets the candidate to self each election pass while retaining the
    // configured self metric/counter.
    TransmitElection selected{
        local.self_address, local.self_address, 0,
        local.election.self_metric, local.election.self_metric,
        local.election.self_counter, local.election.self_counter};
    wire::MacAddress selected_source = local.self_address;
    std::uint32_t selected_peer_height = 0;

    peers.for_each_peer([&](const peer_state::Peer& peer) {
        if (!peer.metadata_ready()) return;
        const auto* election = std::get_if<wire::ElectionV2Info>(&peer.election);
        if (election == nullptr) return;
        // OWL rejects a peer when adding it would make the local tree exceed
        // AWDL_ELECTION_TREE_MAX_HEIGHT (10): remote height >= 10 is excluded.
        if (election->distance_to_master >= 10 ||
            !election_roles_consistent(peer, *election, local.self_address)) {
            return;
        }
        if (!better_candidate(*election, peer.source,
                              selected.master_counter, selected.master_metric,
                              selected_peer_height, selected_source)) {
            return;
        }

        selected.master_address = election->master_address;
        selected.sync_address = peer.source;
        selected.height = election->distance_to_master + 1;
        selected.master_metric = election->master_metric;
        selected.master_counter = election->master_counter;
        selected_source = peer.source;
        selected_peer_height = election->distance_to_master;
    });

    return wire::CodecResult<TransmitElection>::success(std::move(selected));
}

wire::CodecResult<TransmitSync> update_owl_sync(
    const TransmitSync& current,
    const wire::MacAddress& selected_source,
    const wire::MacAddress& frame_source,
    const wire::SyncInfo& fresh_frame_sync,
    MonotonicTime received_at) {
    constexpr std::uint8_t owl_presence_mode = 4;
    const auto anchor_us = current.anchor.time_since_epoch().count();
    const auto received_us = received_at.time_since_epoch().count();
    const std::uint32_t eaw_tu =
        static_cast<std::uint32_t>(current.aw_period_tu) * current.presence_mode;

    if (!unicast(selected_source) || frame_source != selected_source ||
        !unicast(frame_source) || current.presence_mode != owl_presence_mode ||
        fresh_frame_sync.presence_mode != owl_presence_mode ||
        current.aw_period_tu == 0 || fresh_frame_sync.aw_period != current.aw_period_tu ||
        eaw_tu == 0 || eaw_tu > 0xffff || current.aw_counter % owl_presence_mode != 0 ||
        anchor_us < 0 || received_us < 0 || received_at < current.anchor) {
        return malformed_sync();
    }

    const auto next_down_tu = static_cast<std::uint32_t>(fresh_frame_sync.tx_down_counter);
    if (next_down_tu == 0 || next_down_tu > eaw_tu) return malformed_sync();

    const auto elapsed_in_eaw_tu = eaw_tu - next_down_tu;
    const auto aw_phase = elapsed_in_eaw_tu / current.aw_period_tu;
    if (aw_phase >= owl_presence_mode ||
        (static_cast<std::uint32_t>(fresh_frame_sync.next_aw_sequence) & 0x3u) != aw_phase) {
        return malformed_sync();
    }

    const auto elapsed_us = static_cast<std::int64_t>(elapsed_in_eaw_tu) * 1024;
    if (received_us < elapsed_us) return malformed_sync();

    const auto anchor = MonotonicTime(std::chrono::microseconds(received_us - elapsed_us));
    const auto base_counter = static_cast<std::uint16_t>(fresh_frame_sync.next_aw_sequence & 0xfffcu);
    return wire::CodecResult<TransmitSync>::success(
        TransmitSync{anchor, base_counter, current.aw_period_tu, current.presence_mode});
}

} // namespace awdlwin::discovery
