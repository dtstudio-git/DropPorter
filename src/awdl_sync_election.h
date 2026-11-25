#pragma once

#include "awdl_discovery_state.h"
#include "awdl_peer_state.h"

namespace awdlwin::discovery {

// Bounded OWL election over the observations currently retained by peers.
// Expiry remains an explicit PeerTable operation. Only complete Election v2
// views participate; v1 cannot provide the counter/sync-address inputs needed
// by this algorithm and is intentionally deferred.
wire::CodecResult<TransmitElection> choose_owl_election(
    const TransmitState& local, const peer_state::PeerTable& peers);

// Apply one freshly decoded Sync TLV from the selected peer. received_at and
// current.anchor must use this process's same steady-clock microsecond epoch;
// never pass wall time or a remote TSFT relabeled as MonotonicTime.
// The caller must first accept this frame through its serialized peer receive
// path, including per-peer stale-timestamp rejection; this pure helper does not
// retain a last-receipt timestamp and never reads Peer::sync.
wire::CodecResult<TransmitSync> update_owl_sync(
    const TransmitSync& current,
    const wire::MacAddress& selected_source,
    const wire::MacAddress& frame_source,
    const wire::SyncInfo& fresh_frame_sync,
    MonotonicTime received_at);

} // namespace awdlwin::discovery
