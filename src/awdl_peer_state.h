#pragma once

#include "awdl_discovery.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>

namespace awdlwin::peer_state {

inline constexpr std::size_t max_peer_count = 256;

enum class PeerStateError {
    none,
    invalid_source_mac,
    stale_timestamp,
    invalid_action_body,
    duplicate_singleton_tlv,
    unsupported_field_value,
    table_full
};

struct PeerStateResult {
    PeerStateError error{PeerStateError::none};
    wire::CodecError codec_error{wire::CodecError::none};
    std::size_t offset{};

    explicit operator bool() const noexcept { return error == PeerStateError::none; }
};

using ElectionView = std::variant<std::monostate, wire::ElectionInfo, wire::ElectionV2Info>;

struct Peer {
    wire::MacAddress source{};
    std::uint64_t last_seen_us{};
    bool has_seen_mif{};
    std::optional<wire::VersionInfo> version;
    std::optional<std::string> name;
    std::optional<wire::ChannelSequence> channel_sequence;
    // Presence means an advertised sync view was decoded. It does not mean
    // that the local clock is synchronized to this peer.
    std::optional<wire::SyncInfo> sync;
    ElectionView election;
    // Owned parsed representation preserving every ordered TLV value,
    // including unknown and duplicate unknown TLVs, from the latest frame.
    std::optional<wire::ActionBody> last_action_body;

    // OWL's peer metadata predicate: MIF seen and nonzero advertised version
    // and device class. This is not synchronization, authentication, channel
    // agreement or communication readiness. Do not use it as TX admission.
    bool metadata_ready() const noexcept;

    // Diagnostic shape check only. It does not compare with or imply the
    // presence mode/channel configuration of a local radio.
    std::optional<bool> channel_sequence_matches_owl_shape;
};

class PeerTable {
public:
    // Timestamps are caller-provided monotonic microseconds.
    // Equal timestamps are accepted; a value older than this source's current
    // last_seen_us is rejected. Calls must be serialized by the owner.
    PeerStateResult ingest(const wire::MacAddress& source,
                           std::span<const std::uint8_t> action_body,
                           std::uint64_t now_us);

    const Peer* find(const wire::MacAddress& source) const noexcept;
    bool remove(const wire::MacAddress& source) noexcept;

    // Read-only iteration for callers that already serialize access to this
    // table. Iteration does not expire peers or expose the backing container.
    template<class Visitor>
    void for_each_peer(Visitor&& visitor) const {
        for (const auto& entry : peers_) visitor(entry.second);
    }

    // Explicit caller-driven expiry in microseconds. A peer expires at the
    // exact timeout boundary: now_us - last_seen_us >= timeout_us. No timer
    // or implicit eviction.
    std::size_t expire(std::uint64_t now_us, std::uint64_t timeout_us) noexcept;

    std::size_t size() const noexcept { return peers_.size(); }
    static constexpr std::size_t capacity() noexcept { return max_peer_count; }

private:
    struct MacHash {
        std::size_t operator()(const wire::MacAddress& address) const noexcept;
    };

    std::unordered_map<wire::MacAddress, Peer, MacHash> peers_;
};

} // namespace awdlwin::peer_state
