#include "awdl_peer_state.h"

#include <array>
#include <type_traits>
#include <utility>

namespace awdlwin::peer_state {
namespace {

static_assert(std::is_nothrow_move_assignable_v<Peer>);
static_assert(std::is_nothrow_move_constructible_v<Peer>);

PeerStateResult fail(PeerStateError error, wire::CodecError codec_error = wire::CodecError::none,
                     std::size_t offset = 0) noexcept {
    return PeerStateResult{error, codec_error, offset};
}

bool valid_unicast_source(const wire::MacAddress& address) noexcept {
    bool any_nonzero = false;
    for (const auto octet : address) any_nonzero = any_nonzero || octet != 0;
    return any_nonzero && (address[0] & 0x01u) == 0;
}

bool is_singleton_type(std::uint8_t type) noexcept {
    // OWL's recognized peer fields are one observation per Action body.
    // Unrecognized TLVs remain opaque and may repeat in the retained body.
    switch (type) {
    case 4: case 5: case 6: case 7: case 12: case 16: case 18: case 21: case 24:
        return true;
    default:
        return false;
    }
}

struct DecodedFields {
    bool saw_mif{};
    std::optional<wire::VersionInfo> version;
    std::optional<std::string> name;
    std::optional<wire::ChannelSequence> channel_sequence;
    std::optional<bool> channel_shape;
    std::optional<wire::SyncInfo> sync;
    std::optional<wire::ElectionInfo> election_v1;
    std::optional<wire::ElectionV2Info> election_v2;
};

PeerStateResult decode_fields(const wire::ActionBody& body, DecodedFields& decoded) {
    std::array<bool, 256> seen{};
    std::size_t offset = wire::action_header_size;
    for (const auto& tlv : body.tlvs) {
        if (is_singleton_type(tlv.type)) {
            if (seen[tlv.type])
                return fail(PeerStateError::duplicate_singleton_tlv, wire::CodecError::none, offset);
            seen[tlv.type] = true;
        }

        switch (tlv.type) {
        case 4: {
            auto value = wire::decode_sync(tlv);
            if (!value) return fail(PeerStateError::unsupported_field_value, value.error(), offset);
            decoded.sync.emplace(std::move(value.value()));
            break;
        }
        case 5: {
            auto value = wire::decode_election(tlv);
            if (!value) return fail(PeerStateError::unsupported_field_value, value.error(), offset);
            decoded.election_v1.emplace(std::move(value.value()));
            break;
        }
        case 16: {
            auto value = wire::decode_arpa(tlv);
            if (!value) return fail(PeerStateError::unsupported_field_value, value.error(), offset);
            decoded.name.emplace(std::move(value.value().name));
            break;
        }
        case 18: {
            auto value = wire::decode_channel_sequence(tlv);
            if (!value) return fail(PeerStateError::unsupported_field_value, value.error(), offset);
            const auto& sequence = value.value();
            decoded.channel_shape = sequence.count == 16 && sequence.duplicate_count == 0 &&
                sequence.step_count == 3 && sequence.fill_channel == 0xffff;
            decoded.channel_sequence.emplace(std::move(value.value()));
            break;
        }
        case 21: {
            auto value = wire::decode_version(tlv);
            if (!value) return fail(PeerStateError::unsupported_field_value, value.error(), offset);
            decoded.version.emplace(std::move(value.value()));
            break;
        }
        case 24: {
            auto value = wire::decode_election_v2(tlv);
            if (!value) return fail(PeerStateError::unsupported_field_value, value.error(), offset);
            decoded.election_v2.emplace(std::move(value.value()));
            break;
        }
        default:
            break;
        }

        offset += 3 + tlv.value.size();
    }
    decoded.saw_mif = body.header.subtype == wire::ActionSubtype::mif;
    return {};
}

} // namespace

bool Peer::metadata_ready() const noexcept {
    return has_seen_mif && version.has_value() && version->version != 0 &&
        version->device_class != 0;
}

std::size_t PeerTable::MacHash::operator()(const wire::MacAddress& address) const noexcept {
    std::size_t hash = 1469598103934665603ull;
    for (const auto octet : address) {
        hash ^= octet;
        hash *= 1099511628211ull;
    }
    return hash;
}

PeerStateResult PeerTable::ingest(const wire::MacAddress& source,
                                  std::span<const std::uint8_t> action_body,
                                  std::uint64_t now_us) {
    if (!valid_unicast_source(source)) return fail(PeerStateError::invalid_source_mac);

    auto current = peers_.find(source);
    if (current != peers_.end() && now_us < current->second.last_seen_us)
        return fail(PeerStateError::stale_timestamp);

    auto parsed = wire::parse_action_body(action_body);
    if (!parsed)
        return fail(PeerStateError::invalid_action_body, parsed.error(), parsed.offset());

    DecodedFields decoded;
    const auto decode_result = decode_fields(parsed.value(), decoded);
    if (!decode_result) return decode_result;

    if (current == peers_.end() && peers_.size() >= max_peer_count)
        return fail(PeerStateError::table_full);

    // Prepare the entire new value before changing the table. Allocation or
    // decoding failures therefore cannot partially refresh an existing peer.
    Peer updated = current == peers_.end() ? Peer{} : current->second;
    updated.source = source;
    updated.last_seen_us = now_us;
    if (decoded.saw_mif) updated.has_seen_mif = true;
    if (decoded.version) updated.version = std::move(decoded.version);
    if (decoded.name) updated.name = std::move(decoded.name);
    if (decoded.channel_sequence) updated.channel_sequence = std::move(decoded.channel_sequence);
    if (decoded.channel_shape) updated.channel_sequence_matches_owl_shape = decoded.channel_shape;
    if (decoded.sync) updated.sync = std::move(decoded.sync);

    // OWL ignores v1 election data once v2 support has been observed.
    if (decoded.election_v2) {
        updated.election = std::move(*decoded.election_v2);
    } else if (decoded.election_v1 &&
               !std::holds_alternative<wire::ElectionV2Info>(updated.election)) {
        updated.election = std::move(*decoded.election_v1);
    }

    updated.last_action_body.emplace(std::move(parsed.value()));
    if (current == peers_.end()) {
        peers_.emplace(source, std::move(updated));
    } else {
        current->second = std::move(updated);
    }
    return {};
}

const Peer* PeerTable::find(const wire::MacAddress& source) const noexcept {
    const auto found = peers_.find(source);
    return found == peers_.end() ? nullptr : &found->second;
}

bool PeerTable::remove(const wire::MacAddress& source) noexcept {
    return peers_.erase(source) != 0;
}

std::size_t PeerTable::expire(std::uint64_t now_us, std::uint64_t timeout_us) noexcept {
    std::size_t removed = 0;
    for (auto it = peers_.begin(); it != peers_.end();) {
        const auto last_seen_us = it->second.last_seen_us;
        if (now_us >= last_seen_us && now_us - last_seen_us >= timeout_us) {
            it = peers_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

} // namespace awdlwin::peer_state
