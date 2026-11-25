#include "awdl_discovery.h"

#include <algorithm>
#include <utility>

namespace awdlwin::wire {
namespace {
template<class T> CodecResult<T> fail(CodecError error, std::size_t offset = 0) {
    return CodecResult<T>::failure(error, offset);
}
template<class T> CodecResult<T> success(T value) {
    return CodecResult<T>::success(std::move(value));
}
std::uint16_t le16(std::span<const std::uint8_t> b, std::size_t at) {
    return static_cast<std::uint16_t>(b[at] | (b[at + 1] << 8));
}
std::uint32_t le32(std::span<const std::uint8_t> b, std::size_t at) {
    return static_cast<std::uint32_t>(b[at]) |
        (static_cast<std::uint32_t>(b[at + 1]) << 8) |
        (static_cast<std::uint32_t>(b[at + 2]) << 16) |
        (static_cast<std::uint32_t>(b[at + 3]) << 24);
}
MacAddress mac(std::span<const std::uint8_t> b, std::size_t at) {
    MacAddress result{};
    std::copy_n(b.begin() + at, result.size(), result.begin());
    return result;
}
void append16(Bytes& b, std::uint16_t n) {
    b.push_back(static_cast<std::uint8_t>(n));
    b.push_back(static_cast<std::uint8_t>(n >> 8));
}
void append32(Bytes& b, std::uint32_t n) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        b.push_back(static_cast<std::uint8_t>(n >> shift));
}
CodecError header_error(const ActionHeader& h) {
    // This is the Action-header compatibility version, not Version TLV version.
    if (h.version != 0x10) return CodecError::unsupported_version;
    if (h.subtype != ActionSubtype::psf && h.subtype != ActionSubtype::mif)
        return CodecError::unsupported_subtype;
    return CodecError::none;
}
constexpr std::size_t sync_channel_offset = 33;
constexpr std::size_t sync_channel_padding = 2;
constexpr std::size_t standalone_channel_padding = 3;
constexpr std::size_t observed_apple_trailing_padding_size = 8;
CodecResult<ChannelSequence> channels(std::span<const std::uint8_t> b, std::size_t padding) {
    if (b.size() < 6 + padding) return fail<ChannelSequence>(CodecError::malformed_tlv);
    const auto count = static_cast<std::size_t>(b[0]) + 1;
    const std::size_t width = b[1] == 0 ? 1 : (b[1] == 1 || b[1] == 3 ? 2 : 0);
    // Unknown channel encoding is retained in the raw TLV, but not decoded.
    if (width == 0) return fail<ChannelSequence>(CodecError::malformed_tlv, 1);
    const auto end = 6 + count * width;
    if (b.size() - padding < end) return fail<ChannelSequence>(CodecError::malformed_tlv, 6);
    return success(ChannelSequence{b[1], b[2], b[3], le16(b, 4),
        Bytes(b.begin() + 6, b.begin() + end), Bytes(b.begin() + end, b.begin() + end + padding),
        Bytes(b.begin() + end + padding, b.end()), count});
}
CodecError tlv_error(const Tlv& t) {
    const auto& b = t.value;
    switch (t.type) {
    case 4: // Fixed sync fields plus embedded channel sequence.
        if (b.size() < sync_channel_offset + 6 + sync_channel_padding) return CodecError::malformed_tlv;
        // Future encodings stay opaque. Known encodings get bounded validation.
        if (b[34] != 0 && b[34] != 1 && b[34] != 3) return CodecError::none;
        return channels(std::span(b).subspan(sync_channel_offset), sync_channel_padding)
            ? CodecError::none : CodecError::malformed_tlv;
    case 5: return b.size() >= 21 ? CodecError::none : CodecError::malformed_tlv;
    case 6: return b.size() >= 9 ? CodecError::none : CodecError::malformed_tlv;
    case 7: return b.size() >= 8 ? CodecError::none : CodecError::malformed_tlv;
    case 12: // Flag-dependent/partially understood fields remain opaque.
        return b.size() >= 2 ? CodecError::none : CodecError::malformed_tlv;
    case 16:
        return b.size() >= 2 && static_cast<std::size_t>(b[1]) <= b.size() - 2
            ? CodecError::none : CodecError::malformed_tlv;
    case 18:
        if (b.size() < 6 + standalone_channel_padding) return CodecError::malformed_tlv;
        if (b[1] != 0 && b[1] != 1 && b[1] != 3) return CodecError::none;
        return channels(b, standalone_channel_padding) ? CodecError::none : CodecError::malformed_tlv;
    case 21: return b.size() >= 2 ? CodecError::none : CodecError::malformed_tlv;
    case 24: return b.size() >= 40 ? CodecError::none : CodecError::malformed_tlv;
    default: return CodecError::none;
    }
}
bool is_type(const Tlv& t, std::uint8_t type, std::size_t minimum) {
    return t.type == type && t.value.size() >= minimum;
}
} // namespace

CodecResult<ActionBody> parse_action_body(std::span<const std::uint8_t> b) {
    if (b.size() > max_action_body_size) return fail<ActionBody>(CodecError::size_limit);
    if (b.size() < action_header_size) return fail<ActionBody>(CodecError::truncated, b.size());
    if (b[0] != 0x7f || b[1] != 0x00 || b[2] != 0x17 || b[3] != 0xf2 || b[4] != 8)
        return fail<ActionBody>(CodecError::not_awdl);
    ActionBody out{{b[5], static_cast<ActionSubtype>(b[6]), b[7], le32(b, 8), le32(b, 12)}, {}};
    if (const auto e = header_error(out.header); e != CodecError::none)
        return fail<ActionBody>(e, e == CodecError::unsupported_version ? 5 : 6);
    for (std::size_t at = action_header_size; at < b.size();) {
        const auto remaining = b.size() - at;
        if (remaining == observed_apple_trailing_padding_size &&
            std::all_of(b.begin() + at, b.end(), [](std::uint8_t byte) { return byte == 0; })) {
            out.trailing_padding.assign(b.begin() + at, b.end());
            break;
        }
        if (b.size() - at < 3) return fail<ActionBody>(CodecError::truncated, at);
        const auto length = le16(b, at + 1);
        if (length > b.size() - at - 3) return fail<ActionBody>(CodecError::truncated, at);
        Tlv t{b[at], Bytes(b.begin() + at + 3, b.begin() + at + 3 + length)};
        if (auto e = tlv_error(t); e != CodecError::none) return fail<ActionBody>(e, at);
        out.tlvs.push_back(std::move(t));
        at += 3 + length;
    }
    return success(std::move(out));
}

CodecResult<Bytes> serialize_action_body(const ActionBody& body) {
    if (auto e = header_error(body.header); e != CodecError::none) return fail<Bytes>(e);
    if (!body.trailing_padding.empty() &&
        (body.trailing_padding.size() != observed_apple_trailing_padding_size ||
         !std::all_of(body.trailing_padding.begin(), body.trailing_padding.end(),
                      [](std::uint8_t byte) { return byte == 0; })))
        return fail<Bytes>(CodecError::malformed_tlv);
    std::size_t size = action_header_size;
    for (const auto& t : body.tlvs) {
        if (t.value.size() > max_action_body_size - 3 ||
            size > max_action_body_size - 3 - t.value.size()) return fail<Bytes>(CodecError::size_limit);
        if (auto e = tlv_error(t); e != CodecError::none) return fail<Bytes>(e, size);
        size += 3 + t.value.size();
    }
    if (body.trailing_padding.size() > max_action_body_size - size)
        return fail<Bytes>(CodecError::size_limit);
    size += body.trailing_padding.size();
    Bytes b{0x7f, 0x00, 0x17, 0xf2, 8, body.header.version,
        static_cast<std::uint8_t>(body.header.subtype), body.header.reserved};
    b.reserve(size);
    append32(b, body.header.phy_tx);
    append32(b, body.header.target_tx);
    for (const auto& t : body.tlvs) {
        b.push_back(t.type);
        append16(b, static_cast<std::uint16_t>(t.value.size()));
        b.insert(b.end(), t.value.begin(), t.value.end());
    }
    b.insert(b.end(), body.trailing_padding.begin(), body.trailing_padding.end());
    return success(std::move(b));
}

CodecResult<Bytes> generate_discovery(const ActionBody& body) {
    if (const auto e = header_error(body.header); e != CodecError::none)
        return fail<Bytes>(e);
    const auto has = [&](std::uint8_t type) {
        return std::any_of(body.tlvs.begin(), body.tlvs.end(),
            [type](const Tlv& t) { return t.type == type; });
    };
    // OWL's full-action profile. This is not a claim that every Apple frame
    // must have this set, or that syntax alone makes a live peer discoverable.
    for (const auto type : {4, 5, 18, 24, 6, 12, 21})
        if (!has(static_cast<std::uint8_t>(type)))
            return fail<Bytes>(CodecError::missing_discovery_tlv, static_cast<std::size_t>(type));
    if (body.header.subtype == ActionSubtype::mif && (!has(7) || !has(16)))
        return fail<Bytes>(CodecError::missing_discovery_tlv);
    return serialize_action_body(body);
}

CodecResult<VersionInfo> decode_version(const Tlv& t) {
    if (!is_type(t, 21, 2)) return fail<VersionInfo>(CodecError::malformed_tlv);
    return success(VersionInfo{t.value[0], t.value[1]});
}
CodecResult<ArpaInfo> decode_arpa(const Tlv& t) {
    if (!is_type(t, 16, 2) || tlv_error(t) != CodecError::none)
        return fail<ArpaInfo>(CodecError::malformed_tlv);
    const auto end = 2 + static_cast<std::size_t>(t.value[1]);
    return success(ArpaInfo{t.value[0], std::string(t.value.begin() + 2, t.value.begin() + end),
        Bytes(t.value.begin() + end, t.value.end())});
}
CodecResult<ChannelSequence> decode_channel_sequence(const Tlv& t) {
    if (t.type != 18) return fail<ChannelSequence>(CodecError::malformed_tlv);
    return channels(t.value, standalone_channel_padding);
}
CodecResult<SyncInfo> decode_sync(const Tlv& t) {
    if (!is_type(t, 4, sync_channel_offset + 6 + sync_channel_padding))
        return fail<SyncInfo>(CodecError::malformed_tlv);
    const auto c = channels(std::span(t.value).subspan(sync_channel_offset), sync_channel_padding);
    if (!c) return fail<SyncInfo>(c.error(), sync_channel_offset + c.offset());
    const auto& b = t.value;
    return success(SyncInfo{b[0], le16(b, 1), b[3], le16(b, 5), le16(b, 7),
        le16(b, 9), mac(b, 21), b[27], le16(b, 29), le16(b, 31), c.value()});
}
CodecResult<ElectionInfo> decode_election(const Tlv& t) {
    if (!is_type(t, 5, 21)) return fail<ElectionInfo>(CodecError::malformed_tlv);
    return success(ElectionInfo{t.value[3], mac(t.value, 5), le32(t.value, 11), le32(t.value, 15)});
}
CodecResult<ElectionV2Info> decode_election_v2(const Tlv& t) {
    if (!is_type(t, 24, 40)) return fail<ElectionV2Info>(CodecError::malformed_tlv);
    return success(ElectionV2Info{mac(t.value, 0), mac(t.value, 6), le32(t.value, 12),
        le32(t.value, 16), le32(t.value, 20), le32(t.value, 24), le32(t.value, 36)});
}

CodecResult<ActionMpdu> parse_action_mpdu(std::span<const std::uint8_t> b, bool has_fcs) {
    if (b.size() < 24 + (has_fcs ? 4u : 0u)) return fail<ActionMpdu>(CodecError::truncated);
    if (has_fcs) b = b.first(b.size() - 4);
    const auto fc = le16(b, 0);
    // Only unprotected, unfragmented Action management frames, without HT control.
    if ((fc & 0x00ff) != 0x00d0) return fail<ActionMpdu>(CodecError::not_awdl);
    if ((fc & 0xc700) != 0 || (le16(b, 22) & 0x000f) != 0)
        return fail<ActionMpdu>(CodecError::unsupported_mac_header);
    auto body = parse_action_body(b.subspan(24));
    if (!body) return fail<ActionMpdu>(body.error(), 24 + body.offset());
    return success(ActionMpdu{mac(b, 4), mac(b, 10), mac(b, 16),
        static_cast<std::uint16_t>(le16(b, 22) >> 4), (fc & 0x0800) != 0, std::move(body.value())});
}
} // namespace awdlwin::wire
