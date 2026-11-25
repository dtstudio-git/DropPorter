#include "awdl_discovery_state.h"

#include <algorithm>

namespace awdlwin::discovery {
namespace {
using namespace wire;
void put16(Bytes& b, std::uint16_t n) {
    b.push_back(static_cast<std::uint8_t>(n));
    b.push_back(static_cast<std::uint8_t>(n >> 8));
}
void put32(Bytes& b, std::uint32_t n) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        b.push_back(static_cast<std::uint8_t>(n >> shift));
}
void put_mac(Bytes& b, const MacAddress& address) {
    b.insert(b.end(), address.begin(), address.end());
}
bool unicast(const MacAddress& address) {
    return (address[0] & 1) == 0 &&
        std::any_of(address.begin(), address.end(), [](auto n) { return n != 0; });
}
bool channel_valid(OpClassChannel c, bool allow_null) {
    return (allow_null && c.channel == 0 && c.opclass == 0) ||
        (c.channel == 6 && c.opclass == 0x51) ||
        ((c.channel == 44 || c.channel == 149) && c.opclass == 0x80);
}
bool election_valid(const TransmitState& s) {
    const auto& e = s.election;
    if (e.height == 0)
        return e.master_address == s.self_address && e.sync_address == s.self_address &&
            e.master_metric == e.self_metric && e.master_counter == e.self_counter;
    return e.master_address != s.self_address && e.sync_address != s.self_address;
}
Bytes channel_bytes(const TransmitState& s, std::size_t padding) {
    Bytes b{15, 3, 0, 3, 0xff, 0xff};
    for (const auto c : s.channel_sequence) {
        b.push_back(c.channel);
        b.push_back(c.opclass);
    }
    b.insert(b.end(), padding, 0);
    return b;
}
} // namespace

wire::CodecResult<wire::Bytes> generate_owl_discovery(
    const TransmitState& s, wire::ActionSubtype subtype, MonotonicTime now) {
    using namespace wire;
    if (subtype != ActionSubtype::psf && subtype != ActionSubtype::mif)
        return CodecResult<Bytes>::failure(CodecError::unsupported_subtype);
    // Constrain to the source's initialized OPCLASS/presence profile. Do not
    // guess social-channel mappings or truncate an inconsistent v1/v2 height.
    if (!unicast(s.self_address) || !unicast(s.election.master_address) ||
        !unicast(s.election.sync_address) || s.name.empty() || s.name.size() > 64 ||
        s.name.find('\0') != std::string::npos || s.version == 0 || s.device_class == 0 ||
        s.psf_interval_tu == 0 || s.sync.aw_period_tu == 0 || s.sync.presence_mode != 4 ||
        s.sync.aw_counter % s.sync.presence_mode != 0 ||
        static_cast<std::uint32_t>(s.sync.aw_period_tu) * s.sync.presence_mode > 0xffff ||
        now < s.sync.anchor || now.time_since_epoch().count() < 0 ||
        s.sync.anchor.time_since_epoch().count() < 0 ||
        s.election.height > 255 || !election_valid(s) ||
        !channel_valid(s.current_channel, true) || !channel_valid(s.master_channel, false) ||
        !std::all_of(s.channel_sequence.begin(), s.channel_sequence.end(),
            [](auto c) { return channel_valid(c, true); }))
        return CodecResult<Bytes>::failure(CodecError::malformed_tlv);

    // UTC/system_clock and raw integer inputs cannot bind to this API. Only
    // validated nonnegative same-clock counts are converted to wire units.
    const auto elapsed_tu = static_cast<std::uint64_t>((now - s.sync.anchor).count()) / 1024;
    const auto eaw_tu = static_cast<std::uint32_t>(s.sync.aw_period_tu) * s.sync.presence_mode;
    const auto next_tu = static_cast<std::uint16_t>(eaw_tu - elapsed_tu % eaw_tu);
    const auto aw = static_cast<std::uint16_t>(s.sync.aw_counter + elapsed_tu / s.sync.aw_period_tu);
    const auto remaining = eaw_tu - next_tu;
    const auto remaining_aw = static_cast<std::uint16_t>(
        remaining > s.sync.aw_period_tu ? 0 : s.sync.aw_period_tu - remaining);
    const auto timestamp = static_cast<std::uint32_t>(now.time_since_epoch().count());
    ActionBody body{{0x10, subtype, 0, timestamp, timestamp}, {}};

    Bytes sync{s.current_channel.channel};
    put16(sync, next_tu);
    sync.push_back(s.master_channel.channel);
    sync.push_back(0); // OWL guard_time.
    put16(sync, s.sync.aw_period_tu);
    put16(sync, s.psf_interval_tu);
    put16(sync, 0x1800); // OWL flags, semantics unresolved in the reference.
    put16(sync, s.sync.aw_period_tu); // aw_ext_length
    put16(sync, s.sync.aw_period_tu); // aw_com_length
    put16(sync, remaining_aw);
    sync.insert(sync.end(), 4, static_cast<std::uint8_t>(s.sync.presence_mode - 1));
    put_mac(sync, s.election.master_address);
    sync.push_back(s.sync.presence_mode);
    sync.push_back(0); // OWL reserved.
    put16(sync, aw);
    put16(sync, aw); // OWL ap_alignment equals next_aw_seq.
    const auto embedded = channel_bytes(s, 2);
    sync.insert(sync.end(), embedded.begin(), embedded.end());
    body.tlvs.push_back({4, std::move(sync)});

    Bytes election{0, 0, 0, static_cast<std::uint8_t>(s.election.height), 0};
    put_mac(election, s.election.master_address);
    put32(election, s.election.master_metric);
    put32(election, s.election.self_metric);
    put16(election, 0);
    body.tlvs.push_back({5, std::move(election)});
    body.tlvs.push_back({18, channel_bytes(s, 3)});

    Bytes election_v2;
    put_mac(election_v2, s.election.master_address);
    put_mac(election_v2, s.election.sync_address);
    put32(election_v2, s.election.master_counter);
    put32(election_v2, s.election.height);
    put32(election_v2, s.election.master_metric);
    put32(election_v2, s.election.self_metric);
    put32(election_v2, 0); // OWL unknown.
    put32(election_v2, 0); // OWL reserved.
    put32(election_v2, s.election.self_counter);
    body.tlvs.push_back({24, std::move(election_v2)});
    body.tlvs.push_back({6, Bytes(9, 0)}); // OWL service parameters.
    if (subtype == ActionSubtype::mif) {
        body.tlvs.push_back({7, {0, 0, 0xce, 0x11, 0x1b, 0xff, 0, 0}});
        Bytes arpa{3, static_cast<std::uint8_t>(s.name.size())};
        arpa.insert(arpa.end(), s.name.begin(), s.name.end());
        arpa.insert(arpa.end(), {0xc0, 0x0c}); // OWL DNS short .local suffix.
        body.tlvs.push_back({16, std::move(arpa)});
    }
    Bytes data_path{0x24, 0x8f, 'X', '0', 0}; // OWL data-path reference constants.
    put16(data_path, s.master_channel.channel == 6 ? 1 : s.master_channel.channel == 44 ? 2 : 4);
    put_mac(data_path, s.self_address);
    put16(data_path, 0);
    body.tlvs.push_back({12, std::move(data_path)});
    body.tlvs.push_back({21, {s.version, s.device_class}});
    return generate_discovery(body);
}
} // namespace awdlwin::discovery
