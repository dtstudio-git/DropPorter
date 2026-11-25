#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace awdlwin::wire {

// Offline codec boundary: Action body only, not radiotap, MAC header or WDI TLVs.
// Layout reference: seemoo-lab/owl da255a70f221784c836d943dd3f243bc798f223b.
using Bytes = std::vector<std::uint8_t>;
using MacAddress = std::array<std::uint8_t, 6>;
inline constexpr std::size_t action_header_size = 16;
// A local allocation bound, not an advertised radio/driver capability.
inline constexpr std::size_t max_action_body_size = 4096;

enum class ActionSubtype : std::uint8_t { psf = 0, mif = 3 };
enum class CodecError {
    none, truncated, not_awdl, unsupported_version, unsupported_subtype,
    malformed_tlv, size_limit, missing_discovery_tlv, unsupported_mac_header,
    malformed_data
};

struct CodecFailure { CodecError error; std::size_t offset; };

// Exactly one alternative: a success value or a non-none failure. No aggregate
// construction, default state or assignment can create conflicting status.
template<class T> class CodecResult {
public:
    static CodecResult success(T value) {
        return CodecResult(std::variant<T, CodecFailure>(std::in_place_index<0>, std::move(value)));
    }
    static CodecResult failure(CodecError error, std::size_t offset = 0) {
        if (error == CodecError::none) throw std::invalid_argument("Codec failure requires an error");
        return CodecResult(std::variant<T, CodecFailure>(std::in_place_index<1>, CodecFailure{error, offset}));
    }
    CodecResult(const CodecResult&) = default;
    CodecResult(CodecResult&&) = default;
    CodecResult& operator=(const CodecResult&) = delete;
    CodecResult& operator=(CodecResult&&) = delete;
    explicit operator bool() const noexcept { return state_.index() == 0; }
    T& value() { return std::get<0>(state_); }
    const T& value() const { return std::get<0>(state_); }
    CodecError error() const noexcept {
        return state_.index() == 0 ? CodecError::none : std::get<1>(state_).error;
    }
    std::size_t offset() const noexcept {
        return state_.index() == 0 ? 0 : std::get<1>(state_).offset;
    }
private:
    explicit CodecResult(std::variant<T, CodecFailure> state) : state_(std::move(state)) {}
    std::variant<T, CodecFailure> state_;
};

struct ActionHeader {
    std::uint8_t version; // Compatibility header version 0x10, independent of TLV 21.
    ActionSubtype subtype;
    std::uint8_t reserved;
    std::uint32_t phy_tx;
    std::uint32_t target_tx;
};
struct Tlv {
    std::uint8_t type;
    Bytes value;
};
struct ActionBody {
    ActionHeader header;
    // Ordered, owned bytes. Unknown TLVs and fields survive parse/serialize.
    std::vector<Tlv> tlvs;
    // Exact eight-zero suffix observed in Apple Action bodies; not a general TLV rule.
    Bytes trailing_padding{};
};
struct VersionInfo { std::uint8_t version; std::uint8_t device_class; }; // TLV 21 version.
struct ArpaInfo {
    std::uint8_t flags;
    std::string name; // Length-delimited bytes; no implicit NUL termination.
    Bytes suffix;    // DNS suffix remains opaque; do not assume .local on RX.
};
struct ChannelSequence {
    std::uint8_t encoding;
    std::uint8_t duplicate_count;
    std::uint8_t step_count;
    std::uint16_t fill_channel;
    // Entries remain encoded bytes: legacy flags are not channel numbers.
    Bytes entries;
    Bytes padding;  // Two bytes inside Sync TLV, three inside standalone TLV 18.
    Bytes trailing; // Additional uninterpreted bytes after the expected padding.
    std::size_t count;
};
// Partial decoded read views only. Omitted Sync fields (guard/extension lengths,
// min/max values/reserved), Election flags/id/unknown/pad and Election v2
// unknown/reserved remain in Tlv::value. Serialize the original ActionBody/TLV
// bytes; never reconstruct those bytes from these views or zero-fill omissions.
struct SyncInfo {
    std::uint8_t next_aw_channel;
    std::uint16_t tx_down_counter;
    std::uint8_t master_channel;
    std::uint16_t aw_period;
    std::uint16_t af_period;
    std::uint16_t flags;
    MacAddress master_address;
    std::uint8_t presence_mode;
    std::uint16_t next_aw_sequence;
    std::uint16_t ap_alignment;
    ChannelSequence channels;
};
struct ElectionInfo {
    // Partial read view of TLV 5; not a serialization model.
    std::uint8_t distance_to_master;
    MacAddress master_address;
    std::uint32_t master_metric;
    std::uint32_t self_metric;
};
struct ElectionV2Info {
    // Partial read view of TLV 24; not a serialization model.
    MacAddress master_address;
    MacAddress sync_address;
    std::uint32_t master_counter;
    std::uint32_t distance_to_master;
    std::uint32_t master_metric;
    std::uint32_t self_metric;
    std::uint32_t self_counter;
};

CodecResult<ActionBody> parse_action_body(std::span<const std::uint8_t> body);
CodecResult<Bytes> serialize_action_body(const ActionBody& body);
// Presence/structural validation and serialization of caller-supplied OWL
// PSF/MIF TLVs. Duplicates and inter-TLV consistency are not checked here.
// This is not a node-state generator or proof of live Discovery readiness.
// No clock/channel/flags/election/identity/unknown field is synthesized here.
CodecResult<Bytes> generate_discovery(const ActionBody& body);

CodecResult<VersionInfo> decode_version(const Tlv& tlv);
CodecResult<ArpaInfo> decode_arpa(const Tlv& tlv);
CodecResult<ChannelSequence> decode_channel_sequence(const Tlv& tlv);
CodecResult<SyncInfo> decode_sync(const Tlv& tlv);
CodecResult<ElectionInfo> decode_election(const Tlv& tlv);
CodecResult<ElectionV2Info> decode_election_v2(const Tlv& tlv);

struct ActionMpdu {
    MacAddress destination;
    MacAddress source;
    MacAddress bssid;
    std::uint16_t sequence;
    bool retry;
    ActionBody body;
};
// Caller supplies an already extracted 802.11 management MPDU and explicit FCS
// presence. FCS is stripped, not verified. No PCAP/Npcap or WDI interpretation.
CodecResult<ActionMpdu> parse_action_mpdu(std::span<const std::uint8_t> mpdu,
                                         bool has_fcs);

} // namespace awdlwin::wire
