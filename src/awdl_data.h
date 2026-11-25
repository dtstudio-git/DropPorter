#pragma once

#include "awdl_discovery.h"

namespace awdlwin::wire {

// Decapsulated MSDU, ready for an explicit upper-layer consumer. No OS network
// injection, peer admission, IPv6 validation or decryption occurs in this codec.
struct DataMsdu {
    MacAddress destination;
    MacAddress source;
    std::uint16_t awdl_sequence;
    std::uint16_t ether_type;
    Bytes payload;
};

struct DataMpdu {
    MacAddress destination;
    MacAddress source;
    MacAddress bssid;
    std::uint16_t sequence;
    bool retry;
    bool qos;
    bool aggregated;
    std::vector<DataMsdu> msdus;
};

// Cheap recognition only. A true result still requires the full parser and a
// caller-verified FCS. Does not infer FCS presence or trust the BSSID alone.
bool is_awdl_data_candidate(std::span<const std::uint8_t> mpdu);

// Pinned OWL rx.c/tx.c data encapsulation: plain Data or QoS Data, optional
// A-MSDU, Apple SNAP + eight-byte AWDL header. All subframes must parse before
// a result is published. Bounds: 65535-byte MPDU, at most 64 MSDUs. Protected,
// fragmented, DS-addressed and HT-control frames are explicitly unsupported.
// FCS presence is supplied by the caller; like parse_action_mpdu this strips
// but does not verify FCS. Exact owned payload bytes are retained.
CodecResult<DataMpdu> parse_awdl_data_mpdu(std::span<const std::uint8_t> mpdu,
                                         bool has_fcs);

// Plain, unprotected, direct Data with Apple SNAP/AWDL encapsulation and fixed
// AWDL BSSID. No FCS/radiotap; transport owns hardware sequence/encryption policy.
CodecResult<Bytes> build_awdl_data_mpdu(const DataMsdu& msdu,std::uint16_t mac_sequence);

} // namespace awdlwin::wire
