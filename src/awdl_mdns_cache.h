#pragma once
#include "awdl_mdns_names.h"

namespace awdlwin::mdns {
enum class Update { applied, invalid_time, capacity, invalid_record };
struct Endpoint {
    wire::MacAddress peer;
    BrowseService service;
    ip::Name instance, host;
    ip::Address address;
    std::uint16_t port, priority, weight;
    std::vector<wire::Bytes> text;
    std::uint64_t expires_at_us;
    struct RecordReception {
        std::uint64_t ptr{},srv{},txt{},aaaa{};
    } record_received_at_us{};
};
struct Snapshot {std::vector<Endpoint> endpoints;bool truncated{};};
// Passive, source-scoped DNS-SD cache, not an authenticated peer identity or
// a network route. The caller supplies serialized same-session monotonic time
// and admits CRC/IP/UDP/DNS and source peers before calling ingest().
class Cache {
    struct Entry {
        wire::MacAddress peer;
        ip::Record record;
        std::uint64_t received_at_us, expires_at_us;
    };
    std::vector<Entry> entries_;
    std::uint64_t last_at_us_{};
public:
    static constexpr std::size_t capacity=256;
    // Atomic update; queries (including known-answer lists) are not assertions.
    // PTR/SRV/TXT/AAAA only. Names compare ASCII-case-insensitively by label;
    // compressed wire offsets are not used as record identity.
    Update ingest(const wire::MacAddress& peer,const ip::Mdns& message,std::uint64_t now_us);
    void expire(std::uint64_t now_us);
    void remove_peer(const wire::MacAddress& peer);
    std::vector<wire::MacAddress> peers() const;
    Snapshot endpoints(std::uint64_t now_us) const;
    std::size_t size() const noexcept {return entries_.size();}
};
} // namespace awdlwin::mdns
