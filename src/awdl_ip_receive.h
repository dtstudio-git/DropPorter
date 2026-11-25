#pragma once
#include "awdl_data.h"
#include <optional>
#include <string>
#include <variant>

namespace awdlwin::ip {
using Address = std::array<std::uint8_t,16>;
enum class Error { malformed_ipv6, unsupported_extension, malformed_udp, checksum,
                   malformed_dns, size_limit, not_mdns };
template<class T> using Result = std::variant<T,Error>;
struct Udp { std::uint16_t source_port{}, destination_port{}; wire::Bytes payload; };
struct Packet {
    Address source{}, destination{};
    std::uint8_t hop_limit{}, protocol{};
    std::optional<Udp> udp;
};
// Exact IPv6 length; bounded Hop-by-Hop/Destination Options traversal. No
// fragmentation, Routing, AH, ESP or jumbograms. UDP is checksum-validated.
// Other upper protocols are identified only, never presented as validated UDP.
Result<Packet> parse_ipv6(std::span<const std::uint8_t> bytes);
bool destination_matches(const Address& ip, const wire::MacAddress& ethernet,
                         const wire::MacAddress& self) noexcept;
// This checks Ethernet delivery / multicast mapping, not local unicast IPv6
// address ownership. No host address has been configured by this receive API.

// Labels are retained separately: a DNS-SD instance label may contain dots.
using Name = std::vector<std::string>;
struct Question { Name name; std::uint16_t type{}, klass{}; bool unicast_response{}; };
struct Record {
    Name name;
    std::uint16_t type{}, klass{};
    bool cache_flush{};
    std::uint32_t ttl{};
    wire::Bytes rdata;
    std::optional<Name> target; // NS / CNAME / PTR / SRV / DNAME, expanded.
    std::uint16_t priority{}, weight{}, port{}; // SRV
    std::vector<wire::Bytes> text; // TXT, retains binary strings.
};
struct Mdns {
    std::uint16_t id{}, flags{};
    std::vector<Question> questions;
    std::vector<Record> answers, authorities, additionals;
};
// Receive-side DNS decoding only. Does not populate a service cache or reply.
// Rejects malformed known RDATA and compression cycles before publishing.
Result<Mdns> parse_mdns(const Packet& packet);
// Legacy one-shot mDNS uses an ephemeral local port and echoed DNS ID. This
// path admits only a matching unicast reply from an IPv6 link-local source;
// the active query owner must additionally match its echoed question/deadline.
Result<Mdns> parse_mdns_legacy_reply(const Packet& packet,const Address& local,
                                    std::uint16_t local_port,std::uint16_t id);
bool is_airdrop_name(const Name& name) noexcept;
} // namespace awdlwin::ip
