#pragma once
#include "awdl_mdns_names.h"
namespace awdlwin::mdns {
struct BrowseQuery {
    wire::MacAddress source;
    ip::Address local_address;
    std::uint16_t local_port, id;
    wire::Bytes ip_packet, mpdu;
    BrowseService service{BrowseService::airdrop};
};
// Bounded QM multicast (5353, ID zero) or legacy one-shot (ephemeral port) PTR query.
// Derives OWL's link-local address from the explicit source MAC. This does not
// configure/claim an OS address or submit a radio request.
wire::CodecResult<BrowseQuery> build_browse_query(const wire::MacAddress& source,
    std::uint16_t local_port,std::uint16_t id,std::uint16_t awdl_sequence,std::uint16_t mac_sequence,
    BrowseService service=BrowseService::airdrop);
ip::Result<ip::Mdns> parse_browse_reply(const BrowseQuery& query,const ip::Packet& packet);
} // namespace awdlwin::mdns
