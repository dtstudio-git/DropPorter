#include "awdl_mdns_query.h"
#include <algorithm>

namespace awdlwin::mdns {
namespace {
void put16(wire::Bytes& b,std::size_t p,std::uint16_t n) {b[p]=std::uint8_t(n>>8);b[p+1]=std::uint8_t(n);}
std::uint32_t sum(std::span<const std::uint8_t> b) {
    std::uint32_t result=0;
    for(std::size_t i=0;i<b.size();i+=2)result+=(std::uint32_t(b[i])<<8)|(i+1<b.size()?b[i+1]:0);
    return result;
}
}
wire::CodecResult<BrowseQuery> build_browse_query(const wire::MacAddress& source,
    std::uint16_t port,std::uint16_t id,std::uint16_t awdl_sequence,std::uint16_t mac_sequence,
    BrowseService service) {
    using Result=wire::CodecResult<BrowseQuery>;
    if(service_label(service).empty()||(port<49152&&port!=5353)||(port==5353&&id!=0)||(source[0]&1)||
       std::all_of(source.begin(),source.end(),[](auto b){return b==0;}))
        return Result::failure(wire::CodecError::malformed_data);
    BrowseQuery result{source,{},port,id,{},{},service};
    auto& address=result.local_address;address[0]=0xfe;address[1]=0x80;
    address[8]=source[0]^2;address[9]=source[1];address[10]=source[2];address[11]=0xff;
    address[12]=0xfe;std::copy_n(source.begin()+3,3,address.begin()+13);
    wire::Bytes dns(12,0);put16(dns,0,id);dns[5]=1;
    for(const auto& label:service_name(service)) {
        dns.push_back(static_cast<std::uint8_t>(label.size()));
        dns.insert(dns.end(),label.begin(),label.end());
    }
    dns.insert(dns.end(),{0,0,12,0,1}); // PTR, IN; QM (no QU/legacy cache flags).
    auto& packet=result.ip_packet;packet.resize(48+dns.size(),0);packet[0]=0x60;
    put16(packet,4,static_cast<std::uint16_t>(8+dns.size()));packet[6]=17;packet[7]=255;
    std::copy(address.begin(),address.end(),packet.begin()+8);packet[24]=0xff;packet[25]=2;packet[39]=0xfb;
    put16(packet,40,port);put16(packet,42,5353);put16(packet,44,static_cast<std::uint16_t>(8+dns.size()));
    std::copy(dns.begin(),dns.end(),packet.begin()+48);
    auto checksum=sum(std::span(packet).subspan(8,32))+sum(std::span(packet).subspan(40))+
        static_cast<std::uint32_t>(8+dns.size())+17;
    while(checksum>>16)checksum=(checksum&0xffff)+(checksum>>16);
    const auto complement=static_cast<std::uint16_t>(checksum^0xffff);
    put16(packet,46,complement?complement:0xffff);
    auto frame=wire::build_awdl_data_mpdu({{0x33,0x33,0,0,0,0xfb},source,awdl_sequence,0x86dd,packet},mac_sequence);
    if(!frame)return Result::failure(frame.error(),frame.offset());
    result.mpdu=std::move(frame.value());return Result::success(std::move(result));
}
ip::Result<ip::Mdns> parse_browse_reply(const BrowseQuery& query,const ip::Packet& packet) {
    if(query.local_port==5353) {
        ip::Address group{};group[0]=0xff;group[1]=2;group[15]=0xfb;
        if(query.id!=0||!packet.udp||packet.udp->source_port!=5353||
           packet.udp->destination_port!=5353||packet.destination!=group)return ip::Error::not_mdns;
        auto result=ip::parse_mdns(packet);
        if(const auto* m=std::get_if<ip::Mdns>(&result);m&&((m->flags&0x8000)==0||m->id!=0))
            return ip::Error::not_mdns;
        // QM responses need not echo a question and may carry cache-flush bits.
        // ID zero cannot distinguish a response from an unsolicited announcement.
        return result;
    }
    auto result=ip::parse_mdns_legacy_reply(packet,query.local_address,query.local_port,query.id);
    if(const auto* m=std::get_if<ip::Mdns>(&result)) {
        if(m->questions.size()!=1||m->questions[0].type!=12||m->questions[0].klass!=1||
           m->questions[0].unicast_response||
           !equal_name(m->questions[0].name,service_name(query.service)))return ip::Error::not_mdns;
        for(const auto* section:{&m->answers,&m->authorities,&m->additionals})
            for(const auto& r:*section)if(r.cache_flush)return ip::Error::malformed_dns;
    }
    return result;
}
} // namespace awdlwin::mdns
