#pragma once
#include "../../src/awdl_mdns_cache.h"
#include <algorithm>
#include <optional>

namespace tx10ub::tcp {
// Bounded, payload-free connection diagnostic, not a TCP stream or TLS stack.
// RFC 9293: correlate SYN-ACK by tuple and ACK, then ACK and reset this test only.
struct Segment {
    awdlwin::ip::Address source{},destination{};
    std::uint16_t source_port{},destination_port{};
    std::uint32_t sequence{},acknowledgement{};
    std::uint8_t flags{};
    std::size_t payload_size{};
};
inline std::uint16_t read16(std::span<const std::uint8_t> b,std::size_t p) {
    return std::uint16_t((std::uint16_t(b[p])<<8)|b[p+1]);
}
inline std::uint32_t read32(std::span<const std::uint8_t> b,std::size_t p) {
    return (std::uint32_t(read16(b,p))<<16)|read16(b,p+2);
}
inline std::uint32_t sum(std::span<const std::uint8_t> b) {
    std::uint32_t s=0;
    for(std::size_t i=0;i<b.size();i+=2)s+=(std::uint32_t(b[i])<<8)|(i+1<b.size()?b[i+1]:0);
    return s;
}
inline std::uint16_t fold(std::uint32_t s) {
    while(s>>16)s=(s&0xffff)+(s>>16);
    return static_cast<std::uint16_t>(s);
}
inline bool link_local(const awdlwin::ip::Address& a) {return a[0]==0xfe&&(a[1]&0xc0)==0x80;}
inline awdlwin::ip::Address local_address(const awdlwin::wire::MacAddress& mac) {
    awdlwin::ip::Address a{0xfe,0x80};
    a[8]=mac[0]^2;a[9]=mac[1];a[10]=mac[2];a[11]=0xff;a[12]=0xfe;
    std::copy_n(mac.begin()+3,3,a.begin()+13);return a;
}
inline std::optional<Segment> parse(std::span<const std::uint8_t> ip) {
    // No extension/fragment, Fast Open, or general stream reassembly is claimed.
    if(ip.size()<60||ip.size()>65575||(ip[0]>>4)!=6||ip[6]!=6||
       std::size_t(read16(ip,4))+40!=ip.size())return std::nullopt;
    const auto tcp=ip.subspan(40);
    const auto header=std::size_t(tcp[12]>>4)*4;
    if(header<20||header>tcp.size()||(tcp[12]&0x0f)!=0)return std::nullopt;
    if(fold(sum(ip.subspan(8,32))+sum(tcp)+static_cast<std::uint32_t>(tcp.size())+6)!=0xffff)
        return std::nullopt;
    for(std::size_t p=20;p<header;) {
        const auto kind=tcp[p++];if(kind==0)break;if(kind==1)continue;
        if(p>=header||tcp[p]<2||tcp[p]>header-(p-1))return std::nullopt;
        p+=tcp[p]-1;
    }
    Segment s;
    std::copy_n(ip.begin()+8,16,s.source.begin());std::copy_n(ip.begin()+24,16,s.destination.begin());
    s.source_port=read16(tcp,0);s.destination_port=read16(tcp,2);
    s.sequence=read32(tcp,4);s.acknowledgement=read32(tcp,8);s.flags=tcp[13];
    s.payload_size=tcp.size()-header;return s;
}
class ConnectCheck {
    awdlwin::wire::MacAddress self_;
    awdlwin::mdns::Endpoint endpoint_;
    std::uint16_t port_;
    std::uint32_t isn_;
    std::optional<Segment> reply_;
public:
    enum class Packet { syn, ack, reset };
    ConnectCheck(const awdlwin::wire::MacAddress& self,const awdlwin::mdns::Endpoint& endpoint,
                 std::uint16_t localPort,std::uint32_t isn)
        :self_(self),endpoint_(endpoint),port_(localPort),isn_(isn){}
    bool valid()const {
        const auto unicast=[](const auto& mac){return (mac[0]&1)==0&&
            std::any_of(mac.begin(),mac.end(),[](auto b){return b!=0;});};
        return unicast(self_)&&unicast(endpoint_.peer)&&self_!=endpoint_.peer&&
            endpoint_.service==awdlwin::mdns::BrowseService::airdrop&&endpoint_.port!=0&&
            port_>=49152&&link_local(endpoint_.address)&&endpoint_.address!=local_address(self_);
    }
    bool receive(const awdlwin::wire::MacAddress& peer,std::span<const std::uint8_t> ip) {
        const auto s=parse(ip);
        if(!valid()||peer!=endpoint_.peer||!s||s->source!=endpoint_.address||
           s->destination!=local_address(self_)||s->source_port!=endpoint_.port||
           s->destination_port!=port_||s->acknowledgement!=isn_+1u||s->payload_size!=0||
           (s->flags!=0x12&&s->flags!=0x14))return false;
        // A duplicate SYN-ACK is harmless; a later segment cannot rewrite the accepted tuple/ISN.
        if(reply_)return reply_->sequence==s->sequence&&reply_->flags==s->flags;
        reply_=s;return true;
    }
    bool syn_ack_received()const{return reply_&&reply_->flags==0x12;}
    bool refused()const{return reply_&&reply_->flags==0x14;}
    const awdlwin::mdns::Endpoint& endpoint()const{return endpoint_;}
    awdlwin::wire::CodecResult<awdlwin::wire::Bytes> frame(Packet kind,std::uint16_t awdlSequence)const {
        using Result=awdlwin::wire::CodecResult<awdlwin::wire::Bytes>;
        if(!valid()||(kind!=Packet::syn&&!syn_ack_received()))
            return Result::failure(awdlwin::wire::CodecError::malformed_data);
        const std::size_t tcpLength=kind==Packet::syn?24:20;
        awdlwin::wire::Bytes ip(40+tcpLength,0);ip[0]=0x60;ip[5]=static_cast<std::uint8_t>(tcpLength);
        ip[6]=6;ip[7]=64;const auto local=local_address(self_);
        std::copy(local.begin(),local.end(),ip.begin()+8);
        std::copy(endpoint_.address.begin(),endpoint_.address.end(),ip.begin()+24);
        const auto put16=[&](std::size_t p,std::uint16_t v){ip[p]=std::uint8_t(v>>8);ip[p+1]=std::uint8_t(v);};
        const auto put32=[&](std::size_t p,std::uint32_t v){put16(p,std::uint16_t(v>>16));put16(p+2,std::uint16_t(v));};
        put16(40,port_);put16(42,endpoint_.port);put32(44,kind==Packet::syn?isn_:isn_+1u);
        if(kind!=Packet::syn)put32(48,reply_->sequence+1u);
        ip[52]=std::uint8_t((tcpLength/4)<<4);
        ip[53]=kind==Packet::syn?2:kind==Packet::ack?0x10:0x14;put16(54,65535);
        if(kind==Packet::syn){ip[60]=2;ip[61]=4;put16(62,1220);} // IPv6 minimum MTU minus IP/TCP headers.
        put16(56,static_cast<std::uint16_t>(~fold(sum(std::span(ip).subspan(8,32))+
            sum(std::span(ip).subspan(40))+static_cast<std::uint32_t>(tcpLength)+6)));
        return awdlwin::wire::build_awdl_data_mpdu({endpoint_.peer,self_,awdlSequence,0x86dd,std::move(ip)},0);
    }
};
} // namespace tx10ub::tcp
