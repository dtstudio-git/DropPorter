#include "awdl_ip_receive.h"
#include <algorithm>

namespace awdlwin::ip {
namespace {
using View = std::span<const std::uint8_t>;
std::uint16_t u16(View b,std::size_t p) { return std::uint16_t((b[p]<<8)|b[p+1]); }
std::uint32_t u32(View b,std::size_t p) { return (std::uint32_t(u16(b,p))<<16)|u16(b,p+2); }
std::uint32_t sum(View b) {
    std::uint32_t s=0;
    for(std::size_t i=0;i<b.size();i+=2)s+=std::uint32_t(b[i])<<8 | (i+1<b.size()?b[i+1]:0);
    return s;
}
// A backward-only compression pointer both follows RFC 1035's prior occurrence
// rule and bounds traversal. The step bound also covers malformed label loops.
bool name(View b,std::vector<bool>& starts,std::size_t& cursor,std::size_t end,Name& out) {
    std::size_t p=cursor,limit=end,expanded=0; // mDNS permits 255 + terminal zero.
    bool jumped=false;
    for(unsigned steps=0;steps<256;++steps) {
        if(p>=limit)return false;
        starts[p]=true;
        const auto n=b[p++];
        if(!n){if(!jumped)cursor=p;return true;}
        if((n&0xc0)==0xc0) {
            if(p>=limit)return false;
            const auto target=std::size_t((n&0x3f)<<8)|b[p++];
            if(target<12||target>=p-2||!starts[target])return false;
            if(!jumped)cursor=p;
            jumped=true;p=target;limit=b.size();continue;
        }
        if((n&0xc0)||n>limit-p||expanded+1+n>255)return false;
        out.emplace_back(reinterpret_cast<const char*>(b.data()+p),n);
        p+=n;expanded+=1+n;
    }
    return false;
}
bool records(View b,std::vector<bool>& starts,std::size_t& p,std::uint16_t count,std::vector<Record>& out) {
    for(unsigned i=0;i<count;++i) {
        Record r;
        if(!name(b,starts,p,b.size(),r.name)||b.size()-p<10)return false;
        r.type=u16(b,p);const auto cls=u16(b,p+2);
        // OPT uses the full CLASS as its UDP size, not cache-flush semantics.
        r.klass=r.type==41?cls:cls&0x7fff;r.cache_flush=r.type!=41&&(cls&0x8000)!=0;
        r.ttl=u32(b,p+4);const auto length=u16(b,p+8);p+=10;
        if(length>b.size()-p)return false;
        const auto end=p+length;
        r.rdata.assign(b.begin()+p,b.begin()+end);
        if(r.type==2||r.type==5||r.type==12||r.type==33||r.type==39) {
            auto q=p;
            if(r.type==33) {
                if(length<7)return false;
                r.priority=u16(b,q);r.weight=u16(b,q+2);r.port=u16(b,q+4);q+=6;
            }
            Name target;
            if(!name(b,starts,q,end,target)||q!=end)return false;
            r.target=std::move(target);
        } else if(r.type==16) {
            auto q=p;
            while(q<end){const auto n=b[q++];if(n>end-q)return false;
                r.text.emplace_back(b.begin()+q,b.begin()+q+n);q+=n;}
        } else if((r.type==28&&length!=16)||(r.type==1&&length!=4))return false;
        p=end;out.push_back(std::move(r));
    }
    return true;
}
} // namespace
Result<Packet> parse_ipv6(View b) {
    if(b.size()<40||(b[0]>>4)!=6||b.size()!=40u+u16(b,4))return Error::malformed_ipv6;
    Packet result;
    std::copy_n(b.begin()+8,16,result.source.begin());
    std::copy_n(b.begin()+24,16,result.destination.begin());
    const Address unspecified{};
    Address loopback{};loopback.back()=1;
    if(result.source[0]==0xff||result.source==loopback||
       result.destination==unspecified||result.destination==loopback)return Error::malformed_ipv6;
    result.hop_limit=b[7];auto next=b[6];std::size_t p=40;
    unsigned extensions=0;
    while(next==0||next==60) {
        if(++extensions>8)return Error::size_limit;
        if(next==0&&p!=40)return Error::malformed_ipv6;
        if(b.size()-p<2)return Error::malformed_ipv6;
        const auto length=8u*(std::size_t(b[p+1])+1);
        if(length>b.size()-p)return Error::malformed_ipv6;
        // Validate option boundaries; do not silently process unknown options
        // whose action bits require discard. Jumbo Payload is unsupported.
        for(std::size_t q=p+2;q<p+length;) {
            const auto type=b[q++];if(!type)continue;
            if(q==p+length)return Error::malformed_ipv6;
            const auto n=b[q++];if(n>p+length-q)return Error::malformed_ipv6;
            if(type==0xc2||(type&0xc0))return Error::unsupported_extension;
            q+=n;
        }
        next=b[p];p+=length;
    }
    if(next==43||next==44||next==50||next==51)return Error::unsupported_extension;
    result.protocol=next;
    if(next==17) {
        if(result.source==unspecified)return Error::malformed_ipv6;
        const auto udp=b.subspan(p);
        if(udp.size()<8||u16(udp,4)!=udp.size())return Error::malformed_udp;
        if(u16(udp,6)==0)return Error::checksum;
        auto s=sum(b.subspan(8,32))+sum(udp)+static_cast<std::uint32_t>(udp.size())+17;
        while(s>>16)s=(s&0xffff)+(s>>16);
        if(s!=0xffff)return Error::checksum;
        result.udp=Udp{u16(udp,0),u16(udp,2),wire::Bytes(udp.begin()+8,udp.end())};
    }
    return result;
}
bool destination_matches(const Address& ip,const wire::MacAddress& mac,const wire::MacAddress& self) noexcept {
    if(ip[0]==0xff)return mac==wire::MacAddress{0x33,0x33,ip[12],ip[13],ip[14],ip[15]};
    return mac==self;
}
namespace {
Result<Mdns> dns_payload(View b) {
    if(b.size()>8952)return Error::size_limit;
    if(b.size()<12)return Error::malformed_dns;
    Mdns result;result.id=u16(b,0);result.flags=u16(b,2);
    if((result.flags&0x780f)!=0)return Error::malformed_dns;
    const auto questions=u16(b,4),answers=u16(b,6),authorities=u16(b,8),additionals=u16(b,10);
    if(std::uint32_t(questions)+answers+authorities+additionals>512)return Error::size_limit;
    std::size_t p=12;
    std::vector<bool> starts(b.size(),false);
    for(unsigned i=0;i<questions;++i) {
        Question q;
        if(!name(b,starts,p,b.size(),q.name)||b.size()-p<4)return Error::malformed_dns;
        q.type=u16(b,p);const auto cls=u16(b,p+2);q.klass=cls&0x7fff;q.unicast_response=(cls&0x8000)!=0;p+=4;
        result.questions.push_back(std::move(q));
    }
    if(!records(b,starts,p,answers,result.answers)||!records(b,starts,p,authorities,result.authorities)||
       !records(b,starts,p,additionals,result.additionals)||p!=b.size())return Error::malformed_dns;
    return result;
}
} // namespace
Result<Mdns> parse_mdns(const Packet& packet) {
    if(!packet.udp||packet.udp->destination_port!=5353)return Error::not_mdns;
    const auto& udp=*packet.udp;
    if(packet.destination[0]==0xff) {
        Address multicast{};multicast[0]=0xff;multicast[1]=2;multicast[15]=0xfb;
        if(packet.destination!=multicast)return Error::not_mdns;
    }
    // RFC 6762 section 11: multicast establishes locality. Unicast is limited
    // to link-local sources until an interface/on-link prefix owner exists.
    if(packet.destination[0]!=0xff&&
       !(packet.source[0]==0xfe&&(packet.source[1]&0xc0)==0x80))return Error::not_mdns;
    auto result=dns_payload(udp.payload);
    if(const auto* m=std::get_if<Mdns>(&result);m&&(m->flags&0x8000)&&udp.source_port!=5353)
        return Error::malformed_dns;
    return result;
}
Result<Mdns> parse_mdns_legacy_reply(const Packet& packet,const Address& local,
                                    std::uint16_t port,std::uint16_t id) {
    if(port<49152||!packet.udp||packet.udp->source_port!=5353||packet.udp->destination_port!=port||
       packet.destination!=local||packet.source[0]!=0xfe||(packet.source[1]&0xc0)!=0x80)
        return Error::not_mdns;
    auto result=dns_payload(packet.udp->payload);
    if(const auto* m=std::get_if<Mdns>(&result);m&&((m->flags&0x8000)==0||m->id!=id))return Error::not_mdns;
    return result;
}
bool is_airdrop_name(const Name& n) noexcept {
    const auto eq=[](const std::string& s,const char* expected) {
        std::size_t i=0;for(;i<s.size()&&expected[i];++i){auto c=static_cast<unsigned char>(s[i]);
            if(c>='A'&&c<='Z')c+=32;if(c!=static_cast<unsigned char>(expected[i]))return false;}
        return i==s.size()&&expected[i]==0;
    };
    return n.size()>=3&&eq(n[n.size()-3],"_airdrop")&&eq(n[n.size()-2],"_tcp")&&eq(n.back(),"local");
}
} // namespace awdlwin::ip
