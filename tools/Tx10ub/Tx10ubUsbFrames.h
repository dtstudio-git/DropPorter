#pragma once
#include "../../src/awdl_discovery.h"
#include "../../src/awdl_data.h"
#include "../../src/awdl_ip_receive.h"
#include "Tx10ubTcpConnect.h"
#include "Tx10ubLinkMtu.h"
#include <algorithm>
#include <array>
#include <functional>
#include <span>
#include <stdexcept>

// Experimental TX10UB USB ingress decoder, not a WDI notification adapter.
// USBPcap 1.5.4.0 USBPcap.h; fixed rtwlanu6.sys decoder RVA 0x4D5C70.
// Offset/8-byte aggregation corroboration: Realtek RTL8851BU source,
// phl/hal_g6/rtl8851b/hal_trx_8851b.c and phl/hci/phl_trx_usb.c.
// No channel/TSFT/steady-clock correspondence is invented here.
namespace tx10ub::usb {
inline std::uint32_t le32(std::span<const std::uint8_t> b,std::size_t p) {
    return std::uint32_t(b[p])|(std::uint32_t(b[p+1])<<8)|
        (std::uint32_t(b[p+2])<<16)|(std::uint32_t(b[p+3])<<24);
}
inline std::uint16_t le16(std::span<const std::uint8_t> b,std::size_t p) {
    return std::uint16_t(b[p])|std::uint16_t(std::uint16_t(b[p+1])<<8);
}
inline bool valid_fcs(std::span<const std::uint8_t> b) {
    if(b.size()<4)return false;
    std::uint32_t crc=0xffffffffu;
    for(auto v:b.first(b.size()-4)) {
        crc^=v;
        for(unsigned bit=0;bit<8;++bit)crc=(crc>>1)^(0xedb88320u&(0u-(crc&1u)));
    }
    return ~crc==le32(b,b.size()-4);
}
// USB reports the FCS. The native-Wi-Fi receive indication may omit it.
enum class Fcs { present, stripped_by_ndis };
struct Frame {
    awdlwin::wire::ActionMpdu action;
    std::size_t body_bytes;
    std::uint64_t capture_utc_us;
    awdlwin::wire::Bytes mpdu;
    Fcs fcs=Fcs::present;
};
struct DataFrame {
    awdlwin::wire::DataMpdu data;
    std::uint64_t capture_utc_us;
    awdlwin::wire::Bytes mpdu;
    Fcs fcs=Fcs::present;
};
struct TxObservation {
    awdlwin::wire::MacAddress source_mac;
    awdlwin::wire::Bytes exact_action_body;
    std::uint64_t capture_utc_us; // USBPcap OUT submit event, never a steady-clock epoch.
};
struct DataTxObservation {
    awdlwin::wire::Bytes exact_mpdu; // Exact descriptor payload; no FCS in the observed query.
    std::uint64_t capture_utc_us; // USBPcap OUT submit event, never a steady-clock epoch.
};
struct Counts {
    std::uint64_t records{},bulk_in{},bulk_out{},wifi{},awdl{},rejected{},codec_rejected{};
    std::uint64_t target_bulk_out{};
    std::uint64_t awdl_candidates{},fcs_rejected{},parse_rejected{},roundtrip_rejected{};
    std::uint64_t data_candidates{},data_frames{},data_msdus{},data_fcs_rejected{},data_parse_rejected{};
    std::uint64_t action_out{},tx_rejected{},data_out{},data_tx_rejected{};
};
namespace detail {
inline constexpr awdlwin::wire::MacAddress awdl_bssid{0,0x25,0,0xff,0x94,0x73};
inline constexpr awdlwin::wire::MacAddress mdns_mac{0x33,0x33,0,0,0,0xfb};
inline constexpr awdlwin::ip::Address mdns_ipv6{0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfb};
inline constexpr std::array<std::uint8_t,8> apple_snap{0xaa,0xaa,3,0,0x17,0xf2,8,0};

// Cheap signature used only to classify an OUT packet as a possible mDNS
// query before reporting malformed descriptor or transfer metadata.
inline bool looks_like_mdns_query(std::span<const std::uint8_t> mpdu) {
    if(mpdu.size()<94||mpdu.size()>265)return false;
    const auto control=le16(mpdu,0);
    if((control&0x00fc)!=0x0008||(control&(0x0003|0x0300|0x0400|0x4000|0x8000))!=0||
       (le16(mpdu,22)&0x000f)!=0)return false;
    if(!std::equal(mdns_mac.begin(),mdns_mac.end(),mpdu.begin()+4)||
       !std::equal(awdl_bssid.begin(),awdl_bssid.end(),mpdu.begin()+16)||
       !std::equal(apple_snap.begin(),apple_snap.end(),mpdu.begin()+24)||
       mpdu[32]!=3||mpdu[33]!=4||mpdu[36]!=0||mpdu[37]!=0||
       mpdu[38]!=0x86||mpdu[39]!=0xdd)return false;
    if((mpdu[40]>>4)!=6||mpdu[46]!=17||mpdu[47]!=255||
       !std::equal(mdns_ipv6.begin(),mdns_ipv6.end(),mpdu.begin()+64)||
       mpdu[82]!=0x14||mpdu[83]!=0xe9)return false;
    return (mpdu[90]&0x80)==0&&(std::uint16_t(mpdu[92])<<8|mpdu[93])!=0;
}
inline bool valid_mdns_query(std::span<const std::uint8_t> mpdu) {
    if(!looks_like_mdns_query(mpdu))return false;
    auto decoded=awdlwin::wire::parse_awdl_data_mpdu(mpdu,false);
    if(!decoded||decoded.value().qos||decoded.value().aggregated||decoded.value().msdus.size()!=1||
       decoded.value().bssid!=awdl_bssid)return false;
    const auto& msdu=decoded.value().msdus.front();
    if(msdu.ether_type!=0x86dd||msdu.destination!=mdns_mac)return false;
    auto ip=awdlwin::ip::parse_ipv6(msdu.payload);
    if(!std::holds_alternative<awdlwin::ip::Packet>(ip))return false;
    const auto& packet=std::get<awdlwin::ip::Packet>(ip);
    if(packet.destination!=mdns_ipv6||packet.protocol!=17||packet.hop_limit!=255||!packet.udp||
       packet.udp->destination_port!=5353)return false;
    const auto& dns=packet.udp->payload;
    return dns.size()>=12&&(dns[2]&0x80)==0&&
        (std::uint16_t(dns[4])<<8|dns[5])!=0;
}
inline bool looks_like_mdns_response(std::span<const std::uint8_t> mpdu) {
    return mpdu.size()>=100&&mpdu.size()<=1320&&mpdu[0]==8&&mpdu[1]==0&&
        mpdu[46]==17&&mpdu[80]==0x14&&mpdu[81]==0xe9&&mpdu[82]==0x14&&mpdu[83]==0xe9&&
        (mpdu[90]&0x80)!=0;
}
inline bool valid_mdns_response(std::span<const std::uint8_t> mpdu) {
    if(!looks_like_mdns_response(mpdu))return false;
    const auto decoded=awdlwin::wire::parse_awdl_data_mpdu(mpdu,false);
    if(!decoded||decoded.value().qos||decoded.value().aggregated||decoded.value().msdus.size()!=1||
       decoded.value().bssid!=awdl_bssid)return false;
    const auto& msdu=decoded.value().msdus.front();
    if(msdu.ether_type!=0x86dd||msdu.destination!=mdns_mac)return false;
    const auto packet=awdlwin::ip::parse_ipv6(msdu.payload);
    const auto* ip=std::get_if<awdlwin::ip::Packet>(&packet);
    if(!ip||ip->source!=tx10ub::tcp::local_address(msdu.source)||ip->destination!=mdns_ipv6||
       ip->hop_limit!=255||!ip->udp||ip->udp->source_port!=5353||ip->udp->destination_port!=5353)return false;
    const auto parsed=awdlwin::ip::parse_mdns(*ip);
    const auto* dns=std::get_if<awdlwin::ip::Mdns>(&parsed);
    if(!dns||dns->id||!(dns->flags&0x8000)||dns->answers.empty()||dns->answers.size()>16)return false;
    return std::any_of(dns->answers.begin(),dns->answers.end(),[](const auto& record){
        return record.type==12&&awdlwin::ip::is_airdrop_name(record.name)&&record.target.has_value();
    });
}
inline bool looks_like_tcp_connect(std::span<const std::uint8_t> mpdu) {
    return (mpdu.size()==100||mpdu.size()==104)&&mpdu[0]==8&&mpdu[1]==0&&mpdu[46]==6;
}
inline bool valid_tcp_connect(std::span<const std::uint8_t> mpdu) {
    if(!looks_like_tcp_connect(mpdu))return false;
    const auto decoded=awdlwin::wire::parse_awdl_data_mpdu(mpdu,false);
    if(!decoded||decoded.value().bssid!=awdl_bssid||decoded.value().qos||decoded.value().aggregated||
       decoded.value().msdus.size()!=1||(decoded.value().destination[0]&1)!=0)return false;
    const auto& msdu=decoded.value().msdus.front();
    if(msdu.ether_type!=0x86dd)return false;
    const auto s=tx10ub::tcp::parse(msdu.payload);
    return s&&s->source==tx10ub::tcp::local_address(msdu.source)&&
        tx10ub::tcp::link_local(s->destination)&&s->source_port>=49152&&s->destination_port!=0&&
        s->payload_size==0&&(s->flags==2||s->flags==0x10||s->flags==0x14);
}
inline bool looks_like_stream_frame(std::span<const std::uint8_t> mpdu) {
    return mpdu.size()>=80&&mpdu.size()<=40+TX10UB_IPV6_MTU&&mpdu[0]==8&&mpdu[1]==0&&
        (mpdu[46]==6||mpdu[46]==58);
}
inline bool valid_stream_frame(std::span<const std::uint8_t> mpdu) {
    if(!looks_like_stream_frame(mpdu))return false;
    const auto data=awdlwin::wire::parse_awdl_data_mpdu(mpdu,false);
    if(!data||data.value().bssid!=awdl_bssid||data.value().msdus.size()!=1)return false;
    const auto& msdu=data.value().msdus.front();
    if(msdu.ether_type!=0x86dd)return false;
    const auto parsed=awdlwin::ip::parse_ipv6(msdu.payload);
    if(!std::holds_alternative<awdlwin::ip::Packet>(parsed))return false;
    const auto& ip=std::get<awdlwin::ip::Packet>(parsed);
    if(ip.source!=tx10ub::tcp::local_address(msdu.source)||
       !awdlwin::ip::destination_matches(ip.destination,msdu.destination,msdu.destination))return false;
    if(ip.protocol==6) {
        const auto s=tx10ub::tcp::parse(msdu.payload);
        return s&&tx10ub::tcp::link_local(s->destination)&&(s->source_port>=49152||s->source_port==8771)&&s->destination_port!=0&&
            (msdu.destination[0]&1)==0;
    }
    const auto& bytes=msdu.payload;
    return bytes[6]==58&&bytes.size()>=48&&
        tx10ub::tcp::fold(tx10ub::tcp::sum(std::span(bytes).subspan(8,32))+
        tx10ub::tcp::sum(std::span(bytes).subspan(40))+static_cast<std::uint32_t>(bytes.size()-40)+58)==0xffff;
}
} // namespace detail
class Decoder {
    static constexpr std::size_t limit=1024*1024;
    std::vector<std::uint8_t> pending_;
    unsigned address_;
    bool header_=false;
    std::uint32_t snaplen_=0;
    std::function<void(const Frame&)> sink_;
    std::function<void(const DataFrame&)> data_sink_;
    std::function<void(const TxObservation&)> tx_sink_;
    std::function<void(const DataTxObservation&)> data_tx_sink_;
    void outbound_transfer(std::span<const std::uint8_t> r,std::uint32_t original,std::uint64_t utc) {
        // The specific-packet entry uses the ordinary TX queue rather than
        // the old raw management queue. Validate Action MPDUs on either
        // known OUT endpoint; endpoint 0x0b is counted by the Data decoder.
        if(le16(r,19)!=address_||(r[21]!=0x05&&r[21]!=0x0b)||r[22]!=3)return;
        if(r[21]==0x05)++counts.bulk_out;
        const auto reject=[this]{++counts.tx_rejected;};
        const auto h=le16(r,0);
        if(h<27||h>r.size())return;
        const auto data=r.subspan(h);
        constexpr std::size_t descriptor_bytes=48;
        if(data.size()<descriptor_bytes+29)return;
        const auto candidate_mpdu=data.subspan(descriptor_bytes);
        if(candidate_mpdu[0]!=0xd0||candidate_mpdu[24]!=0x7f||candidate_mpdu[25]!=0||
           candidate_mpdu[26]!=0x17||candidate_mpdu[27]!=0xf2||candidate_mpdu[28]!=8)return;
        if(r[16]!=0||le32(r,10)!=0||le16(r,14)!=9) {reject();return;}
        if(h<27||h>r.size()||r.size()!=original||le32(r,23)!=r.size()-h) {reject();return;}
        const auto packet_bytes=static_cast<std::size_t>(le32(data,8)&0x3fffu);
        if(packet_bytes!=data.size()-descriptor_bytes) {reject();return;}
        const auto mpdu=data.subspan(descriptor_bytes,packet_bytes);
        const auto body=mpdu.subspan(24);
        if(body.size()<16||body.size()>265||(mpdu[1]&0x44)!=0) {reject();return;}
        auto action=awdlwin::wire::parse_action_mpdu(mpdu,false);
        if(!action) {reject();return;}
        auto serialized=awdlwin::wire::serialize_action_body(action.value().body);
        if(!serialized||serialized.value().size()!=body.size()||
           !std::equal(serialized.value().begin(),serialized.value().end(),body.begin())) {
            reject();return;
        }
        ++counts.action_out;
        if(tx_sink_)tx_sink_(TxObservation{action.value().source,
            awdlwin::wire::Bytes(body.begin(),body.end()),utc});
    }
    void outbound_data_transfer(std::span<const std::uint8_t> r,std::uint32_t original,std::uint64_t utc) {
        if(le16(r,19)!=address_||r[21]!=0x0b||r[22]!=3)return;
        ++counts.bulk_out;
        const auto h=le16(r,0);
        if(h<27||h>r.size())return;
        const auto data=r.subspan(h);
        // Realtek AX_TXD_PKT_OFFSET (DWORD0 bit 21) inserts an 8-byte
        // USB dummy after the fixed descriptor at bulk packet boundaries.
        // Corroborated by phl_trx_usb.c / txdesc.h and the pinned Windows
        // driver's 520-byte OUT carrying a 464-byte MPDU at offset 56.
        if(data.size()<48)return;
        const std::size_t descriptor_bytes=48+((le32(data,0)&(1u<<21))?8u:0u);
        if(data.size()<descriptor_bytes+80)return;
        const auto available_mpdu=data.subspan(descriptor_bytes);
        if(!detail::looks_like_mdns_query(available_mpdu)&&!detail::looks_like_mdns_response(available_mpdu)&&!detail::looks_like_tcp_connect(available_mpdu)&&
           !detail::looks_like_stream_frame(available_mpdu))return;
        const auto reject=[this]{++counts.data_tx_rejected;};
        if(r[16]!=0||le32(r,10)!=0||le16(r,14)!=9||r.size()!=original||
           le32(r,23)!=r.size()-h) {reject();return;}
        const auto packet_bytes=static_cast<std::size_t>(le32(data,8)&0x3fffu);
        if(packet_bytes<80||packet_bytes>1600||packet_bytes!=data.size()-descriptor_bytes) {reject();return;}
        const auto mpdu=data.subspan(descriptor_bytes,packet_bytes);
        if(!detail::valid_mdns_query(mpdu)&&!detail::valid_mdns_response(mpdu)&&!detail::valid_tcp_connect(mpdu)&&!detail::valid_stream_frame(mpdu)) {reject();return;}
        ++counts.data_out;
        if(data_tx_sink_)data_tx_sink_(DataTxObservation{
            awdlwin::wire::Bytes(mpdu.begin(),mpdu.end()),utc});
    }
    void transfer(std::span<const std::uint8_t> r,std::uint32_t original,std::uint64_t utc) {
        ++counts.records;
        if(r.size()<27){++counts.rejected;return;}
        if(!(r[16]&1)) {
            if(le16(r,19)==address_ && !(r[21]&0x80) && r[22]==3) ++counts.target_bulk_out;
            if(r[21]==0x0b)outbound_data_transfer(r,original,utc);
            outbound_transfer(r,original,utc);
            return;
        }
        const auto h=le16(r,0);
        if(le16(r,19)!=address_||r[21]!=0x84||r[22]!=3||!(r[16]&1)||le32(r,10)!=0||le16(r,14)!=9)return;
        ++counts.bulk_in;
        if(h<27||h>r.size()||r.size()!=original||le32(r,23)!=r.size()-h){++counts.rejected;return;}
        const auto data=r.subspan(h);
        for(std::size_t p=0;p<data.size();) {
            if(data.size()-p<16){++counts.rejected;return;}
            const auto word=le32(data,p);
            const auto type=(word>>24)&15;
            const std::size_t length=word&0x3fff;
            const std::size_t descriptor=(word>>31)?32:16;
            // MAC-info prefix size is not yet validated for this Windows image.
            if(length==0||((word&(1u<<23))&&type!=1)){++counts.rejected;return;}
            const std::size_t offset=descriptor+((word>>14)&3)*2+((word>>28)&7)*8;
            if(offset>data.size()-p||length>data.size()-p-offset){++counts.rejected;return;}
            const auto mpdu=data.subspan(p+offset,length);
            if(type==0) {
                ++counts.wifi;
                if(mpdu.size()>=32&&(mpdu[0]&0xfc)==0xd0&&
                   mpdu[24]==0x7f&&mpdu[25]==0&&mpdu[26]==0x17&&mpdu[27]==0xf2&&mpdu[28]==8) {
                    ++counts.awdl_candidates;
                    if(!valid_fcs(mpdu)){++counts.codec_rejected;++counts.fcs_rejected;}
                    else {
                        auto action=awdlwin::wire::parse_action_mpdu(mpdu,true);
                        if(!action){++counts.codec_rejected;++counts.parse_rejected;}
                        else {
                            auto body=awdlwin::wire::serialize_action_body(action.value().body);
                            if(!body||body.value().size()!=mpdu.size()-28||
                               !std::equal(body.value().begin(),body.value().end(),mpdu.begin()+24)) {
                                ++counts.codec_rejected;++counts.roundtrip_rejected;
                            }
                            else {++counts.awdl;sink_(Frame{std::move(action.value()),mpdu.size()-28,utc,
                                awdlwin::wire::Bytes(mpdu.begin(),mpdu.end())});}
                        }
                    }
                } else if(awdlwin::wire::is_awdl_data_candidate(mpdu)) {
                    ++counts.data_candidates;
                    if(!valid_fcs(mpdu))++counts.data_fcs_rejected;
                    else {
                        auto decoded=awdlwin::wire::parse_awdl_data_mpdu(mpdu,true);
                        if(!decoded)++counts.data_parse_rejected;
                        else {
                            ++counts.data_frames;
                            counts.data_msdus+=decoded.value().msdus.size();
                            if(data_sink_)data_sink_(DataFrame{std::move(decoded.value()),utc,
                                awdlwin::wire::Bytes(mpdu.begin(),mpdu.end())});
                        }
                    }
                }
            }
            const auto end=p+offset+length;
            if(end==data.size())return;
            const auto next=(end+7)&~std::size_t(7);
            if(next>=data.size())return;
            p=next;
        }
    }
public:
    Counts counts;
    Decoder(unsigned address,std::function<void(const Frame&)> sink,
            std::function<void(const DataFrame&)> dataSink={},
            std::function<void(const TxObservation&)> txSink={},
            std::function<void(const DataTxObservation&)> dataTxSink={})
        :address_(address),sink_(std::move(sink)),data_sink_(std::move(dataSink)),tx_sink_(std::move(txSink)),
         data_tx_sink_(std::move(dataTxSink)){}
    void feed(std::span<const std::uint8_t> input) {
        // Incremental reads need not end on PCAP record boundaries.
        if(input.size()>limit||pending_.size()>limit+16)throw std::runtime_error("usb_stream_size_limit");
        pending_.insert(pending_.end(),input.begin(),input.end());
        std::size_t p=0;
        if(!header_) {
            if(pending_.size()<24)return;
            const auto b=std::span<const std::uint8_t>(pending_);
            if(le32(b,0)!=0xa1b2c3d4||le16(b,4)!=2||le16(b,6)!=4||le32(b,20)!=249)
                throw std::runtime_error("unsupported_usb_pcap");
            snaplen_=le32(b,16);
            if(snaplen_==0||snaplen_>limit)throw std::runtime_error("usb_snaplen_limit");
            header_=true;p=24;
        }
        while(pending_.size()-p>=16) {
            const auto b=std::span<const std::uint8_t>(pending_);
            const auto size=le32(b,p+8),original=le32(b,p+12),us=le32(b,p+4);
            if(size>snaplen_||us>=1000000)throw std::runtime_error("malformed_usb_pcap_record");
            if(size>pending_.size()-p-16)break;
            transfer(b.subspan(p+16,size),original,std::uint64_t(le32(b,p))*1000000+us);
            p+=16+size;
        }
        pending_.erase(pending_.begin(),pending_.begin()+static_cast<std::ptrdiff_t>(p));
    }
    bool complete()const{return header_&&pending_.empty();}
};
}
