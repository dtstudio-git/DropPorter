#pragma once
#include "../src/awdl_mdns_query.h"
#include <cstdio>
#include <optional>
#include <stdexcept>
#include <utility>

namespace tx10ub::airdrop {
class ReceiveDiscoveryRound {
    using MacAddress = awdlwin::wire::MacAddress;
    static constexpr std::uint64_t RequesterGatherMs = 250;
    static constexpr std::uint64_t RequesterLifetimeMs = 1500;
    // Allow a short quiet interval between /Discover and a separate /Ask.
    static constexpr std::uint64_t ReopenQuietMs = 4000;
    std::optional<MacAddress> requester_;
    std::uint64_t firstRequest_{}, lastRequest_{};
    std::optional<std::uint64_t> lastOther_, reopenAt_;
    std::optional<MacAddress> widePeer_;
    std::optional<std::uint64_t> wideOtherRequest_;
public:
    void observe(const MacAddress& peer, std::uint64_t now) {
        if (widePeer_) {
            if (peer == *widePeer_)
                reopenAt_ = now + ReopenQuietMs;
            else
                wideOtherRequest_ = now;
            return;
        }
        if (!requester_ || now - lastRequest_ >= RequesterLifetimeMs) {
            requester_ = peer;
            firstRequest_ = lastRequest_ = now;
        } else if (*requester_ == peer) {
            lastRequest_ = now;
        } else {
            lastOther_ = now;
        }
    }
    std::optional<MacAddress> single_requester(std::uint64_t now) const {
        if (reopenAt_ || !requester_ || now - lastRequest_ >= RequesterLifetimeMs ||
            now - firstRequest_ < RequesterGatherMs ||
            (lastOther_ && now - *lastOther_ < RequesterLifetimeMs)) return std::nullopt;
        return requester_;
    }
    void channel_attempted(std::uint64_t now, std::optional<MacAddress> widePeer = std::nullopt) {
        widePeer_ = widePeer;
        reopenAt_ = now + ReopenQuietMs;
    }
    const std::optional<MacAddress>& wide_peer() const { return widePeer_; }
    void tcp_ended(std::uint64_t now, bool terminalResponse) {
        if (terminalResponse)
            widePeer_.reset();
        reopenAt_ = now + (terminalResponse ? 0 : ReopenQuietMs);
    }
    bool should_reopen(std::uint64_t now, bool widePeerPresent = false) const {
        if (widePeer_ && wideOtherRequest_ && now - *wideOtherRequest_ < RequesterLifetimeMs)
            return true;
        return reopenAt_ && now >= *reopenAt_ && !(widePeer_ && widePeerPresent);
    }
    void reset() { *this = {}; }
};

// DNS-SD AirDrop advertisement, encoded without DNS compression. The existing
// AWDL serializer remains the only Ethernet/802.11 data frame builder.
class ReceiveMdns {
    awdlwin::wire::MacAddress self_;
    awdlwin::ip::Address local_{};
    awdlwin::ip::Name instance_,host_;
    std::optional<std::uint64_t> lastAnnouncement_;
    bool withdrawing_{}, serviceActionSent_{}, withdrawalActionSent_{};
    std::optional<std::pair<awdlwin::wire::MacAddress, unsigned>> link_;
    // RFC 6762 §8.3 allows a startup series with doubling intervals.
    static constexpr std::array<std::uint64_t, 4> AnnouncementDelays{0, 1000, 2000, 4000};
    static constexpr std::uint64_t ListeningRefreshIntervalMs = 10000;
    unsigned announcementsOnLink_{};
    static void u16(awdlwin::wire::Bytes& b,unsigned n){b.push_back(std::uint8_t(n>>8));b.push_back(std::uint8_t(n));}
    static void u32(awdlwin::wire::Bytes& b,unsigned n){u16(b,n>>16);u16(b,n);}
    static void name(awdlwin::wire::Bytes& b,const awdlwin::ip::Name& n){for(const auto& s:n){b.push_back(std::uint8_t(s.size()));b.insert(b.end(),s.begin(),s.end());}b.push_back(0);}
    void record(awdlwin::wire::Bytes& b,const awdlwin::ip::Name& n,unsigned type,bool flush,const awdlwin::wire::Bytes& r) const {name(b,n);u16(b,type);u16(b,flush?0x8001:1);u32(b,withdrawing_ ? 0 : 120);u16(b,unsigned(r.size()));b.insert(b.end(),r.begin(),r.end());}
public:
    explicit ReceiveMdns(const awdlwin::wire::MacAddress& self):self_(self){
        const auto query=awdlwin::mdns::build_browse_query(self,5353,0,0,0);
        if(!query)throw std::runtime_error("receive_mdns_address");
        local_=query.value().local_address;
        char id[13]{};for(unsigned i=0;i<6;++i)std::snprintf(id+i*2,3,"%02x",self[i]);
        host_={id,"local"};instance_={id,"_airdrop","_tcp","local"};
    }
    void begin_withdrawal() { withdrawing_=true; }
    bool mdns_announced() const { return lastAnnouncement_.has_value(); }
    bool action_withdrawal_pending() const { return serviceActionSent_ && !withdrawalActionSent_; }
    bool withdrawal_action_sent() const { return withdrawalActionSent_; }
    void action_submitted() {
        if (withdrawing_) withdrawalActionSent_=true;
        else serviceActionSent_=true;
    }
    awdlwin::wire::Bytes service_action(std::span<const std::uint8_t> original) const {
        using namespace awdlwin::wire;
        auto parsed = parse_action_body(original);
        if (!parsed) throw std::invalid_argument("receive_service_action");
        auto& action = parsed.value();
        for (auto& tlv : action.tlvs) {
            // Service update indicator and compressed AirDrop service bitmap.
            if (tlv.type == 6) {
                if (withdrawing_) tlv.value = {0,0,0,2,0,0,0,0,0};
                else tlv.value = {0,0,0,1,0,0,0x20,8,0,4,0x40};
            }
        }
        if (action.header.subtype == ActionSubtype::mif) {
            // AWDL name dictionary suffixes: 7 = _airdrop._tcp.local, 12 = local, 0 = end.
            const auto label = [&](std::uint8_t suffix) {
                Bytes value{static_cast<std::uint8_t>(host_.front().size())};
                value.insert(value.end(),host_.front().begin(),host_.front().end());
                value.insert(value.end(),{0xc0,suffix});
                return value;
            };
            const auto appendRecord = [&](const Bytes& owner,std::uint8_t type,const Bytes& data) {
                // AWDL record sizes are little-endian, SRV port is network order.
                Bytes value{static_cast<std::uint8_t>(owner.size()+1),0};
                value.insert(value.end(),owner.begin(),owner.end());
                value.insert(value.end(),{type,static_cast<std::uint8_t>(data.size()),0,0,0});
                value.insert(value.end(),data.begin(),data.end());
                action.tlvs.push_back({2,std::move(value)});
            };
            const auto host=label(12);
            for(auto& tlv:action.tlvs) if(tlv.type==16){
                tlv.value={3};
                tlv.value.insert(tlv.value.end(),host.begin(),host.end());
            }
            if(!withdrawing_){
                appendRecord({0xc0,7},12,label(0));
                const auto instance=label(7);
                Bytes srv{0,0,0,0};
                u16(srv,8771);
                srv.insert(srv.end(),host.begin(),host.end());
                appendRecord(instance,33,srv);
                appendRecord(instance,16,{9,'f','l','a','g','s','=','1','3','6'});
            }
        }
        auto encoded=generate_discovery(action);
        if(!encoded)throw std::invalid_argument("receive_service_encoding");
        return std::move(encoded.value());
    }
    enum class Query { unrelated, local, otherInstanceLookup };
    Query classify_query(const awdlwin::ip::Mdns& m) const {
        if (m.flags & 0x8000) return Query::unrelated;
        auto result = Query::unrelated;
        for (const auto& q : m.questions) {
            if (q.klass != 1) continue;
            if (awdlwin::mdns::equal_name(q.name, {"_airdrop","_tcp","local"}) ||
                awdlwin::mdns::equal_name(q.name, instance_) || awdlwin::mdns::equal_name(q.name, host_))
                return Query::local;
            // A sender resolving another recipient is currently browsing AirDrop.
            // Only service resolution (TXT/SRV), not a name-ownership probe, is a hint.
            if (m.authorities.empty() && (q.type == 16 || q.type == 33) &&
                q.name.size() == 4 && awdlwin::ip::is_airdrop_name(q.name))
                result = Query::otherInstanceLookup;
        }
        return result;
    }
    void observe_link(const awdlwin::wire::MacAddress& peer, unsigned channel) noexcept {
        const auto observed = std::pair{peer, channel};
        if (link_ == observed) return;
        link_ = observed;
        announcementsOnLink_ = 0;
    }
    // now is monotonic milliseconds from the receive owner loop.
    bool announcement_due(std::uint64_t now,bool queryPending,bool waitingForConnection)const noexcept {
        if(!lastAnnouncement_)return true;
        if(now<*lastAnnouncement_||now-*lastAnnouncement_<1000)return false;
        if(queryPending)return true;
        const auto elapsed = now - *lastAnnouncement_;
        if(announcementsOnLink_ < AnnouncementDelays.size())
            return elapsed >= AnnouncementDelays[announcementsOnLink_];
        // Refresh discovery during receive standby, when an open share sheet
        // might have missed the initial series.
        return waitingForConnection && elapsed >= ListeningRefreshIntervalMs;
    }
    void announced(std::uint64_t now)noexcept {
        lastAnnouncement_=now;
        if(announcementsOnLink_<AnnouncementDelays.size())++announcementsOnLink_;
    }
    awdlwin::wire::Bytes frame(std::uint16_t sequence)const {
        awdlwin::wire::Bytes dns{0,0,0x84,0,0,0,0,4,0,0,0,0},r;
        name(r,instance_);record(dns,{"_airdrop","_tcp","local"},12,false,r);
        r.clear();u16(r,0);u16(r,0);u16(r,8771);name(r,host_);record(dns,instance_,33,true,r);
        r={9,'f','l','a','g','s','=','1','3','6'};record(dns,instance_,16,true,r);
        r.assign(local_.begin(),local_.end());record(dns,host_,28,true,r);
        awdlwin::wire::Bytes p(40,0);p[0]=0x60;p[6]=17;p[7]=255;
        std::copy(local_.begin(),local_.end(),p.begin()+8);p[24]=0xff;p[25]=2;p[39]=0xfb;
        const auto length=unsigned(8+dns.size());p[4]=std::uint8_t(length>>8);p[5]=std::uint8_t(length);
        u16(p,5353);u16(p,5353);u16(p,length);u16(p,0);p.insert(p.end(),dns.begin(),dns.end());
        unsigned checksum=length+17;for(std::size_t i=8;i<p.size();i+=2)checksum+=(unsigned(p[i])<<8)|(i+1<p.size()?p[i+1]:0);
        // Only IPv6 addresses and UDP datagram belong to the pseudo-header.
        // Bytes 8..39 contain both addresses, followed immediately by UDP.
        while(checksum>>16)checksum=(checksum&0xffff)+(checksum>>16);
        const auto value=std::uint16_t(checksum^0xffff);p[46]=std::uint8_t((value?value:0xffff)>>8);p[47]=std::uint8_t(value?value:0xffff);
        auto result=awdlwin::wire::build_awdl_data_mpdu({{0x33,0x33,0,0,0,0xfb},self_,sequence,0x86dd,p},0);
        if(!result)throw std::runtime_error("receive_mdns_frame");return std::move(result.value());
    }
};
}
