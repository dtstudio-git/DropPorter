#pragma once
#include "Tx10ubUsbClock.h"
#include "Tx10ubUsbFrames.h"
#include "../../src/awdl_discovery_session.h"
#include "../../src/awdl_ip_receive.h"
#include "../../src/awdl_mdns_cache.h"
#include "../../src/awdl_mdns_query.h"
#include <string>
#include <limits>

namespace tx10ub::usb {
// Experimental software-event timeline. This does not calibrate radio/USB
// hardware latency or adopt an unobserved receive channel. The existing core
// remains the sole election, sync and PSF/MIF state machine.
class Session {
    using Clock=awdlwin::tx10ub::usb_clock::Bridge;
    Clock clock_;
    awdlwin::discovery::DiscoverySession session_;
    bool failed_=false;
    std::uint64_t lifetime_us_;
    bool has_applied_sync_=false;
    awdlwin::mdns::Cache services_;
    struct ReceivedData {
        awdlwin::wire::MacAddress source,destination,bssid;
        std::uint16_t sequence;
        std::uint8_t traffic_id;
        bool aggregated;
        std::uint64_t received_at_us;
        awdlwin::wire::Bytes body;
    };
    // Bounded MAC-retry history, separate from TCP sequence/retransmission
    // handling. Exact body comparison prevents a sequence reuse from dropping
    // different content. Multicast does not participate in this history.
    std::array<std::optional<ReceivedData>,64> received_data_{};
    std::size_t next_received_data_{};
    struct BrowseWindow {
        awdlwin::mdns::BrowseQuery query;
        awdlwin::discovery::MonotonicTime start, end;
        awdlwin::mdns::Cache responses;
    };
    std::optional<BrowseWindow> browse_;
    void prune_services(awdlwin::mdns::Cache& cache,std::uint64_t now) const {
        cache.expire(now);
        for(const auto& source:cache.peers()) {
            const auto* peer=session_.peers().find(source);
            if(!peer||(now>=peer->last_seen_us&&now-peer->last_seen_us>=lifetime_us_))cache.remove_peer(source);
        }
    }
    Session(Clock clock,awdlwin::discovery::DiscoverySession session,std::uint64_t lifetime)
        :clock_(std::move(clock)),session_(std::move(session)),lifetime_us_(lifetime){}
public:
    enum class DataReject { invalid_frame, unknown_peer, stale_peer, source_mismatch,
                            destination, unsupported_ether_type, invalid_ip, invalid_mdns, service_cache,
                            stale_event, duplicate_frame };
    struct StaleEvent {};
    struct PeerChannelWindowDecision {
        awdlwin::wire::MacAddress peer;
        std::uint8_t center_channel;
        std::uint8_t primary_channel;
        std::optional<std::uint8_t> width_mhz;
        std::uint8_t encoding;
        std::uint8_t raw_flags; // Legacy flags, or the OPCLASS byte for encoding 3.
        std::uint16_t aw_counter;
        std::uint16_t eaw_counter;
        std::uint8_t sequence_slot;
        std::uint32_t elapsed_in_eaw_us;
        std::uint32_t remaining_eaw_us;
        std::uint64_t peer_age_us;
        bool same_channel_before=false;
        bool same_channel_after=false;
    };
    using PeerMulticastDecision = PeerChannelWindowDecision;
    struct PeerMulticastCenterCandidate {
        awdlwin::discovery::MonotonicTime transmit_at;
        PeerMulticastDecision decision;
    };
    struct PeerUnicastWindow {
        awdlwin::discovery::MonotonicTime submit_begin,submit_end;
        PeerChannelWindowDecision decision;
    };
    struct Datagram {
        awdlwin::wire::MacAddress source;
        awdlwin::ip::Packet packet;
        std::optional<awdlwin::ip::Mdns> mdns;
        bool matched_browse_reply{};
        awdlwin::wire::Bytes ipv6;
    };
    struct DataReceipt {
        awdlwin::discovery::MonotonicTime event_at;
        std::vector<Datagram> datagrams;
    };
    using DataResult=std::variant<DataReceipt,DataReject,std::string>;
private:
    static bool channel_shape(const awdlwin::wire::ChannelSequence& c) {
        return (c.encoding==1||c.encoding==3)&&c.count==16&&c.duplicate_count==0&&
            c.step_count==3&&c.fill_channel==0xffff&&c.entries.size()==32;
    }
    struct RadioChannel {
        std::uint8_t center,primary,encoding,flags;
        std::optional<std::uint8_t> width;
        bool empty{};
    };
    static std::optional<RadioChannel> decode_radio_channel(
        const awdlwin::wire::ChannelSequence& channels,std::size_t slot) {
        const auto first=channels.entries[slot*2];
        const auto second=channels.entries[slot*2+1];
        if(first==0&&second==0)return RadioChannel{0,0,channels.encoding,0,std::nullopt,true};
        if(channels.encoding==3) {
            const bool known=(second==0x51&&first==6)||
                (second==0x80&&(first==44||first==149));
            if(!known)return std::nullopt;
            return RadioChannel{first,first,3,second,std::nullopt,false};
        }
        const auto band=first&0x30,channel_width=first&0x0c,control=first&0x03;
        // Captured Apple ch6 legacy entry; width remains unresolved.
        if(first==0x2b&&second==6)
            return RadioChannel{6,6,1,first,std::nullopt,false};
        if((first&0xc0)!=0||band!=0x10)return std::nullopt;
        std::uint8_t primary=0;
        std::optional<std::uint8_t> width;
        if(channel_width==0x0c&&(control==1||control==2)) {
            if(control==1) {
                if(second<2)return std::nullopt;
                primary=static_cast<std::uint8_t>(second-2);
            } else {
                if(second>std::numeric_limits<std::uint8_t>::max()-2)return std::nullopt;
                primary=static_cast<std::uint8_t>(second+2);
            }
            width=std::uint8_t{40};
        } else if(channel_width==0x04&&control==3) {
            primary=second;width=std::uint8_t{20};
        } else return std::nullopt;
        return RadioChannel{second,primary,1,first,width,false};
    }
    std::optional<std::array<std::uint8_t,16>> target_paired_channels(
        const awdlwin::wire::MacAddress& target,
        awdlwin::discovery::MonotonicTime now,std::uint64_t maximum_age_us,bool* wide44=nullptr,
        bool multicastOnly=false)const {
        const auto ticks=now.time_since_epoch().count();
        const auto* peer=session_.peers().find(target);
        if(failed_||ticks<0||!peer||!peer->metadata_ready()||!peer->last_action_body||
           static_cast<std::uint64_t>(ticks)<peer->last_seen_us)return std::nullopt;
        const auto age=static_cast<std::uint64_t>(ticks)-peer->last_seen_us;
        if(age>=lifetime_us_||age>maximum_age_us)return std::nullopt;
        const auto& tlvs=peer->last_action_body->tlvs;
        const auto sync_tlv=std::find_if(tlvs.begin(),tlvs.end(),
            [](const auto& tlv){return tlv.type==4;});
        const auto sequence_tlv=std::find_if(tlvs.begin(),tlvs.end(),
            [](const auto& tlv){return tlv.type==18;});
        if(sync_tlv==tlvs.end()||sequence_tlv==tlvs.end())return std::nullopt;
        const auto sync=awdlwin::wire::decode_sync(*sync_tlv);
        const auto sequence=awdlwin::wire::decode_channel_sequence(*sequence_tlv);
        if(!sync||!sequence||!channel_shape(sync.value().channels)||!channel_shape(sequence.value())||
           (sync.value().master_address[0]&1)||
           std::all_of(sync.value().master_address.begin(),sync.value().master_address.end(),
                       [](auto b){return b==0;}))return std::nullopt;
        const auto received=awdlwin::discovery::MonotonicTime{std::chrono::microseconds{
            static_cast<std::int64_t>(peer->last_seen_us)}};
        const awdlwin::discovery::TransmitSync seed{received,0,16,4};
        if(!awdlwin::discovery::update_owl_sync(seed,target,target,sync.value(),received))
            return std::nullopt;
        std::array<std::uint8_t,16> primary{};
        bool all44Wide=true;
        for(std::size_t slot=0;slot<primary.size();++slot) {
            // The captured Apple schedule advertises ch112 in both formats.
            // That slot is unusable for this 6/44 handoff, but does not
            // invalidate the independently matched slots on 6 and 44.
            const auto offset=slot*2;
            const auto& syncChannels=sync.value().channels;
            const auto& advertisedChannels=sequence.value();
            if(syncChannels.encoding==1&&advertisedChannels.encoding==3&&
               syncChannels.entries[offset]==0x1b&&syncChannels.entries[offset+1]==112&&
               advertisedChannels.entries[offset]==112&&advertisedChannels.entries[offset+1]==121)
                continue;
            const auto embedded=decode_radio_channel(sync.value().channels,slot);
            const auto advertised=decode_radio_channel(sequence.value(),slot);
            if(!embedded||!advertised||embedded->empty!=advertised->empty)return std::nullopt;
            if(embedded->empty)continue;
            if(embedded->primary!=advertised->primary||
               (embedded->width&&advertised->width&&
                (embedded->width!=advertised->width||embedded->center!=advertised->center)))
                return std::nullopt;
            if(multicastOnly&&!awdlwin::discovery::owl_multicast_slot(static_cast<unsigned>(slot)))continue;
            if(embedded->primary==44&&
               !((embedded->width==40&&embedded->center==46)||(advertised->width==40&&advertised->center==46)))
                all44Wide=false;
            primary[slot]=embedded->primary;
        }
        if(wide44)*wide44=all44Wide&&std::find(primary.begin(),primary.end(),44)!=primary.end();
        return primary;
    }
    // Read the target's own latest Action timestamp and Sync; never borrow the
    // elected parent's phase or refresh retained metadata with a Data receipt.
    std::optional<awdlwin::discovery::TransmitSync> target_timing(
        const awdlwin::wire::MacAddress& target,awdlwin::discovery::MonotonicTime now)const {
        const auto ticks=now.time_since_epoch().count();
        const auto* peer=session_.peers().find(target);
        if(failed_||ticks<0||!peer||!peer->metadata_ready()||!peer->last_action_body||
           static_cast<std::uint64_t>(ticks)<peer->last_seen_us||
           static_cast<std::uint64_t>(ticks)-peer->last_seen_us>=lifetime_us_)return std::nullopt;
        const auto& tlvs=peer->last_action_body->tlvs;
        const auto s=std::find_if(tlvs.begin(),tlvs.end(),[](const auto& t){return t.type==4;});
        const auto c=std::find_if(tlvs.begin(),tlvs.end(),[](const auto& t){return t.type==18;});
        if(s==tlvs.end()||c==tlvs.end())return std::nullopt;
        const auto sync=awdlwin::wire::decode_sync(*s);
        const auto channels=awdlwin::wire::decode_channel_sequence(*c);
        if(!sync||!channels||!channel_shape(sync.value().channels)||!channel_shape(channels.value())||
           (sync.value().master_address[0]&1)||
           std::all_of(sync.value().master_address.begin(),sync.value().master_address.end(),
                       [](auto b){return b==0;}))return std::nullopt;
        const auto received=awdlwin::discovery::MonotonicTime{std::chrono::microseconds{
            static_cast<std::int64_t>(peer->last_seen_us)}};
        const awdlwin::discovery::TransmitSync seed{received,0,16,4};
        const auto timing=awdlwin::discovery::update_owl_sync(seed,target,target,sync.value(),received);
        if(!timing)return std::nullopt;
        return timing.value();
    }
    // Decode the selected peer's channel for an already modeled local
    // availability position. This shares the paired Sync/TLV-18 and mixed
    // legacy/OPCLASS validation between Action and DATA admission.
    std::optional<PeerChannelWindowDecision> peer_channel_at(
        awdlwin::discovery::MonotonicTime now,unsigned requested_channel,
        const awdlwin::discovery::AvailabilityWindow& local_position,
        const awdlwin::wire::MacAddress* target=nullptr,bool inspectAdjacent=false)const {
        if(failed_||now.time_since_epoch().count()<0)return std::nullopt;
        const auto& state=session_.state();
        if(state.election.height==0||local_position.sequence_channel.channel!=requested_channel)
            return std::nullopt;
        const auto& source=target?*target:state.election.sync_address;
        const auto* peer=session_.peers().find(source);
        const auto now_us=static_cast<std::uint64_t>(now.time_since_epoch().count());
        if(!peer||!peer->metadata_ready()||now_us<peer->last_seen_us||
           now_us-peer->last_seen_us>=lifetime_us_||!peer->last_action_body)return std::nullopt;
        const auto& body=*peer->last_action_body;
        const auto sync_tlv=std::find_if(body.tlvs.begin(),body.tlvs.end(),
            [](const auto& tlv){return tlv.type==4;});
        const auto sequence_tlv=std::find_if(body.tlvs.begin(),body.tlvs.end(),
            [](const auto& tlv){return tlv.type==18;});
        if(sync_tlv==body.tlvs.end()||sequence_tlv==body.tlvs.end())return std::nullopt;
        const auto sync=awdlwin::wire::decode_sync(*sync_tlv);
        const auto sequence=awdlwin::wire::decode_channel_sequence(*sequence_tlv);
        if(!sync||!sequence||(!target&&!awdlwin::discovery::sync_address_matches_election(
            sync.value().master_address,state.election.master_address,body)))
            return std::nullopt;
        const auto& embedded=sync.value().channels;
        const auto& advertised=sequence.value();
        if(!channel_shape(embedded)||!channel_shape(advertised))return std::nullopt;
        auto position=local_position;
        if(target) {
            const auto timing=target_timing(*target,now);
            if(!timing)return std::nullopt;
            // Only compute the target's counter/phase here. Channel bytes are
            // decoded below from the target's paired TLVs, not this local array.
            const auto projected=awdlwin::discovery::inspect_owl_availability(
                *timing,state.channel_sequence,now);
            if(!projected)return std::nullopt;
            position=projected.value();
        }
        const auto channelAt=[&](std::size_t slot)->std::optional<RadioChannel> {
            const auto sync_channel=decode_radio_channel(embedded,slot);
            const auto standalone_channel=decode_radio_channel(advertised,slot);
            if(!sync_channel||!standalone_channel||sync_channel->empty||standalone_channel->empty||
               sync_channel->primary!=requested_channel||standalone_channel->primary!=requested_channel)
                return std::nullopt;
            if(sync_channel->width&&standalone_channel->width&&
               (sync_channel->width!=standalone_channel->width||
                sync_channel->center!=standalone_channel->center))return std::nullopt;
            // The two encodings can describe the same primary channel.
            return sync_channel->width?sync_channel:standalone_channel;
        };
        const auto slot=position.sequence_slot;
        const auto radio=channelAt(slot);
        if(!radio)return std::nullopt;
        const auto sameAdjacent=[&](std::size_t adjacentSlot) {
            const auto next=channelAt(adjacentSlot);
            return next&&next->center==radio->center&&next->width==radio->width&&
                next->encoding==radio->encoding&&next->flags==radio->flags;
        };
        return PeerChannelWindowDecision{source,radio->center,radio->primary,radio->width,radio->encoding,radio->flags,
            position.aw_counter,position.eaw_counter,position.sequence_slot,position.elapsed_in_eaw_us,
            position.remaining_eaw_us,now_us-peer->last_seen_us,
            inspectAdjacent&&sameAdjacent((slot+15)%16),inspectAdjacent&&sameAdjacent((slot+1)%16)};
    }
public:
    // Connection lifetime only. Election/Sync readiness is separately required
    // by target_peer_current and every unicast send permit.
    bool target_peer_present(const awdlwin::wire::MacAddress& target,
                             awdlwin::discovery::MonotonicTime now)const {
        const auto ticks=now.time_since_epoch().count();
        const auto* peer=session_.peers().find(target);
        return !failed_&&ticks>=0&&peer&&peer->metadata_ready()&&
            static_cast<std::uint64_t>(ticks)>=peer->last_seen_us&&
            static_cast<std::uint64_t>(ticks)-peer->last_seen_us<lifetime_us_;
    }
    std::optional<unsigned> preferred_data_channel(
        const awdlwin::wire::MacAddress& target,
        awdlwin::discovery::MonotonicTime now,bool receiving=false,bool* wide44=nullptr)const {
        bool wide=false;
        const auto channels=target_paired_channels(target,now,1'000'000,&wide);
        if(wide44)*wide44=wide;
        if(!channels)return std::nullopt;
        const auto count6=static_cast<std::size_t>(std::count(channels->begin(),channels->end(),6));
        if(receiving&&!wide&&count6)return 6u;
        const auto count44=static_cast<std::size_t>(std::count(channels->begin(),channels->end(),44));
        return count44>count6?44u:6u;
    }
    std::optional<bool> name_channel_44(const awdlwin::wire::MacAddress& target,
                                        awdlwin::discovery::MonotonicTime now)const {
        bool wide=false;
        const auto channels=target_paired_channels(target,now,1'000'000,&wide);
        if(!channels||std::find(channels->begin(),channels->end(),44)==channels->end())return std::nullopt;
        return wide;
    }
    std::optional<std::pair<awdlwin::wire::MacAddress,bool>> browse_channel_44(
        awdlwin::discovery::MonotonicTime now)const {
        const auto& state=session_.state();
        if(state.election.height==0)return std::nullopt;
        const auto& peer=state.election.sync_address;
        bool wide=false;
        const auto channels=target_paired_channels(peer,now,1'000'000,&wide,true);
        if(!channels||std::find(channels->begin(),channels->end(),44)==channels->end())return std::nullopt;
        return std::pair{peer,wide};
    }
    bool target_action_after(const awdlwin::wire::MacAddress& target,
                             awdlwin::discovery::MonotonicTime after,
                             awdlwin::discovery::MonotonicTime now)const {
        if(after.time_since_epoch().count()<0||now<after)return false;
        const auto* peer=session_.peers().find(target);
        if(!peer||peer->last_seen_us<static_cast<std::uint64_t>(after.time_since_epoch().count()))
            return false;
        return target_paired_channels(target,now,lifetime_us_).has_value();
    }
    bool set_fixed_channel(unsigned channel,awdlwin::discovery::MonotonicTime now) {
        if(failed_)return false;
        if(channel==6)return session_.set_fixed_channel({6,0x51},now);
        if(channel==44)return session_.set_fixed_channel({44,0x80},now);
        return false;
    }
    bool target_peer_current(const awdlwin::wire::MacAddress& target,
                             awdlwin::discovery::MonotonicTime now)const {
        return session_.state().election.height!=0&&target_timing(target,now).has_value()&&
            std::holds_alternative<awdlwin::discovery::AvailabilityWindow>(session_.availability(now));
    }
    std::string peer_name(const awdlwin::wire::MacAddress& target)const {
        const auto* peer=session_.peers().find(target);
        return peer&&peer->name?*peer->name:std::string{};
    }
    std::optional<PeerChannelWindowDecision> target_channel_window(
        const awdlwin::wire::MacAddress& target,awdlwin::discovery::MonotonicTime now,
        unsigned channel,bool fixedUpload=false)const {
        const auto local=data_local_availability(now,channel,fixedUpload?&target:nullptr);
        return local?peer_channel_at(now,channel,*local,&target):std::nullopt;
    }
    struct Receipt {
        awdlwin::discovery::SessionResult update;
        awdlwin::discovery::MonotonicTime event_at;
        std::uint64_t clock_uncertainty_us;
    };
    using Result=std::variant<Receipt,StaleEvent,std::string>;
    // Opens one receive/cache lifetime, independently of query retransmission.
    // The default preserves legacy one-shot callers; QM discovery can supply
    // its overall deadline and keep valid records until cleanup/TTL/peer expiry.
    bool register_browse_query(const awdlwin::mdns::BrowseQuery& query,
                              awdlwin::discovery::MonotonicTime now,
                              std::optional<awdlwin::discovery::MonotonicTime> deadline=std::nullopt) {
        if(failed_||query.source!=session_.state().self_address||now<session_.last_event_at()||
           now.time_since_epoch().count()<0||
           now.time_since_epoch().count()>std::numeric_limits<std::int64_t>::max()-3'000'000)return false;
        const auto end=deadline.value_or(now+std::chrono::seconds(3));
        if(end<=now||end-now>std::chrono::seconds(30))return false;
        if(browse_&&now<browse_->end)return false;
        browse_=BrowseWindow{query,now,end,{}};
        return true;
    }
    void clear_browse_query() {browse_.reset();}
    void clear_discovered_services() {services_={};}
    bool browse_window_open(awdlwin::discovery::MonotonicTime now)const {
        return !failed_&&browse_&&now>=browse_->start&&now<browse_->end;
    }
    static std::variant<Session,std::string> create(
        awdlwin::discovery::TransmitState initial,
        const awdlwin::tx10ub::usb_clock::Observation& first,
        const awdlwin::tx10ub::usb_clock::Budget& budget,std::uint64_t lifetime_us) {
        auto clock=Clock::start(first,budget);
        if(!std::holds_alternative<Clock>(clock))return "usb_clock_initialization_failed";
        auto& mapped=std::get<Clock>(clock);
        const auto start=mapped.session_start();
        if(initial.sync.anchor!=start)return "usb_initial_anchor_mismatch";
        auto core=awdlwin::discovery::DiscoverySession::create(std::move(initial),start,
            lifetime_us,awdlwin::discovery::ChannelPolicy::fixed_local);
        if(!core)return "usb_session_initialization_failed";
        return Session(std::move(mapped),std::move(core.value()),lifetime_us);
    }
    bool observe(const awdlwin::tx10ub::usb_clock::Observation& value) {
        if(failed_)return false;
        failed_=clock_.observe(value).has_value();
        return !failed_;
    }
    // Read-only peer-aware admission for the selected local multicast window.
    // This is an experiment gate; it neither changes the source bytes nor
    // claims radio/PHY admission.
    std::optional<PeerMulticastDecision> peer_multicast_decision(
        awdlwin::discovery::MonotonicTime now,unsigned requested_channel)const {
        if(failed_||now.time_since_epoch().count()<0)return std::nullopt;
        // Ch6 comparison uses Apple's observed social slot 8. Leave OWL's
        // ch44 multicast slots unchanged and retain the 16-TU edge guards.
        if(requested_channel==6) {
            const auto available=session_.availability(now);
            const auto* p=std::get_if<awdlwin::discovery::AvailabilityWindow>(&available);
            if(!p||p->sequence_slot!=8||p->elapsed_in_eaw_us<16*1024||
               p->remaining_eaw_us<16*1024)return std::nullopt;
            return peer_channel_at(now,requested_channel,*p);
        }
        const auto schedule=session_.multicast_schedule(now);
        const auto* selected=std::get_if<awdlwin::discovery::ScheduleDecision>(&schedule);
        if(!selected||selected->reason!=awdlwin::discovery::ScheduleReason::eligible||
           selected->position.sequence_channel.channel!=requested_channel)return std::nullopt;
        return peer_channel_at(now,requested_channel,selected->position);
    }
    // Action-channel presence uses the same selected-peer/paired-channel
    // validation as DATA, but deliberately has no multicast slot or guard
    // requirement. This is a modeled peer channel window, not RF admission.
    std::optional<PeerChannelWindowDecision> peer_action_channel_window(
        awdlwin::discovery::MonotonicTime now,unsigned requested_channel)const {
        if(failed_||now.time_since_epoch().count()<0)return std::nullopt;
        const auto availability=session_.availability(now);
        const auto* position=std::get_if<awdlwin::discovery::AvailabilityWindow>(&availability);
        if(!position||position->sequence_channel.channel!=requested_channel)return std::nullopt;
        return peer_channel_at(now,requested_channel,*position);
    }
private:
    std::optional<awdlwin::discovery::AvailabilityWindow> data_local_availability(
        awdlwin::discovery::MonotonicTime now,unsigned channel,
        const awdlwin::wire::MacAddress* uploadTarget)const {
        using namespace awdlwin::discovery;
        const auto available=session_.availability(now);
        if(const auto* local=std::get_if<AvailabilityWindow>(&available))return *local;
        if(failed_||!uploadTarget||channel!=44||
           std::get<SessionFailure>(available).error!=SessionError::awaiting_fresh_sync||
           !has_applied_sync_)return std::nullopt;
        const auto& state=session_.state();
        // The upload radio stays on 44 in every slot. While global Sync is
        // pending, use the destination's freshly observed EAW phase for this
        // unicast permit. Do not rephase the shared election or advertisements.
        const auto isFixed44=[](const auto& slot){return slot.channel==44&&slot.opclass==0x80;};
        if(!isFixed44(state.current_channel)||
           !std::all_of(state.channel_sequence.begin(),state.channel_sequence.end(),
                        isFixed44))return std::nullopt;
        constexpr auto peerCycleUs=16u*4u*16u*1024u;
        const auto* peer=session_.peers().find(*uploadTarget);
        const auto ticks=static_cast<std::uint64_t>(now.time_since_epoch().count());
        if(!peer||ticks<peer->last_seen_us||ticks-peer->last_seen_us>=peerCycleUs)
            return std::nullopt;
        const auto timing=target_timing(*uploadTarget,now);
        if(!timing)return std::nullopt;
        const auto position=inspect_owl_availability(*timing,state.channel_sequence,now);
        return position?std::optional{position.value()}:std::nullopt;
    }

    std::optional<PeerUnicastWindow> paired_data_window(
        awdlwin::discovery::MonotonicTime now,unsigned requested_channel,
        std::chrono::microseconds delay,const awdlwin::wire::MacAddress* target,
        std::int64_t guardTu,bool fixedUpload=false)const {
        using Duration=std::chrono::microseconds;
        const auto ticks=now.time_since_epoch().count();
        const auto max=(std::numeric_limits<std::int64_t>::max)();
        if(ticks<0||delay.count()<0||delay.count()>100000||delay.count()>max-ticks)return std::nullopt;
        const bool useAdjacent=fixedUpload&&requested_channel==44&&target;
        const auto projected=now+delay;
        const auto local=data_local_availability(projected,requested_channel,fixedUpload?target:nullptr);
        const auto first=local?peer_channel_at(projected,requested_channel,*local,target,useAdjacent):std::nullopt;
        const std::int64_t guard=guardTu*1024+
            awdlwin::tx10ub::usb_clock::discovery_budget.maximum_mapping_error_us;
        constexpr std::int64_t permitLifetime=4000; // Same maximum width as the former center permit.
        if(!first||!local)return std::nullopt;
        const auto sameLocal=[&](unsigned adjacent) {
            const auto& slot=session_.state().channel_sequence[(local->sequence_slot+adjacent)%16];
            return useAdjacent&&slot.channel==requested_channel&&slot.opclass==local->sequence_channel.opclass;
        };
        // Keep the guard at real channel transitions. A short permit can
        // cross into the next EAW when that radio stays on the same channel.
        const bool peerContinues=first->same_channel_after;
        const bool localContinues=sameLocal(1);
        if((!first->same_channel_before&&first->elapsed_in_eaw_us<guard)||
           (!sameLocal(15)&&local->elapsed_in_eaw_us<guard))
            return std::nullopt;
        const auto span=(std::min)(permitLifetime,
            (std::min)(peerContinues?permitLifetime:static_cast<std::int64_t>(first->remaining_eaw_us)-guard,
                       localContinues?permitLifetime:static_cast<std::int64_t>(local->remaining_eaw_us)-guard));
        if(span<=0||span>max-ticks-delay.count())return std::nullopt;
        const auto end=now+Duration{span};
        const auto localEnd=data_local_availability(end+delay,requested_channel,fixedUpload?target:nullptr);
        const auto last=localEnd?peer_channel_at(end+delay,requested_channel,*localEnd,target):std::nullopt;
        const auto withinPermit=[](const auto& start,const auto& finish,bool continues,std::int64_t guardUs) {
            if(finish.eaw_counter==start.eaw_counter&&finish.sequence_slot==start.sequence_slot)
                return continues||finish.remaining_eaw_us>=guardUs;
            return continues&&finish.eaw_counter==(start.eaw_counter+1u)%16384u&&
                finish.sequence_slot==(start.sequence_slot+1u)%16u;
        };
        if(!last||last->peer!=first->peer||!localEnd||
           !withinPermit(*first,*last,peerContinues,guard)||!withinPermit(*local,*localEnd,localContinues,guard))
            return std::nullopt;
        return PeerUnicastWindow{now,end,*first};
    }
public:
    // OWL schedule.h uses 3 TU for unicast, 16 TU for multicast. Retain
    // the clock-mapping uncertainty in addition to each protocol guard.
    // Permits remain per-frame, paired and at most 4ms wide.
    std::optional<PeerUnicastWindow> peer_unicast_window(
        awdlwin::discovery::MonotonicTime now,unsigned requested_channel,
        std::chrono::microseconds delay,const awdlwin::wire::MacAddress* target=nullptr,
        bool fixedUpload=false)const {
        return paired_data_window(now,requested_channel,delay,target,3,fixedUpload);
    }
    // Receiver mDNS replies use the first guarded multicast opportunity. The
    // paired helper supplies the 16-TU local/peer guards and <=4ms worker
    // permit; both ends must additionally belong to this multicast EAW.
    std::optional<PeerUnicastWindow> peer_multicast_window(
        awdlwin::discovery::MonotonicTime now,unsigned channel,
        std::chrono::microseconds delay)const {
        const auto window=paired_data_window(now,channel,delay,nullptr,16);
        if(!window)return std::nullopt;
        const auto first=peer_multicast_decision(window->submit_begin+delay,channel);
        const auto last=peer_multicast_decision(window->submit_end+delay,channel);
        if(!first||!last||first->peer!=window->decision.peer||last->peer!=first->peer||
           first->eaw_counter!=last->eaw_counter||first->sequence_slot!=last->sequence_slot)
            return std::nullopt;
        return window;
    }
    // Target the middle of the eligible EAW, rather than its first admissible
    // instant. The delay is a Data-specific same-session USB measurement.
    static constexpr std::int64_t multicast_center_tolerance_us=2000;
    static constexpr std::int64_t maximum_paired_rf_lead_us=16000;
    std::optional<PeerMulticastDecision> peer_multicast_center(
        awdlwin::discovery::MonotonicTime now,unsigned channel,
        std::chrono::microseconds delay,std::chrono::microseconds pairedRfLead={})const {
        const auto ticks=now.time_since_epoch().count();
        if(ticks<0||delay.count()<0||delay.count()>100000||pairedRfLead.count()<0||
           pairedRfLead.count()>maximum_paired_rf_lead_us)return std::nullopt;
        const auto lead=delay+pairedRfLead;
        if(ticks>(std::numeric_limits<std::int64_t>::max)()-lead.count())return std::nullopt;
        // Paired capture calibration changes only the Data scheduling lookup.
        // It never changes the receive clock/anchor or claims pure TX latency.
        const auto decision=peer_multicast_decision(now+lead,channel);
        if(!decision)return std::nullopt;
        const auto error=static_cast<std::int64_t>(decision->elapsed_in_eaw_us)-
                         static_cast<std::int64_t>(decision->remaining_eaw_us);
        if(error < -2*multicast_center_tolerance_us||error > 2*multicast_center_tolerance_us)
            return std::nullopt;
        return decision;
    }
    // Find the next center at which the current peer and requested channel
    // agree. OWL's supported profile has 16 TU AWs and a 4-AW presence mode,
    // giving a 64 TU EAW; the 16-slot channel sequence repeats every 16 EAWs.
    std::optional<PeerMulticastCenterCandidate> next_peer_multicast_center(
        awdlwin::discovery::MonotonicTime earliestTransmitAt,unsigned channel)const {
        using Time=awdlwin::discovery::MonotonicTime;
        using Duration=std::chrono::microseconds;
        if(failed_||earliestTransmitAt.time_since_epoch().count()<0)return std::nullopt;
        const auto schedule=session_.multicast_schedule(earliestTransmitAt);
        const auto* current=std::get_if<awdlwin::discovery::ScheduleDecision>(&schedule);
        if(!current)return std::nullopt;
        const auto& position=current->position;
        const auto elapsed=static_cast<std::int64_t>(position.elapsed_in_eaw_us);
        const auto eawUs=static_cast<std::int64_t>(position.elapsed_in_eaw_us)+
                         static_cast<std::int64_t>(position.remaining_eaw_us);
        if(eawUs<=0||elapsed<0||elapsed>=eawUs)return std::nullopt;
        const auto center=eawUs/2;
        auto offset=center-elapsed;
        if(offset<0)offset+=eawUs;
        const auto start=earliestTransmitAt.time_since_epoch().count();
        const auto max=(std::numeric_limits<std::int64_t>::max)();
        const auto sequenceSlots=session_.state().channel_sequence.size();
        for(std::size_t slot=0;slot<sequenceSlots;++slot) {
            if(offset>max-start)return std::nullopt;
            const Time candidateAt{Duration{start+offset}};
            if(const auto decision=peer_multicast_decision(candidateAt,channel))
                return PeerMulticastCenterCandidate{candidateAt,*decision};
            if(offset>max-eawUs)return std::nullopt;
            offset+=eawUs;
        }
        return std::nullopt;
    }
    Result ingest(const Frame& frame) {
        if(failed_)return "usb_clock_halted";
        const bool hasFcs=frame.fcs==Fcs::present;
        if(hasFcs&&!valid_fcs(frame.mpdu))return "usb_session_invalid_fcs";
        auto event=clock_.map_event(frame.capture_utc_us);
        if(!std::holds_alternative<awdlwin::tx10ub::usb_clock::MappedEvent>(event)) {
            if(std::get<awdlwin::tx10ub::usb_clock::Failure>(event).error==
               awdlwin::tx10ub::usb_clock::ClockError::event_stale)return StaleEvent{};
            failed_=true;
            return "usb_event_clock_rejected_"+std::to_string(static_cast<int>(
                std::get<awdlwin::tx10ub::usb_clock::Failure>(event).error));
        }
        const auto& mapped=std::get<awdlwin::tx10ub::usb_clock::MappedEvent>(event);
        const auto now=static_cast<std::uint64_t>(mapped.event_at.time_since_epoch().count());
        std::vector<awdlwin::wire::MacAddress> departed;
        auto sources=services_.peers();
        if(browse_)for(const auto& source:browse_->responses.peers())
            if(std::find(sources.begin(),sources.end(),source)==sources.end())sources.push_back(source);
        for(const auto& source:sources) {
            const auto* peer=session_.peers().find(source);
            if(!peer||(now>=peer->last_seen_us&&now-peer->last_seen_us>=lifetime_us_))departed.push_back(source);
        }
        auto update=session_.ingest_mpdu(frame.mpdu,hasFcs,mapped.event_at);
        if(const auto* accepted=std::get_if<awdlwin::discovery::SessionUpdate>(&update)) {
            if(std::holds_alternative<awdlwin::discovery::AppliedSync>(accepted->sync))
                has_applied_sync_=true;
            // A late reappearance of the same MAC must not revive services
            // advertised before that Action peer expired.
            for(const auto& source:departed) {
                services_.remove_peer(source);
                if(browse_)browse_->responses.remove_peer(source);
            }
            prune_services(services_,now);
            if(browse_)prune_services(browse_->responses,now);
        }
        return Receipt{std::move(update),mapped.event_at,mapped.uncertainty_us};
    }
    // Data shares the USB event clock, but cannot refresh discovery, election
    // or Sync. Entire A-MSDU admission is atomic. Forwarded subframe sources
    // are unsupported by this direct-peer receive path.
    // Pass false while no unicast delivery consumer is installed. Merely
    // parsing a warmup packet is not delivery and must not suppress its retry.
    DataResult ingest_data(const DataFrame& frame,bool unicastDeliveryActive=true) {
        if(failed_)return std::string("usb_clock_halted");
        const bool hasFcs=frame.fcs==Fcs::present;
        if(hasFcs&&!valid_fcs(frame.mpdu))return DataReject::invalid_frame;
        auto decoded=awdlwin::wire::parse_awdl_data_mpdu(frame.mpdu,hasFcs);
        if(!decoded)return DataReject::invalid_frame;
        auto event=clock_.map_event(frame.capture_utc_us);
        if(!std::holds_alternative<awdlwin::tx10ub::usb_clock::MappedEvent>(event)) {
            if(std::get<awdlwin::tx10ub::usb_clock::Failure>(event).error==
               awdlwin::tx10ub::usb_clock::ClockError::event_stale)return DataReject::stale_event;
            failed_=true;return std::string("usb_data_clock_rejected");
        }
        const auto time=std::get<awdlwin::tx10ub::usb_clock::MappedEvent>(event).event_at;
        auto& data=decoded.value();
        const auto* peer=session_.peers().find(data.source);
        if(!peer)return DataReject::unknown_peer;
        const auto ticks=time.time_since_epoch().count();
        if(ticks<0||static_cast<std::uint64_t>(ticks)<peer->last_seen_us||
           static_cast<std::uint64_t>(ticks)-peer->last_seen_us>=lifetime_us_)return DataReject::stale_peer;
        DataReceipt receipt{time,{}};
        for(auto& msdu:data.msdus) {
            if(msdu.source!=data.source)return DataReject::source_mismatch;
            if(msdu.ether_type!=0x86dd)return DataReject::unsupported_ether_type;
            auto ip=awdlwin::ip::parse_ipv6(msdu.payload);
            if(!std::holds_alternative<awdlwin::ip::Packet>(ip))return DataReject::invalid_ip;
            auto packet=std::move(std::get<awdlwin::ip::Packet>(ip));
            if(!awdlwin::ip::destination_matches(packet.destination,msdu.destination,session_.state().self_address)||
               (data.destination!=session_.state().self_address&&(data.destination[0]&1)==0))return DataReject::destination;
            std::optional<awdlwin::ip::Mdns> mdns;
            bool matched=false;
            if(packet.udp&&packet.udp->destination_port==5353) {
                auto parsed=awdlwin::ip::parse_mdns(packet);
                if(const auto* error=std::get_if<awdlwin::ip::Error>(&parsed)) {
                    if(*error!=awdlwin::ip::Error::not_mdns)return DataReject::invalid_mdns;
                } else {
                    mdns=std::move(std::get<awdlwin::ip::Mdns>(parsed));
                    if(browse_&&browse_->query.local_port==5353&&time>=browse_->start&&time<browse_->end) {
                        // Multicast ID zero gives a receive window, not a unique
                        // request/reply correlation. Never borrow older records.
                        auto inWindow=awdlwin::mdns::parse_browse_reply(browse_->query,packet);
                        matched=std::holds_alternative<awdlwin::ip::Mdns>(inWindow);
                    }
                }
            } else if(packet.udp&&browse_&&time>=browse_->start&&time<browse_->end) {
                auto parsed=awdlwin::mdns::parse_browse_reply(browse_->query,packet);
                if(const auto* error=std::get_if<awdlwin::ip::Error>(&parsed)) {
                    if(*error!=awdlwin::ip::Error::not_mdns)return DataReject::invalid_mdns;
                } else {mdns=std::move(std::get<awdlwin::ip::Mdns>(parsed));matched=true;}
            }
            receipt.datagrams.push_back({msdu.source,std::move(packet),std::move(mdns),matched,std::move(msdu.payload)});
        }
        std::optional<awdlwin::mdns::Cache> staged,replies;
        for(const auto& datagram:receipt.datagrams) {
            if(!datagram.mdns)continue;
            if(!staged)prune_services(staged.emplace(services_),ticks);
            if(staged->ingest(datagram.source,*datagram.mdns,ticks)!=awdlwin::mdns::Update::applied)
                return DataReject::service_cache;
            if(datagram.matched_browse_reply) {
                if(!replies)replies.emplace(browse_->responses);
                if(replies->ingest(datagram.source,*datagram.mdns,ticks)!=awdlwin::mdns::Update::applied)
                    return DataReject::service_cache;
            }
        }
        std::optional<ReceivedData> remembered;
        if(unicastDeliveryActive&&(data.destination[0]&1)==0) {
            const auto header=data.qos?26u:24u;
            const auto trafficId=static_cast<std::uint8_t>(data.qos?(frame.mpdu[24]&15):16);
            const auto body=std::span<const std::uint8_t>(frame.mpdu).subspan(
                header,frame.mpdu.size()-header-(hasFcs?4:0));
            const auto receivedAt=static_cast<std::uint64_t>(ticks);
            if(data.retry)for(const auto& previous:received_data_) {
                if(previous&&receivedAt>=previous->received_at_us&&
                   receivedAt-previous->received_at_us<lifetime_us_&&
                   previous->source==data.source&&previous->destination==data.destination&&
                   previous->bssid==data.bssid&&previous->sequence==data.sequence&&
                   previous->traffic_id==trafficId&&previous->aggregated==data.aggregated&&
                   std::equal(previous->body.begin(),previous->body.end(),body.begin(),body.end()))
                    return DataReject::duplicate_frame;
            }
            // Allocate before committing either cache. A rejected/invalid frame
            // cannot poison retry history, and a duplicate cannot refresh TTLs.
            remembered.emplace(ReceivedData{data.source,data.destination,data.bssid,data.sequence,
                trafficId,data.aggregated,receivedAt,{body.begin(),body.end()}});
        }
        if(staged)services_=std::move(*staged);
        else prune_services(services_,ticks);
        if(replies)browse_->responses=std::move(*replies);
        if(remembered) {
            received_data_[next_received_data_]=std::move(remembered);
            next_received_data_=(next_received_data_+1)%received_data_.size();
        }
        return receipt;
    }
    void clear_data_retry_history()noexcept {
        for(auto& entry:received_data_)entry.reset();
        next_received_data_=0;
    }
    awdlwin::mdns::Snapshot browse_services(awdlwin::discovery::MonotonicTime now) const {
        const auto ticks=now.time_since_epoch().count();
        if(failed_||ticks<0||!browse_)return {};
        auto current=browse_->responses;prune_services(current,static_cast<std::uint64_t>(ticks));
        return current.endpoints(static_cast<std::uint64_t>(ticks));
    }
    awdlwin::mdns::Snapshot airdrop_services(awdlwin::discovery::MonotonicTime now) const {
        const auto ticks=now.time_since_epoch().count();
        if(failed_||ticks<0)return {};
        auto current=services_;
        // Remove stale sources before the endpoint output bound is applied,
        // otherwise an expired source could crowd out a live recipient.
        prune_services(current,static_cast<std::uint64_t>(ticks));
        return current.endpoints(static_cast<std::uint64_t>(ticks));
    }
    bool advance_receive_watermark() {
        if(failed_)return false;
        const auto watermark=clock_.minimum_future_event_time();
        if(!std::holds_alternative<awdlwin::tx10ub::usb_clock::MappedEvent>(watermark)){failed_=true;return false;}
        const auto time=std::get<awdlwin::tx10ub::usb_clock::MappedEvent>(watermark).event_at;
        if(time<=session_.last_event_at())return true;
        // Only a coordinate older than every future admissible receive event
        // can expire peers. Never advance to the read/generation timestamp.
        if(std::holds_alternative<awdlwin::discovery::SessionFailure>(session_.advance(time))){failed_=true;return false;}
        prune_services(services_,static_cast<std::uint64_t>(time.time_since_epoch().count()));
        if(browse_)prune_services(browse_->responses,static_cast<std::uint64_t>(time.time_since_epoch().count()));
        return true;
    }
    awdlwin::discovery::SessionFrameResult generate(awdlwin::wire::ActionSubtype subtype,
                                                   awdlwin::discovery::MonotonicTime now)const {
        if(failed_)return awdlwin::discovery::SessionFailure{awdlwin::discovery::SessionError::invalid_time};
        return session_.generate(subtype,now);
    }
    const awdlwin::discovery::DiscoverySession& core()const{return session_;}
    std::optional<awdlwin::discovery::MonotonicTime> transport_event_time(std::uint64_t utc)const {
        if(failed_)return std::nullopt;
        const auto mapped=clock_.map_transport_sample(utc);
        if(const auto* event=std::get_if<awdlwin::tx10ub::usb_clock::MappedEvent>(&mapped))return event->event_at;
        return std::nullopt;
    }
    // Response-task experiments need a real, newly accepted selected-peer
    // Sync. This is USB-event freshness, not a calibrated RF response deadline.
    std::optional<awdlwin::discovery::MonotonicTime> response_observation(
        awdlwin::discovery::MonotonicTime now,
        std::optional<awdlwin::discovery::MonotonicTime> after)const {
        const auto received=session_.last_sync_observation();
        const auto& state=session_.state();
        if(failed_||state.election.height==0||!received||now<*received||
           (after&&*received<=*after)||now-*received>=std::chrono::milliseconds{100})return std::nullopt;
        const auto* peer=session_.peers().find(state.election.sync_address);
        if(!peer||!peer->metadata_ready())return std::nullopt;
        return received;
    }
    int clock_error()const {
        return clock_.failure()?static_cast<int>(clock_.failure()->error):-1;
    }
    // generate(now) is const. Expiry is confined to the receive watermark.
};
}
