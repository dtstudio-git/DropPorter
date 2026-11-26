#include "awdl_mdns_cache.h"
#include <algorithm>
#include <limits>

namespace awdlwin::mdns {
namespace {
bool same_set(const ip::Record& a,const ip::Record& b) {
    return a.type==b.type&&a.klass==b.klass&&equal_name(a.name,b.name);
}
bool same_record(const ip::Record& a,const ip::Record& b) {
    if(!same_set(a,b))return false;
    if(a.type==12||a.type==33)return a.target&&b.target&&equal_name(*a.target,*b.target)&&
        (a.type==12||(a.port==b.port&&a.priority==b.priority&&a.weight==b.weight));
    if(a.type==16)return a.text==b.text;
    return a.rdata==b.rdata;
}
std::uint64_t deadline(std::uint64_t now,std::uint32_t ttl) {
    const auto delta=std::uint64_t(ttl)*1'000'000;
    return delta>std::numeric_limits<std::uint64_t>::max()-now?
        std::numeric_limits<std::uint64_t>::max():now+delta;
}
bool supported(const ip::Record& r) {return r.klass==1&&(r.type==12||r.type==33||r.type==16||r.type==28);}
bool valid_name(const ip::Name& n) {
    std::size_t size=0;
    for(const auto& label:n){if(label.empty()||label.size()>63)return false;size+=1+label.size();}
    return size<=255;
}
bool valid(const ip::Record& r) {
    return valid_name(r.name)&&((r.type==12||r.type==33)?r.target&&valid_name(*r.target):
        r.type==28?r.rdata.size()==16:
        std::all_of(r.text.begin(),r.text.end(),[](const auto& item){return item.size()<=255;}));
}
bool usable_address(const wire::Bytes& b) {
    if(b.size()!=16||b[0]==0xff)return false;
    return !std::all_of(b.begin(),b.begin()+15,[](auto byte){return byte==0;})||b.back()>1;
}
bool advertises_airdrop(const std::vector<wire::Bytes>& text) {
    constexpr std::string_view expected="com.apple.sharingd.AirDrop";
    for(const auto& item:text) {
        const auto separator=std::find(item.begin(),item.end(),std::uint8_t('='));
        const auto keyEnd=separator==item.end()?item.end():separator;
        bool isServiceName=static_cast<std::size_t>(keyEnd-item.begin())==2;
        if(isServiceName) {
            const auto first=static_cast<unsigned char>(item[0]);
            const auto second=static_cast<unsigned char>(item[1]);
            isServiceName=(first=='s'||first=='S')&&(second=='n'||second=='N');
        }
        if(!isServiceName)continue;
        if(separator==item.end())return false;
        const auto value=separator+1;
        return static_cast<std::size_t>(item.end()-value)==expected.size()&&
            std::equal(value,item.end(),expected.begin(),[](std::uint8_t a,char b){return a==static_cast<unsigned char>(b);});
    }
    return false;
}
} // namespace
Update Cache::ingest(const wire::MacAddress& peer,const ip::Mdns& message,std::uint64_t now) {
    if(now<last_at_us_)return Update::invalid_time;
    Cache next=*this;next.expire(now);
    if((message.flags&0x8000)==0){*this=std::move(next);return Update::applied;}
    std::vector<const ip::Record*> records;
    for(const auto* section:{&message.answers,&message.authorities,&message.additionals})
        for(const auto& r:*section)if(supported(r)) {
            if(!valid(r))return Update::invalid_record;
            records.push_back(&r);
        }
    // Flush at RRset granularity before refresh, so multiple addresses carried
    // in one message survive. Entries received <=1 second ago are protected.
    for(const auto* r:records)if(r->cache_flush&&r->ttl!=0)
        for(auto& old:next.entries_)if(old.peer==peer&&same_set(old.record,*r)&&
            now-old.received_at_us>1'000'000)
            old.expires_at_us=std::min(old.expires_at_us,deadline(now,1));
    for(const auto* r:records) {
        auto found=std::find_if(next.entries_.begin(),next.entries_.end(),[&](const Entry& e){
            return e.peer==peer&&same_record(e.record,*r);});
        if(r->ttl==0) {
            if(found!=next.entries_.end())found->expires_at_us=std::min(found->expires_at_us,deadline(now,1));
            continue;
        }
        Entry entry{peer,*r,now,deadline(now,r->ttl)};
        if(found!=next.entries_.end())*found=std::move(entry);
        else {
            if(next.entries_.size()==capacity)return Update::capacity;
            next.entries_.push_back(std::move(entry));
        }
    }
    *this=std::move(next);return Update::applied;
}
void Cache::expire(std::uint64_t now) {
    // A receive watermark can lag already accepted Data. Never reverse time.
    if(now<last_at_us_)return;
    last_at_us_=now;
    std::erase_if(entries_,[&](const Entry& e){return now>=e.expires_at_us;});
}
void Cache::remove_peer(const wire::MacAddress& peer) {
    std::erase_if(entries_,[&](const Entry& e){return e.peer==peer;});
}
std::vector<wire::MacAddress> Cache::peers() const {
    std::vector<wire::MacAddress> result;
    for(const auto& e:entries_)if(std::find(result.begin(),result.end(),e.peer)==result.end())result.push_back(e.peer);
    return result;
}
Snapshot Cache::endpoints(std::uint64_t now) const {
    Snapshot result;
    if(now<last_at_us_)return result;
    const auto live=[&](const Entry& e){return now<e.expires_at_us;};
    // DNS-SD instance SRV/TXT are unique. Prefer the latest assertion during
    // cache-flush grace; conflicting equally recent assertions stay unresolved.
    const auto latest=[&](const wire::MacAddress& peer,const ip::Name& name,std::uint16_t type) {
        const Entry* found=nullptr;bool conflict=false;
        for(const auto& e:entries_)if(live(e)&&e.peer==peer&&e.record.type==type&&equal_name(e.record.name,name)) {
            if(!found||e.received_at_us>found->received_at_us){found=&e;conflict=false;}
            else if(e.received_at_us==found->received_at_us&&!same_record(e.record,found->record))conflict=true;
        }
        return conflict?nullptr:found;
    };
    for(const auto& ptr:entries_) {
        if(!live(ptr)||ptr.record.type!=12||!ptr.record.target)continue;
        const auto selected_service=service_for_name(ptr.record.name);
        if(!selected_service||!instance_for_service(*ptr.record.target,*selected_service))continue;
        const auto* service_record=latest(ptr.peer,*ptr.record.target,33);
        const auto* text=latest(ptr.peer,*ptr.record.target,16);
        if(!service_record||!text||!service_record->record.target||service_record->record.port==0)continue;
        if(*selected_service!=BrowseService::airdrop&&!advertises_airdrop(text->record.text))continue;
        const auto& srv=*service_record;const auto& txt=*text;
        for(const auto& addr:entries_) {
            if(!live(addr)||addr.peer!=ptr.peer||addr.record.type!=28||
               !equal_name(addr.record.name,*srv.record.target)||!usable_address(addr.record.rdata))continue;
            ip::Address address{};std::copy_n(addr.record.rdata.begin(),16,address.begin());
            if(result.endpoints.size()==capacity){result.truncated=true;return result;}
            result.endpoints.push_back({ptr.peer,*selected_service,*ptr.record.target,*srv.record.target,address,srv.record.port,
                srv.record.priority,srv.record.weight,txt.record.text,
                std::min({ptr.expires_at_us,srv.expires_at_us,txt.expires_at_us,addr.expires_at_us}),
                {ptr.received_at_us,srv.received_at_us,txt.received_at_us,addr.received_at_us}});
        }
    }
    return result;
}
} // namespace awdlwin::mdns
