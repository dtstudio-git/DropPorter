#pragma once
#include "../../src/awdl_mdns_cache.h"
#include "../DropPorter/DropPorterTargetFiles.h"
#include <algorithm>
#include <span>
#include <sstream>

namespace tx10ub::airdrop {
inline bool same_target(const awdlwin::mdns::Endpoint& a,const awdlwin::mdns::Endpoint& b) {
    return a.peer==b.peer&&a.service==b.service&&a.address==b.address&&a.port==b.port&&
        awdlwin::mdns::equal_name(a.instance,b.instance)&&awdlwin::mdns::equal_name(a.host,b.host);
}

// Tokens are session-local and never reassigned to another endpoint.
class TargetSelection {
    struct Entry {
        unsigned id;
        awdlwin::mdns::Endpoint endpoint;
        std::string receiverName;
        bool nameLookupActive=false,nameLookupFinished=false,current=false;
        bool offerClientCertificate=true;
        bool immediateCertificateRetry=false;
        unsigned nameAttempts=0;
        std::uint64_t nameStarted=0,nameRetryAt=0;
    };
    std::vector<Entry> entries_;
public:
    void restart_lookups() {
        // Retain endpoint IDs across a manual browse. A completed or interrupted
        // name lookup gets another chance after the endpoint answers again.
        for(auto& e:entries_){
            const auto offerCertificate=e.offerClientCertificate;
            e=Entry{e.id,e.endpoint};
            e.offerClientCertificate=offerCertificate;
        }
    }
    void update(const awdlwin::mdns::Snapshot& snapshot) {
        for(auto& entry:entries_)entry.current=false;
        if(snapshot.truncated||snapshot.endpoints.size() > dropporter::target_files::MaxRows)return;
        for(const auto& endpoint:snapshot.endpoints) {
            if(endpoint.service!=awdlwin::mdns::BrowseService::airdrop)continue;
            auto found=std::find_if(entries_.begin(),entries_.end(),[&](const auto& e){return same_target(e.endpoint,endpoint);});
            if(found==entries_.end()) {
                if(entries_.size() >= dropporter::target_files::MaxTargetId)continue;
                entries_.push_back({static_cast<unsigned>(entries_.size()+1),endpoint,{}});
                found=entries_.end()-1;
            }
            found->endpoint=endpoint;found->current=true;
        }
    }
    std::vector<unsigned> current_target_ids() const {
        std::vector<unsigned> ids;
        for(const auto& e:entries_)if(e.current)ids.push_back(e.id);
        return ids;
    }
    std::optional<std::pair<unsigned,awdlwin::mdns::Endpoint>> next_name_lookup(
        std::uint64_t now=0,std::span<const unsigned> firstRound={}) {
        const Entry* next=nullptr;
        for(auto& e:entries_) {
            if(!e.immediateCertificateRetry&&!firstRound.empty()&&(e.nameAttempts||
                std::find(firstRound.begin(),firstRound.end(),e.id)==firstRound.end()))continue;
            if(e.nameAttempts&&!e.nameLookupActive&&now>=e.nameStarted+20'000'000)e.nameLookupFinished=true;
            if(e.current&&!e.nameLookupActive&&!e.nameLookupFinished&&now>=e.nameRetryAt&&e.nameAttempts<4) {
                if(e.immediateCertificateRetry)return std::pair{e.id,e.endpoint};
                if(!next)next=&e;
            }
        }
        return next?std::optional{std::pair{next->id,next->endpoint}}:std::nullopt;
    }
    unsigned mark_name_lookup_attempted(unsigned id,std::uint64_t now=0) {
        for(auto& e:entries_)if(e.id==id&&e.current){
            if(!e.nameAttempts)e.nameStarted=now;
            e.immediateCertificateRetry=false;
            e.nameLookupActive=true;return ++e.nameAttempts;
        }
        return 0;
    }
    std::uint64_t name_lookup_deadline(unsigned id)const {
        for(const auto& e:entries_)if(e.id==id)return e.nameStarted+20'000'000;
        return 0;
    }
    bool offer_client_certificate(unsigned id)const {
        for(const auto& e:entries_)if(e.id==id)return e.offerClientCertificate;
        return true;
    }
    bool retry_name_lookup(unsigned id,std::uint64_t now,bool certificateRejected=false,bool retryOnCurrentChannel=false) {
        for(auto& e:entries_)if(e.id==id){
            e.nameLookupActive=false;
            const bool immediate=certificateRejected&&retryOnCurrentChannel&&e.offerClientCertificate;
            const auto retryAt=now+(immediate?0:500'000);
            if(e.nameAttempts<4&&retryAt<e.nameStarted+20'000'000){
                if(certificateRejected)e.offerClientCertificate=false;
                e.immediateCertificateRetry=immediate;
                e.nameRetryAt=retryAt;return true;
            }
            e.nameLookupFinished=true;return false;
        }
        return false;
    }
    void set_receiver_name(unsigned id,std::string name) {
        if(name.size()>256)return;
        for(auto& e:entries_)if(e.id==id){
            if(e.current)e.receiverName=std::move(name);
            e.nameLookupFinished=true;e.nameLookupActive=false;return;
        }
    }
    std::string rows()const {
        constexpr char hex[]="0123456789abcdef";
        constexpr char pending[]="\xe5\x90\x8d\xe5\x89\x8d\xe5\x8f\x96\xe5\xbe\x97\xe4\xb8\xad";
        constexpr char unknown[]="\xe5\x90\x8d\xe5\x89\x8d\xe4\xb8\x8d\xe6\x98\x8e\xe3\x81\xae\xe3\x83\x87\xe3\x83\x90\xe3\x82\xa4\xe3\x82\xb9";
        std::ostringstream out;
        for(const auto& e:entries_)if(e.current) {
            out<<e.id << dropporter::target_files::RowSeparator;
            auto label=e.receiverName.empty()?std::string(e.nameLookupFinished?unknown:pending):e.receiverName;
            label+=" [";
            for(unsigned i=3;i<6;++i) {
                if(i!=3)label+=':';
                label+=hex[e.endpoint.peer[i]>>4];label+=hex[e.endpoint.peer[i]&15];
            }
            label+=']';
            for(unsigned char c:label)out<<hex[c>>4]<<hex[c&15];
            out << dropporter::target_files::RowSeparator;
            for(auto byte:e.endpoint.peer)out<<hex[byte>>4]<<hex[byte&15];
            out << dropporter::target_files::RowSeparator<<(e.receiverName.empty() ? dropporter::target_files::Unnamed : dropporter::target_files::Named);
            out<<'\n';
        }
        return out.str();
    }
    std::optional<awdlwin::mdns::Endpoint> select(unsigned id)const {
        for(const auto& e:entries_)if(e.id==id&&e.current)return e.endpoint;
        return std::nullopt;
    }
};
}
