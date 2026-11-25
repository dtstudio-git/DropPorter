#pragma once
#include "Tx10ubAirDropHttp.h"
#include "Tx10ubTcpStream.h"
#include "Tx10ubTls.h"
#include <optional>

namespace tx10ub::airdrop {
// Incremental /Discover only. The USB owner interleaves several instances;
// this object neither reads USB nor submits radio operations.
class NameLookup {
public:
    enum class State {active,complete,peer_failed,fatal};
private:
    tcp::Stream& stream_;
    tls::Client tls_;
    Response response_;
    awdlwin::wire::Bytes request_,pending_;
    std::size_t requestOffset_=0,pendingOffset_=0;
    std::uint64_t deadline_;
    static constexpr std::uint64_t idleTimeoutUs=5'000'000;
    std::optional<std::uint64_t> lastProgress_;
    bool tcpEstablished_=false;
    bool requested_=false,closing_=false,aborted_=false,closed_=false;
    State state_=State::active;
    std::string name_;
    const char* reason_="none";
    bool retryable_=false;
    State finish(State state) {state_=state;return state_;}
    State peer_failure(const char* reason,bool retryable=false) {
        reason_=reason;retryable_=retryable;return finish(State::peer_failed);
    }
public:
    NameLookup(tcp::Stream& stream,std::uint64_t deadline):stream_(stream),deadline_(deadline) {}
    NameLookup(tcp::Stream& stream,std::uint64_t deadline,tls::Identity& identity,std::uint64_t started,
               bool offerCertificate=true)
        :stream_(stream),tls_(identity,offerCertificate),deadline_(deadline),lastProgress_(started) {}
    ~NameLookup(){close();}
    const std::string& name()const{return name_;}
    const char* reason()const{return reason_;}
    bool retryable()const{return retryable_;}
    bool certificate_rejected()const{return !requested_&&tls_.certificate_rejected();}
    unsigned http_status()const{return response_.status();}
    std::uint32_t tls_error()const{return tls_.error();}
    const char* phase()const {
        if(closing_)return "closing";
        if(requested_)return "discover";
        return stream_.connected()?"tls":"tcp";
    }
    bool close() {
        if(closed_)return state_!=State::fatal;
        closed_=true;stream_.abort();
        if(!tls_.close()){state_=State::fatal;return false;}
        return true;
    }
    State step(std::uint64_t now) {
        if(state_!=State::active)return state_;
        if(!tls_.healthy())return finish(State::fatal);
        if(now>=deadline_)return peer_failure("timeout",!response_.complete());
        if(!stream_.healthy())return stream_.retryable_error()?
            peer_failure("connection_ended",!response_.complete()):finish(State::fatal);
        const auto received=stream_.read();
        if(lastProgress_) {
            const bool connected=stream_.connected();
            if((!tcpEstablished_&&connected)||!received.empty())*lastProgress_=now;
            if(connected)tcpEstablished_=true;
            if(now-*lastProgress_>=idleTimeoutUs)return peer_failure("timeout",!response_.complete());
        }
        if(!received.empty()&&!tls_.closed()&&!tls_.feed(received))return peer_failure("tls_error");
        if(tls_.ready()&&!requested_) {
            request_=discover_request(stream_.endpoint().address,stream_.endpoint().port);
            requested_=true;
        }
        const auto plaintext=tls_.read();
        if(!plaintext.empty()&&!response_.complete()&&!response_.feed(plaintext))return peer_failure("invalid_response");
        if((tls_.closed()||stream_.eof())&&!response_.complete()) {
            if(!tls_.closed()||!response_.finish())return peer_failure("connection_ended",true);
        }
        if(response_.complete()&&!closing_) {
            if(!requested_||requestOffset_!=request_.size())return peer_failure("invalid_response");
            if(response_.status()==200)if(const auto name=receiver_computer_name(response_.body()))name_=*name;
            closing_=true;
            if(!tls_.closed()&&!tls_.shutdown())return finish(State::fatal);
        }
        if(requested_&&!closing_&&pending_.empty()&&requestOffset_<request_.size()) {
            const auto count=(std::min)(std::size_t{4096},request_.size()-requestOffset_);
            if(!tls_.write(std::span(request_).subspan(requestOffset_,count)))return finish(State::fatal);
            requestOffset_+=count;
        }
        const auto wire=tls_.outbound();
        if(!wire.empty()) {
            if(pendingOffset_){pending_.erase(pending_.begin(),pending_.begin()+pendingOffset_);pendingOffset_=0;}
            if(wire.size()>131072-pending_.size())return finish(State::fatal);
            pending_.insert(pending_.end(),wire.begin(),wire.end());
        }
        if(pendingOffset_<pending_.size()&&stream_.connected()) {
            pendingOffset_+=stream_.write(std::span(pending_).subspan(pendingOffset_));
            if(pendingOffset_==pending_.size()){pending_.clear();pendingOffset_=0;}
        }
        if(closing_&&pending_.empty()) {
            if(!aborted_){stream_.abort();aborted_=true;}
            else if(!stream_.outbound()) {
                if(!close())return finish(State::fatal);
                if(response_.status()!=200)return peer_failure("http_error");
                if(name_.empty())reason_="name_not_disclosed";
                return finish(State::complete);
            }
        }
        return state_;
    }
};
}
