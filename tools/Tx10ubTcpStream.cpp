#include "Tx10ubTcpStream.h"
#include "Tx10ubTcpConnect.h"
extern "C" {
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip6.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/timeouts.h"
}
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <limits>
#include <stdexcept>
#pragma comment(lib,"bcrypt.lib")

namespace {
using Bytes=awdlwin::wire::Bytes;
constexpr std::size_t streamLimit=4;
constexpr std::size_t queueLimit=TCP_SND_QUEUELEN;
constexpr std::size_t globalQueueLimit=streamLimit*queueLimit;
constexpr std::size_t packetLimit=TX10UB_IPV6_MTU;
constexpr std::size_t controlQueueLimit=8;
constexpr std::size_t controlBytesLimit=controlQueueLimit*packetLimit;
using Endpoint=awdlwin::mdns::Endpoint;
struct ControlPacket {Bytes bytes;Endpoint peer;};
struct ControlPeer {Endpoint endpoint{};std::uint64_t seenAtUs=0;bool used=false;};

struct Stack {
    netif iface{};
    std::array<void*,streamLimit> streams{};
    std::size_t streamCount=0;
    std::size_t queuedBytes=0;
    std::size_t queuedPackets=0;
    std::array<ControlPeer,streamLimit> controlPeers{};
    std::deque<ControlPacket> controlTx;
    std::size_t controlBytes=0;
    awdlwin::wire::MacAddress self{};
    void* listener=nullptr;
    void* activeOwner=nullptr;
    int* activeFailure=nullptr;
    const Endpoint* activeControlPeer=nullptr;
    bool ifaceAdded=false;
    bool randomFailed=false;
    bool timeoutTicked=false;
    std::uint32_t timeoutMs=0;
};
Stack stack;
bool initialized=false;
std::uint64_t clockUs=0;
const Endpoint* control_peer_by_address(const std::uint8_t* address) noexcept {
    for(const auto& peer:stack.controlPeers)if(peer.used&&
        std::equal(peer.endpoint.address.begin(),peer.endpoint.address.end(),address))return &peer.endpoint;
    return nullptr;
}
Endpoint* remember_control_peer(const awdlwin::wire::MacAddress& mac,
                               const awdlwin::ip::Address& address,std::uint16_t port) {
    ControlPeer* available=nullptr;
    for(auto& entry:stack.controlPeers) {
        if(entry.used&&entry.endpoint.address==address) {
            if(entry.endpoint.peer!=mac)return nullptr;
            if(port)entry.endpoint.port=port;
            entry.endpoint.expires_at_us=(std::numeric_limits<std::uint64_t>::max)();entry.seenAtUs=clockUs;
            return &entry.endpoint;
        }
        if(!available||(!entry.used&&available->used)||
           (entry.used&&available->used&&entry.seenAtUs<available->seenAtUs))available=&entry;
    }
    if(!available)return nullptr;
    available->endpoint={};available->endpoint.peer=mac;
    available->endpoint.service=awdlwin::mdns::BrowseService::airdrop;
    available->endpoint.address=address;available->endpoint.port=port;
    available->endpoint.expires_at_us=(std::numeric_limits<std::uint64_t>::max)();
    available->seenAtUs=clockUs;available->used=true;
    return &available->endpoint;
}
void clear_control_queue() noexcept {
    stack.controlTx.clear();stack.controlBytes=0;
    for(auto& peer:stack.controlPeers){peer.endpoint={};peer.used=false;}
    stack.activeControlPeer=nullptr;
}
bool queue_control_packet(Bytes bytes,const Endpoint& peer) {
    if(bytes.size()>packetLimit||stack.controlTx.size()>=controlQueueLimit||
       stack.controlBytes+bytes.size()>controlBytesLimit)return false;
    const auto size=bytes.size();stack.controlTx.push_back({std::move(bytes),peer});
    stack.controlBytes+=size;return true;
}
void mark_random_failure() noexcept {
    if(stack.activeFailure)*stack.activeFailure=ERR_VAL;
    else stack.randomFailed=true;
}
struct ActiveOwner {
    void* previousOwner;
    int* previousFailure;
    ActiveOwner(void* owner,int* failure=nullptr) noexcept
        :previousOwner(stack.activeOwner),previousFailure(stack.activeFailure) {
        stack.activeOwner=owner;stack.activeFailure=failure;
    }
    ~ActiveOwner(){stack.activeOwner=previousOwner;stack.activeFailure=previousFailure;}
};
struct ActiveControlPeer {
    const Endpoint* previous;
    explicit ActiveControlPeer(const Endpoint* peer) noexcept:previous(stack.activeControlPeer) {
        stack.activeControlPeer=peer;
    }
    ~ActiveControlPeer(){stack.activeControlPeer=previous;}
};
}
extern "C" u32_t sys_now(void){return static_cast<u32_t>(clockUs/1000);}
extern "C" uint32_t awdl_lwip_random(void) {
    uint32_t value=0;
    if(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&value),sizeof(value),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0)
        mark_random_failure(); // Attribute failures to the operation that requested randomness.
    return value;
}

namespace tx10ub::tcp {
using Bytes=awdlwin::wire::Bytes;
struct Stream::Impl {
    awdlwin::wire::MacAddress self;
    awdlwin::mdns::Endpoint peer;
    std::uint16_t port;
    tcp_pcb* pcb=nullptr;
    bool registered=false,up=false,remoteEof=false,closing=false,serverCandidate=false,accepted=false;
    int failure=0;
    std::deque<Bytes> tx;
    bool selected=false;
    Bytes rx;
    std::uint64_t acknowledgedBytes=0;
    static constexpr std::size_t receiveLimit=65536;
    u16_t withheldReceiveCredit=0;

    static std::uint16_t be16(const std::uint8_t* p) noexcept {
        return static_cast<std::uint16_t>((std::uint16_t(p[0])<<8)|p[1]);
    }
    static bool replaces_ack(const Bytes& old,const Bytes& next) {
        const auto a=parse(old),b=parse(next);
        if(!a||!b||a->flags!=0x10||b->flags!=0x10||a->payload_size||b->payload_size||
           a->source!=b->source||a->destination!=b->destination||
           a->source_port!=b->source_port||a->destination_port!=b->destination_port||
           a->sequence!=b->sequence||old.size()!=next.size()||
           read16(old,54)!=read16(next,54)||read16(old,58)||read16(next,58))return false;
        const auto forward=[](std::uint32_t from,std::uint32_t to){return to-from<0x80000000u;};
        if(!forward(a->acknowledgement,b->acknowledgement))return false;
        // Only plain ACKs or the timestamp option emitted by this lwIP build.
        // Preserve window changes, SACK/unknown options, and backwards TS values.
        for(std::size_t p=60;p<old.size();) {
            if(old[p]!=next[p])return false;
            if(old[p]==0)return std::equal(old.begin()+p,old.end(),next.begin()+p);
            if(old[p]==1){++p;continue;}
            if(old[p]!=8||old.size()-p<10||old[p+1]!=10||next[p+1]!=10||
               !forward(read32(old,p+2),read32(next,p+2))||
               !forward(read32(old,p+6),read32(next,p+6)))return false;
            p+=10;
        }
        return true;
    }
    static Impl* by_port(std::uint16_t localPort) noexcept {
        for(std::size_t i=0;i<stack.streams.size();++i) {
            auto* stream=static_cast<Impl*>(stack.streams[i]);
            if(stream&&stream->port==localPort)return stream;
        }
        return nullptr;
    }
    static Impl* by_tuple(const std::uint8_t* localAddress,const std::uint8_t* remoteAddress,
                          std::uint16_t localPort,std::uint16_t remotePort) noexcept {
        for(const auto item:stack.streams) {
            auto* stream=static_cast<Impl*>(item);
            if(stream&&stream->port==localPort&&stream->peer.port==remotePort&&
               std::equal(stream->peer.address.begin(),stream->peer.address.end(),remoteAddress)) {
                const auto local=local_address(stream->self);
                if(std::equal(local.begin(),local.end(),localAddress))return stream;
            }
        }
        return nullptr;
    }
    static Impl* icmp_dispatcher(const awdlwin::wire::MacAddress& mac,
                                 const awdlwin::ip::Address& address) noexcept {
        for(const auto item:stack.streams) {
            auto* stream=static_cast<Impl*>(item);
            if(stream&&!stream->failure&&stream->self==stack.self&&
               stream->peer.peer==mac&&stream->peer.address==address)return stream;
        }
        return nullptr;
    }
    static Impl* by_peer_address(const std::uint8_t* address) noexcept {
        for(const auto item:stack.streams) {
            auto* stream=static_cast<Impl*>(item);
            if(stream&&std::equal(stream->peer.address.begin(),stream->peer.address.end(),address))return stream;
        }
        return nullptr;
    }
    static std::size_t queued_packets() noexcept {return stack.queuedPackets;}
    static void pop_back(Impl& stream) noexcept {
        if(stream.tx.empty())return;
        stack.queuedBytes-=stream.tx.back().size();--stack.queuedPackets;stream.tx.pop_back();
    }
    static err_t output(netif* n,pbuf* p,const ip6_addr_t*) noexcept {
        if(n!=&stack.iface||!p)return ERR_IF;
        std::array<std::uint8_t,64> prefix{};
        const auto prefixSize=(std::min)(std::size_t(p->tot_len),prefix.size());
        if(prefixSize<40||pbuf_copy_partial(p,prefix.data(),static_cast<u16_t>(prefixSize),0)!=prefixSize)return ERR_BUF;
        if((prefix[0]>>4)!=6)return ERR_VAL;
        Impl* owner=nullptr;
        const Endpoint* controlOwner=nullptr;
        if(prefix[6]==6) {
            if(prefixSize>=44)owner=by_tuple(prefix.data()+8,prefix.data()+24,
                be16(prefix.data()+40),be16(prefix.data()+42));
        } else if(stack.activeOwner)owner=static_cast<Impl*>(stack.activeOwner);
        else if(stack.activeControlPeer)controlOwner=stack.activeControlPeer;
        else {
            owner=by_peer_address(prefix.data()+24);
            // ND timer probes use a solicited-node multicast destination; the
            // target address identifies the peer whose timer emitted the probe.
            if(!owner&&prefix[6]==58&&prefixSize>=64&&(prefix[40]==135||prefix[40]==136))
                owner=by_peer_address(prefix.data()+48);
            if(!owner&&prefix[6]==58&&prefixSize>=64&&(prefix[40]==135||prefix[40]==136))
                controlOwner=control_peer_by_address(prefix.data()+48);
            if(!owner&&!controlOwner&&prefix[6]==58)controlOwner=control_peer_by_address(prefix.data()+24);
        }
        if(!owner&&!controlOwner)return ERR_OK; // Ignore control output without an admitted stream/peer owner.
        if(stack.randomFailed){if(owner)owner->failure=ERR_VAL;return ERR_VAL;}
        if(p->tot_len>packetLimit){if(owner)owner->failure=ERR_MEM;return ERR_MEM;}
        try {
            Bytes bytes(p->tot_len);
            if(pbuf_copy_partial(p,bytes.data(),p->tot_len,0)!=p->tot_len){if(owner)owner->failure=ERR_BUF;return ERR_BUF;}
            if(controlOwner)return static_cast<err_t>(queue_control_packet(std::move(bytes),*controlOwner)?ERR_OK:ERR_MEM);
            // An unresolved receive gap needs duplicate ACKs for loss recovery.
            // Otherwise the newest cumulative ACK can replace an unsent tail.
            // Never mutate the selected front while the USB owner is polling.
            if(owner->pcb&&!owner->pcb->ooseq) {
                while(!owner->tx.empty()&&!(owner->selected&&owner->tx.size()==1)&&
                      replaces_ack(owner->tx.back(),bytes))pop_back(*owner);
            }
            if(owner->tx.size()>=queueLimit||queued_packets()>=globalQueueLimit||
               stack.queuedBytes+bytes.size()>globalQueueLimit*packetLimit){owner->failure=ERR_MEM;return ERR_MEM;}
            const auto size=bytes.size();owner->tx.push_back(std::move(bytes));
            stack.queuedBytes+=size;++stack.queuedPackets;return ERR_OK;
        }catch(...){if(owner)owner->failure=ERR_MEM;return ERR_MEM;}
    }
    static err_t init(netif* n) noexcept {
        const auto* owner=static_cast<const Stack*>(n->state);
        n->name[0]='a';n->name[1]='w';n->mtu=packetLimit;n->output_ip6=output;
        n->hwaddr_len=static_cast<u8_t>(owner->self.size());
        std::memcpy(n->hwaddr,owner->self.data(),owner->self.size());
        n->flags=0;return ERR_OK;
    }
    static err_t attach_interface(const awdlwin::wire::MacAddress& mac) {
        if(stack.ifaceAdded)return static_cast<err_t>(stack.self==mac?ERR_OK:ERR_VAL);
        stack.self=mac;
        if(!netif_add_noaddr(&stack.iface,&stack,init,ip6_input))return ERR_IF;
        stack.ifaceAdded=true;
        const auto local=local_address(mac);ip6_addr_t address{};
        std::memcpy(address.addr,local.data(),16);netif_ip6_addr_set(&stack.iface,0,&address);
        netif_ip6_addr_set_state(&stack.iface,0,IP6_ADDR_PREFERRED);
        netif_set_default(&stack.iface);netif_set_link_up(&stack.iface);netif_set_up(&stack.iface);
        return ERR_OK;
    }
    void register_stream() {
        if(stack.streamCount>=streamLimit)throw std::runtime_error("TCP stream limit reached");
        if((stack.streamCount||stack.listener)&&stack.self!=self)throw std::invalid_argument("TCP owner address changed");
        if(serverCandidate) {
            const auto local=local_address(self);
            if(by_tuple(local.data(),peer.address.data(),port,peer.port))
                throw std::invalid_argument("TCP tuple already active");
        } else if(by_port(port))throw std::invalid_argument("TCP local port already active");
        if(!initialized){lwip_init();initialized=true;}
        const auto added=attach_interface(self);
        if(added!=ERR_OK)throw std::runtime_error("TCP netif creation failed");
        auto slot=std::find(stack.streams.begin(),stack.streams.end(),nullptr);
        if(slot==stack.streams.end())throw std::runtime_error("TCP stream registry full");
        *slot=this;++stack.streamCount;registered=true;
    }
    static void failed(void* arg,err_t e) noexcept {
        auto& stream=*static_cast<Impl*>(arg);stream.pcb=nullptr;stream.up=false;
        if(!stream.closing)stream.failure=e;
    }
    static err_t established(void* arg,tcp_pcb*,err_t e) noexcept {
        auto& stream=*static_cast<Impl*>(arg);if(e!=ERR_OK)stream.failure=e;else stream.up=true;return ERR_OK;
    }
    static err_t acknowledged(void* arg,tcp_pcb*,u16_t length) noexcept {
        static_cast<Impl*>(arg)->acknowledgedBytes+=length;
        return ERR_OK;
    }
    static err_t received(void* arg,tcp_pcb* pcb,pbuf* p,err_t e) noexcept {
        auto& stream=*static_cast<Impl*>(arg);
        if(!p){stream.remoteEof=true;return ERR_OK;}
        if(e!=ERR_OK)return e;
        if(p->tot_len>receiveLimit-stream.rx.size())return ERR_MEM; // lwIP retains refused data.
        try {
            const auto start=stream.rx.size();stream.rx.resize(start+p->tot_len);
            if(pbuf_copy_partial(p,stream.rx.data()+start,p->tot_len,0)!=p->tot_len){stream.rx.resize(start);return ERR_BUF;}
            // Keep one advertised window of free storage for an inbound burst.
            // Once TLS falls behind, let lwIP close the window until read().
            static_assert(TCP_WND <= receiveLimit && TCP_WND <= UINT16_MAX);
            if(stream.accepted && stream.rx.size() > receiveLimit - TCP_WND)
                stream.withheldReceiveCredit+=p->tot_len;
            else tcp_recved(pcb,p->tot_len);
            pbuf_free(p);return ERR_OK;
        }catch(...){stream.failure=ERR_MEM;return ERR_MEM;}
    }
    Impl(const awdlwin::wire::MacAddress& mac,const awdlwin::mdns::Endpoint& endpoint,
         std::uint16_t localPort,std::uint64_t now,bool inbound=false)
        :self(mac),peer(endpoint),port(localPort),serverCandidate(inbound) {
        if(!inbound&&!ConnectCheck(mac,endpoint,localPort,0).valid())throw std::invalid_argument("invalid TCP endpoint");
        if(inbound) {
            const auto validMac=[](const auto& value){return (value[0]&1)==0&&
                std::any_of(value.begin(),value.end(),[](auto byte){return byte!=0;});};
            if(!validMac(mac)||!validMac(endpoint.peer)||mac==endpoint.peer||
               endpoint.service!=awdlwin::mdns::BrowseService::airdrop||!endpoint.port||
               endpoint.address[0]!=0xfe||(endpoint.address[1]&0xc0)!=0x80||
               endpoint.address==local_address(mac)||!localPort)
                throw std::invalid_argument("invalid TCP server peer");
        }
        if(now<clockUs)throw std::invalid_argument("TCP clock regressed");
        clockUs=now;
        register_stream();
        if(inbound)return;
        try {
            pcb=tcp_new_ip_type(IPADDR_TYPE_V6);if(!pcb)throw std::runtime_error("TCP PCB allocation failed");
            tcp_nagle_disable(pcb);
            tcp_arg(pcb,this);tcp_err(pcb,failed);tcp_recv(pcb,received);tcp_bind_netif(pcb,&stack.iface);
            tcp_sent(pcb,acknowledged);
            ip_addr_t source{},destination{};
            ip_addr_copy_from_ip6(source,*netif_ip6_addr(&stack.iface,0));
            ip6_addr_t target{};std::memcpy(target.addr,peer.address.data(),16);
            ip6_addr_assign_zone(&target,IP6_UNICAST,&stack.iface);ip_addr_copy_from_ip6(destination,target);
            ActiveOwner active(this,&failure);
            if(tcp_bind(pcb,&source,port)!=ERR_OK||tcp_connect(pcb,&destination,peer.port,established)!=ERR_OK||failure)
                throw std::runtime_error("TCP connect initiation failed");
        }catch(...) {release();throw;}
    }
    void clear_tx() noexcept {
        for(const auto& bytes:tx){stack.queuedBytes-=bytes.size();--stack.queuedPackets;}
        tx.clear();selected=false;
    }
    void abort() noexcept {
        closing=true;up=false;
        if(pcb){auto* p=pcb;pcb=nullptr;tcp_abort(p);}
    }
    void release() noexcept {
        abort();clear_tx();
        if(registered) {
            for(auto& item:stack.streams)if(item==this){item=nullptr;--stack.streamCount;break;}
            registered=false;
            if(!stack.streamCount&&!stack.listener&&stack.ifaceAdded){netif_remove(&stack.iface);stack.ifaceAdded=false;stack.self={};}
        }
    }
    ~Impl(){release();}
};
struct Listener::Impl {
    awdlwin::wire::MacAddress self;
    std::uint16_t port;
    tcp_pcb* pcb=nullptr;
    bool registered=false;
    int failure=0;
    std::array<std::unique_ptr<Stream>,streamLimit> candidates{};
    Stream* selected=nullptr;
    bool selectedControl=false;

    static bool same_tuple(const tcp_pcb* pcb,const Stream::Impl& stream) noexcept {
        if(!pcb||!IP_IS_V6(&pcb->local_ip)||!IP_IS_V6(&pcb->remote_ip)||
           pcb->local_port!=stream.port||pcb->remote_port!=stream.peer.port)return false;
        const auto local=local_address(stream.self);
        const auto* localBytes=reinterpret_cast<const std::uint8_t*>(ip_2_ip6(&pcb->local_ip)->addr);
        const auto* remoteBytes=reinterpret_cast<const std::uint8_t*>(ip_2_ip6(&pcb->remote_ip)->addr);
        return std::equal(local.begin(),local.end(),localBytes)&&
            std::equal(stream.peer.address.begin(),stream.peer.address.end(),remoteBytes);
    }
    Stream* candidate(const awdlwin::wire::MacAddress& peer,const Segment& segment) const noexcept {
        for(const auto& item:candidates)if(item) {
            const auto& endpoint=item->impl_->peer;
            if(endpoint.peer==peer&&endpoint.address==segment.source&&endpoint.port==segment.source_port)
                return item.get();
        }
        return nullptr;
    }
    Stream* tuple_candidate(const Segment& segment) const noexcept {
        for(const auto& item:candidates)if(item) {
            const auto& endpoint=item->impl_->peer;
            if(endpoint.address==segment.source&&endpoint.port==segment.source_port)return item.get();
        }
        return nullptr;
    }
    Stream* create_candidate(const awdlwin::wire::MacAddress& peer,const Segment& segment,
                             std::uint64_t now) {
        auto slot=std::find(candidates.begin(),candidates.end(),nullptr);
        if(slot==candidates.end())return nullptr;
        awdlwin::mdns::Endpoint endpoint{};endpoint.peer=peer;
        endpoint.service=awdlwin::mdns::BrowseService::airdrop;
        endpoint.address=segment.source;endpoint.port=segment.source_port;
        endpoint.expires_at_us=(std::numeric_limits<std::uint64_t>::max)();
        *slot=std::unique_ptr<Stream>(new Stream(self,endpoint,port,now,true));
        return slot->get();
    }
    bool has_half_open(const Stream::Impl& stream) const noexcept {
        for(auto* active=tcp_active_pcbs;active;active=active->next)
            if(active->state==SYN_RCVD&&same_tuple(active,stream))return true;
        return false;
    }
    void abort_half_open(Stream::Impl& stream) noexcept {
        auto* active=tcp_active_pcbs;
        while(active) {
            auto* next=active->next;
            if(active->state==SYN_RCVD&&same_tuple(active,stream)) {
                ActiveOwner owner(&stream,&stream.failure);tcp_abort(active);return;
            }
            active=next;
        }
    }
    static err_t accepted(void* arg,tcp_pcb* acceptedPcb,err_t error) noexcept {
        auto& listener=*static_cast<Impl*>(arg);
        if(error!=ERR_OK||!acceptedPcb)return error;
        Stream* owner=nullptr;
        for(auto& item:listener.candidates)if(item&&same_tuple(acceptedPcb,*item->impl_)) {
            owner=item.get();break;
        }
        if(!owner) {
            tcp_abort(acceptedPcb);
            return ERR_ABRT;
        }
        auto& stream=*owner->impl_;
        stream.pcb=acceptedPcb;stream.accepted=true;stream.up=true;
        tcp_nagle_disable(acceptedPcb);tcp_arg(acceptedPcb,&stream);
        tcp_err(acceptedPcb,Stream::Impl::failed);tcp_recv(acceptedPcb,Stream::Impl::received);
        tcp_sent(acceptedPcb,Stream::Impl::acknowledged);
        return ERR_OK;
    }
    Impl(const awdlwin::wire::MacAddress& mac,std::uint16_t localPort,std::uint64_t now)
        :self(mac),port(localPort) {
        const auto validMac=[](const auto& value){return (value[0]&1)==0&&
            std::any_of(value.begin(),value.end(),[](auto byte){return byte!=0;});};
        if(!validMac(self)||!localPort)throw std::invalid_argument("invalid TCP listener endpoint");
        if(now<clockUs)throw std::invalid_argument("TCP clock regressed");
        clockUs=now;
        if(!initialized){lwip_init();initialized=true;}
        if(stack.listener)throw std::runtime_error("TCP listener already active");
        const auto added=Stream::Impl::attach_interface(self);
        if(added!=ERR_OK)throw std::runtime_error("TCP netif creation failed");
        stack.listener=this;registered=true;
        try {
            auto* bound=tcp_new_ip_type(IPADDR_TYPE_V6);
            if(!bound)throw std::runtime_error("TCP listener PCB allocation failed");
            tcp_arg(bound,this);tcp_bind_netif(bound,&stack.iface);
            const auto local=local_address(self);ip6_addr_t address{};
            std::memcpy(address.addr,local.data(),16);ip6_addr_assign_zone(&address,IP6_UNICAST,&stack.iface);
            ip_addr_t source{};ip_addr_copy_from_ip6(source,address);
            const auto bindResult=tcp_bind(bound,&source,port);
            if(bindResult!=ERR_OK){tcp_abort(bound);throw std::runtime_error("TCP listener bind failed");}
            err_t listenError=ERR_OK;
            pcb=tcp_listen_with_backlog_and_err(bound,static_cast<u8_t>(streamLimit),&listenError);
            if(!pcb){tcp_abort(bound);throw std::runtime_error("TCP listen setup failed");}
            tcp_accept(pcb,accepted);
        }catch(...) {release();throw;}
    }
    void tick(std::uint64_t now) {
        if(now<clockUs){failure=ERR_VAL;return;}
        clockUs=now;
        const auto nowMs=static_cast<std::uint32_t>(now/1000);
        if(!stack.timeoutTicked||stack.timeoutMs!=nowMs) {
            stack.timeoutTicked=true;stack.timeoutMs=nowMs;sys_check_timeouts();
        }
        for(auto& item:candidates)if(item&&
            (!item->healthy()||(!item->impl_->accepted&&!has_half_open(*item->impl_)))) {
            if(item.get()==selected)selected=nullptr;
            if(!item->impl_->accepted)abort_half_open(*item->impl_);
            item.reset();
        }
    }
    void release() noexcept {
        for(auto& item:candidates)if(item&&!item->impl_->accepted)abort_half_open(*item->impl_);
        if(pcb) {
            auto* closingPcb=pcb;pcb=nullptr;
            if(tcp_close(closingPcb)!=ERR_OK)tcp_abort(closingPcb);
        }
        for(auto& item:candidates)item.reset();
        selected=nullptr;selectedControl=false;
        if(registered) {
            if(stack.listener==this){stack.listener=nullptr;clear_control_queue();}
            registered=false;
            if(!stack.streamCount&&stack.ifaceAdded){netif_remove(&stack.iface);stack.ifaceAdded=false;stack.self={};}
        }
    }
    ~Impl(){release();}
};
Stream::Stream(const awdlwin::wire::MacAddress& self,const awdlwin::mdns::Endpoint& peer,
               std::uint16_t port,std::uint64_t now):impl_(std::make_unique<Impl>(self,peer,port,now)){}
Stream::Stream(const awdlwin::wire::MacAddress& self,const awdlwin::mdns::Endpoint& peer,
               std::uint16_t port,std::uint64_t now,bool serverCandidate)
    :impl_(std::make_unique<Impl>(self,peer,port,now,serverCandidate)){}
Stream::~Stream()=default;
bool Stream::healthy()const{return impl_->failure==0&&!stack.randomFailed;}
bool Stream::connected()const{return impl_->up&&healthy();}
bool Stream::eof()const{return impl_->remoteEof;}
int Stream::error()const{return impl_->failure;}
bool Stream::retryable_error()const{return impl_->failure==ERR_RST||impl_->failure==ERR_TIMEOUT||impl_->failure==ERR_CLSD;}
bool Stream::write_pending()const{return !impl_->tx.empty()||(impl_->pcb&&(impl_->pcb->unsent||impl_->pcb->unacked));}
std::uint64_t Stream::acknowledged_bytes()const{return impl_->acknowledgedBytes;}
UploadQueueState Stream::upload_queue_state(std::size_t pendingBytes,bool moreRecords)const {
    using State=UploadQueueState;
    if(!impl_->tx.empty())return State::queued;
    const auto* pcb=impl_->pcb;
    if(!pcb)return State::other;
    const auto* next=pcb->unsent;
    const auto mss=tcp_mss(pcb);
    const auto wanted=moreRecords?std::size_t(mss):(std::min)(pendingBytes,std::size_t(mss));
    if(!next&&!wanted)return State::other;
    // Compare the head segment with both TCP windows, just as tcp_output does.
    // Without an unsent segment, check whether another upload write could fill one.
    const auto start=next?lwip_ntohl(next->tcphdr->seqno):pcb->snd_lbb;
    const auto needed=std::uint32_t(start-pcb->lastack)+(next?next->len:wanted);
    const bool peer=needed>pcb->snd_wnd, congestion=needed>pcb->cwnd;
    if(peer&&congestion)return State::bothWindows;
    if(peer)return State::peerWindow;
    if(congestion)return State::congestionWindow;
    if(!next&&pendingBytes>=wanted&&pcb->snd_buf<wanted)return State::localBuffer;
    return State::other;
}
const awdlwin::mdns::Endpoint& Stream::endpoint()const{return impl_->peer;}
void Stream::tick(std::uint64_t now) {
    if(now<clockUs){impl_->failure=ERR_VAL;return;}
    clockUs=now;
    const auto nowMs=static_cast<std::uint32_t>(now/1000);
    if(!stack.timeoutTicked||stack.timeoutMs!=nowMs) {
        stack.timeoutTicked=true;stack.timeoutMs=nowMs;
        sys_check_timeouts();
    }
}
bool Stream::receive(const awdlwin::wire::MacAddress& peer,std::span<const std::uint8_t> ip) {
    if(!healthy()||peer!=impl_->peer.peer||ip.size()<40||ip.size()>packetLimit||
       (ip[0]>>4)!=6||std::size_t(read16(ip,4))+40!=ip.size())return false;
    const auto local=local_address(impl_->self);
    if(!std::equal(impl_->peer.address.begin(),impl_->peer.address.end(),ip.begin()+8))return false;
    if(ip[6]==6) {
        const auto segment=parse(ip);
        if(!segment||segment->source!=impl_->peer.address||segment->destination!=local||
           segment->source_port!=impl_->peer.port||segment->destination_port!=impl_->port)return false;
    } else if(ip[6]==58) {
        // ICMPv6 errors are dispatched by their quoted TCP tuple so one frame can
        // affect only its owning stream. Preserve other peer ICMPv6 input (such
        // as ND) by passing each packet to the shared stack exactly once.
        if(ip.size()<41)return false;
        if(ip[40]>=1&&ip[40]<=4) {
            if(ip.size()<96||!std::equal(local.begin(),local.end(),ip.begin()+24))return false;
            const auto quote=ip.subspan(48);
            if((quote[0]>>4)!=6||quote[6]!=6||
               !std::equal(local.begin(),local.end(),quote.begin()+8)||
               !std::equal(impl_->peer.address.begin(),impl_->peer.address.end(),quote.begin()+24)||
               read16(quote,40)!=impl_->port||read16(quote,42)!=impl_->peer.port)return false;
        } else if(Impl::icmp_dispatcher(peer,impl_->peer.address)!=impl_.get())return false;
    } else return false;
    auto* p=pbuf_alloc(PBUF_RAW,static_cast<u16_t>(ip.size()),PBUF_RAM);
    if(!p){impl_->failure=ERR_MEM;return false;}
    if(pbuf_take(p,ip.data(),static_cast<u16_t>(ip.size()))!=ERR_OK){pbuf_free(p);return false;}
    // The one shared lwIP stack sees each accepted packet exactly once.
    ActiveOwner active(impl_.get(),&impl_->failure);
    const auto result=ip6_input(p,&stack.iface); // ip6_input owns p on all paths.
    if(result!=ERR_OK)impl_->failure=result;
    return result==ERR_OK;
}
std::size_t Stream::write_upload(std::span<const std::uint8_t> b,bool moreRecords) {
    if(!connected()||impl_->closing)return 0;
    auto count=(std::min)(b.size(),std::size_t(tcp_sndbuf(impl_->pcb)));
    const auto* pcb=impl_->pcb;
    const auto payload=tcp_mss(pcb);
    if(payload>0&&(moreRecords||count<b.size())) {
        const auto tail=count%payload;
        // Carry TLS record tails forward. At the actual local buffer limit a
        // substantial final segment can go on the wire before the next ACK.
        const bool fillsWindow=count==pcb->snd_buf&&pcb->snd_wnd>=TCP_SND_BUF&&
            pcb->cwnd>=TCP_SND_BUF&&tail*2>=payload;
        if(!fillsWindow)count-=tail;
    }
    return write(b.first(count));
}
std::size_t Stream::write(std::span<const std::uint8_t> b) {
    if(!connected()||impl_->closing||b.empty())return 0;
    const auto count=static_cast<u16_t>((std::min)(b.size(),std::size_t(tcp_sndbuf(impl_->pcb))));
    if(!count)return 0;
    ActiveOwner active(impl_.get(),&impl_->failure);
    const auto e=tcp_write(impl_->pcb,b.data(),count,TCP_WRITE_FLAG_COPY);
    if(e!=ERR_OK){if(e!=ERR_MEM)impl_->failure=e;return 0;}
    const auto sent=tcp_output(impl_->pcb);if(sent!=ERR_OK&&sent!=ERR_MEM)impl_->failure=sent;
    return count;
}
Bytes Stream::read(){
    Bytes b;b.swap(impl_->rx);
    if(impl_->pcb && impl_->withheldReceiveCredit) {
        ActiveOwner active(impl_.get(),&impl_->failure);
        tcp_recved(impl_->pcb,impl_->withheldReceiveCredit);
        impl_->withheldReceiveCredit=0;
    }
    return b;
}
const Bytes* Stream::outbound()const {
    if(impl_->tx.empty())return nullptr;
    impl_->selected=true;return &impl_->tx.front();
}
void Stream::sent(){if(!impl_->tx.empty()){stack.queuedBytes-=impl_->tx.front().size();--stack.queuedPackets;impl_->tx.pop_front();}impl_->selected=false;}
void Stream::abort(){impl_->abort();}
Listener::Listener(const awdlwin::wire::MacAddress& self,std::uint16_t localPort,std::uint64_t now)
    :impl_(std::make_unique<Impl>(self,localPort,now)){}
Listener::~Listener()=default;
bool Listener::healthy()const{return impl_->failure==0&&!stack.randomFailed;}
int Listener::error()const{return impl_->failure;}
void Listener::tick(std::uint64_t now){impl_->tick(now);}
bool Listener::receive(const awdlwin::wire::MacAddress& admittedPeer,std::span<const std::uint8_t> ip) {
    if(!healthy()||ip.size()<40||ip.size()>packetLimit||(ip[0]>>4)!=6||
       std::size_t(read16(ip,4))+40!=ip.size())return false;
    const auto local=local_address(impl_->self);
    const auto macValid=[](const auto& value){return (value[0]&1)==0&&
        std::any_of(value.begin(),value.end(),[](auto byte){return byte!=0;});};
    if(!macValid(admittedPeer)||admittedPeer==impl_->self)return false;

    if(ip[6]==58) {
        if(ip.size()<64||ip[7]!=255||ip[41]!=0||
           fold(sum(ip.subspan(8,32))+sum(ip.subspan(40))+static_cast<std::uint32_t>(ip.size()-40)+58)!=0xffff)
            return false;
        awdlwin::ip::Address source{},destination{},target{};
        std::copy_n(ip.begin()+8,16,source.begin());std::copy_n(ip.begin()+24,16,destination.begin());
        std::copy_n(ip.begin()+48,16,target.begin());
        if(source[0]!=0xfe||(source[1]&0xc0)!=0x80||source==local)return false;
        awdlwin::ip::Address solicited{};solicited[0]=0xff;solicited[1]=0x02;
        solicited[11]=1;solicited[12]=0xff;std::copy(local.end()-3,local.end(),solicited.end()-3);
        awdlwin::ip::Address allNodes{};allNodes[0]=0xff;allNodes[1]=0x02;allNodes[15]=1;
        if(ip[40]==135) {
            if(target!=local||(destination!=local&&destination!=solicited))return false;
        } else if(ip[40]==136) {
            if((target!=source&&target!=local)||(destination!=local&&destination!=allNodes))return false;
        } else return false;
        for(std::size_t offset=64;offset<ip.size();) {
            if(ip.size()-offset<2||ip[offset+1]==0)return false;
            const auto optionSize=std::size_t(ip[offset+1])*8;
            if(optionSize>ip.size()-offset)return false;
            const auto expectedType=ip[40]==135?1:2;
            if(ip[offset]==expectedType&&
               (optionSize!=8||!std::equal(admittedPeer.begin(),admittedPeer.end(),ip.begin()+offset+2)))return false;
            offset+=optionSize;
        }
        auto* controlPeer=remember_control_peer(admittedPeer,source,0);if(!controlPeer)return false;
        auto* packet=pbuf_alloc(PBUF_RAW,static_cast<u16_t>(ip.size()),PBUF_RAM);
        if(!packet){impl_->failure=ERR_MEM;return false;}
        if(pbuf_take(packet,ip.data(),static_cast<u16_t>(ip.size()))!=ERR_OK){pbuf_free(packet);return false;}
        ActiveControlPeer active(controlPeer);
        const auto result=ip6_input(packet,&stack.iface); // lwIP verifies ICMPv6 checksum and ND options.
        if(result!=ERR_OK)impl_->failure=result;
        return result==ERR_OK;
    }
    if(ip[6]!=6)return false;
    const auto segment=parse(ip);if(!segment)return false;
    if(segment->destination!=local||segment->destination_port!=impl_->port||
       segment->source[0]!=0xfe||(segment->source[1]&0xc0)!=0x80||segment->source==local)return false;

    if(auto* pending=impl_->tuple_candidate(*segment)) {
        if(pending->endpoint().peer!=admittedPeer)return false;
        return pending->receive(admittedPeer,ip);
    }
    // Apple advertises ECN support on its initial SYN (ECE+CWR). lwIP's
    // listener accepts SYN based on the SYN bit, so retain the same allowance
    // here while rejecting every other control flag on a new connection.
    constexpr std::uint8_t ecnSynFlags=0x02|0x40|0x80;
    if((segment->flags&static_cast<std::uint8_t>(~ecnSynFlags))!=0||
       (segment->flags&0x02)==0||segment->payload_size!=0)return false;
    if(Stream::Impl::by_tuple(local.data(),segment->source.data(),impl_->port,segment->source_port))
        return false; // An accepted stream owns this tuple; let its caller route the frame.
    try {
        auto* candidate=impl_->create_candidate(admittedPeer,*segment,clockUs);
        return candidate&&candidate->receive(admittedPeer,ip);
    }catch(...) {return false;}
}
std::unique_ptr<Stream> Listener::accept() {
    for(auto& item:impl_->candidates)if(item&&item->impl_->accepted&&item.get()!=impl_->selected)
        return std::move(item);
    return {};
}
bool Listener::has_pending_connections()const {
    return std::any_of(impl_->candidates.begin(),impl_->candidates.end(),[](const auto& item){return item!=nullptr;});
}
const Bytes* Listener::outbound()const {
    if(impl_->selected)return impl_->selected->outbound();
    if(impl_->selectedControl)return stack.controlTx.empty()?nullptr:&stack.controlTx.front().bytes;
    for(const auto& item:impl_->candidates)if(item)if(const auto* packet=item->outbound()) {
        impl_->selected=item.get();return packet;
    }
    if(!stack.controlTx.empty()) {
        impl_->selectedControl=true;return &stack.controlTx.front().bytes;
    }
    return nullptr;
}
const awdlwin::mdns::Endpoint* Listener::outbound_endpoint()const {
    if(impl_->selected)return &impl_->selected->endpoint();
    return impl_->selectedControl&&!stack.controlTx.empty()?&stack.controlTx.front().peer:nullptr;
}
void Listener::sent() {
    if(impl_->selected){impl_->selected->sent();impl_->selected=nullptr;return;}
    if(impl_->selectedControl&&!stack.controlTx.empty()) {
        stack.controlBytes-=stack.controlTx.front().bytes.size();stack.controlTx.pop_front();
    }
    impl_->selectedControl=false;
}
void Listener::discard_outbound() {
    if(impl_->selected) {
        auto* selected=impl_->selected;
        impl_->selected=nullptr;
        for(auto& item:impl_->candidates)if(item.get()==selected) {
            if(!item->impl_->accepted)impl_->abort_half_open(*item->impl_);
            item.reset();return;
        }
        return;
    }
    if(impl_->selectedControl&&!stack.controlTx.empty()) {
        stack.controlBytes-=stack.controlTx.front().bytes.size();stack.controlTx.pop_front();
    }
    impl_->selectedControl=false;
}
} // namespace tx10ub::tcp
