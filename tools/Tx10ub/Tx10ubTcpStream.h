#pragma once
#include "../../src/awdl_mdns_cache.h"
#include "Tx10ubUploadQueue.h"
#include <memory>
#include <optional>

namespace tx10ub::tcp {
// Up to four sessions share one serialized NO_SYS lwIP stack/netif. All methods,
// callbacks and destruction belong to the USB/discovery owner thread. No Windows
// socket or OS route.
class Listener;
class Stream {
    friend class Listener;
    struct Impl;
    std::unique_ptr<Impl> impl_;
    Stream(const awdlwin::wire::MacAddress& self,const awdlwin::mdns::Endpoint& peer,
           std::uint16_t localPort,std::uint64_t nowUs,bool serverCandidate);
public:
    Stream(const awdlwin::wire::MacAddress& self,const awdlwin::mdns::Endpoint& peer,
           std::uint16_t localPort,std::uint64_t nowUs);
    ~Stream();
    Stream(const Stream&)=delete;
    Stream& operator=(const Stream&)=delete;
    bool healthy()const;
    bool connected()const;
    bool eof()const;
    int error()const;
    bool retryable_error()const;
    bool write_pending()const;
    std::uint64_t acknowledged_bytes()const;
    UploadQueueState upload_queue_state(std::size_t pendingBytes,bool moreRecords)const;
    const awdlwin::mdns::Endpoint& endpoint()const;
    void tick(std::uint64_t nowUs);
    bool receive(const awdlwin::wire::MacAddress& peer,std::span<const std::uint8_t> ipv6);
    std::size_t write(std::span<const std::uint8_t> bytes);
    // Carry a sub-segment tail across upload records until the final write.
    std::size_t write_upload(std::span<const std::uint8_t> bytes,bool moreRecords);
    awdlwin::wire::Bytes read();
    // Selects an immutable front packet until sent(), including receive/timer callbacks.
    const awdlwin::wire::Bytes* outbound()const;
    void sent();
    // Next in-order receive sequence (diagnostics only).
    std::optional<std::uint32_t> receive_next()const;
    void abort();
};

// Raw TCP listener for an already source-admitted AWDL peer. The caller passes
// only admitted frames; Listener consumes fresh SYNs and their handshake packets.
// Pre-accept output (SYN-ACK/retransmit) uses the same immutable send fence as Stream.
class Listener {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    Listener(const awdlwin::wire::MacAddress& self,std::uint16_t localPort,std::uint64_t nowUs);
    ~Listener();
    Listener(const Listener&)=delete;
    Listener& operator=(const Listener&)=delete;
    bool healthy()const;
    int error()const;
    void tick(std::uint64_t nowUs);
    bool receive(const awdlwin::wire::MacAddress& admittedPeer,std::span<const std::uint8_t> ipv6);
    bool has_pending_connections()const;
    std::unique_ptr<Stream> accept();
    const awdlwin::wire::Bytes* outbound()const;
    const awdlwin::mdns::Endpoint* outbound_endpoint()const;
    void sent();
    // Drop the selected front only when the owner has confirmed no USB send fence is active.
    void discard_outbound();
};
} // namespace tx10ub::tcp
