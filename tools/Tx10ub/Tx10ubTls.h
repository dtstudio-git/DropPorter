#pragma once
#include "../../src/awdl_data.h"
#include <cstddef>
#include <memory>

namespace tx10ub::tls {
// Process-specific temporary user key, deleted on close. The certificate is
// memory-only; no certificate store or existing key is changed.
class Identity {
    friend class Client;
    friend class Server;
    struct Impl;
    std::shared_ptr<Impl> impl_;
public:
    Identity();
    ~Identity();
    Identity(const Identity&)=delete;
    Identity& operator=(const Identity&)=delete;
    const void* certificate()const;
    bool close();
};
// TLS 1.2 stream engine for the explicit AirDrop interoperability experiment.
// AirDrop self-signed peer certificates are accepted in this context only;
// encryption is not an authenticated Apple/account/device identity.
class Client {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    explicit Client(bool offerCertificate=true);
    explicit Client(Identity& identity,bool offerCertificate=true);
    ~Client();
    Client(const Client&)=delete;
    Client& operator=(const Client&)=delete;
    bool healthy()const;
    bool ready()const;
    bool closed()const;
    std::uint32_t error()const;
    bool certificate_rejected()const {
        return error()==0x80090327u; // SEC_E_CERT_UNKNOWN, including the peer's bad_certificate alert.
    }
    std::size_t max_message_size()const;
    bool feed(std::span<const std::uint8_t> ciphertext);
    bool write(std::span<const std::uint8_t> plaintext);
    awdlwin::wire::Bytes outbound();
    awdlwin::wire::Bytes read();
    bool shutdown();
    // After draining close_notify, create a fresh context for another TCP
    // connection. Retains this trial's credentials/certificate until close().
    bool reset_connection();
    bool close();
};
// TLS 1.2 server context for inbound AirDrop streams. The default constructor
// creates an Identity; the overload shares an owner-held Identity across sessions.
// The peer certificate is not treated as an authenticated Apple identity.
class Server {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    static constexpr std::size_t MaxBufferedBytes = 512 * 1024; // One TCP read plus a partial TLS record.
    Server();
    explicit Server(Identity& identity);
    ~Server();
    Server(const Server&)=delete;
    Server& operator=(const Server&)=delete;
    bool healthy()const;
    bool ready()const;
    bool closed()const;
    std::uint32_t error()const;
    std::size_t max_message_size()const;
    bool feed(std::span<const std::uint8_t> ciphertext);
    bool write(std::span<const std::uint8_t> plaintext);
    awdlwin::wire::Bytes outbound();
    awdlwin::wire::Bytes read();
    bool shutdown();
    bool close();
};
} // namespace tx10ub::tls
