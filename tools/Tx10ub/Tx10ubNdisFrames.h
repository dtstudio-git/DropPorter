#pragma once

#include "../../src/awdl_data.h"
#include "../../src/awdl_ip_receive.h"
#include "Tx10ubUsbFrames.h" // Existing MPDU CRC routine, no capture handle.
#include "Tx10ubUsbClock.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>

namespace tx10ub::ndiscap {
// Microsoft-Windows-NDIS-PacketCapture, PacketFragment v0. Only complete
// single-event Native802.11 records from the target miniport are decoded.
inline constexpr std::uint64_t nativeWifi = 0x10000, truncated = 0x2000000,
    packetStart = 0x40000000, packetEnd = 0x80000000,
    sendPath = 0x100000000, receivePath = 0x200000000;

// Returns the exact native MPDU bytes from one complete target-interface RX
// PacketFragment v0 event. The result excludes the 12-byte NDIS event prefix;
// it does not add, remove, or infer an FCS. Empty means the event is unrelated
// or fails one of the target/direction/completeness/self-source checks.
inline std::span<const std::uint8_t> select_incoming_native_mpdu(
        unsigned interfaceIndex, const awdlwin::wire::MacAddress& self,
        std::uint64_t keywords, std::span<const std::uint8_t> event) noexcept {
    if (event.size() < 12 || !(keywords & nativeWifi)) return {};
    const auto direction = keywords & (receivePath | sendPath);
    if (direction != receivePath) return {};
    if ((keywords & (truncated | packetStart | packetEnd)) != (packetStart | packetEnd)) return {};

    std::uint32_t miniport{}, size{};
    std::memcpy(&miniport, event.data(), sizeof(miniport));
    std::memcpy(&size, event.data() + 8, sizeof(size));
    if (miniport != interfaceIndex || size > event.size() - 12 || size < 24) return {};

    const auto mpdu = event.subspan(12, size);
    if (std::equal(self.begin(), self.end(), mpdu.begin() + 10)) return {};
    return mpdu;
}

inline bool is_awdl_action_candidate(std::span<const std::uint8_t> mpdu) noexcept {
    return mpdu.size() >= 29 && mpdu[0] == 0xd0 &&
        mpdu[24] == 0x7f && mpdu[25] == 0 && mpdu[26] == 0x17 &&
        mpdu[27] == 0xf2 && mpdu[28] == 8;
}

inline std::span<const std::uint8_t> select_incoming_awdl_mpdu(
        unsigned interfaceIndex, const awdlwin::wire::MacAddress& self,
        std::uint64_t keywords, std::span<const std::uint8_t> event) noexcept {
    const auto mpdu = select_incoming_native_mpdu(interfaceIndex, self, keywords, event);
    if (mpdu.empty() || (!is_awdl_action_candidate(mpdu) &&
        !awdlwin::wire::is_awdl_data_candidate(mpdu))) return {};
    return mpdu;
}

struct Counts {
    std::uint64_t target{}, nativeRx{}, nativeTx{}, incomplete{}, malformed{};
    std::uint64_t psf{}, mif{}, data{}, mdns{}, tcpToSelf{}, txAction{}, txData{};
    std::uint64_t syncWithinBudget{}, tcpWithPayload{}, tcpAckOnly{};
    std::uint64_t payloadWithinBudget{}, payloadMaxUs{};
    std::uint64_t firstRx{}, lastRx{}, maxDeliveryUs{}, clockErrors{}, rxWithCrc{};
};

inline void observe(Counts& count, unsigned index, const awdlwin::wire::MacAddress& self,
                    std::uint64_t keywords, std::span<const std::uint8_t> event,
                    std::uint64_t eventTime, std::uint64_t callbackTime) {
    using namespace awdlwin;
    if (event.size() < 12) return;
    std::uint32_t miniport{}, size{};
    std::memcpy(&miniport, event.data(), 4);
    std::memcpy(&size, event.data()+8, 4);
    if (miniport != index) return;
    ++count.target;
    if (!(keywords & nativeWifi)) return;
    const auto direction = keywords & (receivePath | sendPath);
    if (direction != receivePath && direction != sendPath) return;
    const bool incoming = direction == receivePath;
    if (incoming) ++count.nativeRx;
    else ++count.nativeTx;
    if ((keywords & (truncated | packetStart | packetEnd)) != (packetStart | packetEnd) ||
        size > event.size()-12) { ++count.incomplete; return; }
    const auto frame = event.subspan(12, size);
    if (frame.size() < 24) return;
    const bool localSource = std::equal(self.begin(),self.end(),frame.begin()+10);
    if (incoming == localSource) return;
    const bool timely = callbackTime >= eventTime && callbackTime - eventTime <=
        awdlwin::tx10ub::usb_clock::discovery_budget.maximum_event_age_us * 10;
    bool crcMatched=false;
    if (frame[0] == 0xd0 && frame.size() >= 29 &&
        frame[24]==0x7f && frame[25]==0 && frame[26]==0x17 && frame[27]==0xf2 && frame[28]==8) {
        crcMatched=usb::valid_fcs(frame);
        const auto action = wire::parse_action_mpdu(frame,crcMatched);
        if (!action) { ++count.malformed; return; }
        if (!incoming) { ++count.txAction; return; }
        if (action.value().body.header.subtype == wire::ActionSubtype::psf) ++count.psf;
        else ++count.mif;
        if (timely) ++count.syncWithinBudget;
    } else if (wire::is_awdl_data_candidate(frame)) {
        crcMatched=usb::valid_fcs(frame);
        const auto data = wire::parse_awdl_data_mpdu(frame,crcMatched);
        if (!data) { ++count.malformed; return; }
        if (!incoming) { ++count.txData; return; }
        ++count.data;
        for (const auto& msdu : data.value().msdus) {
            if (msdu.ether_type != 0x86dd) continue;
            const auto ipPacket = ip::parse_ipv6(msdu.payload);
            const auto* packet = std::get_if<ip::Packet>(&ipPacket);
            if (!packet || !ip::destination_matches(packet->destination,msdu.destination,self)) continue;
            if (packet->udp && std::holds_alternative<ip::Mdns>(ip::parse_mdns(*packet))) ++count.mdns;
            if (msdu.destination != self || packet->destination != tcp::local_address(self)) continue;
            if (const auto segment = tcp::parse(msdu.payload)) {
                ++count.tcpToSelf;
                if (segment->payload_size != 0) {
                    ++count.tcpWithPayload;
                    if (timely) ++count.payloadWithinBudget;
                    if (callbackTime>=eventTime)
                        count.payloadMaxUs=std::max(count.payloadMaxUs,(callbackTime-eventTime)/10);
                }
                else if (segment->flags == 0x10) ++count.tcpAckOnly;
            }
        }
    } else return;
    if (crcMatched) ++count.rxWithCrc;
    if (!count.firstRx) count.firstRx = eventTime;
    count.lastRx = eventTime;
    if (callbackTime < eventTime) ++count.clockErrors;
    else count.maxDeliveryUs = std::max(count.maxDeliveryUs, (callbackTime-eventTime)/10);
}
}
