#pragma once

#include <array>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace tx10ub::probe_events {

inline constexpr wchar_t LogFileName[] = L"usb.txt";
inline constexpr wchar_t ProgressFileName[] = L"progress.txt";

inline constexpr char ReceiveWaiting[] = "airdrop_receive_waiting=1";
inline constexpr char ReceiveConnected[] = "airdrop_receive_connected id=";
inline constexpr char ReceiveTcpIdle[] = "airdrop_receive_tcp_idle=1";
inline constexpr char DiscoveredEndpoints[] = "mdns_discovered_endpoints=";
inline constexpr char TargetWaiting[] = "airdrop_target_waiting=1";
inline constexpr char TargetSelected[] = "airdrop_target_selected=1";
inline constexpr char UploadWaiting[] = "airdrop_upload_waiting=1";
inline constexpr char UploadSucceeded[] = "airdrop_upload_success=1";
inline constexpr char TransportClosed[] = "airdrop_transport_closed=1";
inline constexpr char RadioHandoff[] = "airdrop_radio_handoff_waiting=";
inline constexpr char HandoffIdle[] = "0", HandoffSend[] = "1", HandoffSendWide[] = "send40";
inline constexpr char HandoffReceive[] = "receive", HandoffReceiveWide[] = "receive40";

inline constexpr std::string_view StagePrefix = "airdrop_stage=";
inline constexpr std::string_view FailurePrefix = "airdrop_failure stage=";
inline constexpr std::string_view FailureReason = " reason=";
inline constexpr std::string_view FailureHttpStatus = " http_status=";
inline constexpr char Preparing[] = "preparing", Discovery[] = "discovery", Select[] = "select";
inline constexpr char BluetoothUnavailable[] = "bluetooth_unavailable";
inline constexpr char Connect[] = "connect", Tls[] = "tls", Discover[] = "discover";
inline constexpr char Ask[] = "ask", Upload[] = "upload";

template <std::size_t Size>
constexpr std::array<wchar_t, Size> WidenAscii(const char (&text)[Size]) {
    std::array<wchar_t, Size> result{};
    for (std::size_t i = 0; i < Size; ++i) result[i] = text[i];
    return result;
}
inline constexpr auto WideConnect = WidenAscii(Connect);
inline constexpr auto WideTls = WidenAscii(Tls);
inline constexpr auto WideDiscover = WidenAscii(Discover);
inline constexpr auto WideAsk = WidenAscii(Ask);
inline constexpr auto WideUpload = WidenAscii(Upload);

inline constexpr char ExchangePrefix[] = "airdrop_";
inline constexpr char RequestQueued[] = "_request_queued=1";
inline constexpr char ResponseComplete[] = "_http_response_complete=1 status=";
inline const std::string AskQueued = std::string(ExchangePrefix) + Ask + RequestQueued;
inline const std::string AskAccepted = std::string(ExchangePrefix) + Ask + ResponseComplete + "200";
inline const std::string NoEndpoints = std::string(DiscoveredEndpoints) + '0';

inline constexpr std::string_view ProgressPrefix = "airdrop_progress ";
inline constexpr char ProcessedKey[] = "processed", TotalKey[] = "total", ElapsedKey[] = "elapsed_ms";

struct Progress { std::uint64_t processed, total, elapsedMs; };

inline bool ParseUnsigned(std::string_view text, std::uint64_t& value) {
    if (text.empty()) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

inline std::optional<Progress> ParseProgressEvent(std::string_view line, std::uint64_t maxBytes) {
    if (!line.starts_with(ProgressPrefix)) return std::nullopt;
    line.remove_prefix(ProgressPrefix.size());
    const auto readField = [&line](std::string_view key, std::uint64_t& value) {
        const auto end = line.find(' ');
        const auto field = line.substr(0, end);
        if (!field.starts_with(key) || field.size() <= key.size() || field[key.size()] != '=') return false;
        if (!ParseUnsigned(field.substr(key.size() + 1), value)) return false;
        if (end == line.npos) line = {};
        else line.remove_prefix(end + 1);
        return true;
    };
    Progress value{};
    if (!readField(ProcessedKey, value.processed) || !readField(TotalKey, value.total) ||
        line.find(' ') != line.npos || !readField(ElapsedKey, value.elapsedMs) ||
        value.processed > value.total || value.total > maxBytes) return std::nullopt;
    return value;
}

inline std::string EncodeProgressFile(const Progress& value) {
    return std::string(ProcessedKey) + '=' + std::to_string(value.processed) + '\n' +
        TotalKey + '=' + std::to_string(value.total) + '\n' +
        ElapsedKey + '=' + std::to_string(value.elapsedMs) + '\n';
}

}
